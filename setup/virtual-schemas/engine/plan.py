"""Connectors, inputs and the plan.

Everything here is pure: it decides WHAT a connect will do from the
connector definition, the user's inputs and a snapshot of facts about the
database, without touching either. lifecycle.py applies the plan; --dry-run
prints it and stops.

A connector is a folder: connector.json says what can be said as data, and
an optional hooks.py says what cannot - a URL shape the generic parser does
not know (SQL Server's ;databaseName=, Oracle's @//host/service), extra
connection objects (Exasol's EXA connection), properties that depend on the
host. Every hook has a generic default here, so most connectors need none.

What a connector.json can say beyond the JDBC basics:

  runtime        java (default) | rust | lua - which script language the
                 adapter runs in. rust uses the kit's pinned custom SLC
                 (runtimes.json); lua is built into the database.
  adapter.assets per-architecture downloads ({"x86_64": {file, url, sha256},
                 "aarch64": {...}}) for native adapters; adapter.extract
                 names the library inside an archive download;
                 adapter.script_name fixes the adapter script's name (a
                 native library's entry point is named after its script).
  scripts        companion scripts the adapter calls by name, as SQL
                 templates with {schema} and {udf_object}; they live in the
                 kit's adapter schema and go with the connector's last adapter.
  check.kind     jdbc (default) | exa | vs - how a candidate connection is
                 proven: an IMPORT through it, or (vs) a throwaway virtual
                 schema for adapters with no JDBC side.

Hooks: parse_url, build_url, extra_connections, properties, prepare, validate,
connection_user and connection_secret (what the CONNECTION's USER and
IDENTIFIED BY hold, when that is not user + password), adapter_source (a
Lua adapter's source, patched before it goes into the script).
"""

import importlib.util
import json
import os
import re
from pathlib import Path

from . import net, sql

CONNECTORS_DIR = Path(__file__).resolve().parent.parent / "connectors"

TLS_LABELS = {
    "verify": "encrypted, certificate verified",
    "encrypt": "encrypted (certificate not verified)",
    "none": "not encrypted",
}


class PlanError(ValueError):
    pass


def load_connectors(root=None):
    root = Path(root or CONNECTORS_DIR)
    found = {}
    for d in sorted(root.iterdir()) if root.is_dir() else []:
        f = d / "connector.json"
        if not f.is_file():
            continue
        with open(f, "r", encoding="utf-8") as fh:
            c = json.load(fh)
        h = d / "hooks.py"
        if h.is_file():
            spec = importlib.util.spec_from_file_location("exakit_vs_hooks_%s" % c["id"], h)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            c["_hooks"] = mod
        found[c["id"]] = c
    return found


def hook(connector, name):
    """The connector's own implementation of `name`, or None."""
    mod = connector.get("_hooks")
    return getattr(mod, name, None) if mod else None


def find_connector(connectors, name):
    n = (name or "").strip().lower()
    for c in connectors.values():
        if n == c["id"] or n == c["label"].lower() or n in c.get("aliases", []):
            return c
    raise PlanError("unknown source %r (available: %s)" % (
        name, ", ".join(sorted(connectors))))


def unavailable_reason(connector):
    """Why this connector cannot be used on Exasol Personal yet, or None.
    EXAKIT_VS_ALLOW_UNAVAILABLE=1 lets someone try anyway (against a real
    account, to find out whether a newer Exasol Personal has fixed it)."""
    if connector.get("available", True) is not False:
        return None
    if os.environ.get("EXAKIT_VS_ALLOW_UNAVAILABLE") == "1":
        return None
    return connector.get("unavailable_reason") or "this source is not supported yet"


def driver(connector):
    """The JDBC driver the database's import side needs registered, or None
    (Exasol's own adapter reads through IMPORT FROM EXA instead)."""
    d = connector.get("driver")
    return d if d and d.get("settings") else None


# --- runtimes and adapters -----------------------------------------------------------
# A connector runs on one runtime: java (JAR adapters, the default), rust
# (a native library in BucketFS, on the kit's pinned custom SLC) or lua
# (adapter source inline in the script, built into the database).

RUNTIMES_FILE = CONNECTORS_DIR.parent / "runtimes.json"


def runtime_kind(connector):
    return connector.get("runtime", "java")


def load_runtimes(path=None):
    with open(path or RUNTIMES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def runtime_spec(kind, arch=None, runtimes=None):
    """The pinned custom-SLC download for `kind` on this architecture, or None
    for a runtime that is not custom (java, lua)."""
    if kind not in ("rust",):
        return None
    rt = (runtimes or load_runtimes())[kind]
    asset = rt["assets"].get(arch or _arch())
    if not asset:
        raise PlanError("the %s runtime has no build for this machine's architecture (%s)"
                        % (kind, arch or _arch()))
    return dict(asset, alias=rt["alias"], language=rt["language"], version=rt["version"],
                license=rt.get("license"))


def _arch():
    from . import runtime
    return runtime.db_arch()


def adapter(connector, arch=None):
    """The adapter artifact for this machine: the connector's adapter block,
    with a per-architecture asset (native adapters) merged in. stage_name is
    the file that lands in BucketFS - the archive member for a .tar.gz."""
    a = dict(connector["adapter"])
    assets = a.pop("assets", None)
    if assets:
        asset = assets.get(arch or _arch())
        if not asset:
            raise PlanError("%s has no build for this machine's architecture (%s)"
                            % (connector["label"], arch or _arch()))
        a.update(asset)
    a["stage_name"] = Path(a["extract"]).name if a.get("extract") else a["file"]
    return a


def connection_user(connector, inputs):
    """What goes into the CONNECTION's USER: the source user by default; a
    connector whose secret is not a password says otherwise (Databricks:
    'token'; Lakehouse: '')."""
    fn = hook(connector, "connection_user")
    return fn(connector, inputs) if fn else (inputs.get("user") or "")


def connection_secret(connector, inputs, password):
    """What goes into IDENTIFIED BY: the password by default; a hook can wrap
    it (Lakehouse: a JSON document of storage settings and keys)."""
    fn = hook(connector, "connection_secret")
    return fn(connector, inputs, password) if fn else password


# --- inputs -----------------------------------------------------------------------
# Precedence: explicit flag > EXAKIT_VS_* environment > pasted URL > what this
# source was given last time > prompt or default.

ENV = {
    "source": "EXAKIT_VS_SOURCE", "name": "EXAKIT_VS_NAME", "url": "EXAKIT_VS_JDBC_URL",
    "host": "EXAKIT_VS_HOST", "port": "EXAKIT_VS_PORT", "database": "EXAKIT_VS_DATABASE",
    "user": "EXAKIT_VS_USER", "schema": "EXAKIT_VS_SCHEMA", "tls": "EXAKIT_VS_TLS",
}


def from_env(environ=None):
    environ = os.environ if environ is None else environ
    return {k: environ[v] for k, v in ENV.items() if environ.get(v)}


def env_var(field_id):
    return ENV.get(field_id, "EXAKIT_VS_%s" % field_id.upper())


def connector_env(connector, environ=None):
    """Connector-specific inputs (Snowflake's warehouse and role, ...) from
    EXAKIT_VS_<ID>."""
    environ = os.environ if environ is None else environ
    out = {}
    for f in connector["inputs"]:
        if f.get("secret") or f["id"] in ENV:
            continue
        v = environ.get(env_var(f["id"]))
        if v:
            out[f["id"]] = v
    return out


def input_ids(connector):
    return [f["id"] for f in connector["inputs"] if not f.get("secret")]


_BARE_ENDPOINT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?::(\d{1,5}))?(?:/([A-Za-z0-9_$.-]+))?/?$")


def parse_url(connector, text):
    # A cloud console (RDS, Azure SQL, Cloud SQL) shows the endpoint as a bare
    # host name, and that is what people paste: host, host:port or
    # host:port/database is taken as the fields it names, for every source.
    m = _BARE_ENDPOINT.match((text or "").strip())
    if m:
        fields = {"host": m.group(1), "params": {}}
        if m.group(2):
            fields["port"] = int(m.group(2))
        if m.group(3) and "database" in input_ids(connector):
            fields["database"] = m.group(3)
        return fields, []
    fn = hook(connector, "parse_url")
    return fn(connector, text) if fn else net.parse_url(connector, text)


def merge_url(connector, inputs, notes):
    """Fold a pasted connection string into the field inputs; explicit fields
    win over what the URL says."""
    if not inputs.get("url"):
        return inputs
    fields, url_notes = parse_url(connector, inputs["url"])
    notes.extend(url_notes)
    out = dict(inputs)
    for k in set(input_ids(connector)) | {"host", "port", "database", "user"}:
        if fields.get(k) is not None and not out.get(k):
            out[k] = fields[k]
    params = dict(fields.get("params") or {})
    tls_param = connector["tls"].get("param")
    if tls_param and tls_param in params and not out.get("tls"):
        mapped = connector["tls"].get("from_url", {}).get(params[tls_param])
        if mapped:
            out["tls"] = mapped
    # The kit owns the TLS parameters; everything else allowed rides along.
    tls_keys = set()
    for lvl in connector["tls"]["levels"].values():
        tls_keys.update(lvl.get("params", {}))
    out["params"] = {k: v for k, v in params.items() if k not in tls_keys}
    return out


def validate(connector, inputs):
    v = dict(inputs)
    v["host"] = net.validate_host(v.get("host"))
    v["port"] = net.validate_port(v.get("port") or connector["url"]["default_port"])
    for f in connector["inputs"]:
        if f.get("secret") or f["id"] in ("host", "port"):
            continue
        if f.get("required") and not v.get(f["id"]) and f.get("default") is None:
            raise PlanError("%s is required" % f["label"])
        if not v.get(f["id"]) and f.get("default") is not None:
            v[f["id"]] = f["default"]
    v["name"] = sql.validate_name(v.get("name"))
    if v.get("tls") and v["tls"] not in TLS_LABELS:
        raise PlanError("EXAKIT_VS_TLS must be verify, encrypt or none (got %r)" % v["tls"])
    fn = hook(connector, "validate")
    if fn:
        # Rules that depend on other answers (Lakehouse: a warehouse only on
        # the Iceberg route). Raises PlanError.
        v = fn(connector, v) or v
    return v


# --- TLS ---------------------------------------------------------------------------

def tls_offer(connector, host_class):
    """The levels a user may pick for this host, best first. `none` only for a
    host on this machine or a private network: an unencrypted link across the
    internet is not offered at all."""
    levels = connector["tls"]["levels"]
    order = [l for l in ("verify", "encrypt", "none") if l in levels]
    out = []
    for l in order:
        if levels[l].get("available", True) is False:
            continue
        if l == "none" and host_class == "public":
            continue
        out.append(l)
    return out


def tls_start(connector, host_class, requested):
    """The level the first attempt uses, or a PlanError explaining why the
    requested one cannot be used."""
    levels = connector["tls"]["levels"]
    if requested:
        lvl = levels.get(requested)
        if lvl is None:
            raise PlanError("%s does not support TLS level %r" % (connector["label"], requested))
        if lvl.get("available", True) is False:
            raise PlanError("TLS level %r is not possible yet: %s Use EXAKIT_VS_TLS=encrypt."
                            % (requested, lvl.get("reason", "")))
        if requested == "none" and host_class == "public":
            raise PlanError("an unencrypted connection is only allowed to a host on this machine or "
                            "a private network, and this host is a public address")
        return requested
    default = connector["tls"].get("default", "encrypt")
    offer = tls_offer(connector, host_class)
    if not offer:
        raise PlanError("%s offers no usable TLS level for this host" % connector["label"])
    return default if default in offer else offer[0]


def url_params(connector, level, extra):
    params = dict(extra or {})
    params.update(connector["tls"]["levels"][level].get("params", {}))
    return params


def build_url(connector, host, inputs, level):
    """The JDBC URL for the main connection. A hook builds it when the
    connector's URL is not host:port/database?params (SQL Server, Oracle,
    Snowflake, Exasol)."""
    params = url_params(connector, level, inputs.get("params"))
    fn = hook(connector, "build_url")
    if fn:
        return fn(connector, host, inputs, level, params)
    return net.build_url(connector, host, inputs["port"], inputs.get("database"), params)


def extra_connections(connector, names, host, inputs, level):
    """[(name, target)] the connector needs beside the main JDBC connection,
    all with the same credentials (Exasol: the EXA connection IMPORT FROM EXA
    reads through)."""
    fn = hook(connector, "extra_connections")
    return list(fn(connector, names, host, inputs, level)) if fn else []


# --- properties and the plan ----------------------------------------------------------

_FIELD = re.compile(r"\{(\w+)(?:\|(\w+))?\}")


def render(template, values):
    """'{schema|upper}' -> the schema upper-cased. Filters: upper, lower."""
    def sub(m):
        v = "" if values.get(m.group(1)) is None else str(values.get(m.group(1)))
        f = m.group(2)
        if f == "upper":
            return v.upper()
        if f == "lower":
            return v.lower()
        if f:
            raise PlanError("unknown filter %r in a connector template" % f)
        return v
    return _FIELD.sub(sub, template)


def vs_properties(connector, names, inputs, host=None):
    """names: the object names (connection, schema, extra connections)."""
    fn = hook(connector, "properties")
    if fn:
        return fn(connector, names, inputs, host)
    props = {"CONNECTION_NAME": names["connection"]}
    values = {k: inputs.get(k, "") for k in input_ids(connector)}
    for k, tmpl in connector["properties"].items():
        props[k] = render(tmpl, values)
    return props


RUNTIME_LABELS = {"java": "Java", "rust": "Rust", "lua": "Lua"}


def restart_needed(facts):
    """A runtime recorded but not active (a run interrupted between the
    install and the restart) needs the restart just as much as one never
    installed; so does a custom runtime being replaced. Lua is built in."""
    if facts.get("runtime", "java") == "lua":
        return False
    return (not facts.get("runtime_installed") or facts.get("runtime_active") is False
            or bool(facts.get("runtime_conflict")))


def build_plan(connector, inputs, facts):
    """facts: runtime (java|rust|lua), runtime_installed, runtime_active
    (True|False|None=unknown), runtime_conflict (the other version a custom
    runtime has, or None), adapter_cached, driver_cached, adapter_staged,
    driver_registered, dns (ok|missing|unknown|inactive|n/a),
    connection_exists, connection_owned, schema_exists, schema_owned,
    adapter_schema_foreign, script_exists."""
    names = sql.object_names(inputs["name"])
    ad = adapter(connector)
    script = sql.adapter_script_name(connector["id"], ad["version"], ad.get("script_name"))
    drv = driver(connector)
    kind = runtime_kind(connector)
    rt_label = RUNTIME_LABELS.get(kind, kind)
    steps = []

    def add(key, text, needed=True, consent=False):
        steps.append({"step": key, "action": text, "needed": bool(needed), "consent": consent})

    # Every refusal comes before anything is staged or changed.
    if facts.get("connection_exists") and not facts.get("connection_owned"):
        raise PlanError("a connection named %s already exists and was not created by the kit; "
                        "pick another name" % names["connection"])
    if facts.get("schema_exists") and not facts.get("schema_owned"):
        raise PlanError("a schema named %s already exists and was not created by the kit; "
                        "pick another name" % names["schema"])
    if facts.get("adapter_schema_foreign"):
        raise PlanError("a schema named %s exists and was not created by the kit; the kit will not "
                        "put its adapter scripts there" % sql.ADAPTER_SCHEMA)

    if kind == "java":
        add("runtime", "Install the Java runtime in the database (exasol slc install java)",
            not facts.get("runtime_installed"), consent=True)
    elif kind != "lua":
        spec = runtime_spec(kind)
        if facts.get("runtime_conflict"):
            text = "Replace the %s runtime %s with %s (custom SLC %s)" % (
                rt_label, facts["runtime_conflict"], spec["version"], spec["alias"])
        else:
            text = "Install the %s runtime %s in the database (custom SLC %s)" % (
                rt_label, spec["version"], spec["alias"])
        add("runtime", text, not facts.get("runtime_installed") or bool(facts.get("runtime_conflict")),
            consent=True)
    what = "%s adapter %s" % (connector["label"], ad["version"])
    if drv:
        what += " and %s %s" % (drv["name"], drv["version"])
    add("download", "Download and verify " + what,
        not (facts.get("adapter_cached") and (facts.get("driver_cached") or not drv)))
    if kind != "lua":
        add("stage", "Stage the adapter in BucketFS (exakit-vs/%s/%s)" % (connector["id"], ad["version"]),
            not facts.get("adapter_staged"))
    if drv:
        add("driver", "Register the JDBC driver %s" % drv["settings"]["DRIVERNAME"],
            not facts.get("driver_registered"))
    add("restart", "Restart the database once, to activate the %s runtime" % rt_label,
        restart_needed(facts), consent=True)
    if kind == "java":
        add("dns", "Link name resolution into the Java sandbox (temporary workaround)",
            facts.get("dns") != "ok")
    add("connection", "Create connection %s (%s stored only there)" % (
        names["connection"], connector.get("secret_label", "password").lower()))
    companions = [s["name"] for s in connector.get("scripts", [])]
    add("script", "Create adapter script %s.%s%s" % (
        sql.ADAPTER_SCHEMA, script, " and %s" % ", ".join(companions) if companions else ""),
        not facts.get("script_exists"))
    add("probe", "Test the source and its schema from inside the database")
    add("schema", "%s virtual schema %s" % (
        "Refresh" if facts.get("schema_exists") else "Create", names["schema"]))
    add("verify", "Read real rows through the virtual schema")
    return {"source": inputs["name"], "connector": connector["id"], "objects": dict(names, script="%s.%s" % (
        sql.ADAPTER_SCHEMA, script)), "restart_needed": restart_needed(facts), "steps": steps}


def connection_fields(connector):
    """The inputs that make up a source's CONNECTION. A re-run of connect that
    changes any of them must rebuild it, which needs the password; inputs
    marked "connection": false (the source schema, used only by the virtual
    schema) change without one."""
    return [f["id"] for f in connector["inputs"]
            if not f.get("secret") and f.get("connection", True)] + ["params", "tls"]


def changed_fields(connector, saved, inputs, level):
    fields = connection_fields(connector)
    if not saved:
        return fields
    want = dict(inputs, tls=level)
    out = []
    for k in fields:
        a, b = saved.get(k), want.get(k)
        if k == "params":
            a, b = a or {}, b or {}
        elif k == "port":
            a, b = int(a or 0), int(b or 0)
        elif a in (None, "") and b in (None, ""):
            continue
        if a != b:
            out.append(k)
    return out
