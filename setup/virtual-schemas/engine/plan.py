"""Connectors, inputs and the plan.

Everything here is pure: it decides WHAT a connect will do from the
connector definition, the user's inputs and a snapshot of facts about the
database, without touching either. lifecycle.py applies the plan; --dry-run
prints it and stops.
"""

import json
import os
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
        if f.is_file():
            with open(f, "r", encoding="utf-8") as fh:
                c = json.load(fh)
            found[c["id"]] = c
    return found


def find_connector(connectors, name):
    n = (name or "").strip().lower()
    for c in connectors.values():
        if n == c["id"] or n == c["label"].lower() or n in c.get("aliases", []):
            return c
    raise PlanError("unknown source %r (available: %s)" % (
        name, ", ".join(sorted(connectors))))


# --- inputs -----------------------------------------------------------------------
# Precedence: explicit flag > EXAKIT_VS_* environment > pasted URL > prompt.

ENV = {
    "source": "EXAKIT_VS_SOURCE", "name": "EXAKIT_VS_NAME", "url": "EXAKIT_VS_JDBC_URL",
    "host": "EXAKIT_VS_HOST", "port": "EXAKIT_VS_PORT", "database": "EXAKIT_VS_DATABASE",
    "user": "EXAKIT_VS_USER", "schema": "EXAKIT_VS_SCHEMA", "tls": "EXAKIT_VS_TLS",
}


def from_env(environ=None):
    environ = os.environ if environ is None else environ
    return {k: environ[v] for k, v in ENV.items() if environ.get(v)}


def merge_url(connector, inputs, notes):
    """Fold a pasted connection string into the field inputs; explicit fields
    win over what the URL says."""
    if not inputs.get("url"):
        return inputs
    fields, url_notes = net.parse_url(connector, inputs["url"])
    notes.extend(url_notes)
    out = dict(inputs)
    for k in ("host", "port", "database", "user"):
        if fields.get(k) is not None and not out.get(k):
            out[k] = fields[k]
    params = dict(fields.get("params") or {})
    tls_param = connector["tls"]["param"]
    if tls_param in params and not out.get("tls"):
        mapped = connector["tls"].get("from_url", {}).get(params[tls_param])
        if mapped:
            out["tls"] = mapped
    # The kit owns the TLS parameters; everything else allowed rides along.
    tls_keys = set()
    for lvl in connector["tls"]["levels"].values():
        tls_keys.update(lvl["params"])
    out["params"] = {k: v for k, v in params.items() if k not in tls_keys}
    return out


def validate(connector, inputs):
    v = dict(inputs)
    v["host"] = net.validate_host(v.get("host"))
    v["port"] = net.validate_port(v.get("port") or connector["url"]["default_port"])
    for f in connector["inputs"]:
        if f.get("secret"):
            continue
        if f.get("required") and not v.get(f["id"]) and f.get("default") is None:
            raise PlanError("%s is required" % f["label"])
        if not v.get(f["id"]) and f.get("default") is not None:
            v[f["id"]] = f["default"]
    v["name"] = sql.validate_name(v.get("name"))
    if v.get("tls") and v["tls"] not in TLS_LABELS:
        raise PlanError("EXAKIT_VS_TLS must be verify, encrypt or none (got %r)" % v["tls"])
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
    return default if default in offer else offer[0]


def url_params(connector, level, extra):
    params = dict(extra or {})
    params.update(connector["tls"]["levels"][level]["params"])
    return params


# --- properties and the plan ----------------------------------------------------------

def vs_properties(connector, conn_name, inputs):
    props = {"CONNECTION_NAME": conn_name}
    for k, tmpl in connector["properties"].items():
        props[k] = tmpl.format(**{f["id"]: inputs.get(f["id"], "") for f in connector["inputs"]
                                  if not f.get("secret")})
    return props


def restart_needed(facts):
    """Java recorded but not active (a run interrupted between the install and
    the restart) needs the restart just as much as Java never installed."""
    return not facts.get("java_installed") or facts.get("java_active") is False


def build_plan(connector, inputs, facts):
    """facts: java_installed, java_active (True|False|None=unknown),
    adapter_cached, driver_cached, adapter_staged, driver_registered,
    dns (ok|missing|unknown|inactive), connection_exists, connection_owned,
    schema_exists, schema_owned, adapter_schema_foreign, script_exists."""
    names = sql.object_names(inputs["name"])
    script = sql.adapter_script_name(connector["id"], connector["adapter"]["version"])
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

    add("java", "Install the Java runtime in the database (exasol slc install java)",
        not facts.get("java_installed"), consent=True)
    add("download", "Download and verify %s %s and %s %s" % (
        connector["label"], "adapter " + connector["adapter"]["version"],
        connector["driver"]["name"], connector["driver"]["version"]),
        not (facts.get("adapter_cached") and facts.get("driver_cached")))
    add("stage", "Stage the adapter in BucketFS (exakit-vs/%s/%s)" % (
        connector["id"], connector["adapter"]["version"]), not facts.get("adapter_staged"))
    add("driver", "Register the JDBC driver %s" % connector["driver"]["settings"]["DRIVERNAME"],
        not facts.get("driver_registered"))
    add("restart", "Restart the database once, to activate the Java runtime",
        restart_needed(facts), consent=True)
    add("dns", "Link name resolution into the Java sandbox (temporary workaround)",
        facts.get("dns") != "ok")
    add("connection", "Create connection %s (password stored only there)" % names["connection"])
    add("probe", "Test the source and its schema from inside the database")
    add("script", "Create adapter script %s.%s" % (sql.ADAPTER_SCHEMA, script),
        not facts.get("script_exists"))
    add("schema", "%s virtual schema %s" % (
        "Refresh" if facts.get("schema_exists") else "Create", names["schema"]))
    add("verify", "Read real rows through the virtual schema")
    return {"source": inputs["name"], "connector": connector["id"], "objects": dict(names, script="%s.%s" % (
        sql.ADAPTER_SCHEMA, script)), "restart_needed": restart_needed(facts), "steps": steps}


# The fields that make up a source's connection. A re-run of connect that
# changes any of them must rebuild the CONNECTION, which needs the password.
CONNECTION_FIELDS = ("host", "port", "database", "user", "params", "tls")


def changed_fields(saved, inputs, level):
    if not saved:
        return list(CONNECTION_FIELDS)
    want = dict(inputs, tls=level)
    out = []
    for k in CONNECTION_FIELDS:
        a, b = saved.get(k), want.get(k)
        if k == "params":
            a, b = a or {}, b or {}
        if k == "port":
            a, b = int(a or 0), int(b or 0)
        if a != b:
            out.append(k)
    return out
