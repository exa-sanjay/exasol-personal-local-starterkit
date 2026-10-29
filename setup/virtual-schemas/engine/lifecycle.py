"""connect and the source lifecycle: check, reauth, refresh, remove, list, show.

Every command returns (exit_code, result_dict). The result is the --json
answer; the screen is written as the command goes. Exit codes are the kit's:
0 ok, 1 failed, 2 bad input, 3 database not running, 4 not installed,
5 a change that needs consent nobody gave.

Rules every command here keeps:
  - The lock is taken BEFORE anything is looked at, so two commands never
    plan from the same snapshot.
  - A connection is only ever replaced by one that was just proven to work:
    new details go into a staging connection first, and only a successful
    probe promotes them. A wrong password never overwrites working ones.
  - A first connect that fails takes back what it made; nothing half-built is
    left for `source list` to show.
  - Only objects carrying the kit's COMMENT are ever dropped, and an object
    someone else still depends on is kept with a warning, never forced.
  - "Ready" is only said after rows came back through the virtual schema.
"""

import os
import re
import sys
import time

from . import artifacts, net, plan, runtime, sql, state, ui as ui_mod

MCP_USER = "mcp_readonly"


class Fail(Exception):
    def __init__(self, code, message, remedy=None, hint=None, kind=None):
        super().__init__(message)
        self.code, self.remedy, self.hint, self.kind = code, remedy, hint, kind


# --- what to tell the user about a failure ---------------------------------------------

def _connect_cmd(cfg, *extra):
    parts = ["exakit connect", cfg.get("connector") or "<source>", "--name", (cfg.get("name") or "<name>").lower()]
    return " ".join(parts + list(extra))


def explain(kind, cfg, detail, first_time=False):
    """(message, remedy, hint) for a classified source failure. On a first
    connect nothing was kept, so the fix is always the connect itself."""
    name = (cfg.get("name") or "<name>").lower()
    host, port = cfg.get("host"), cfg.get("port")
    where = "%s:%s" % (host, port)
    again = _connect_cmd(cfg)
    pw_hint = "Pass the password with --password-file <path> (or answer the prompt)."
    rt = plan.RUNTIME_LABELS.get((cfg.get("artifacts") or {}).get("runtime", "java"), "Java")
    table = {
        "auth": ("The source refused the user name or password.",
                 again if first_time else "exakit source reauth %s" % name,
                 "Check both: the user was '%s', and it must be a user of the source database, "
                 "not of Exasol." % (cfg.get("user") or "?")),
        "network": ("The database cannot reach %s." % where, None,
                    "The connection starts INSIDE the database container, not on this PC. If the "
                    "source runs on this computer (or in a container), publish its port and use "
                    "localhost; a source on a company network may be unreachable over a VPN that "
                    "does not route WSL/Podman traffic."),
        "unresolvable": ("%s does not resolve to an address, not even from this PC." % host, None,
                         "Check the spelling of the host name, or use its IP address."),
        "dns": ("The database's Java runtime could not resolve %s." % host,
                "exakit source check %s" % name,
                "The Java sandbox needs the name-resolution links the kit adds after every database "
                "start; check puts them back. An IP address instead of the name always works."),
        "tls": ("The encrypted connection to %s failed." % where,
                _connect_cmd(cfg, "--tls", "none"),
                "If the source does not offer TLS at all, an unencrypted connection is allowed for "
                "hosts on this machine or a private network. " + pw_hint),
        "tls_policy": ("The database's Java security policy blocked the connection.",
                       "exakit source check %s" % name,
                       "The driver registration is missing NOSECURITY=YES; check re-registers it."),
        "database_missing": ("The source has no database named %r." % cfg.get("database"), None,
                             "Check the database name; re-run connect with the right one."),
        "schema_missing": ("The source database has no schema named %r." % cfg.get("schema"), None,
                           "Check the schema name (it is case-sensitive); re-run connect with --schema."),
        "permission": ("User %r may not read schema %r on the source." % (cfg.get("user"), cfg.get("schema")),
                       None, "Grant the user USAGE on the schema and SELECT on its tables, then: "
                             "exakit source check %s" % name),
        "driver_not_registered": ("The JDBC driver registration is missing.",
                                  "exakit source check %s" % name, None),
        "slc_missing": ("The %s runtime is not active in the database." % rt,
                        _connect_cmd(cfg, "--yes"),
                        "Activating it restarts the database once; --yes consents."),
        "runtime_mismatch": ("The adapter was built for another %s runtime version than the one "
                             "active in the database." % rt, _connect_cmd(cfg, "--yes"),
                             "Connecting again installs the runtime version this kit pins (one restart)."),
        "mixed_case": ("The source has mixed-case table names the adapter refused.", None, None),
    }
    return table.get(kind, ("The source could not be used: %s" % detail, None, None))


def _source_fail(cfg, kind, err, first_time=False):
    detail = sql.short(str(err)) if err else ""
    if kind == "network" and cfg.get("host") and not net.is_ip(cfg["host"]) and \
            net.classify_host(cfg["host"]) != "loopback" and not net.resolve_here(cfg["host"]):
        kind = "unresolvable"
    msg, remedy, hint = explain(kind, cfg, detail, first_time)
    if detail and kind not in ("unknown",):
        hint = "%s (engine said: %s)" % (hint, detail) if hint else "(engine said: %s)" % detail
    return Fail(1, msg, remedy, hint, kind)


# --- the session every command shares ---------------------------------------------------

class Ctx:
    def __init__(self, args):
        self.args = args
        self.json = bool(getattr(args, "json", False))
        if self.json:
            # A JSON caller is a program: never block it on a prompt it cannot see.
            os.environ["EXAKIT_VS_NONINTERACTIVE"] = "1"
        self.ui = ui_mod.UI(json_mode=self.json, quiet=self.json)
        try:
            self.manifest = state.read_manifest()
        except state.NotInstalled as e:
            raise Fail(4, str(e), "irm https://www.exasol.com/install/starter-kit.ps1 | iex"
                       if os.name == "nt" else "curl -fsSL https://www.exasol.com/install/starter-kit.sh | sh",
                       kind="not_installed")
        try:
            self.rt = runtime.Runtime(self.manifest)
        except runtime.RuntimeError_ as e:
            raise Fail(2, str(e), kind=e.kind)
        self._db = None

    @property
    def db(self):
        if self._db is None:
            try:
                self._db = sql.Db(self.manifest)
            except sql.SqlError as e:
                state.log("WARN", "database connection: %s" % e)
                raise Fail(3, "The database is not running or does not accept connections.",
                           "exakit start", None, "db_down")
        return self._db

    def reconnect(self):
        if self._db:
            self._db.close()
        self._db = None
        return self.db

    def wait_ready(self, deadline):
        while True:
            try:
                self.reconnect().value("SELECT 1")
                return
            except (Fail, sql.SqlError):
                if time.time() > deadline:
                    raise Fail(3, "The database did not come back after the restart.", "exakit status",
                               None, "db_down")
                time.sleep(3)

    def lock(self):
        return state.Lock(on_wait=lambda: self.ui.info(
            "Waiting for another exakit connect/source command to finish"))


def consent(ctx, question):
    """yes/no for a database restart, through the kit's consent model."""
    if getattr(ctx.args, "yes", False):
        return True
    preset = (os.environ.get("EXAKIT_CONFIRM_RUNTIME_UPDATE") or "").strip().lower()
    if preset in ("1", "y", "yes"):
        return True
    if preset in ("0", "n", "no"):
        return False
    if ui_mod.interactive():
        return ctx.ui.confirm(question, default=True)
    return None  # nobody to ask


def _owned(rows):
    return bool(rows) and (rows[0][0] or "") == sql.MARKER


def _comment(kind, name):
    return "COMMENT ON %s %s IS %s" % (kind, name, sql.literal(sql.MARKER))


# --- the Java sandbox: is Java active, can it resolve names ------------------------------

def sandbox_net(ctx, mode, arg="", create=True):
    """Ask the kit's probe UDF inside the Java sandbox. Returns its answer,
    'inactive' when Java is not active in the database, or 'unknown'."""
    db = ctx.db
    exists = db.run("SELECT 1 FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = %s AND SCRIPT_NAME = %s"
                    % (sql.literal(sql.ADAPTER_SCHEMA), sql.literal(sql.NET_PROBE)))
    if not exists:
        if not create:
            return "unknown"
        _ensure_adapter_schema(ctx)
        try:
            # Creating a Java script already needs Java ACTIVE in the database,
            # so this is where a recorded-but-not-yet-active Java shows first.
            db.run(sql.create_net_probe(), fetch=False)
        except sql.SqlError as e:
            if e.kind == "slc_missing":
                return "inactive"
            raise
        db.run(_comment("SCRIPT", "%s.%s" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(sql.NET_PROBE))),
               fetch=False)
    try:
        return db.value("SELECT %s.%s(%s, %s)" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(sql.NET_PROBE),
                                                   sql.literal(mode), sql.literal(arg or "")))
    except sql.SqlError as e:
        if e.kind == "slc_missing":
            return "inactive"
        state.log("WARN", "sandbox probe: %s" % e)
        return "unknown"


def _ensure_dns(ctx, quiet=False):
    """Make host names resolvable inside the Java sandbox (temporary
    workaround, see runtime.py). Returns (state, fixed): ok | missing |
    inactive | unknown."""
    st = sandbox_net(ctx, "dns")
    if st != "missing":
        return st, False
    if os.environ.get("EXAKIT_VS_DNS_WORKAROUND", "1") == "0":
        # The user asked the kit to leave the database container alone.
        if not quiet:
            ctx.ui.info("The Java sandbox cannot resolve host names; EXAKIT_VS_DNS_WORKAROUND=0, so the "
                        "kit uses IP addresses instead of linking name resolution in.")
        return st, False
    if not ctx.rt.can_link():
        if not quiet:
            ctx.ui.warn("The Java sandbox cannot resolve host names, and the kit cannot reach the "
                        "database container from here to fix it; the kit uses IP addresses instead.")
        return st, False
    try:
        ctx.rt.link_sandbox_dns()
    except runtime.RuntimeError_ as e:
        if not quiet:
            ctx.ui.warn("Could not link name resolution into the Java sandbox: %s" % e)
        return st, False
    st = sandbox_net(ctx, "dns")
    if st == "ok":
        if not quiet:
            ctx.ui.ok("Name resolution linked into the Java sandbox (temporary workaround, redone "
                      "after every database start)")
        return st, True
    if not quiet:
        ctx.ui.warn("Linked name resolution into the Java sandbox, but it still does not resolve; "
                    "the kit uses IP addresses instead.")
    return st, False


# --- facts about the database, for the plan -----------------------------------------------

def _script_languages(ctx):
    """The database's active SCRIPT_LANGUAGES. It lists JAVA, PYTHON3 and R
    whether or not their SLC is installed, so it proves nothing for those;
    a CUSTOM alias (RUST=...) appears only once that SLC is active."""
    try:
        return ctx.db.value("SELECT SYSTEM_VALUE FROM EXA_PARAMETERS WHERE PARAMETER_NAME = 'SCRIPT_LANGUAGES'") or ""
    except sql.SqlError as e:
        state.log("WARN", "SCRIPT_LANGUAGES: %s" % e)
        return ""


def _custom_runtime_version(row, kind, reg=None):
    """The version of the custom SLC registered under the kit's alias: what
    the kit recorded when it installed it, else the version in the source
    file's name, else None (someone else's, unknown)."""
    rec = ((reg or artifacts.load_registry()).get("runtimes") or {}).get(kind) or {}
    src = (row or {}).get("source") or ""
    if rec.get("version") and (not rec.get("file") or os.path.basename(src) == rec["file"]):
        return rec["version"]
    m = re.search(r"lc-%s-(\d+(?:\.\d+)+)" % re.escape(kind), os.path.basename(src))
    return m.group(1) if m else None


def _runtime_facts(ctx, connector, dry_run, foreign_adapter_schema):
    kind = plan.runtime_kind(connector)
    if kind == "lua":
        return {"runtime": kind, "runtime_installed": True, "runtime_active": True,
                "runtime_conflict": None, "dns": "n/a"}
    if kind == "java":
        java = ctx.rt.slc("java")
        installed = bool(java and java["installed"] and java.get("type", "official") == "official")
        # Java "installed" (the launcher's record) is not Java ACTIVE: a run
        # interrupted between the install and the restart has the first without
        # the second. Only the sandbox can say - and a dry run must not create
        # the probe, so there an unknown is taken at the launcher's word.
        dns, active = "unknown", installed
        if installed and not foreign_adapter_schema:
            dns = sandbox_net(ctx, "dns", create=not dry_run)
            active = None if dns == "unknown" else dns != "inactive"
        return {"runtime": kind, "runtime_installed": installed, "runtime_active": active if installed else False,
                "runtime_conflict": None, "dns": dns}
    spec = plan.runtime_spec(kind)
    row = ctx.rt.slc(spec["alias"])
    installed = bool(row and row["installed"] and row.get("type") == "custom")
    conflict = None
    if installed:
        version = _custom_runtime_version(row, kind)
        if version != spec["version"]:
            conflict = version or "of an unknown version"
    active = installed and ("%s=" % spec["alias"]) in _script_languages(ctx)
    return {"runtime": kind, "runtime_installed": installed, "runtime_active": active,
            "runtime_conflict": conflict, "dns": "n/a"}


def gather_facts(ctx, connector, inputs, dry_run=False):
    db, rt = ctx.db, ctx.rt
    names = sql.object_names(inputs["name"])
    ad = plan.adapter(connector)
    script = sql.adapter_script_name(connector["id"], ad["version"], ad.get("script_name"))
    exa = rt.exa_root
    adapter_cache = state.cache_dir() / ad["sha256"] / ad["file"]
    staged = exa / artifacts.BUCKET_DIR / artifacts.bucket_rel(connector) / ad["stage_name"]
    drv = plan.driver(connector)
    driver_cache, registered = False, True
    if drv:
        driver_cache = (state.cache_dir() / drv["sha256"] / drv["file"]).is_file()
        ddir = artifacts.driver_dir(exa, drv)
        registered = (ddir / drv["file"]).is_file() and (ddir / "settings.cfg").is_file() and \
            (ddir / "settings.cfg").read_bytes() == artifacts.settings_cfg(drv)
    conn = db.run("SELECT CONNECTION_COMMENT FROM SYS.EXA_DBA_CONNECTIONS WHERE CONNECTION_NAME = %s"
                  % sql.literal(names["connection"]))
    schema = db.run("SELECT SCHEMA_IS_VIRTUAL, SCHEMA_COMMENT FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s"
                    % sql.literal(names["schema"]))
    vs_ours = bool(db.run("SELECT 1 FROM SYS.EXA_ALL_VIRTUAL_SCHEMAS WHERE SCHEMA_NAME = %s AND "
                          "ADAPTER_SCRIPT_SCHEMA = %s" % (sql.literal(names["schema"]),
                                                          sql.literal(sql.ADAPTER_SCHEMA))))
    adapter_schema = db.run("SELECT SCHEMA_COMMENT FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s"
                            % sql.literal(sql.ADAPTER_SCHEMA))
    script_rows = db.run("SELECT 1 FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = %s AND SCRIPT_NAME = %s"
                         % (sql.literal(sql.ADAPTER_SCHEMA), sql.literal(script)))
    foreign_adapter_schema = bool(adapter_schema) and not _owned(adapter_schema)
    facts = _runtime_facts(ctx, connector, dry_run, foreign_adapter_schema)
    schema_owned = bool(schema) and vs_ours and (
        (schema[0][1] or "") == sql.MARKER or state.source_dir(inputs["name"]).is_dir())
    facts.update({
        "adapter_cached": adapter_cache.is_file(),
        "driver_cached": driver_cache,
        # A Lua adapter lives in the script text: there is nothing to stage.
        "adapter_staged": staged.is_file() or facts["runtime"] == "lua",
        "driver_registered": registered,
        "connection_exists": bool(conn),
        "connection_owned": _owned(conn),
        "schema_exists": bool(schema),
        "schema_owned": schema_owned,
        "adapter_schema_foreign": foreign_adapter_schema,
        "script_exists": bool(script_rows),
    })
    return facts


# --- inputs ---------------------------------------------------------------------------------

def _ask_inputs(ctx, connectors, inputs, url_from):
    """Fill what is missing - by prompt when there is a terminal, otherwise
    refuse with the variable that answers it. Precedence: flag > environment
    > pasted URL > what this source was given last time > prompt/default."""
    u = ctx.ui
    tty = ui_mod.interactive()
    if inputs.get("name"):
        try:
            sql.validate_name(inputs["name"])
        except ValueError as e:
            raise Fail(2, str(e))

    if not inputs.get("source"):
        if not tty:
            raise Fail(2, "The source type is required: pass it (exakit connect postgresql), or set "
                          "EXAKIT_VS_SOURCE")
        inputs["source"] = u.choose("Which source do you want to connect?",
                                    [(c["id"], c["label"]) for c in connectors.values()])
    try:
        connector = plan.find_connector(connectors, inputs["source"])
    except plan.PlanError as e:
        raise Fail(2, str(e))
    why = plan.unavailable_reason(connector)
    if why:
        raise Fail(2, "%s cannot be connected yet: %s" % (connector["label"], why), None, None, "unavailable")
    for k, v in plan.connector_env(connector).items():
        inputs.setdefault(k, v)

    notes = []
    if tty and not inputs.get("url") and not inputs.get("host"):
        pasted = u.ask("Connection string (a JDBC URL, or the endpoint host[:port][/database] as a cloud console shows it; Enter to type the fields)")
        if pasted:
            inputs["url"], url_from = pasted, "prompt"
    try:
        inputs = plan.merge_url(connector, inputs, notes)
    except net.UrlError as e:
        raise Fail(2, str(e))
    for key, text in notes:
        if key == "password_stripped" and url_from in ("flag", "env"):
            text += (" It was given on the command line or in the environment, so it may already be "
                     "in your shell history; consider changing it.")
        u.warn(text)

    saved = state.read_json(state.source_dir(inputs["name"]) / "config.json") if inputs.get("name") else None
    if saved:
        # Re-running connect for a known name finishes or repairs it: what was
        # entered last time fills what was not given now - never the reverse.
        for k in plan.input_ids(connector) + ["tls", "params"]:
            if not inputs.get(k) and saved.get(k) is not None:
                inputs[k] = saved[k]

    for f in connector["inputs"]:
        if f.get("secret") or inputs.get(f["id"]):
            continue
        env = plan.env_var(f["id"])
        if not tty:
            if f.get("default") is not None:
                inputs[f["id"]] = f["default"]
                continue
            if not f.get("required"):
                continue
            raise Fail(2, "%s is required: set %s (or EXAKIT_VS_JDBC_URL)" % (f["label"], env))
        answer = u.ask(f["label"] + ("" if f.get("required") else " (optional)"), str(f.get("default") or ""))
        if answer:
            inputs[f["id"]] = answer
    if not inputs.get("name"):
        default = "".join(ch for ch in (inputs.get("database") or "src") if ch.isalnum() or ch == "_")
        if not default or not default[0].isalpha():
            default = "src_" + default
        if not tty:
            raise Fail(2, "A name for the source is required: set EXAKIT_VS_NAME")
        inputs["name"] = u.ask("Name in Exasol (becomes VS_<NAME>)", default)
    return connector, inputs, saved


def _decode_secret_bytes(data, where):
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if data.startswith(bom):
            return data[len(bom):].decode(enc)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise Fail(2, "%s is not UTF-8 text. Save it as UTF-8 (in Windows PowerShell 5.1: "
                      "Set-Content -Encoding utf8)." % where)


def _read_password(ctx, user, required=True, secret_label="Password", can_keep=False):
    a = ctx.args
    path = getattr(a, "password_file", None) or os.environ.get("EXAKIT_VS_PASSWORD_FILE")
    pw = None
    if path:
        try:
            with open(path, "rb") as f:
                pw = _decode_secret_bytes(f.read(), "The password file").rstrip("\r\n")
        except OSError as e:
            raise Fail(2, "cannot read the password file %s: %s" % (path, e.strerror))
    elif getattr(a, "password_stdin", False):
        pw = sys.stdin.readline().rstrip("\r\n")
    elif ui_mod.interactive():
        # Only offered when there IS a stored one to keep: on a first connect
        # the line promised a password that did not exist.
        keep = ", Enter keeps the stored one" if can_keep else ""
        who = " for %s" % user if user else ""
        pw = ctx.ui.ask_secret("%s%s (hidden%s)" % (secret_label, who, keep))
    if not pw and not required:
        return None
    if not pw:
        raise Fail(2, "A password is required: use --password-file <path>, --password-stdin, or "
                      "EXAKIT_VS_PASSWORD_FILE. There is deliberately no --password option: "
                      "a command line is readable by every process on this machine.")
    state.register_secret(pw)
    return pw


# --- establishing the connection ------------------------------------------------------------

def _probe_target(connector, conn_name):
    """The connection a probe reads through and how: the main JDBC one with
    the kit's driver named, or - for a connector whose check says "via" -
    one of its extra connections (Exasol: IMPORT FROM EXA)."""
    chk = connector["check"]
    drv = plan.driver(connector)
    return (conn_name + chk.get("via", ""), drv["settings"]["DRIVERNAME"] if drv else None,
            chk.get("kind", "jdbc"))


def _probe(ctx, connector, conn_name, cfg=None, host=None):
    if connector["check"].get("kind") == "vs":
        _probe_vs(ctx, connector, conn_name, cfg, host)
        return
    target, drv, kind = _probe_target(connector, conn_name)
    ctx.db.run(sql.import_probe(target, drv, connector["check"]["statement"], kind))


def _probe_vs(ctx, connector, conn_name, cfg, host):
    """A source with no JDBC side to read through (native and REST adapters):
    the adapter itself is the probe. Creating a virtual schema on the
    candidate connection makes it reach the source, log in and read the
    catalog; the throwaway schema is dropped again either way."""
    db = ctx.db
    names = dict(cfg["objects"], connection=conn_name)
    probe = cfg["objects"]["schema"] + "_PROBE"
    script = cfg["objects"]["script"].split(".", 1)[1]
    rows = db.run("SELECT SCHEMA_IS_VIRTUAL FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s" % sql.literal(probe))
    ours = db.run("SELECT 1 FROM SYS.EXA_ALL_VIRTUAL_SCHEMAS WHERE SCHEMA_NAME = %s AND ADAPTER_SCRIPT_SCHEMA = %s"
                  % (sql.literal(probe), sql.literal(sql.ADAPTER_SCHEMA)))
    if rows and not ours:
        raise Fail(2, "A schema named %s exists and was not created by the kit; the kit needs that name "
                      "for a moment to test the source. Rename or drop it." % probe)
    props = plan.vs_properties(connector, names, cfg, host or cfg.get("db_host") or cfg.get("host"))
    try:
        if ours:
            db.run("DROP VIRTUAL SCHEMA %s CASCADE" % sql.ident(probe), fetch=False)
        db.run(sql.create_virtual_schema(probe, script, props), fetch=False)
    finally:
        try:
            db.run("DROP VIRTUAL SCHEMA IF EXISTS %s CASCADE" % sql.ident(probe), fetch=False)
        except (sql.SqlError, Fail) as e:
            state.log("WARN", "probe schema %s: %s" % (probe, e))


def _probe_schema(ctx, connector, conn_name, cfg, first_time):
    """Does the source schema exist, and may the user read it? Exasol does
    not ask: a virtual schema over a missing schema is created empty."""
    tmpl = connector["check"].get("schema")
    if not tmpl or connector["check"].get("kind") == "vs":
        return
    statement = plan.render(tmpl, {k: sql.literal(cfg.get(k) or "") for k in plan.input_ids(connector)})
    target, drv, kind = _probe_target(connector, conn_name)
    try:
        answer = ctx.db.value(sql.import_probe(target, drv, statement, kind))
    except sql.SqlError as e:
        raise _source_fail(cfg, e.kind, e, first_time)
    if answer == "missing":
        raise _source_fail(cfg, "schema_missing", None, first_time)
    if answer == "denied":
        raise _source_fail(cfg, "permission", None, first_time)


def _db_host(ctx, cfg, candidate, dns_state):
    """The host to write into the CONNECTION. A name is kept when the Java
    sandbox can resolve it (the adapter connects from there on every query);
    otherwise its address - as the sandbox's own hosts file maps it, else as
    this machine resolves it - and the caller is told. dns_state 'n/a': a
    runtime that resolves names itself (Rust, Lua) - the name is kept."""
    if net.is_ip(candidate) or dns_state in ("ok", "n/a") or net.classify_host(candidate) == "loopback":
        return candidate, False
    ip = sandbox_net(ctx, "resolve", candidate)
    if not ip or ip in ("unknown", "inactive"):
        here = net.resolve_here(candidate)
        ip = here[0] if here else ""
    return (ip, True) if ip else (candidate, False)


def _establish(ctx, connector, cfg, names, level, host_cls, password, dns_state, first_time):
    """Prove new connection details through a staging connection, then
    promote them to the real one. Walks the host candidates and - only with
    the user's say-so - the TLS levels. Returns (db_host, level, ip_fallback)."""
    u = ctx.ui
    staging = names["connection"] + "_NEW"
    offer = plan.tls_offer(connector, host_cls)
    prepare = plan.hook(connector, "prepare")
    if prepare:
        # e.g. Exasol: the server certificate's fingerprint, read from here.
        cfg.update(prepare(connector, cfg) or {})
    # localhost inside the database is the database itself: right for a
    # connector whose source IS this database (Exasol), wrong for any other,
    # which is reached through the container's host alias instead.
    if host_cls == "loopback" and connector.get("loopback", "alias") == "alias":
        candidates = [net.HOST_ALIAS]
    else:
        candidates = [cfg["host"]]
    made = [staging]
    user = plan.connection_user(connector, cfg)
    try:
        while True:
            last = None
            for cand in candidates:
                host, fallback = _db_host(ctx, cfg, cand, dns_state)
                url = plan.build_url(connector, host, cfg, level)
                extras = plan.extra_connections(connector, names, host, cfg, level)
                # The secret may wrap the password (a JSON document of keys);
                # it is a secret as a whole, so the log never shows it either.
                secret = plan.connection_secret(connector, dict(cfg, db_host=host), password)
                if secret != password:
                    state.register_secret(secret)
                ctx.db.run(sql.create_connection(staging, url, user, secret), fetch=False)
                ctx.db.run(sql.comment_connection(staging), fetch=False)
                for suffix, target in extras:
                    made.append(staging + suffix)
                    ctx.db.run(sql.create_connection(staging + suffix, target, user, secret), fetch=False)
                    ctx.db.run(sql.comment_connection(staging + suffix), fetch=False)
                try:
                    _probe(ctx, connector, staging, dict(cfg, tls=level), host)
                except sql.SqlError as e:
                    last = e
                    state.log("INFO", "probe %s failed: %s" % (host, e.kind))
                    if e.kind in ("network", "dns"):
                        continue
                    break
                _probe_schema(ctx, connector, staging, cfg, first_time)
                ctx.db.run(sql.create_connection(names["connection"], url, user, secret), fetch=False)
                ctx.db.run(sql.comment_connection(names["connection"]), fetch=False)
                for suffix, target in extras:
                    full = names["connection"] + suffix
                    ctx.db.run(sql.create_connection(full, target, user, secret), fetch=False)
                    ctx.db.run(sql.comment_connection(full), fetch=False)
                names["extra_connections"] = [names["connection"] + sfx for sfx, _ in extras]
                u.ok("The database reaches %s:%s (%s)" % (host, cfg["port"], plan.TLS_LABELS[level]))
                if fallback:
                    u.warn("The database's Java runtime cannot resolve %s, so the connection uses its "
                           "address %s. If that address changes, run: exakit source check %s"
                           % (cand, host, cfg["name"].lower()))
                if level != "verify" and host_cls == "public":
                    u.warn("The connection is encrypted, but the server's certificate is not verified "
                           "(Exasol Personal cannot yet). Use it only over networks you trust.")
                return host, level, fallback
            kind = last.kind if last else "unknown"
            if kind == "tls":
                lower = [l for l in offer if offer.index(l) > offer.index(level)] if level in offer else []
                if not lower or not ui_mod.interactive():
                    raise _source_fail(dict(cfg, tls=level), kind, last, first_time)
                u.warn("The encrypted connection failed: %s" % sql.short(str(last)))
                choice = u.choose("How should the kit continue?",
                                  [(l, "Use a connection that is %s" % plan.TLS_LABELS[l]) for l in lower]
                                  + [("stop", "Stop - I will fix TLS on the source")])
                if choice == "stop":
                    raise Fail(1, "Stopped at your request.", None, None, kind)
                level = choice
                continue
            raise _source_fail(cfg, kind, last, first_time)
    finally:
        for name in made:
            try:
                ctx.db.run("DROP CONNECTION IF EXISTS %s" % sql.ident(name), fetch=False)
            except (sql.SqlError, Fail):
                pass


# --- shared database objects -----------------------------------------------------------------

def _ensure_adapter_schema(ctx):
    rows = ctx.db.run("SELECT SCHEMA_COMMENT FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s"
                      % sql.literal(sql.ADAPTER_SCHEMA))
    if rows and not _owned(rows):
        raise Fail(2, "A schema named %s exists and was not created by the kit; the kit will not put "
                      "its adapter scripts there." % sql.ADAPTER_SCHEMA)
    if not rows:
        ctx.db.run("CREATE SCHEMA %s" % sql.ident(sql.ADAPTER_SCHEMA), fetch=False)
        ctx.db.run(_comment("SCHEMA", sql.ident(sql.ADAPTER_SCHEMA)), fetch=False)


def _ensure_adapter_script(ctx, connector, cfg):
    """The adapter script in the kit's schema, in the source's runtime - and
    the companion scripts the adapter calls by name, which must live in the
    same schema. Idempotent: CREATE OR REPLACE throughout."""
    script = cfg["objects"]["script"].split(".", 1)[1]
    bucket = cfg["artifacts"]["bucket"]
    kind = plan.runtime_kind(connector)
    udf = None
    _ensure_adapter_schema(ctx)
    if kind == "java":
        jar = "%s/%s/%s" % (artifacts.BUCKET_PREFIX, bucket, cfg["artifacts"]["adapter_file"])
        jars = [jar]
        if plan.driver(connector) and not connector["driver"].get("bundled_in_adapter") and \
                cfg["artifacts"].get("driver_file"):
            jars.append("%s/%s/%s" % (artifacts.BUCKET_PREFIX, bucket, cfg["artifacts"]["driver_file"]))
        stmt = sql.create_adapter_script(script, connector["script"]["class"],
                                         connector["script"]["jvm_options"], jars)
    elif kind == "lua":
        ad = plan.adapter(connector)
        source = artifacts.fetch(ad, ctx.ui).read_text(encoding="utf-8")
        patch = plan.hook(connector, "adapter_source")
        if patch:
            source = patch(connector, source, cfg)
        stmt = sql.create_lua_adapter_script(script, source, (connector.get("script") or {}).get("preamble", ""))
    else:
        udf = artifacts.udf_object(bucket, cfg["artifacts"]["adapter_file"])
        stmt = sql.create_rust_adapter_script(script, udf, plan.runtime_spec(kind)["alias"])
    ctx.db.run(stmt, fetch=False)
    ctx.db.run(_comment("SCRIPT", "%s.%s" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(script))), fetch=False)
    for comp in connector.get("scripts", []):
        ctx.db.run(sql.companion_script(comp["sql"], udf or ""), fetch=False)
        ctx.db.run(_comment("SCRIPT", "%s.%s" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(comp["name"]))),
                   fetch=False)
    return script


def _vs_call(ctx, cfg, statement, first_time=False):
    try:
        ctx.db.run(statement, fetch=False)
    except sql.SqlError as e:
        raise _source_fail(cfg, e.kind, e, first_time)


def _ensure_virtual_schema(ctx, connector, cfg, refresh=True, first_time=False):
    """Create the virtual schema, or bring an existing one up to date without
    ever dropping it for a property change: ALTER ... SET leaves a working
    schema in place if the new value is refused. Only a change of adapter
    script (an adapter upgrade) has to recreate it."""
    db, names = ctx.db, cfg["objects"]
    script = cfg["objects"]["script"].split(".", 1)[1]
    props = plan.vs_properties(connector, names, cfg, cfg.get("db_host"))
    vs = sql.ident(names["schema"])
    adapter = db.value("SELECT ADAPTER_SCRIPT_NAME FROM SYS.EXA_ALL_VIRTUAL_SCHEMAS WHERE SCHEMA_NAME = %s"
                       % sql.literal(names["schema"]))
    if adapter and adapter != script:
        ctx.ui.info("Moving %s to the adapter %s" % (names["schema"], script))
        db.run("DROP VIRTUAL SCHEMA %s CASCADE" % vs, fetch=False)
        adapter = None
    if not adapter:
        _vs_call(ctx, cfg, sql.create_virtual_schema(names["schema"], script, props), first_time)
        db.run(_comment("SCHEMA", vs), fetch=False)
        ctx.ui.ok("Virtual schema %s created" % names["schema"])
        return "created"
    current = dict(db.run("SELECT PROPERTY_NAME, PROPERTY_VALUE FROM SYS.EXA_ALL_VIRTUAL_SCHEMA_PROPERTIES "
                          "WHERE SCHEMA_NAME = %s" % sql.literal(names["schema"])))
    changed = {k: v for k, v in props.items() if current.get(k) != v}
    if changed:
        _vs_call(ctx, cfg, "ALTER VIRTUAL SCHEMA %s SET %s" % (
            vs, " ".join("%s = %s" % (k, sql.literal(v)) for k, v in changed.items())), first_time)
        ctx.ui.ok("Virtual schema %s updated (%s)" % (names["schema"], ", ".join(sorted(changed))))
    elif refresh:
        _vs_call(ctx, cfg, "ALTER VIRTUAL SCHEMA %s REFRESH" % vs, first_time)
        ctx.ui.ok("Virtual schema %s refreshed" % names["schema"])
    db.run(_comment("SCHEMA", vs), fetch=False)
    return "updated" if changed else "refreshed"


def _verify(ctx, cfg, first_time=False):
    """Read rows through the virtual schema, as the admin and as the MCP
    read-only user. The first table that answers is proof enough; one
    unreadable table does not fail the source."""
    db, names = ctx.db, cfg["objects"]
    tables = [r[0] for r in db.run("SELECT TABLE_NAME FROM SYS.EXA_ALL_TABLES WHERE TABLE_SCHEMA = %s "
                                   "ORDER BY TABLE_NAME" % sql.literal(names["schema"]))]
    out = {"tables": tables, "rows_read": False, "sample_query": None, "mcp_readable": None}
    if not tables:
        where = cfg.get("schema") or cfg.get("namespace") or cfg.get("database") or cfg.get("collection")
        ctx.ui.warn("Connected, but %r shows no tables%s." % (
            where, " to user %s" % cfg["user"] if cfg.get("user") else ""))
        return out
    first_err, readable = None, None
    for t in tables:
        try:
            rows = db.run("SELECT * FROM %s.%s LIMIT 1" % (sql.ident(names["schema"]), sql.ident(t)))
            readable = (t, len(rows))
            break
        except sql.SqlError as e:
            first_err = first_err or e
    if readable is None:
        raise _source_fail(cfg, first_err.kind, first_err, first_time)
    t, n = readable
    out["rows_read"] = True
    out["sample_query"] = "SELECT * FROM %s.%s LIMIT 10" % (names["schema"], sql.ident(t))
    ctx.ui.ok("%s %s.%s through the virtual schema" % ("Read rows from" if n else "Queried (no rows yet)",
                                                       names["schema"], t))
    pwfile = state.kit_home() / "credentials" / "mcp_readonly_password"
    if pwfile.is_file():
        try:
            ro = sql.Db(ctx.manifest, user=MCP_USER, password_file=str(pwfile))
            ro.run("SELECT * FROM %s.%s LIMIT 1" % (sql.ident(names["schema"]), sql.ident(t)))
            ro.close()
            out["mcp_readable"] = True
        except sql.SqlError as e:
            out["mcp_readable"] = False
            state.log("WARN", "read-only user check: %s" % e)
    return out


def _say_ready(ctx, connector, cfg, result):
    u, names = ctx.ui, cfg["objects"]
    if result["mcp_readable"] is not False:
        u.warn("%s is visible to your AI clients: the MCP read-only user can read every schema, "
               "this one included." % names["schema"])
    for note in connector.get("notes", []):
        u.info(note)
    if result["sample_query"]:
        u.done("Ready: %s" % result["sample_query"])
        if os.name == "nt":
            u.info("From PowerShell, escape the inner quotes: exakit sql '%s'"
                   % result["sample_query"].replace('"', '\\"'))
    else:
        u.done("Connected: %s (no tables visible yet)" % names["schema"])


# --- connect ---------------------------------------------------------------------------------

def _gather_inputs(ctx):
    a = ctx.args
    inputs = plan.from_env()
    url_from = "env" if inputs.get("url") else None
    for k in ("source", "name", "url", "host", "port", "database", "user", "schema", "tls"):
        v = getattr(a, k, None)
        if v:
            inputs[k] = v
            if k == "url":
                url_from = "flag"
    return inputs, url_from


def connect(ctx):
    a, u = ctx.args, ctx.ui
    connectors = plan.load_connectors()
    inputs, url_from = _gather_inputs(ctx)
    connector, inputs, saved = _ask_inputs(ctx, connectors, inputs, url_from)
    try:
        inputs = plan.validate(connector, inputs)
    except (plan.PlanError, net.UrlError, ValueError) as e:
        raise Fail(2, str(e))
    names = sql.object_names(inputs["name"])
    name_l = inputs["name"].lower()
    host_cls = net.classify_host(inputs["host"])
    try:
        requested_level = plan.tls_start(connector, host_cls, inputs.get("tls"))
    except plan.PlanError as e:
        raise Fail(2, str(e))

    u.step("Connecting %s as %s" % (connector["label"], names["schema"]))
    dry_run = getattr(a, "dry_run", False)
    first_time = saved is None
    with ctx.lock():
        facts = gather_facts(ctx, connector, inputs, dry_run=dry_run)
        try:
            p = plan.build_plan(connector, inputs, facts)
        except plan.PlanError as e:
            raise Fail(2, str(e))
        if dry_run:
            for s in p["steps"]:
                (u.info if s["needed"] else u.ok)(("%s" if s["needed"] else "already done: %s") % s["action"])
            return 0, {"ok": True, "status": "planned", "dry_run": True, "plan": p, "tls": requested_level,
                       "remedy": None, "remedy_hint": None}
        cfg = {"schema_version": 2, "name": inputs["name"], "connector": connector["id"]}
        for k in plan.input_ids(connector):
            cfg[k] = inputs.get(k)
        cfg.update(params=inputs.get("params") or {}, tls=requested_level, objects=p["objects"],
                   artifacts=artifacts.describe(connector),
                   created=(saved or {}).get("created") or state.now_iso())
        try:
            result = _connect_locked(ctx, connector, inputs, saved, facts, p, cfg, host_cls,
                                     requested_level, first_time)
        except BaseException:
            # Anything a FIRST connect made is taken back - including the
            # kit's adapter schema and probe when no source is left to use them.
            if first_time:
                _rollback(ctx, cfg)
            raise

    _say_ready(ctx, connector, cfg, result)
    return 0, {"ok": True, "status": "ready" if result["rows_read"] else "connected_empty",
               "source": cfg["name"], "connector": connector["id"], "schema": names["schema"],
               "connection": names["connection"], "tables": result["tables"], "tls": cfg["tls"],
               "db_host": cfg["db_host"], "ip_fallback": cfg.get("ip_fallback", False),
               "sample_query": result["sample_query"], "mcp_visible": True,
               "remedy": None, "remedy_hint": None}


def _connect_locked(ctx, connector, inputs, saved, facts, p, cfg, host_cls, requested_level, first_time):
    """Everything connect does once the plan stands: consent, the password
    (or the reasons it is needed), then _apply."""
    name_l = inputs["name"].lower()
    if p["restart_needed"]:
        kind = facts.get("runtime", "java")
        rt = plan.RUNTIME_LABELS.get(kind, kind)
        if kind == "java":
            question = ("Virtual schemas need the Java runtime inside the database. Activating it restarts "
                        "the database once (the first time takes a few minutes while it downloads; later "
                        "restarts about 30 s). Go ahead?")
        elif facts.get("runtime_conflict"):
            spec = plan.runtime_spec(kind)
            question = ("The database has the %s runtime %s; %s needs %s. Replacing it restarts the "
                        "database once, and %s scripts built for the other version stop loading until "
                        "they are rebuilt. Go ahead?" % (rt, facts["runtime_conflict"], connector["label"],
                                                         spec["version"], rt))
        else:
            question = ("%s runs on the %s runtime, which the kit installs into the database (a pinned, "
                        "verified download). Activating it restarts the database once (about a minute). "
                        "Go ahead?" % (connector["label"], rt))
        answer = consent(ctx, question)
        if not answer:
            raise Fail(5, "Not connected: the %s runtime needs a database restart, and %s." % (
                rt, "nobody confirmed it" if answer is None else "it was declined"),
                _connect_cmd({"connector": connector["id"], "name": name_l}, "--yes"),
                "--yes or EXAKIT_CONFIRM_RUNTIME_UPDATE=1 consents to the one restart.", "consent")

    # A repair run for a source whose connection the kit made needs no
    # password - but only while nothing about the connection changes.
    # New details are applied only by rebuilding it, which needs one.
    changes = plan.changed_fields(connector, saved, inputs, requested_level)
    reuse_ok = facts["connection_owned"] and saved and not changes
    label = connector.get("secret_label", "Password")
    password = _read_password(ctx, inputs.get("user"), required=False, secret_label=label, can_keep=reuse_ok)
    if password is None and not reuse_ok:
        if saved and facts["connection_owned"]:
            raise Fail(2, "The connection details changed (%s); rebuilding the connection needs the "
                          "password." % ", ".join(changes), None,
                       "Pass it with --password-file <path> or --password-stdin.", "password_needed")
        _read_password(ctx, inputs.get("user"), required=True, secret_label=label)  # explains what is missing

    if password is None:
        for k in ("db_host", "tls", "ip_fallback", "fingerprint"):
            if saved.get(k) is not None:
                cfg[k] = saved[k]
        if saved.get("objects", {}).get("extra_connections"):
            cfg["objects"]["extra_connections"] = saved["objects"]["extra_connections"]
    return _apply(ctx, connector, cfg, facts, p, password, host_cls, first_time, saved)


def _install_runtime(ctx, facts):
    """Record the source's runtime for the next start, when it is missing
    (or, for a custom one, the wrong version). Lua is built in."""
    kind = facts["runtime"]
    if kind == "java":
        if not facts["runtime_installed"]:
            ctx.rt.install_slc("java")
            ctx.ui.ok("Java runtime recorded for the next start")
        return
    if kind == "lua" or (facts["runtime_installed"] and not facts.get("runtime_conflict")):
        return
    spec = plan.runtime_spec(kind)
    path = artifacts.fetch(spec, ctx.ui)
    ctx.rt.install_custom_slc(spec["alias"], spec["language"], path, update=facts["runtime_installed"])
    reg = artifacts.load_registry()
    reg["runtimes"][kind] = {"alias": spec["alias"], "version": spec["version"], "file": spec["file"],
                             "sha256": spec["sha256"], "installed": state.now_iso()}
    state.write_json(state.registry_path(), reg)
    ctx.ui.ok("%s runtime %s recorded for the next start" % (plan.RUNTIME_LABELS[kind], spec["version"]))


def _ensure_runtime_active(ctx, connector, cfg, first_time=False, quiet=False):
    """After any restart: the source's runtime must be ACTIVE. For Java this
    is also where the sandbox's name resolution is put back. Returns the dns
    state the host choice uses ('n/a' for runtimes that resolve names)."""
    kind = plan.runtime_kind(connector)
    if kind == "java":
        st, _ = _ensure_dns(ctx, quiet=quiet)
        if st == "inactive":
            raise _source_fail(cfg, "slc_missing", None, first_time)
        return st
    if kind != "lua" and ("%s=" % plan.runtime_spec(kind)["alias"]) not in _script_languages(ctx):
        raise _source_fail(cfg, "slc_missing", None, first_time)
    return "n/a"


def _stage(ctx, connector, quiet=False):
    """Fetch, verify and stage what the source's adapter needs. Returns the
    adapter version and driver (or None) for the message."""
    u, exa = ctx.ui, ctx.rt.exa_root
    ad = plan.adapter(connector)
    drv = plan.driver(connector)
    adapter = artifacts.fetch(ad, u)
    driver = artifacts.fetch(drv, u) if drv else None
    if plan.runtime_kind(connector) != "lua":
        artifacts.stage_adapter(exa, connector, artifacts.payload(ad, adapter), driver)
    if drv:
        artifacts.stage_driver(exa, drv, driver)
    return ad, drv


def _apply(ctx, connector, cfg, facts, p, password, host_cls, first_time, saved):
    u, name = ctx.ui, cfg["name"]
    _install_runtime(ctx, facts)
    if connector.get("license_notice"):
        u.info(connector["license_notice"])
    ad, drv = _stage(ctx, connector)
    if drv:
        u.ok("Adapter %s and driver %s verified and staged" % (ad["version"], drv["version"]))
        clash = artifacts.foreign_prefix_owners(ctx.rt.exa_root, drv)
        if clash:
            u.warn("Another JDBC driver registration also claims %s (%s). Queries may use that one "
                   "instead of the kit's." % (drv["settings"]["PREFIX"], ", ".join(clash)))
    else:
        u.ok("Adapter %s verified%s" % (ad["version"], "" if plan.runtime_kind(connector) == "lua" else " and staged"))
    reg = artifacts.load_registry()
    art = cfg["artifacts"]
    artifacts.add_ref(reg, "adapters", art["adapter_key"], name,
                      {"bucket": art["bucket"], "script": cfg["objects"]["script"], "connector": connector["id"],
                       "companions": [s["name"] for s in connector.get("scripts", [])]})
    if drv:
        artifacts.add_ref(reg, "drivers", art["driver_name"], name, {"connector": connector["id"],
                                                                     "file": art["driver_file"]})
    state.write_json(state.registry_path(), reg)

    if p["restart_needed"]:
        u.info("Restarting the database to activate the %s runtime"
               % plan.RUNTIME_LABELS.get(facts["runtime"], facts["runtime"]))
        took = ctx.rt.restart(ctx.wait_ready, say=u.info)
        u.ok("Database restarted (%ds)" % took)
    dns_state = _ensure_runtime_active(ctx, connector, cfg, first_time)
    # Before any probe: a source without a JDBC side is probed THROUGH its
    # adapter, and every later step needs the script anyway.
    _ensure_adapter_script(ctx, connector, cfg)

    if password is None:
        try:
            _probe(ctx, connector, cfg["objects"]["connection"], cfg)
        except sql.SqlError as e:
            f = _source_fail(cfg, e.kind, e, first_time)
            f.hint = ("%s The existing connection was kept; pass the password again to rebuild it."
                      % (f.hint or "")).strip()
            raise f
        _probe_schema(ctx, connector, cfg["objects"]["connection"], cfg, first_time)
        u.ok("The existing connection %s still works" % cfg["objects"]["connection"])
    else:
        host, level, fallback = _establish(ctx, connector, cfg, cfg["objects"], cfg["tls"], host_cls,
                                           password, dns_state, first_time)
        cfg.update(db_host=host, tls=level, ip_fallback=fallback)

    _ensure_virtual_schema(ctx, connector, cfg, refresh=True, first_time=first_time)
    result = _verify(ctx, cfg, first_time)

    # Recorded only now: a run that failed above changed nothing on file.
    cfg["updated"] = state.now_iso()
    state.write_json(state.source_dir(name) / "config.json", cfg)
    _save_state(cfg, {}, status="ready" if result["rows_read"] else "connected_empty", last_outcome="ok",
                tables=result["tables"], mcp_readable=result["mcp_readable"])
    if saved and (saved.get("artifacts") or {}).get("adapter_key") not in (None, cfg["artifacts"]["adapter_key"]):
        _release_artifacts(ctx, saved, keep_driver=True)
    return result


def _rollback(ctx, cfg):
    """A first connect failed: take back what it made, so the next attempt
    starts clean and `source list` shows nothing half-built."""
    name, names = cfg["name"], cfg["objects"]
    try:
        db = ctx.db
        vs = db.run("SELECT SCHEMA_COMMENT FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s"
                    % sql.literal(names["schema"]))
        if _owned(vs):
            db.run("DROP VIRTUAL SCHEMA %s CASCADE" % sql.ident(names["schema"]), fetch=False)
        for conn in [names["connection"]] + list(names.get("extra_connections") or []):
            c = db.run("SELECT CONNECTION_COMMENT FROM SYS.EXA_DBA_CONNECTIONS WHERE CONNECTION_NAME = %s"
                       % sql.literal(conn))
            if _owned(c):
                db.run("DROP CONNECTION %s" % sql.ident(conn), fetch=False)
    except (sql.SqlError, Fail) as e:
        state.log("WARN", "rollback: %s" % e)
    try:
        _release_artifacts(ctx, cfg, keep_driver=False)
    except Exception as e:  # cleanup must never hide the original failure
        state.log("WARN", "rollback artifacts: %s" % e)
    d = state.source_dir(name)
    for f in ("config.json", "state.json"):
        if (d / f).exists():
            (d / f).unlink()
    try:
        d.rmdir()
    except OSError:
        pass


# --- the source lifecycle --------------------------------------------------------------------

def _load(name):
    try:
        n = sql.validate_name(name)
    except ValueError as e:
        raise Fail(2, str(e))
    cfg = state.read_json(state.source_dir(n) / "config.json")
    if not cfg:
        raise Fail(2, "No source named %s. See: exakit source list" % name.lower())
    if "artifacts" not in cfg:
        # Written by the first engine build: it recorded no versions, which
        # were the connector's at the time.
        try:
            cfg["artifacts"] = artifacts.describe(_connector(cfg))
        except Fail:
            cfg["artifacts"] = {}
    return cfg, state.read_json(state.source_dir(n) / "state.json", {}) or {}


def _connector(cfg):
    try:
        return plan.find_connector(plan.load_connectors(), cfg["connector"])
    except plan.PlanError:
        raise Fail(2, "This kit copy no longer carries the %s connector; update the kit (exakit update)."
                   % cfg["connector"])


def _save_state(cfg, st, **changes):
    st = dict(st or state.read_json(state.source_dir(cfg["name"]) / "state.json", {}) or {}, **changes)
    st["schema_version"] = 1
    st["last_check"] = state.now_iso()
    st.setdefault("adapter_version", (cfg.get("artifacts") or {}).get("adapter_version"))
    state.write_json(state.source_dir(cfg["name"]) / "state.json", st)
    return st


def _connection_exists(ctx, cfg):
    return _owned(ctx.db.run("SELECT CONNECTION_COMMENT FROM SYS.EXA_DBA_CONNECTIONS WHERE CONNECTION_NAME = %s"
                             % sql.literal(cfg["objects"]["connection"])))


def _check_runtime(ctx, connector, cfg):
    """What a restart or an outside change can undo, repaired before judging:
    the staged files of THIS source's adapter version, the driver
    registration, the runtime (and, for Java, name resolution) - and then the
    adapter script, which a probe through the adapter needs."""
    art, exa = cfg["artifacts"], ctx.rt.exa_root
    if art.get("adapter_version") == connector["adapter"]["version"]:
        ad = plan.adapter(connector)
        drv = plan.driver(connector)
        adapter = artifacts.fetch(ad, ctx.ui)
        driver = artifacts.fetch(drv, ctx.ui) if drv else None
        if plan.runtime_kind(connector) != "lua":
            artifacts.stage_adapter(exa, connector, artifacts.payload(ad, adapter), driver)
        if drv and art.get("driver_file") == drv["file"]:
            artifacts.stage_driver(exa, drv, driver)
    elif plan.runtime_kind(connector) != "lua" and \
            not (exa / artifacts.BUCKET_DIR / art["bucket"] / art["adapter_file"]).is_file():
        raise Fail(1, "The adapter files of %s (version %s) are gone, and this kit now ships %s." % (
            cfg["objects"]["schema"], art.get("adapter_version"), connector["adapter"]["version"]),
            _connect_cmd(cfg), "Connecting again moves the source to the current adapter.", "upgrade_needed")
    st = _ensure_runtime_active(ctx, connector, cfg)
    _ensure_adapter_script(ctx, connector, cfg)
    return st


def check(ctx):
    cfg, st = _load(ctx.args.name)
    connector = _connector(cfg)
    names = cfg["objects"]
    u = ctx.ui
    u.step("Checking %s" % names["schema"])
    with ctx.lock():
        try:
            _check_runtime(ctx, connector, cfg)
            if not _connection_exists(ctx, cfg):
                raise Fail(1, "The connection %s is gone (was the database rebuilt?)." % names["connection"],
                           _connect_cmd(cfg), "Connecting again recreates it; it asks for the password.",
                           "connection_missing")
            _probe(ctx, connector, names["connection"], cfg)
            u.ok("The database reaches the source")
            if cfg.get("ip_fallback") and cfg.get("db_host"):
                now = net.resolve_here(cfg["host"])
                if now and cfg["db_host"] not in now:
                    u.warn("%s now resolves to %s, but the connection still uses %s." % (
                        cfg["host"], ", ".join(now), cfg["db_host"]))
            _ensure_virtual_schema(ctx, connector, cfg, refresh=False)
            result = _verify(ctx, cfg)
        except sql.SqlError as e:
            _save_state(cfg, st, status="failed", last_outcome=e.kind)
            raise _source_fail(cfg, e.kind, e)
        except Fail as f:
            _save_state(cfg, st, status="failed", last_outcome=f.kind or "failed")
            raise
        _save_state(cfg, st, status="ready" if result["rows_read"] else "connected_empty",
                    last_outcome="ok", tables=result["tables"], mcp_readable=result["mcp_readable"])
    if connector["adapter"]["version"] != cfg["artifacts"].get("adapter_version"):
        u.info("A newer adapter (%s) is available; move to it with: %s" % (
            connector["adapter"]["version"], _connect_cmd(cfg)))
    u.done("%s is healthy" % names["schema"])
    return 0, {"ok": True, "status": "ready", "source": cfg["name"], "tables": result["tables"],
               "remedy": None, "remedy_hint": None}


def reauth(ctx):
    cfg, st = _load(ctx.args.name)
    connector = _connector(cfg)
    names = cfg["objects"]
    new = dict(cfg)
    if getattr(ctx.args, "user", None):
        new["user"] = ctx.args.user
    password = _read_password(ctx, new.get("user"), secret_label=connector.get("secret_label", "Password"))
    ctx.ui.step("Updating the credentials of %s" % names["connection"])
    with ctx.lock():
        try:
            dns_state = _check_runtime(ctx, connector, cfg)
            host, level, fallback = _establish(ctx, connector, new, names, new["tls"],
                                               net.classify_host(new["host"]), password, dns_state, False)
            new.update(db_host=host, tls=level, ip_fallback=fallback)
            _ensure_virtual_schema(ctx, connector, new, refresh=False)
            result = _verify(ctx, new)
        except sql.SqlError as e:
            _save_state(cfg, st, status="failed", last_outcome=e.kind)
            raise _source_fail(new, e.kind, e)
        except Fail as f:
            _save_state(cfg, st, status="failed", last_outcome=f.kind or "failed")
            raise
        new["updated"] = state.now_iso()
        state.write_json(state.source_dir(cfg["name"]) / "config.json", new)
        _save_state(new, st, status="ready", last_outcome="ok", tables=result["tables"])
    ctx.ui.done("New credentials work for %s" % names["schema"])
    return 0, {"ok": True, "status": "ready", "source": cfg["name"], "remedy": None, "remedy_hint": None}


def refresh(ctx):
    cfg, st = _load(ctx.args.name)
    connector = _connector(cfg)
    names = cfg["objects"]
    ctx.ui.step("Refreshing %s" % names["schema"])
    with ctx.lock():
        try:
            _check_runtime(ctx, connector, cfg)
            _ensure_virtual_schema(ctx, connector, cfg, refresh=True)
            result = _verify(ctx, cfg)
        except sql.SqlError as e:
            _save_state(cfg, st, status="failed", last_outcome=e.kind)
            raise _source_fail(cfg, e.kind, e)
        except Fail as f:
            _save_state(cfg, st, status="failed", last_outcome=f.kind or "failed")
            raise
        _save_state(cfg, st, status="ready" if result["rows_read"] else "connected_empty",
                    last_outcome="ok", tables=result["tables"])
    ctx.ui.done("%s refreshed: %d table(s)" % (names["schema"], len(result["tables"])))
    return 0, {"ok": True, "status": "ready", "source": cfg["name"], "tables": result["tables"],
               "remedy": None, "remedy_hint": None}


# --- remove ----------------------------------------------------------------------------------

def removal_plan(cfg, reg, connector=None):
    """What `remove` would delete: this source's own objects always; the
    adapter version and driver it RECORDED only when no other source still
    references them."""
    name, names, art = cfg["name"], cfg["objects"], cfg.get("artifacts") or {}
    items = [("virtual_schema", names["schema"]), ("connection", names["connection"])]
    akey = art.get("adapter_key")
    a = reg["adapters"].get(akey, {"refs": []}) if akey else {"refs": [name]}
    if akey and not [r for r in a.get("refs", []) if r != name]:
        items.append(("adapter_script", a.get("script", names.get("script"))))
        items.append(("bucket_folder", a.get("bucket", art.get("bucket"))))
        if not [k for k in reg["adapters"] if k != akey and k.split("/")[0] == akey.split("/")[0]]:
            items += [("script", "%s.%s" % (sql.ADAPTER_SCHEMA, c)) for c in a.get("companions") or []]
    dkey = art.get("driver_name")
    d = reg["drivers"].get(dkey, {"refs": []}) if dkey else {"refs": [name]}
    if dkey and not [r for r in d.get("refs", []) if r != name]:
        items.append(("driver_registration", dkey))
    items.append(("source_record", str(state.source_dir(name))))
    return items


def _drop_script_if_unused(ctx, qualified):
    """Drop a kit adapter script unless a virtual schema - anyone's - still
    uses it. Returns (dropped, reason_kept)."""
    db = ctx.db
    schema, script = qualified.split(".", 1)
    s = db.run("SELECT SCRIPT_COMMENT FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = %s AND SCRIPT_NAME = %s"
               % (sql.literal(schema), sql.literal(script)))
    if not s:
        return False, None
    if not _owned(s):
        return False, "not created by the kit"
    users = [r[0] for r in db.run("SELECT SCHEMA_NAME FROM SYS.EXA_ALL_VIRTUAL_SCHEMAS WHERE "
                                  "ADAPTER_SCRIPT_SCHEMA = %s AND ADAPTER_SCRIPT_NAME = %s"
                                  % (sql.literal(schema), sql.literal(script)))]
    if users:
        return False, "still used by %s" % ", ".join(users)
    db.run("DROP ADAPTER SCRIPT %s.%s" % (sql.ident(schema), sql.ident(script)), fetch=False)
    return True, None


def _drop_companion(ctx, name):
    """Drop one of the kit's companion scripts - only if it carries the kit's
    COMMENT. Returns True when it was dropped."""
    s = ctx.db.run("SELECT SCRIPT_COMMENT FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = %s AND SCRIPT_NAME = %s"
                   % (sql.literal(sql.ADAPTER_SCHEMA), sql.literal(name)))
    if not _owned(s):
        return False
    ctx.db.run("DROP SCRIPT %s.%s" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(name)), fetch=False)
    return True


def _release_artifacts(ctx, cfg, keep_driver):
    """Drop this source's references to an adapter version (and driver), and
    delete what nothing references any more - skipping, with a reason, what
    something outside the kit still uses."""
    reg = artifacts.load_registry()
    art = cfg.get("artifacts") or {}
    removed, kept = [], []
    exa = ctx.rt.exa_root
    akey = art.get("adapter_key")
    if akey and artifacts.drop_ref(reg, "adapters", akey, cfg["name"]):
        entry = reg["adapters"][akey]
        dropped, why = _drop_script_if_unused(ctx, entry.get("script") or cfg["objects"]["script"])
        if why:
            kept.append({"kind": "adapter_script", "name": entry.get("script"), "reason": why})
        else:
            if dropped:
                removed.append({"kind": "adapter_script", "name": entry.get("script")})
            if artifacts.remove_bucket_files(exa, entry.get("bucket") or art["bucket"]):
                removed.append({"kind": "bucket_folder", "name": entry.get("bucket") or art["bucket"]})
            reg["adapters"].pop(akey, None)
            # Companion scripts have fixed names, shared by every version of
            # the connector's adapter: they go with the last one.
            same = [k for k in reg["adapters"] if k.split("/")[0] == akey.split("/")[0]]
            if not same:
                for comp in entry.get("companions") or []:
                    if _drop_companion(ctx, comp):
                        removed.append({"kind": "script", "name": "%s.%s" % (sql.ADAPTER_SCHEMA, comp)})
    dkey = art.get("driver_name")
    if dkey and not keep_driver and artifacts.drop_ref(reg, "drivers", dkey, cfg["name"]):
        users = [k for k, v in reg["adapters"].items() if k.split("/")[0] == cfg["connector"] and v.get("refs")]
        if users:
            kept.append({"kind": "driver_registration", "name": dkey, "reason": "still used"})
        else:
            if artifacts.remove_driver(exa, dkey, reg["drivers"][dkey].get("file") or art["driver_file"]):
                removed.append({"kind": "driver_registration", "name": dkey})
            reg["drivers"].pop(dkey, None)
    state.write_json(state.registry_path(), reg)
    if not reg["adapters"] and not any(state.sources_dir().glob("*/config.json")):
        removed += _drop_adapter_schema_if_empty(ctx, kept)
    return removed, kept


def _drop_adapter_schema_if_empty(ctx, kept):
    """The kit's EXAKIT_VS goes with the last source - only if it is ours and,
    apart from the kit's probe, empty. Never with CASCADE."""
    db = ctx.db
    owned = db.run("SELECT SCHEMA_COMMENT FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s"
                   % sql.literal(sql.ADAPTER_SCHEMA))
    if not _owned(owned):
        return []
    others = [r[0] for r in db.run("SELECT OBJECT_NAME FROM SYS.EXA_ALL_OBJECTS WHERE ROOT_NAME = %s AND "
                                   "ROOT_TYPE = 'SCHEMA' AND OBJECT_NAME <> %s"
                                   % (sql.literal(sql.ADAPTER_SCHEMA), sql.literal(sql.NET_PROBE)))]
    if others:
        kept.append({"kind": "adapter_schema", "name": sql.ADAPTER_SCHEMA,
                     "reason": "it still holds %s" % ", ".join(others)})
        return []
    db.run("DROP SCRIPT IF EXISTS %s.%s" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(sql.NET_PROBE)),
           fetch=False)
    db.run("DROP SCHEMA %s" % sql.ident(sql.ADAPTER_SCHEMA), fetch=False)
    return [{"kind": "adapter_schema", "name": sql.ADAPTER_SCHEMA}]


def remove(ctx):
    cfg, _ = _load(ctx.args.name)
    u = ctx.ui
    with ctx.lock():
        reg = artifacts.load_registry()
        items = removal_plan(cfg, reg)
        u.step("Removing %s" % cfg["objects"]["schema"])
        for kind, what in items:
            u.info("%s: %s" % (kind.replace("_", " "), what))
        if getattr(ctx.args, "dry_run", False):
            return 0, {"ok": True, "status": "planned", "dry_run": True,
                       "would_remove": [{"kind": k, "name": w} for k, w in items],
                       "remedy": None, "remedy_hint": None}
        if not getattr(ctx.args, "yes", False):
            again = "exakit source remove %s --yes" % cfg["name"].lower()
            if not ui_mod.interactive():
                raise Fail(5, "Removing a source drops its virtual schema and connection; nobody confirmed it.",
                           again, None, "consent")
            if not u.confirm("Remove these now?", default=False):
                return 5, {"ok": False, "status": "declined", "changed": False, "remedy": again,
                           "remedy_hint": None}
        db, names = ctx.db, cfg["objects"]
        removed = []
        vs = db.run("SELECT SCHEMA_COMMENT FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s"
                    % sql.literal(names["schema"]))
        uses_kit = db.run("SELECT 1 FROM SYS.EXA_ALL_VIRTUAL_SCHEMAS WHERE SCHEMA_NAME = %s AND "
                          "ADAPTER_SCRIPT_SCHEMA = %s" % (sql.literal(names["schema"]),
                                                          sql.literal(sql.ADAPTER_SCHEMA)))
        if vs and (_owned(vs) or uses_kit):
            db.run("DROP VIRTUAL SCHEMA %s CASCADE" % sql.ident(names["schema"]), fetch=False)
            removed.append({"kind": "virtual_schema", "name": names["schema"]})
        for conn in [names["connection"]] + list(names.get("extra_connections") or []):
            c = db.run("SELECT CONNECTION_COMMENT FROM SYS.EXA_DBA_CONNECTIONS WHERE CONNECTION_NAME = %s"
                       % sql.literal(conn))
            if _owned(c):
                db.run("DROP CONNECTION %s" % sql.ident(conn), fetch=False)
                removed.append({"kind": "connection", "name": conn})
        d = state.source_dir(cfg["name"])
        for f in ("config.json", "state.json"):
            if (d / f).exists():
                (d / f).unlink()
        try:
            d.rmdir()
        except OSError:
            pass
        removed.append({"kind": "source_record", "name": str(d)})
        more, kept = _release_artifacts(ctx, cfg, keep_driver=False)
        removed += more
    for k in kept:
        u.warn("Kept %s %s: %s." % (k["kind"].replace("_", " "), k["name"], k["reason"]))
    u.done("%s removed" % names["schema"])
    return 0, {"ok": True, "status": "removed", "source": cfg["name"], "removed": removed, "kept": kept,
               "remedy": None, "remedy_hint": None}


# --- reading ---------------------------------------------------------------------------------

def list_sources(ctx):
    rows = []
    d = state.sources_dir()
    for sub in sorted(d.iterdir()) if d.is_dir() else []:
        cfg = state.read_json(sub / "config.json")
        if not cfg:
            continue
        st = state.read_json(sub / "state.json", {}) or {}
        rows.append({"name": cfg["name"].lower(), "connector": cfg["connector"],
                     "schema": cfg["objects"]["schema"], "host": "%s:%s" % (cfg["host"], cfg["port"]),
                     "tls": cfg.get("tls"), "status": st.get("status", "unknown"),
                     "last_check": st.get("last_check")})
    if rows:
        ctx.ui.table(["NAME", "SOURCE", "SCHEMA", "HOST", "TLS", "STATUS", "LAST CHECK"],
                     [[r["name"], r["connector"], r["schema"], r["host"], r["tls"], r["status"],
                       (r["last_check"] or "-")[:16].replace("T", " ")] for r in rows])
    else:
        ctx.ui.info("No sources yet. Connect one with: exakit connect")
    return 0, {"ok": True, "count": len(rows), "sources": rows, "remedy": None, "remedy_hint": None}


def show(ctx):
    cfg, st = _load(ctx.args.name)
    o, art = cfg["objects"], cfg.get("artifacts") or {}
    reached = cfg.get("db_host") or cfg["host"]
    if cfg.get("ip_fallback"):
        reached += " (address used because the Java runtime cannot resolve names)"
    # Connectors differ in what they ask (Exasol has no database, Snowflake a
    # warehouse), so the line lists what this source actually has.
    detail = ", ".join("%s %s" % (k, cfg[k]) for k in ("database", "warehouse", "schema", "role", "namespace",
                                                        "collection", "catalog") if cfg.get(k))
    ctx.ui.panel("Source %s" % cfg["name"].lower(), [
        ("Source", "%s (%s:%s%s)" % (cfg["connector"], cfg["host"], cfg["port"], ", " + detail if detail else "")),
        ("Reached as", reached),
        ("TLS", plan.TLS_LABELS.get(cfg.get("tls"), cfg.get("tls"))),
        ("User", cfg.get("user") or "-"),
        ("Objects", "%s, %s, %s" % (o["schema"], o["connection"], o["script"])),
        ("Adapter", "%s (%s runtime, driver %s)" % (
            art.get("adapter_version", "?"), plan.RUNTIME_LABELS.get(art.get("runtime", "java"), "?"),
            art.get("driver_version") or "none")),
        ("Status", "%s (checked %s)" % (st.get("status", "unknown"), (st.get("last_check") or "never")[:16])),
        ("Tables", ", ".join(st.get("tables") or []) or "-"),
    ])
    return 0, {"ok": True, "source": cfg, "state": st, "remedy": None, "remedy_hint": None}


def runtime_hook(ctx):
    """Run after every database start: put the sandbox's name-resolution links
    back. Quiet and best-effort - a start must never fail because of this.
    Only Java sources need it: the Rust SLC links its own, Lua resolves."""
    java = [f for f in state.sources_dir().glob("*/config.json")
            if ((state.read_json(f) or {}).get("artifacts") or {}).get("runtime", "java") == "java"]
    if not java:
        return 0, {"ok": True, "status": "nothing_to_do", "remedy": None, "remedy_hint": None}
    try:
        st, fixed = _ensure_dns(ctx, quiet=True)
    except Fail as f:
        state.log("WARN", "post-start DNS links: %s" % f)
        return 0, {"ok": False, "status": "skipped", "reason": str(f), "remedy": None, "remedy_hint": None}
    return 0, {"ok": st == "ok", "status": st, "fixed": fixed, "remedy": None, "remedy_hint": None}
