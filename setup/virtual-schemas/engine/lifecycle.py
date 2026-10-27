"""connect and the source lifecycle: check, reauth, refresh, remove, list, show.

Every command returns (exit_code, result_dict). The result is the --json
answer; the screen is written as the command goes. Exit codes are the kit's:
0 ok, 1 failed, 2 bad input, 3 database not running, 4 not installed,
5 a change that needs consent nobody gave.

"Ready" is only ever said after rows came back through the virtual schema.
"""

import os
import sys
import time

from . import artifacts, net, plan, runtime, sql, state, ui as ui_mod

MCP_USER = "mcp_readonly"


class Fail(Exception):
    def __init__(self, code, message, remedy=None, hint=None, kind=None):
        super().__init__(message)
        self.code, self.remedy, self.hint, self.kind = code, remedy, hint, kind


# --- what to tell the user about a failure ---------------------------------------------

def explain(kind, cfg, detail):
    """(message, remedy, hint) for a classified source failure."""
    name = cfg.get("name", "<name>").lower()
    host, port = cfg.get("host"), cfg.get("port")
    where = "%s:%s" % (host, port)
    table = {
        "db_down": ("The database is not running.", "exakit start", None),
        "auth": ("The source refused the user name or password.",
                 "exakit source reauth %s" % name, None),
        "network": ("The database cannot reach %s." % where, None,
                    "The connection starts INSIDE the database container, not on this PC. If the "
                    "source runs on this computer (or in a container), publish its port and use "
                    "localhost; a source on a company network may be unreachable over a VPN that "
                    "does not route WSL/Podman traffic."),
        "dns": ("The database could not resolve %s." % host, "exakit source check %s" % name,
                "The Java sandbox needs the name-resolution links the kit adds after every start; "
                "`exakit source check` puts them back. Or use the IP address instead of the name."),
        "tls": ("The encrypted connection to %s failed." % where, None,
                "If the source does not offer TLS, re-run with EXAKIT_VS_TLS=none (private and "
                "local hosts only)."),
        "tls_policy": ("The database's Java security policy blocked the connection.",
                       "exakit source check %s" % name,
                       "The driver registration is missing NOSECURITY=YES; check re-registers it."),
        "database_missing": ("The source has no database named %r." % cfg.get("database"), None, None),
        "permission": ("The source user may not read that schema.", None,
                       "Grant the user USAGE on the schema and SELECT on its tables."),
        "driver_not_registered": ("The JDBC driver registration is missing.",
                                  "exakit source check %s" % name, None),
        "slc_missing": ("The Java runtime is not active in the database.",
                        "exakit source check %s" % name, None),
        "mixed_case": ("The source has mixed-case table names the adapter refused.", None, None),
    }
    msg, remedy, hint = table.get(kind, ("The source check failed: %s" % detail, None, None))
    return msg, remedy, hint


# --- the session every command shares ---------------------------------------------------

class Ctx:
    def __init__(self, args):
        self.args = args
        self.json = bool(getattr(args, "json", False))
        # --json is one object and nothing else, like every other kit command
        # that takes it; the progress lines are for a human watching.
        self.ui = ui_mod.UI(json_mode=self.json, quiet=self.json)
        try:
            self.manifest = state.read_manifest()
        except state.NotInstalled as e:
            raise Fail(4, str(e), "irm https://www.exasol.com/install/starter-kit.ps1 | iex"
                       if os.name == "nt" else "curl -fsSL https://www.exasol.com/install/starter-kit.sh | sh")
        try:
            self.rt = runtime.Runtime(self.manifest)
        except runtime.RuntimeError_ as e:
            raise Fail(2, str(e))
        self._db = None

    @property
    def db(self):
        if self._db is None:
            try:
                self._db = sql.Db(self.manifest)
            except sql.SqlError as e:
                raise Fail(3, "The database is not running or does not accept connections.",
                           "exakit start", state.redact(str(e)))
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
            except Fail:
                if time.time() > deadline:
                    raise Fail(3, "The database did not come back after the restart.", "exakit status")
                time.sleep(3)


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


# --- facts about the database, for the plan -----------------------------------------------

def gather_facts(ctx, connector, inputs):
    db, rt = ctx.db, ctx.rt
    names = sql.object_names(inputs["name"])
    script = sql.adapter_script_name(connector["id"], connector["adapter"]["version"])
    java = rt.slc("java")
    exa = rt.exa_root
    adapter_cache = state.cache_dir() / connector["adapter"]["sha256"] / connector["adapter"]["file"]
    driver_cache = state.cache_dir() / connector["driver"]["sha256"] / connector["driver"]["file"]
    staged = exa / artifacts.BUCKET_DIR / artifacts.bucket_rel(connector) / connector["adapter"]["file"]
    ddir = artifacts.driver_dir(exa, connector["driver"])
    registered = (ddir / connector["driver"]["file"]).is_file() and \
        (ddir / "settings.cfg").is_file() and \
        (ddir / "settings.cfg").read_bytes() == artifacts.settings_cfg(connector["driver"])
    conn = db.run("SELECT CONNECTION_COMMENT FROM SYS.EXA_DBA_CONNECTIONS WHERE CONNECTION_NAME = %s"
                  % sql.literal(names["connection"]))
    schema = db.run("SELECT SCHEMA_IS_VIRTUAL FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s"
                    % sql.literal(names["schema"]))
    vs_owned = bool(db.run("SELECT 1 FROM SYS.EXA_ALL_VIRTUAL_SCHEMAS WHERE SCHEMA_NAME = %s AND "
                           "ADAPTER_SCRIPT_SCHEMA = %s" % (sql.literal(names["schema"]),
                                                           sql.literal(sql.ADAPTER_SCHEMA))))
    script_rows = db.run("SELECT SCRIPT_TEXT FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = %s AND "
                         "SCRIPT_NAME = %s" % (sql.literal(sql.ADAPTER_SCHEMA), sql.literal(script)))
    dns = sandbox_dns_state(ctx, create=False) if java and java["installed"] else "unknown"
    return {
        "java_installed": bool(java and java["installed"]),
        "adapter_cached": adapter_cache.is_file(),
        "driver_cached": driver_cache.is_file(),
        "adapter_staged": staged.is_file(),
        "driver_registered": registered,
        "dns_links": dns,
        "connection_exists": bool(conn),
        "connection_owned": bool(conn) and (conn[0][0] or "") == sql.MARKER,
        "schema_exists": bool(schema),
        "schema_owned": bool(schema) and vs_owned and state.source_dir(inputs["name"]).is_dir(),
        "script_exists": bool(script_rows),
    }


# --- connect ---------------------------------------------------------------------------------

def _ask_inputs(ctx, connectors, inputs):
    """Fill what is missing - by prompt when there is a terminal, otherwise
    refuse with the variable that answers it."""
    u = ctx.ui
    tty = ui_mod.interactive()

    def need(key, label, env):
        if inputs.get(key):
            return
        if not tty:
            raise Fail(2, "%s is required: pass it, or set %s" % (label, env))

    if not inputs.get("source"):
        need("source", "The source type", "EXAKIT_VS_SOURCE")
        inputs["source"] = u.choose("Which source do you want to connect?",
                                    [(c["id"], c["label"]) for c in connectors.values()])
    connector = plan.find_connector(connectors, inputs["source"])
    saved = state.read_json(state.source_dir(inputs["name"]) / "config.json") if inputs.get("name") else None
    if saved:
        # Re-running connect for a known name finishes or repairs it: what was
        # entered last time is the default for everything not given now.
        for k in ("host", "port", "database", "user", "schema", "tls", "params"):
            if not inputs.get(k) and saved.get(k) is not None:
                inputs[k] = saved[k]

    notes = []
    if tty and not inputs.get("url") and not inputs.get("host"):
        pasted = u.ask("Connection string (paste a JDBC URL, or press Enter to type host/port/database)")
        if pasted:
            inputs["url"] = pasted
    try:
        inputs = plan.merge_url(connector, inputs, notes)
    except net.UrlError as e:
        raise Fail(2, str(e))
    for _, text in notes:
        u.warn(text)

    for f in connector["inputs"]:
        if f.get("secret") or inputs.get(f["id"]):
            continue
        env = plan.ENV.get(f["id"], "EXAKIT_VS_%s" % f["id"].upper())
        if not tty:
            if f.get("default") is not None:
                inputs[f["id"]] = f["default"]
                continue
            raise Fail(2, "%s is required: set %s (or EXAKIT_VS_JDBC_URL)" % (f["label"], env))
        inputs[f["id"]] = u.ask(f["label"], str(f.get("default") or ""))
    if not inputs.get("name"):
        default = "".join(ch for ch in (inputs.get("database") or "src") if ch.isalnum() or ch == "_")
        if not default or not default[0].isalpha():
            default = "src_" + default
        if not tty:
            raise Fail(2, "A name for the source is required: set EXAKIT_VS_NAME")
        inputs["name"] = u.ask("Name in Exasol (becomes VS_<NAME>)", default)
    return connector, inputs, notes


def _read_password(ctx, cfg, required=True):
    a = ctx.args
    path = getattr(a, "password_file", None) or os.environ.get("EXAKIT_VS_PASSWORD_FILE")
    pw = None
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                pw = f.read().rstrip("\r\n")
        except OSError as e:
            raise Fail(2, "cannot read the password file %s: %s" % (path, e.strerror))
    elif getattr(a, "password_stdin", False):
        pw = sys.stdin.readline().rstrip("\r\n")
    elif ui_mod.interactive():
        keep = "" if required else ", Enter keeps the stored one"
        pw = ctx.ui.ask_secret("Password for %s (hidden%s)" % (cfg["user"], keep))
    if not pw and not required:
        return None
    if not pw and required:
        raise Fail(2, "A password is required: use --password-file <path>, --password-stdin, or "
                      "EXAKIT_VS_PASSWORD_FILE. There is deliberately no --password option: "
                      "a command line is readable by every process on this machine.")
    state.register_secret(pw)
    return pw


def _probe(ctx, connector, conn_name):
    drv = connector["driver"]["settings"]["DRIVERNAME"]
    ctx.db.run(sql.import_probe(conn_name, drv, connector["check"]["statement"]))


def _host_candidates(ctx, host, dns_state):
    """Where the database should try the source, best first. localhost inside
    the database is the database itself, so a source on this PC is reached
    through the container's host alias; when the sandbox cannot resolve names
    the alias's address is the fallback."""
    cls = net.classify_host(host)
    if cls == "loopback":
        cands = [net.HOST_ALIAS]
        if dns_state != "linked":
            cands.append("169.254.1.2")
        return cands, cls
    return [host], cls


def connect(ctx):
    a, u = ctx.args, ctx.ui
    connectors = plan.load_connectors()
    inputs = plan.from_env()
    for k in ("source", "name", "url", "host", "port", "database", "user", "schema", "tls"):
        v = getattr(a, k, None)
        if v:
            inputs[k] = v
    connector, inputs, _ = _ask_inputs(ctx, connectors, inputs)
    try:
        inputs = plan.validate(connector, inputs)
    except (plan.PlanError, net.UrlError, ValueError) as e:
        raise Fail(2, str(e))
    names = sql.object_names(inputs["name"])
    name_l = inputs["name"].lower()

    u.step("Connecting %s as %s" % (connector["label"], names["schema"]))
    facts = gather_facts(ctx, connector, inputs)
    try:
        p = plan.build_plan(connector, inputs, facts)
    except plan.PlanError as e:
        raise Fail(2, str(e))

    if getattr(a, "dry_run", False):
        for s in p["steps"]:
            (u.info if s["needed"] else u.ok)(("%s" if s["needed"] else "already done: %s") % s["action"])
        return 0, {"ok": True, "status": "planned", "dry_run": True, "plan": p,
                   "remedy": None, "remedy_hint": None}

    host_cls = net.classify_host(inputs["host"])
    try:
        level = plan.tls_start(connector, host_cls, inputs.get("tls"))
    except plan.PlanError as e:
        raise Fail(2, str(e))

    if p["restart_needed"]:
        answer = consent(ctx, "Virtual schemas need the Java runtime inside the database. Installing "
                              "it restarts the database once (the first time takes a few minutes while "
                              "it downloads; later restarts about 30 s). Install it now?")
        if answer is None:
            raise Fail(5, "Installing the Java runtime restarts the database, and nobody confirmed it.",
                       "exakit connect --yes",
                       "--yes or EXAKIT_CONFIRM_RUNTIME_UPDATE=1 consents to the one restart.")
        if not answer:
            raise Fail(5, "Not connected: the Java runtime is needed and the restart was declined.",
                       "exakit connect --yes")

    # A repair run for a source whose connection the kit already made needs no
    # password: the one stored in the CONNECTION is reused as it is.
    password = _read_password(ctx, inputs, required=not facts["connection_owned"])

    cfg = {
        "schema_version": 1, "name": inputs["name"], "connector": connector["id"],
        "host": inputs["host"], "port": inputs["port"], "database": inputs["database"],
        "user": inputs["user"], "schema": inputs["schema"], "params": inputs.get("params") or {},
        "objects": p["objects"], "created": state.now_iso(),
    }
    old = state.read_json(state.source_dir(name_l) / "config.json")
    if old:
        cfg["created"] = old.get("created") or cfg["created"]
        for k in ("db_host", "tls"):
            if old.get(k) and password is None:
                cfg[k] = old[k]

    with state.Lock():
        # 1. Java runtime (recorded now, active after the restart below).
        if not facts["java_installed"]:
            ctx.rt.install_slc("java")
            u.ok("Java runtime recorded for the next start")
        # 2-4. Artifacts.
        adapter = artifacts.fetch(connector["adapter"], u)
        driver = artifacts.fetch(connector["driver"], u)
        jars = artifacts.stage_adapter(ctx.rt.exa_root, connector, adapter, driver)
        artifacts.stage_driver(ctx.rt.exa_root, connector["driver"], driver)
        u.ok("Adapter %s and driver %s verified and staged" % (
            connector["adapter"]["version"], connector["driver"]["version"]))
        clash = artifacts.foreign_prefix_owners(ctx.rt.exa_root, connector["driver"])
        if clash:
            u.warn("Another JDBC driver registration also claims %s (%s). Queries may use that one "
                   "instead of the kit's." % (connector["driver"]["settings"]["PREFIX"], ", ".join(clash)))
        reg = artifacts.load_registry()
        artifacts.add_ref(reg, "adapters", "%s/%s" % (connector["id"], connector["adapter"]["version"]),
                          inputs["name"], {"bucket": artifacts.bucket_rel(connector).as_posix(),
                                           "script": p["objects"]["script"]})
        artifacts.add_ref(reg, "drivers", connector["driver"]["settings"]["DRIVERNAME"], inputs["name"],
                          {"connector": connector["id"], "file": connector["driver"]["file"]})
        state.write_json(state.registry_path(), reg)
        state.write_json(state.source_dir(name_l) / "config.json", dict(cfg, tls=level))
        # 5. The one restart.
        if p["restart_needed"]:
            u.info("Restarting the database to activate the Java runtime")
            took = ctx.rt.restart(ctx.wait_ready)
            u.ok("Database restarted (%ds)" % took)
        # 6. Name resolution inside the Java sandbox.
        dns_state, fixed = _ensure_dns(ctx)

        # 7-8. Where and how to reach the source.
        candidates, _ = _host_candidates(ctx, inputs["host"], dns_state)
        chosen, level = _establish(ctx, connector, cfg, names, candidates, level, host_cls, password)
        cfg.update(db_host=chosen, tls=level, dns=dns_state)

        # 9. Adapter script (shared by every source of this connector + version).
        _ensure_adapter_schema(ctx)
        script = p["objects"]["script"].split(".", 1)[1]
        ctx.db.run(sql.create_adapter_script(script, connector["script"]["class"],
                                             connector["script"]["jvm_options"], jars), fetch=False)
        ctx.db.run("COMMENT ON SCRIPT %s.%s IS %s" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(script),
                                                       sql.literal(sql.MARKER)), fetch=False)

        # 10. The virtual schema.
        props = plan.vs_properties(connector, names["connection"], cfg)
        _create_or_refresh_vs(ctx, cfg, names, script, props, facts)

        # 11. Proof.
        result = _verify(ctx, cfg, names)
        cfg["updated"] = state.now_iso()
        state.write_json(state.source_dir(name_l) / "config.json", cfg)
        state.write_json(state.source_dir(name_l) / "state.json", {
            "schema_version": 1, "status": "ready" if result["rows_read"] else "connected_empty",
            "last_check": state.now_iso(), "last_outcome": "ok", "tables": result["tables"],
            "adapter_version": connector["adapter"]["version"],
            "driver_version": connector["driver"]["version"],
            "mcp_readable": result["mcp_readable"]})

    _say_ready(ctx, connector, cfg, names, result)
    return 0, {"ok": True, "status": "ready" if result["rows_read"] else "connected_empty",
               "source": cfg["name"], "connector": connector["id"], "schema": names["schema"],
               "connection": names["connection"], "tables": result["tables"], "tls": level,
               "db_host": cfg["db_host"], "sample_query": result["sample_query"],
               "mcp_visible": True, "remedy": None, "remedy_hint": None}


def sandbox_dns_state(ctx, create=True):
    """'linked' | 'missing' | 'unknown', asked of the Java sandbox itself
    through the kit's probe UDF. With create=False (a dry run) nothing is
    created and a missing probe answers 'unknown'."""
    db = ctx.db
    exists = db.run("SELECT 1 FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = %s AND SCRIPT_NAME = %s"
                    % (sql.literal(sql.ADAPTER_SCHEMA), sql.literal(sql.DNS_PROBE)))
    if not exists:
        if not create:
            return "unknown"
        _ensure_adapter_schema(ctx)
        db.run(sql.create_dns_probe(), fetch=False)
        db.run("COMMENT ON SCRIPT %s.%s IS %s" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(sql.DNS_PROBE),
                                                   sql.literal(sql.MARKER)), fetch=False)
    try:
        return db.value("SELECT %s.%s()" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(sql.DNS_PROBE)))
    except sql.SqlError as e:
        state.log("WARN", "DNS probe: %s" % e)
        return "unknown"


def _ensure_dns(ctx, quiet=False):
    """Make host names resolvable inside the Java sandbox (temporary
    workaround, see runtime.py). Returns (state, fixed)."""
    st = sandbox_dns_state(ctx)
    if st == "linked":
        return st, False
    if not ctx.rt.can_link():
        if not quiet:
            ctx.ui.warn("The Java sandbox cannot resolve host names, and the kit cannot reach the "
                        "database container from here to fix it; IP addresses still work.")
        return st, False
    try:
        ctx.rt.link_sandbox_dns()
    except runtime.RuntimeError_ as e:
        if not quiet:
            ctx.ui.warn("Could not link name resolution into the Java sandbox: %s" % e)
        return st, False
    st = sandbox_dns_state(ctx)
    if st == "linked":
        if not quiet:
            ctx.ui.ok("Name resolution linked into the Java sandbox (temporary workaround, redone "
                      "after every database start)")
        return st, True
    if not quiet:
        ctx.ui.warn("Linked name resolution into the Java sandbox, but it still does not resolve; "
                    "IP addresses still work.")
    return st, False


def _establish(ctx, connector, cfg, names, candidates, level, host_cls, password):
    """CREATE CONNECTION + a probe from inside the database, walking the host
    candidates and - only with the user's say-so - the TLS levels."""
    u = ctx.ui
    offer = plan.tls_offer(connector, host_cls)
    if password is None:
        try:
            _probe(ctx, connector, names["connection"])
        except sql.SqlError as e:
            f = _source_fail(cfg, e.kind, e)
            f.hint = ("%s The existing connection was kept; pass the password again "
                      "(--password-file) to rebuild it." % (f.hint or "")).strip()
            raise f
        u.ok("The existing connection %s still works" % names["connection"])
        return cfg.get("db_host") or candidates[0], cfg.get("tls") or level
    while True:
        last = None
        for host in candidates:
            params = plan.url_params(connector, level, cfg.get("params"))
            url = net.build_url(connector, host, cfg["port"], cfg["database"], params)
            ctx.db.run(sql.create_connection(names["connection"], url, cfg["user"], password), fetch=False)
            ctx.db.run(sql.comment_connection(names["connection"]), fetch=False)
            try:
                _probe(ctx, connector, names["connection"])
                u.ok("The database reaches %s:%s (%s)" % (host, cfg["port"], plan.TLS_LABELS[level]))
                return host, level
            except sql.SqlError as e:
                last = e
                state.log("INFO", "probe %s failed: %s" % (host, e.kind))
                if e.kind not in ("network", "dns"):
                    break
        kind = last.kind if last else "unknown"
        if kind == "tls":
            lower = [l for l in offer if offer.index(l) > offer.index(level)] if level in offer else []
            if not lower:
                raise _source_fail(cfg, kind, last)
            u.warn("The encrypted connection failed: %s" % sql.short(str(last)))
            nxt = lower[0]
            if not ui_mod.interactive():
                raise Fail(1, "The %s connection failed and the kit never lowers TLS on its own."
                           % plan.TLS_LABELS[level], None,
                           "Re-run with EXAKIT_VS_TLS=%s to accept a %s connection." % (nxt, plan.TLS_LABELS[nxt]),
                           kind)
            choice = u.choose("How should the kit continue?",
                              [(l, "Use a connection that is %s" % plan.TLS_LABELS[l]) for l in lower]
                              + [("stop", "Stop - I will fix TLS on the source")])
            if choice == "stop":
                raise Fail(1, "Stopped at your request; nothing else was changed.", None, None, kind)
            level = choice
            continue
        raise _source_fail(cfg, kind, last)


def _source_fail(cfg, kind, err):
    msg, remedy, hint = explain(kind, cfg, sql.short(str(err)) if err else "")
    detail = sql.short(str(err)) if err else None
    return Fail(1, msg, remedy, "%s%s" % (hint + " " if hint else "", "(engine said: %s)" % detail if detail else ""),
                kind)


def _ensure_adapter_schema(ctx):
    rows = ctx.db.run("SELECT SCHEMA_COMMENT FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s"
                      % sql.literal(sql.ADAPTER_SCHEMA))
    if rows and (rows[0][0] or "") != sql.MARKER:
        raise Fail(2, "A schema named %s exists and was not created by the kit; the kit will not put "
                      "its adapter scripts there." % sql.ADAPTER_SCHEMA)
    if not rows:
        ctx.db.run("CREATE SCHEMA %s" % sql.ident(sql.ADAPTER_SCHEMA), fetch=False)
        ctx.db.run("COMMENT ON SCHEMA %s IS %s" % (sql.ident(sql.ADAPTER_SCHEMA), sql.literal(sql.MARKER)),
                   fetch=False)


def _create_or_refresh_vs(ctx, cfg, names, script, props, facts):
    db = ctx.db
    if facts["schema_exists"]:
        current = dict(db.run("SELECT PROPERTY_NAME, PROPERTY_VALUE FROM SYS.EXA_ALL_VIRTUAL_SCHEMA_PROPERTIES "
                              "WHERE SCHEMA_NAME = %s" % sql.literal(names["schema"])))
        adapter = db.value("SELECT ADAPTER_SCRIPT_NAME FROM SYS.EXA_ALL_VIRTUAL_SCHEMAS WHERE SCHEMA_NAME = %s"
                           % sql.literal(names["schema"]))
        if adapter == script and all(current.get(k) == v for k, v in props.items()):
            _vs_call(ctx, cfg, "ALTER VIRTUAL SCHEMA %s REFRESH" % sql.ident(names["schema"]))
            ctx.ui.ok("Virtual schema %s refreshed" % names["schema"])
            return
        db.run("DROP VIRTUAL SCHEMA %s CASCADE" % sql.ident(names["schema"]), fetch=False)
    _vs_call(ctx, cfg, sql.create_virtual_schema(names["schema"], script, props))
    ctx.ui.ok("Virtual schema %s created" % names["schema"])


def _vs_call(ctx, cfg, statement):
    try:
        ctx.db.run(statement, fetch=False)
    except sql.SqlError as e:
        raise _source_fail(cfg, e.kind, e)


def _verify(ctx, cfg, names):
    db = ctx.db
    tables = [r[0] for r in db.run("SELECT TABLE_NAME FROM SYS.EXA_ALL_TABLES WHERE TABLE_SCHEMA = %s "
                                   "ORDER BY TABLE_NAME" % sql.literal(names["schema"]))]
    out = {"tables": tables, "rows_read": False, "sample_query": None, "mcp_readable": None}
    if not tables:
        ctx.ui.warn("Connected, but schema %r shows no tables to user %s." % (cfg["schema"], cfg["user"]))
        return out
    q = "SELECT * FROM %s.%s LIMIT 10" % (names["schema"], sql.ident(tables[0]))
    out["sample_query"] = q
    try:
        db.run("SELECT * FROM %s.%s LIMIT 1" % (sql.ident(names["schema"]), sql.ident(tables[0])))
    except sql.SqlError as e:
        raise _source_fail(cfg, e.kind, e)
    out["rows_read"] = True
    ctx.ui.ok("Read rows from %s.%s through the virtual schema" % (names["schema"], tables[0]))
    pwfile = state.kit_home() / "credentials" / "mcp_readonly_password"
    if pwfile.is_file():
        try:
            ro = sql.Db(ctx.manifest, user=MCP_USER, password_file=str(pwfile))
            ro.run("SELECT * FROM %s.%s LIMIT 1" % (sql.ident(names["schema"]), sql.ident(tables[0])))
            ro.close()
            out["mcp_readable"] = True
        except sql.SqlError as e:
            out["mcp_readable"] = False
            state.log("WARN", "read-only user check: %s" % e)
    return out


def _say_ready(ctx, connector, cfg, names, result):
    u = ctx.ui
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


# --- the source lifecycle --------------------------------------------------------------------

def _load(name):
    try:
        n = sql.validate_name(name)
    except ValueError as e:
        raise Fail(2, str(e))
    cfg = state.read_json(state.source_dir(n) / "config.json")
    if not cfg:
        raise Fail(2, "No source named %s. See: exakit source list" % name.lower())
    return cfg, state.read_json(state.source_dir(n) / "state.json", {}) or {}


def _connector(cfg):
    return plan.find_connector(plan.load_connectors(), cfg["connector"])


def _save_state(cfg, st, **changes):
    st = dict(st, **changes)
    st["last_check"] = state.now_iso()
    state.write_json(state.source_dir(cfg["name"]) / "state.json", st)
    return st


def check(ctx):
    cfg, st = _load(ctx.args.name)
    connector = _connector(cfg)
    names = cfg["objects"]
    u = ctx.ui
    u.step("Checking %s" % names["schema"])
    # Repair what a restart or an outside change can undo, before judging.
    exa = ctx.rt.exa_root
    adapter = artifacts.fetch(connector["adapter"], u)
    driver = artifacts.fetch(connector["driver"], u)
    artifacts.stage_adapter(exa, connector, adapter, driver)
    artifacts.stage_driver(exa, connector["driver"], driver)
    java = ctx.rt.slc("java")
    if not (java and java["installed"]):
        raise Fail(1, "The Java runtime is not installed in the database any more.", "exakit connect --yes")
    _ensure_dns(ctx)
    try:
        _probe(ctx, connector, names["connection"])
        u.ok("The database reaches the source")
        result = _verify(ctx, cfg, names)
    except sql.SqlError as e:
        f = _source_fail(cfg, e.kind, e)
        _save_state(cfg, st, status="failed", last_outcome=e.kind)
        raise f
    except Fail as f:
        _save_state(cfg, st, status="failed", last_outcome=f.kind or "failed")
        raise
    _save_state(cfg, st, status="ready" if result["rows_read"] else "connected_empty",
                last_outcome="ok", tables=result["tables"], mcp_readable=result["mcp_readable"])
    here = net.resolve_here(cfg["host"]) if net.classify_host(cfg["host"]) != "loopback" else []
    u.done("%s is healthy" % names["schema"])
    return 0, {"ok": True, "status": "ready", "source": cfg["name"], "tables": result["tables"],
               "resolves_to": here, "remedy": None, "remedy_hint": None}


def reauth(ctx):
    cfg, st = _load(ctx.args.name)
    connector = _connector(cfg)
    names = cfg["objects"]
    if getattr(ctx.args, "user", None):
        cfg["user"] = ctx.args.user
    password = _read_password(ctx, cfg)
    ctx.ui.step("Updating the credentials of %s" % names["connection"])
    params = plan.url_params(connector, cfg["tls"], cfg.get("params"))
    url = net.build_url(connector, cfg.get("db_host") or cfg["host"], cfg["port"], cfg["database"], params)
    ctx.db.run(sql.create_connection(names["connection"], url, cfg["user"], password), fetch=False)
    ctx.db.run(sql.comment_connection(names["connection"]), fetch=False)
    state.write_json(state.source_dir(cfg["name"]) / "config.json", dict(cfg, updated=state.now_iso()))
    try:
        _probe(ctx, connector, names["connection"])
        result = _verify(ctx, cfg, names)
    except sql.SqlError as e:
        _save_state(cfg, st, status="failed", last_outcome=e.kind)
        raise _source_fail(cfg, e.kind, e)
    _save_state(cfg, st, status="ready", last_outcome="ok", tables=result["tables"])
    ctx.ui.done("New credentials work for %s" % names["schema"])
    return 0, {"ok": True, "status": "ready", "source": cfg["name"], "remedy": None, "remedy_hint": None}


def refresh(ctx):
    cfg, st = _load(ctx.args.name)
    names = cfg["objects"]
    ctx.ui.step("Refreshing %s" % names["schema"])
    _ensure_dns(ctx)
    _vs_call(ctx, cfg, "ALTER VIRTUAL SCHEMA %s REFRESH" % sql.ident(names["schema"]))
    result = _verify(ctx, cfg, names)
    _save_state(cfg, st, status="ready" if result["rows_read"] else "connected_empty",
                last_outcome="ok", tables=result["tables"])
    ctx.ui.done("%s refreshed: %d table(s)" % (names["schema"], len(result["tables"])))
    return 0, {"ok": True, "status": "ready", "source": cfg["name"], "tables": result["tables"],
               "remedy": None, "remedy_hint": None}


def removal_plan(cfg, reg, connector):
    """What `remove` would delete, given the registry. Shared artifacts stay
    while another source still references them."""
    name = cfg["name"]
    names = cfg["objects"]
    items = [("virtual_schema", names["schema"]), ("connection", names["connection"])]
    akey = "%s/%s" % (connector["id"], connector["adapter"]["version"])
    a = reg["adapters"].get(akey, {"refs": []})
    if [r for r in a.get("refs", []) if r != name] == []:
        items.append(("adapter_script", a.get("script", names.get("script"))))
        items.append(("bucket_folder", a.get("bucket", artifacts.bucket_rel(connector).as_posix())))
    dkey = connector["driver"]["settings"]["DRIVERNAME"]
    d = reg["drivers"].get(dkey, {"refs": []})
    if [r for r in d.get("refs", []) if r != name] == []:
        items.append(("driver_registration", dkey))
    items.append(("source_record", str(state.source_dir(name))))
    return items


def remove(ctx):
    cfg, _ = _load(ctx.args.name)
    connector = _connector(cfg)
    reg = artifacts.load_registry()
    items = removal_plan(cfg, reg, connector)
    u = ctx.ui
    u.step("Removing %s" % cfg["objects"]["schema"])
    for kind, what in items:
        u.info("%s: %s" % (kind.replace("_", " "), what))
    if getattr(ctx.args, "dry_run", False):
        return 0, {"ok": True, "status": "planned", "dry_run": True,
                   "would_remove": [{"kind": k, "name": w} for k, w in items],
                   "remedy": None, "remedy_hint": None}
    if not getattr(ctx.args, "yes", False):
        if not ui_mod.interactive():
            raise Fail(5, "Removing a source drops its virtual schema and connection; nobody confirmed it.",
                       "exakit source remove %s --yes" % cfg["name"].lower())
        if not u.confirm("Remove these now?", default=False):
            return 5, {"ok": False, "status": "declined", "changed": False,
                       "remedy": "exakit source remove %s --yes" % cfg["name"].lower(), "remedy_hint": None}
    db = ctx.db
    with state.Lock():
        exa = ctx.rt.exa_root
        for kind, what in items:
            if kind == "virtual_schema":
                if db.run("SELECT 1 FROM SYS.EXA_ALL_VIRTUAL_SCHEMAS WHERE SCHEMA_NAME = %s AND "
                          "ADAPTER_SCRIPT_SCHEMA = %s" % (sql.literal(what), sql.literal(sql.ADAPTER_SCHEMA))):
                    db.run("DROP VIRTUAL SCHEMA %s CASCADE" % sql.ident(what), fetch=False)
            elif kind == "connection":
                c = db.run("SELECT CONNECTION_COMMENT FROM SYS.EXA_DBA_CONNECTIONS WHERE CONNECTION_NAME = %s"
                           % sql.literal(what))
                if c and (c[0][0] or "") == sql.MARKER:
                    db.run("DROP CONNECTION %s" % sql.ident(what), fetch=False)
            elif kind == "adapter_script":
                schema, script = what.split(".", 1)
                s = db.run("SELECT SCRIPT_COMMENT FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = %s AND "
                           "SCRIPT_NAME = %s" % (sql.literal(schema), sql.literal(script)))
                if s and (s[0][0] or "") == sql.MARKER:
                    db.run("DROP ADAPTER SCRIPT %s.%s" % (sql.ident(schema), sql.ident(script)), fetch=False)
            elif kind == "bucket_folder":
                artifacts.remove_bucket_files(exa, what)
            elif kind == "driver_registration":
                artifacts.remove_driver(exa, connector["driver"])
        akey = "%s/%s" % (connector["id"], connector["adapter"]["version"])
        if artifacts.drop_ref(reg, "adapters", akey, cfg["name"]):
            reg["adapters"].pop(akey, None)
        dkey = connector["driver"]["settings"]["DRIVERNAME"]
        if artifacts.drop_ref(reg, "drivers", dkey, cfg["name"]):
            reg["drivers"].pop(dkey, None)
        state.write_json(state.registry_path(), reg)
        # The adapter schema goes with the last source, and only if it is ours
        # and empty.
        if not reg["adapters"]:
            probe = db.run("SELECT SCRIPT_COMMENT FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = %s AND "
                           "SCRIPT_NAME = %s" % (sql.literal(sql.ADAPTER_SCHEMA), sql.literal(sql.DNS_PROBE)))
            if probe and (probe[0][0] or "") == sql.MARKER:
                db.run("DROP SCRIPT %s.%s" % (sql.ident(sql.ADAPTER_SCHEMA), sql.ident(sql.DNS_PROBE)),
                       fetch=False)
            left = db.run("SELECT COUNT(*) FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = %s"
                          % sql.literal(sql.ADAPTER_SCHEMA))
            owned = db.run("SELECT SCHEMA_COMMENT FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME = %s"
                           % sql.literal(sql.ADAPTER_SCHEMA))
            if owned and (owned[0][0] or "") == sql.MARKER and left and left[0][0] == 0:
                db.run("DROP SCHEMA %s" % sql.ident(sql.ADAPTER_SCHEMA), fetch=False)
        d = state.source_dir(cfg["name"])
        for f in ("config.json", "state.json"):
            if (d / f).exists():
                (d / f).unlink()
        try:
            d.rmdir()
        except OSError:
            pass
    u.done("%s removed" % cfg["objects"]["schema"])
    return 0, {"ok": True, "status": "removed", "source": cfg["name"],
               "removed": [{"kind": k, "name": w} for k, w in items], "remedy": None, "remedy_hint": None}


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
    o = cfg["objects"]
    ctx.ui.panel("Source %s" % cfg["name"].lower(), [
        ("Source", "%s (%s:%s, database %s, schema %s)" % (cfg["connector"], cfg["host"], cfg["port"],
                                                          cfg["database"], cfg["schema"])),
        ("Reached as", cfg.get("db_host") or cfg["host"]),
        ("TLS", plan.TLS_LABELS.get(cfg.get("tls"), cfg.get("tls"))),
        ("User", cfg["user"]),
        ("Objects", "%s, %s, %s" % (o["schema"], o["connection"], o["script"])),
        ("Status", "%s (checked %s)" % (st.get("status", "unknown"), (st.get("last_check") or "never")[:16])),
        ("Tables", ", ".join(st.get("tables") or []) or "-"),
    ])
    return 0, {"ok": True, "source": cfg, "state": st, "remedy": None, "remedy_hint": None}


def runtime_hook(ctx):
    """Run after every database start: put the sandbox's name-resolution links
    back. Quiet and best-effort - a start must never fail because of this."""
    if not any(state.sources_dir().glob("*/config.json")):
        return 0, {"ok": True, "status": "nothing_to_do", "remedy": None, "remedy_hint": None}
    try:
        st, fixed = _ensure_dns(ctx, quiet=True)
    except Fail as f:
        state.log("WARN", "post-start DNS links: %s" % f)
        return 0, {"ok": False, "status": "skipped", "reason": str(f), "remedy": None, "remedy_hint": None}
    return 0, {"ok": st == "linked", "status": st, "fixed": fixed, "remedy": None, "remedy_hint": None}
