"""Live regression tests: one case per bug the Phase-2 QA pass and
architecture review found, run against the installed kit's database and the
test PostgreSQL (see live_postgresql.py for the setup).

    VS_LIVE_PG_PASSWORD_FILE=<file> <venv-python> tests/virtual-schemas/live_regressions.py [--restart]

--restart adds the cases that stop and start the database (DNS links lost
on restart, the IP fallback). Every source it makes is named qa_* and is
removed again; test objects it puts in the database are dropped.
"""

import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "setup" / "virtual-schemas" / "exakit_vs.py"
PWFILE = os.environ.get("VS_LIVE_PG_PASSWORD_FILE")
HOME = Path(os.environ.get("EXAKIT_HOME", Path.home() / ".exasol-starter-kit"))
URL = "jdbc:postgresql://localhost:5432/spike"
RESULTS = []


def run(*args, env=None, json_out=True):
    e = dict(os.environ, EXAKIT_VS_NONINTERACTIVE="1")
    e.update(env or {})
    argv = [sys.executable, "-I", str(ENGINE)] + list(args) + (["--json"] if json_out else [])
    p = subprocess.run(argv, capture_output=True, text=True, env=e, timeout=900)
    try:
        obj = json.loads(p.stdout) if json_out else {}
    except ValueError:
        obj = {"_raw_stdout": p.stdout[-500:], "_stderr": p.stderr[-500:]}
    return p.returncode, obj, p.stdout + p.stderr


def check(label, cond, detail=""):
    RESULTS.append((label, bool(cond)))
    print("%s %s%s" % ("ok  " if cond else "FAIL", label, ("  -- %s" % str(detail)[:400]) if not cond else ""))


def admin():
    import pyexasol
    m = json.loads((HOME / "manifest.json").read_text(encoding="utf-8"))["runtime"]
    pw = Path(m["password_file"]).read_text(encoding="utf-8").strip()
    return pyexasol.connect(dsn=m["dsn"], user=m["user"], password=pw, encryption=True,
                            websocket_sslopt={"cert_reqs": ssl.CERT_NONE}, autocommit=True)


def q1(sql):
    c = admin()
    try:
        st = c.execute(sql)
        return st.fetchall() if st.result_type == "resultSet" else []
    finally:
        c.close()


def base(name, *extra):
    return ["connect", "postgresql", "--name", name, "--url", URL, "--user", "spike", "--schema", "sales",
            "--password-file", PWFILE] + list(extra)


def wrong_pw_file():
    f = Path(tempfile.gettempdir()) / "vs-qa-wrong.pw"
    f.write_text("definitely-wrong-ZZ")
    return str(f)


def leaks(text, secret):
    return secret in text


LOG_START = {}


def _daily_logs():
    return [p for p in (HOME / "logs").glob("virtual-schemas-*.log") if len(p.stem) == len("virtual-schemas-20261028")]


def mark_logs():
    for p in _daily_logs():
        LOG_START[p] = p.stat().st_size


def logs_text():
    """What this run wrote to the logs - older files (other runs, older
    engine builds) are not this run's to judge."""
    out = []
    for p in _daily_logs():
        with open(p, "rb") as f:
            f.seek(LOG_START.get(p, 0))
            out.append(f.read().decode("utf-8", "replace"))
    return "\n".join(out)


def main():
    if not PWFILE:
        sys.exit("set VS_LIVE_PG_PASSWORD_FILE")
    with_restart = "--restart" in sys.argv
    bad = wrong_pw_file()
    mark_logs()

    # M1: a failed FIRST connect leaves nothing, and its remedy is connect.
    rc, o, _ = run(*base("qa_m1")[:-1], bad)
    check("M1 wrong password on first connect: auth, exit 1", rc == 1 and o.get("kind") == "auth", o)
    check("M1 remedy is connect, not a dead-end reauth",
          o.get("remedy") == "exakit connect postgresql --name qa_m1", o.get("remedy"))
    rc2, o2, _ = run("source", "show", "qa_m1")
    check("M1 nothing half-made left behind (show exits 2)", rc2 == 2, o2)
    check("M1 no connection left in the database",
          not q1("SELECT 1 FROM SYS.EXA_DBA_CONNECTIONS WHERE CONNECTION_NAME LIKE 'EXAKIT_SRC_QA_M1%'"))
    rc, o, _ = run(*base("qa_m1"))
    check("M1 the remedy works", rc == 0 and o.get("status") == "ready", o)

    # M4 / M6: a re-run that changes the connection needs the password.
    rc, o, _ = run("connect", "postgresql", "--name", "qa_m1", "--url", "jdbc:postgresql://localhost:5999/spike",
                   "--user", "spike", "--schema", "sales")
    check("M4 new --url without password is refused (exit 2, password_needed)",
          rc == 2 and o.get("kind") == "password_needed", o)
    rc, o, _ = run("connect", "postgresql", "--name", "qa_m1", "--tls", "none")
    check("M6 new --tls without password is refused", rc == 2 and o.get("kind") == "password_needed", o)
    rc, o, _ = run("connect", "postgresql", "--name", "qa_m1", "--url", "jdbc:postgresql://localhost:5999/spike",
                   "--user", "spike", "--schema", "sales", "--password-file", PWFILE)
    check("M4 new --url with password is applied (and fails: nothing listens on 5999)",
          rc == 1 and o.get("kind") == "network", o)
    rc, o, _ = run("source", "check", "qa_m1")
    check("M4 the working connection survived the failed change", rc == 0, o)
    cfg = json.loads((HOME / "sources" / "qa_m1" / "config.json").read_text())
    check("M6 config still records the working port", cfg["port"] == 5432, cfg.get("port"))
    rc, o, _ = run("connect", "postgresql", "--name", "qa_m1", "--schema", "public")
    check("schema change needs no password and is applied with ALTER", rc == 0, o)
    run("connect", "postgresql", "--name", "qa_m1", "--schema", "sales")

    # m9 / D7: a failed reauth never replaces working credentials.
    rc, o, _ = run("source", "reauth", "qa_m1", "--password-file", bad)
    check("m9 reauth with a wrong password fails as auth", rc == 1 and o.get("kind") == "auth", o)
    rc, o, _ = run("source", "check", "qa_m1")
    check("m9 ...and the old credentials still work", rc == 0, o)
    rc, o, _ = run("source", "reauth", "qa_m1", "--user", "nobody", "--password-file", PWFILE)
    cfg = json.loads((HOME / "sources" / "qa_m1" / "config.json").read_text())
    check("m9 a failed reauth with a new user does not save that user", rc == 1 and cfg["user"] == "spike",
          (rc, cfg.get("user")))

    # M2 / M3 / A: passwords in pasted URLs never leak.
    rc, o, out = run("connect", "postgresql", "--name", "qa_m2", "--url",
                     "jdbc:postgresql://localhost:5432/spike;user=spike;password=SemiSecretZZ",
                     "--schema", "sales", "--password-file", PWFILE)
    conn = q1("SELECT CONNECTION_STRING FROM SYS.EXA_DBA_CONNECTIONS WHERE CONNECTION_NAME = 'EXAKIT_SRC_QA_M2'")
    cfgtxt = (HOME / "sources" / "qa_m2" / "config.json").read_text() if (HOME / "sources" / "qa_m2").exists() else ""
    check("M2 ';password=' form connects", rc == 0, o)
    check("M2 ...and the password is nowhere: connection, config, output",
          not any(leaks(t, "SemiSecretZZ") for t in (str(conn), cfgtxt, out)), conn)
    rc, o, out = run("connect", "postgresql", "--name", "qa_m3", "--url",
                     "postgres://spike:Se/cretZZQ@localhost:5432/spike", "--schema", "sales", "--password-file", PWFILE)
    check("M3 password with '/' parses and connects", rc == 0, o)
    check("M3 ...no fragment of it anywhere in the output", not leaks(out, "Se/cret") and "'Se'" not in out, out[-300:])
    check("A no URL password in this run's log", not any(leaks(logs_text(), s) for s in ("SemiSecretZZ", "cretZZQ")))
    check("A2 redaction no longer garbles package names in the log", "com.***." not in logs_text())

    # m1: names with characters a path cannot hold.
    rc, o, _ = run("connect", "postgresql", "--name", 'qa"x', "--url", URL, "--password-file", PWFILE)
    check("m1 a name with a quote is refused cleanly (exit 2, JSON)", rc == 2 and o.get("ok") is False, o)

    # m3 / D2: a missing or forbidden source schema is a failure, not success.
    rc, o, _ = run("connect", "postgresql", "--name", "qa_m3s", "--url", URL, "--user", "spike",
                   "--schema", "nosuchschema", "--password-file", PWFILE)
    check("m3 missing source schema: exit 1, schema_missing", rc == 1 and o.get("kind") == "schema_missing", o)
    check("m3 ...and rolled back", run("source", "show", "qa_m3s")[0] == 2)

    # m5: --dry-run applies the TLS rules.
    rc, o, _ = run("connect", "postgresql", "--name", "qa_dry", "--url", "jdbc:postgresql://example.com:5432/d",
                   "--user", "u", "--schema", "s", "--tls", "none", "--dry-run")
    check("m5 dry-run refuses --tls none to a public host", rc == 2, o)

    # m7: a UTF-16 password file (PowerShell 5.1's default) works.
    utf16 = Path(tempfile.gettempdir()) / "vs-qa-utf16.pw"
    utf16.write_bytes(("﻿" + Path(PWFILE).read_text().strip()).encode("utf-16-le"))
    rc, o, _ = run("connect", "postgresql", "--name", "qa_m7", "--url", URL, "--user", "spike",
                   "--schema", "sales", "--password-file", str(utf16))
    utf16.unlink()
    check("m7 UTF-16 password file", rc == 0, o)

    # m8: a host that resolves nowhere says so.
    rc, o, _ = run("connect", "postgresql", "--name", "qa_m8", "--url", "jdbc:postgresql://no-such-host.invalid:5432/d",
                   "--user", "u", "--schema", "s", "--password-file", PWFILE)
    check("m8 unresolvable host is classified as such", rc == 1 and o.get("kind") == "unresolvable", o)

    # m2: a refusal (foreign EXAKIT_VS) stages nothing - only checkable with no
    # kit sources left, so it runs at the end.

    # Cosmetic: --json at every level, --password explained.
    rc, o, _ = run("source")
    check("'source --json' answers with JSON", rc == 2 and o.get("ok") is False, o)
    rc, o, _ = run("connect", "--password", "x")
    check("--password is refused with the reason", rc == 2 and "deliberately" in o.get("error", ""), o)

    # M5: a foreign virtual schema on the kit's adapter script, and a user
    # table in EXAKIT_VS, never block removing the last source.
    for n in ("qa_m2", "qa_m3", "qa_m7"):
        run("source", "remove", n, "--yes")
    # Case A: someone else's virtual schema on the kit's adapter script.
    q1("CREATE VIRTUAL SCHEMA QA_FOREIGN_VS USING EXAKIT_VS.POSTGRESQL_4_1_0 WITH CONNECTION_NAME = "
       "'EXAKIT_SRC_QA_M1' CATALOG_NAME = 'spike' SCHEMA_NAME = 'sales' "
       "POSTGRESQL_IDENTIFIER_MAPPING = 'PRESERVE_ORIGINAL_CASE'")
    rc, o, _ = run("source", "remove", "qa_m1", "--yes")
    kept = {k["kind"]: k["reason"] for k in o.get("kept", [])}
    check("M5a last remove succeeds despite a foreign VS on the adapter", rc == 0, o)
    check("M5a ...keeps the adapter script that VS uses", "QA_FOREIGN_VS" in kept.get("adapter_script", ""), kept)
    check("M5a the source record is gone", run("source", "show", "qa_m1")[0] == 2)
    q1("DROP VIRTUAL SCHEMA QA_FOREIGN_VS CASCADE")
    q1("DROP ADAPTER SCRIPT EXAKIT_VS.POSTGRESQL_4_1_0")
    q1("DROP SCRIPT IF EXISTS EXAKIT_VS.SANDBOX_NET")
    q1("DROP SCHEMA EXAKIT_VS")
    q1("DROP CONNECTION IF EXISTS EXAKIT_SRC_QA_M1")
    forget_artifacts()

    # Case B: a user table inside EXAKIT_VS.
    rc, o, _ = run(*base("qa_m5b"))
    q1("CREATE TABLE EXAKIT_VS.QA_USER_TABLE (a INT)")
    rc, o, _ = run("source", "remove", "qa_m5b", "--yes")
    kept = {k["kind"]: k["reason"] for k in o.get("kept", [])}
    check("M5b last remove succeeds with a user table in EXAKIT_VS", rc == 0, o)
    check("M5b ...keeps EXAKIT_VS and names the table, no CASCADE",
          "QA_USER_TABLE" in kept.get("adapter_schema", ""), kept)
    check("M5b ...but removes the kit's own adapter and driver",
          {"adapter_script", "driver_registration"} <= {r["kind"] for r in o.get("removed", [])}, o.get("removed"))
    q1("DROP TABLE EXAKIT_VS.QA_USER_TABLE")
    q1("DROP SCRIPT IF EXISTS EXAKIT_VS.SANDBOX_NET")
    q1("DROP SCHEMA EXAKIT_VS")

    # m2: with no kit sources, a foreign EXAKIT_VS is refused before anything is staged.
    q1("CREATE SCHEMA EXAKIT_VS")
    rc, o, _ = run(*base("qa_m2b"))
    staged = (Path(json.loads((HOME / "manifest.json").read_text())["runtime"]["deployment_dir"])
              / "local" / "runtime" / "exa" / "bucketfs" / "bfsdefault" / "default" / "exakit-vs")
    check("m2 foreign EXAKIT_VS refused with exit 2", rc == 2, o)
    check("m2 ...nothing staged and no source record",
          not staged.exists() and run("source", "show", "qa_m2b")[0] == 2, staged)
    q1("DROP SCHEMA EXAKIT_VS")

    if with_restart:
        restart_cases()

    Path(bad).unlink()
    left = [p.name for p in (HOME / "sources").iterdir() if p.is_dir()] if (HOME / "sources").exists() else []
    check("cleanup: no qa_ sources left", not [n for n in left if n.startswith("qa_")], left)
    failed = [l for l, ok in RESULTS if not ok]
    print("\n%d checks, %d failed" % (len(RESULTS), len(failed)))
    return 1 if failed else 0


def forget_artifacts():
    """After the test dropped kept objects by hand: delete the kit's staged
    files and registry entries that nothing references any more."""
    import shutil
    exa = (Path(json.loads((HOME / "manifest.json").read_text())["runtime"]["deployment_dir"])
           / "local" / "runtime" / "exa")
    for d in (exa / "bucketfs" / "bfsdefault" / "default" / "exakit-vs", exa / "jdbc" / "EXAKIT_POSTGRESQL"):
        if d.exists():
            shutil.rmtree(d)
    reg_path = HOME / "sources" / "registry.json"
    reg = json.loads(reg_path.read_text())
    for kind in ("adapters", "drivers"):
        reg[kind] = {k: v for k, v in reg.get(kind, {}).items() if v.get("refs")}
    reg_path.write_text(json.dumps(reg, indent=2, sort_keys=True) + "\n")


def exakit(*args):
    exe = Path.home() / ".local" / "bin" / ("exakit.cmd" if os.name == "nt" else "exakit")
    return subprocess.run([str(exe)] + list(args), capture_output=True, text=True, timeout=900).returncode


def restart_cases():
    # C2: with the workaround switched off, a host given by name still works
    # through the address the sandbox's own hosts file maps it to.
    rc, o, _ = run(*base("qa_dns"))
    check("restart: connect qa_dns", rc == 0, o)
    exakit("stop")
    exakit("start")
    rc, o, _ = run("source", "check", "qa_dns", env={"EXAKIT_VS_DNS_WORKAROUND": "0"})
    check("C after a restart without the links, a name-based source fails as dns",
          rc == 1 and o.get("kind") == "dns", o)
    rc, o, _ = run("hook", "post-start")
    check("C the post-start hook relinks", o.get("status") == "ok" and o.get("fixed") is True, o)
    rc, o, _ = run("source", "check", "qa_dns")
    check("C ...and the source works again", rc == 0, o)
    run("source", "remove", "qa_dns", "--yes")
    exakit("stop")
    exakit("start")
    rc, o, _ = run(*base("qa_ipfb"), env={"EXAKIT_VS_DNS_WORKAROUND": "0"})
    check("C2 no links: connect falls back to the address", rc == 0 and o.get("ip_fallback") is True, o)
    check("C2 ...read from the sandbox's hosts file, not hard-coded",
          o.get("db_host") not in (None, "host.containers.internal"), o.get("db_host"))
    exakit("stop")
    exakit("start")
    rc, o, _ = run("source", "check", "qa_ipfb", env={"EXAKIT_VS_DNS_WORKAROUND": "0"})
    check("C2 the address-based source survives a restart with no links", rc == 0, o)
    run("source", "remove", "qa_ipfb", "--yes")


if __name__ == "__main__":
    sys.exit(main())
