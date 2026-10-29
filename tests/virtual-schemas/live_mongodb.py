"""Live tests for the MongoDB connector (native Rust adapter) against a local
mongo:8 container: localhost:27017, database shop, collection people with 3
documents (a nested object and an array each), and a user `reader` with the
read role on shop, defined in admin.

    VS_LIVE_MONGO_PASSWORD_FILE=<reader's password file> \\
        <venv-python> tests/virtual-schemas/live_mongodb.py

On a machine without the Rust runtime the first connect installs it - with
--yes, so one database restart. Every source it makes is named qa_* and
removed again.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "setup" / "virtual-schemas" / "exakit_vs.py"
HOME = Path(os.environ.get("EXAKIT_HOME", Path.home() / ".exasol-starter-kit"))
URL = "mongodb://reader@localhost:27017/shop?tls=false"
RESULTS = []


def run(*args, env=None):
    e = dict(os.environ, EXAKIT_VS_NONINTERACTIVE="1", EXAKIT_VS_COLLECTION="people")
    e.update(env or {})
    p = subprocess.run([sys.executable, "-I", str(ENGINE)] + list(args) + ["--json"],
                       capture_output=True, text=True, env=e, timeout=1800)
    try:
        return p.returncode, json.loads(p.stdout)
    except ValueError:
        return p.returncode, {"_raw": p.stdout[-400:], "_err": p.stderr[-400:]}


def check(label, cond, detail=""):
    RESULTS.append((label, bool(cond)))
    print("%s %s%s" % ("ok  " if cond else "FAIL", label, ("  -- %s" % str(detail)[:500]) if not cond else ""))


def admin_rows(sql_text):
    import ssl
    import pyexasol
    m = json.loads((HOME / "manifest.json").read_text(encoding="utf-8"))["runtime"]
    c = pyexasol.connect(dsn=m["dsn"], user=m["user"], password=Path(m["password_file"]).read_text().strip(),
                         encryption=True, websocket_sslopt={"cert_reqs": ssl.CERT_NONE}, autocommit=True)
    try:
        st = c.execute(sql_text)
        return st.fetchall() if st.result_type == "resultSet" else []
    finally:
        c.close()


def main():
    pw = os.environ.get("VS_LIVE_MONGO_PASSWORD_FILE")
    if not pw:
        sys.exit("set VS_LIVE_MONGO_PASSWORD_FILE (and start the local mongo:8, see the docstring)")
    bad = Path(tempfile.gettempdir()) / "vs-qa-mongo-wrong.pw"
    bad.write_text("definitely-wrong-ZZ")
    secret = Path(pw).read_text().strip()

    rc, o = run("connect", "mongodb", "--name", "qa_mongo", "--url", URL, "--password-file", pw, "--yes")
    check("connect is ready", rc == 0 and o.get("status") == "ready", o)
    check("root, object and array tables", o.get("tables") == ["PEOPLE", "PEOPLE_profile", "PEOPLE_tags_arr"],
          o.get("tables"))
    check("a local MongoDB without TLS is 'none'", o.get("tls") == "none", o.get("tls"))
    rows = admin_rows('SELECT p."name", pr."city" FROM VS_QA_MONGO.PEOPLE p JOIN VS_QA_MONGO."PEOPLE_profile" pr '
                      'ON pr."_id" = p."profile|object" ORDER BY p."mongo_id"')
    check("a nested object joins to its document", [r[1] for r in rows] == ["London", "Arlington", "Helsinki"], rows)
    tags = admin_rows('SELECT t."_value" FROM VS_QA_MONGO.PEOPLE p JOIN VS_QA_MONGO."PEOPLE_tags_arr" t '
                      'ON t."_parent" = p."_id" WHERE p."name" = \'Ada\' ORDER BY t."_pos"')
    check("an array keeps its order", [r[0] for r in tags] == ["math", "engines"], tags)
    props = dict(admin_rows("SELECT PROPERTY_NAME, PROPERTY_VALUE FROM SYS.EXA_ALL_VIRTUAL_SCHEMA_PROPERTIES "
                            "WHERE SCHEMA_NAME = 'VS_QA_MONGO'"))
    check("properties: connection, database, collection",
          props == {"MONGODB_CONNECTION": "EXAKIT_SRC_QA_MONGO", "DATABASE": "shop", "COLLECTION": "people"}, props)
    conn = admin_rows("SELECT CONNECTION_STRING, USER_NAME FROM SYS.EXA_DBA_CONNECTIONS "
                      "WHERE CONNECTION_NAME = 'EXAKIT_SRC_QA_MONGO'")
    check("the URI reaches this machine through the host alias, user in its own field",
          conn and conn[0][0].startswith("mongodb://host.containers.internal:27017/") and conn[0][1] == "reader", conn)
    st = json.loads((HOME / "sources" / "qa_mongo" / "state.json").read_text())
    check("the MCP read-only user reads it", st.get("mcp_readable") is True, st)
    log = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in (HOME / "logs").glob("virtual-schemas-*.log"))
    check("the password never reaches the log", secret not in log)

    # Another collection of the same database is a property change: no password.
    rc, o = run("connect", "mongodb", "--name", "qa_mongo", env={"EXAKIT_VS_COLLECTION": "nosuch"})
    check("a collection change needs no password, and an unknown collection is reported",
          rc != 2 and o.get("kind") != "password_needed", o)
    rc, o = run("connect", "mongodb", "--name", "qa_mongo")
    check("...and switching back works", rc == 0, o)

    rc, o = run("source", "reauth", "qa_mongo", "--password-file", str(bad))
    # The adapter reports a refused login and a TLS mismatch with one line,
    # so the kit says what it knows: login or connection, and what to check.
    check("reauth with a wrong password fails (login_or_connection)",
          rc == 1 and o.get("kind") == "login_or_connection", o)
    check("...and the working password stays",
          admin_rows("SELECT COUNT(*) FROM VS_QA_MONGO.PEOPLE")[0][0] == 3)
    rc, o = run("source", "check", "qa_mongo")
    check("source check", rc == 0, o)

    rc, o = run("connect", "mongodb", "--name", "qa_mongo_bad", "--url", URL, "--password-file", str(bad))
    check("a wrong password on a first connect fails with what to check",
          rc == 1 and o.get("kind") == "login_or_connection" and "authentication database" in (o.get("remedy_hint") or ""), o)
    rc, o = run("connect", "mongodb", "--name", "qa_mongo_tls", "--url", "mongodb://reader@localhost:27017/shop",
                "--password-file", pw, "--tls", "verify")
    check("TLS against a plain MongoDB fails with what to check",
          rc == 1 and o.get("kind") == "login_or_connection" and "--tls none" in (o.get("remedy_hint") or ""), o)
    left = [n for n in ("qa_mongo_bad", "qa_mongo_tls") if (HOME / "sources" / n).exists()]
    check("failed first connects left nothing", not left, left)

    rc, o = run("source", "remove", "qa_mongo", "--yes")
    kinds = {r["kind"] for r in o.get("removed", [])}
    check("remove takes adapter, bucket folder and the scan script",
          rc == 0 and {"adapter_script", "bucket_folder", "script"} <= kinds, o)
    left = admin_rows("SELECT SCRIPT_NAME FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = 'EXAKIT_VS' "
                      "AND SCRIPT_NAME LIKE 'MONGODB%'")
    check("no MongoDB scripts left", left == [], left)

    bad.unlink()
    failed = [l for l, ok in RESULTS if not ok]
    print("\n%d checks, %d failed" % (len(RESULTS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
