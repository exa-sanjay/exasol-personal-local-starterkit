"""Live tests for the connectors beyond PostgreSQL, against local containers.

Each connector runs only when its password file is given (the password of
the test container's reader account), so the suite fits whatever is up:

    VS_LIVE_MYSQL_PASSWORD_FILE    mysql:8 on localhost:3306, database shop,
                                   user reader, table shop.Orders
    VS_LIVE_MSSQL_PASSWORD_FILE    mssql/server:2022 on localhost:1433,
                                   database Shop, schema sales, user reader
    VS_LIVE_ORACLE_PASSWORD_FILE   gvenzl/oracle-free on localhost:1521,
                                   service FREEPDB1, user/schema shop, table ORDERS
    VS_LIVE_EXASOL=1               a second schema of this database (EXA_SRC,
                                   created here), read as the kit's admin user

    <venv-python> tests/virtual-schemas/live_connectors.py

Every source it makes is named qa_* and removed again.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "setup" / "virtual-schemas" / "exakit_vs.py"
HOME = Path(os.environ.get("EXAKIT_HOME", Path.home() / ".exasol-starter-kit"))
RESULTS = []


def run(*args):
    e = dict(os.environ, EXAKIT_VS_NONINTERACTIVE="1")
    p = subprocess.run([sys.executable, "-I", str(ENGINE)] + list(args) + ["--json"],
                       capture_output=True, text=True, env=e, timeout=900)
    try:
        return p.returncode, json.loads(p.stdout)
    except ValueError:
        return p.returncode, {"_raw": p.stdout[-300:], "_err": p.stderr[-300:]}


def check(label, cond, detail=""):
    RESULTS.append((label, bool(cond)))
    print("%s %s%s" % ("ok  " if cond else "FAIL", label, ("  -- %s" % str(detail)[:400]) if not cond else ""))


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


def source_case(label, name, connect_args, table, expect_rows, extra=None):
    rc, o = run("connect", *connect_args, "--name", name)
    check("%s: connect is ready" % label, rc == 0 and o.get("status") == "ready", o)
    if rc != 0:
        return
    rows = admin_rows('SELECT COUNT(*) FROM "VS_%s"."%s"' % (name.upper(), table))
    check("%s: rows come through the virtual schema" % label, rows and rows[0][0] == expect_rows, rows)
    rc, o = run("source", "check", name)
    check("%s: source check" % label, rc == 0, o)
    for fn in extra or []:
        fn(name)
    rc, o = run("source", "remove", name, "--yes")
    check("%s: remove" % label, rc == 0, o)


def main():
    ran = False
    mysql = os.environ.get("VS_LIVE_MYSQL_PASSWORD_FILE")
    if mysql:
        ran = True
        base = ["mysql", "--url", "jdbc:mysql://localhost:3306/shop", "--user", "reader", "--password-file", mysql]
        rc, o = run("connect", *base, "--name", "qa_my_a")
        check("MySQL: first source", rc == 0, o)
        source_case("MySQL (unencrypted, second source)", "qa_my_b", base + ["--tls", "none"], "Orders", 2)
        reg = json.loads((HOME / "sources" / "registry.json").read_text())
        check("MySQL: the remaining source still holds the shared adapter",
              reg["adapters"].get("mysql/6.1.0", {}).get("refs") == ["QA_MY_A"], reg.get("adapters"))
        rc, o = run("source", "remove", "qa_my_a", "--yes")
        kinds = [r["kind"] for r in o.get("removed", [])]
        check("MySQL: the last source takes the adapter and driver with it",
              "adapter_script" in kinds and "driver_registration" in kinds, kinds)

    mssql = os.environ.get("VS_LIVE_MSSQL_PASSWORD_FILE")
    if mssql:
        ran = True
        url = "jdbc:sqlserver://localhost:1433;databaseName=Shop"
        source_case("SQL Server", "qa_ms", ["mssql", "--url", url, "--user", "reader", "--schema", "sales",
                                            "--password-file", mssql], "Orders", 2)
        rc, o = run("connect", "sqlserver", "--name", "qa_ms_bad", "--url", url, "--user", "reader",
                    "--schema", "nosuch", "--password-file", mssql)
        check("SQL Server: a missing schema is schema_missing", rc == 1 and o.get("kind") == "schema_missing", o)

    oracle = os.environ.get("VS_LIVE_ORACLE_PASSWORD_FILE")
    if oracle:
        ran = True
        url = "jdbc:oracle:thin:@//localhost:1521/FREEPDB1"

        def nne(name):
            # The session the database opens through the kit's connection is
            # encrypted (Native Network Encryption), as Oracle itself reports.
            stmt = ("SELECT COUNT(*) FROM V$SESSION_CONNECT_INFO WHERE SID = SYS_CONTEXT(''USERENV'',''SID'') "
                    "AND NETWORK_SERVICE_BANNER LIKE ''%%AES%%Encryption%%''")
            rows = admin_rows("SELECT * FROM (IMPORT FROM JDBC DRIVER = 'EXAKIT_ORACLE' AT EXAKIT_SRC_%s "
                              "STATEMENT '%s')" % (name.upper(), stmt))
            check("Oracle: the connection is encrypted (AES, per V$SESSION_CONNECT_INFO)",
                  rows and int(rows[0][0]) >= 1, rows)
        source_case("Oracle", "qa_ora", ["oracle", "--url", url, "--user", "shop", "--schema", "shop",
                                         "--password-file", oracle], "ORDERS", 2, [nne])

    if os.environ.get("VS_LIVE_EXASOL") == "1":
        ran = True
        admin_rows("CREATE SCHEMA IF NOT EXISTS EXA_SRC")
        admin_rows("CREATE OR REPLACE TABLE EXA_SRC.CUSTOMERS (ID INT, NAME VARCHAR(50))")
        admin_rows("INSERT INTO EXA_SRC.CUSTOMERS VALUES (1, 'Acme'), (2, 'Globex')")
        pw = json.loads((HOME / "manifest.json").read_text())["runtime"]["password_file"]

        def verified(name):
            rc, o = run("source", "show", name)
            check("Exasol: TLS is certificate-verified (fingerprint)", o.get("source", {}).get("tls") == "verify", o)
            props = dict(admin_rows("SELECT PROPERTY_NAME, PROPERTY_VALUE FROM SYS.EXA_ALL_VIRTUAL_SCHEMA_PROPERTIES "
                                    "WHERE SCHEMA_NAME = 'VS_%s'" % name.upper()))
            check("Exasol: a schema of this database runs IS_LOCAL", props.get("IS_LOCAL") == "true", props)
        source_case("Exasol", "qa_exa", ["exasol", "--host", "localhost", "--user", "sys", "--schema", "EXA_SRC",
                                         "--password-file", pw], "CUSTOMERS", 2, [verified])
        admin_rows("DROP SCHEMA EXA_SRC CASCADE")

    if not ran:
        sys.exit("set at least one of VS_LIVE_MYSQL_PASSWORD_FILE, VS_LIVE_MSSQL_PASSWORD_FILE, "
                 "VS_LIVE_ORACLE_PASSWORD_FILE, VS_LIVE_EXASOL=1")
    failed = [l for l, ok in RESULTS if not ok]
    print("\n%d checks, %d failed" % (len(RESULTS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
