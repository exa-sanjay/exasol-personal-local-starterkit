"""Live tests for the Lakehouse connector (native Rust adapter) against the
local Iceberg stack of tests/virtual-schemas/spike/lakehouse: an Iceberg REST
catalog on localhost:18181, SeaweedFS on localhost:19000 with the test-only
key pair lhadmin / lhadminsecret123 (the upstream compose file's), and the
table shop.orders with 3 rows (seed_iceberg.py).

    VS_LIVE_LAKEHOUSE=1 <venv-python> tests/virtual-schemas/live_lakehouse.py

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
RESULTS = []
LAKE_ENV = {"EXAKIT_VS_NAMESPACE": "shop", "EXAKIT_VS_WAREHOUSE": "s3://warehouse/",
            "EXAKIT_VS_ENDPOINT": "http://localhost:19000"}


def run(*args, env=None):
    e = dict(os.environ, EXAKIT_VS_NONINTERACTIVE="1", **LAKE_ENV)
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


def secret_file(text):
    f = Path(tempfile.gettempdir()) / ("vs-qa-lake-%d.pw" % len(text))
    f.write_text(text)
    return str(f)


def main():
    if os.environ.get("VS_LIVE_LAKEHOUSE") != "1":
        sys.exit("set VS_LIVE_LAKEHOUSE=1 (and start the local Iceberg stack, see the docstring)")
    good, bad = secret_file("lhadminsecret123"), secret_file("wrong-secret-ZZ")
    base = ["connect", "lakehouse", "--url", "http://localhost:18181", "--user", "lhadmin"]

    rc, o = run(*base, "--name", "qa_lake", "--password-file", good, "--yes")
    check("connect is ready", rc == 0 and o.get("status") == "ready", o)
    check("plain-HTTP catalog on this machine is 'none' TLS", o.get("tls") == "none", o.get("tls"))
    check("the table maps upper-case", "ORDERS" in (o.get("tables") or []), o.get("tables"))
    rows = admin_rows("SELECT COUNT(*), SUM(AMOUNT) FROM VS_QA_LAKE.ORDERS")
    check("3 rows through the virtual schema", rows and int(rows[0][0]) == 3, rows)
    reg = json.loads((HOME / "sources" / "registry.json").read_text())
    check("the kit recorded the Rust runtime it installed",
          (reg.get("runtimes") or {}).get("rust", {}).get("version") == "0.33.0", reg.get("runtimes"))
    st = json.loads((HOME / "sources" / "qa_lake" / "state.json").read_text())
    check("the MCP read-only user reads it", st.get("mcp_readable") is True, st)
    props = dict(admin_rows("SELECT PROPERTY_NAME, PROPERTY_VALUE FROM SYS.EXA_ALL_VIRTUAL_SCHEMA_PROPERTIES "
                            "WHERE SCHEMA_NAME = 'VS_QA_LAKE'"))
    check("properties: namespace, ALLOW_HTTP, the kit's connection",
          props.get("NAMESPACE") == "shop" and props.get("ALLOW_HTTP") == "true"
          and props.get("CATALOG_CONNECTION") == "EXAKIT_SRC_QA_LAKE", props)
    conn = admin_rows("SELECT CONNECTION_STRING FROM SYS.EXA_DBA_CONNECTIONS WHERE CONNECTION_NAME = 'EXAKIT_SRC_QA_LAKE'")
    check("localhost became the container's host alias", conn and "host.containers.internal" in conn[0][0], conn)
    log = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                    for p in (HOME / "logs").glob("virtual-schemas-*.log"))
    check("the secret key never reaches the log", "lhadminsecret123" not in log)

    rc, o = run("source", "check", "qa_lake")
    check("source check", rc == 0, o)
    rc, o = run("source", "show", "qa_lake")
    check("show names the Rust runtime", (o.get("source") or {}).get("artifacts", {}).get("runtime") == "rust", o)

    # Failures are classified, and a failed first connect leaves nothing.
    rc, o = run(*base, "--name", "qa_lake_auth", "--password-file", bad)
    check("a wrong secret key is auth", rc == 1 and o.get("kind") == "auth", o)
    rc, o = run(*base, "--name", "qa_lake_ns", "--password-file", good, env={"EXAKIT_VS_NAMESPACE": "nosuch"})
    check("a missing namespace is schema_missing", rc == 1 and o.get("kind") == "schema_missing", o)
    rc, o = run(*base, "--name", "qa_lake_tls", "--password-file", good, "--tls", "verify")
    check("https against a plain-HTTP catalog is tls", rc == 1 and o.get("kind") == "tls", o)
    rc, o = run("connect", "lakehouse", "--name", "qa_lake_exp", "--url", "https://expired.badssl.com",
                "--user", "lhadmin", "--password-file", good)
    check("an expired certificate is refused as tls (verified TLS)", rc == 1 and o.get("kind") == "tls", o)
    left = [n for n in ("qa_lake_auth", "qa_lake_ns", "qa_lake_tls", "qa_lake_exp")
            if (HOME / "sources" / n).exists()]
    check("failed first connects left no source records", not left, left)
    probes = admin_rows("SELECT SCHEMA_NAME FROM SYS.EXA_SCHEMAS WHERE SCHEMA_NAME LIKE 'VS_QA_LAKE%'")
    check("...and no probe or half-made schemas", probes == [("VS_QA_LAKE",)], probes)

    rc, o = run("source", "remove", "qa_lake", "--dry-run")
    would = {(w["kind"], w["name"]) for w in o.get("would_remove", [])}
    check("remove --dry-run lists the companion scripts",
          ("script", "EXAKIT_VS.LAKEHOUSE_SCAN") in would, would)
    rc, o = run("source", "remove", "qa_lake", "--yes")
    kinds = {r["kind"] for r in o.get("removed", [])}
    check("remove takes adapter, bucket folder and companions",
          rc == 0 and {"adapter_script", "bucket_folder", "script"} <= kinds, o)
    left = admin_rows("SELECT SCRIPT_NAME FROM SYS.EXA_ALL_SCRIPTS WHERE SCRIPT_SCHEMA = 'EXAKIT_VS' "
                      "AND SCRIPT_NAME LIKE 'LAKEHOUSE%'")
    check("no Lakehouse scripts left", left == [], left)

    for f in (good, bad):
        Path(f).unlink()
    failed = [l for l, ok in RESULTS if not ok]
    print("\n%d checks, %d failed" % (len(RESULTS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
