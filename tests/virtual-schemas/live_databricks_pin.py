"""Live test of the Databricks connector's certificate pin - no workspace
needed. The patched upstream adapter is installed in a throwaway schema and
pointed at Databricks' public endpoint, which serves a real Databricks
certificate; a dummy token means every call fails AFTER the TLS handshake,
which is all this needs:

  - the right pin:  the handshake passes, the failure is Databricks' answer
  - a wrong pin:    refused by the kit's patch (E-EXAKIT-PIN)
  - no pin:         refused too (fail closed)

    <venv-python> tests/virtual-schemas/live_databricks_pin.py

Needs internet access. Everything lives in schema ZZ_DBX_PIN and is dropped.
"""

import json
import ssl
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "setup" / "virtual-schemas"))

from engine import artifacts, plan, sql, state  # noqa: E402

HOST = "accounts.cloud.databricks.com"
RESULTS = []


def check(label, cond, detail=""):
    RESULTS.append((label, bool(cond)))
    print("%s %s%s" % ("ok  " if cond else "FAIL", label, ("  -- %s" % str(detail)[:400]) if not cond else ""))


def message(e):
    return " ".join(l.strip() for l in str(e).splitlines() if "message" in l) or str(e)


def main():
    import pyexasol
    c = plan.load_connectors()["databricks"]
    hooks = c["_hooks"]
    source = artifacts.fetch(plan.adapter(c)).read_text(encoding="utf-8")
    pin = hooks.prepare(c, {"host": HOST, "port": 443}).get("fingerprint")
    check("the certificate is read and VERIFIED from this machine", pin and len(pin) == 64, pin)

    m = json.loads((state.kit_home() / "manifest.json").read_text())["runtime"]
    db = pyexasol.connect(dsn=m["dsn"], user=m["user"], password=Path(m["password_file"]).read_text().strip(),
                          encryption=True, websocket_sslopt={"cert_reqs": ssl.CERT_NONE}, autocommit=True)
    db.execute("CREATE SCHEMA IF NOT EXISTS ZZ_DBX_PIN")
    db.execute("CREATE OR REPLACE CONNECTION ZZ_DBX_PIN_CONN TO "
               "'jdbc:databricks://%s:443/default;AuthMech=3;httpPath=/sql/1.0/warehouses/none' "
               "USER 'token' IDENTIFIED BY 'dapi-qa-dummy-token'" % HOST)

    def attempt(fingerprint):
        patched = hooks.adapter_source(c, source, {"fingerprint": fingerprint})
        stmt = sql.create_lua_adapter_script("ADAPTER", patched, c["script"]["preamble"]).replace(
            '"%s"' % sql.ADAPTER_SCHEMA, '"ZZ_DBX_PIN"', 1)
        db.execute(stmt)
        db.execute("DROP VIRTUAL SCHEMA IF EXISTS ZZ_DBX_PIN_VS CASCADE")
        try:
            db.execute("CREATE VIRTUAL SCHEMA ZZ_DBX_PIN_VS USING ZZ_DBX_PIN.ADAPTER WITH "
                       "CONNECTION_NAME = 'ZZ_DBX_PIN_CONN' CATALOG_NAME = 'main' SCHEMA_NAME = 'default'")
            return "created"
        except Exception as e:
            return message(e)

    try:
        got = attempt(pin)
        check("the right pin: the handshake passes (Databricks itself answers)",
              "E-EXAKIT-PIN" not in got and "E-VSDAB" in got, got)
        got = attempt("0" * 64)
        check("a wrong pin is refused by the kit's patch", "E-EXAKIT-PIN" in got, got)
        got = attempt(None)
        check("no pin at all is refused too (fail closed)", "E-EXAKIT-PIN" in got, got)
    finally:
        db.execute("DROP VIRTUAL SCHEMA IF EXISTS ZZ_DBX_PIN_VS CASCADE")
        db.execute("DROP CONNECTION IF EXISTS ZZ_DBX_PIN_CONN")
        db.execute("DROP SCHEMA IF EXISTS ZZ_DBX_PIN CASCADE")
        db.close()
    failed = [l for l, ok in RESULTS if not ok]
    print("\n%d checks, %d failed" % (len(RESULTS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
