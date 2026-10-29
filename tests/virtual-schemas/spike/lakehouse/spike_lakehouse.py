"""Phase-6 spike: Lakehouse (Rust SLC 0.33.0, engine v0.57.2) against a local
Iceberg REST catalog + SeaweedFS. Everything lives in schema ZZ_LH_SPIKE and
is dropped at the end unless --keep.

Setup (the credentials are test-only, the same as the upstream compose file):

    exasol slc custom install --alias RUST --language rust \\
        --source lc-rust-0.33.0.tar.gz --auto-approve        # restarts the DB
    # liblakehouse_engine.so from lakehouse-engine.tar.gz (v0.57.2) into
    #   <deployment>/local/runtime/exa/bucketfs/bfsdefault/default/zz-lh-spike/
    podman network create vs-lake
    podman run -d --name vs-s3 --network vs-lake -p 19000:8333 \\
        -v ./seaweedfs-iam.json:/etc/seaweedfs/iam.json:ro chrislusf/seaweedfs:4.48 \\
        mini -dir=/data -bucket=warehouse -s3.config=/etc/seaweedfs/iam.json \\
        -s3.iam.config=/etc/seaweedfs/iam.json -s3.iam.readOnly=false
    podman run -d --name vs-iceberg-rest --network vs-lake -p 18181:8181 \\
        -e CATALOG_WAREHOUSE=s3://warehouse/ \\
        -e CATALOG_IO__IMPL=org.apache.iceberg.aws.s3.S3FileIO \\
        -e CATALOG_S3_ENDPOINT=http://vs-s3:8333 -e CATALOG_S3_PATH__STYLE__ACCESS=true \\
        -e AWS_ACCESS_KEY_ID=lhadmin -e AWS_SECRET_ACCESS_KEY=lhadminsecret123 \\
        -e AWS_REGION=us-east-1 apache/iceberg-rest-fixture:1.10.1
    python seed_iceberg.py              # pyiceberg[pyarrow]==0.10.0, shop.orders, 3 rows
    <kit-venv-python> spike_lakehouse.py [host.containers.internal] [--keep]

Findings (Windows, Nano 2026.2.0-nano.3, 2026-10-29):
- `exasol slc list` offers no official Rust; custom install took 40 s with the
  restart, and JAVA stays installed and working next to RUST.
- The .so is 219 MB unpacked; it loads (LAKEHOUSE_VERSION() = 0.57.2).
- The catalog and storage are reached by IP (169.254.1.2) AND by name
  (host.containers.internal): the Rust SLC links /etc/resolv.conf itself.
- Tables map upper-case (ORDERS, ORDER_ID ...); filter and projection are
  pushed into LAKEHOUSE_SCAN; the MCP read-only user reads the rows.
- TLS is verified against the SLC's CA bundle: an expired certificate fails
  with "invalid peer certificate: certificate expired".
"""
import json
import pathlib
import ssl
import sys

import pyexasol

SO = "buckets/bfsdefault/default/zz-lh-spike/liblakehouse_engine.so"
S = "ZZ_LH_SPIKE"
HOST = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "169.254.1.2"

m = json.loads((pathlib.Path.home() / ".exasol-starter-kit" / "manifest.json").read_text())["runtime"]
c = pyexasol.connect(dsn=m["dsn"], user=m["user"], password=pathlib.Path(m["password_file"]).read_text().strip(),
                     encryption=True, websocket_sslopt={"cert_reqs": ssl.CERT_NONE}, autocommit=True)


def run(label, stmt, fetch=False):
    try:
        st = c.execute(stmt)
        out = st.fetchall() if fetch else "ok"
        print("ok  ", label, "->", out)
        return out
    except Exception as e:
        msg = [l.strip() for l in str(e).splitlines() if "message" in l]
        print("FAIL", label, "->", (msg[0] if msg else str(e))[:600])
        return None


run("schema", "CREATE SCHEMA IF NOT EXISTS %s" % S)
run("adapter script", "CREATE OR REPLACE RUST ADAPTER SCRIPT %s.LAKEHOUSE_ADAPTER AS\n%%udf_object %s\n" % (S, SO))
run("scan script", "CREATE OR REPLACE RUST SCALAR SCRIPT %s.LAKEHOUSE_SCAN(common VARCHAR(2000000), files VARCHAR(2000000))\n"
    "EMITS (...) AS\n%%udf_object %s\n" % (S, SO))
run("version script", "CREATE OR REPLACE RUST SCALAR SCRIPT %s.LAKEHOUSE_VERSION()\nRETURNS VARCHAR(100) AS\n%%udf_object %s\n" % (S, SO))
run("distribute script", "CREATE OR REPLACE LUA SET SCRIPT %s.LAKEHOUSE_DISTRIBUTE_FILES(files VARCHAR(2000000))\n"
    "EMITS (files VARCHAR(2000000)) AS\nfunction run(ctx)\n    repeat\n        ctx.emit(ctx.files)\n    until not ctx.next()\nend\n" % S)
run("engine version (Rust SLC loads the .so)", "SELECT %s.LAKEHOUSE_VERSION()" % S, fetch=True)

creds = {"warehouse": "s3://warehouse/", "endpoint": "http://%s:19000" % HOST, "region": "us-east-1",
         "access_key": "lhadmin", "secret_key": "lhadminsecret123", "path_style": True}
run("connection", "CREATE OR REPLACE CONNECTION ZZ_LH_CONN TO 'http://%s:18181' USER '' IDENTIFIED BY '%s'"
    % (HOST, json.dumps(creds)))
run("drop old vs", "DROP VIRTUAL SCHEMA IF EXISTS ZZ_LH_VS CASCADE")
run("virtual schema", "CREATE VIRTUAL SCHEMA ZZ_LH_VS USING %s.LAKEHOUSE_ADAPTER WITH "
    "CATALOG_CONNECTION='ZZ_LH_CONN' NAMESPACE='shop' ALLOW_HTTP='true'" % S)
run("tables", "SELECT TABLE_NAME FROM SYS.EXA_ALL_TABLES WHERE TABLE_SCHEMA='ZZ_LH_VS'", fetch=True)
run("rows", 'SELECT * FROM ZZ_LH_VS."orders" ORDER BY 1', fetch=True)
run("pushdown filter", 'SELECT "customer" FROM ZZ_LH_VS."orders" WHERE "amount" > 100', fetch=True)

# TLS: the catalog client verifies certificates against the SLC's CA bundle?
for label, uri in (("tls valid cert (expect a non-TLS error)", "https://www.google.com"),
                   ("tls expired cert (expect a certificate error)", "https://expired.badssl.com")):
    run("conn " + label, "CREATE OR REPLACE CONNECTION ZZ_LH_TLS TO '%s' USER '' IDENTIFIED BY '%s'" % (uri, json.dumps(creds)))
    run("drop", "DROP VIRTUAL SCHEMA IF EXISTS ZZ_LH_TLS_VS CASCADE")
    run(label, "CREATE VIRTUAL SCHEMA ZZ_LH_TLS_VS USING %s.LAKEHOUSE_ADAPTER WITH "
        "CATALOG_CONNECTION='ZZ_LH_TLS' NAMESPACE='shop'" % S)

# Java still runs next to Rust.
run("java udf", "CREATE OR REPLACE JAVA SCALAR SCRIPT %s.JHELLO() RETURNS VARCHAR(100) AS\n"
    "class JHELLO { static String run(ExaMetadata exa, ExaIterator ctx) { return \"java \" + System.getProperty(\"java.version\"); } }\n" % S)
run("java runs", "SELECT %s.JHELLO()" % S, fetch=True)

if "--keep" not in sys.argv:
    run("cleanup vs", "DROP VIRTUAL SCHEMA IF EXISTS ZZ_LH_VS CASCADE")
    run("cleanup tls vs", "DROP VIRTUAL SCHEMA IF EXISTS ZZ_LH_TLS_VS CASCADE")
    run("cleanup conns", "DROP CONNECTION IF EXISTS ZZ_LH_CONN")
    run("cleanup conns", "DROP CONNECTION IF EXISTS ZZ_LH_TLS")
    run("cleanup schema", "DROP SCHEMA IF EXISTS %s CASCADE" % S)
c.close()
