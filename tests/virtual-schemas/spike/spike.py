"""Throwaway Phase-1 spike: prove the Virtual Schema mechanics by hand.

Not product code. Each step is its own subcommand so it can be timed and
observed separately:

    python spike.py info                 deployment dir, port, slc list
    python spike.py slc                  exasol slc install java --no-restart
    python spike.py fetch                download + sha256-verify adapter and driver
    python spike.py stage [--nosecurity] copy JARs into bucketfs + jdbc/<NAME>/settings.cfg
    python spike.py buckets              list /buckets from inside the DB (UDF-free: via adapter error)
    python spike.py restart              exasol stop + start, timed
    python spike.py sql HOST [--tls MODE] [--case upper|preserve]
                                         CONNECTION + adapter script + VS, then query
    python spike.py probe HOST...        IMPORT ... STATEMENT 'SELECT 1' per host candidate
    python spike.py readonly             query the VS as the MCP read-only user
    python spike.py cleanup              drop everything the spike created

Run it with the kit's pyexasol venv python. The source password is read from
the SPIKE_PG_PASSWORD environment variable (a throwaway test container's
password), never from argv.
"""

import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HOME = Path(os.environ.get("EXAKIT_HOME", Path.home() / ".exasol-starter-kit"))
SCRATCH = Path(__file__).resolve().parent / ".cache"  # gitignored by the spike dir's .gitignore

ADAPTER_REPO = "exasol/postgresql-virtual-schema"
ADAPTER_TAG = "4.1.0"
ADAPTER_JAR = "virtual-schema-dist-14.1.0-postgresql-4.1.0.jar"
DRIVER_VERSION = "42.7.14"
DRIVER_JAR = f"postgresql-{DRIVER_VERSION}.jar"
DRIVER_URL = (
    "https://repo.maven.apache.org/maven2/org/postgresql/postgresql/"
    f"{DRIVER_VERSION}/{DRIVER_JAR}"
)
DRIVERNAME = "EXAKIT_POSTGRESQL"
BFS_DIR = os.environ.get("SPIKE_BFS_DIR", f"exakit-vs/postgresql/{ADAPTER_TAG}")

CONN = "EXAKIT_SRC_SPIKE"
ADAPTER_SCHEMA = "EXAKIT_VS"
ADAPTER_SCRIPT = f"POSTGRESQL_{ADAPTER_TAG.replace('.', '_')}"
VS = "VS_SPIKE"


def manifest():
    return json.loads((HOME / "manifest.json").read_text(encoding="utf-8"))


def exasol_cli():
    exe = Path.home() / ".local" / "bin" / ("exasol.exe" if os.name == "nt" else "exasol")
    return str(exe) if exe.exists() else "exasol"


def run(cmd, check=True):
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True)
    dt = time.time() - t0
    print(f"$ {' '.join(cmd)}  -> rc={p.returncode} ({dt:.1f}s)")
    out = (p.stdout + p.stderr).strip()
    if out:
        print("  " + out.replace("\n", "\n  "))
    if check and p.returncode != 0:
        sys.exit(p.returncode)
    return p, dt


_DEPLOY_DIR = None


def deploy_dir():
    global _DEPLOY_DIR
    if _DEPLOY_DIR is None:
        p = subprocess.run([exasol_cli(), "info", "--json"], capture_output=True, text=True)
        try:
            _DEPLOY_DIR = Path(json.loads(p.stdout)["deploymentDir"])
        except Exception:
            _DEPLOY_DIR = Path(manifest()["runtime"]["deployment_dir"])
    return _DEPLOY_DIR


def exa_root():
    return deploy_dir() / "local" / "runtime" / "exa"


def db_port():
    dep = json.loads((deploy_dir() / "deployment.json").read_text(encoding="utf-8"))
    return dep.get("dbPort", 8563)


def connect(user=None, pwfile=None):
    import pyexasol

    rt = manifest()["runtime"]
    user = user or rt["user"]
    pwfile = pwfile or rt["password_file"]
    pw = Path(pwfile).read_text(encoding="utf-8").strip()
    return pyexasol.connect(
        dsn=f"127.0.0.1:{db_port()}",
        user=user,
        password=pw,
        encryption=True,
        websocket_sslopt={"cert_reqs": ssl.CERT_NONE},
        autocommit=True,
    )


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, dest):
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f)
    os.replace(tmp, dest)


def cmd_info():
    d = deploy_dir()
    print("deploymentDir:", d)
    print("exa root exists:", exa_root().exists(), exa_root())
    if exa_root().exists():
        for p in sorted(exa_root().iterdir()):
            print("  ", p.name)
    print("dbPort:", db_port())
    run([exasol_cli(), "slc", "list"], check=False)


def cmd_slc():
    run([exasol_cli(), "slc", "list"], check=False)
    run([exasol_cli(), "slc", "install", "java", "--no-restart"], check=False)
    run([exasol_cli(), "slc", "list"], check=False)


def cmd_fetch():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    base = f"https://github.com/{ADAPTER_REPO}/releases/download/{ADAPTER_TAG}/{ADAPTER_JAR}"
    a = SCRATCH / ADAPTER_JAR
    if not a.exists():
        download(base, a)
    with urllib.request.urlopen(base + ".sha256", timeout=60) as r:
        want = r.read().decode().split()[0]
    got = sha256(a)
    print(f"adapter sha256 {got} upstream {want} -> {'OK' if got == want else 'MISMATCH'}")
    d = SCRATCH / DRIVER_JAR
    if not d.exists():
        download(DRIVER_URL, d)
    with urllib.request.urlopen(DRIVER_URL + ".sha1", timeout=60) as r:
        want1 = r.read().decode().split()[0]
    h = hashlib.sha1(d.read_bytes()).hexdigest()
    print(f"driver sha1 {h} upstream {want1} -> {'OK' if h == want1 else 'MISMATCH'}")
    print(f"driver sha256 (to pin): {sha256(d)}")


def cmd_stage(nosecurity):
    root = exa_root()
    bfs = root / "bucketfs" / "bfsdefault" / "default" / Path(BFS_DIR)
    bfs.mkdir(parents=True, exist_ok=True)
    for name in (ADAPTER_JAR, DRIVER_JAR):
        tmp = bfs / (name + ".part")
        shutil.copyfile(SCRATCH / name, tmp)
        os.replace(tmp, bfs / name)
    jdbc = root / "jdbc" / DRIVERNAME
    jdbc.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SCRATCH / DRIVER_JAR, jdbc / DRIVER_JAR)
    lines = [
        f"DRIVERNAME={DRIVERNAME}",
        "PREFIX=jdbc:postgresql:",
        "DRIVERMAIN=org.postgresql.Driver",
        "FETCHSIZE=100000",
        "INSERTSIZE=-1",
        f"JAR={DRIVER_JAR}",
    ]
    if nosecurity:
        lines.append("NOSECURITY=YES")
    (jdbc / "settings.cfg").write_bytes(("\n".join(lines) + "\n\n").encode("ascii"))
    print("staged:", bfs, "and", jdbc)
    for p in sorted(bfs.iterdir()) + sorted(jdbc.iterdir()):
        print("  ", p, p.stat().st_size)


def cmd_restart():
    t0 = time.time()
    run([exasol_cli(), "stop"], check=False)
    run([exasol_cli(), "start"], check=False)
    # wait for SQL
    while time.time() - t0 < 900:
        try:
            c = connect()
            c.execute("SELECT 1")
            c.close()
            break
        except Exception:
            time.sleep(3)
    print(f"restart total until SQL answers: {time.time() - t0:.1f}s")


def q(c, sql, show=True):
    print("SQL>", sql if "IDENTIFIED BY" not in sql else sql.split("IDENTIFIED BY")[0] + "IDENTIFIED BY '***'")
    t0 = time.time()
    try:
        st = c.execute(sql)
        rows = st.fetchall() if st.result_type == "resultSet" else []
        print(f"  ok ({time.time() - t0:.1f}s) rows={len(rows)}")
        if show:
            for r in rows[:10]:
                print("   ", r)
        return rows
    except Exception as e:
        print(f"  FAIL ({time.time() - t0:.1f}s): {str(e)[:900]}")
        return None


def jdbc_url(host, tls):
    url = f"jdbc:postgresql://{host}:5432/spike"
    if tls == "verify-java":
        url += "?sslmode=verify-full&sslfactory=org.postgresql.ssl.DefaultJavaSSLFactory"
    elif tls:
        url += f"?sslmode={tls}"
    return url


def make_connection(c, host, tls):
    pw = os.environ["SPIKE_PG_PASSWORD"].replace("'", "''")
    q(c, f"CREATE OR REPLACE CONNECTION {CONN} TO '{jdbc_url(host, tls)}' USER 'spike' IDENTIFIED BY '{pw}'")


def cmd_probe(hosts, tls):
    c = connect()
    for h in hosts:
        print(f"--- host candidate: {h}")
        make_connection(c, h, tls)
        q(c, f"SELECT * FROM (IMPORT FROM JDBC AT {CONN} STATEMENT 'SELECT 1')")


def cmd_sql(host, tls, case):
    c = connect()
    make_connection(c, host, tls)
    q(c, f"SELECT * FROM (IMPORT FROM JDBC AT {CONN} STATEMENT 'SELECT 1')")
    q(c, f"CREATE SCHEMA IF NOT EXISTS {ADAPTER_SCHEMA}")
    script = (
        f"CREATE OR REPLACE JAVA ADAPTER SCRIPT {ADAPTER_SCHEMA}.{ADAPTER_SCRIPT} AS\n"
        "  %scriptclass com.exasol.adapter.RequestDispatcher;\n"
        + ("  %jvmoption -Duser.timezone=UTC;\n" if os.environ.get("SPIKE_UTC", "1") == "1" else "")
        + f"  %jar /buckets/bfsdefault/default/{BFS_DIR}/{ADAPTER_JAR};\n"
        + (f"  %jar /buckets/bfsdefault/default/{BFS_DIR}/{DRIVER_JAR};\n" if os.environ.get("SPIKE_DRIVER_JAR", "1") == "1" else "")
        + "/"
    )
    q(c, script)
    q(c, f"DROP VIRTUAL SCHEMA IF EXISTS {VS} CASCADE")
    mapping = "PRESERVE_ORIGINAL_CASE" if case == "preserve" else "CONVERT_TO_UPPER"
    q(
        c,
        f"CREATE VIRTUAL SCHEMA {VS} USING {ADAPTER_SCHEMA}.{ADAPTER_SCRIPT} WITH "
        f"CONNECTION_NAME = '{CONN}' CATALOG_NAME = 'spike' SCHEMA_NAME = 'sales' "
        f"POSTGRESQL_IDENTIFIER_MAPPING = '{mapping}'",
    )
    q(c, f"SELECT TABLE_NAME FROM SYS.EXA_ALL_TABLES WHERE TABLE_SCHEMA = '{VS}'")
    q(c, f"SELECT COLUMN_TABLE, COLUMN_NAME, COLUMN_TYPE FROM SYS.EXA_ALL_COLUMNS WHERE COLUMN_SCHEMA = '{VS}'")
    for t in ('"Orders"', "ORDERS", '"orders"', "PLAIN_T", '"plain_t"'):
        q(c, f"SELECT * FROM {VS}.{t} LIMIT 3")


def cmd_readonly():
    pw = HOME / "credentials" / "mcp_readonly_password"
    c = connect(user="mcp_readonly", pwfile=str(pw))
    q(c, "SELECT PRIVILEGE FROM SYS.EXA_USER_SYS_PRIVS")
    q(c, f"SELECT TABLE_NAME FROM SYS.EXA_ALL_TABLES WHERE TABLE_SCHEMA = '{VS}'")
    for t in ('"Orders"', "ORDERS", '"plain_t"', "PLAIN_T"):
        q(c, f"SELECT * FROM {VS}.{t} LIMIT 3")


def cmd_cleanup():
    c = connect()
    q(c, f"DROP VIRTUAL SCHEMA IF EXISTS {VS} CASCADE")
    q(c, f"DROP SCHEMA IF EXISTS {ADAPTER_SCHEMA} CASCADE")
    q(c, f"DROP CONNECTION IF EXISTS {CONN}")
    root = exa_root()
    for p in (root / "bucketfs" / "bfsdefault" / "default" / "exakit-vs", root / "jdbc" / DRIVERNAME):
        if p.exists():
            shutil.rmtree(p)
            print("removed", p)


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    tls = None
    if "--tls" in rest:
        i = rest.index("--tls")
        tls = rest[i + 1]
        rest = rest[:i] + rest[i + 2 :]
    case = "upper"
    if "--case" in rest:
        i = rest.index("--case")
        case = rest[i + 1]
        rest = rest[:i] + rest[i + 2 :]
    if cmd == "info":
        cmd_info()
    elif cmd == "slc":
        cmd_slc()
    elif cmd == "fetch":
        cmd_fetch()
    elif cmd == "stage":
        cmd_stage("--nosecurity" in rest)
    elif cmd == "restart":
        cmd_restart()
    elif cmd == "probe":
        cmd_probe(rest, tls)
    elif cmd == "sql":
        cmd_sql(rest[0], tls, case)
    elif cmd == "readonly":
        cmd_readonly()
    elif cmd == "cleanup":
        cmd_cleanup()
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
