"""Live end-to-end test of the virtual-schemas engine against a real
PostgreSQL and the installed kit's database.

Needs: an installed kit with the database running, and a PostgreSQL reachable
on localhost:5432 with database `spike`, schema `sales`, user `spike` (see
spike/pg-seed.sql and the container command in the Phase-1 notes). Run it
with the kit's pyexasol python:

    VS_LIVE_PG_PASSWORD_FILE=<file> <venv-python> tests/virtual-schemas/live_postgresql.py

It creates sources LIVE_A and LIVE_B and removes them again.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "setup" / "virtual-schemas" / "exakit_vs.py"
PWFILE = os.environ.get("VS_LIVE_PG_PASSWORD_FILE")
RESULTS = []


def run(*args, env=None):
    e = dict(os.environ, EXAKIT_VS_NONINTERACTIVE="1")
    e.update(env or {})
    p = subprocess.run([sys.executable, "-I", str(ENGINE)] + list(args) + ["--json"],
                       capture_output=True, text=True, env=e, timeout=900)
    try:
        obj = json.loads(p.stdout)
    except ValueError:
        obj = {"_raw_stdout": p.stdout, "_stderr": p.stderr}
    return p.returncode, obj


def check(label, cond, detail=""):
    RESULTS.append((label, bool(cond)))
    print("%s %s%s" % ("ok  " if cond else "FAIL", label, ("  -- %s" % detail) if not cond else ""))


def main():
    if not PWFILE:
        sys.exit("set VS_LIVE_PG_PASSWORD_FILE")
    base = ["--url", "jdbc:postgresql://localhost:5432/spike", "--user", "spike", "--schema", "sales",
            "--password-file", PWFILE]

    rc, o = run("connect", "postgresql", "--name", "live_a", *base)
    check("connect A: ready", rc == 0 and o.get("status") == "ready", o)
    check("connect A: tables seen", set(o.get("tables", [])) == {"Orders", "plain_t"}, o.get("tables"))
    check("connect A: encrypted by default", o.get("tls") == "encrypt", o.get("tls"))
    check("connect A: password not in result", "test" not in json.dumps(o).replace("tests", ""), o)

    rc, o = run("connect", "postgresql", "--name", "live_a", "--url", "jdbc:postgresql://localhost:5432/spike",
                "--user", "spike", "--schema", "sales")
    check("re-run connect without password repairs in place", rc == 0 and o.get("status") == "ready", o)

    rc, o = run("connect", "pg", "--name", "live_b", *base, env={"EXAKIT_VS_TLS": "none"})
    check("connect B (alias pg, TLS none on a local host)", rc == 0 and o.get("tls") == "none", o)

    reg = json.loads((Path(os.environ.get("EXAKIT_HOME", Path.home() / ".exasol-starter-kit"))
                      / "sources" / "registry.json").read_text())
    refs = reg["adapters"]["postgresql/4.1.0"]["refs"]
    check("both sources share one staged adapter", {"LIVE_A", "LIVE_B"} <= set(refs), refs)
    # Sources that existed before this test keep the shared artifacts alive.
    others = sorted(set(refs) - {"LIVE_A", "LIVE_B", "LIVE_C", "LIVE_D"})

    rc, o = run("source", "list")
    names = [s["name"] for s in o.get("sources", [])]
    check("list shows both", {"live_a", "live_b"} <= set(names), names)
    rc, o = run("source", "show", "live_a")
    check("show", rc == 0 and o["source"]["objects"]["schema"] == "VS_LIVE_A", o)
    rc, o = run("source", "check", "live_a")
    check("check", rc == 0 and o.get("status") == "ready", o)
    rc, o = run("source", "refresh", "live_b")
    check("refresh", rc == 0 and len(o.get("tables", [])) == 2, o)

    bad = Path(PWFILE).with_name("vs-live-wrong.pw")
    bad.write_text("definitely-wrong")
    try:
        rc, o = run("source", "reauth", "live_b", "--password-file", str(bad))
        check("reauth with a wrong password fails as auth", rc == 1 and o.get("kind") == "auth", o)
        check("auth failure names reauth as the remedy", o.get("remedy") == "exakit source reauth live_b", o)
        check("wrong password never echoed", "definitely-wrong" not in json.dumps(o), o)
    finally:
        bad.unlink()
    rc, o = run("source", "reauth", "live_b", "--password-file", PWFILE)
    check("reauth with the right password", rc == 0, o)

    rc, o = run("connect", "postgresql", "--name", "live_c", "--url", "jdbc:postgresql://localhost:5999/spike",
                "--user", "spike", "--schema", "sales", "--password-file", PWFILE)
    check("unreachable port fails as network, exit 1", rc == 1 and o.get("kind") == "network", o)
    run("source", "remove", "live_c", "--yes")

    rc, o = run("connect", "postgresql", "--name", "live_d", "--url", "jdbc:postgresql://localhost:5432/spike",
                "--user", "spike", "--schema", "sales", "--password-file", PWFILE, "--password-stdin")
    check("--password-file wins without consuming stdin", rc in (0, 1), o)
    run("source", "remove", "live_d", "--yes")

    rc, o = run("source", "remove", "live_a", "--dry-run")
    kinds = [w["kind"] for w in o.get("would_remove", [])]
    check("remove dry-run keeps shared artifacts", kinds == ["virtual_schema", "connection", "source_record"], kinds)
    rc, o = run("source", "remove", "live_a")
    check("remove without --yes and no terminal exits 5", rc == 5, o)

    rc, o = run("source", "remove", "live_a", "--yes")
    check("remove A", rc == 0, o)
    rc, o = run("source", "remove", "live_b", "--yes")
    kinds = [w["kind"] for w in o.get("removed", [])]
    shared = {"adapter_script", "driver_registration", "bucket_folder"}
    if others:
        check("remove keeps artifacts still used by %s" % ", ".join(others), not (shared & set(kinds)), kinds)
    else:
        check("remove last source also removes adapter + driver", shared <= set(kinds), kinds)
    rc, o = run("source", "show", "live_a")
    check("removed source is gone (exit 2)", rc == 2, o)

    failed = [l for l, ok in RESULTS if not ok]
    print("\n%d checks, %d failed" % (len(RESULTS), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
