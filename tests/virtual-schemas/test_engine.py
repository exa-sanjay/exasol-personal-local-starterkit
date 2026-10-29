"""Unit tests for the virtual-schemas engine: no database, no network.

    python -m unittest discover -s tests/virtual-schemas -p "test_*.py"
"""

import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "setup" / "virtual-schemas"))

from engine import artifacts, cli, lifecycle, net, plan, sql, state, ui  # noqa: E402

PG = plan.load_connectors()["postgresql"]


class UrlParsing(unittest.TestCase):
    def test_jdbc_url_fields(self):
        f, notes = net.parse_url(PG, "jdbc:postgresql://db.example.com:6543/shop?sslmode=require")
        self.assertEqual(f["host"], "db.example.com")
        self.assertEqual(f["port"], 6543)
        self.assertEqual(f["database"], "shop")
        self.assertEqual(f["params"], {"sslmode": "require"})
        self.assertEqual(notes, [])

    def test_default_port(self):
        f, _ = net.parse_url(PG, "jdbc:postgresql://db.example.com/shop")
        self.assertEqual(f["port"], 5432)

    def test_cloud_uri_strips_password(self):
        f, notes = net.parse_url(PG, "postgres://reader:s3cr%40t@ep-x.neon.tech/app?sslmode=require")
        self.assertEqual(f["user"], "reader")
        self.assertEqual(f["host"], "ep-x.neon.tech")
        self.assertNotIn("s3cr", json.dumps(f))
        self.assertEqual([n[0] for n in notes], ["password_stripped"])

    def test_password_with_url_delimiters_never_leaks(self):
        # A password containing '/', '?', ';' or '@' used to be cut in two,
        # with the first half shown in a "port must be a number" error.
        for pw in ("Se/cretZZQ", "p?xZZQ", "a;b@cZZQ"):
            with self.subTest(pw=pw):
                f, notes = net.parse_url(PG, "postgres://spike:%s@localhost:5432/spike" % pw)
                self.assertEqual((f["host"], f["port"], f["database"], f["user"]),
                                 ("localhost", 5432, "spike", "spike"))
                self.assertNotIn("ZZQ", json.dumps(f))
                self.assertEqual(state.redact("x %s y" % pw), "x *** y")

    def test_semicolon_parameter_form(self):
        # pgJDBC's ';key=value' form after the database name used to stay in
        # the database name - and the password with it, in the stored URL.
        f, notes = net.parse_url(PG, "jdbc:postgresql://localhost:5432/spike;user=spike;password=SemiSecretZZ")
        self.assertEqual(f["database"], "spike")
        self.assertEqual(f["user"], "spike")
        self.assertNotIn("SemiSecretZZ", json.dumps(f))
        self.assertIn("password_stripped", [n[0] for n in notes])

    def test_errors_never_quote_input(self):
        for bad in ("jdbc:postgresql://h:ZZQ1/db", "jdbc:postgresql://h:99999/db"):
            with self.assertRaises(net.UrlError) as cm:
                net.parse_url(PG, bad)
            self.assertNotIn("ZZQ1", str(cm.exception))

    def test_password_parameter_stripped(self):
        f, notes = net.parse_url(PG, "jdbc:postgresql://h/db?user=u&password=hunter2&sslmode=disable")
        self.assertEqual(f["user"], "u")
        self.assertNotIn("hunter2", json.dumps(f))
        self.assertIn("password_stripped", [n[0] for n in notes])

    def test_unknown_params_dropped_and_reported(self):
        f, notes = net.parse_url(PG, "jdbc:postgresql://h/db?foo=1&ApplicationName=x")
        self.assertEqual(f["params"], {"ApplicationName": "x"})
        self.assertIn("foo", dict(notes)["params_dropped"])

    def test_ipv6_host(self):
        f, _ = net.parse_url(PG, "jdbc:postgresql://[::1]:5433/db")
        self.assertEqual((f["host"], f["port"]), ("::1", 5433))

    def test_wrong_scheme_refused(self):
        with self.assertRaises(net.UrlError):
            net.parse_url(PG, "jdbc:mysql://h/db")

    def test_bad_port_refused(self):
        with self.assertRaises(net.UrlError):
            net.parse_url(PG, "jdbc:postgresql://h:99999/db")

    def test_build_round_trip(self):
        url = net.build_url(PG, "db.example.com", 5432, "shop", {"sslmode": "require"})
        self.assertEqual(url, "jdbc:postgresql://db.example.com:5432/shop?sslmode=require")
        self.assertEqual(net.build_url(PG, "::1", 5432, "d", {}), "jdbc:postgresql://[::1]:5432/d")

    def test_url_merge_maps_tls_and_keeps_explicit_fields(self):
        notes = []
        out = plan.merge_url(PG, {"url": "jdbc:postgresql://h:1/db?sslmode=disable&ApplicationName=a",
                                  "host": "override"}, notes)
        self.assertEqual(out["host"], "override")
        self.assertEqual(out["tls"], "none")
        self.assertEqual(out["params"], {"ApplicationName": "a"})


class HostClass(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(net.classify_host("localhost"), "loopback")
        self.assertEqual(net.classify_host("127.0.0.1"), "loopback")
        self.assertEqual(net.classify_host("::1"), "loopback")
        self.assertEqual(net.classify_host("10.1.2.3"), "private")
        self.assertEqual(net.classify_host("192.168.0.9"), "private")
        self.assertEqual(net.classify_host("host.containers.internal"), "private")
        self.assertEqual(net.classify_host("db01"), "private")
        self.assertEqual(net.classify_host("db.corp.local"), "private")
        self.assertEqual(net.classify_host("8.8.8.8"), "public")

    def test_bad_host(self):
        for bad in ("", "a b", "x;DROP", "-x.com"):
            with self.assertRaises(net.UrlError):
                net.validate_host(bad)

    def test_underscore_host_allowed(self):
        self.assertEqual(net.validate_host("my_pg_container"), "my_pg_container")


class Quoting(unittest.TestCase):
    def test_names(self):
        self.assertEqual(sql.validate_name("sales_2"), "SALES_2")
        for bad in ("2x", "a-b", 'x"', "a b", "", "x" * 41, "x;drop"):
            with self.assertRaises(ValueError):
                sql.validate_name(bad)
        self.assertEqual(sql.object_names("sales"),
                         {"connection": "EXAKIT_SRC_SALES", "schema": "VS_SALES"})

    def test_identifiers_and_literals(self):
        self.assertEqual(sql.ident('we"ird'), '"we""ird"')
        self.assertEqual(sql.literal("o'brien"), "'o''brien'")

    def test_connection_statement_quotes_everything(self):
        s = sql.create_connection("EXAKIT_SRC_X", "jdbc:postgresql://h:5432/d", "u'x", "p'w")
        self.assertIn("TO 'jdbc:postgresql://h:5432/d'", s)
        self.assertIn("USER 'u''x'", s)
        self.assertIn("IDENTIFIED BY 'p''w'", s)

    def test_adapter_script(self):
        s = sql.create_adapter_script("POSTGRESQL_4_1_0", "com.exasol.adapter.RequestDispatcher",
                                      ["-Duser.timezone=UTC"], ["/buckets/bfsdefault/default/a.jar"])
        self.assertTrue(s.startswith('CREATE OR REPLACE JAVA ADAPTER SCRIPT "EXAKIT_VS"."POSTGRESQL_4_1_0" AS'))
        self.assertIn("%jvmoption -Duser.timezone=UTC;", s)
        self.assertTrue(s.endswith("\n/"))

    def test_probe_names_driver(self):
        self.assertIn("DRIVER = 'EXAKIT_POSTGRESQL'", sql.import_probe("C", "EXAKIT_POSTGRESQL"))

    def test_schema_probe_quotes_twice(self):
        stmt = PG["check"]["schema"].format(schema=sql.literal("it's"))
        wrapped = sql.import_probe("C", "D", stmt)
        self.assertIn("nspname = ''it''''s''", wrapped)


class Redaction(unittest.TestCase):
    def test_patterns(self):
        self.assertNotIn("hunter2", state.redact("CREATE CONNECTION C TO 'x' USER 'u' IDENTIFIED BY 'hunter2'"))
        self.assertNotIn("hunter2", state.redact("jdbc:postgresql://h/db?user=u&password=hunter2"))
        self.assertNotIn("hunter2", state.redact("postgres://u:hunter2@h/db"))

    def test_url_encoded_password_param(self):
        self.assertNotIn("TopSecret", state.redact("spike%3Bpassword%3DTopSecret?sslmode=require"))

    def test_registered_secret(self):
        state.register_secret("Zebra-Unique-42")
        self.assertEqual(state.redact("auth failed for Zebra-Unique-42"), "auth failed for ***")

    def test_redaction_is_whole_word(self):
        # A secret that is an ordinary word blanked out of every path and
        # package name made it easy to guess instead of hiding it.
        state.register_secret("bananas")
        self.assertEqual(state.redact("password was bananas"), "password was ***")
        self.assertEqual(state.redact("com.bananasoft.adapter"), "com.bananasoft.adapter")

    def test_kit_password_is_not_registered(self):
        # sql.Db must not register the kit's own database password.
        src = (ROOT / "setup" / "virtual-schemas" / "engine" / "sql.py").read_text(encoding="utf-8")
        body = src[src.index("class Db"):src.index("def run(")]
        self.assertNotIn("register_secret(", body)


class Classification(unittest.TestCase):
    CASES = {
        "No default DRIVER registered for jdbc:postgresql://h/db": "driver_not_registered",
        "failed: Your security policy has prevented the connection from being attempted.": "tls_policy",
        "Caused by: java.net.UnknownHostException: host.containers.internal": "dns",
        "failed: SSL error: PKIX path building failed": "tls",
        "FATAL: password authentication failed for user \"x\"": "auth",
        "FATAL: database \"nope\" does not exist": "database_missing",
        "E-VSPG-6: Table 'Orders' cannot be used in virtual schema.": "mixed_case",
        "Connection to localhost:5432 refused.": "network",
        "SSL error: Connection reset by peer": "network",
        "unsupported script language connection scheme": "slc_missing",
    }

    def test_kinds(self):
        for msg, kind in self.CASES.items():
            self.assertEqual(sql.classify(msg), kind, msg)

    def test_sslmode_in_quoted_url_is_not_tls(self):
        msg = ("JDBC-Client-Error: Connecting to 'jdbc:postgresql://h:5432/d?sslmode=require' as "
               "user='u' failed: The connection attempt failed.")
        self.assertEqual(sql.classify(msg), "network")

    def test_short(self):
        m = ("VM error: F-UDF-CL-LIB-1126: ...\ncom.exasol.adapter.jdbc.RemoteMetadataReaderException: "
             "E-VSPG-3: Unable to create. Caused by: 'The connection attempt failed.'\nat x")
        self.assertEqual(sql.short(m), "The connection attempt failed.")

    def test_remedies(self):
        cfg = {"name": "SALES", "connector": "postgresql", "host": "h", "port": 5432}
        self.assertEqual(lifecycle.explain("auth", cfg, "", first_time=False)[1], "exakit source reauth sales")
        # Nothing is kept after a failed FIRST connect, so reauth would be a dead end.
        self.assertEqual(lifecycle.explain("auth", cfg, "", first_time=True)[1],
                         "exakit connect postgresql --name sales")
        self.assertEqual(lifecycle.explain("tls", cfg, "")[1], "exakit connect postgresql --name sales --tls none")


class SettingsCfg(unittest.TestCase):
    def test_format(self):
        data = artifacts.settings_cfg(PG["driver"])
        text = data.decode("ascii")
        self.assertTrue(text.endswith("\n\n"), "settings.cfg must end with an empty line")
        self.assertNotIn("\r", text)
        lines = text.rstrip("\n").split("\n")
        self.assertEqual(lines[0], "DRIVERNAME=EXAKIT_POSTGRESQL")
        self.assertIn("NOSECURITY=YES", lines)
        self.assertEqual(lines[-1], "JAR=postgresql-42.7.14.jar")


class Tls(unittest.TestCase):
    def test_offer_by_host(self):
        self.assertEqual(plan.tls_offer(PG, "public"), ["encrypt"])
        self.assertEqual(plan.tls_offer(PG, "private"), ["encrypt", "none"])
        self.assertEqual(plan.tls_offer(PG, "loopback"), ["encrypt", "none"])

    def test_default_is_encrypt(self):
        self.assertEqual(plan.tls_start(PG, "public", None), "encrypt")

    def test_verify_explains_why_not(self):
        with self.assertRaises(plan.PlanError) as cm:
            plan.tls_start(PG, "public", "verify")
        self.assertIn("trust store", str(cm.exception))

    def test_none_refused_for_public(self):
        with self.assertRaises(plan.PlanError):
            plan.tls_start(PG, "public", "none")
        self.assertEqual(plan.tls_start(PG, "private", "none"), "none")

    def test_params(self):
        self.assertEqual(plan.url_params(PG, "encrypt", {"ApplicationName": "a"}),
                         {"ApplicationName": "a", "sslmode": "require"})


class Changes(unittest.TestCase):
    SAVED = {"host": "h", "port": 5432, "database": "d", "user": "u", "params": {}, "tls": "encrypt"}

    def test_no_change(self):
        self.assertEqual(plan.changed_fields(PG, self.SAVED, dict(self.SAVED, port="5432"), "encrypt"), [])

    def test_changes_detected(self):
        # A re-run with a new port or TLS level used to report ready while the
        # old connection stayed in place.
        self.assertEqual(plan.changed_fields(PG, self.SAVED, dict(self.SAVED, port=5433), "encrypt"), ["port"])
        self.assertEqual(plan.changed_fields(PG, self.SAVED, self.SAVED, "none"), ["tls"])
        self.assertEqual(len(plan.changed_fields(PG, None, self.SAVED, "encrypt")), len(plan.connection_fields(PG)))

    def test_schema_is_not_a_connection_change(self):
        self.assertEqual(plan.changed_fields(PG, self.SAVED, dict(self.SAVED, schema="other"), "encrypt"), [])

    def test_restart_needed(self):
        self.assertTrue(plan.restart_needed({"runtime_installed": False}))
        self.assertTrue(plan.restart_needed({"runtime_installed": True, "runtime_active": False}))
        self.assertFalse(plan.restart_needed({"runtime_installed": True, "runtime_active": None}))
        self.assertFalse(plan.restart_needed({"runtime_installed": True, "runtime_active": True}))
        # A custom runtime of the wrong version is replaced: one restart.
        self.assertTrue(plan.restart_needed({"runtime": "rust", "runtime_installed": True,
                                             "runtime_active": True, "runtime_conflict": "0.32.0"}))
        # Lua is built into the database.
        self.assertFalse(plan.restart_needed({"runtime": "lua"}))


class PasswordFile(unittest.TestCase):
    def test_encodings(self):
        word = "päss"
        for data in (word.encode("utf-8"), b"\xef\xbb\xbf" + word.encode("utf-8"),
                     ("﻿" + word).encode("utf-16-le"), ("﻿" + word).encode("utf-16-be")):
            self.assertEqual(lifecycle._decode_secret_bytes(data, "f"), word)
        with self.assertRaises(lifecycle.Fail):
            lifecycle._decode_secret_bytes(b"\xc3\x28", "f")


class Registry(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["EXAKIT_HOME"] = self.tmp.name

    def tearDown(self):
        os.environ.pop("EXAKIT_HOME", None)
        self.tmp.cleanup()

    def test_ref_counting(self):
        reg = artifacts.load_registry()
        artifacts.add_ref(reg, "adapters", "postgresql/4.1.0", "SALES", {"bucket": "exakit-vs/postgresql/4.1.0"})
        artifacts.add_ref(reg, "adapters", "postgresql/4.1.0", "HR", {"bucket": "exakit-vs/postgresql/4.1.0"})
        artifacts.add_ref(reg, "adapters", "postgresql/4.1.0", "HR", {"bucket": "exakit-vs/postgresql/4.1.0"})
        self.assertEqual(reg["adapters"]["postgresql/4.1.0"]["refs"], ["HR", "SALES"])
        self.assertFalse(artifacts.drop_ref(reg, "adapters", "postgresql/4.1.0", "SALES"))
        self.assertTrue(artifacts.drop_ref(reg, "adapters", "postgresql/4.1.0", "HR"))
        state.write_json(state.registry_path(), reg)
        self.assertEqual(artifacts.load_registry()["adapters"]["postgresql/4.1.0"]["refs"], [])

    def _cfg(self, name, version):
        art = dict(artifacts.describe(PG), adapter_key="postgresql/%s" % version, adapter_version=version,
                   bucket="exakit-vs/postgresql/%s" % version)
        return {"name": name, "connector": "postgresql", "artifacts": art,
                "objects": {"schema": "VS_" + name, "connection": "EXAKIT_SRC_" + name,
                            "script": "EXAKIT_VS.POSTGRESQL_%s" % version.replace(".", "_")}}

    def test_removal_plan_keeps_shared(self):
        reg = artifacts.load_registry()
        for src in ("SALES", "HR"):
            artifacts.add_ref(reg, "adapters", "postgresql/4.1.0", src,
                              {"bucket": "exakit-vs/postgresql/4.1.0", "script": "EXAKIT_VS.POSTGRESQL_4_1_0"})
            artifacts.add_ref(reg, "drivers", "EXAKIT_POSTGRESQL", src, {"connector": "postgresql"})
        cfg = self._cfg("SALES", "4.1.0")
        self.assertEqual([k for k, _ in lifecycle.removal_plan(cfg, reg)],
                         ["virtual_schema", "connection", "source_record"])
        artifacts.drop_ref(reg, "adapters", "postgresql/4.1.0", "HR")
        artifacts.drop_ref(reg, "drivers", "EXAKIT_POSTGRESQL", "HR")
        self.assertEqual([k for k, _ in lifecycle.removal_plan(cfg, reg)],
                         ["virtual_schema", "connection", "adapter_script", "bucket_folder",
                          "driver_registration", "source_record"])

    def test_removal_uses_recorded_version_not_current(self):
        # After a kit update pins 4.2.0, removing a 4.1.0 source must touch
        # 4.1.0 and nothing the 4.2.0 sources use.
        reg = artifacts.load_registry()
        artifacts.add_ref(reg, "adapters", "postgresql/4.1.0", "OLD",
                          {"bucket": "exakit-vs/postgresql/4.1.0", "script": "EXAKIT_VS.POSTGRESQL_4_1_0"})
        artifacts.add_ref(reg, "adapters", "postgresql/4.2.0", "NEW",
                          {"bucket": "exakit-vs/postgresql/4.2.0", "script": "EXAKIT_VS.POSTGRESQL_4_2_0"})
        artifacts.add_ref(reg, "drivers", "EXAKIT_POSTGRESQL", "OLD", {})
        artifacts.add_ref(reg, "drivers", "EXAKIT_POSTGRESQL", "NEW", {})
        items = dict(lifecycle.removal_plan(self._cfg("OLD", "4.1.0"), reg))
        self.assertEqual(items["adapter_script"], "EXAKIT_VS.POSTGRESQL_4_1_0")
        self.assertEqual(items["bucket_folder"], "exakit-vs/postgresql/4.1.0")
        self.assertNotIn("driver_registration", items)

    def test_bucket_delete_is_scoped(self):
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.remove_bucket_files(self.tmp.name, "..")
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.remove_bucket_files(self.tmp.name, "exakit-vs")
        root = Path(self.tmp.name) / artifacts.BUCKET_DIR / "exakit-vs" / "postgresql" / "4.1.0"
        root.mkdir(parents=True)
        (root / "a.jar").write_bytes(b"x")
        keep = Path(self.tmp.name) / artifacts.BUCKET_DIR / "users-own.jar"
        keep.write_bytes(b"y")
        artifacts.remove_bucket_files(self.tmp.name, "exakit-vs/postgresql/4.1.0")
        self.assertFalse(root.exists())
        self.assertTrue(keep.exists())


class Plan(unittest.TestCase):
    INPUTS = {"name": "SALES", "host": "h", "port": 5432, "database": "shop", "user": "u", "schema": "public"}

    def test_fresh_machine(self):
        p = plan.build_plan(PG, self.INPUTS, {})
        needed = [s["step"] for s in p["steps"] if s["needed"]]
        self.assertEqual(needed, ["runtime", "download", "stage", "driver", "restart", "dns", "connection",
                                  "script", "probe", "schema", "verify"])
        self.assertTrue(p["restart_needed"])
        self.assertEqual(p["objects"]["script"], "EXAKIT_VS.POSTGRESQL_4_1_0")
        self.assertIn("Java", [s for s in p["steps"] if s["step"] == "runtime"][0]["action"])

    def test_second_source_needs_no_restart(self):
        facts = {"runtime": "java", "runtime_installed": True, "runtime_active": True, "adapter_cached": True,
                 "driver_cached": True, "adapter_staged": True, "driver_registered": True,
                 "dns": "ok", "script_exists": True}
        p = plan.build_plan(PG, self.INPUTS, facts)
        self.assertFalse(p["restart_needed"])
        self.assertEqual([s["step"] for s in p["steps"] if s["needed"]],
                         ["connection", "probe", "schema", "verify"])

    def test_installed_but_inactive_java_restarts(self):
        p = plan.build_plan(PG, self.INPUTS, {"runtime_installed": True, "runtime_active": False})
        self.assertTrue(p["restart_needed"])

    def test_refuses_foreign_objects(self):
        for facts in ({"connection_exists": True, "connection_owned": False},
                      {"schema_exists": True, "schema_owned": False},
                      {"adapter_schema_foreign": True}):
            with self.assertRaises(plan.PlanError):
                plan.build_plan(PG, self.INPUTS, facts)

    def test_properties(self):
        props = plan.vs_properties(PG, {"connection": "EXAKIT_SRC_SALES"}, self.INPUTS)
        self.assertEqual(props, {"CONNECTION_NAME": "EXAKIT_SRC_SALES", "CATALOG_NAME": "shop",
                                 "SCHEMA_NAME": "public", "POSTGRESQL_IDENTIFIER_MAPPING": "PRESERVE_ORIGINAL_CASE"})

    def test_connector_lookup(self):
        cs = plan.load_connectors()
        for alias in ("pg", "postgres", "PostgreSQL", "postgresql"):
            self.assertEqual(plan.find_connector(cs, alias)["id"], "postgresql")
        with self.assertRaises(plan.PlanError):
            plan.find_connector(cs, "nosuchdb")


class Connectors(unittest.TestCase):
    """Every connector.json is complete: a new source is a folder, so the
    folder is what gets checked."""

    def test_shape(self):
        for cid, c in plan.load_connectors().items():
            with self.subTest(connector=cid):
                for key in ("id", "label", "adapter", "driver", "url", "inputs", "properties", "tls", "check"):
                    self.assertIn(key, c)
                drv = plan.driver(c)
                arches = sorted(c["adapter"]["assets"]) if c["adapter"].get("assets") else [None]
                for art in [plan.adapter(c, a) for a in arches] + ([drv] if drv else []):
                    self.assertRegex(art["sha256"], r"^[0-9a-f]{64}$")
                    self.assertTrue(art["url"].startswith("https://"))
                if drv:
                    s = drv["settings"]
                    self.assertTrue(s["DRIVERNAME"].startswith("EXAKIT_"))
                    self.assertEqual(s.get("NOSECURITY"), "YES")
                if plan.runtime_kind(c) == "java":
                    self.assertIn("-Duser.timezone=UTC", c["script"]["jvm_options"])
                if plan.runtime_kind(c) == "rust":
                    # A native adapter only loads in the runtime version it was
                    # built for: the connector and runtimes.json must agree.
                    self.assertEqual(c["adapter"]["runtime_version"], plan.load_runtimes()["rust"]["version"])
                    self.assertEqual(arches, ["aarch64", "x86_64"])
                self.assertIn(c["tls"]["default"], c["tls"]["levels"])
                for f in c["inputs"]:
                    self.assertIn("label", f)

    def test_driver_names_unique(self):
        names = [plan.driver(c)["settings"]["DRIVERNAME"] for c in plan.load_connectors().values() if plan.driver(c)]
        self.assertEqual(len(names), len(set(names)))

    def test_all_present(self):
        self.assertEqual(sorted(plan.load_connectors()),
                         ["exasol", "lakehouse", "mysql", "oracle", "postgresql", "snowflake", "sqlserver"])


CS = plan.load_connectors()


class OtherConnectors(unittest.TestCase):
    def _cfg(self, cid, **kw):
        c = CS[cid]
        base = {f["id"]: f.get("default") for f in c["inputs"] if not f.get("secret")}
        base.update(kw)
        return c, base

    def test_mysql(self):
        c, cfg = self._cfg("mysql", host="db", database="shop")
        self.assertEqual(plan.build_url(c, "db", cfg, "encrypt"), "jdbc:mysql://db:3306/shop?sslMode=REQUIRED")
        self.assertIn("allowPublicKeyRetrieval=true", plan.build_url(c, "db", cfg, "none"))
        f, notes = plan.parse_url(c, "jdbc:mysql://db:3307/shop?allowLoadLocalInfile=true&sslMode=REQUIRED")
        self.assertEqual((f["port"], f["database"]), (3307, "shop"))
        self.assertIn("allowLoadLocalInfile", dict(notes)["params_dropped"])
        self.assertEqual(plan.vs_properties(c, {"connection": "C"}, cfg), {"CONNECTION_NAME": "C", "CATALOG_NAME": "shop"})
        self.assertTrue(c.get("license_notice"))

    def test_sqlserver(self):
        c, cfg = self._cfg("sqlserver", host="sql", database="Shop")
        self.assertEqual(plan.build_url(c, "sql", cfg, "encrypt"),
                         "jdbc:sqlserver://sql:1433;databaseName=Shop;encrypt=true;trustServerCertificate=true")
        f, notes = plan.parse_url(c, "jdbc:sqlserver://sql:1444;databaseName=Shop;user=sa;password=Secr3tZZ;encrypt=false")
        self.assertEqual((f["host"], f["port"], f["database"], f["user"]), ("sql", 1444, "Shop", "sa"))
        self.assertNotIn("Secr3tZZ", json.dumps(f))
        self.assertIn("password_stripped", [n[0] for n in notes])
        merged = plan.merge_url(c, {"url": "jdbc:sqlserver://sql;databaseName=Shop;encrypt=false"}, [])
        self.assertEqual(merged["tls"], "none")
        self.assertEqual(plan.vs_properties(c, {"connection": "C"}, cfg)["SCHEMA_NAME"], "dbo")

    def test_oracle(self):
        c, cfg = self._cfg("oracle", host="ora", database="FREEPDB1", schema="hr")
        self.assertEqual(plan.build_url(c, "ora", cfg, "none"), "jdbc:oracle:thin:@//ora:1521/FREEPDB1")
        self.assertIn("oracle.net.encryption_client=REQUIRED", plan.build_url(c, "ora", cfg, "encrypt"))
        for text, want in (("jdbc:oracle:thin:@//ora:1522/FREEPDB1", ("ora", 1522, "FREEPDB1")),
                           ("jdbc:oracle:thin:@ora:1522/FREEPDB1", ("ora", 1522, "FREEPDB1")),
                           ("jdbc:oracle:thin:@ora:1522:XE", ("ora", 1522, "XE"))):
            f, _ = plan.parse_url(c, text)
            self.assertEqual((f["host"], f["port"], f["database"]), want, text)
        f, notes = plan.parse_url(c, "jdbc:oracle:thin:scott/T1gerZZ@//ora:1521/SVC")
        self.assertEqual(f["user"], "scott")
        self.assertNotIn("T1gerZZ", json.dumps(f))
        with self.assertRaises(net.UrlError):
            plan.parse_url(c, "jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(HOST=x)))")
        self.assertEqual(plan.vs_properties(c, {"connection": "C"}, cfg)["SCHEMA_NAME"], "HR")

    def test_snowflake(self):
        c, cfg = self._cfg("snowflake", host="xy1.snowflakecomputing.com", database="shop",
                           warehouse="wh", schema="public")
        url = plan.build_url(c, cfg["host"], cfg, "encrypt")
        self.assertTrue(url.startswith("jdbc:snowflake://xy1.snowflakecomputing.com:443/?db=shop&warehouse=wh"))
        self.assertTrue(url.endswith("JDBC_QUERY_RESULT_FORMAT=JSON"))
        self.assertNotIn("role=", url)
        f, notes = plan.parse_url(c, "jdbc:snowflake://xy1.snowflakecomputing.com/?db=S&warehouse=W&role=R&token=TokZZ")
        self.assertEqual((f["database"], f["warehouse"], f["role"]), ("S", "W", "R"))
        self.assertNotIn("TokZZ", json.dumps(f))
        props = plan.vs_properties(c, {"connection": "C"}, cfg)
        self.assertEqual((props["CATALOG_NAME"], props["SCHEMA_NAME"]), ("SHOP", "PUBLIC"))
        self.assertIn("trust store", plan.unavailable_reason(c))
        os.environ["EXAKIT_VS_ALLOW_UNAVAILABLE"] = "1"
        try:
            self.assertIsNone(plan.unavailable_reason(c))
        finally:
            os.environ.pop("EXAKIT_VS_ALLOW_UNAVAILABLE")
        self.assertEqual(plan.connector_env(c, {"EXAKIT_VS_WAREHOUSE": "W2", "EXAKIT_VS_ROLE": "R2"}),
                         {"warehouse": "W2", "role": "R2"})

    def test_exasol(self):
        c, cfg = self._cfg("exasol", host="localhost", schema="SALES", fingerprint="AB12")
        self.assertIsNone(plan.driver(c))
        self.assertEqual(plan.build_url(c, "localhost", cfg, "verify"), "jdbc:exa:localhost/AB12:8563")
        self.assertEqual(plan.build_url(c, "localhost", cfg, "encrypt"), "jdbc:exa:localhost/nocertcheck:8563")
        self.assertEqual(plan.extra_connections(c, {"connection": "C"}, "localhost", cfg, "verify"),
                         [("_EXA", "localhost/AB12:8563")])
        local = plan.vs_properties(c, {"connection": "C"}, cfg, "localhost")
        self.assertEqual(local.get("IS_LOCAL"), "true")
        remote = plan.vs_properties(c, {"connection": "C"}, dict(cfg, host="10.0.0.5"), "10.0.0.5")
        self.assertEqual((remote["IMPORT_FROM_EXA"], remote["EXA_CONNECTION"]), ("true", "C_EXA"))
        self.assertEqual(plan.tls_start(c, "loopback", None), "verify")
        self.assertEqual(artifacts.describe(c)["driver_name"], None)
        p = plan.build_plan(c, {"name": "X", "host": "localhost"}, {})
        self.assertNotIn("driver", [st["step"] for st in p["steps"]])

    def test_probe_kinds(self):
        self.assertIn('IMPORT FROM EXA AT "C_EXA"', sql.import_probe("C_EXA", None, "SELECT 1", "exa"))
        self.assertEqual(lifecycle._probe_target(CS["exasol"], "C"), ("C_EXA", None, "exa"))
        self.assertEqual(lifecycle._probe_target(CS["mysql"], "C"), ("C", "EXAKIT_MYSQL", "jdbc"))

    def test_bare_endpoint(self):
        # What a cloud console shows (an RDS endpoint) is accepted as the URL.
        rds = "db1.c54yea04y0f8.ap-south-1.rds.amazonaws.com"
        f, notes = plan.parse_url(CS["postgresql"], rds)
        self.assertEqual((f["host"], f.get("port"), notes), (rds, None, []))
        f, _ = plan.parse_url(CS["postgresql"], rds + ":5433/shop")
        self.assertEqual((f["host"], f["port"], f["database"]), (rds, 5433, "shop"))
        f, _ = plan.parse_url(CS["oracle"], "ora.example.com:1521/FREEPDB1")
        self.assertEqual(f["database"], "FREEPDB1")
        f, _ = plan.parse_url(CS["exasol"], "exa.example.com:8563/ignored")
        self.assertNotIn("database", f)
        merged = plan.merge_url(CS["postgresql"], {"url": rds, "database": "app"}, [])
        self.assertEqual((merged["host"], merged["database"]), (rds, "app"))
        for bad in ("jdbc:mysql://x:3306/db", "host:port", "a b"):
            with self.assertRaises(net.UrlError):
                plan.parse_url(CS["postgresql"], bad)

    def test_render(self):
        self.assertEqual(plan.render("{a|upper}-{b|lower}-{c}", {"a": "x", "b": "Y", "c": None}), "X-y-")
        with self.assertRaises(plan.PlanError):
            plan.render("{a|nope}", {"a": "x"})


def _native_connector(**kw):
    """A fixture Rust connector shaped like Lakehouse: per-architecture
    archives, a library inside, companion scripts, probed through the adapter."""
    c = {
        "id": "nativex", "label": "NativeX", "runtime": "rust",
        "adapter": {"version": "1.2.3", "extract": "udf/libnativex.so", "assets": {
            "x86_64": {"file": "nx.tar.gz", "url": "https://example.invalid/nx.tar.gz", "sha256": "a" * 64},
            "aarch64": {"file": "nx-aarch64.tar.gz", "url": "https://example.invalid/nx-a.tar.gz", "sha256": "b" * 64}}},
        "scripts": [{"name": "NX_SCAN", "sql": "CREATE OR REPLACE RUST SCALAR SCRIPT {schema}.NX_SCAN(x VARCHAR(10)) "
                                               "EMITS (...) AS\n%udf_object {udf_object}\n/"}],
        "url": {"default_port": 8181}, "inputs": [{"id": "host", "label": "Host", "required": True}],
        "properties": {}, "tls": {"default": "verify", "levels": {"verify": {}, "none": {}}},
        "check": {"kind": "vs"},
    }
    c.update(kw)
    return c


class Runtimes(unittest.TestCase):
    def test_runtime_pin_is_complete(self):
        rt = plan.load_runtimes()["rust"]
        self.assertEqual(rt["alias"], "RUST")
        for arch in ("x86_64", "aarch64"):
            spec = plan.runtime_spec("rust", arch)
            self.assertRegex(spec["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(spec["url"].startswith("https://"))
            self.assertIn(spec["version"], spec["file"])
        self.assertIsNone(plan.runtime_spec("java"))
        self.assertIsNone(plan.runtime_spec("lua"))

    def test_db_arch(self):
        from engine import runtime
        self.assertEqual(runtime.db_arch({"EXAKIT_VS_ARCH": "AMD64"}), "x86_64")
        self.assertEqual(runtime.db_arch({"EXAKIT_VS_ARCH": "arm64"}), "aarch64")

    def test_adapter_per_arch(self):
        c = _native_connector()
        a = plan.adapter(c, "aarch64")
        self.assertEqual((a["file"], a["stage_name"], a["version"]), ("nx-aarch64.tar.gz", "libnativex.so", "1.2.3"))
        with self.assertRaises(plan.PlanError):
            plan.adapter(c, "riscv64")
        self.assertEqual(plan.adapter(PG)["stage_name"], PG["adapter"]["file"])

    def test_native_plan(self):
        c = _native_connector()
        p = plan.build_plan(c, {"name": "LAKE", "host": "h"}, {"runtime": "rust"})
        steps = {s["step"]: s for s in p["steps"]}
        self.assertNotIn("dns", steps)          # the Rust SLC resolves names itself
        self.assertNotIn("driver", steps)
        self.assertIn("Rust runtime", steps["runtime"]["action"])
        self.assertIn("NX_SCAN", steps["script"]["action"])
        self.assertTrue(p["restart_needed"])
        p = plan.build_plan(c, {"name": "LAKE", "host": "h"},
                            {"runtime": "rust", "runtime_installed": True, "runtime_active": True,
                             "runtime_conflict": "0.32.0"})
        self.assertIn("Replace the Rust runtime 0.32.0", [s for s in p["steps"] if s["step"] == "runtime"][0]["action"])

    def test_lua_plan_needs_no_runtime_or_staging(self):
        c = _native_connector(runtime="lua", adapter={"version": "1.0.2", "file": "a.lua", "url": "https://x/a.lua",
                                                      "sha256": "c" * 64})
        p = plan.build_plan(c, {"name": "DBX", "host": "h"}, {"runtime": "lua", "runtime_installed": True,
                                                               "runtime_active": True})
        steps = [s["step"] for s in p["steps"]]
        self.assertNotIn("runtime", steps)
        self.assertNotIn("stage", steps)
        self.assertNotIn("dns", steps)
        self.assertFalse(p["restart_needed"])

    def test_script_sql(self):
        s = sql.create_rust_adapter_script("NX_1_2_3", "buckets/bfsdefault/default/exakit-vs/nativex/1.2.3/libnativex.so")
        self.assertEqual(s, 'CREATE OR REPLACE RUST ADAPTER SCRIPT "EXAKIT_VS"."NX_1_2_3" AS\n'
                            '%udf_object buckets/bfsdefault/default/exakit-vs/nativex/1.2.3/libnativex.so\n/')
        lua = sql.create_lua_adapter_script("DBX_1_0_2", "function adapter_call() end\n", "-- preamble")
        self.assertTrue(lua.startswith('CREATE OR REPLACE LUA ADAPTER SCRIPT "EXAKIT_VS"."DBX_1_0_2" AS\n-- preamble\n'))
        self.assertTrue(lua.endswith("function adapter_call() end\n/"))
        comp = sql.companion_script(_native_connector()["scripts"][0]["sql"], "buckets/x/lib.so")
        self.assertIn('"EXAKIT_VS".NX_SCAN', comp)
        self.assertIn("%udf_object buckets/x/lib.so", comp)
        self.assertEqual(artifacts.udf_object("exakit-vs/nativex/1.2.3", "libnativex.so"),
                         "buckets/bfsdefault/default/exakit-vs/nativex/1.2.3/libnativex.so")

    def test_payload_extracts_only_the_named_member(self):
        import tarfile
        with tempfile.TemporaryDirectory() as d:
            arc = Path(d) / "nx.tar.gz"
            with tarfile.open(arc, "w:gz") as t:
                for name, data in (("udf/libnativex.so", b"ELF..."), ("../evil", b"x")):
                    ti = tarfile.TarInfo(name)
                    ti.size = len(data)
                    t.addfile(ti, io.BytesIO(data))
            out = artifacts.payload({"file": "nx.tar.gz", "extract": "udf/libnativex.so"}, arc)
            self.assertEqual(out.read_bytes(), b"ELF...")
            self.assertEqual(out.parent, Path(d) / "extracted")
            self.assertFalse((Path(d).parent / "evil").exists())
            with self.assertRaises(artifacts.ArtifactError):
                artifacts.payload({"file": "nx.tar.gz", "extract": "udf/missing.so"}, arc)
            self.assertEqual(artifacts.payload({"file": "a.jar"}, arc), arc)

    def test_custom_runtime_version(self):
        reg = {"runtimes": {"rust": {"version": "0.33.0", "file": "lc-rust-0.33.0.tar.gz"}}}
        row = {"source": "C:\\tmp\\lc-rust-0.33.0.tar.gz"}
        self.assertEqual(lifecycle._custom_runtime_version(row, "rust", reg), "0.33.0")
        self.assertEqual(lifecycle._custom_runtime_version({"source": "/x/lc-rust-0.32.0.tar.gz"}, "rust",
                                                           {"runtimes": {}}), "0.32.0")
        self.assertIsNone(lifecycle._custom_runtime_version({"source": "/x/my-own.tar.gz"}, "rust",
                                                            {"runtimes": {}}))

    def test_native_failure_kinds(self):
        tls = ("UDF error: catalog request failed: error sending request for url (https://x/v1/config): "
               "client error (Connect): invalid peer certificate: certificate expired")
        self.assertEqual(sql.classify(tls), "tls")
        self.assertEqual(sql.classify("error sending request for url (http://10.0.0.9:8181/v1/config): "
                                      "client error (Connect): tcp connect error: Connection refused"), "network")
        self.assertEqual(sql.classify("client error (Connect): dns error: failed to lookup address information"),
                         "dns")
        self.assertEqual(sql.classify("catalog request failed with HTTP 401: Unauthorized"), "auth")
        self.assertEqual(sql.classify("S3 error: InvalidAccessKeyId"), "auth")
        self.assertEqual(sql.classify("Fingerprint mismatch: built for 0.32.0"), "runtime_mismatch")
        self.assertEqual(sql.classify("NoSuchNamespaceException: Namespace does not exist: shop"), "schema_missing")

    def test_connection_user_and_secret_defaults(self):
        self.assertEqual(plan.connection_user(PG, {"user": "u"}), "u")
        self.assertEqual(plan.connection_user(_native_connector(), {}), "")
        self.assertEqual(plan.connection_secret(PG, {}, "pw"), "pw")


class Lakehouse(unittest.TestCase):
    LH = CS["lakehouse"]
    BASE = {"name": "LAKE", "host": "localhost", "port": 18181, "catalog": "iceberg", "namespace": "shop",
            "warehouse": "s3://warehouse/", "endpoint": "http://localhost:19000", "region": "us-east-1",
            "user": "lhadmin"}

    def test_url_and_tls(self):
        f, notes = plan.parse_url(self.LH, "http://localhost:18181")
        self.assertEqual((f["host"], f["port"], f["params"]), ("localhost", 18181, {"scheme": "http"}))
        merged = plan.merge_url(self.LH, {"url": "http://localhost:18181"}, [])
        self.assertEqual((merged["tls"], merged["params"]), ("none", {}))
        merged = plan.merge_url(self.LH, {"url": "https://dbc-1.cloud.databricks.com"}, [])
        self.assertEqual((merged["port"], merged["tls"]), (443, "verify"))
        self.assertEqual(plan.build_url(self.LH, "dbc-1.cloud.databricks.com", dict(self.BASE, port=443), "verify"),
                         "https://dbc-1.cloud.databricks.com")
        self.assertEqual(plan.build_url(self.LH, "host.containers.internal", self.BASE, "none"),
                         "http://host.containers.internal:18181")
        self.assertEqual(plan.tls_start(self.LH, "public", None), "verify")
        with self.assertRaises(plan.PlanError):
            plan.tls_start(self.LH, "public", "none")

    def test_secret_document(self):
        doc = json.loads(plan.connection_secret(self.LH, self.BASE, "s3cretKEY"))
        self.assertEqual(doc, {"warehouse": "s3://warehouse/", "access_key": "lhadmin", "secret_key": "s3cretKEY",
                               "region": "us-east-1", "endpoint": "http://host.containers.internal:19000",
                               "path_style": True})
        self.assertEqual(plan.connection_user(self.LH, self.BASE), "")
        unity = dict(self.BASE, catalog="unity", namespace="main.sales", user=None, endpoint=None)
        self.assertEqual(json.loads(plan.connection_secret(self.LH, unity, "dapiTOKEN")),
                         {"token": "dapiTOKEN", "use_vended_credentials": True})

    def test_properties(self):
        props = plan.vs_properties(self.LH, {"connection": "C"}, dict(self.BASE, tls="none"))
        self.assertEqual(props, {"CATALOG_CONNECTION": "C", "NAMESPACE": "shop", "ALLOW_HTTP": "true"})
        unity = dict(self.BASE, catalog="unity", namespace="main.sales", endpoint=None, tls="verify")
        self.assertEqual(plan.vs_properties(self.LH, {"connection": "C"}, unity),
                         {"CATALOG_CONNECTION": "C", "NAMESPACE": "main.sales", "CATALOG_KIND": "UNITY_CATALOG"})

    def test_validate(self):
        v = plan.validate(self.LH, dict(self.BASE, catalog="Unity", namespace="main.sales"))
        self.assertEqual(v["catalog"], "unity")
        for bad in (dict(self.BASE, warehouse=None), dict(self.BASE, catalog="glue"),
                    dict(self.BASE, catalog="unity", namespace="nodot"), dict(self.BASE, endpoint="minio:9000")):
            with self.assertRaises(plan.PlanError):
                plan.validate(self.LH, bad)

    def test_plan(self):
        p = plan.build_plan(self.LH, self.BASE, {"runtime": "rust", "runtime_installed": True,
                                                 "runtime_active": True, "runtime_conflict": None})
        steps = [s["step"] for s in p["steps"]]
        self.assertNotIn("driver", steps)
        self.assertNotIn("dns", steps)
        self.assertFalse(p["restart_needed"])
        self.assertEqual(p["objects"]["script"], "EXAKIT_VS.LAKEHOUSE_ADAPTER")


class UiTwin(unittest.TestCase):
    def test_glyphs_match_ui_sh(self):
        """ui.py is a third twin of ui.sh / ui.ps1: the fancy glyphs are the same."""
        text = (ROOT / "setup" / "lib" / "ui.sh").read_text(encoding="utf-8")
        start = text.index('if [ "$UI_FANCY" = 1 ]; then')
        fancy = text[start:text.index("\nelse\n", start)]
        src = (ROOT / "setup" / "virtual-schemas" / "engine" / "ui.py").read_text(encoding="utf-8")
        for name in ("TICK", "CROSS", "BULLET", "ARROW", "HR", "TL", "TR", "BL", "BR", "VB"):
            m = re.search(r"UI_%s='([^']*)'" % name, fancy)
            self.assertIsNotNone(m, name)
            glyph = m.group(1)
            self.assertTrue(glyph in src or "\\u%04x" % ord(glyph) in src, "%s %r is not in ui.py" % (name, glyph))


class Cli(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(argv)
        return rc, json.loads(buf.getvalue())

    def test_password_option_refused_with_reason(self):
        rc, obj = self._run(["connect", "--password", "x", "--json"])
        self.assertEqual(rc, 2)
        self.assertEqual((obj["ok"], obj["rejected"]), (False, True))
        self.assertIn("deliberately", obj["error"])

    def test_unknown_option(self):
        rc, obj = self._run(["connect", "--bogus", "--json"])
        self.assertEqual((rc, obj["rejected"]), (2, True))

    def test_top_level_json(self):
        for argv in (["--json"], ["source", "--json"]):
            rc, obj = self._run(argv)
            self.assertEqual(rc, 2)
            self.assertFalse(obj["ok"])


if __name__ == "__main__":
    unittest.main()
