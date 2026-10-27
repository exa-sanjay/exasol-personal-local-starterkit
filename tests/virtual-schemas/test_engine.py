"""Unit tests for the virtual-schemas engine: no database, no network.

    python -m unittest discover -s tests/virtual-schemas -p "test_*.py"
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "setup" / "virtual-schemas"))

from engine import artifacts, net, plan, sql, state  # noqa: E402

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
        self.assertNotIn("s3cr", json.dumps(f))
        self.assertEqual([n[0] for n in notes], ["password_stripped"])

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


class Redaction(unittest.TestCase):
    def test_patterns(self):
        self.assertNotIn("hunter2", state.redact("CREATE CONNECTION C TO 'x' USER 'u' IDENTIFIED BY 'hunter2'"))
        self.assertNotIn("hunter2", state.redact("jdbc:postgresql://h/db?user=u&password=hunter2"))
        self.assertNotIn("hunter2", state.redact("postgres://u:hunter2@h/db"))

    def test_registered_secret(self):
        state.register_secret("Zebra-Unique-42")
        self.assertEqual(state.redact("auth failed for Zebra-Unique-42"), "auth failed for ***")


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

    def test_removal_plan_keeps_shared(self):
        reg = artifacts.load_registry()
        for src in ("SALES", "HR"):
            artifacts.add_ref(reg, "adapters", "postgresql/4.1.0", src,
                              {"bucket": "exakit-vs/postgresql/4.1.0", "script": "EXAKIT_VS.POSTGRESQL_4_1_0"})
            artifacts.add_ref(reg, "drivers", "EXAKIT_POSTGRESQL", src, {"connector": "postgresql"})
        cfg = {"name": "SALES", "objects": {"schema": "VS_SALES", "connection": "EXAKIT_SRC_SALES"}}
        kinds = [k for k, _ in __import__("engine.lifecycle", fromlist=["x"]).removal_plan(cfg, reg, PG)]
        self.assertEqual(kinds, ["virtual_schema", "connection", "source_record"])
        artifacts.drop_ref(reg, "adapters", "postgresql/4.1.0", "HR")
        artifacts.drop_ref(reg, "drivers", "EXAKIT_POSTGRESQL", "HR")
        kinds = [k for k, _ in __import__("engine.lifecycle", fromlist=["x"]).removal_plan(cfg, reg, PG)]
        self.assertEqual(kinds, ["virtual_schema", "connection", "adapter_script", "bucket_folder",
                                 "driver_registration", "source_record"])

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
        self.assertEqual(needed, ["java", "download", "stage", "driver", "restart", "dns", "connection",
                                  "probe", "script", "schema", "verify"])
        self.assertTrue(p["restart_needed"])
        self.assertEqual(p["objects"]["script"], "EXAKIT_VS.POSTGRESQL_4_1_0")

    def test_second_source_needs_no_restart(self):
        facts = {"java_installed": True, "adapter_cached": True, "driver_cached": True,
                 "adapter_staged": True, "driver_registered": True, "dns_links": "linked",
                 "script_exists": True}
        p = plan.build_plan(PG, self.INPUTS, facts)
        self.assertFalse(p["restart_needed"])
        self.assertEqual([s["step"] for s in p["steps"] if s["needed"]],
                         ["connection", "probe", "schema", "verify"])

    def test_refuses_foreign_objects(self):
        with self.assertRaises(plan.PlanError):
            plan.build_plan(PG, self.INPUTS, {"connection_exists": True, "connection_owned": False})
        with self.assertRaises(plan.PlanError):
            plan.build_plan(PG, self.INPUTS, {"schema_exists": True, "schema_owned": False})

    def test_properties(self):
        props = plan.vs_properties(PG, "EXAKIT_SRC_SALES", self.INPUTS)
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
                for key in ("id", "label", "adapter", "driver", "script", "url", "inputs", "properties", "tls", "check"):
                    self.assertIn(key, c)
                for art in (c["adapter"], c["driver"]):
                    self.assertRegex(art["sha256"], r"^[0-9a-f]{64}$")
                    self.assertTrue(art["url"].startswith("https://"))
                s = c["driver"]["settings"]
                self.assertTrue(s["DRIVERNAME"].startswith("EXAKIT_"))
                self.assertEqual(s.get("NOSECURITY"), "YES")
                self.assertIn("-Duser.timezone=UTC", c["script"]["jvm_options"])
                self.assertIn(c["tls"]["default"], c["tls"]["levels"])


class Cli(unittest.TestCase):
    def test_unknown_option_is_json_refusal(self):
        import io
        from contextlib import redirect_stdout
        from engine import cli
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["connect", "--password", "x", "--json"])
        self.assertEqual(rc, 2)
        obj = json.loads(buf.getvalue())
        self.assertEqual((obj["ok"], obj["rejected"]), (False, True))


if __name__ == "__main__":
    unittest.main()
