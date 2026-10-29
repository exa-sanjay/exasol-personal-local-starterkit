"""SQL for the add-on: quoting, statements, the database session, and what a
failure means.

Nothing user-typed is ever interpolated unchecked. Object names the kit
generates are validated against a strict pattern and then quoted anyway;
values (URLs, user names, passwords, source schema names) only ever appear as
single-quoted literals with quotes doubled. The password travels inside the
CREATE CONNECTION statement and nowhere else, and every statement is redacted
before it reaches the log.
"""

import re
import ssl

from . import state

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,39}$")
MARKER = "managed by exakit virtual-schemas"
ADAPTER_SCHEMA = "EXAKIT_VS"


class SqlError(Exception):
    def __init__(self, message, kind="unknown"):
        super().__init__(message)
        self.kind = kind


def validate_name(name):
    """A source name: letters, digits, underscore, starting with a letter."""
    if not name or not NAME_RE.match(name):
        raise ValueError("%r is not a valid name: use letters, digits and _ (start with a letter, "
                         "at most 40 characters)" % name)
    return name.upper()


def ident(name):
    return '"%s"' % name.replace('"', '""')


def literal(value):
    return "'%s'" % str(value).replace("'", "''")


def object_names(name):
    n = validate_name(name)
    return {"connection": "EXAKIT_SRC_%s" % n, "schema": "VS_%s" % n}


def probe_schema_name(name):
    """The throwaway schema a source is tested through. Source schemas are
    always VS_<NAME>, so no source can ever own this name."""
    return "EXAKIT_PROBE_%s" % validate_name(name)


def adapter_script_name(connector_id, version, fixed=None, source=None):
    """Versioned (POSTGRESQL_4_1_0), so an upgrade sits beside the old
    version - unless the adapter dictates its name (a native library is
    found by an entry point named after the script: LAKEHOUSE_ADAPTER ->
    __exa_udf_entry_LAKEHOUSE_ADAPTER), or the script is the source's own
    (DATABRICKS_SALES: an adapter patched with one source's pin)."""
    if fixed:
        return fixed
    if source:
        return "%s_%s" % (connector_id.upper(), validate_name(source))
    return "%s_%s" % (connector_id.upper(), re.sub(r"[^A-Za-z0-9]", "_", version))


# --- statements -----------------------------------------------------------------

def create_connection(conn, url, user, password):
    return "CREATE OR REPLACE CONNECTION %s TO %s USER %s IDENTIFIED BY %s" % (
        ident(conn), literal(url), literal(user), literal(password))


def comment_connection(conn):
    return "COMMENT ON CONNECTION %s IS %s" % (ident(conn), literal(MARKER))


def import_probe(conn, driver_name, statement="SELECT 1", kind="jdbc"):
    """A bounded read through the database's import side. kind 'exa' reads
    through an EXA connection (Exasol to Exasol, no JDBC driver involved)."""
    if kind == "exa":
        return "SELECT * FROM (IMPORT FROM EXA AT %s STATEMENT %s)" % (ident(conn), literal(statement))
    drv = " DRIVER = %s" % literal(driver_name) if driver_name else ""
    return "SELECT * FROM (IMPORT FROM JDBC%s AT %s STATEMENT %s)" % (drv, ident(conn), literal(statement))


def create_adapter_script(script, script_class, jvm_options, jars):
    lines = ["CREATE OR REPLACE JAVA ADAPTER SCRIPT %s.%s AS" % (ident(ADAPTER_SCHEMA), ident(script)),
             "  %%scriptclass %s;" % script_class]
    lines += ["  %%jvmoption %s;" % o for o in jvm_options]
    lines += ["  %%jar %s;" % j for j in jars]
    lines.append("/")
    return "\n".join(lines)


def create_rust_adapter_script(script, udf_object, alias="RUST"):
    """A native adapter: the library in BucketFS, loaded by the custom SLC
    registered under `alias`."""
    return "CREATE OR REPLACE %s ADAPTER SCRIPT %s.%s AS\n%%udf_object %s\n/" % (
        alias, ident(ADAPTER_SCHEMA), ident(script), udf_object)


def create_lua_adapter_script(script, source, preamble=""):
    """A Lua adapter carries its whole source in the script text."""
    body = (preamble.rstrip("\n") + "\n" if preamble else "") + source.rstrip("\n")
    return "CREATE OR REPLACE LUA ADAPTER SCRIPT %s.%s AS\n%s\n/" % (ident(ADAPTER_SCHEMA), ident(script), body)


def companion_script(template, udf_object):
    """A script an adapter calls by name (Lakehouse: its scan, version and
    distribution scripts). The connector's template names the schema as
    {schema} and the library as {udf_object}; such scripts must live in the
    adapter's own schema."""
    return template.replace("{schema}", ident(ADAPTER_SCHEMA)).replace("{udf_object}", udf_object)


NET_PROBE = "SANDBOX_NET"


def create_net_probe():
    """A Java UDF that answers from INSIDE the sandbox adapters run in:

      SANDBOX_NET('dns', '')    'ok' when /etc/resolv.conf and /etc/hosts have
                                content (directly, through the kit's links, or
                                through a fixed image), else 'missing'
      SANDBOX_NET('resolve', h) h's address as the sandbox sees it: DNS first,
                                then the hosts file the database mounts at
                                /conf/hosts; '' when neither knows it

    It tests what the files DO, not what they are, so an upstream fix in any
    shape reads as 'ok' and the kit stops touching anything."""
    return "\n".join([
        "CREATE OR REPLACE JAVA SCALAR SCRIPT %s.%s(mode VARCHAR(10), arg VARCHAR(255)) "
        "RETURNS VARCHAR(255) AS" % (ident(ADAPTER_SCHEMA), ident(NET_PROBE)),
        "import java.net.*;",
        "import java.nio.file.*;",
        "class %s {" % NET_PROBE,
        "  static String run(ExaMetadata m, ExaIterator ctx) throws Exception {",
        "    String arg = ctx.getString(\"arg\");",
        "    if (\"dns\".equals(ctx.getString(\"mode\"))) {",
        "      for (String f : new String[] {\"/etc/resolv.conf\", \"/etc/hosts\"}) {",
        "        try { if (Files.size(Paths.get(f)) == 0) return \"missing\"; }",
        "        catch (Exception e) { return \"missing\"; }",
        "      }",
        "      return \"ok\";",
        "    }",
        "    try { return InetAddress.getByName(arg).getHostAddress(); } catch (Exception e) { }",
        "    try {",
        "      for (String l : Files.readAllLines(Paths.get(\"/conf/hosts\"))) {",
        "        String[] t = l.trim().split(\"\\\\s+\");",
        "        for (int i = 1; i < t.length; i++) if (t[i].equalsIgnoreCase(arg)) return t[0];",
        "      }",
        "    } catch (Exception e) { }",
        "    return \"\";",
        "  }",
        "}",
        "/"])


def create_virtual_schema(schema, script, props):
    with_ = " ".join("%s = %s" % (k, literal(v)) for k, v in props.items())
    return "CREATE VIRTUAL SCHEMA %s USING %s.%s WITH %s" % (
        ident(schema), ident(ADAPTER_SCHEMA), ident(script), with_)


# --- session --------------------------------------------------------------------

class Db:
    """The admin session, from the kit's own records: runtime.dsn,
    runtime.user and the password FILE (read here, never put on a command
    line). Same TLS posture as the rest of the kit: encrypted, local
    self-signed certificate not validated."""

    def __init__(self, manifest, user=None, password_file=None):
        import pyexasol

        rt = manifest.get("runtime") or {}
        self.dsn = rt.get("dsn") or "127.0.0.1:8563"
        user = user or rt.get("user") or "sys"
        pwfile = password_file or rt.get("password_file")
        if not pwfile:
            raise SqlError("the kit's runtime password file is not recorded", "not_installed")
        with open(pwfile, "r", encoding="utf-8") as f:
            pw = f.read().strip()
        # Not registered for redaction: it never appears in a statement or a
        # message, and on a fresh deployment it is a common word.
        try:
            self.c = pyexasol.connect(dsn=self.dsn, user=user, password=pw, encryption=True,
                                      websocket_sslopt={"cert_reqs": ssl.CERT_NONE},
                                      autocommit=True, connection_timeout=10)
        except Exception as e:
            raise SqlError(state.redact(str(e)), "db_down")

    def run(self, sql, fetch=True):
        state.log("SQL", sql)
        try:
            st = self.c.execute(sql)
        except Exception as e:
            msg = _engine_message(e)
            state.log("SQLERR", msg)
            raise SqlError(msg, classify(msg))
        if fetch and st.result_type == "resultSet":
            return st.fetchall()
        return []

    def value(self, sql):
        rows = self.run(sql)
        return rows[0][0] if rows else None

    def close(self):
        try:
            self.c.close()
        except Exception:
            pass


def _engine_message(e):
    msg = getattr(e, "message", None) or str(e)
    return state.redact(msg)


# --- what a failure means -------------------------------------------------------
# Ordered: the first match wins. Each kind maps to a remedy in lifecycle.py.

_KINDS = [
    ("driver_not_registered", r"No default DRIVER registered|Driver=\S+ is unknown"),
    # A native adapter built for another Rust SLC version than the active one.
    ("runtime_mismatch", r"Fingerprint mismatch"),
    ("slc_missing", r"unsupported script language|script language container|"
                    r"Script language \S+ is not (?:defined|available)"),
    ("tls_policy", r"security policy has prevented|SocketPermission"),
    # Native clients wrap a certificate failure in their network error
    # ("error sending request ... invalid peer certificate"): before network.
    # ...and TLS spoken to a plain-HTTP port reads as a corrupt message.
    ("tls", r"invalid peer certificate|UnknownIssuer|certificate verify failed|"
            r"corrupt message|InvalidContentType"),
    ("dns", r"UnknownHostException|Temporary failure in name resolution|Name or service not known|"
            r"dns error|failed to lookup address"),
    ("schema_missing", r"NoSuchNamespace|Namespace does not exist|namespace \S+ (?:not found|does not exist)"),
    # Before tls: "SSL ... Connection reset" is the network dropping, and
    # reading it as a TLS failure would invite a needless TLS downgrade.
    ("network", r"Connection (?:to \S+ )?refused|Connection reset|No route to host|"
                r"Network is unreachable|connect timed out|client error \(Connect\)|"
                r"error sending request|operation timed out"),
    ("tls", r"SSL|PKIX|trustAnchors|certificate|does not support SSL|handshake"),
    ("auth", r"password authentication failed|authentication failed|Access denied for user|"
             r"Login failed|ORA-01017|invalid username|role \S+ does not exist|"
             r"HTTP 401|HTTP 403|Unauthorized|InvalidAccessKeyId|SignatureDoesNotMatch|AccessDenied|"
             r"PermissionDenied|status: 40[13]\b"),
    ("database_missing", r"database \S+ does not exist|Unknown database|Cannot open database"),
    ("permission", r"permission denied|insufficient privilege|not authorized"),
    ("mixed_case", r"E-VSPG-6|cannot be used in virtual schema"),
    ("timezone", r"invalid value for parameter \"TimeZone\""),
    ("network", r"Connection (?:to \S+ )?refused|connection attempt failed|timed out|No route to host|"
                r"Network is unreachable|Connection reset|EOFException"),
]


def classify(message):
    # The engine quotes the connection string back ("Connecting to
    # 'jdbc:postgresql://...?sslmode=require' failed: Connection refused"), and
    # its sslmode would read as a TLS failure. Classify the words, not the URL.
    text = re.sub(r"'jdbc:[^']*'", "''", message or "")
    for kind, pattern in _KINDS:
        if re.search(pattern, text, re.I):
            return kind
    return "unknown"


def short(message, limit=300):
    """The engine's first meaningful line, without the Java stack."""
    m = state.redact(message or "")
    caused = re.findall(r"Caused by: '([^']+)'", m)
    if caused:
        return caused[-1][:limit]
    jdbc = re.search(r"failed: (.+?)(?: \(Session: \d+\))?$", m.splitlines()[0] if m else "")
    if jdbc:
        return jdbc.group(1)[:limit]
    first = m.strip().splitlines()[0] if m.strip() else ""
    return re.sub(r"\s*\(Session: \d+\)", "", first)[:limit]
