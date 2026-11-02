"""Databricks (exasol/databricks-virtual-schema): a Lua adapter for the
metadata, the Databricks JDBC driver for the rows.

  - The adapter reads table metadata over HTTPS from the workspace's REST
    API, and upstream switches certificate checks off there (its issue #4):
    a Lua script has no filesystem, so it cannot load a trust store. The kit
    closes that gap by pinning: when connecting, it reads the workspace's
    certificate from THIS machine with full verification (CA chain and host
    name), and writes that certificate's SHA-256 into the adapter script,
    patched to refuse any other certificate; the patched handshake sends the
    host name (SNI) as the PC does, so both see the same certificate, and a
    renewed certificate is re-read, verified and re-pinned by `source check`.
    The script is therefore the
    source's own (adapter.script_scope "source").
  - The rows travel through the database's import process and the
    Databricks JDBC driver, whose Java trust store is empty on Exasol
    Personal; AllowSelfSignedCerts=1 is the driver's way past that (proven
    against a live workspace).
  - Token authentication: the CONNECTION's USER is the literal 'token', the
    personal access token is its password (AuthMech=3).
"""

import hashlib
import re
import socket
import ssl

from engine import net, plan

_URL = re.compile(r"^jdbc:databricks://([^:/;]+)(?::(\d{1,5}))?(?:/[^;]*)?(;.*)?$", re.I)
_SECRET_KEYS = ("pwd", "password", "token", "oauth2secret", "auth_accesstoken")
PIN_MARK = "-- exakit: certificate pin"


def parse_url(connector, text):
    m = _URL.match((text or "").strip())
    if not m:
        raise net.UrlError("this does not look like a Databricks JDBC URL (expected "
                           "jdbc:databricks://<host>:443/default;...;httpPath=...)")
    fields = {"host": m.group(1), "port": int(m.group(2) or 443), "params": {}}
    notes = []
    for part in (m.group(3) or "").split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        if k.strip().lower() == "httppath":
            fields["http_path"] = v.strip()
        elif k.strip().lower() in _SECRET_KEYS:
            from engine import state
            state.register_secret(v)
            notes.append(("password_stripped", net.PASSWORD_NOTE))
    return fields, notes


def validate(connector, v):
    hp = v.get("http_path") or ""
    if not re.match(r"^/[A-Za-z0-9/_.-]+$", hp):
        # It goes into the JDBC URL: a ';' would add driver properties.
        raise plan.PlanError("The SQL warehouse HTTP path looks like /sql/1.0/warehouses/abc123 (got %r)" % hp)
    return v


def connection_user(connector, inputs):
    return "token"


def build_url(connector, host, inputs, level, params):
    # The adapter parses host AND port from this URL, so the port is always
    # written out; AuthMech=3 is token authentication.
    parts = ["transportMode=http", "AuthMech=3", "httpPath=%s" % inputs["http_path"]]
    parts += ["%s=%s" % (k, v) for k, v in sorted(params.items())]
    return "jdbc:databricks://%s:%s/default;%s" % (host, int(inputs.get("port") or 443), ";".join(parts))


def prepare(connector, inputs):
    """Read and VERIFY the workspace certificate from this machine, and
    return its SHA-256 to pin. A certificate that does not verify here is
    refused: the pin must start from a certificate a CA vouches for."""
    host, port = inputs["host"], int(inputs.get("port") or 443)
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as e:
        raise plan.PlanError("The certificate of %s could not be verified from this PC (%s); the kit only "
                             "pins a certificate it could verify." % (host, e.verify_message))
    except ssl.SSLError as e:
        # Any other TLS failure: never leave an empty pin behind it.
        raise plan.PlanError("The TLS handshake with %s failed from this PC (%s); the kit pins only a "
                             "certificate it could read and verify." % (host, e.reason or e))
    except OSError as e:
        # Never an empty pin: the database may reach the workspace when this
        # PC does not (a proxy, a split VPN), and every call would then fail
        # as a pin mismatch.
        raise plan.PlanError("This PC cannot reach %s:%s (%s); the kit reads and verifies the workspace "
                             "certificate here before it pins it." % (host, port, e.strerror or e))
    return {"fingerprint": hashlib.sha256(der).hexdigest()}


_HANDSHAKE = """            socket.try(self.c:dohandshake())
            return 1"""

_PINNED = """            pcall(function() self.c:sni(host) end)
            socket.try(self.c:dohandshake())
            local exakit_cert = self.c:getpeercertificate()
            local exakit_got = exakit_cert and string.lower(exakit_cert:digest("sha256")) or ""
            if not EXAKIT_PINS[exakit_got] then
                pcall(function() self.c:close() end)
                error("E-EXAKIT-PIN: the certificate of " .. tostring(host) .. " is not the one the kit pinned ("
                      .. exakit_got .. ")")
            end
            return 1"""


def adapter_source(connector, source, cfg):
    """The upstream adapter with every HTTPS handshake checked against the
    source's pinned certificate. Without a pin (a first connect before the
    certificate was read) the table is empty and every call is refused:
    fail closed, never open."""
    if source.count(_HANDSHAKE) != 1:
        raise plan.PlanError("the Databricks adapter %s no longer has the handshake the kit pins; the kit "
                             "will not install it unpinned" % connector["adapter"]["version"])
    fp = (cfg.get("fingerprint") or "").lower()
    if fp and not re.match(r"^[0-9a-f]{64}$", fp):
        raise plan.PlanError("the recorded certificate fingerprint is malformed")
    pins = "local EXAKIT_PINS = {%s}  %s" % ('["%s"] = true' % fp if fp else "", PIN_MARK)
    return pins + "\n" + source.replace(_HANDSHAKE, _PINNED)
