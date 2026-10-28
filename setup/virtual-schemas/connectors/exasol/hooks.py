"""Exasol as a source - another Exasol database, or a schema of this one.

Three things set it apart from the JDBC connectors:

  - No driver registration. The adapter carries Exasol's JDBC driver for its
    metadata calls, and the data travels through the database's native
    IMPORT FROM EXA, which reads through an EXA connection
    (<name>_EXA, 'host/fingerprint:port') rather than a JDBC one.
  - Certificate verification WORKS: Exasol pins the server certificate by its
    SHA-256 fingerprint in the connection string, so neither the import side
    nor the adapter needs a trust store. The fingerprint is read from the
    server when connecting (prepare) and recorded with the source.
  - localhost is this very database (the connector's "loopback": "local"), and
    such a virtual schema runs with IS_LOCAL = 'true': the pushdown becomes a
    plain local SELECT instead of an import.
"""

import hashlib
import socket
import ssl

from engine import net


def prepare(connector, inputs):
    """Read the server's certificate fingerprint from this machine. For a
    schema of this database the host the user typed is localhost, which
    from here is the published database port as well."""
    host = inputs["host"]
    target = "127.0.0.1" if net.classify_host(host) == "loopback" else host
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target, int(inputs["port"])), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError:
        return {}  # the probe that follows explains the network failure
    return {"fingerprint": hashlib.sha256(der).hexdigest().upper()}


def _endpoint(host, inputs, level):
    h = "[%s]" % host if ":" in host and not host.startswith("[") else host
    fp = inputs.get("fingerprint") if level == "verify" else None
    return "%s/%s:%s" % (h, fp or "nocertcheck", inputs["port"])


def build_url(connector, host, inputs, level, params):
    return "jdbc:exa:" + _endpoint(host, inputs, level)


def extra_connections(connector, names, host, inputs, level):
    return [("_EXA", _endpoint(host, inputs, level))]


def properties(connector, names, inputs, host):
    props = {"CONNECTION_NAME": names["connection"], "SCHEMA_NAME": inputs["schema"]}
    if net.classify_host(host or inputs["host"]) == "loopback":
        props["IS_LOCAL"] = "true"
    else:
        props["IMPORT_FROM_EXA"] = "true"
        props["EXA_CONNECTION"] = names["connection"] + "_EXA"
    return props
