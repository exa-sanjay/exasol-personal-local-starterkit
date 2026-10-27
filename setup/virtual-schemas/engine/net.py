"""Connection strings and hosts.

The user may paste a JDBC URL (or the postgres:// URI a cloud console hands
out) instead of typing fields. It is a convenience, not a passthrough: the URL
is parsed into fields, only the parameters connector.json allows survive, and
an embedded password is stripped and refused - it would otherwise land in the
CONNECTION string, which every user with access to the connection can read.
"""

import ipaddress
import re
import socket
from urllib.parse import parse_qsl, quote, unquote

LOOPBACK_NAMES = ("localhost", "localhost.localdomain", "ip6-localhost")
HOST_ALIAS = "host.containers.internal"
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*\.?$")


class UrlError(ValueError):
    pass


def parse_url(connector, text):
    """Returns (fields, notes). fields: host, port, database, params, user."""
    url = connector["url"]
    text = text.strip()
    notes = []
    lowered = text.lower()
    rest = None
    for prefix in [url["scheme"]] + url.get("alt_schemes", []):
        if lowered.startswith(prefix.lower()):
            rest = text[len(prefix):]
            break
    if rest is None:
        raise UrlError("this does not look like a %s connection string (expected it to start with %s)"
                       % (connector["label"], url["scheme"]))

    # Everything after '?' is parameters. PostgreSQL JDBC also accepts ';'.
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    path = ""
    if "/" in rest:
        rest, path = rest.split("/", 1)

    user = None
    if "@" in rest:
        userinfo, rest = rest.rsplit("@", 1)
        if ":" in userinfo:
            user, _ = userinfo.split(":", 1)
            notes.append(("password_stripped",
                          "The pasted string contained a password. It was removed: you are asked "
                          "for it separately, so it never lands in the connection string, the "
                          "kit's files or your shell history."))
        else:
            user = userinfo
        user = unquote(user) if user else None

    host, port = _split_host_port(rest)
    if not host:
        raise UrlError("no host found in the connection string")

    params = {}
    secret = set(p.lower() for p in url.get("secret_params", []))
    allowed = {p.lower(): p for p in url.get("allowed_params", [])}
    dropped = []
    for key, value in parse_qsl(query.replace(";", "&"), keep_blank_values=True):
        k = key.lower()
        if k in secret:
            if k in ("password",) and not any(n[0] == "password_stripped" for n in notes):
                notes.append(("password_stripped",
                              "The pasted string contained a password parameter. It was removed "
                              "and you are asked for the password separately."))
            continue
        if k == "user":
            user = user or value
            continue
        if k in allowed:
            params[allowed[k]] = value
        else:
            dropped.append(key)
    if dropped:
        notes.append(("params_dropped",
                      "Ignored connection parameter(s) the kit does not manage: %s" % ", ".join(sorted(dropped))))

    fields = {"host": host, "port": port or url["default_port"], "database": unquote(path) or None,
              "params": params}
    if user:
        fields["user"] = user
    return fields, notes


def _split_host_port(hp):
    hp = hp.strip()
    if hp.startswith("["):
        end = hp.find("]")
        if end < 0:
            raise UrlError("unterminated IPv6 address")
        host, tail = hp[1:end], hp[end + 1:]
        port = tail[1:] if tail.startswith(":") else ""
    elif hp.count(":") == 1:
        host, port = hp.split(":")
    else:
        host, port = hp, ""
    if port:
        port = validate_port(port)
    return host, port or None


def validate_port(value):
    try:
        p = int(str(value).strip())
    except ValueError:
        raise UrlError("port must be a number, got %r" % value)
    if not 1 <= p <= 65535:
        raise UrlError("port must be between 1 and 65535, got %d" % p)
    return p


def validate_host(host):
    host = (host or "").strip()
    if not host:
        raise UrlError("a host is required")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOST_RE.match(host):
        raise UrlError("%r is not a valid host name" % host)
    return host


def build_url(connector, host, port, database, params):
    url = connector["url"]
    h = "[%s]" % host if ":" in host and not host.startswith("[") else host
    base = url["template"].format(host=h, port=port, database=quote(database or "", safe=""))
    if params:
        sep = url.get("param_separator", "&")
        first = url.get("param_start", "?")
        base += first + sep.join("%s=%s" % (k, quote(str(v), safe=":/=")) for k, v in params.items())
    return base


def classify_host(host):
    """loopback | private | public. Private is where an unencrypted link may
    be offered at all: a host on this machine or a local network."""
    h = (host or "").strip().lower().rstrip(".")
    if h in LOOPBACK_NAMES:
        return "loopback"
    if h in (HOST_ALIAS, "host.docker.internal"):
        return "private"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback:
            return "loopback"
        if ip.is_private or ip.is_link_local:
            return "private"
        return "public"
    if "." not in h or h.endswith((".local", ".lan", ".internal", ".home.arpa", ".localdomain")):
        return "private"
    # A name that resolves (from this machine) only to private addresses is a
    # company or home-network server.
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(h, None)}
    except OSError:
        return "public"
    try:
        if addrs and all(ipaddress.ip_address(a.split("%")[0]).is_private for a in addrs):
            return "private"
    except ValueError:
        pass
    return "public"


def resolve_here(host):
    """The addresses this machine resolves the host to (for diagnostics and
    for the IP fallback when the database cannot resolve names)."""
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET)})
    except OSError:
        return []
