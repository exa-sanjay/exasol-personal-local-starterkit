"""Oracle: the thin driver's URL is not host:port/database.

    jdbc:oracle:thin:@//host:1521/SERVICE      Easy Connect (what the kit writes)
    jdbc:oracle:thin:@host:1521/SERVICE        Easy Connect without the slashes
    jdbc:oracle:thin:@host:1521:SID            the old SID form
    jdbc:oracle:thin:user/password@//host...   credentials inline - stripped

A TNS descriptor, (DESCRIPTION=...), is refused with the reason: the kit
writes and checks Easy Connect only. Parameters ride on Easy Connect Plus
(?key=value&...), which ojdbc 19 and later read - that is how the encrypt
level asks for Native Network Encryption.
"""

from urllib.parse import parse_qsl, quote

from engine import net, state


def parse_url(connector, text):
    url = connector["url"]
    text = text.strip()
    if not text.lower().startswith("jdbc:oracle:thin:"):
        raise net.UrlError("this does not look like an Oracle connection string "
                           "(expected it to start with jdbc:oracle:thin:@)")
    rest = text[len("jdbc:oracle:thin:"):]
    notes, user = [], None
    at = rest.rfind("@")
    if at < 0:
        raise net.UrlError("an Oracle connection string needs @//host:port/service")
    creds, rest = rest[:at], rest[at + 1:]
    if creds:
        user, slash, secret = creds.partition("/")
        if slash:
            state.register_secret(secret)
            notes.append(("password_stripped", net.PASSWORD_NOTE))
    if rest.startswith("("):
        raise net.UrlError("TNS descriptors are not supported - give the host, port and service name "
                           "(jdbc:oracle:thin:@//host:1521/SERVICE)")
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    rest = rest[2:] if rest.startswith("//") else rest
    if "/" in rest:
        hostport, service = rest.split("/", 1)
    else:
        parts = rest.split(":")
        if len(parts) != 3:
            raise net.UrlError("expected host:port/SERVICE or host:port:SID after the @")
        hostport, service = ":".join(parts[:2]), parts[2]
    host, port = net._split_host_port(hostport)
    if not host:
        raise net.UrlError("no host found in the connection string")
    allowed = {p.lower(): p for p in url["allowed_params"]}
    secret = set(p.lower() for p in url["secret_params"])
    params, dropped = {}, []
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key.lower() in secret:
            state.register_secret(value)
            if not any(n[0] == "password_stripped" for n in notes):
                notes.append(("password_stripped", net.PASSWORD_NOTE))
        elif key.lower() in allowed:
            params[allowed[key.lower()]] = value
        else:
            dropped.append(key)
    if dropped:
        notes.append(("params_dropped",
                      "Ignored connection parameter(s) the kit does not manage: %s" % ", ".join(sorted(dropped))))
    fields = {"host": host, "port": port or url["default_port"], "database": service, "params": params}
    if user:
        fields["user"] = user
    return fields, notes


def build_url(connector, host, inputs, level, params):
    h = "[%s]" % host if ":" in host and not host.startswith("[") else host
    base = "jdbc:oracle:thin:@//%s:%s/%s" % (h, inputs["port"], inputs["database"])
    if params:
        base += "?" + "&".join("%s=%s" % (k, quote(str(v), safe="")) for k, v in params.items())
    return base
