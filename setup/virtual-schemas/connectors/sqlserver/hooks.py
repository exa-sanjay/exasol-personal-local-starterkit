"""SQL Server: its URL carries the database and every option as ;key=value
after the host - jdbc:sqlserver://host:1433;databaseName=shop;encrypt=true -
which the generic host:port/database?params parser does not read.

Building it needs no hook: connector.json's template and ';' separators
already produce that shape.
"""

from urllib.parse import unquote

from engine import net, state


def parse_url(connector, text):
    url = connector["url"]
    text = text.strip()
    if not text.lower().startswith(url["scheme"]):
        raise net.UrlError("this does not look like a SQL Server connection string "
                           "(expected it to start with %s)" % url["scheme"])
    rest = text[len(url["scheme"]):]
    hostport, _, opts = rest.partition(";")
    # jdbc:sqlserver://host\instance:port is legal; the named instance goes
    # in the host as the driver writes it.
    host, port = net._split_host_port(hostport)
    if not host:
        raise net.UrlError("no host found in the connection string")
    notes, fields, params, dropped = [], {"host": host, "port": port or url["default_port"]}, {}, []
    allowed = {p.lower(): p for p in url["allowed_params"]}
    secret = set(p.lower() for p in url["secret_params"])
    for part in opts.split(";"):
        if not part.strip() or "=" not in part:
            continue
        key, value = part.split("=", 1)
        k = key.strip().lower()
        value = unquote(value.strip().strip("{}"))
        if k in ("databasename", "database"):
            fields["database"] = value
        elif k in ("user", "username"):
            fields["user"] = value
        elif k in secret:
            state.register_secret(value)
            if not any(n[0] == "password_stripped" for n in notes):
                notes.append(("password_stripped", net.PASSWORD_NOTE))
        elif k in allowed:
            params[allowed[k]] = value
        else:
            dropped.append(key.strip())
    if dropped:
        notes.append(("params_dropped",
                      "Ignored connection parameter(s) the kit does not manage: %s" % ", ".join(sorted(dropped))))
    fields["params"] = params
    return fields, notes
