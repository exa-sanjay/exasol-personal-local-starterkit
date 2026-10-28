"""Snowflake: the account is the host, and the database, warehouse, schema
and role are URL parameters, not a path -

    jdbc:snowflake://xy12345.eu-central-1.snowflakecomputing.com:443/?db=SHOP&warehouse=WH&role=R

JDBC_QUERY_RESULT_FORMAT=JSON is not optional: with driver 4.x the default
Arrow format fails inside Exasol's Java runtime (ExceptionInInitializerError
in UnsafeAllocationManager), so the kit always sets it.
"""

from urllib.parse import parse_qsl, quote

from engine import net, state

_FIELD_PARAMS = {"db": "database", "warehouse": "warehouse", "schema": "schema", "role": "role", "user": "user"}


def parse_url(connector, text):
    url = connector["url"]
    text = text.strip()
    if not text.lower().startswith(url["scheme"]):
        raise net.UrlError("this does not look like a Snowflake connection string "
                           "(expected it to start with %s)" % url["scheme"])
    rest = text[len(url["scheme"]):]
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    host, port = net._split_host_port(rest.rstrip("/"))
    if not host:
        raise net.UrlError("no account host found in the connection string")
    notes, fields, params, dropped = [], {"host": host, "port": port or url["default_port"]}, {}, []
    allowed = {p.lower(): p for p in url["allowed_params"]}
    secret = set(p.lower() for p in url["secret_params"])
    for key, value in parse_qsl(query, keep_blank_values=True):
        k = key.lower()
        if k in _FIELD_PARAMS:
            fields[_FIELD_PARAMS[k]] = value
        elif k in secret:
            state.register_secret(value)
            if not any(n[0] == "password_stripped" for n in notes):
                notes.append(("password_stripped", net.PASSWORD_NOTE))
        elif k == "jdbc_query_result_format":
            continue  # the kit sets it
        elif k in allowed:
            params[allowed[k]] = value
        else:
            dropped.append(key)
    if dropped:
        notes.append(("params_dropped",
                      "Ignored connection parameter(s) the kit does not manage: %s" % ", ".join(sorted(dropped))))
    fields["params"] = params
    return fields, notes


def build_url(connector, host, inputs, level, params):
    q = [("db", inputs.get("database")), ("warehouse", inputs.get("warehouse")), ("role", inputs.get("role"))]
    q = [(k, v) for k, v in q if v] + sorted(params.items()) + [("JDBC_QUERY_RESULT_FORMAT", "JSON")]
    return "jdbc:snowflake://%s:%s/?%s" % (host, inputs["port"], "&".join(
        "%s=%s" % (k, quote(str(v), safe="")) for k, v in q))
