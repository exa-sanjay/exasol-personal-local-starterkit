"""MongoDB (exasol-labs/exasol-mongodb-vs): a native Rust adapter, one
collection per virtual schema.

The CONNECTION is a MongoDB URI with the user and password in their own
fields (they override any in the URI). The database and collection are
virtual-schema properties, not part of the URI. A mongodb+srv:// address
(Atlas) has no port: the driver finds the hosts through DNS SRV records,
which the Rust SLC resolves itself.

TLS is the URI's tls parameter: verified (the driver carries its own root
certificates and checks the chain) or off, which the kit allows only for
hosts on this machine or a private network.
"""

from engine import net

_SRV = "mongodb+srv://"


def parse_url(connector, text):
    srv = (text or "").strip().lower().startswith(_SRV)
    fields, notes = net.parse_url(connector, text)
    params = fields.setdefault("params", {})
    if srv:
        params["srv"] = "true"
        # Atlas speaks TLS unless told otherwise.
        params.setdefault("tls", "true")
    if "ssl" in params:  # the older spelling of the same switch
        params.setdefault("tls", params.pop("ssl"))
    if params.get("authSource"):
        fields["auth_source"] = params.pop("authSource")
    return fields, notes


def build_url(connector, host, inputs, level, params):
    p = dict(params)
    srv = p.pop("srv", None) == "true"
    h = "[%s]" % host if ":" in host and not host.startswith("[") else host
    if srv:
        base = "%s%s/" % (_SRV, h)
    else:
        base = "mongodb://%s:%s/" % (h, inputs.get("port") or connector["url"]["default_port"])
    p["authSource"] = inputs.get("auth_source") or "admin"
    return base + "?" + "&".join("%s=%s" % (k, net.quote(str(v), safe="")) for k, v in sorted(p.items()))


def properties(connector, names, inputs, host):
    return {"MONGODB_CONNECTION": names["connection"], "DATABASE": inputs.get("database") or "",
            "COLLECTION": inputs.get("collection") or ""}
