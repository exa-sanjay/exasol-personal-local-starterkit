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
    t = (text or "").strip()
    srv = t.lower().startswith(_SRV)
    hosts = t.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
    if "," in hosts:
        raise net.UrlError("give one host of the replica set, not a seed list: the driver finds the other "
                           "members itself (a mongodb+srv:// address works too)")
    fields, notes = net.parse_url(connector, text)
    params = fields.setdefault("params", {})
    if srv:
        params["srv"] = "true"
        # Atlas speaks TLS unless told otherwise.
        params.setdefault("tls", "true")
    if "ssl" in params:  # the older spelling of the same switch
        params.setdefault("tls", params.pop("ssl"))
    if "tls" in params:
        params["tls"] = params["tls"].lower()
    auth = params.pop("authSource", None)
    if auth and auth != "admin":
        # exasol-mongodb-vs 0.1.3 authenticates against admin whatever the
        # URI says (seen in the MongoDB server log): a user defined elsewhere
        # could never log in. Said now, instead of a refused login later.
        raise net.UrlError("the MongoDB adapter always logs in against the admin database, so authSource=%s "
                           "cannot work: use a user defined in admin (with the read role on the database "
                           "to query)" % auth)
    return fields, notes


def build_url(connector, host, inputs, level, params):
    p = dict(params)
    srv = p.pop("srv", None) == "true"
    h = "[%s]" % host if ":" in host and not host.startswith("[") else host
    if srv:
        base = "%s%s/" % (_SRV, h)
    else:
        base = "mongodb://%s:%s/" % (h, inputs.get("port") or connector["url"]["default_port"])
    p["authSource"] = "admin"  # what the adapter uses anyway; written so the URI says the truth
    return base + "?" + "&".join("%s=%s" % (k, net.quote(str(v), safe="")) for k, v in sorted(p.items()))


def properties(connector, names, inputs, host):
    return {"MONGODB_CONNECTION": names["connection"], "DATABASE": inputs.get("database") or "",
            "COLLECTION": inputs.get("collection") or ""}
