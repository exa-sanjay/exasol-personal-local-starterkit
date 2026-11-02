"""Lakehouse (exasol-labs/lakehouse-engine-rs): a native Rust adapter over an
Iceberg REST catalog or a Unity Catalog (Databricks or OSS).

Its CONNECTION is not user + password: TO is the catalog's HTTP(S) address,
USER is empty, and IDENTIFIED BY is a JSON document of storage settings and
keys - the secret is the S3 secret key, or a catalog token when the catalog
vends storage credentials. The kit builds that document from the answers,
so the user never writes JSON.

TLS is the scheme: https (verified - the Rust SLC carries a CA bundle and
checks the chain) or http, which the virtual schema has to allow with
ALLOW_HTTP. A storage endpoint on this machine is reached through the
container's host alias, like the catalog itself.
"""

import json
import re
from urllib.parse import urlsplit

from engine import net, plan

_URL = re.compile(r"^(https?)://([^/:?#]+)(?::(\d{1,5}))?(/[^?#]*)?", re.I)


def parse_url(connector, text):
    t = (text or "").strip()
    if re.match(r"^https?://[^/?#]*@", t, re.I):
        # Never accepted, never echoed: the key would sit in shell history and
        # the CONNECTION's address in clear text.
        raise net.UrlError("the catalog URL carries credentials; give the access key with --user and the "
                           "secret with --password-file instead")
    m = _URL.match(t)
    if not m or t[m.end():] not in ("", "/"):
        raise net.UrlError("this does not look like a catalog URL (expected http://host:port or "
                           "https://host)")
    scheme = m.group(1).lower()
    fields = {"host": m.group(2), "params": {"scheme": scheme}}
    fields["port"] = int(m.group(3)) if m.group(3) else (443 if scheme == "https" else 80)
    path = (m.group(4) or "").rstrip("/")
    if path:
        fields["path"] = path
    return fields, []


def build_url(connector, host, inputs, level, params):
    scheme = params.get("scheme") or ("https" if level == "verify" else "http")
    port = int(inputs.get("port") or connector["url"]["default_port"])
    default = 443 if scheme == "https" else 80
    netloc = "[%s]" % host if ":" in host and not host.startswith("[") else host
    url = "%s://%s%s" % (scheme, netloc, "" if port == default else ":%d" % port)
    return url + (inputs.get("path") or "")


def _kind(inputs):
    k = (inputs.get("catalog") or "iceberg").strip().lower().replace("_", "-")
    if k in ("iceberg", "iceberg-rest", "rest"):
        return "iceberg"
    if k in ("unity", "unity-catalog", "databricks"):
        return "unity"
    raise plan.PlanError("Catalog type must be iceberg or unity (got %r)" % inputs.get("catalog"))


def validate(connector, v):
    v = dict(v)
    v["catalog"] = _kind(v)
    if v["catalog"] == "iceberg" and not v.get("warehouse"):
        raise plan.PlanError("Warehouse is required for an Iceberg REST catalog: set EXAKIT_VS_WAREHOUSE "
                             "(the identifier the catalog registered, e.g. s3://warehouse/)")
    if v["catalog"] == "unity" and v.get("namespace") and \
            not re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", v["namespace"]):
        raise plan.PlanError("A Unity Catalog namespace is catalog.schema (e.g. main.sales)")
    ep = v.get("endpoint")
    if ep:
        m = re.match(r"^(https?)://([^/\s:@]+)(?::\d{1,5})?/?$", ep, re.I)
        if not m:
            raise plan.PlanError("The storage endpoint must be a URL such as http://minio:9000 (no "
                                 "credentials, no path)")
        # The rule the catalog follows: plain HTTP only on this machine or a
        # private network, never across the internet.
        if m.group(1).lower() == "http" and net.classify_host(m.group(2)) == "public":
            raise plan.PlanError("A plain-HTTP storage endpoint is only allowed on this machine or a private "
                                 "network; %s is a public host - use https" % m.group(2))
    return v


def connection_user(connector, inputs):
    return ""


def _endpoint_for_db(endpoint):
    """A storage endpoint on this machine is reached from inside the database
    container through its host alias, exactly as the catalog is."""
    parts = urlsplit(endpoint)
    host = parts.hostname or ""
    if net.classify_host(host) != "loopback":
        return endpoint
    netloc = net.HOST_ALIAS + (":%d" % parts.port if parts.port else "")
    return parts._replace(netloc=netloc).geturl()


def connection_secret(connector, inputs, password):
    doc = {}
    if _kind(inputs) == "iceberg" and inputs.get("warehouse"):
        doc["warehouse"] = inputs["warehouse"]
    if inputs.get("user"):
        # Static S3 keys: the access key is the "user", the secret key the password.
        doc.update(access_key=inputs["user"], secret_key=password, region=inputs.get("region") or "us-east-1")
        if inputs.get("endpoint"):
            doc.update(endpoint=_endpoint_for_db(inputs["endpoint"]), path_style=True)
    else:
        # A catalog token; storage credentials come from the catalog. Unity
        # Catalog's temporary credentials carry no region, and without one the
        # adapter addresses 's3..amazonaws.com' (seen live): state it.
        doc.update(token=password, use_vended_credentials=True)
        if inputs.get("region"):
            doc["region"] = inputs["region"]
    return json.dumps(doc, separators=(",", ":"))


def properties(connector, names, inputs, host):
    props = {"CATALOG_CONNECTION": names["connection"], "NAMESPACE": inputs.get("namespace") or ""}
    if _kind(inputs) == "unity":
        props["CATALOG_KIND"] = "UNITY_CATALOG"
    plain = inputs.get("tls") == "none" or (inputs.get("endpoint") or "").lower().startswith("http://")
    if plain:
        props["ALLOW_HTTP"] = "true"
    return props
