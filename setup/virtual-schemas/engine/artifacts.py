"""Adapter and driver JARs: fetch, verify, cache, stage, release.

A JAR is downloaded only when a connect needs it, and accepted only when its
SHA-256 matches the pin in connector.json AND the checksum its publisher
ships (a GitHub release's .sha256, Maven Central's .sha1). Verified files are
cached by digest, so ten sources of one type download once.

Staging is a file copy into the deployment's /exa folder - on Exasol Personal
local that folder IS BucketFS and the JDBC driver store, and the database
picks changes up without a restart:

    <exa>/bucketfs/bfsdefault/default/exakit-vs/<connector>/<version>/<adapter>.jar
        -> /buckets/bfsdefault/default/exakit-vs/<connector>/<version>/...
    <exa>/jdbc/<DRIVERNAME>/{<driver>.jar, settings.cfg}

Versioned bucket folders mean an update stages next to the old files instead
of over them, so a running adapter script never sees its JAR change.
"""

import hashlib
import os
import shutil
import urllib.request
from pathlib import Path

from . import state

BUCKET_PREFIX = "/buckets/bfsdefault/default"
BUCKET_DIR = Path("bucketfs") / "bfsdefault" / "default"
KIT_BUCKET = "exakit-vs"


class ArtifactError(Exception):
    """kind: 'checksum' (a file did not match its pin - do not retry, report
    it), 'download' (network or publisher trouble - retry later)."""

    def __init__(self, message, kind="download"):
        super().__init__(message)
        self.kind = kind


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _get(url, timeout=120):
    if not url.startswith("https://"):
        raise ArtifactError("refusing to download over anything but HTTPS: %s" % url)
    req = urllib.request.Request(url, headers={"User-Agent": "exakit-virtual-schemas"})
    return urllib.request.urlopen(req, timeout=timeout)


def _upstream_digest(spec):
    """(algorithm, hex) the publisher states for this file, or None when it
    states none or cannot be reached - then the pin alone decides. The pin is
    the security check; this second opinion only catches a pin that was
    copied wrong, so its absence must not stop an install."""
    for key, algo in (("sha256_url", "sha256"), ("sha1_url", "sha1")):
        url = spec.get(key)
        if not url:
            continue
        try:
            with _get(url, 60) as r:
                text = r.read().decode("utf-8", "replace").strip()
        except Exception as e:
            state.log("WARN", "publisher checksum for %s unavailable: %s" % (spec["file"], e))
            return None
        if not text:
            return None
        # sha256sum format ("<hex>  <file>") or a bare hex digest.
        return algo, text.split()[0].lower()
    return None


def fetch(spec, ui=None):
    """Return the cached, verified path of the artifact `spec` describes."""
    want = spec["sha256"].lower()
    target = state.cache_dir() / want / spec["file"]
    if target.exists() and sha256_file(target) == want:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".part-%d" % os.getpid())
    if ui:
        ui.info("Downloading %s" % spec["file"])
    state.log("INFO", "download %s" % spec["url"])
    try:
        with _get(spec["url"]) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
        got = sha256_file(tmp)
        if got != want:
            raise ArtifactError("%s failed verification: SHA-256 %s does not match the pinned %s. "
                                "Nothing was installed." % (spec["file"], got, want), "checksum")
        upstream = _upstream_digest(spec)
        if upstream:
            algo, stated = upstream
            actual = got if algo == "sha256" else _digest(tmp, algo)
            if actual != stated:
                raise ArtifactError("%s does not match the %s its publisher states (%s). "
                                    "Nothing was installed." % (spec["file"], algo, stated), "checksum")
        os.replace(tmp, target)
    except ArtifactError:
        raise
    except Exception as e:
        raise ArtifactError("could not download %s: %s" % (spec["file"], e))
    finally:
        if tmp.exists():
            tmp.unlink()
    return target


def payload(spec, path):
    """The file to stage from a verified download: the download itself, or -
    for an archive (spec "extract": "udf/lib.so") - that one member, unpacked
    next to it in the cache. Only the named member is read, and only as a
    regular file: no other path in the archive is ever written."""
    member = spec.get("extract")
    if not member:
        return path
    out = Path(path).parent / "extracted" / Path(member).name
    if out.is_file():
        return out
    import tarfile
    try:
        with tarfile.open(path, "r:*") as t:
            info = t.getmember(member)
            if not info.isfile():
                raise ArtifactError("%s in %s is not a regular file" % (member, spec["file"]), "checksum")
            src = t.extractfile(info)
            out.parent.mkdir(parents=True, exist_ok=True)
            tmp = out.with_name(out.name + ".part-%d" % os.getpid())
            with open(tmp, "wb") as f:
                shutil.copyfileobj(src, f)
            os.replace(tmp, out)
    except KeyError:
        raise ArtifactError("%s does not contain %s" % (spec["file"], member), "checksum")
    except (tarfile.TarError, OSError) as e:
        raise ArtifactError("could not unpack %s from %s: %s" % (member, spec["file"], e))
    return out


def _digest(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _copy_atomic(src, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and sha256_file(dest) == sha256_file(src):
        return False
    tmp = dest.with_name(dest.name + ".part-%d" % os.getpid())
    shutil.copyfile(src, tmp)
    os.replace(tmp, dest)
    return True


def udf_object(bucket, file_name):
    """How a native script names its library: bucket-relative, no leading
    slash (as the Lakehouse installer writes it, proven in the Phase-6 spike)."""
    return "%s/%s/%s" % (BUCKET_PREFIX.lstrip("/"), bucket, file_name)


def bucket_rel(connector, version=None):
    return Path(KIT_BUCKET) / connector["id"] / (version or connector["adapter"]["version"])


def describe(connector):
    """What a source built from this connector right now records about its
    artifacts - so it can later be checked and removed by what it USES, not
    by whatever the connector pins after a kit update."""
    from . import plan
    drv = connector.get("driver") if (connector.get("driver") or {}).get("settings") else None
    ad = plan.adapter(connector)
    return {
        "adapter_key": "%s/%s" % (connector["id"], ad["version"]),
        "adapter_version": ad["version"],
        "adapter_file": ad["stage_name"],
        "runtime": plan.runtime_kind(connector),
        "bucket": bucket_rel(connector).as_posix(),
        "driver_name": drv["settings"]["DRIVERNAME"] if drv else None,
        "driver_file": drv["file"] if drv else None,
        "driver_version": drv["version"] if drv else None,
    }


def stage_adapter(exa_root, connector, adapter_path, driver_path):
    """Copy the adapter (and the driver, when the adapter does not bundle
    one) into the versioned bucket folder. Returns the %jar paths."""
    rel = bucket_rel(connector)
    host_dir = Path(exa_root) / BUCKET_DIR / rel
    jars = [adapter_path]
    if driver_path is not None and not (connector.get("driver") or {}).get("bundled_in_adapter"):
        jars.append(driver_path)
    sql_paths = []
    for p in jars:
        _copy_atomic(p, host_dir / p.name)
        sql_paths.append("%s/%s/%s" % (BUCKET_PREFIX, rel.as_posix(), p.name))
    return sql_paths


def settings_cfg(driver):
    """The registration file: KEY=VALUE lines, LF only, and it MUST end with an
    empty line or Nano silently ignores the last key."""
    s = driver["settings"]
    order = ["DRIVERNAME", "PREFIX", "DRIVERMAIN", "FETCHSIZE", "INSERTSIZE", "NOSECURITY"]
    keys = [k for k in order if k in s] + sorted(k for k in s if k not in order)
    lines = ["%s=%s" % (k, s[k]) for k in keys] + ["JAR=%s" % driver["file"]]
    return ("\n".join(lines) + "\n\n").encode("ascii")


def driver_dir(exa_root, driver):
    return Path(exa_root) / "jdbc" / driver["settings"]["DRIVERNAME"]


def stage_driver(exa_root, driver, driver_path):
    d = driver_dir(exa_root, driver)
    d.mkdir(parents=True, exist_ok=True)
    _copy_atomic(driver_path, d / driver["file"])
    cfg = d / "settings.cfg"
    data = settings_cfg(driver)
    if not cfg.exists() or cfg.read_bytes() != data:
        tmp = cfg.with_name("settings.cfg.part-%d" % os.getpid())
        tmp.write_bytes(data)
        os.replace(tmp, cfg)
    # An older driver version left in the folder would be a second JAR on the
    # registration's classpath; only the pinned one stays.
    for p in d.iterdir():
        if p.suffix == ".jar" and p.name != driver["file"]:
            p.unlink()
    return d


def foreign_prefix_owners(exa_root, driver):
    """Other registrations claiming the same JDBC prefix. Nano keys on
    DRIVERNAME and reads every jdbc/ subfolder; with two registrations for one
    prefix the later one silently becomes the default, which is what the
    adapter's generated IMPORT uses."""
    ours = driver["settings"]["DRIVERNAME"]
    prefix = driver["settings"]["PREFIX"]
    found = []
    root = Path(exa_root) / "jdbc"
    if not root.is_dir():
        return found
    for sub in root.iterdir():
        cfg = sub / "settings.cfg"
        if not cfg.is_file():
            continue
        kv = dict(l.split("=", 1) for l in cfg.read_text("utf-8", "replace").splitlines() if "=" in l)
        if kv.get("PREFIX") == prefix and kv.get("DRIVERNAME") != ours:
            found.append(kv.get("DRIVERNAME") or sub.name)
    return found


# --- registry: who uses what -------------------------------------------------------

def load_registry():
    reg = state.read_json(state.registry_path(), {}) or {}
    reg.setdefault("schema_version", 1)
    reg.setdefault("adapters", {})
    reg.setdefault("drivers", {})
    # Custom runtimes the KIT installed, with the version it put in: the
    # launcher records the alias and the source file, not a version.
    reg.setdefault("runtimes", {})
    return reg


def add_ref(reg, kind, key, source, info):
    entry = reg[kind].setdefault(key, dict(info, refs=[]))
    entry.update(info)
    if source not in entry["refs"]:
        entry["refs"].append(source)
        entry["refs"].sort()


def drop_ref(reg, kind, key, source):
    """Returns True when nothing references the entry any more."""
    entry = reg[kind].get(key)
    if not entry:
        return False
    if source in entry["refs"]:
        entry["refs"].remove(source)
    return not entry["refs"]


def remove_bucket_files(exa_root, rel):
    """Delete exactly the kit's versioned folder, then its empty parents up
    to (not including) the bucket root. Never a broad delete."""
    rel = Path(rel)
    if rel.parts[:1] != (KIT_BUCKET,) or len(rel.parts) != 3:
        raise ArtifactError("refusing to delete %s: not a kit-owned versioned folder" % rel)
    root = Path(exa_root) / BUCKET_DIR
    target = root / rel
    removed = []
    if target.is_dir():
        for p in target.iterdir():
            if p.is_file():
                p.unlink()
                removed.append(str(p))
        target.rmdir()
    for parent in (target.parent, target.parent.parent):
        try:
            parent.rmdir()
        except OSError:
            break
    return removed


def remove_driver(exa_root, driver_name, driver_file):
    d = Path(exa_root) / "jdbc" / driver_name
    removed = []
    if d.is_dir():
        for name in (driver_file, "settings.cfg"):
            p = d / name
            if p.exists():
                p.unlink()
                removed.append(str(p))
        try:
            d.rmdir()
        except OSError:
            pass  # someone put their own file there; leave it
    return removed
