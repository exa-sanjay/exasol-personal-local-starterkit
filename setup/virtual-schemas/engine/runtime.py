"""The Exasol Personal deployment this add-on works on.

Facts this module is built on (verified against launcher 2.3.0, Nano
2026.2.0-nano.3, see tests/virtual-schemas/spike):

  - `exasol info --json` names the deployment directory; its
    local/runtime/exa folder is the database's /exa.
  - JDBC adapters need the Java script language container (SLC). A fresh
    deployment has none: `exasol slc install java --no-restart` records it and
    it activates on the next start - the only step here that needs a restart.
  - Native (Rust) adapters need a CUSTOM SLC: there is no official Rust
    flavor, so `exasol slc custom install --alias RUST --no-restart` records
    a pinned, verified tarball (runtimes.json), again active after a restart.
    The launcher keeps no version for it; the kit records the one it put in.
  - Lua is built into the database: nothing to install.
  - Every `exasol start` creates a NEW database container.
  - The SLC images on Docker Hub ship /etc/resolv.conf and /etc/hosts as
    empty files, while the UDF framework mounts the real ones under /conf.
    The release tarballs carry /etc -> /conf symlinks; the images do not, so
    adapter scripts cannot resolve any host name. Until the launcher creates
    those links itself, link_sandbox_dns() adds them to the running
    container - and because each start makes a new container, after every
    start (lifecycle.runtime_hook).
"""

import io
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import time
from pathlib import Path


class RuntimeError_(Exception):
    def __init__(self, message, kind="runtime"):
        super().__init__(message)
        self.kind = kind


def _run(cmd, timeout=60, check=False, input_bytes=None):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, input=input_bytes)
    except FileNotFoundError:
        raise RuntimeError_("%s was not found" % cmd[0], "missing_tool")
    except subprocess.TimeoutExpired:
        raise RuntimeError_("%s did not answer within %ss" % (" ".join(cmd[:3]), timeout), "timeout")
    if check and p.returncode != 0:
        raise RuntimeError_("%s failed: %s" % (" ".join(cmd[:3]), _text(p.stderr or p.stdout)[:500]))
    return p


def _text(b):
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")


def db_arch(environ=None):
    """The database's CPU architecture, for native (Rust) artifacts: the
    database runs on this machine's architecture - in Podman on Linux and
    Windows, in the launcher's VM on macOS. EXAKIT_VS_ARCH overrides."""
    environ = os.environ if environ is None else environ
    m = (environ.get("EXAKIT_VS_ARCH") or platform.machine() or "").lower()
    if m in ("amd64", "x86_64", "x64"):
        return "x86_64"
    if m in ("arm64", "aarch64"):
        return "aarch64"
    return m


class Runtime:
    def __init__(self, manifest):
        rt = manifest.get("runtime") or {}
        self.type = rt.get("type")
        self.launcher = rt.get("launcher") or shutil.which("exasol") or "exasol"
        self.engine = rt.get("engine") or "podman"
        self._info = None
        self._deploy_dir = rt.get("deployment_dir")
        if self.type != "personal":
            raise RuntimeError_("virtual schemas need the Exasol Personal runtime (this install "
                                "records %r)" % self.type, "unsupported_runtime")

    def info(self):
        if self._info is None:
            p = _run([self.launcher, "info", "--json"], timeout=30)
            try:
                self._info = json.loads(_text(p.stdout))
            except ValueError:
                self._info = {}
        return self._info

    @property
    def deploy_dir(self):
        d = self.info().get("deploymentDir") or self._deploy_dir
        if not d:
            raise RuntimeError_("the Exasol Personal deployment directory is unknown", "no_database")
        return Path(d)

    @property
    def exa_root(self):
        root = self.deploy_dir / "local" / "runtime" / "exa"
        if not root.is_dir():
            raise RuntimeError_("the deployment has no local/runtime/exa folder (%s) - this launcher "
                                "version does not expose BucketFS on the host" % root, "unsupported_runtime")
        return root

    @property
    def deployment_id(self):
        return self.info().get("deploymentId")

    # --- script language containers ----------------------------------------------

    def slc_list(self):
        """[{type, aliases, flavor, version, installed, source}] from `exasol
        slc list --json`; the table form is the fallback for a launcher
        without --json. A custom SLC (type 'custom') carries no version - the
        launcher does not know it - only the source it was installed from."""
        p = _run([self.launcher, "slc", "list", "--json"], timeout=30)
        out = _text(p.stdout)
        start = out.find("[")
        if p.returncode == 0 and start >= 0:
            try:
                rows = []
                for r in json.loads(out[start:out.rfind("]") + 1]):
                    aliases = r.get("aliases") or ([r["alias"]] if r.get("alias") else [])
                    rows.append({"type": r.get("type", "official"), "language": r.get("language"),
                                 "aliases": [a.lower() for a in aliases], "flavor": r.get("flavor"),
                                 "version": r.get("version"), "installed": bool(r.get("installed")),
                                 "source": r.get("source")})
                return rows
            except (ValueError, KeyError, TypeError):
                pass
        p = _run([self.launcher, "slc", "list"], timeout=30)
        rows = []
        for line in _text(p.stdout).splitlines():
            cols = re.split(r"\s{2,}", line.strip())
            if len(cols) < 4 or cols[0] in ("ALIASES", "CUSTOM ALIAS"):
                continue
            rows.append({"type": "official", "language": None,
                         "aliases": [a.strip().lower() for a in cols[0].split(",")],
                         "flavor": cols[1], "version": cols[2], "installed": cols[3].lower() == "yes",
                         "source": None})
        return rows

    def slc(self, alias):
        for row in self.slc_list():
            if alias.lower() in row["aliases"]:
                return row
        return None

    def install_slc(self, alias):
        _run([self.launcher, "slc", "install", alias, "--no-restart"], timeout=120, check=True)

    def install_custom_slc(self, alias, language, source, update=False):
        """Record a custom SLC (a verified local tarball) for the next start.
        `update` replaces one already registered under that alias."""
        _run([self.launcher, "slc", "custom", "update" if update else "install", "--alias", alias,
              "--language", language, "--source", str(source), "--no-restart"], timeout=600, check=True)

    def java_flavor_dirs(self):
        # Java only: its adapters need the links, the Rust SLC makes its own,
        # and the kit has no business changing how the user's own Python or R
        # scripts behave.
        return ["/exa/slc/%s" % r["flavor"] for r in self.slc_list()
                if r["installed"] and r["type"] == "official" and "java" in r["aliases"]]

    # --- restart ------------------------------------------------------------------
    # Through exakit when the bridge told us where it is: `exakit stop` and
    # `exakit start` also take care of add-on services, a leftover runner on
    # the port, and the launcher's quirks. The launcher directly is the
    # fallback for a bare engine run.

    def restart(self, wait_ready, say=None, timeout=1200):
        """Stop and start the database once. Through exakit when the bridge
        named it: only the add-on services that were RUNNING are started
        again afterwards - a bare `exakit start` would also start ones the
        user had stopped on purpose."""
        t0 = time.time()
        say = say or (lambda text: None)
        exakit = os.environ.get("EXAKIT_VS_EXAKIT")
        running = []
        if exakit and Path(exakit).exists():
            try:
                st = json.loads(_text(_run([exakit, "status", "--json"], timeout=120).stdout) or "{}")
                running = sorted(k for k, v in (st.get("services") or {}).items()
                                 if k != "database" and str(v).startswith("running"))
            except (ValueError, RuntimeError_):
                running = []
            steps = [("Stopping the database", [exakit, "stop", "database"]),
                     ("Starting the database", [exakit, "start", "database"])]
            steps += [("Starting %s again" % sid, [exakit, "start", sid]) for sid in running]
        else:
            steps = [("Stopping the database", [self.launcher, "stop"]),
                     ("Starting the database", [self.launcher, "start"])]
        env = dict(os.environ, EXAKIT_STOP_ADDONS="1")
        for label, cmd in steps:
            say(label)
            try:
                p = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
            except (OSError, subprocess.TimeoutExpired) as e:
                raise RuntimeError_("%s failed: %s" % (label.lower(), e), "restart_failed")
            if p.returncode != 0:
                detail = _text(p.stderr or p.stdout)[-500:]
                if "database" in label:
                    raise RuntimeError_("%s failed: %s" % (label.lower(), detail), "restart_failed")
                # An add-on service that does not come back is worth a line,
                # not a failed connect: the database is up.
                say("%s did not succeed; start it with: exakit start %s" % (label, cmd[-1]))
            if label == "Starting the database":
                self._info = None
                wait_ready(deadline=t0 + timeout)
        return time.time() - t0

    # --- the sandbox DNS links (temporary workaround, see module doc) ---------------

    def _podman(self):
        if self.engine != "podman":
            return None
        exe = shutil.which("podman")
        if not exe and os.name == "nt":
            cand = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RedHat" / "Podman" / "podman.exe"
            exe = str(cand) if cand.exists() else None
        return exe

    def db_container(self):
        podman = self._podman()
        if not podman:
            return None
        want = "exasol-db-%s" % (self.deployment_id or "")
        p = _run([podman, "ps", "--format", "{{.Names}}"], timeout=30)
        names = [n.strip() for n in _text(p.stdout).splitlines() if n.strip()]
        if want in names:
            return want
        matches = [n for n in names if n.startswith("exasol-db-")]
        return matches[0] if len(matches) == 1 else None

    def can_link(self):
        """True when this machine can reach the database container (Windows
        and Linux with Podman). macOS runs it inside the launcher's VM."""
        return bool(self._podman() and self.db_container())

    def link_sandbox_dns(self):
        """Add /etc/resolv.conf -> /conf/resolv.conf and /etc/hosts ->
        /conf/hosts to every installed SLC in the running container.
        Idempotent; whether it took is judged from inside the sandbox
        (lifecycle.sandbox_dns_state), because only there do the links
        resolve - /conf exists in the sandbox, not in the container, and
        `podman cp` cannot export to a pipe on Windows anyway."""
        podman, ctr = self._podman(), self.db_container()
        if not (podman and ctr):
            raise RuntimeError_("the database container is not reachable from here", "unavailable")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name in ("resolv.conf", "hosts"):
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.SYMTYPE
                ti.linkname = "/conf/%s" % name
                ti.mtime = int(time.time())
                t.addfile(ti)
        payload = buf.getvalue()
        flavors = self.java_flavor_dirs()
        for flavor in flavors:
            _run([podman, "cp", "-", "%s:%s/etc/" % (ctr, flavor)], timeout=30, check=True,
                 input_bytes=payload)
        return flavors
