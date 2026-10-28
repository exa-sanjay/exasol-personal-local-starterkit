"""Where the add-on keeps things, and how it writes them.

    <EXAKIT_HOME>/sources/<name>/config.json   non-secret inputs + object names
    <EXAKIT_HOME>/sources/<name>/state.json    pins, last check, outcome
    <EXAKIT_HOME>/sources/registry.json        which sources use which artifacts
    <EXAKIT_HOME>/cache/virtual-schemas/<sha256>/<file>
    <EXAKIT_HOME>/logs/virtual-schemas-<ts>.log

No secret is ever written here: a password lives only in the database's
CONNECTION object. Every JSON write goes to a temp file first and is renamed
into place, so an interrupted run never leaves half a file behind.
"""

import datetime
import json
import os
import re
import time
from pathlib import Path


def kit_home():
    env = os.environ.get("EXAKIT_HOME")
    return Path(env) if env else Path.home() / ".exasol-starter-kit"


def manifest_path():
    return kit_home() / "manifest.json"


def sources_dir():
    return kit_home() / "sources"


def source_dir(name):
    return sources_dir() / name.lower()


def registry_path():
    return sources_dir() / "registry.json"


def cache_dir():
    return kit_home() / "cache" / "virtual-schemas"


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except ValueError as e:
        raise StateError("%s is not valid JSON (%s); move it aside and re-run" % (path, e))


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp-%d" % os.getpid())
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


class StateError(Exception):
    pass


class Busy(StateError):
    """Another connect/source command holds the lock."""


def read_manifest():
    m = read_json(manifest_path())
    if m is None:
        raise NotInstalled("No installation found at %s" % kit_home())
    return m


class NotInstalled(Exception):
    pass


# --- per-deployment lock ------------------------------------------------------
# Two connects at once would race on the registry and on the jdbc/ folder.
# A lock file with our pid; a stale one (dead pid, or older than an hour) is
# taken over rather than wedging every later run. The wait is long because
# the holder may be inside the one database restart, which takes minutes the
# first time.

LOCK_WAIT = int(os.environ.get("EXAKIT_VS_LOCK_WAIT", "900"))


class Lock:
    def __init__(self, path=None, on_wait=None):
        self.path = Path(path or (sources_dir() / ".lock"))
        self.on_wait = on_wait

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + LOCK_WAIT
        told = False
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                if self._stale():
                    try:
                        os.unlink(self.path)
                    except FileNotFoundError:
                        pass
                    continue
                if time.time() > deadline:
                    raise Busy("another exakit connect or source command is still running")
                if not told and self.on_wait:
                    self.on_wait()
                    told = True
                time.sleep(0.5)

    def _stale(self):
        try:
            age = time.time() - self.path.stat().st_mtime
            pid = int(self.path.read_text().strip() or "0")
        except (OSError, ValueError):
            return True
        if age > 3600:
            return True
        return not _pid_alive(pid)

    def __exit__(self, *exc):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


def _pid_alive(pid):
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# --- log ------------------------------------------------------------------------
# Every line goes through the redactor first. The redactor knows the secrets
# of this run (registered as they are read) plus the generic shapes a password
# takes in SQL and URLs.

_SECRETS = []


def register_secret(value):
    """A source password (or one found in a pasted URL). Only these are
    redacted by value; the kit's own database password is never registered,
    because it is a common word on a fresh deployment and blanking it out of
    every path and package name gave it away instead of hiding it."""
    if value and len(value) >= 4 and value not in _SECRETS:
        _SECRETS.append(value)


_PATTERNS = [
    (re.compile(r"(IDENTIFIED\s+BY\s+)'(?:[^']|'')*'", re.I), r"\1'***'"),
    (re.compile(r"((?:[?&;]|%3B|%26|%3F)(?:password|pwd|sslpassword|token)(?:=|%3D))(?:(?!%26|%3B)[^&;\s'?])*",
                re.I), r"\1***"),
    (re.compile(r"(://[^/@\s]+:)[^@\s]+@"), r"\1***@"),
]


def redact(text):
    if text is None:
        return text
    text = str(text)
    for pat, rep in _PATTERNS:
        text = pat.sub(rep, text)
    for s in _SECRETS:
        # Whole occurrences only, so a secret that happens to be an ordinary
        # word does not turn every message containing that word into a riddle.
        text = re.sub(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(s), "***", text)
    return text


LOG_KEEP_DAYS = 14


class Log:
    """One file per day (virtual-schemas-YYYYMMDD.log), each line tagged with
    the process id, older files pruned. A file per invocation filled the logs
    folder with hundreds of files from status-like commands."""

    def __init__(self):
        d = kit_home() / "logs"
        try:
            d.mkdir(parents=True, exist_ok=True)
            self.path = d / ("virtual-schemas-%s.log" % datetime.date.today().strftime("%Y%m%d"))
            self._f = open(self.path, "a", encoding="utf-8", newline="\n")
        except OSError:
            self.path, self._f = None, None
            return
        cutoff = time.time() - LOG_KEEP_DAYS * 86400
        for old in d.glob("virtual-schemas-*.log"):
            try:
                if old.stat().st_mtime < cutoff:
                    old.unlink()
            except OSError:
                pass

    def write(self, level, text):
        if not self._f:
            return
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for line in redact(text).splitlines() or [""]:
            self._f.write("%s [%d] %-5s %s\n" % (ts, os.getpid(), level, line))
        self._f.flush()


LOG = None


def log(level, text):
    global LOG
    if LOG is None:
        LOG = Log()
    LOG.write(level, text)
