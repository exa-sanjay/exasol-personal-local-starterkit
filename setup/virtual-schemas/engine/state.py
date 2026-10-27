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
# taken over rather than wedging every later run.

class Lock:
    def __init__(self, path=None):
        self.path = Path(path or (sources_dir() / ".lock"))

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + 30
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
                    raise StateError(
                        "another exakit connect/source command is running (lock: %s)" % self.path)
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
    if value and len(value) >= 3 and value not in _SECRETS:
        _SECRETS.append(value)


_PATTERNS = [
    (re.compile(r"(IDENTIFIED\s+BY\s+)'(?:[^']|'')*'", re.I), r"\1'***'"),
    (re.compile(r"([?&;](?:password|pwd|sslpassword|token)=)[^&;\s']*", re.I), r"\1***"),
    (re.compile(r"(://[^/:@\s]+:)[^@/\s]+@"), r"\1***@"),
]


def redact(text):
    if text is None:
        return text
    text = str(text)
    for pat, rep in _PATTERNS:
        text = pat.sub(rep, text)
    for s in _SECRETS:
        text = text.replace(s, "***")
    return text


class Log:
    def __init__(self):
        d = kit_home() / "logs"
        try:
            d.mkdir(parents=True, exist_ok=True)
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            self.path = d / ("virtual-schemas-%s.log" % stamp)
            self._f = open(self.path, "a", encoding="utf-8", newline="\n")
        except OSError:
            self.path, self._f = None, None

    def write(self, level, text):
        if not self._f:
            return
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for line in redact(text).splitlines() or [""]:
            self._f.write("%s %-5s %s\n" % (ts, level, line))
        self._f.flush()


LOG = None


def log(level, text):
    global LOG
    if LOG is None:
        LOG = Log()
    LOG.write(level, text)
