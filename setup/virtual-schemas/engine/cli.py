"""Command line: `exakit connect` and `exakit source ...` land here.

    connect [SOURCE] [--name N] [--url URL | --host H --port P --database D]
            [--user U] [--schema S] [--tls verify|encrypt|none]
            [--password-file PATH | --password-stdin] [--yes] [--dry-run] [--json]
    source list|show|check|reauth|refresh|remove NAME [--dry-run] [--yes] [--json]
    hook post-start

There is deliberately no --password option: a command line is readable by
every process on the machine.
"""

import argparse
import json
import sys

from . import artifacts, lifecycle, plan, runtime, sql, state


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _BadInput(message)


class _BadInput(Exception):
    pass


def _parser():
    p = _Parser(prog="exakit", add_help=True, allow_abbrev=False)
    p.add_argument("--json", "-j", action="store_true")
    sub = p.add_subparsers(dest="command", parser_class=_Parser)

    c = sub.add_parser("connect", help="connect an external database as a virtual schema", allow_abbrev=False)
    c.add_argument("source", nargs="?")
    c.add_argument("--name")
    c.add_argument("--url", help="the source's address instead of host/port/database: a JDBC URL, a postgres:// or mongodb[+srv]:// URI, a lakehouse catalog's http(s):// URL, or a bare host[:port][/database]")
    c.add_argument("--host")
    c.add_argument("--port")
    c.add_argument("--database")
    c.add_argument("--user")
    c.add_argument("--schema")
    c.add_argument("--tls", choices=["verify", "encrypt", "none"])
    c.add_argument("--password-file")
    c.add_argument("--password-stdin", action="store_true")
    c.add_argument("--yes", "-y", action="store_true")
    c.add_argument("--dry-run", action="store_true")
    c.add_argument("--json", "-j", action="store_true")

    s = sub.add_parser("source", help="list and manage connected sources", allow_abbrev=False)
    s.add_argument("--json", "-j", action="store_true")
    ss = s.add_subparsers(dest="action", parser_class=_Parser)
    lst = ss.add_parser("list", allow_abbrev=False)
    lst.add_argument("--json", "-j", action="store_true")
    for action in ("show", "check", "reauth", "refresh", "remove"):
        a = ss.add_parser(action, allow_abbrev=False)
        a.add_argument("name")
        a.add_argument("--json", "-j", action="store_true")
        if action == "reauth":
            a.add_argument("--user")
            a.add_argument("--password-file")
            a.add_argument("--password-stdin", action="store_true")
        if action == "remove":
            a.add_argument("--dry-run", action="store_true")
            a.add_argument("--yes", "-y", action="store_true")

    h = sub.add_parser("hook", allow_abbrev=False)
    h.add_argument("event", choices=["post-start"])
    h.add_argument("--json", "-j", action="store_true")
    return p


def _wants_json(argv):
    return any(a in ("--json", "-j") for a in argv)


def _emit(obj):
    sys.stdout.write(json.dumps(obj, sort_keys=True) + "\n")
    sys.stdout.flush()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = _wants_json(argv)
    if any(a == "--password" or a.startswith("--password=") for a in argv):
        return _refuse(as_json, "there is deliberately no --password option: a command line is readable by "
                                "every process on this machine. Use --password-file <path>, "
                                "--password-stdin, or the hidden prompt.")
    try:
        args = _parser().parse_args(argv)
    except _BadInput as e:
        return _refuse(as_json, str(e))
    if not args.command or (args.command == "source" and not args.action):
        return _refuse(as_json, "say what to do: connect, or source list|show|check|reauth|refresh|remove")

    code, result, ctx = 1, None, None
    try:
        ctx = lifecycle.Ctx(args)
        if args.command == "connect":
            code, result = lifecycle.connect(ctx)
        elif args.command == "hook":
            code, result = lifecycle.runtime_hook(ctx)
        else:
            fn = {"list": lifecycle.list_sources, "show": lifecycle.show, "check": lifecycle.check,
                  "reauth": lifecycle.reauth, "refresh": lifecycle.refresh,
                  "remove": lifecycle.remove}[args.action]
            code, result = fn(ctx)
    except lifecycle.Fail as f:
        code, result = f.code, _failure(f.code, str(f), f.remedy, f.hint, f.kind)
    except (plan.PlanError, ValueError) as e:
        code, result = 2, _failure(2, str(e))
    except artifacts.ArtifactError as e:
        if e.kind == "checksum":
            hint = ("Do not retry: a file that does not match its pin is a supply-chain alert. "
                    "Nothing was installed. Report it at "
                    "https://github.com/exasol-labs/exasol-personal-local-starterkit/issues")
        else:
            hint = "Nothing was installed. Check the network connection, then run the same command again."
        code, result = 1, _failure(1, str(e), None, hint, "artifact_" + e.kind)
    except runtime.RuntimeError_ as e:
        rc = 3 if e.kind in ("no_database",) else 1
        code, result = rc, _failure(rc, str(e), None, None, e.kind)
    except state.Busy as e:
        code, result = 1, _failure(1, str(e), None, "Wait for it to finish, then run this command again.",
                                   "busy")
    except state.StateError as e:
        code, result = 1, _failure(1, str(e), None, None, "state")
    except sql.SqlError as e:
        # A database statement failed outside the steps that classify their
        # own errors. Still an answer with a kind, never a traceback.
        code, result = 1, _failure(1, sql.short(str(e)), None,
                                   "Running the same command again picks up where this one stopped.", e.kind)
    except KeyboardInterrupt:
        code, result = 130, _failure(130, "interrupted")
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
        result = _failure(code, "stopped", None, None, "aborted")
    except Exception as e:  # the --json contract holds for the unexpected too
        import traceback
        state.log("ERROR", traceback.format_exc())
        code, result = 1, _failure(1, "unexpected error: %s: %s" % (type(e).__name__, state.redact(str(e))[:300]),
                                   None, "The details are in the log: %s" % (
                                       state.LOG.path if state.LOG and state.LOG.path else "~/.exasol-starter-kit/logs"),
                                   "internal")
    finally:
        if ctx is not None and ctx._db is not None:
            ctx._db.close()

    if result and not result.get("ok", True) and not as_json:
        ui = ctx.ui if ctx else None
        _print_failure(ui, result)
    if as_json and result is not None:
        _emit(result)
    if result is not None:
        state.log("EXIT", "%s %s" % (code, state.redact(json.dumps(result, sort_keys=True))[:2000]))
    return code


def _failure(code, message, remedy=None, hint=None, kind=None):
    status = {2: "rejected", 3: "stopped", 4: "not installed", 5: "declined"}.get(code, "failed")
    return {"ok": False, "status": status, "error": state.redact(message), "kind": kind,
            "remedy": remedy, "remedy_hint": state.redact(hint) if hint else None}


def _refuse(as_json, message):
    if as_json:
        _emit(dict(_failure(2, message), rejected=True))
    else:
        sys.stderr.write("\n  [x] %s\n" % message)
        sys.stderr.write("      Usage: exakit connect [source] | exakit source list|show|check|"
                         "reauth|refresh|remove <name>\n")
    return 2


def _print_failure(ui, result):
    if ui is None:
        sys.stderr.write("  [x] %s\n" % result["error"])
        if result.get("remedy"):
            sys.stderr.write("      Fix: %s\n" % result["remedy"])
        return
    ui.fail(result["error"])
    if result.get("remedy_hint"):
        ui.info(result["remedy_hint"])
    if result.get("remedy"):
        ui.info("Fix: %s" % result["remedy"])
    if state.LOG is not None and state.LOG.path:
        ui.info("Details: %s" % state.LOG.path)
