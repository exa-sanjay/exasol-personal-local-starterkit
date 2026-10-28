"""Terminal output in the kit's look.

A third close twin of setup/lib/ui.sh and ui.ps1, kept deliberately small: the
palette, the glyphs and the four indents the kit's screens are built from
(step at 2, action at 4, outcome at 6, panel lines at 2). When a glyph or a
colour changes there, change it here too - UiTwin in
tests/virtual-schemas/test_engine.py compares the glyphs against ui.sh.

In --json mode nothing here writes to stdout: the one JSON object is the whole
answer there, so human lines go to stderr (or nowhere, when quiet).
"""

import os
import sys


def _fancy(stream):
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if os.environ.get("EXAKIT_NO_FANCY", "0") == "1":
        return False
    if os.name == "nt":
        # The PowerShell bridge switches the console to UTF-8 and VT mode
        # before it starts us (Initialize-ExakitConsole), which is what the
        # locale check below stands for on unix.
        return True
    loc = os.environ.get("LC_ALL") or os.environ.get("LC_CTYPE") or os.environ.get("LANG") or ""
    return "utf" in loc.lower()


class UI:
    def __init__(self, json_mode=False, quiet=False):
        self.json_mode = json_mode
        self.quiet = quiet
        self.out = sys.stderr if json_mode else sys.stdout
        fancy = (not quiet) and _fancy(self.out)
        self.fancy = fancy
        if fancy:
            self.RESET, self.BOLD, self.DIM = "\033[0m", "\033[1m", "\033[2m"
            self.ACCENT = "\033[38;5;35m"
            self.OK, self.WARN, self.ERR = "\033[1;32m", "\033[1;33m", "\033[1;31m"
            self.INFO, self.ASK = "\033[1;34m", "\033[1;36m"
            self.TICK, self.CROSS, self.BULLET, self.ARROW = "✓", "✗", "•", "▸"
            self.HR, self.TL, self.TR, self.BL, self.BR, self.VB = "─", "╭", "╮", "╰", "╯", "│"
        else:
            self.RESET = self.BOLD = self.DIM = self.ACCENT = ""
            self.OK = self.WARN = self.ERR = self.INFO = self.ASK = ""
            self.TICK, self.CROSS, self.BULLET, self.ARROW = "[ok]", "[x]", "-", ">"
            self.HR, self.TL, self.TR, self.BL, self.BR, self.VB = "-", "+", "+", "+", "+", "|"
        if not fancy and not json_mode:
            # A pipe on Windows defaults to the ANSI codepage; the plain glyphs
            # above are ASCII, but user data (names, hosts) may not be.
            try:
                self.out.reconfigure(errors="replace")
            except (AttributeError, ValueError):
                pass

    def _p(self, text, err=False):
        if self.quiet:
            return
        print(text, file=sys.stderr if err else self.out, flush=True)

    # The four lines every kit screen is made of.
    def step(self, text):
        self._p("  %s%s%s %s" % (self.OK, self.ARROW, self.RESET, text))

    def info(self, text):
        self._p("    %s%s%s %s" % (self.DIM, self.BULLET, self.RESET, text))

    def ok(self, text):
        self._p("      %s%s%s %s" % (self.OK, self.TICK, self.RESET, text))

    # Warnings and errors go to stderr, as common.sh's warn/error do, so a
    # caller capturing stdout gets the result without the noise.
    def warn(self, text):
        self._p("      %s!%s %s" % (self.WARN, self.RESET, text), err=True)

    def error(self, text):
        self._p("      %s%s%s %s" % (self.ERR, self.CROSS, self.RESET, text), err=True)

    def done(self, text):
        self._p("  %s%s%s %s%s%s" % (self.OK, self.TICK, self.RESET, self.BOLD, text, self.RESET))

    def fail(self, text):
        self._p("\n  %s%s %s%s%s" % (self.ERR, self.CROSS, self.BOLD, text, self.RESET), err=True)

    def blank(self):
        self._p("")

    def panel(self, title, rows):
        """rows: list of (label, value); a box like ui_panel_* draws."""
        if self.quiet:
            return
        lw = max([len(r[0]) for r in rows] + [0])
        lines = ["%-*s  %s" % (lw, k, v) for k, v in rows]
        width = max([len(l) for l in lines] + [len(title) + 4])
        top = "  %s%s %s %s%s" % (self.TL, self.HR, title, self.HR * (width - len(title) - 1), self.TR)
        self._p(top)
        for l in lines:
            self._p("  %s %s%s %s" % (self.VB, l, " " * (width - len(l)), self.VB))
        self._p("  %s%s%s" % (self.BL, self.HR * (width + 2), self.BR))

    def table(self, headers, rows):
        if self.quiet:
            return
        widths = [len(h) for h in headers]
        for r in rows:
            for i, c in enumerate(r):
                widths[i] = max(widths[i], len(str(c)))
        fmt = "  " + "  ".join("%%-%ds" % w for w in widths)
        self._p(self.DIM + (fmt % tuple(headers)).rstrip() + self.RESET)
        for r in rows:
            self._p((fmt % tuple(str(c) for c in r)).rstrip())

    # --- questions ----------------------------------------------------------
    # Asked on the controlling terminal only; callers check interactive()
    # first and fall back to an environment answer or a refusal.

    def ask(self, question, default=""):
        hint = " %s[%s]%s" % (self.DIM, default, self.RESET) if default else ""
        sys.stderr.write("    %s?%s %s%s " % (self.ASK, self.RESET, question, hint))
        sys.stderr.flush()
        try:
            answer = sys.stdin.readline()
        except KeyboardInterrupt:
            raise SystemExit(130)
        if answer == "":
            raise SystemExit(130)
        answer = answer.strip()
        return answer or default

    def ask_secret(self, question):
        import getpass

        try:
            return getpass.getpass("    %s?%s %s " % (self.ASK, self.RESET, question))
        except (KeyboardInterrupt, EOFError):
            raise SystemExit(130)

    def confirm(self, question, default=False):
        hint = "[Y/n]" if default else "[y/N]"
        answer = self.ask("%s %s" % (question, hint)).lower()
        if not answer:
            return default
        return answer in ("y", "yes")

    def choose(self, question, options, default_index=0):
        """options: list of (value, label). Returns the chosen value."""
        self.info(question)
        for i, (_, label) in enumerate(options, 1):
            self._p("      %s%d.%s %s" % (self.ACCENT, i, self.RESET, label))
        while True:
            raw = self.ask("Choose", str(default_index + 1))
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return options[int(raw) - 1][0]
            for value, label in options:
                if raw.lower() in (str(value).lower(), label.lower()):
                    return value
            self.warn("Pick a number from the list.")


def interactive():
    """A question may be asked. Never under --json (Ctx sets the variable):
    a JSON caller is a program, and a prompt it cannot see would hang it."""
    try:
        return sys.stdin.isatty() and os.environ.get("EXAKIT_VS_NONINTERACTIVE", "0") != "1"
    except (AttributeError, ValueError):
        return False
