#!/usr/bin/env bash
# virtual-schemas.sh — virtual-schemas (external databases as virtual
# schemas): the bridge from `exakit connect` / `exakit source` to the engine.
#
# A MARKETPLACE ADD-ON: never installed by the setup scripts.
#
# All logic lives in ONE Python engine (setup/virtual-schemas/engine), shared
# with the PowerShell twin; this file only finds the kit-managed Python - the
# pyexasol venv, the same interpreter the kit already validates against the
# database - and runs the engine with it. Nothing is pip-installed for this
# add-on, and nothing here knows about any particular source type: those are
# setup/virtual-schemas/connectors/<id>/connector.json.
#
# Secrets: the engine reads the source password from a hidden prompt,
# --password-file, --password-stdin or EXAKIT_VS_PASSWORD_FILE. It is never
# an argument, never in a file the kit writes, never in a log.

EXAKIT_VIRTUAL_SCHEMAS_VERSION="${EXAKIT_VIRTUAL_SCHEMAS_VERSION:-}"
EXAKIT_VIRTUAL_SCHEMAS_VERSION_FALLBACK="${EXAKIT_VIRTUAL_SCHEMAS_VERSION_FALLBACK:-0.1.0}"

_VS_MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"

# virtual_schemas_engine — the engine's entry script, from this kit copy.
virtual_schemas_engine() {
    _vse="$_VS_MODULE_DIR/../virtual-schemas/exakit_vs.py"
    [ -f "$_vse" ] || return 1
    printf '%s\n' "$_vse"
}

# virtual_schemas_python — the interpreter the engine runs on. The pyexasol
# venv is a kit component with its own repair command, so a missing one is
# answered with that command rather than with an attempt to build a second
# environment here.
virtual_schemas_python() {
    if command -v pyexasol_venv_python >/dev/null 2>&1; then
        _vsp="$(pyexasol_venv_python)"
    else
        _vsp="$EXAKIT_HOME/pyexasol-venv/bin/python"
    fi
    [ -x "$_vsp" ] || return 1
    printf '%s\n' "$_vsp"
}

# virtual_schemas_run <engine args...> — run the engine; its exit code is the
# command's (0 ok, 1 failed, 2 bad input, 3 database not running, 4 not
# installed, 5 not confirmed).
virtual_schemas_run() {
    _vsr_engine="$(virtual_schemas_engine)" || \
        reject "This kit copy does not carry the virtual-schemas engine. Update the kit first: exakit update"
    _vsr_python="$(virtual_schemas_python)" || {
        if [ "${EXAKIT_REFUSAL_JSON:-0}" = "1" ]; then
            exakit_json_out '{"ok": false, "status": "failed", "error": "%s", "remedy": "exakit update", "remedy_hint": "%s"}\n' \
                "$(_exakit_json_string "The kit's Python environment (pyexasol) is not installed.")" \
                "$(_exakit_json_string "Virtual schemas run on the pyexasol venv; exakit update repairs it.")"
            exit 1
        fi
        error "Virtual schemas need the kit's Python environment (pyexasol), which is not installed."
        info "Repair it with: exakit update"
        exit 1
    }
    # -I: isolated mode. No PYTHONPATH, no user site-packages, no current
    # directory on the import path - only the engine's own folder and the venv.
    EXAKIT_HOME="$EXAKIT_HOME" \
    EXAKIT_VS_EXAKIT="${EXAKIT_BIN_DIR:-$HOME/.local/bin}/exakit" \
        "$_vsr_python" -I "$_vsr_engine" "$@"
}

# virtual_schemas_post_start — after every database start. Each start creates
# a new database container, which drops the name-resolution links the engine
# adds to the Java sandbox (see engine/runtime.py); this puts them back.
# Quiet and best-effort: a start never fails because of it, and a machine
# with no sources does nothing at all.
virtual_schemas_post_start() {
    ls "$EXAKIT_HOME/sources"/*/config.json >/dev/null 2>&1 || return 0
    # A SUBSHELL, not just `|| true`: virtual_schemas_run exits (reject, a
    # missing venv), and an exit in this shell would end `exakit start`
    # before the add-on services it still has to start.
    ( virtual_schemas_run hook post-start --json ) >> "${EXAKIT_LOG_FILE:-/dev/null}" 2>&1 || true
    return 0
}
