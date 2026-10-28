# virtual-schemas.ps1 - virtual schemas (external databases queried live from
# Exasol): Windows counterpart of virtual-schemas.sh, the bridge from
# `exakit connect` / `exakit source` to the engine.
#
# Part of the kit itself, not a marketplace add-on: nothing to install. The
# engine ships with every kit copy (setup\virtual-schemas) and runs on the
# kit's own Python - the pyexasol venv. Adapters and JDBC drivers are fetched
# per source, by the engine, on demand, and the database's Java runtime is
# installed on the first connect (one restart, asked first).
#
# Secrets: the engine reads the source password from a hidden prompt,
# --password-file, --password-stdin or EXAKIT_VS_PASSWORD_FILE. It is never an
# argument, never in a file the kit writes, never in a log.

$script:VirtualSchemasHome = if ($env:EXAKIT_VIRTUAL_SCHEMAS_HOME) { $env:EXAKIT_VIRTUAL_SCHEMAS_HOME } else { Join-Path $script:ExakitHome "sources" }

# The engine's entry script, from this kit copy; $null when absent.
function Get-VirtualSchemasEngine {
    $engine = Join-Path (Split-Path -Parent $PSScriptRoot) "virtual-schemas\exakit_vs.py"
    if (Test-Path $engine) { return $engine }
    return $null
}

# The interpreter the engine runs on: the pyexasol venv, a kit component with
# its own repair command (exakit update). $null when it is missing.
function Get-VirtualSchemasPython {
    if (Get-Command Get-PyexasolVenvPython -ErrorAction SilentlyContinue) {
        $python = Get-PyexasolVenvPython
    } else {
        $python = Join-Path $script:ExakitHome "pyexasol-venv\Scripts\python.exe"
    }
    if (Test-Path $python) { return $python }
    return $null
}

function Test-VirtualSchemasHasSources {
    if (-not (Test-Path $script:VirtualSchemasHome)) { return $false }
    return [bool](Get-ChildItem -Path $script:VirtualSchemasHome -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName "config.json") } | Select-Object -First 1)
}

# Run the engine with the caller's console attached (it may ask questions,
# the password hidden). Its exit code lands in $script:VirtualSchemasExitCode
# rather than in this function's output, which would capture the engine's
# printed lines along with it: 0 ok, 1 failed, 2 bad input, 3 database not
# running, 4 not installed, 5 not confirmed.
$script:VirtualSchemasExitCode = 0
function Invoke-VirtualSchemasEngine {
    param([string[]]$Arguments = @())
    $engine = Get-VirtualSchemasEngine
    if (-not $engine) {
        Deny-ExakitInput "This kit copy does not carry the virtual-schemas engine. Update the kit first: exakit update"
    }
    $python = Get-VirtualSchemasPython
    if (-not $python) {
        if ($Arguments -contains "--json" -or $Arguments -contains "-j") {
            $answer = [ordered]@{
                ok = $false; status = "failed"
                error = "The kit's Python environment (pyexasol) is not installed."
                remedy = "exakit update"
                remedy_hint = "Virtual schemas run on the pyexasol venv; exakit update repairs it."
            }
            [Console]::Out.WriteLine(($answer | ConvertTo-Json -Compress))
            $script:VirtualSchemasExitCode = 1
            return
        }
        Write-ExakitError "Virtual schemas need the kit's Python environment (pyexasol), which is not installed."
        Info "Repair it with: exakit update"
        $script:VirtualSchemasExitCode = 1
        return
    }
    $prevHome = $env:EXAKIT_HOME
    $prevCli = $env:EXAKIT_VS_EXAKIT
    try {
        $env:EXAKIT_HOME = $script:ExakitHome
        $env:EXAKIT_VS_EXAKIT = Join-Path $script:BinDir "exakit.cmd"
        # -I: isolated mode. No PYTHONPATH, no user site-packages, no current
        # directory on the import path - only the engine's own folder and the venv.
        & $python -I $engine @Arguments
        $script:VirtualSchemasExitCode = $LASTEXITCODE
    } finally {
        $env:EXAKIT_HOME = $prevHome
        $env:EXAKIT_VS_EXAKIT = $prevCli
    }
}

# After every database start. Each start creates a new database container,
# which drops the name-resolution links the engine adds to the Java sandbox
# (see engine\runtime.py); this puts them back. Quiet and best-effort: a start
# never fails because of it, and a machine with no sources does nothing.
# Twin of virtual_schemas_post_start.
function Invoke-VirtualSchemasPostStart {
    if (-not (Test-VirtualSchemasHasSources)) { return }
    try {
        $out = (Invoke-VirtualSchemasEngine -Arguments @("hook", "post-start", "--json") 2>&1 | Out-String -Width 4096).Trim()
        Write-ExakitLog "INFO" "virtual-schemas post-start: $out"
    } catch {
        Write-ExakitLog "WARN" "virtual-schemas post-start: $_"
    }
}
