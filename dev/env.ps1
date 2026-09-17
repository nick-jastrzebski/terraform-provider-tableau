# Dot-source from the repo root to set up a dev shell:
#
#   . .\dev\env.ps1
#
# Points Terraform at dev/dev.tfrc (so it uses the locally built provider),
# loads credentials from the repo-root .env file, then rebuilds the binary.
# Re-run `go build -o terraform-provider-tableau.exe .` after every code
# change - Terraform does not rebuild for you.
#
# Must be dot-sourced (note the leading ". "), otherwise the variables are set
# in a child scope and vanish when the script ends.

$repoRoot = Split-Path -Parent $PSScriptRoot
$env:TF_CLI_CONFIG_FILE = Join-Path $PSScriptRoot 'dev.tfrc'

# --- Load .env -------------------------------------------------------------
# Accepts KEY=value, KEY="value", KEY='value' and `export KEY=value` (the
# format of env.vars.example). Lines starting with # are comments. Values are
# taken literally - no $VAR expansion. .env is gitignored; never commit it.
$envFile = Join-Path $repoRoot '.env'
if (Test-Path $envFile) {
    $seen = @{}
    $lineNo = 0
    foreach ($line in Get-Content $envFile) {
        $lineNo++
        if ($line -match '^\s*(#|$)') { continue }
        if ($line -notmatch '^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') {
            Write-Warning ".env line ${lineNo}: could not parse, skipped"
            continue
        }
        $key = $matches[1]
        $value = $matches[2]
        if ($value -match '^"(.*)"$' -or $value -match "^'(.*)'$") { $value = $matches[1] }

        if ($seen.ContainsKey($key)) {
            Write-Warning ".env line ${lineNo}: $key already set on line $($seen[$key]) - this later value wins"
        }
        $seen[$key] = $lineNo
        Set-Item -Path "env:$key" -Value $value
    }
    # Print names only, so secrets never end up in terminal scrollback.
    Write-Host "Loaded from .env: $($seen.Keys -join ', ')"

    $required = 'TABLEAU_SERVER_URL', 'TABLEAU_SERVER_VERSION', 'TABLEAU_SITE_NAME'
    foreach ($name in $required) {
        if (-not (Get-Item "env:$name" -ErrorAction SilentlyContinue).Value) {
            Write-Warning "$name is not set - the provider will refuse to configure"
        }
    }
}
else {
    Write-Host 'No .env file found - using whatever is already in the environment'
}

# Provider debug logs; set to 'DEBUG' or 'TRACE' when chasing a problem.
$env:TF_LOG = ''

Write-Host "TF_CLI_CONFIG_FILE = $env:TF_CLI_CONFIG_FILE"
Write-Host 'Building provider...'
Push-Location $repoRoot
try {
    go build -o terraform-provider-tableau.exe .
    if ($LASTEXITCODE -eq 0) { Write-Host 'Build OK' -ForegroundColor Green }
    else { Write-Host 'Build FAILED' -ForegroundColor Red }
}
finally {
    Pop-Location
}
