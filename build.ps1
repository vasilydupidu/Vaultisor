#Requires -Version 5.1
# =============================================================================
# Vaultisor build script (Windows portable .exe).
#
# Steps:
#   1) Verify Node.js, Rust, Cargo are installed.
#   2) Install npm dependencies (unless -SkipDeps).
#   3) Build frontend (Vite -> dist/).
#   4) Build Tauri release (-> src-tauri/target/release/vaultisor.exe).
#   5) Copy the result to .\release\Vaultisor.exe.
#
# Usage:
#   PS> .\build.ps1
#   PS> .\build.ps1 -SkipDeps
#   PS> .\build.ps1 -Clean
#
# Note: kept ASCII-only on purpose. Windows PowerShell 5.1 reads .ps1 files
# without a BOM as ANSI; non-ASCII characters break the parser. Comments and
# user-facing messages are English to be safe across locales.
# =============================================================================

[CmdletBinding()]
param(
    [switch]$SkipDeps,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Bypass Tauri CLI dependency version checks during build
$env:TAURI_SKIP_DEPS_CHECK = "true"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-Tool {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [string]$Hint = ""
    )
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "Tool not found: '$Name'. $Hint"
    }
    Write-Host "  OK: $Name found at $($cmd.Source)"
}

# ----- Pre-flight checks -----
Write-Step "Checking required tools"
Assert-Tool -Name "node"  -Hint "Install Node.js 20+ from https://nodejs.org/"
Assert-Tool -Name "npm"   -Hint "Comes with Node.js."
Assert-Tool -Name "cargo" -Hint "Install Rust via https://rustup.rs/"
Assert-Tool -Name "rustc"
# SQLCipher uses vendored OpenSSL which requires Perl + NASM at build time.
Assert-Tool -Name "perl"  -Hint "Install Strawberry Perl Portable from https://strawberryperl.com/ and add C:\strawberry\perl\bin + C:\strawberry\c\bin to PATH."
Assert-Tool -Name "nasm"  -Hint "Install NASM from https://www.nasm.us/ and add to PATH (e.g. C:\nasm)."

# ----- Optional clean -----
if ($Clean) {
    Write-Step "Cleaning build artifacts"
    foreach ($p in @("dist", "src-tauri\target", "node_modules\.vite", "release")) {
        if (Test-Path $p) {
            Write-Host "  rm $p"
            Remove-Item -Recurse -Force $p
        }
    }
}

# ----- npm install -----
if (-not $SkipDeps) {
    Write-Step "Installing npm dependencies"
    npm install --no-fund
    if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)" }
    Write-Step "Running npm audit"
    npm audit --omit=dev 2>&1 | Write-Host
    # Non-zero exit from audit is advisory, not fatal.
}

# ----- Frontend build -----
Write-Step "Building frontend (Vite)"
npm run build
if ($LASTEXITCODE -ne 0) { throw "vite build failed (exit $LASTEXITCODE)" }

# ----- Tauri build -----
Write-Step "Building Tauri (release)"
# We attempt --no-bundle first to skip MSI/NSIS generation and produce a single
# .exe. If the installed Tauri CLI does not support that flag, fall back to a
# full build and pick up the .exe from the target dir.
$tauriOk = $false
try {
    npm run tauri:build -- --no-bundle --ignore-version-mismatches
    if ($LASTEXITCODE -eq 0) { $tauriOk = $true }
} catch {
    Write-Host "  --no-bundle not supported, falling back to full build" -ForegroundColor Yellow
}
if (-not $tauriOk) {
    npm run tauri:build -- --ignore-version-mismatches
    if ($LASTEXITCODE -ne 0) { throw "tauri build failed (exit $LASTEXITCODE)" }
}

# ----- Collect artifact -----
Write-Step "Collecting portable .exe"
$exeSrc = Join-Path "target\release" "vaultisor.exe"
if (-not (Test-Path $exeSrc)) {
    throw "Built .exe not found at: $exeSrc"
}

$releaseDir = "release"
if (-not (Test-Path $releaseDir)) {
    New-Item -ItemType Directory -Path $releaseDir | Out-Null
}

$exeDst = Join-Path $releaseDir "Vaultisor.exe"
Copy-Item -Force $exeSrc $exeDst

$size = (Get-Item $exeDst).Length / 1MB
Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host "  Artifact: $exeDst"
Write-Host ("  Size: {0:N2} MB" -f $size)
Write-Host ""
Write-Host "Vaultisor.exe is portable. First launch creates data in %APPDATA%\Vaultisor." -ForegroundColor Green
