#Requires -Version 5.1
# =============================================================================
# Vaultisor build script (Windows portable .exe).
#
# Steps:
#   1) Verify Node.js, Rust, Cargo are installed.
#   2) Install npm dependencies (unless -SkipDeps).
#   3) Build frontend (Vite -> dist/).
#   4) Build Tauri release (-> target\release\vaultisor.exe).
#   5) Copy the result to .\release\Vaultisor-<version>.exe.
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
    # release\ is deliberately NOT cleaned: it may hold a portable vault
    # folder (release\vault) that belongs to the user. Only build output goes.
    foreach ($p in @("dist", "target", "node_modules\.vite")) {
        if (Test-Path $p) {
            Write-Host "  rm $p"
            Remove-Item -Recurse -Force $p
        }
    }
}

# ----- npm ci -----
# npm ci installs exactly package-lock.json and fails if it disagrees with
# package.json: the build never silently resolves a different dependency tree.
# Install scripts are skipped: the build needs none, and dependency code must
# not run on the machine that produces the release binary.
if (-not $SkipDeps) {
    Write-Step "Installing npm dependencies (npm ci)"
    npm ci --no-fund --ignore-scripts
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed (exit $LASTEXITCODE)" }
    Write-Step "Running npm audit"
    npm audit --audit-level=high --no-fund
    if ($LASTEXITCODE -ne 0) { throw "npm audit found high/critical vulnerabilities (exit $LASTEXITCODE)" }
}

# ----- Frontend build -----
Write-Step "Building frontend (Vite)"
npm run build
if ($LASTEXITCODE -ne 0) { throw "vite build failed (exit $LASTEXITCODE)" }

# ----- Tauri build -----
# A single portable .exe (no MSI/NSIS). Cargo runs with --locked: the build
# uses exactly Cargo.lock and fails instead of resolving new versions.
Write-Step "Building Tauri (release)"
npm run tauri:build -- --no-bundle --ignore-version-mismatches -- --locked
if ($LASTEXITCODE -ne 0) { throw "tauri build failed (exit $LASTEXITCODE)" }

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

# The artifact always carries its version. An unversioned copy next to it
# only invites running the wrong build and reporting the wrong logs.
$pkgJson = Get-Content "package.json" -Raw | ConvertFrom-Json
if (-not $pkgJson.version) {
    throw "package.json has no version field; refusing to produce an unnamed build"
}
# Only the current version may be in release/: the release workflow refuses to
# publish when it finds more than one executable.
Get-ChildItem $releaseDir -Filter "Vaultisor*.exe" | Remove-Item -Force
$exeDst = Join-Path $releaseDir "Vaultisor-$($pkgJson.version).exe"
Copy-Item -Force $exeSrc $exeDst

$size = (Get-Item $exeDst).Length / 1MB
Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host "  Artifact: $exeDst"
Write-Host ("  Size: {0:N2} MB" -f $size)
Write-Host ""
Write-Host "The .exe is portable: the vault folder is created next to it." -ForegroundColor Green
Write-Host "A small anti-rollback marker is also kept in %LOCALAPPDATA%\Vaultisor\SecurityCheckpoints." -ForegroundColor Yellow
