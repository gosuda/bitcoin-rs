# Install the pinned Bitcoin Core bitcoind used by the live differential —
# the native-Windows entry point mirroring install-bitcoind.sh.
#
# Reads the win64 artifact pins from crates/rpc/core-compat.toml (the
# canonical pin site), downloads the official release zip, checks its
# SHA-256, and extracts bitcoind.exe. Prints the binary path on stdout
# (log lines go to stderr).
#
#   scripts/install-bitcoind.ps1 -PrintPath
#   iex "$(scripts/install-bitcoind.ps1 -Export)"   # sets $env:BITCOIND_COMMAND
#
# Owner: docs/contracts/core-differential.md (CORE-01).

[CmdletBinding()]
param(
    [switch]$PrintPath,
    [switch]$Export,
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Help) {
    [Console]::Error.WriteLine('usage: scripts/install-bitcoind.ps1 [-PrintPath|-Export]')
    exit 0
}
if ($PrintPath -and $Export) {
    [Console]::Error.WriteLine('usage: scripts/install-bitcoind.ps1 [-PrintPath|-Export]')
    exit 2
}

function Log([string]$Message) {
    [Console]::Error.WriteLine("[install-bitcoind] $Message")
}

$root = Split-Path -Parent $PSScriptRoot
$compat = Get-Content -Raw (Join-Path $root 'crates/rpc/core-compat.toml')
function Pin([string]$Key) {
    $match = [regex]::Match($compat, "(?m)^$Key = `"([^`"]+)`"")
    if (-not $match.Success) {
        throw "core-compat.toml is missing a valid $Key pin"
    }
    $match.Groups[1].Value
}

$TARBALL       = Pin 'archive_win64'
$TARBALL_SHA256 = Pin 'archive_win64_sha256'
# The released version label is recovered from the win64 archive name: the
# TOML carries a separate development `core_version` (31.99.x) that must not
# leak into this script's paths.
$versionMatch = [regex]::Match($TARBALL, '^bitcoin-(.+)-win64\.zip$')
if (-not $versionMatch.Success) {
    throw "win64 archive pin '$TARBALL' does not carry a version label"
}
$CORE_VERSION = $versionMatch.Groups[1].Value
$TARBALL_URL   = "https://bitcoincore.org/bin/bitcoin-core-$CORE_VERSION/$TARBALL"
$PREFIX        = if ($env:BITCOIND_PREFIX) { $env:BITCOIND_PREFIX } else { Join-Path $HOME "bitcoin-core-$CORE_VERSION" }
$BITCOIND      = Join-Path $PREFIX 'bin\bitcoind.exe'
$CLI           = Join-Path $PREFIX 'bin\bitcoin-cli.exe'
$STAMP         = Join-Path $PREFIX '.bitcoin-rs-core-tarball-sha256'

# Component-exact match against the canonical pin, mirroring the bash
# installer and crates/p2p/tests/core_interop_live.rs version_is_pinned_line:
# "31.1" accepts 31.1(.N) but not 31.10(.N), 31.2(.N), or 30.1(.N).
function VersionMatchesPin {
    $out = & $BITCOIND -version 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $false }
    if ($out[0] -notmatch '(\d+(\.\d+)*)') { return $false }
    $parsed = $Matches[1] -split '\.'
    $pinned = $CORE_VERSION -split '\.'
    if ($parsed.Count -lt $pinned.Count) { return $false }
    for ($i = 0; $i -lt $pinned.Count; $i++) {
        if ($parsed[$i] -ne $pinned[$i]) { return $false }
    }
    return $true
}

$cached = (Test-Path $BITCOIND) -and (Test-Path $STAMP) -and
          ((Get-Content -Raw $STAMP).Trim() -eq $TARBALL_SHA256) -and
          (VersionMatchesPin)

if ($cached) {
    Log "already installed at $BITCOIND (tarball $TARBALL_SHA256)"
} else {
    if (Test-Path $BITCOIND) {
        Log "cached $BITCOIND is not the pinned Core $CORE_VERSION artifact; reinstalling"
    }
    Log "downloading $TARBALL_URL"
    $workdir = Join-Path ([IO.Path]::GetTempPath()) "bitcoind-install-$(New-Guid)"
    New-Item -ItemType Directory -Path $workdir | Out-Null
    try {
        $archive = Join-Path $workdir $TARBALL
        Invoke-WebRequest -Uri $TARBALL_URL -OutFile $archive -UseBasicParsing
        $got = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -ne $TARBALL_SHA256) {
            Log "ABORT: tarball sha256 $got != $TARBALL_SHA256"
            exit 1
        }
        Expand-Archive -Path $archive -DestinationPath $workdir -Force
        New-Item -ItemType Directory -Path (Join-Path $PREFIX 'bin') -Force | Out-Null
        Copy-Item (Join-Path $workdir "bitcoin-$CORE_VERSION\bin\bitcoind.exe") $BITCOIND -Force
        $cliExtracted = Join-Path $workdir "bitcoin-$CORE_VERSION\bin\bitcoin-cli.exe"
        if (Test-Path $cliExtracted) { Copy-Item $cliExtracted $CLI -Force }
        Set-Content -Path $STAMP -Value $TARBALL_SHA256 -NoNewline
        Log "installed $BITCOIND"
    } finally {
        Remove-Item -Recurse -Force $workdir -ErrorAction SilentlyContinue
    }
}

if ($Export) {
    # Emit a PowerShell assignment for `iex` — the counterpart of the bash
    # script's `export BITCOIND_COMMAND=...`.
    $escaped = $BITCOIND -replace "'", "''"
    Write-Output "`$env:BITCOIND_COMMAND = '$escaped'"
} else {
    Write-Output $BITCOIND
}
