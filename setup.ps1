<#
.SYNOPSIS
    Bounty Mode -- Windows PowerShell launcher.

.DESCRIPTION
    One-click setup for Windows.  Thin wrapper: it finds a Python interpreter and
    hands over to `run.py`, which does the real work (install, ask for the
    OpenRouter key and your name, validate the key, write .env, start the UI).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File setup.ps1
.EXAMPLE
    .\setup.ps1 -NoInstall -NoLaunch     # configure only, do not start the UI
#>

[CmdletBinding()]
param(
    [switch]$NoInstall,
    [switch]$NoLaunch
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

function Find-Python {
    # Prefer the py launcher (it knows about every installed version), then
    # python3, then python.  `Get-Command` throws if nothing matches, so each
    # probe is guarded.
    foreach ($candidate in @('py', 'python3', 'python')) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

$python = Find-Python
if (-not $python) {
    Write-Host ''
    Write-Host '  Python was not found on this machine.' -ForegroundColor Red
    Write-Host '  Install Python 3.9 or newer from https://www.python.org/downloads/'
    Write-Host '  and tick "Add python.exe to PATH" during installation, then run this again.'
    Write-Host ''
    exit 1
}

$argsList = @()
if ($NoInstall) { $argsList += '--no-install' }
if ($NoLaunch)  { $argsList += '--no-launch' }

& $python 'run.py' @argsList
exit $LASTEXITCODE
