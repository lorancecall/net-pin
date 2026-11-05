<#
.SYNOPSIS
  Forwards to net-pin.exe in the same folder (net-pin help).

.DESCRIPTION
  Keel, a tool with a network feature of its own, detects an installed net-pin by this file and
  then leaves the network alone (see src/keel.rs). The commands install / reconcile map to
  apply, uninstall to service uninstall.

  Must stay compatible with Windows PowerShell 5.1.
#>
param(
    [Parameter(Position = 0)]
    [string]$Command = 'status',
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Rest = @()
)

$Version = '0.3.0'
$exe = Join-Path $PSScriptRoot 'net-pin.exe'
if (-not (Test-Path $exe)) { Write-Error "net-pin.exe not found next to netpin.ps1 ($PSScriptRoot)"; exit 1 }
$argv = @(switch ($Command) {
    'install'   { @('apply') }
    'reconcile' { @('apply') }
    'uninstall' { @('service', 'uninstall') }
    default     { @($Command) + @($Rest) }
})
& $exe @argv
exit $LASTEXITCODE
