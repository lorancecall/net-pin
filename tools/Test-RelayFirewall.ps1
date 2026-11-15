# Administrator-only diagnostic. Creates DISABLED rules with unique names and removes
# only those rules in finally. Does not change net-pin config or active protection.
# Run on the affected machine, not on a machine where Keel controls networking.
# Example: .\tools\Test-RelayFirewall.ps1 -InterfaceAlias Ethernet -RelayHosts 192.168.50.5
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$InterfaceAlias,
    [Parameter(Mandatory=$true)][string[]]$RelayHosts
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this diagnostic in an administrator PowerShell window.'
}
$adapter = @(Get-NetAdapter -IncludeHidden | Where-Object Name -CEQ $InterfaceAlias)
if ($adapter.Count -ne 1) { throw 'InterfaceAlias must exactly match one existing adapter.' }
function IpNumber([string]$text) {
    $ip = [Net.IPAddress]::Parse($text)
    if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'IPv4 hosts only.' }
    $b = $ip.GetAddressBytes()
    if (-not ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168))) { throw 'Private hosts only.' }
    [uint64]$b[0]*16777216 + [uint64]$b[1]*65536 + [uint64]$b[2]*256 + $b[3]
}
function IpText([uint64]$n) { '{0}.{1}.{2}.{3}' -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255) }
$hostsSorted = @($RelayHosts | ForEach-Object { IpNumber $_ } | Sort-Object -Unique)
if (-not $hostsSorted.Count) { throw 'At least one host is required.' }
$old = [Collections.Generic.List[string]]::new()
$new = [Collections.Generic.List[string]]::new()
[uint64]$start = 0
foreach ($end in @($hostsSorted | ForEach-Object { $_ - 1 }) + @(4294967295)) {
    if ($start -le $end) {
        $old.Add("$(IpText $start)-$(IpText $end)")
        [uint64]$cursor = $start
        while ($cursor -le $end) {
            $bits = 0
            while ($bits -lt 32 -and ($cursor % [math]::Pow(2,$bits+1)) -eq 0 -and [math]::Pow(2,$bits+1) -le ($end-$cursor+1)) { $bits++ }
            $new.Add("$(IpText $cursor)/$(32-$bits)")
            $cursor += [uint64][math]::Pow(2,$bits)
        }
    }
    $start = [uint64]$end + 2
}
$old.Add('::/0'); $new.Add('::/1'); $new.Add('8000::/1')
$policy = New-Object -ComObject HNetCfg.FwPolicy2
foreach ($case in @(@{Label='v0.4.1 ranges';Value=($old -join ',')}, @{Label='candidate CIDRs';Value=($new -join ',')})) {
    $name = 'net-pin-disabled-diagnostic-' + [guid]::NewGuid().ToString()
    $added = $false
    try {
        $rule = New-Object -ComObject HNetCfg.FWRule
        $rule.Name = $name
        $rule.Grouping = 'net-pin diagnostics'
        $rule.Description = 'Disabled address-parser diagnostic; removed immediately.'
        $rule.ApplicationName = "$env:SystemRoot\System32\notepad.exe"
        $rule.Protocol = 256
        $rule.RemoteAddresses = $case.Value
        $rule.Direction = 2
        $rule.Action = 0
        $rule.Profiles = 2147483647
        $rule.Interfaces = @($InterfaceAlias)
        $rule.Enabled = $false
        $policy.Rules.Add($rule)
        $added = $true
        '{0}: ACCEPTED (disabled)' -f $case.Label
    } catch {
        '{0}: REJECTED: {1}' -f $case.Label, $_.Exception.Message
    } finally {
        if ($added) { $policy.Rules.Remove($name) }
    }
}
'Finished. No net-pin config or active firewall rules were changed.'
