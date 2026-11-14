# Builds net-pin.exe and net-pin-tray.exe, runs tests, and builds the installer into dist.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
# Cargo's encoded form preserves flags containing spaces. Keep the caller's precedence:
# encoded flags win over RUSTFLAGS; otherwise Cargo splits RUSTFLAGS on whitespace.
$oldEncoded = [Environment]::GetEnvironmentVariable('CARGO_ENCODED_RUSTFLAGS', 'Process')
$flags = @()
if ($null -ne $oldEncoded) {
    if ($oldEncoded.Length -gt 0) { $flags += $oldEncoded.Split([char]31) }
} elseif ($env:RUSTFLAGS) {
    $flags += @($env:RUSTFLAGS -split '\s+' | Where-Object { $_ })
}
if ($env:USERPROFILE) {
    $flags += "--remap-path-prefix=$($env:USERPROFILE)=/build/user"
    $flags += "--remap-path-prefix=$($env:USERPROFILE.Replace('\', '/'))=/build/user"
}
$flags += "--remap-path-prefix=$PSScriptRoot=/build/net-pin"
$flags += "--remap-path-prefix=$($PSScriptRoot.Replace('\', '/'))=/build/net-pin"
try {
    $env:CARGO_ENCODED_RUSTFLAGS = $flags -join [char]31
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    cargo test --release
    if ($LASTEXITCODE -ne 0) { throw 'cargo test failed' }
    & "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" /Q installer\net-pin.iss
    if ($LASTEXITCODE -ne 0) { throw 'ISCC failed' }
    Get-ChildItem dist\*.exe | ForEach-Object { '{0}  {1:N1} MB' -f $_.Name, ($_.Length / 1MB) }
} finally {
    if ($null -eq $oldEncoded) {
        Remove-Item Env:\CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue
    } else {
        [Environment]::SetEnvironmentVariable('CARGO_ENCODED_RUSTFLAGS', $oldEncoded, 'Process')
    }
}