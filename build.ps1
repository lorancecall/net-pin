# Builds net-pin.exe and net-pin-tray.exe, runs the tests, and builds the installer into dist\.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
cargo build --release
if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
cargo test --release
if ($LASTEXITCODE -ne 0) { throw 'cargo test failed' }
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" /Q installer\net-pin.iss
if ($LASTEXITCODE -ne 0) { throw 'ISCC failed' }
Get-ChildItem dist\*.exe | ForEach-Object { '{0}  {1:N1} MB' -f $_.Name, ($_.Length / 1MB) }
