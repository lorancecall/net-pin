; Inno Setup script - build with .\build.ps1 (cargo build --release, tests, then ISCC.exe installer\net-pin.iss)
#define AppVersion "0.4.0"

[Setup]
AppId={{5E0B8C51-7A2E-4B8F-9C3D-6F1A2B4E8D70}
AppName=net-pin
AppVersion={#AppVersion}
AppPublisher=lorancecall
; The service runs only from C:\Program Files\net-pin, so the folder is fixed.
DefaultDirName={autopf}\net-pin
DisableDirPage=yes
DefaultGroupName=net-pin
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=net-pin-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
UninstallDisplayName=net-pin
WizardStyle=modern
SetupIconFile=..\assets\net-pin.ico
UninstallDisplayIcon={app}\net-pin.exe
; {app} goes on the system PATH (the net-pin command).
ChangesEnvironment=yes
; The tray's Run value is per user (the user running setup).
UsedUserAreasWarning=no

[Tasks]
; Optional memory feature (off unless chosen; remembered on upgrade). See net-pin ram help.
Name: "memory"; Description: "Memory: keep chosen app families off and record memory samples (net-pin ram)"; Flags: unchecked

[Files]
Source: "..\target\release\net-pin.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\net-pin-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[InstallDelete]
; Left by 0.3.0 installs.
Type: files; Name: "{app}\netpin.ps1"

[Icons]
Name: "{group}\net-pin"; Filename: "{app}\net-pin-tray.exe"
Name: "{group}\net-pin Status"; Filename: "{cmd}"; Parameters: "/k ""{app}\net-pin.exe"" status"; WorkingDir: "{app}"
Name: "{group}\Open net-pin Log"; Filename: "notepad.exe"; Parameters: """{commonappdata}\net-pin\net-pin.log"""
Name: "{group}\Uninstall net-pin"; Filename: "{uninstallexe}"

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "net-pin-tray"; ValueData: """{app}\net-pin-tray.exe"""; Flags: uninsdeletevalue

[Run]
; The tray in the user's own (un-elevated) session.
Filename: "{app}\net-pin-tray.exe"; Flags: runasoriginaluser nowait; StatusMsg: "Starting the tray..."

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM net-pin-tray.exe"; Flags: runhidden waituntilterminated; RunOnceId: "KillTray"
; Stops and removes the service and puts back the recorded values.
Filename: "{app}\net-pin.exe"; Parameters: "service uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "Restore"

[Code]
const
  EnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function NeedsAddPath(Dir: String): Boolean;
var Path: String;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvKey, 'Path', Path) then begin Result := True; exit; end;
  Result := Pos(';' + Lowercase(Dir) + ';', ';' + Lowercase(Path) + ';') = 0;
end;

procedure RemovePath(Dir: String);
var Path, Rest, Part, Kept: String; P: Integer;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, EnvKey, 'Path', Path) then exit;
  Rest := Path; Kept := '';
  while Rest <> '' do begin
    P := Pos(';', Rest);
    if P = 0 then begin Part := Rest; Rest := ''; end
    else begin Part := Copy(Rest, 1, P - 1); Delete(Rest, 1, P); end;
    if (Part <> '') and (CompareText(RemoveBackslashUnlessRoot(Part), RemoveBackslashUnlessRoot(Dir)) <> 0) then begin
      if Kept <> '' then Kept := Kept + ';';
      Kept := Kept + Part;
    end;
  end;
  if Kept <> Path then RegWriteExpandStringValue(HKEY_LOCAL_MACHINE, EnvKey, 'Path', Kept);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var rc: Integer;
begin
  Result := '';
  { upgrade: release the running tray and service exes }
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM net-pin-tray.exe', '', SW_HIDE, ewWaitUntilTerminated, rc);
  if FileExists(ExpandConstant('{app}\net-pin.exe')) then
    Exec(ExpandConstant('{app}\net-pin.exe'), 'service stop', '', SW_HIDE, ewWaitUntilTerminated, rc);
end;

{ Runs net-pin.exe with its output in setup.log; true on success. }
function RunNetPin(Params, What: String): Boolean;
var rc: Integer; Log: String;
begin
  Log := ExpandConstant('{commonappdata}\net-pin\setup.log');
  Result := Exec(ExpandConstant('{cmd}'), '/c ""' + ExpandConstant('{app}\net-pin.exe') + '" ' + Params + ' >> "' + Log + '" 2>&1"',
                 '', SW_HIDE, ewWaitUntilTerminated, rc) and (rc = 0);
  if not Result then
    MsgBox('net-pin: ' + What + ' failed. See ' + Log + '.', mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    ForceDirectories(ExpandConstant('{commonappdata}\net-pin'));
    { The memory switch is saved before the service starts (it reads it at start). }
    if WizardIsTaskSelected('memory') then
      RunNetPin('feature memory on', 'turning memory on')
    else if FileExists(ExpandConstant('{commonappdata}\net-pin\service.toml')) then
      RunNetPin('feature memory off', 'turning memory off');
    WizardForm.StatusLabel.Caption := 'Starting the net-pin service...';
    RunNetPin('service install', 'starting the service');
  end;
  if CurStep = ssDone then
    MsgBox('net-pin is installed. It changes nothing until you tell it what to pin.' + #13#10#13#10 +
           'Open a new terminal and run:' + #13#10 +
           '  net-pin status        what is pinned where' + #13#10 +
           '  net-pin help          all commands' + #13#10 +
           '  net-pin preset        ready-made setups for common cases' + #13#10 +
           '  net-pin ram help      memory: app families, leaks (net-pin feature memory on|off)', mbInformation, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then RemovePath(ExpandConstant('{app}'));
end;
