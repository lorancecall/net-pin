; Inno Setup script - build with .\build.ps1 (cargo build --release, tests, then ISCC.exe installer\net-pin.iss)
#define AppVersion "0.3.0"

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
Name: "tailscalewifi"; Description: "Keep Tailscale on Wi-Fi only (locked kill switch) and send general internet over the wired LAN"; Flags: unchecked

[Files]
Source: "..\target\release\net-pin.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\net-pin-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
; Keel detects net-pin by this file (its network feature then waits); it forwards to net-pin.exe.
Source: "..\netpin.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

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

{ Keel's network feature runs the same engine: only one of them may manage the network.
  Mirrors keel.rs: the Keel service is installed and service.toml does not say net = false,
  or Keel's recorded network changes (net-state.json) are still in place. }
function KeelHasNetwork(var Why: String): Boolean;
var Lines: TArrayOfString; I: Integer; S, Dir: String; NetOn: Boolean;
begin
  Result := False;
  if not RegKeyExists(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\Keel') then exit;
  Dir := ExpandConstant('{commonappdata}\keel');
  NetOn := True;
  if LoadStringsFromFile(Dir + '\service.toml', Lines) then
    for I := 0 to GetArrayLength(Lines) - 1 do begin
      S := Lowercase(Lines[I]);
      StringChangeEx(S, ' ', '', True);
      StringChangeEx(S, #9, '', True);
      if S = 'net=false' then NetOn := False;
    end;
  if NetOn then begin
    Why := 'Keel''s network feature is on. In an admin console run "keel feature net off", then "keel net undo", and run this setup again.';
    Result := True;
  end else if FileExists(Dir + '\net-state.json') then begin
    Why := 'Keel''s network changes are still in place. In an admin console run "keel net undo", and run this setup again.';
    Result := True;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var rc: Integer; Why: String;
begin
  Result := '';
  if KeelHasNetwork(Why) then begin Result := Why; exit; end;
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
    WizardForm.StatusLabel.Caption := 'Starting the net-pin service...';
    if RunNetPin('service install', 'starting the service') and WizardIsTaskSelected('tailscalewifi') then
      RunNetPin('preset tailscale-wifi', 'applying the tailscale-wifi preset');
  end;
  if CurStep = ssDone then
    MsgBox('net-pin is installed. Open a new terminal for the net-pin command: net-pin status, net-pin help.' + #13#10#13#10 +
           'If you keep Wi-Fi beside Ethernet (net-pin set keep-connected on, or the Tailscale preset), reboot once.', mbInformation, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then RemovePath(ExpandConstant('{app}'));
end;
