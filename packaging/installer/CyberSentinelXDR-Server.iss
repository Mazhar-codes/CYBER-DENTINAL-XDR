; ============================================================================
;  Cyber Sentinel XDR - SERVER Installer (Inno Setup 6)
;
;  Installs the central SOC server: the frozen backend.exe (with the dashboard
;  bundled inside it, served same-origin), the VC++ runtime, a firewall rule,
;  and a boot-time service. The endpoint agent has its own separate, lean
;  installer (CyberSentinelXDR.iss) - this one is large (~1 GB, torch).
;
;  PREREQUISITES before building:
;    1. Backend bundle built:  packaging\build_backend.ps1  ->  C:\csxb\dist\backend
;    2. Dashboard built:        npm run build  (bundled into backend.exe by the spec)
;    3. redist\vc_redist.x64.exe present (staged from the MS redistributable)
;
;  BUILD:
;    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" CyberSentinelXDR-Server.iss
;  Output: C:\csxb\installer_out\CyberSentinelXDR-Server-Setup-1.0.0.exe
;
;  NOTE: MongoDB is NOT bundled. The config page asks for MONGO_URI - default is
;  a local MongoDB (mongodb://localhost:27017, requires MongoDB installed on this
;  host), or paste a MongoDB Atlas SRV string to use the cloud.
; ============================================================================

#define MyAppName    "Cyber Sentinel XDR Server"
#define MyAppVersion "1.0.0"
#define MyPublisher  "Cyber Sentinel XDR"
#define BackendExe   "backend.exe"
#define TaskName     "CyberSentinelXDR Server"
#define ServerBundle "C:\csxb\dist\backend"

[Setup]
; Distinct AppId from the endpoint installer so the two coexist / upgrade independently.
AppId={{9C4B2E1F-7A83-4D26-B1E5-3F6A8C2D9E40}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyPublisher}
DefaultDirName={autopf}\Cyber Sentinel XDR Server
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=EULA.txt
WizardStyle=modern
; The bundle is ~1 GB (torch). lzma2/normal balances installer size vs build time.
Compression=lzma2/normal
SolidCompression=yes
OutputDir=C:\csxb\installer_out
OutputBaseFilename=CyberSentinelXDR-Server-Setup-{#MyAppVersion}
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\server\{#BackendExe}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; The entire onedir backend bundle (backend.exe + _internal + bundled dashboard/models).
Source: "{#ServerBundle}\*"; DestDir: "{app}\server"; Flags: recursesubdirs createallsubdirs ignoreversion
; VC++ runtime (lightgbm + torch need it); removed after install.
Source: "redist\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "EULA.txt"; DestDir: "{app}"; Flags: ignoreversion

[UninstallDelete]
Type: files; Name: "{app}\server\.env"
Type: files; Name: "{app}\run_backend.cmd"

[Code]
var
  CfgPage: TInputQueryWizardPage;
  JwtSecret: String;

{ Generate a strong random hex token (64 chars) via PowerShell crypto (two GUIDs).
  Falls back to a tick-based value so the .env always has a usable, non-default
  secret even if PowerShell is unavailable. }
function GenToken: String;
var tmpFile, cmd: String; tokenText: AnsiString; rc: Integer;
begin
  Result := '';
  tmpFile := ExpandConstant('{tmp}\csx_tok.txt');
  cmd := '-NoProfile -Command "([guid]::NewGuid().ToString(''N'')+[guid]::NewGuid().ToString(''N'')) | Out-File -Encoding ascii -NoNewline ''' + tmpFile + '''"';
  if Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), cmd, '', SW_HIDE, ewWaitUntilTerminated, rc) then
    if LoadStringFromFile(tmpFile, tokenText) then
      Result := Trim(tokenText);
  DeleteFile(tmpFile);
  if Length(Result) < 16 then
    Result := 'csx' + GetDateTimeString('yyyymmddhhnnsszzz', #0, #0);
end;

procedure InitializeWizard;
begin
  JwtSecret := GenToken;   { internal session-signing secret; never shown }
  CfgPage := CreateInputQueryPage(wpLicense,
    'Server Configuration',
    'Set the API key, port, and database for this SOC server',
    'A strong API key is pre-generated. The SAME API key must be entered on each endpoint agent, so copy it before you finish.');
  CfgPage.Add('API key (shared with endpoint agents):', False);
  CfgPage.Add('Backend port:', False);
  CfgPage.Add('MongoDB URI (local default, or paste an Atlas SRV string):', False);
  CfgPage.Values[0] := GenToken;
  CfgPage.Values[1] := '8000';
  CfgPage.Values[2] := 'mongodb://localhost:27017';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var portNum: Integer;
begin
  Result := True;
  if CurPageID = CfgPage.ID then
  begin
    if Length(Trim(CfgPage.Values[0])) < 16 then begin
      MsgBox('The API key should be at least 16 characters.', mbError, MB_OK); Result := False; Exit;
    end;
    portNum := StrToIntDef(Trim(CfgPage.Values[1]), -1);
    if (portNum < 1) or (portNum > 65535) then begin
      MsgBox('Enter a valid port (1-65535).', mbError, MB_OK); Result := False; Exit;
    end;
    if Trim(CfgPage.Values[2]) = '' then begin
      MsgBox('Enter a MongoDB URI (or keep the local default).', mbError, MB_OK); Result := False; Exit;
    end;
  end;
end;

{ Stop a previous server (upgrade) so its exe is not locked. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var rc: Integer;
begin
  Result := '';
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/end /tn "{#TaskName}"', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/f /im {#BackendExe}', '', SW_HIDE, ewWaitUntilTerminated, rc);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  env, cmdFile, params, port: String;
  rc: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    port := Trim(CfgPage.Values[1]);

    { 1. Install the VC++ runtime (silent). Required by lightgbm + torch. }
    Exec(ExpandConstant('{tmp}\vc_redist.x64.exe'), '/install /quiet /norestart', '',
         SW_SHOW, ewWaitUntilTerminated, rc);

    { 2. Write the server .env next to backend.exe (backend_entry loads it on start). }
    env :=
      'XDR_API_KEY=' + Trim(CfgPage.Values[0]) + #13#10 +
      'JWT_SECRET_KEY=' + JwtSecret + #13#10 +
      'BACKEND_HOST=0.0.0.0' + #13#10 +
      'BACKEND_PORT=' + port + #13#10 +
      'MONGO_URI=' + Trim(CfgPage.Values[2]) + #13#10;
    SaveStringToFile(ExpandConstant('{app}\server\.env'), env, False);

    { 3. Open the firewall so LAN SOC users + endpoints can reach the server. }
    Exec(ExpandConstant('{sys}\netsh.exe'),
         'advfirewall firewall add rule name="CyberSentinelXDR Server ' + port + '" dir=in action=allow protocol=TCP localport=' + port,
         '', SW_HIDE, ewWaitUntilTerminated, rc);

    { 4. Launcher .cmd (avoids nested-quote issues) + boot-time SYSTEM task. }
    cmdFile := ExpandConstant('{app}\run_backend.cmd');
    SaveStringToFile(cmdFile,
      '@echo off' + #13#10 + '"' + ExpandConstant('{app}\server\{#BackendExe}') + '"' + #13#10, False);
    params := '/create /tn "{#TaskName}" /sc onstart /ru SYSTEM /rl HIGHEST /f /tr "cmd /c \"' + cmdFile + '\""';
    Exec(ExpandConstant('{sys}\schtasks.exe'), params, '', SW_HIDE, ewWaitUntilTerminated, rc);
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/run /tn "{#TaskName}"', '', SW_HIDE, ewWaitUntilTerminated, rc);

    { Remind the operator of the API key to configure endpoint agents with. }
    MsgBox('Cyber Sentinel XDR Server installed and starting on port ' + port + '.'#13#10#13#10 +
           'API key (enter this on each endpoint agent):'#13#10 + Trim(CfgPage.Values[0]) + #13#10#13#10 +
           'The server may take up to a minute to finish loading its models.',
           mbInformation, MB_OK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var rc: Integer; port: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/end /tn "{#TaskName}"', '', SW_HIDE, ewWaitUntilTerminated, rc);
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/delete /tn "{#TaskName}" /f', '', SW_HIDE, ewWaitUntilTerminated, rc);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/f /im {#BackendExe}', '', SW_HIDE, ewWaitUntilTerminated, rc);
  end;
end;

[Icons]
; Start-menu shortcut that opens the dashboard in the default browser.
Name: "{group}\Cyber Sentinel XDR Dashboard"; Filename: "http://localhost:8000/"

[Run]
; Offer to open the dashboard when setup finishes.
Filename: "http://localhost:8000/"; Description: "Open the Cyber Sentinel XDR dashboard"; Flags: postinstall shellexec nowait
