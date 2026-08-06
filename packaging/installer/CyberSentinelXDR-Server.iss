; ============================================================================
;  Cyber Sentinel XDR - SERVER Installer (Inno Setup 6)
;
;  Installs the central SOC server: the frozen backend.exe (with the dashboard
;  bundled inside it, served same-origin), the VC++ runtime, Suricata (IDS
;  engine), a firewall rule, and a boot-time service. The endpoint agent has
;  its own separate, lean installer (CyberSentinelXDR.iss) - this one is large
;  (~1 GB, torch).
;
;  PREREQUISITES before building:
;    1. Backend bundle built:  packaging\build_backend.ps1  ->  C:\csxb\dist\backend
;    2. Dashboard built:        npm run build  (bundled into backend.exe by the spec)
;    3. redist\vc_redist.x64.exe present (staged from the MS redistributable)
;    4. redist\Suricata-7.0.15-1-64bit.msi present
;
;  BUILD:
;    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" CyberSentinelXDR-Server.iss
;  Output: C:\csxb\installer_out\CyberSentinelXDR-Server-Setup-1.0.4.exe
;
;  NOTE: MongoDB is NOT bundled. The config page asks for MONGO_URI - default is
;  a local MongoDB (mongodb://localhost:27017, requires MongoDB installed on this
;  host), or paste a MongoDB Atlas SRV string to use the cloud.
;
;  NOTE: Suricata (GPLv2, no redistribution restriction) IS bundled and silently
;  installed below. Npcap - Suricata's packet-capture driver - is deliberately
;  NOT bundled: the free Npcap license disallows both silent install and
;  redistribution inside another product (that requires a paid Npcap OEM
;  license). ServerControl.exe instead links out to the official npcap.com
;  installer and auto-detects the capture interface once it's present.
; ============================================================================

#define MyAppName    "Cyber Sentinel XDR Server"
#define MyAppVersion "1.0.4"
#define MyPublisher  "Cyber Sentinel XDR"
#define BackendExe   "backend.exe"
#define ControlExe   "ServerControl.exe"
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
; Suricata IDS engine (network detection); removed after install.
Source: "redist\Suricata-7.0.15-1-64bit.msi"; DestDir: "{tmp}"; Flags: deleteafterinstall
Source: "EULA.txt"; DestDir: "{app}"; Flags: ignoreversion

[UninstallDelete]
Type: files; Name: "{app}\server\.env"

[Code]
var
  ApiKey, JwtSecret: String;
  ActPage: TInputQueryWizardPage;

{ Lightweight format check (no crypto) so obvious typos are caught before the
  ~1 GB copy. Full cryptographic validation happens post-install via
  ServerControl.exe --activate. Server codes start with CSXS. }
function IsValidCodeFormat(s, prefix: String): Boolean;
var i: Integer; ch: Char;
begin
  Result := False;
  s := Uppercase(Trim(s));
  StringChangeEx(s, '-', '', True);
  StringChangeEx(s, ' ', '', True);
  if Copy(s, 1, 4) <> prefix then Exit;
  if Length(s) < 20 then Exit;
  for i := 1 to Length(s) do
  begin
    ch := s[i];
    if not ((((ch >= 'A') and (ch <= 'Z'))) or ((ch >= '2') and (ch <= '7'))) then Exit;
  end;
  Result := True;
end;

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
  ApiKey := GenToken;      { strong default; editable later in the Control Panel }
  JwtSecret := GenToken;   { internal session-signing secret; never shown }

  { Activation page, shown right after the EULA. }
  ActPage := CreateInputQueryPage(wpLicense,
    'Product Activation',
    'Enter your Cyber Sentinel XDR Server activation code',
    'You were given an activation code that begins with CSXS-. Enter it below to '
    + 'activate this server. A trial code works once per computer; when a trial '
    + 'ends you will need a new code to continue.');
  ActPage.Add('Activation code:', False);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (ActPage <> nil) and (CurPageID = ActPage.ID) then
  begin
    if not IsValidCodeFormat(ActPage.Values[0], 'CSXS') then
    begin
      MsgBox('Please enter a valid Server activation code.'#13#10 +
             'A Server code starts with CSXS- (Endpoint codes will not work here).',
             mbError, MB_OK);
      Result := False;
    end;
  end;
end;

{ Stop a previous server/control panel (upgrade) so exes are not locked. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var rc: Integer;
begin
  Result := '';
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/f /im {#BackendExe}', '', SW_HIDE, ewWaitUntilTerminated, rc);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/f /im {#ControlExe}', '', SW_HIDE, ewWaitUntilTerminated, rc);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  env: String;
  rc: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    { 1. Install the VC++ runtime (silent). Required by lightgbm + torch. }
    Exec(ExpandConstant('{tmp}\vc_redist.x64.exe'), '/install /quiet /norestart', '',
         SW_SHOW, ewWaitUntilTerminated, rc);

    { 1b. Install Suricata (IDS engine, network detection) silently to its
      default path (C:\Program Files\Suricata). GPLv2 - no redistribution
      restriction, unlike Npcap (see the note at the top of this file), which
      is why only Suricata gets this treatment; Npcap stays a manual step via
      ServerControl.exe's "Install Npcap" button. Suricata runs fine installed
      but without Npcap present - it just can't capture anything yet, and the
      Control Panel's status line reflects that rather than pretending it works. }
    Exec(ExpandConstant('{sys}\msiexec.exe'),
         '/i "' + ExpandConstant('{tmp}\Suricata-7.0.15-1-64bit.msi') + '" /quiet /norestart',
         '', SW_HIDE, ewWaitUntilTerminated, rc);

    { 2. Write a starter .env with strong secrets. MongoDB defaults to localhost;
         set your real database (local or Atlas) in the Server Control Panel. }
    env :=
      'XDR_API_KEY=' + ApiKey + #13#10 +
      'JWT_SECRET_KEY=' + JwtSecret + #13#10 +
      'BACKEND_HOST=0.0.0.0' + #13#10 +
      'BACKEND_PORT=8000' + #13#10 +
      'MONGO_URI=mongodb://localhost:27017' + #13#10;
    SaveStringToFile(ExpandConstant('{app}\server\.env'), env, False);

    { 3. Open the firewall so LAN SOC users + endpoints can reach the server. }
    Exec(ExpandConstant('{sys}\netsh.exe'),
         'advfirewall firewall add rule name="CyberSentinelXDR Server 8000" dir=in action=allow protocol=TCP localport=8000',
         '', SW_HIDE, ewWaitUntilTerminated, rc);

    { 4. Activate the product with the code entered in the wizard. The frozen
         Control Panel performs the real cryptographic check and writes the
         license to C:\ProgramData\CyberSentinel + HKLM (survives reinstall). }
    Exec(ExpandConstant('{app}\server\{#ControlExe}'),
         '--activate "' + Trim(ActPage.Values[0]) + '"', '',
         SW_HIDE, ewWaitUntilTerminated, rc);
    if rc <> 0 then
      MsgBox('The activation code could not be verified.'#13#10#13#10 +
             'The Control Panel will open locked - enter a valid Server code there to unlock it.',
             mbInformation, MB_OK);

    { 5. The server is started from the Control Panel, not a boot task. }
    MsgBox('Cyber Sentinel XDR Server installed.'#13#10#13#10 +
           'The Server Control Panel will open now. Use it to:'#13#10 +
           '  - set your MongoDB URI (local or Atlas)'#13#10 +
           '  - copy the API key for your endpoint agents'#13#10 +
           '  - Start the server and open the dashboard'#13#10#13#10 +
           'API key:'#13#10 + ApiKey,
           mbInformation, MB_OK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var rc: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/f /im {#ControlExe}', '', SW_HIDE, ewWaitUntilTerminated, rc);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/f /im {#BackendExe}', '', SW_HIDE, ewWaitUntilTerminated, rc);
  end;
end;

[Icons]
; Shortcuts to the Server Control Panel (config + start/stop + open dashboard).
Name: "{group}\Cyber Sentinel XDR Server Control"; Filename: "{app}\server\{#ControlExe}"
Name: "{commondesktop}\Cyber Sentinel XDR Server"; Filename: "{app}\server\{#ControlExe}"

[Run]
; Open the Control Panel when setup finishes so the operator can configure + start.
; ServerControl.exe is built with a requireAdministrator manifest (uac_admin), so it
; must be launched via ShellExecute (shellexec) - a plain CreateProcess fails with
; error 740 ("The requested operation requires elevation"). shellexec honours the
; manifest and elevates cleanly.
Filename: "{app}\server\{#ControlExe}"; Description: "Open the Server Control Panel"; Flags: postinstall nowait shellexec runasoriginaluser
