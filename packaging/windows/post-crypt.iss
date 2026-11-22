; Instalador do Post-Crypt (Inno Setup 6).
;
; Gerado por scripts\gerar-instalador.ps1, que passa a versão e a pasta do PyInstaller:
;   ISCC.exe /DAppVersion=1.0.0 /DAppSource=<pasta do PyInstaller> /DAppOutput=<pasta de saída> post-crypt.iss
;
; Instala por usuário, sem pedir administrador (em %LOCALAPPDATA%\Programs\Post-Crypt).
; Quem é administrador pode escolher "todos os usuários" no primeiro passo.

#ifndef AppVersion
  #error Passe a versão: /DAppVersion=x.y.z
#endif
; Caminhos relativos partem da pasta deste arquivo.
#ifndef AppSource
  #define AppSource "..\..\dist\Post-Crypt"
#endif
#ifndef AppOutput
  #define AppOutput "..\..\dist\instalador"
#endif

#define AppName "Post-Crypt"
#define AppExe "Post-Crypt.exe"
#define AppPublisher "Equipe Post-Crypt"
#define AppURL "https://github.com/ArturSiqueiraSudre/post-crypt"

[Setup]
; Identidade do programa para o Windows. NUNCA mude este GUID: é por ele que uma versão
; nova encontra e atualiza a anterior, e que "Adicionar ou remover programas" o reconhece.
AppId={{B50B4263-B4F1-4959-9715-4B8BF87F17B0}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription=Instalador do {#AppName}

; Por usuário por padrão; o assistente oferece "todos os usuários" a administradores.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=auto
AllowNoIcons=yes
UsePreviousAppDir=yes

ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

WizardStyle=modern
SetupIconFile=post-crypt.ico
WizardImageFile=assistente.bmp
WizardSmallImageFile=assistente-pequeno.bmp
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}

OutputDir={#AppOutput}
OutputBaseFilename=Post-Crypt-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes

; Fecha o Post-Crypt aberto antes de atualizar ou desinstalar.
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "ptbr"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; A pasta inteira gerada pelo PyInstaller (Post-Crypt.exe + _internal).
Source: "{#AppSource}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
; Só a pasta do programa. O registro em %LOCALAPPDATA%\Post-Crypt\logs fica, como em
; qualquer programa, e pode ser apagado à mão.
Type: filesandordirs; Name: "{app}\_internal"
