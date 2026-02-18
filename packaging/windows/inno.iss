; MYTH Desktop — Inno Setup Script
; Build: iscc inno.iss

#define MyAppName "MYTH"
#define MyAppVersion "1.1.3"
#define MyAppPublisher "Shesher Hasan"
#define MyAppURL "https://github.com/shesher010/MYTH"
#define MyAppExeName "MYTH.exe"

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputBaseFilename={#MyAppName}_{#MyAppVersion}_x64_setup
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "..\src-tauri\target\release\MYTH.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\src-tauri\binaries\myth-backend.exe"; DestDir: "{app}\binaries"; Flags: ignoreversion

[Icons]
Name: "{group}\MYTH"; Filename: "{app}\MYTH.exe"
Name: "{autodesktop}\MYTH"; Filename: "{app}\MYTH.exe"
