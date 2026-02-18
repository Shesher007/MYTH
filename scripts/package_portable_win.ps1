# MYTH Desktop - Portable Windows Build Script
# Creates a portable .zip containing the app and sidecar

$Version = "1.1.1"
$TargetDir = "ui\src-tauri\target\release"
$OutputDir = "dist\portable"

Write-Host "Building Portable Windows Package (v$Version)..."

# Ensure build exists
if (-not (Test-Path "$TargetDir\myth-desktop.exe")) {
    Write-Error "Build artifacts not found. Run 'npm run tauri:build' first."
    exit 1
}

# Create output dir
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Build directory priority: NSIS bundle (best layout) -> Release dir (fallback)
$NsisDir = "$TargetDir\bundle\nsis"
if (Test-Path "$NsisDir\*.exe") {
    Write-Host "Found NSIS bundle directory. Using it for portable package."
    Copy-Item "$NsisDir\*" -Destination "$OutputDir\" -Recurse
} else {
    Write-Warning "NSIS bundle not found. Falling back to raw release artifacts."
    Copy-Item "$TargetDir\myth-desktop.exe" -Destination "$OutputDir\"
    Copy-Item "$TargetDir\myth-backend.exe" -Destination "$OutputDir\"
    if (Test-Path "$TargetDir\resources") {
        Copy-Item "$TargetDir\resources" -Destination "$OutputDir\" -Recurse
    }
}

# Create portable marker
New-Item -ItemType File -Path "$OutputDir\portable.dat" -Force | Out-Null

# Zip it
Compress-Archive -Path "$OutputDir\*" -DestinationPath "dist\myth-$Version-portable-windows.zip" -Force

Write-Host "Portable package created: dist\myth-$Version-portable-windows.zip"
