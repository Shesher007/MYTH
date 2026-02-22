# MYTH Windows Build Simulator
# ================================================
# This script mirrors the end-to-end CircleCI Windows pipeline.
# Run this locally to ensure your build will pass the cloud CI.

# 1. Environment & Path Logic
function Get-RustupPath {
    $paths = @(
        (Join-Path $env:USERPROFILE ".cargo\bin\rustup.exe"),
        (Join-Path $HOME ".cargo\bin\rustup.exe"),
        "C:\Users\circleci\.cargo\bin\rustup.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    return $null
}

# Find uv
$uv = Get-Command uv -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
if ($null -eq $uv) {
    if (Test-Path "$HOME\.local\bin\uv.exe") {
        $uv = "$HOME\.local\bin\uv.exe"
    } else {
        Write-Host "uv not found locally. Please install it first: irm https://astral.sh/uv/install.ps1 | iex"
        exit 1
    }
}

# 2. Setup Rust (Resilient)
Write-Host "--- Stage 1: Setup Rust ---"
if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
    $rustup = Get-RustupPath
    if ($null -eq $rustup) {
        Write-Host "Rustup not detected. Installing..."
        Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe" -OutFile "rustup-init.exe"
        Start-Process -FilePath ".\rustup-init.exe" -ArgumentList "-y", "--default-host", "x86_64-pc-windows-msvc", "--default-toolchain", "stable", "--no-modify-path" -Wait
        Remove-Item "rustup-init.exe"
        $rustup = Get-RustupPath
    }

    if ($null -ne $rustup) {
        Write-Host "Found rustup at: $rustup"
        & $rustup target add x86_64-pc-windows-msvc
        $binDir = Split-Path $rustup
        $env:PATH = "$binDir;" + $env:PATH
    } else {
        Write-Error "CRITICAL: Rust toolchain initialization failed."
        exit 1
    }
} else {
    Write-Host "Rust already installed: $(rustc --version)"
}

# 3. Build Workflow
Write-Host "`n--- Stage 2: Sync & Hydrate ---"
& $uv sync --all-extras
& $uv run python governance/hydrate.py

Write-Host "`n--- Stage 3: Orchestrator Validation ---"
& $uv run python scripts/ci_orchestrator.py validate --verbose

Write-Host "`n--- Stage 4: Backend & Sidecars ---"
$env:PYTHONWARNINGS = "ignore"
& $uv run python scripts/ci_orchestrator.py build-backend --target x86_64-pc-windows-msvc --verbose

Write-Host "`n--- Stage 5: Desktop App (NSIS) ---"
& $uv run python scripts/ci_orchestrator.py build-desktop --target x86_64-pc-windows-msvc --bundles nsis --verbose

Write-Host "`n--- Stage 6: Windows Portable Package ---"
& $uv run python scripts/ci_orchestrator.py windows-packages --verbose

Write-Host "`n--- SIMULATION COMPLETE ---"
Write-Host "If all stages passed, your build is safe for CircleCI."
