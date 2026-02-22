#!/usr/bin/env python3
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

# --- Configuration ---
# Npcap 1.87 is the latest as of Feb 2026
NMAP_VERSION = "7.92"
NPCAP_VERSION = "1.87"

# Target directories
BASE_DIR = Path(__file__).parent.parent
BINARIES_DIR = BASE_DIR / "ui" / "src-tauri" / "binaries"
NMAP_TARGET_DIR = BINARIES_DIR / "nmap"
DRIVER_TARGET_DIR = BINARIES_DIR / "driver_installers"

# URLs
NMAP_URL = f"https://nmap.org/dist/nmap-{NMAP_VERSION}-win32.zip"
NPCAP_URL = f"https://npcap.com/dist/npcap-{NPCAP_VERSION}.exe"
# URLs
NMAP_URL = f"https://nmap.org/dist/nmap-{NMAP_VERSION}-win32.zip"
NPCAP_URL = f"https://npcap.com/dist/npcap-{NPCAP_VERSION}.exe"


def download_file(url, target_path):
    """Download a file with User-Agent set."""
    print(f"  [INIT] Downloading: {url}...")
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            },
        )
        with (
            urllib.request.urlopen(req, timeout=30) as response,
            open(target_path, "wb") as out_file,
        ):
            shutil.copyfileobj(response, out_file)
        print("  [SUCCESS] Download complete.")
        return True
    except Exception as e:
        print(f"  [ERROR] Download failed: {e}")
        return False


def install_nmap_sidecar():
    """Download and set up portable Nmap and Npcap installer."""
    print(
        f"[NMAP] Setting up portable Nmap v{NMAP_VERSION} and Npcap v{NPCAP_VERSION}..."
    )

    if sys.platform != "win32":
        print(
            f"  [ERROR] Nmap sidecar bundling is currently only configured for Windows. (Found: {sys.platform})"
        )
        return False

    BINARIES_DIR.mkdir(parents=True, exist_ok=True)
    NMAP_TARGET_DIR.mkdir(parents=True, exist_ok=True)
    DRIVER_TARGET_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Download Nmap
    nmap_archive = BINARIES_DIR / f"nmap-{NMAP_VERSION}-win32.zip"
    if not nmap_archive.exists():
        if not download_file(NMAP_URL, nmap_archive):
            return False
    else:
        print("  [SKIP] Using cached Nmap archive.")

    # 2. Extract Nmap
    print(f"  [EXTRACT] Extracting Nmap to {NMAP_TARGET_DIR}...")
    temp_extract_dir = BINARIES_DIR / "nmap_temp"
    if temp_extract_dir.exists():
        shutil.rmtree(temp_extract_dir)
    temp_extract_dir.mkdir()

    try:
        with zipfile.ZipFile(nmap_archive, "r") as zip_ref:
            zip_ref.extractall(temp_extract_dir)

        # Move the inner nmap-VER folder contents to the final target
        extracted_dirs = [
            d
            for d in temp_extract_dir.iterdir()
            if d.is_dir() and d.name.startswith("nmap-")
        ]
        if extracted_dirs:
            # Check if target exists and clean it
            if NMAP_TARGET_DIR.exists():
                shutil.rmtree(NMAP_TARGET_DIR)

            shutil.move(str(extracted_dirs[0]), str(NMAP_TARGET_DIR))
            print(f"  [SUCCESS] Portable Nmap installed at: {NMAP_TARGET_DIR}")
        else:
            print("  [ERROR] Extraction failed: No nmap inner folder found.")
            return False
    except Exception as e:
        print(f"  [ERROR] Nmap extraction failed: {e}")
        return False
    finally:
        if temp_extract_dir.exists():
            shutil.rmtree(temp_extract_dir)

    # 3. Download Npcap Installer
    npcap_installer = DRIVER_TARGET_DIR / "npcap-setup.exe"
    if not npcap_installer.exists():
        if not download_file(NPCAP_URL, npcap_installer):
            # Fallback to alternative Npcap URL if main fails
            print("  [RETRY] Attempting alternative Npcap URL...")
            ALT_NPCAP_URL = f"https://npcap.org/dist/npcap-{NPCAP_VERSION}.exe"
            if not download_file(ALT_NPCAP_URL, npcap_installer):
                return False
    else:
        print("  [SKIP] Using cached Npcap installer.")

    # 4. Verification
    nmap_exe = NMAP_TARGET_DIR / "nmap.exe"
    if nmap_exe.exists():
        print(f"  [SUCCESS] Verified: {nmap_exe}")
        try:
            output = subprocess.check_output([str(nmap_exe), "--version"], text=True)
            print(f"  [INFO] Nmap version: {output.splitlines()[0]}")
            return True
        except Exception as e:
            print(f"  [ERROR] Verification failed: Unable to execute nmap: {e}")
            return False
    else:
        print(f"  [ERROR] Verification failed: nmap.exe not found at {nmap_exe}")
        return False


if __name__ == "__main__":
    if install_nmap_sidecar():
        print("\n[RESULT] Nmap sidecar setup SUCCESSFUL.")
    else:
        print("\n[RESULT] Nmap sidecar setup FAILED.")
        sys.exit(1)
