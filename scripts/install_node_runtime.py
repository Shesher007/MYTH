#!/usr/bin/env python3
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

# --- Configuration ---
NODE_VERSION = "22.14.0"
PLATFORM = sys.platform

# Target directory: ui/src-tauri/binaries/nodejs/
BASE_DIR = Path(__file__).parent.parent
BINARIES_DIR = BASE_DIR / "ui" / "src-tauri" / "binaries"
NODE_TARGET_DIR = BINARIES_DIR / "nodejs"

# URLs for portable Node.js
URLS = {
    "win32": f"https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-win-x64.zip",
    "linux": f"https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-linux-x64.tar.xz",
    "darwin": f"https://nodejs.org/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-darwin-x64.tar.gz",
}


def install_node_runtime():
    """Download and set up a portable Node.js runtime."""
    print(f"[NODE] Setting up portable Node.js v{NODE_VERSION} for {PLATFORM}...")

    if PLATFORM not in URLS:
        print(f"  [ERROR] Unsupported platform: {PLATFORM}")
        return False

    url = URLS[PLATFORM]
    archive_name = url.split("/")[-1]
    archive_path = BINARIES_DIR / archive_name

    # Create binaries folder if missing
    BINARIES_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Download
    if not archive_path.exists():
        print(f"  [INIT] Downloading: {url}...")
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MYTH/1.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as response, open(archive_path, "wb") as out_file:
                shutil.copyfileobj(response, out_file)
            print("  [SUCCESS] Download complete.")
        except Exception as e:
            print(f"  [ERROR] Download failed: {e}")
            return False
    else:
        print(f"  [SKIP] Using cached archive: {archive_name}")

    # 2. Extract
    print(f"  [EXTRACT] Extracting to {NODE_TARGET_DIR}...")
    if NODE_TARGET_DIR.exists():
        shutil.rmtree(NODE_TARGET_DIR)

    temp_extract_dir = BINARIES_DIR / "node_temp"
    if temp_extract_dir.exists():
        shutil.rmtree(temp_extract_dir)
    temp_extract_dir.mkdir()

    try:
        if archive_name.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                zip_ref.extractall(temp_extract_dir)
        else:
            with tarfile.open(archive_path, "r:*") as tar_ref:
                tar_ref.extractall(temp_extract_dir)

        # Move the inner folder to the final target
        extracted_dirs = [d for d in temp_extract_dir.iterdir() if d.is_dir()]
        if extracted_dirs:
            shutil.move(str(extracted_dirs[0]), str(NODE_TARGET_DIR))
            print(f"  [SUCCESS] Portable Node.js installed at: {NODE_TARGET_DIR}")
        else:
            print("  [ERROR] Extraction failed: No inner folder found.")
            return False

    except Exception as e:
        print(f"  [ERROR] Extraction failed: {e}")
        return False
    finally:
        if temp_extract_dir.exists():
            shutil.rmtree(temp_extract_dir)

    # 3. Verification
    node_exe = NODE_TARGET_DIR / ("node.exe" if PLATFORM == "win32" else "bin/node")
    if node_exe.exists():
        print(f"  [SUCCESS] Verified: {node_exe}")
        # Test execution
        try:
            output = subprocess.check_output([str(node_exe), "--version"], text=True)
            print(f"  [INFO] Node version: {output.strip()}")
            return True
        except Exception as e:
            print(f"  [ERROR] Verification failed: Unable to execute node: {e}")
            return False
    else:
        print(f"  [ERROR] Verification failed: node binary not found at {node_exe}")
        return False


if __name__ == "__main__":
    if install_node_runtime():
        print("\n[RESULT] Node.js sidecar setup SUCCESSFUL.")
    else:
        print("\n[RESULT] Node.js sidecar setup FAILED.")
        sys.exit(1)
