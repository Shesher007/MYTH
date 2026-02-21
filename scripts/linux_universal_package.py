import json
import os
import shutil
import tarfile
from pathlib import Path


def create_universal_package():
    # Paths
    project_root = Path(__file__).parent.parent
    src_tauri = project_root / "ui" / "src-tauri"
    dist_dir = project_root / "dist_universal"

    # Load version from tauri.conf.json
    with open(src_tauri / "tauri.conf.json", "r") as f:
        config = json.load(f)
        version = config.get("version", "1.1.1")
        product_name = config.get("productName", "MYTH")

    # Target directory structure
    app_dir = dist_dir / f"{product_name}-{version}"
    bin_dir = app_dir / "bin"
    share_dir = app_dir / "share"
    icons_dir = share_dir / "icons" / "hicolor" / "512x512" / "apps"
    applications_dir = share_dir / "applications"

    # Create directories
    for d in [bin_dir, icons_dir, applications_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # 1. Copy Binary (Assume build is done)
    # Note: In CI, this script will run after cargo build
    release_bin = src_tauri / "target" / "release" / product_name.lower()
    if not release_bin.exists():
        # Try different possible names
        release_bin = src_tauri / "target" / "release" / product_name

    if release_bin.exists():
        shutil.copy2(release_bin, bin_dir / product_name.lower())
        os.chmod(bin_dir / product_name.lower(), 0o755)

    # 2. Copy Icons
    icon_src = src_tauri / "icons" / "icon.png"
    if icon_src.exists():
        shutil.copy2(icon_src, icons_dir / f"{product_name.lower()}.png")

    # 3. Create Desktop File
    desktop_content = f"""[Desktop Entry]
Name={product_name}
Exec={product_name.lower()}
Icon={product_name.lower()}
Type=Application
Categories=Security;Development;
Comment=Multi-Yield Tactical Hub — Autonomous AI Cybersecurity Agent
"""
    with open(applications_dir / f"{product_name.lower()}.desktop", "w") as f:
        f.write(desktop_content)

    # 4. Copy Install Script
    shutil.copy2(project_root / "scripts" / "install.sh", app_dir / "install.sh")
    os.chmod(app_dir / "install.sh", 0o755)

    # 5. Create Tarball
    output_filename = project_root / f"{product_name}-{version}-universal.tar.gz"
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(app_dir, arcname=app_dir.name)

    print(f"✅ Universal package created: {output_filename}")


if __name__ == "__main__":
    create_universal_package()
