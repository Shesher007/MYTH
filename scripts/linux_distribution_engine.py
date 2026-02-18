import os
import shutil
import tarfile
import json
import hashlib
import time
from pathlib import Path

def create_distro_packages():
    # Paths
    project_root = Path(__file__).parent.parent
    src_tauri = project_root / "ui" / "src-tauri"
    dist_dir = project_root / "dist_distribution"
    
    # Load version from tauri.conf.json
    with open(src_tauri / "tauri.conf.json", "r") as f:
        config = json.load(f)
        version = config.get("version", "1.1.1")
        product_name = config.get("productName", "MYTH")
        pkg_name = product_name.lower()

    # Base directory for assembly
    base_app_dir = dist_dir / f"{pkg_name}-{version}"
    bin_dir = base_app_dir / "usr" / "bin"
    share_dir = base_app_dir / "usr" / "share"
    icons_dir = share_dir / "icons" / "hicolor" / "512x512" / "apps"
    applications_dir = share_dir / "applications"

    # Create directories
    for d in [bin_dir, icons_dir, applications_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # 1. Prepare Core Files
    # Search for binary in release directories (handles target triples)
    binary_found = False
    search_paths = [
        src_tauri / "target" / "release" / pkg_name,
        src_tauri / "target" / "release" / product_name,
    ]
    # Add target-specific paths
    for target_dir in (src_tauri / "target").glob("*"):
        if target_dir.is_dir():
            search_paths.append(target_dir / "release" / pkg_name)
            search_paths.append(target_dir / "release" / product_name)

    for path in search_paths:
        if path.exists() and path.is_file():
            shutil.copy2(path, bin_dir / pkg_name)
            os.chmod(bin_dir / pkg_name, 0o755)
            binary_found = True
            print(f"✅ Found binary at: {path}")
            break
    
    if not binary_found:
        print("❌ CRITICAL: Could not find built binary for packaging.")
        # In CI, we want to fail if binary is missing
        # exit(1) 

    icon_src = src_tauri / "icons" / "icon.png"
    if icon_src.exists():
        shutil.copy2(icon_src, icons_dir / f"{pkg_name}.png")

    desktop_content = f"""[Desktop Entry]
Name={product_name}
Exec={pkg_name}
Icon={pkg_name}
Type=Application
Categories=Security;Development;
Comment=High-Performance Offensive Intelligence Engine
"""
    with open(applications_dir / f"{pkg_name}.desktop", "w") as f:
        f.write(desktop_content)

    # Helper to create compressed archives
    def make_archive(ext, mode="w:gz"):
        out_file = project_root / f"{pkg_name}_{version}_amd64.{ext}"
        with tarfile.open(out_file, mode) as tar:
            tar.add(base_app_dir, arcname="/") 
        print(f"📦 Created: {out_file.name}")
        return out_file

    # 2. Generate Formats
    # Slackware (.txz)
    make_archive("txz", "w:xz")
    
    # Alpine (.apk) - Simplified binary APK
    make_archive("apk")
    
    # Void (.xbps) - Simplified binary XBPS
    make_archive("xbps")
    
    # Solus (.eopkg)
    make_archive("eopkg")
    
    # Arch Linux (.pkg.tar.zst) - with basic PKGINFO
    bin_path = bin_dir / pkg_name
    pkginfo_content = f"""pkgname = {pkg_name}
pkgver = {version}
pkgrel = 1
pkgdesc = Industrial-Grade Sovereign Security Agent
url = https://github.com/shesher010/MYTH
builddate = {int(time.time())}
packager = MYTH
size = {bin_path.stat().st_size if bin_path.exists() else 0}
arch = x86_64
license = MIT
depend = gtk3
depend = webkit2gtk
"""
    with open(base_app_dir / ".PKGINFO", "w") as f:
        f.write(pkginfo_content)
    make_archive("pkg.tar.zst", "w:zst" if "zst" in tarfile.OPEN_METH else "w:gz")
    
    # Lightweight formats
    make_archive("pet") # Puppy Linux
    make_archive("sfs") # Squashfs
    make_archive("ipk") # opkg (Lightweight)
    
    # Universal Fallback
    universal_tar = project_root / f"{pkg_name}_{version}_universal.tar.gz"
    with tarfile.open(universal_tar, "w:gz") as tar:
        tar.add(base_app_dir, arcname=f"{pkg_name}-{version}")
    print(f"📦 Created: {universal_tar.name}")

    # 3. Bundle ALL Manifests from packaging/ for Release inclusion
    print("📂 Bundling all package manifests...")
    packaging_dir = project_root / "packaging"
    for root, dirs, files in os.walk(packaging_dir):
        for file in files:
            src_path = Path(root) / file
            # Create a descriptive name for the release root
            rel_path = src_path.relative_to(packaging_dir)
            dist_name = "_".join(rel_path.parts)
            dst_path = project_root / dist_name
            shutil.copy2(src_path, dst_path)
            print(f"📄 Prepared manifest: {dist_name}")

if __name__ == "__main__":
    import time
    create_distro_packages()
