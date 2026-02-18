import os
import sys
import shutil
import asyncio
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

async def verify_nmap_bundle():
    print("[VERIFY] Simulating Backend Sidecar Injection...")
    
    # We can't easily run the actual _inject_sidecar_paths because it assumes it's in a package
    # but we can simulate the logic
    from myth_utils.paths import get_sidecar_dir
    sidecar_dir = get_sidecar_dir()
    
    if not sidecar_dir:
        print("  [ERROR] Could not resolve sidecar directory.")
        return False
        
    print(f"  [INFO] Sidecar Dir: {sidecar_dir}")
    nmap_dir = os.path.join(sidecar_dir, "nmap")
    npcap_installer = os.path.join(sidecar_dir, "driver_installers", "npcap-setup.exe")
    
    # 1. Check folder existence
    if os.path.exists(nmap_dir):
        print(f"  [SUCCESS] Nmap bundled directory found: {nmap_dir}")
    else:
        print(f"  [ERROR] Nmap bundled directory NOT FOUND at {nmap_dir}")
        return False
        
    if os.path.exists(npcap_installer):
        print(f"  [SUCCESS] Npcap installer found: {npcap_installer}")
    else:
        print(f"  [ERROR] Npcap installer NOT FOUND at {npcap_installer}")
        return False

    # 2. Inject and Verify Execution
    os.environ["PATH"] = f"{nmap_dir}{os.pathsep}{os.environ.get('PATH', '')}"
    
    nmap_exe = shutil.which("nmap")
    if nmap_exe:
        print(f"  [SUCCESS] Nmap found in temporary PATH: {nmap_exe}")
        try:
            import subprocess
            output = subprocess.check_output(["nmap", "--version"], text=True)
            print(f"  [INFO] Nmap output: {output.splitlines()[0]}")
            return True
        except Exception as e:
            print(f"  [ERROR] Nmap execution failed: {e}")
            return False
    else:
        print(f"  [ERROR] Nmap NOT FOUND in temporary PATH.")
        return False

if __name__ == "__main__":
    if asyncio.run(verify_nmap_bundle()):
        print("\n[RESULT] Nmap sidecar verification SUCCESSFUL.")
    else:
        print("\n[RESULT] Nmap sidecar verification FAILED.")
        sys.exit(1)
