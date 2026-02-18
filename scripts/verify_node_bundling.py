import os
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from mcp_servers.mcp_client import _get_node_runtime_path, _get_npx_cmd, _is_npx_available

def verify_bundled_node():
    print("[VERIFY] Testing Bundled Node.js Detection...")
    
    node_path = _get_node_runtime_path()
    if node_path:
        print(f"  [SUCCESS] Bundled Node Path: {node_path}")
    else:
        print("  [ERROR] Bundled Node NOT FOUND.")
        return False
        
    npx_cmd = _get_npx_cmd()
    print(f"  [INFO] NPX Command: {npx_cmd}")
    
    available = _is_npx_available()
    print(f"  [INFO] NPX Available: {available}")
    
    if node_path and available:
        print("\n[RESULT] Verification SUCCESSFUL. MYTH is now 100% standalone for Node.js tools.")
        return True
    return False

if __name__ == "__main__":
    if not verify_bundled_node():
        sys.exit(1)
