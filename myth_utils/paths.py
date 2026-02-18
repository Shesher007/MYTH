import os
import sys
from typing import Optional


def is_frozen() -> bool:
    """Detect if we are running inside a PyInstaller-frozen binary."""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')


def get_resource_path(relative_path: str) -> str:
    """
    Resolve resource paths for both source-mode, PyInstaller-bundled mode,
    and Tauri external resource bundles.
    """
    # 1. PyInstaller Internal Bundle (_MEIPASS)
    if hasattr(sys, '_MEIPASS'):
        internal_path = os.path.join(sys._MEIPASS, relative_path)
        if os.path.exists(internal_path):
            return internal_path
    
    # 2. Tauri External Resources (Production Bundle)
    # Sidecar is in a binary folder, resources are usually in a sibling 'resources' folder
    exe_path = sys.executable
    exe_dir = os.path.dirname(exe_path)
    # Check common Tauri resource locations relative to sidecar
    for parent in [exe_dir, os.path.dirname(exe_dir)]:
        tauri_res_path = os.path.join(parent, "resources", relative_path)
        if os.path.exists(tauri_res_path):
            return tauri_res_path

    # 3. Development Mode (Source Root)
    base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base_path, relative_path)

def get_sidecar_dir() -> Optional[str]:
    """
    Resolve the directory containing sidecar binaries.
    In bundled mode, they are usually in the same directory as the executable.
    In development, we look in ui/src-tauri/binaries.
    """
    exe_dir = os.path.dirname(sys.executable)
    
    # Production Check: Use is_frozen() for reliable detection
    if is_frozen():
        # In Tauri 2, if externalBin uses "binaries/name", 
        # the binaries are often placed in a 'binaries' subfolder next to the exe
        binaries_subfolder = os.path.join(exe_dir, "binaries")
        if os.path.isdir(binaries_subfolder):
            return binaries_subfolder
        if os.path.isdir(exe_dir):
            return exe_dir
        # Fallback: Check _MEIPASS for bundled assets
        if hasattr(sys, '_MEIPASS'):
            return sys._MEIPASS


    # Development Check
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    dev_path = os.path.join(root, "ui", "src-tauri", "binaries")
    if os.path.exists(dev_path):
        return dev_path
        
    return None

def get_app_data_path(sub_path: str = "") -> str:
    """
    Returns a persistent path in the user's application data directory.
    - Path is dynamically determined by identity.yaml
    """
    if os.name == "nt":
        base = os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
    
    # Dynamic Identity Load for paths
    def _get_app_name():
        try:
            import yaml
            # Find root via sibling or parent search
            root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            id_path = os.path.join(root, "governance", "identity.yaml")
            if not os.path.exists(id_path):
                id_path = os.path.join(root, "identity.yaml")
                
            if os.path.exists(id_path):
                with open(id_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    return data.get("name", "PROJECT").upper()
        except: pass
        return "PROJECT"

    app_name = _get_app_name()
    app_data_root = os.path.join(base, app_name)
    os.makedirs(app_data_root, exist_ok=True)
    
    if sub_path:
        final_path = os.path.join(app_data_root, sub_path)
        # Ensure subdirectories exist (e.g., 'logs', 'db')
        if not os.path.splitext(sub_path)[1]: # If it's a directory
            os.makedirs(final_path, exist_ok=True)
        else: # If it's a file, ensure parent dir exists
            os.makedirs(os.path.dirname(final_path), exist_ok=True)
        return final_path
        
    return app_data_root
