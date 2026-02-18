
"""
Internal Tool Cache Manager
===========================
Handles the discovery, metadata extraction, and caching of internal tools.
"""
import os
import sys
import json
import logging
from typing import List, Dict, Any, Optional
from langchain_core.tools import BaseTool
from datetime import datetime
import importlib
import hashlib
import time
import pkgutil

# List of packages to scan
PACKAGES = [
    "tools.utilities",
    "tools.recon",
    "tools.exploitation",
    "tools.web",
    "tools.ctf",
    "tools.evasion",
    "tools.intelligence",
    "tools.cloud",
    "tools.reverse_engineering",
    "tools.vr",
]

CACHE_FILE = os.path.join(os.path.dirname(__file__), ".internal_tool_cache.json")
# Determine project name for logger
try:
    _proj_name = os.path.basename(os.path.dirname(os.path.dirname(__file__))).upper()
except:
    _proj_name = "CORE"
logger = logging.getLogger(f"{_proj_name}.tools.cache_manager")

def _sanitize_schema(schema: Any) -> Optional[Dict]:
    """Ensure schema is a JSON-serializable dict."""
    if not schema: return None
    try:
        # V2 class
        if hasattr(schema, 'model_json_schema'):
            return schema.model_json_schema()

        # V2 instance
        if hasattr(schema, 'model_dump'): return schema.model_dump()
        
        if isinstance(schema, dict):
            # Verify serializability and size
            try:
                s = json.dumps(schema)
                if len(s) > 50000: return None
                return schema
            except:
                return None
        return None
    except: return None

def _refine_category(tool_name: str, current_category: str) -> str:
    """Refine tool category based on name keywords if current category is generic."""
    # Mapping for common industrial keywords
    name_lower = tool_name.lower()
    if any(k in name_lower for k in ["exploit", "attack", "payload", "infect", "pwn", "bypass", "vuln", "nuclei", "injection", "sqli", "xss", "ssrf"]):
        return "exploitation"
    if any(k in name_lower for k in ["scan", "recon", "shodan", "census", "whois", "dns", "subdomain", "map", "port", "search"]):
        return "recon"
    if any(k in name_lower for k in ["evade", "stealth", "obfuscate", "unhook", "mask", "hide", "av", "edr"]):
        return "evasion"
    if any(k in name_lower for k in ["process", "registry", "service", "system", "health", "disk", "net", "bash", "shell", "cmd"]):
        return "system"
    if any(k in name_lower for k in ["github", "repo", "commit", "issue", "branch", "intelligence", "threat", "cve"]):
        return "intelligence"
    if any(k in name_lower for k in ["file", "txt", "log", "archive", "compress", "hash", "base64"]):
        return "utilities"
    return current_category

def _extract_tool_metadata(obj: BaseTool, module_path: str, variable_name: str, default_cat: str) -> Dict[str, Any]:
    """Extract standard metadata from a tool object."""
    raw_schema = getattr(obj, 'args_schema', None)
    input_schema = _sanitize_schema(raw_schema)
    
    # Industrial Categorization
    category = getattr(obj, "category", default_cat)
    category = _refine_category(obj.name, category)

    return {
        "name": obj.name,
        "description": obj.description,
        "category": category,
        "module_path": module_path,
        "variable_name": variable_name,
        "input_schema": input_schema
    }

def get_tools_signature() -> str:
    """Generate a high-fidelity signature of the tools directory structure and file states."""
    sig_parts = []
    
    # Base path of the myth project
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    for pkg_name in PACKAGES:
        # Convert package name to file path
        pkg_rel_path = pkg_name.replace(".", os.sep)
        pkg_abs_path = os.path.join(base_dir, pkg_rel_path)
        
        if not os.path.exists(pkg_abs_path):
            continue
            
        # Scan files in the package directory
        for root, _, files in os.walk(pkg_abs_path):
            # Sort for deterministic hashing
            for f in sorted(files):
                if f.endswith(".py") and not f.startswith("__"):
                    f_path = os.path.join(root, f)
                    try:
                        f_stat = os.stat(f_path)
                        # We include path, size and modification time
                        sig_parts.append(f"{f_path}:{f_stat.st_size}:{f_stat.st_mtime}")
                    except Exception:
                        continue
    
    # Hash the cumulative state
    combined = "|".join(sig_parts)
    return hashlib.sha256(combined.encode()).hexdigest()

def rebuild_cache() -> List[Dict[str, Any]]:
    print("🔨 [CACHE] Rebuilding internal tool cache (Package Scan Mode)...")
    tools_data = []
    seen_names = set()
    
    for pkg_name in PACKAGES:
        print(f"🌀 Scanning {pkg_name}...")
        start_count = len(tools_data)
        try:
            # Base path of the myth project
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if base_dir not in sys.path:
                sys.path.append(base_dir)
                
            pkg_rel_path = pkg_name.replace(".", os.sep)
            pkg_abs_path = os.path.join(base_dir, pkg_rel_path)
            
            if not os.path.exists(pkg_abs_path):
                continue

            # Use pkg suffix as default category (e.g., tools.recon -> recon)
            default_cat = pkg_name.split(".")[-1] if "." in pkg_name else "utilities"
            
            # AGGRESSIVE DISCOVERY: Scan every .py file in the directory
            pkg = importlib.import_module(pkg_name)
            
            # Step A: Scan already imported items (Standard)
            for name in dir(pkg):
                if name.startswith("_"): continue
                obj = getattr(pkg, name)
                if isinstance(obj, BaseTool):
                    if obj.name not in seen_names:
                        seen_names.add(obj.name)
                        tools_data.append(_extract_tool_metadata(obj, pkg_name, name, default_cat))

            # Step B: Scan filesystem for sub-modules not yet imported
            for loader, module_name, is_pkg in pkgutil.walk_packages(pkg.__path__, pkg_name + "."):
                try:
                    module = importlib.import_module(module_name)
                    for name in dir(module):
                        if name.startswith("_"): continue
                        obj = getattr(module, name)
                        if isinstance(obj, BaseTool):
                            if obj.name not in seen_names:
                                seen_names.add(obj.name)
                                tools_data.append(_extract_tool_metadata(obj, module_name, name, default_cat))
                except Exception as e:
                    logger.debug(f"Skipping module {module_name}: {e}")
                    
            print(f"📦 {pkg_name}: Found {len(tools_data) - start_count} tools.")
            
        except ImportError as e:
            print(f"❌ Failed to load {pkg_name}: {e}")
        except Exception as e:
             print(f"⚠️ Error scanning {pkg_name}: {e}")

            
    cache_bundle = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "count": len(tools_data),
            "signature": get_tools_signature()
        },
        "tools": tools_data
    }
    
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_bundle, f, indent=2)
        print(f"✅ [CACHE] Built successfully with {len(tools_data)} tools.")
    except Exception as e:
        print(f"❌ [CACHE] Build failed: {e}")
        
    return tools_data

if __name__ == "__main__":
    rebuild_cache()
