#!/usr/bin/env python3
"""
audit_dependencies.py — Deep Source-Code Dependency Scanner
============================================================
Scans EVERY file in the MYTH project to extract:
  1. Python third-party imports (from actual `import` / `from` statements)
  2. Python stdlib modules used
  3. Internal project modules
  4. Node.js / npm packages (from actual `import` / `require` in JS/JSX)
  5. System-level binaries invoked (subprocess, os.system, shutil.which, etc.)
  6. Programming languages & file type statistics
  7. External APIs / services referenced

This does NOT read requirements.txt or pyproject.toml — it reads source code only.
"""

import os
import sys
import re
import ast
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from importlib.metadata import distributions
    VENV_PATH = str(ROOT / ".venv").lower()
    INSTALLED_PACKAGES = {}
    for d in distributions():
        name = d.metadata["Name"].lower()
        path = str(d.locate_file("")).lower()
        is_in_venv = VENV_PATH in path
        INSTALLED_PACKAGES[name] = {
            "version": d.version,
            "is_in_venv": is_in_venv
        }
    
    # Map import names to package names...
    PACKAGE_MAP = {
        "PIL": "pillow",
        "yaml": "pyyaml",
        "bs4": "beautifulsoup4",
        "dotenv": "python-dotenv",
        "duckduckgo_search": "duckduckgo-search",
        "sklearn": "scikit-learn",
        "cv2": "opencv-python",
        "serial": "pyserial",
        "telegram": "python-telegram-bot",
        "fitz": "pymupdf", 
        "jwt": "pyjwt",
        "faiss": "faiss-cpu",
        "dns": "dnspython",
        "dateutil": "python-dateutil",
        "mysqldb": "mysqlclient",
        "neo4j": "neo4j-driver",
        "jose": "python-jose",
        "openssl": "pyopenssl",
        "websocket": "websocket-client",
        "docker": "docker",
        "flask": "flask",
        "phonenumbers": "phonenumbers",
        "magic": "python-magic",
        "docx": "python-docx",
        "ppt": "python-pptx",
        "win32api": "pywin32",
        "win32con": "pywin32",
        "win32gui": "pywin32",
        "win32file": "pywin32",
        "pwn": "pwntools"
    }
except ImportError:
    INSTALLED_PACKAGES = {}
    PACKAGE_MAP = {}

# ─── Python stdlib module list (3.10-3.13) ────────────────────────────────────
# Comprehensive list of all stdlib top-level modules
STDLIB_MODULES = {
    "__future__", "_thread", "abc", "aifc", "argparse", "array", "ast",
    "asynchat", "asyncio", "asyncore", "atexit", "audioop", "base64",
    "bdb", "binascii", "binhex", "bisect", "builtins", "bz2", "calendar",
    "cgi", "cgitb", "chunk", "cmath", "cmd", "code", "codecs", "codeop",
    "collections", "colorsys", "compileall", "concurrent", "configparser",
    "contextlib", "contextvars", "copy", "copyreg", "cProfile", "crypt",
    "csv", "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
    "difflib", "dis", "distutils", "doctest", "email", "encodings",
    "enum", "errno", "faulthandler", "fcntl", "filecmp", "fileinput",
    "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt",
    "getpass", "gettext", "glob", "graphlib", "grp", "gzip", "hashlib",
    "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr",
    "imp", "importlib", "inspect", "io", "ipaddress", "itertools", "json",
    "keyword", "lib2to3", "linecache", "locale", "logging", "lzma",
    "mailbox", "mailcap", "marshal", "math", "mimetypes", "mmap",
    "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
    "numbers", "operator", "optparse", "os", "ossaudiodev", "pathlib",
    "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform",
    "plistlib", "poplib", "posix", "posixpath", "pprint", "profile",
    "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc",
    "queue", "quopri", "random", "re", "readline", "reprlib",
    "resource", "rlcompleter", "runpy", "sched", "secrets", "select",
    "selectors", "shelve", "shlex", "shutil", "signal", "site",
    "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "spwd",
    "sqlite3", "ssl", "stat", "statistics", "string", "stringprep",
    "struct", "subprocess", "sunau", "symtable", "sys", "sysconfig",
    "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios",
    "test", "textwrap", "threading", "time", "timeit", "tkinter",
    "token", "tokenize", "tomllib", "trace", "traceback", "tracemalloc",
    "tty", "turtle", "turtledemo", "types", "typing", "unicodedata",
    "unittest", "urllib", "uu", "uuid", "venv", "warnings", "wave",
    "weakref", "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib",
    "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
    # Also internal/private
    "_io", "_thread", "_abc", "_signal", "_collections_abc",
    "typing_extensions",  # very common, treat as near-stdlib
}

# ─── Known internal project packages ──────────────────────────────────────────
INTERNAL_PACKAGES = {
    "tools", "mcp_servers", "rag_system", "myth_utils", "testing",
    "myth_config", "myth_llm", "config_loader", "backend", "api",
    "run_desktop", "dialog_worker", "mcp_common",
}

# ─── File extension → Language mapping ────────────────────────────────────────
EXT_TO_LANG = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript (JSX/React)",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (TSX/React)",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "Sass",
    ".less": "Less",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".md": "Markdown",
    ".rst": "reStructuredText",
    ".txt": "Plain Text",
    ".sh": "Shell (Bash)",
    ".bash": "Shell (Bash)",
    ".ps1": "PowerShell",
    ".bat": "Batch Script",
    ".cmd": "Batch Script",
    ".sql": "SQL",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".r": "R",
    ".lua": "Lua",
    ".pl": "Perl",
    ".xml": "XML",
    ".svg": "SVG",
    ".wasm": "WebAssembly",
    ".proto": "Protocol Buffers",
    ".graphql": "GraphQL",
    ".dockerfile": "Dockerfile",
    ".env": "Environment Config",
    ".ini": "INI Config",
    ".cfg": "Config",
    ".conf": "Config",
    ".lock": "Lock File",
    ".map": "Source Map",
}

SKIP_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".git", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", "egg-info",
    ".tox", ".eggs", ".idea", ".vscode",
}


def scan_file_types(root: Path):
    """Scan all files and categorize by extension/language."""
    stats = defaultdict(lambda: {"count": 0, "files": [], "total_bytes": 0})
    
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            ext = fpath.suffix.lower()
            lang = EXT_TO_LANG.get(ext, f"Other ({ext})" if ext else "No Extension")
            
            try:
                size = fpath.stat().st_size
            except:
                size = 0
            
            stats[lang]["count"] += 1
            stats[lang]["total_bytes"] += size
            if len(stats[lang]["files"]) < 5:  # Keep sample of up to 5 files
                stats[lang]["files"].append(str(fpath.relative_to(root)))
    
    return dict(stats)


def build_internal_module_set(root: Path) -> set:
    """Build a set of ALL Python module names that exist in the project.
    This includes every .py file stem and every directory with __init__.py.
    This is the ground-truth for what is 'internal'."""
    internal = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel = Path(dirpath).relative_to(root)
        # Any directory with __init__.py is an internal package
        if "__init__.py" in filenames:
            for part in rel.parts:
                internal.add(part)
        for fname in filenames:
            if fname.endswith(".py"):
                stem = Path(fname).stem
                if stem != "__init__":
                    internal.add(stem)
    return internal

# Build the comprehensive internal set once at module load
_ALL_INTERNAL_STEMS = build_internal_module_set(ROOT)


def extract_python_imports(filepath: Path):
    """Use AST to extract all ABSOLUTE imports from a Python file.
    Relative imports (from . import x, from .foo import y) are SKIPPED
    because they are always internal."""
    imports = set()
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                # SKIP relative imports (level > 0 means from . or from .. etc.)
                if node.level > 0:
                    continue
                if node.module:
                    imports.add(node.module.split(".")[0])
    except (SyntaxError, ValueError, UnicodeDecodeError):
        # Fallback: regex-based extraction (less accurate, but gets us something)
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
            # Only match absolute imports (not starting with .)
            for match in re.finditer(r'^\s*import\s+([\w.]+)', source, re.MULTILINE):
                imports.add(match.group(1).split(".")[0])
            for match in re.finditer(r'^\s*from\s+([A-Za-z][\w.]+)\s+import', source, re.MULTILINE):
                imports.add(match.group(1).split(".")[0])
        except:
            pass
    return imports


def extract_js_imports(filepath: Path):
    """Extract npm package imports from JS/JSX/TS/TSX files."""
    imports = set()
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        # ES module imports: import X from 'package'
        for match in re.finditer(r'''import\s+.*?\s+from\s+['"]([^'"./][^'"]*?)['"]''', source):
            pkg = match.group(1).split("/")[0]
            if pkg.startswith("@"):
                pkg = match.group(1).split("/")[0] + "/" + match.group(1).split("/")[1] if "/" in match.group(1) else pkg
            imports.add(pkg)
        # require() calls
        for match in re.finditer(r'''require\s*\(\s*['"]([^'"./][^'"]*?)['"]''', source):
            pkg = match.group(1).split("/")[0]
            if pkg.startswith("@"):
                pkg = match.group(1).split("/")[0] + "/" + match.group(1).split("/")[1] if "/" in match.group(1) else pkg
            imports.add(pkg)
        # CSS/style imports
        for match in re.finditer(r'''import\s+['"]([^'"]+\.css)['"]''', source):
            imports.add(f"[CSS] {match.group(1)}")
    except:
        pass
    return imports


def extract_system_binaries(filepath: Path):
    """Scan for subprocess/os.system calls to find system tool dependencies."""
    binaries = set()
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        
        # subprocess.run/call/Popen patterns
        for match in re.finditer(
            r'''(?:subprocess\.(?:run|call|Popen|check_output|check_call|getoutput))\s*\(\s*\[?\s*['"]([\w./\\-]+)['"]''',
            source
        ):
            binaries.add(match.group(1))
        
        # os.system() calls
        for match in re.finditer(r'''os\.system\s*\(\s*['"f]([\w./\\-]+)''', source):
            binaries.add(match.group(1))
        
        # shutil.which() calls
        for match in re.finditer(r'''shutil\.which\s*\(\s*['"](\w+)['"]''', source):
            binaries.add(match.group(1))
        
        # Direct binary references in strings (common patterns)
        for match in re.finditer(
            r'''['"](?:which|command)\s*['"]\s*,\s*['"](\w+)['"]''',
            source
        ):
            binaries.add(match.group(1))
        
    except:
        pass
    return binaries


def extract_external_apis(filepath: Path):
    """Find API endpoints, URLs, and service references."""
    apis = set()
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        
        # HTTP URLs (API endpoints)
        for match in re.finditer(
            r'''https?://(?:api\.|www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})''',
            source
        ):
            domain = match.group(1).lower()
            # Skip common non-API domains
            if not any(skip in domain for skip in [
                "example.com", "localhost", "127.0.0.1", "0.0.0.0",
                "w3.org", "schema.org", "json-schema.org", "mozilla.org",
                "github.com/explosion", "pypi.org", "python.org"
            ]):
                apis.add(domain)
    except:
        pass
    return apis


def classify_python_import(module_name: str) -> str:
    """Classify a Python import as stdlib, internal, or third-party.
    Uses the dynamically built _ALL_INTERNAL_STEMS set for accurate detection."""
    if module_name in STDLIB_MODULES:
        return "stdlib"
    if module_name in INTERNAL_PACKAGES:
        return "internal"
    # Check against the dynamically built set of all project .py stems
    if module_name in _ALL_INTERNAL_STEMS:
        return "internal"
    # Check for existence as a file or package on disk
    if (ROOT / module_name).exists() or (ROOT / (module_name + ".py")).exists():
        return "internal"
    # Private modules are usually stdlib internals
    if module_name.startswith("_"):
        return "stdlib"
    return "third_party"


def main():
    print("=" * 70)
    print("  MYTH PROJECT — DEEP SOURCE CODE DEPENDENCY AUDIT")
    print("  Scanning every file for actual imports & dependencies")
    print("=" * 70)
    
    # ═══════════════════════════════════════════════════════════════════
    # 1. FILE TYPE / LANGUAGE STATISTICS
    # ═══════════════════════════════════════════════════════════════════
    print("\n\n[1/6] Scanning file types & programming languages...")
    file_stats = scan_file_types(ROOT)
    
    # ═══════════════════════════════════════════════════════════════════
    # 2. PYTHON IMPORTS
    # ═══════════════════════════════════════════════════════════════════
    print("[2/6] Extracting Python imports from all .py files...")
    all_py_imports = defaultdict(set)  # module -> set of files that import it
    py_files_scanned = 0
    
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                fpath = Path(dirpath) / fname
                py_files_scanned += 1
                imports = extract_python_imports(fpath)
                for imp in imports:
                    all_py_imports[imp].add(str(fpath.relative_to(ROOT)))
    
    # Classify imports
    stdlib_imports = {}
    internal_imports = {}
    third_party_imports = {}
    
    for mod, files in sorted(all_py_imports.items()):
        cat = classify_python_import(mod)
        if cat == "stdlib":
            stdlib_imports[mod] = files
        elif cat == "internal":
            internal_imports[mod] = files
        else:
            third_party_imports[mod] = files
    
    # ═══════════════════════════════════════════════════════════════════
    # 3. JS/JSX/TS IMPORTS
    # ═══════════════════════════════════════════════════════════════════
    print("[3/6] Extracting JS/JSX imports from UI files...")
    all_js_imports = defaultdict(set)
    js_files_scanned = 0
    
    for dirpath, dirnames, filenames in os.walk(ROOT / "ui"):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith((".js", ".jsx", ".ts", ".tsx")):
                fpath = Path(dirpath) / fname
                js_files_scanned += 1
                imports = extract_js_imports(fpath)
                for imp in imports:
                    all_js_imports[imp].add(str(fpath.relative_to(ROOT)))
    
    # ═══════════════════════════════════════════════════════════════════
    # 4. SYSTEM BINARIES
    # ═══════════════════════════════════════════════════════════════════
    print("[4/6] Scanning for system binary/tool invocations...")
    all_binaries = defaultdict(set)
    
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                fpath = Path(dirpath) / fname
                bins = extract_system_binaries(fpath)
                for b in bins:
                    all_binaries[b].add(str(fpath.relative_to(ROOT)))
    
    # ═══════════════════════════════════════════════════════════════════
    # 5. EXTERNAL APIs
    # ═══════════════════════════════════════════════════════════════════
    print("[5/6] Scanning for external API/service references...")
    all_apis = defaultdict(set)
    
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith((".py", ".js", ".jsx", ".yaml", ".yml", ".json", ".env")):
                fpath = Path(dirpath) / fname
                apis = extract_external_apis(fpath)
                for api in apis:
                    all_apis[api].add(str(fpath.relative_to(ROOT)))
    
    # ═══════════════════════════════════════════════════════════════════
    # 6. NODE.JS VERSION CHECK
    # ═══════════════════════════════════════════════════════════════════
    print("[6/6] Checking runtime versions...")
    
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    
    node_version = "not found"
    npm_version = "not found"
    uv_version = "not found"
    
    try:
        import subprocess
        # Using shell=True for Windows to find .cmd/.exe easily in PATH
        result = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=5, shell=(os.name == 'nt'))
        if result.returncode == 0:
            node_version = result.stdout.strip()
    except:
        pass
    try:
        result = subprocess.run(["npm", "--version"], capture_output=True, text=True, timeout=5, shell=(os.name == 'nt'))
        if result.returncode == 0:
            npm_version = result.stdout.strip()
    except:
        pass
    try:
        result = subprocess.run(["uv", "--version"], capture_output=True, text=True, timeout=5, shell=(os.name == 'nt'))
        if result.returncode == 0:
            uv_version = result.stdout.strip()
    except:
        pass
    
    # ═══════════════════════════════════════════════════════════════════
    # BUILD THE REPORT
    # ═══════════════════════════════════════════════════════════════════
    
    report = []
    report.append("# MYTH Project — Complete Dependency & Technology Audit")
    report.append(f"> Auto-generated from source code analysis (NOT from requirements.txt/pyproject.toml)")
    report.append(f"> Scanned: **{py_files_scanned}** Python files, **{js_files_scanned}** JS/JSX files")
    report.append("")
    
    # --- Runtime Versions ---
    report.append("## Runtime Versions")
    report.append("")
    report.append("| Runtime | Version |")
    report.append("|---------|---------|")
    report.append(f"| Python | {py_version} |")
    report.append(f"| uv | {uv_version} |")
    report.append(f"| Node.js | {node_version} |")
    report.append(f"| npm | {npm_version} |")
    report.append(f"| OS | {sys.platform} ({os.name}) |")
    report.append("")
    
    # --- Programming Languages ---
    report.append("## Programming Languages & File Types")
    report.append("")
    report.append("| Language | Files | Total Size |")
    report.append("|----------|------:|------------|")
    
    sorted_langs = sorted(file_stats.items(), key=lambda x: x[1]["count"], reverse=True)
    for lang, info in sorted_langs:
        size_kb = info["total_bytes"] / 1024
        if size_kb > 1024:
            size_str = f"{size_kb/1024:.1f} MB"
        else:
            size_str = f"{size_kb:.1f} KB"
        report.append(f"| {lang} | {info['count']} | {size_str} |")
    report.append("")
    
    # --- Python Third-Party Dependencies ---
    report.append("## Python Third-Party Dependencies (from source imports)")
    report.append("")
    report.append(f"**{len(third_party_imports)}** unique third-party packages imported across {py_files_scanned} Python files.")
    report.append("")
    report.append("| # | Import Name | Status | Used In (files) | Sample Locations |")
    report.append("|--:|-------------|--------|----------------:|------------------|")
    
    sorted_tp = sorted(third_party_imports.items(), key=lambda x: len(x[1]), reverse=True)
    install_pkgs = []
    
    for i, (mod, files) in enumerate(sorted_tp, 1):
        sample = ", ".join(sorted(files)[:3])
        # Verify installation status
        is_installed = False
        installed_version = "Not Installed"
        loc_suffix = ""
        
        # Normalize for comparison (replace _ with -)
        mod_norm = mod.lower().replace("_", "-")
        
        # Determine install name
        install_name = mod_norm
        if mod in PACKAGE_MAP:
            install_name = PACKAGE_MAP[mod].lower()
        
        if install_name not in install_pkgs:
            install_pkgs.append(install_name)
            
        # Check direct name (normalized)
        if install_name in INSTALLED_PACKAGES:
            is_installed = True
            info = INSTALLED_PACKAGES[install_name]
            installed_version = info["version"]
            loc_suffix = " (venv)" if info["is_in_venv"] else " (global)"
        # Check mapped name
        elif mod in PACKAGE_MAP and PACKAGE_MAP[mod].lower() in INSTALLED_PACKAGES:
            is_installed = True
            info = INSTALLED_PACKAGES[PACKAGE_MAP[mod].lower()]
            installed_version = info["version"]
            loc_suffix = " (venv)" if info["is_in_venv"] else " (global)"
            mod = f"{mod} ({PACKAGE_MAP[mod]})"
            
        status_icon = "✅" if is_installed else "⚠️"
        if not is_installed and mod in ["win32", "win32api", "win32con", "win32file"]: # special handling for pywin32 modules often missed
             if "pywin32" in INSTALLED_PACKAGES:
                 is_installed = True
                 info = INSTALLED_PACKAGES["pywin32"]
                 installed_version = info["version"]
                 loc_suffix = " (venv)" if info["is_in_venv"] else " (global)"
                 status_icon = "✅"

        report.append(f"| {i} | `{mod}` | {status_icon} {installed_version}{loc_suffix} | {len(files)} | {sample} |")
    report.append("")
    
    # --- Installation Command ---
    report.append("### Installation Command")
    report.append("To install all discovered dependencies, run:")
    report.append(f"```bash\nuv pip install {' '.join(sorted(install_pkgs))}\n```")
    report.append("")
    
    # --- Python Stdlib ---
    report.append("## Python Standard Library Modules Used")
    report.append("")
    report.append(f"**{len(stdlib_imports)}** stdlib modules referenced.")
    report.append("")
    sorted_stdlib = sorted(stdlib_imports.items(), key=lambda x: len(x[1]), reverse=True)
    stdlib_list = ", ".join(f"`{m}` ({len(f)})" for m, f in sorted_stdlib)
    report.append(stdlib_list)
    report.append("")
    
    # --- Internal Modules ---
    report.append("## Internal Project Modules")
    report.append("")
    report.append(f"**{len(internal_imports)}** internal packages/modules.")
    report.append("")
    for mod, files in sorted(internal_imports.items(), key=lambda x: len(x[1]), reverse=True):
        report.append(f"- `{mod}` — imported in {len(files)} files")
    report.append("")
    
    # --- Node.js / npm Dependencies ---
    report.append("## Node.js / npm Dependencies (from source imports)")
    report.append("")
    report.append(f"**{len(all_js_imports)}** unique packages imported across {js_files_scanned} JS/JSX files.")
    report.append("")
    report.append("| Package | Used In (files) | Sample Locations |")
    report.append("|---------|----------------:|------------------|")
    
    sorted_js = sorted(all_js_imports.items(), key=lambda x: len(x[1]), reverse=True)
    for pkg, files in sorted_js:
        if pkg.startswith("[CSS]"):
            continue
        sample = ", ".join(sorted(files)[:3])
        report.append(f"| `{pkg}` | {len(files)} | {sample} |")
    report.append("")
    
    # --- System Binaries ---
    report.append("## System Binaries & External Tools")
    report.append("")
    if all_binaries:
        report.append(f"**{len(all_binaries)}** external programs/tools invoked via subprocess or os.system.")
        report.append("")
        report.append("| Binary/Tool | Referenced In |")
        report.append("|-------------|---------------|")
        for binary, files in sorted(all_binaries.items()):
            sample = ", ".join(sorted(files)[:3])
            report.append(f"| `{binary}` | {sample} |")
    else:
        report.append("No external binaries detected via subprocess/os.system scans.")
    report.append("")
    
    # --- External APIs ---
    report.append("## External APIs & Services Referenced")
    report.append("")
    report.append(f"**{len(all_apis)}** unique external domains found in source code.")
    report.append("")
    report.append("| Domain | Referenced In (files) |")
    report.append("|--------|---------------------:|")
    
    sorted_apis = sorted(all_apis.items(), key=lambda x: len(x[1]), reverse=True)
    for domain, files in sorted_apis:
        report.append(f"| `{domain}` | {len(files)} |")
    report.append("")
    
    # ═══════════════════════════════════════════════════════════════════
    # WRITE TO FILE
    # ═══════════════════════════════════════════════════════════════════
    
    output_path = ROOT / "testing" / "DEPENDENCIES.md"
    output_path.write_text("\n".join(report), encoding="utf-8")
    
    print(f"\n{'='*70}")
    print(f"  AUDIT COMPLETE")
    print(f"  Python files scanned:  {py_files_scanned}")
    print(f"  JS/JSX files scanned:  {js_files_scanned}")
    print(f"  Third-party Python:    {len(third_party_imports)} packages")
    print(f"  Stdlib Python:         {len(stdlib_imports)} modules")
    print(f"  npm packages:          {len(all_js_imports)} packages")
    print(f"  System binaries:       {len(all_binaries)} tools")
    print(f"  External APIs:         {len(all_apis)} domains")
    print(f"  Languages detected:    {len(file_stats)} types")
    print(f"  Report written to:     {output_path}")
    print(f"{'='*70}")
    
    return report


if __name__ == "__main__":
    main()
