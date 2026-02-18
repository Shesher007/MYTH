"""
MYTH Desktop — Python Backend Packager
Bundles the FastAPI backend into a standalone binary for Tauri sidecar distribution.
Uses PyInstaller to create a platform-specific executable.
"""

import os
import sys
import platform
import subprocess
import warnings

# Suppress annoying SyntaxWarnings from third-party libs (like ropper) during build
warnings.simplefilter("ignore", category=SyntaxWarning)

# MISSION CRITICAL: Force UTF-8 encoding for stdout/stderr on Windows
# BEFORE any print() calls that contain emoji characters.
# Windows default cp1252 cannot encode emoji → UnicodeEncodeError.
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIST_DIR = os.path.join(PROJECT_ROOT, "ui", "src-tauri", "binaries")

def get_target_triple():
    """Determine the Rust-style target triple for the current platform."""
    # Allow CI to override the target triple for cross-compilation.
    # macOS runners are ARM64, so building for x86_64 requires this override.
    env_target = os.environ.get("TAURI_TARGET_TRIPLE")
    if env_target:
        return env_target

    machine = platform.machine().lower()
    system = platform.system().lower()

    arch_map = {
        "x86_64": "x86_64", "amd64": "x86_64",
        "aarch64": "aarch64", "arm64": "aarch64",
        "i686": "i686", "x86": "i686",
    }
    arch = arch_map.get(machine, machine)

    if system == "windows":
        return f"{arch}-pc-windows-msvc"
    elif system == "darwin":
        return f"{arch}-apple-darwin"
    elif system == "linux":
        return f"{arch}-unknown-linux-gnu"
    else:
        return f"{arch}-unknown-{system}"


def build_backend():
    """Package the Python backend using PyInstaller."""
    target_triple = get_target_triple()
    system = platform.system().lower()

    # Output name must match the sidecar config in tauri.conf.json
    # Tauri expects: myth-backend-{target_triple}[.exe]
    ext = ".exe" if system == "windows" else ""
    output_name = f"myth-backend-{target_triple}{ext}"
 
    os.makedirs(DIST_DIR, exist_ok=True)
 
    print(f"Packaging MYTH backend for: {target_triple}")
    print(f"Output: {os.path.join(DIST_DIR, output_name)}")

    # PyInstaller invocation
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", f"myth-backend-{target_triple}",
        "--distpath", DIST_DIR,
        "--workpath", os.path.join(PROJECT_ROOT, "build", "pyinstaller"),
        "--specpath", os.path.join(PROJECT_ROOT, "build"),
    ]

    # Include recursive toolsets and mission-critical data
    target_folders = [
        "tools",
        "mcp_servers",
        "rag_system",
        "myth_utils",
        "honeypot",
    ]
    
    mandatory_assets = [
        "governance/agent_manifest.yaml",
        "governance/identity.yaml",           # SSOT Identity
        "resources/nvidia_nim_models.txt",
        "resources/mistral_models.txt",
        "governance/secrets.template.yaml",    # Template only — real secrets loaded from AppData
        "pyproject.toml",           # Required for some tool metadata
    ]

    for folder in target_folders:
        folder_path = os.path.join(PROJECT_ROOT, folder)
        if os.path.exists(folder_path):
            # Industry-Grade Safeguard: Ensure no tool templates are bundled
            if folder == "templates":
                print("🚫 [SAFEGUARD] Skipping bundle of tool templates directory.")
                continue
            cmd += ["--add-data", f"{folder_path}{os.pathsep}{folder}"]
        else:
            print(f"⚠️  [PACKAGER] Folder missing (skipping): {folder}")

    for asset in mandatory_assets:
        asset_path = os.path.join(PROJECT_ROOT, asset)
        if os.path.exists(asset_path):
            # We want them at the root of the executable in bundled mode, 
            # except if we want to keep the subdirectory structure.
            # PyInstaller --add-data "src;dest"
            if "resources/" in asset:
                dest = "resources"
                cmd += ["--add-data", f"{asset_path}{os.pathsep}{dest}"]
            elif "governance/" in asset:
                dest = "governance"
                cmd += ["--add-data", f"{asset_path}{os.pathsep}{dest}"]
            else:
                cmd += ["--add-data", f"{asset_path}{os.pathsep}."]
        else:
            print(f"⚠️  [PACKAGER] Asset missing (skipping): {asset}")

    # ════════════════════════════════════════════════════════════════
    # Hidden Imports — All dynamically imported modules that PyInstaller
    # cannot discover via static analysis. Missing any of these causes
    # runtime ImportError in the frozen binary.
    # ════════════════════════════════════════════════════════════════
    hidden_imports = [
        # --- Web Framework & Server ---
        "uvicorn", "uvicorn.logging", "uvicorn.loops", "uvicorn.loops.auto",
        "uvicorn.protocols", "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets", "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan", "uvicorn.lifespan.on",
        "fastapi", "pydantic", "starlette",
        "sse_starlette",

        # --- MCP Infrastructure ---
        "mcp", "fastmcp", "langchain_mcp_adapters",
        "mcp.client.sse", "mcp.client.stdio",
        "mcp_servers.mcp_common",

        # --- MCP Server Modules (for in-process frozen-mode loading) ---
        "mcp_servers.local_servers.system_tools",
        "mcp_servers.local_servers.browser_tools",
        "mcp_servers.local_servers.filesystem_tools",
        "mcp_servers.local_servers.db_tools",
        "mcp_servers.local_servers.docker_tools",
        "mcp_servers.local_servers.fetch_server",
        "mcp_servers.local_servers.curl_server",
        "mcp_servers.custom_servers.security_tools",
        "mcp_servers.custom_servers.nuclei_server",
        "mcp_servers.custom_servers.burp_server",
        "mcp_servers.custom_servers.target_tracker_server",
        "mcp_servers.custom_servers.recon_server",
        "mcp_servers.custom_servers.exploit_hub_server",
        "mcp_servers.custom_servers.report_gen_server",
        "mcp_servers.remote_servers.external_apis",
        "mcp_servers.remote_servers.shodan_server",
        "mcp_servers.remote_servers.censys_server",
        "mcp_servers.remote_servers.securitytrails_server",
        "mcp_servers.remote_servers.virustotal_server",
        "mcp_servers.remote_servers.hunter_server",
        "mcp_servers.remote_servers.hibp_server",
        "mcp_servers.remote_servers.nvd_server",
        "mcp_servers.remote_servers.exploitdb_server",
        "mcp_servers.remote_servers.gh_advisory_server",
        "mcp_servers.remote_servers.cisa_kev_server",

        # --- LangChain / AI Providers ---
        "langchain_openai", "langchain_community",
        "langchain_nvidia_ai_endpoints", "langchain_mistralai", "langchain_google_genai",
        "langchain_text_splitters",

        # --- Vector Store / RAG ---
        "sentence_transformers", "qdrant_client", "numpy",

        # --- Browser Automation ---
        "playwright", "playwright.async_api", "playwright_stealth", "playwright.__main__",

        # --- Reverse Engineering ---
        "pefile", "lief", "capstone", "ropper",

        # --- Network Analysis ---
        "scapy", "scapy.all",

        # --- HTTP & Networking ---
        "httpx", "httpx_sse", "requests",
        "tldextract", "dns", "dns.resolver",

        # --- Async & Resilience ---
        "backoff", "tenacity", "nest_asyncio",

        # --- Content Processing ---
        "markdownify", "bs4",

        # --- Config & Serialization ---
        "yaml", "orjson", "jinja2",

        # --- Logging ---
        "loguru", "rich", "colorama", "coloredlogs",

        # --- System ---
        "psutil", "aiofiles",

        # --- Myth Internal ---
        "myth_utils", "myth_utils.paths", "myth_utils.sanitizer",
        "myth_config", "config_loader", "dialog_worker",
    ]

    # Optimized hidden imports for robust bundling
    try:
        from PyInstaller.utils.hooks import collect_submodules
        # Dynamically discover all submodules for complex libraries
        hidden_imports += collect_submodules("langchain_core")
        hidden_imports += collect_submodules("pydantic")
    except ImportError:
        print("⚠️ [PACKAGER] PyInstaller hooks unavailable. Using static list.")

    for imp in hidden_imports:
        cmd += ["--hidden-import", imp]

    # Reduce bloat by excluding non-runtime dependencies
    exclusions = [
        "notebook", "ipython", "tkinter", "matplotlib", "PIL._tkinter",
        "triton",  # Linux-only, huge
        "torch.testing", "torch.utils.benchmark", "torch.distributed",  # Dev/Test tools
        "matplotlib.tests", "numpy.tests", "pandas.tests",  # Test suites
        # --- GPU/CUDA libraries (>3GB on Linux, causes 4GB struct.error overflow) ---
        "nvidia", "nvidia.cuda_runtime", "nvidia.cublas", "nvidia.cudnn",
        "nvidia.cufft", "nvidia.curand", "nvidia.cusolver", "nvidia.cusparse",
        "nvidia.nccl", "nvidia.nvjitlink", "nvidia.nvtx",
        "nvidia.cufile", "nvidia.nvshmem", "nvidia.cusparselt",
        "torch.cuda", "torch.backends.cuda", "torch.backends.cudnn",
        "torchaudio", "torchvision",
        # --- Additional torch bloat not needed at runtime ---
        "torch._inductor", "torch._dynamo", "torch._export", "torch._functorch",
        "torch.onnx", "torch.fx", "torch.ao", "torch.quantization",
        "sympy",  # Only pulled in by torch, not used in MYTH directly
        # --- Massive ML Bloat (API-based alternatives used) ---
        "torch", "transformers", "unstructured", "unstructured_client",
        "sentence_transformers", "onnxruntime", "scikit_learn", "scipy",
        # --- Windows crash prevention ---
        "magic.compat",  # access violation in libmagic ctypes on Windows
    ]
    for ex in exclusions:
        cmd += ["--exclude-module", ex]
    
    hidden_imports += ["watchdog"] # Required for FIM
    cmd += [
        "--noupx",
        "--strip",
    ]

    # Don't show console window on Windows
    if system == "windows":
        cmd.append("--noconsole")

    # Entry point
    cmd.append(os.path.join(PROJECT_ROOT, "api.py"))

    print(f"Running: {' '.join(cmd[:5])}... ({len(cmd)} args, {len(hidden_imports)} hidden imports)")

    result = subprocess.run(cmd, cwd=PROJECT_ROOT)

    if result.returncode == 0:
        output_path = os.path.join(DIST_DIR, output_name)
        if os.path.exists(output_path):
            # Ensure executable permissions on POSIX systems
            if os.name == 'posix':
                try:
                    os.chmod(output_path, 0o755)
                    print(f"✅ Set executable permissions (0755) on {output_name}")
                except Exception as e:
                    print(f"⚠️ Failed to set permissions: {e}")

            size_mb = os.path.getsize(output_path) / (1024 * 1024)
            print(f"✅ Backend packaged successfully: {output_name} ({size_mb:.1f} MB)")
        else:
            print(f"Build completed but output not found at: {output_path}")
    else:
        print(f"❌ Backend packaging failed (exit code: {result.returncode})")
        sys.exit(1)


if __name__ == "__main__":
    build_backend()
