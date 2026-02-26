"""
MYTH Desktop — Python Backend Packager
Bundles the FastAPI backend into a standalone binary for Tauri sidecar distribution.
Uses PyInstaller to create a platform-specific executable.
"""

import argparse
import os
import platform
import subprocess
import sys
import threading
import time
import warnings

import yaml

# Suppress annoying SyntaxWarnings from third-party libs (like ropper) during build
warnings.simplefilter("ignore", category=SyntaxWarning)

# MISSION CRITICAL: Force UTF-8 encoding for stdout/stderr on Windows
# BEFORE any print() calls that contain emoji characters.
# Windows default cp1252 cannot encode emoji → UnicodeEncodeError.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        import io

        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

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
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
        "i686": "i686",
        "x86": "i686",
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


def load_codename():
    """Load project codename from identity.yaml."""
    identity_path = os.path.join(PROJECT_ROOT, "governance", "identity.yaml")
    try:
        if os.path.exists(identity_path):
            with open(identity_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data.get("identity", {}).get("codename", "myth")
    except Exception:
        pass
    return "myth"


def build_backend(skip_if_exists=False):
    """Package the Python backend using PyInstaller."""
    target_triple = get_target_triple()
    system = platform.system().lower()
    codename = load_codename()

    # Output name must match the sidecar config in tauri.conf.json
    # Tauri expects: {codename}-backend-{target_triple}[.exe]
    ext = ".exe" if system == "windows" else ""
    output_name = f"{codename}-backend-{target_triple}{ext}"
    output_path = os.path.join(DIST_DIR, output_name)

    if skip_if_exists and os.path.exists(output_path):
        print(
            f"⏭️  [PACKAGER] Output exists and --skip-if-exists set. Skipping: {output_name}"
        )
        return

    os.makedirs(DIST_DIR, exist_ok=True)

    print(f"Packaging {codename.upper()} backend for: {target_triple}")
    print(f"Output: {output_path}")

    # PyInstaller invocation
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",  # Suppress admin-context deprecation & overwrite prompts in CI
        "--onefile",
        "--name",
        f"{codename}-backend-{target_triple}",
        "--distpath",
        DIST_DIR,
        "--workpath",
        os.path.join(PROJECT_ROOT, "build", "pyinstaller"),
        "--specpath",
        os.path.join(PROJECT_ROOT, "build"),
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
        "governance/identity.yaml",  # SSOT Identity
        "resources/nvidia_nim_models.txt",
        "resources/mistral_models.txt",
        "governance/secrets.template.yaml",  # Template only — real secrets loaded from AppData
        "pyproject.toml",  # Required for some tool metadata
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
    # ════════════════════════════════════════════════════════════════
    # Hidden Imports — 100% Dependency Inclusion logic as requested.
    # Synthesized from requirements.txt, requirements-desktop.txt, and pyproject.toml
    # ════════════════════════════════════════════════════════════════
    hidden_imports = [
        "PIL",
        "accelerate",
        "aiofile",
        "aiofiles",
        "aiohappyeyeballs",
        "aiohttp",
        "aiosignal",
        "altair",
        "altgraph",
        "annotated_doc",
        "annotated_types",
        "anyio",
        "attrs",
        "audioop",
        "authlib",
        "backoff",
        "backports.zstd",
        "bcrypt",
        "beartype",
        "bitsandbytes",
        "blinker",
        "boto3",
        "botocore",
        "brotli",
        "bs4",
        "cachetools",
        "caio",
        "capstone",
        "certifi",
        "cffi",
        "charset_normalizer",
        "click",
        "click_plugins",
        "colorama",
        "colored_traceback",
        "coloredlogs",
        "crayons",
        "cryptography",
        "cv2",
        "cyclopts",
        "dataclasses_json",
        "diffusers",
        "distro",
        "dnspython",
        "docker",
        "docstring_parser",
        "docutils",
        "dotenv",
        "duckduckgo_search",
        "email_validator",
        "emoji",
        "et_xmlfile",
        "exceptiongroup",
        "exifread",
        "faker",
        "fastapi",
        "fastmcp",
        "filebytes",
        "filelock",
        "filetype",
        "frozenlist",
        "fsspec",
        "gitdb",
        "git",
        "google.ai.generativelanguage",
        "google.api_core",
        "googleapiclient",
        "google.auth",
        "google_auth_httplib2",
        "google.cloud",
        "google.cloud.modelarmor",
        "google.genai",
        "google.generativeai",
        "serpapi",
        "googleapis_common_protos",
        "greenlet",
        "grpcio",
        "grpcio_status",
        "h11",
        "h2",
        "hatchling",
        "hf_xet",
        "high_performance",
        "hiredis",
        "hpack",
        "html5lib",
        "httpcore",
        "httplib2",
        "httptools",
        "httpx",
        "httpx_sse",
        "huggingface_hub",
        "humanfriendly",
        "hyperframe",
        "idna",
        "imagehash",
        "imageio",
        "importlib_metadata",
        "inflate64",
        "intervaltree",
        "invoke",
        "jaraco.classes",
        "jaraco.context",
        "jaraco.functools",
        "jinja2",
        "jiter",
        "jmespath",
        "joblib",
        "jsonpatch",
        "jsonpointer",
        "jsonref",
        "jsonschema",
        "jsonschema_path",
        "jsonschema_specifications",
        "keyring",
        "langchain",
        "langchain_classic",
        "langchain_community",
        "langchain_core",
        "langchain_google_community",
        "langchain_google_genai",
        "langchain_mcp_adapters",
        "langchain_mistralai",
        "langchain_nvidia_ai_endpoints",
        "langchain_openai",
        "langchain_qdrant",
        "langchain_text_splitters",
        "langdetect",
        "langgraph",
        "langgraph_checkpoint",
        "langgraph_prebuilt",
        "langgraph_sdk",
        "langsmith",
        "lazy_loader",
        "lief",
        "llvmlite",
        "loguru",
        "lxml",
        "magic",
        "mako",
        "markdown_it_py",
        "markdownify",
        "markupsafe",
        "marshmallow",
        "mcp",
        "mdurl",
        "more_itertools",
        "motor",
        "mpmath",
        "multidict",
        "multivolumefile",
        "mypy_extensions",
        "narwhals",
        "nest_asyncio",
        "networkx",
        "nltk",
        "nmapthon2",
        "numba",
        "numpy",
        "oauth2client",
        "olefile",
        "openai",
        "openapi_pydantic",
        "openpyxl",
        "opentelemetry_api",
        "orjson",
        "ormsgpack",
        "packaging",
        "pandas",
        "paramiko",
        "pathable",
        "patool",
        "pdfminer",
        "pdfplumber",
        "pefile",
        "piexif",
        "pip",
        "platformdirs",
        "playwright",
        "playwright_stealth",
        "plumbum",
        "portalocker",
        "primp",
        "propcache",
        "proto_plus",
        "protobuf",
        "psutil",
        "pwntools",
        "py7zr",
        "py_key_value_aio",
        "pyarrow",
        "pyasn1",
        "pyasn1_modules",
        "pybcj",
        "pycparser",
        "pycryptodome",
        "pycryptodomex",
        "pydantic",
        "pydantic_core",
        "pydantic_settings",
        "pydeck",
        "pyee",
        "pyelftools",
        "pygments",
        "pyinstaller",
        "pyinstaller_hooks_contrib",
        "pyjwt",
        "pymongo",
        "pynacl",
        "pyparsing",
        "pypdf",
        "pypdfium2",
        "pyperclip",
        "pyppmd",
        "pyreadline3",
        "pyserial",
        "pysocks",
        "dateutil",
        "iso639",
        "magic",
        "python_multipart",
        "nmap",
        "oxmsg",
        "whois",
        "pytz",
        "pywavelets",
        "pywin32",
        "pywin32_ctypes",
        "qdrant_client",
        "qrcode",
        "rapidfuzz",
        "rarfile",
        "redis",
        "referencing",
        "regex",
        "requests",
        "requests_file",
        "requests_toolbelt",
        "rich",
        "rich_rst",
        "ropgadget",
        "ropper",
        "rpds_py",
        "rpyc",
        "rsa",
        "ruff",
        "s3transfer",
        "safetensors",
        "scapy",
        "scipy",
        "sentence_transformers",
        "setuptools",
        "shellingham",
        "shodan",
        "six",
        "skimage",
        "sklearn",
        "smmap",
        "sniffio",
        "sortedcontainers",
        "soupsieve",
        "sqlalchemy",
        "sse_starlette",
        "starlette",
        "stegano",
        "stepic",
        "streamlit",
        "sympy",
        "tavily",
        "tenacity",
        "texttable",
        "threadpoolctl",
        "tifffile",
        "tiktoken",
        "tldextract",
        "tokenizers",
        "toml",
        "tomli",
        "torch",
        "torchaudio",
        "torchvision",
        "tornado",
        "tqdm",
        "transformers",
        "typer",
        "typer_slim",
        "typing_extensions",
        "typing_inspect",
        "typing_inspection",
        "tzdata",
        "ujson",
        "unicorn",
        "unix_ar",
        "unstructured",
        "unstructured_client",
        "uritemplate",
        "urllib3",
        "uuid_utils",
        "uvicorn",
        "watchdog",
        "watchfiles",
        "webencodings",
        "websockets",
        "wikipedia",
        "win32_setctime",
        "wrapt",
        "xlsxwriter",
        "xmltodict",
        "xxhash",
        "yaml",
        "yarl",
        "zipp",
        "zstandard",
        "config_loader",
        "dialog_worker",
        "myth_config",
        "myth_utils",
        "dateutil",
        "iso639",
        "pythonjsonlogger",
        "nmap",
        "oxmsg",
        "whois",
        "win32ctypes",
        "tavily",
        "autocommand",
        "backports",
        "inflect",
        "jaraco",
        "typeguard",
        "wheel",
        "pydocket",
        "Crypto",
        "multipart",
        "audioop",
        "serpapi",
        "grpc_status",
        "lupa",
        "pathvalidate",
        "prometheus_client",
        "proto",
        "py_key_value_shared",
        "skimage",
        "sklearn",
        "googleapiclient",
    ]

    # Specialized Deep Collection Strategy:
    # We use collect_all for libraries that are prone to causing AST recursion hangs
    # on Windows. This forces PyInstaller to collect their data and binaries directly
    # without doing the deep recursive module scan that times out.
    try:
        from PyInstaller.utils.hooks import collect_all

        # Heavy Modules that notoriously hang Windows PyInstaller analysis
        heavy_modules = [
            "playwright",
            "google",
            "grpc",
            "scipy",
            "torch",
            "transformers",
            "unstructured",
            "langchain",
            "pydantic",
        ]

        for hm in heavy_modules:
            try:
                datas, binaries, hidden = collect_all(hm)
                cmd += ["--collect-all", hm]
                # hidden_imports.extend(hidden) # Redundant with collect-all flag
            except ImportError:
                pass
    except ImportError:
        pass

    # Optimized hidden imports for robust bundling
    try:
        from PyInstaller.utils.hooks import collect_submodules

        # Dynamically discover all submodules for complex libraries
        hidden_imports += collect_submodules("langchain_core")
        hidden_imports += collect_submodules("pydantic")
    except ImportError:
        print("⚠️ [PACKAGER] PyInstaller hooks unavailable. Using static list.")

    # Strict Dependency Validation: Ensure every hidden import is actually importable
    # This prevents the "successful" build of a broken binary in CI environments
    # where the backend might be built without sufficient hydration.
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)

    print(
        f"🔍 [VALIDATOR] Checking {len(hidden_imports)} hidden imports for presence..."
    )
    missing_critical = []
    # Strict Enforcement: 100% of dependencies mentioned in requirements-desktop.txt
    # and the TOML extras MUST be present for the build to proceed.
    # Exception: 'nvidia' can be missing on non-GPU build runners.
    optional_imports = ["nvidia"]

    for imp in hidden_imports:
        # Skip validation for submodules where parent is validated or complex globs
        if "." in imp or "*" in imp:
            continue
        try:
            __import__(imp)
        except ImportError:
            if any(opt in imp for opt in optional_imports):
                print(f"💡 [VALIDATOR] Optional import missing (skipping): {imp}")
            else:
                missing_critical.append(imp)

    if missing_critical:
        print(f"❌ [VALIDATOR] CRITICAL DEPENDENCIES MISSING: {missing_critical}")
        print(
            "💡 The current environment is incomplete. Run 'uv sync' or activate the correct .venv."
        )
        sys.exit(1)

    for imp in hidden_imports:
        cmd += ["--hidden-import", imp]

    # --- Performance & Safety Exclusions ---
    # We only exclude things that are DEFINITELY not in requirements or cause crash.
    # We honor the "NOT MISS" rule for all packages in requirements/pyproject.
    exclusions = [
        "notebook",
        "tkinter",
        "PIL._tkinter",
        "matplotlib.tests",
        "numpy.tests",
        "pandas.tests",
        "torch.testing",
        # Explicitly exclude Windows DLLs on non-Windows to stop warnings
        "user32" if system != "windows" else None,
        "ole32" if system != "windows" else None,
        "shell32" if system != "windows" else None,
        "advapi32" if system != "windows" else None,
        "msvcrt" if system != "windows" else None,
        "wpcap",
    ]
    for ex in [e for e in exclusions if e]:
        cmd += ["--exclude-module", ex]

    hidden_imports += ["watchdog"]  # Required for FIM
    cmd += [
        "--noupx",
    ]

    # Don't show console window on Windows
    if system == "windows":
        cmd.append("--noconsole")

    # Entry point
    cmd.append(os.path.join(PROJECT_ROOT, "api.py"))

    print(
        f"Running: {' '.join(cmd[:5])}... ({len(cmd)} args, {len(hidden_imports)} hidden imports)"
    )

    # ════════════════════════════════════════════════════════════════
    # CI Heartbeat — Prevent no-output timeout during PyInstaller's
    # deep analysis phase which can go silent for >10 minutes.
    # ════════════════════════════════════════════════════════════════
    stop_heartbeat = threading.Event()

    def _heartbeat():
        while not stop_heartbeat.is_set():
            stop_heartbeat.wait(60)
            if not stop_heartbeat.is_set():
                elapsed = int(time.time() - start_time)
                print(
                    f"💓 [HEARTBEAT] PyInstaller still running... ({elapsed}s elapsed)",
                    flush=True,
                )

    start_time = time.time()
    heartbeat_thread = threading.Thread(target=_heartbeat, daemon=True)
    heartbeat_thread.start()

    # Propagate warning suppression into the PyInstaller subprocess.
    # This silences: PydanticDeprecatedSince20, text_unidecode collect_data_files,
    # libpcap provider, and wpcap.dll ctypes warnings from third-party libraries.
    build_env = {**os.environ}
    build_env["PYTHONWARNINGS"] = "ignore"
    build_env["SCAPY_USE_LIBPCAP"] = "no"

    try:
        result = subprocess.run(cmd, cwd=PROJECT_ROOT, env=build_env)
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=2)

    if result.returncode == 0:
        if os.path.exists(output_path):
            # Ensure executable permissions on POSIX systems
            if os.name == "posix":
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


def main():
    parser = argparse.ArgumentParser(
        description="Package MYTH backend for Tauri sidecar."
    )
    parser.add_argument(
        "--skip-if-exists",
        action="store_true",
        help="Skip build if output already exists.",
    )
    args = parser.parse_args()
    build_backend(skip_if_exists=args.skip_if_exists)


if __name__ == "__main__":
    main()
