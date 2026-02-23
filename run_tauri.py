import json
import os
import signal
import socket
import subprocess
import sys
import time
import warnings
from pathlib import Path

from myth_utils.paths import resolve_sidecar_binary

import psutil

# Industry Grade: Suppress noisy third-party SyntaxWarnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
from config_loader import agent_config  # noqa: E402


def scorch_earth_cleanup(ports=[8888, 8890, 5173] + list(range(8001, 8211))):
    """Industrial Grade: Deep-scans system for zombie backends and terminates them."""
    print(
        f"🧹 [CLEANUP] Scouring system for legacy {agent_config.identity.name} infrastructure..."
    )
    current_pid = os.getpid()
    project_root = str(Path(__file__).parent.absolute()).lower()

    # 1. Kill by Port Association
    try:
        connections = psutil.net_connections(kind="inet")
        for port in ports:
            for conn in connections:
                if conn.laddr.port == port and conn.pid and conn.pid > 0:
                    try:
                        proc = psutil.Process(conn.pid)
                        if proc.pid == current_pid:
                            continue
                        print(
                            f"   🗑️  [CLEANUP] Terminating zombie on port {port} (PID: {proc.pid})..."
                        )
                        proc.kill()
                        proc.wait(timeout=3)
                    except Exception:
                        pass
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    # 2. Kill by Command Line Fingerprint (Deep Scan)
    lineage = [current_pid]
    try:
        curr = psutil.Process(current_pid)
        while curr.ppid() > 0:
            lineage.append(curr.ppid())
            curr = psutil.Process(curr.ppid())
    except Exception:
        pass

    for proc in psutil.process_iter(["pid", "name", "cmdline", "cwd"]):
        try:
            pinfo = proc.info
            if not pinfo["cmdline"] or pinfo["pid"] in lineage:
                continue

            cmd_str = " ".join(pinfo["cmdline"]).lower()

            # SURGICAL TARGETING
            is_backend = ("uvicorn" in cmd_str and "api:app" in cmd_str) or (
                "python" in cmd_str and "api.py" in cmd_str
            )
            is_mcp = "python" in cmd_str and "mcp_servers" in cmd_str
            is_frontend = ("vite" in cmd_str and "dev" in cmd_str) or (
                "tauri" in cmd_str and "dev" in cmd_str
            )

            is_in_project = pinfo["cwd"] and project_root in pinfo["cwd"].lower()
            is_protected_name = pinfo["name"].lower() in [
                "powershell.exe",
                "pwsh.exe",
                "cmd.exe",
                "conhost.exe",
                "antigravity.exe",
            ]

            if (
                is_backend
                or is_frontend
                or is_mcp
                or (is_in_project and not is_protected_name)
            ):
                try:
                    print(
                        f"   🗑️  [CLEANUP] Purging industrial ghost: {pinfo['name']} (PID: {pinfo['pid']})"
                    )
                    p = psutil.Process(pinfo["pid"])
                    p.kill()
                except Exception:
                    pass
        except Exception:
            pass


def kill_process_on_port(port):
    """Fallback: Standard netstat cleanup for port specific targets."""
    scorch_earth_cleanup([port])


def wait_for_port(port, host="127.0.0.1", timeout=30):
    """Wait for a port to become reachable."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(1)
    return False


def is_admin():
    """Industrial: Check for elevated privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (AttributeError, ImportError):
        try:
            return os.getuid() == 0
        except AttributeError:
            return False


def sidecar_preflight_check():
    """Verify essential sidecars are present before starting."""
    print("📋 [PRE-FLIGHT] Verifying industrial sidecars...")
    essentials = ["nmap", "nuclei", "subfinder", "httpx"]
    missing = []
    
    for tool in essentials:
        resolved = resolve_sidecar_binary(tool)
        if resolved:
            print(f"   ✅ [FOUND] {tool}: {Path(resolved).name}")
        else:
            missing.append(tool)
    
    if missing:
        print(f"   ⚠️ [WARN] Missing sidecars: {', '.join(missing)}")
        print("   💡 Run 'python scripts/install_nmap_sidecar.py' or ensure binaries are in ui/src-tauri/binaries")
    else:
        print("   ✨ [PASS] All essential sidecars verified.")
    print()


def run_myth_tauri():
    banner = """
    ⌬ {agent_config.identity.name} | {agent_config.identity.codename} (TAURI INDUSTRIAL)
    ----------------------------
    Initializing Peak industrial Infrastructure...
    Region: {agent_config.runtime.region} | Node: {agent_config.runtime.node_id}
    """
    print(banner)

    root_dir = Path(__file__).parent.absolute()
    ui_dir = root_dir / "ui"

    # 1. Start Pre-flight sidecar verification
    sidecar_preflight_check()

    # Check for uv venv
    venv_python = (
        root_dir / ".venv" / "Scripts" / "python.exe"
        if sys.platform == "win32"
        else root_dir / ".venv" / "bin" / "python"
    )

    if not venv_python.exists():
        print(f"❌ Error: UV virtual environment not found at {venv_python}")
        return

    # 0. Admin Status Check
    if not is_admin():
        print("⚠️ [WARN] Not running with Administrative privileges.")
        print("   💡 Some industrial networking tools (Nmap/Scapy) may fail in production.")
        print("   💡 For 100% accuracy, consider running this script as Administrator.")
        print()

    # 2. Port Cleanup & Audit Reset
    print("🧹 [0/3] Cleaning industrial infrastructure (8888, 8890, 5173)...")
    scorch_earth_cleanup()

    # Industrial Audit Reset
    prefix = agent_config.identity.name.lower()
    possible_audit_logs = [
        root_dir / f".{prefix}_audit.log",
        root_dir / f"{prefix}_system.log",
    ]

    for log_path in possible_audit_logs:
        if log_path.exists():
            try:
                with open(log_path, "w") as f:
                    pass
                print(f"   ✅ [CLEANUP] Reset: {log_path.name}")
            except Exception:
                pass

    # Wait for port 8890 to be definitively free
    print("   ⏳ Waiting for port 8890 to be released...")
    for _ in range(5):
        try:
            with socket.create_connection(("127.0.0.1", 8890), timeout=1):
                time.sleep(1)
        except (ConnectionRefusedError, socket.timeout, OSError):
            break

    # Clear Python bytecode cache
    print("   🗑️ Clearing bytecode cache...")
    import shutil

    for cache_dir in root_dir.rglob("__pycache__"):
        if ".venv" not in str(cache_dir):
            try:
                shutil.rmtree(cache_dir)
            except Exception:
                pass

    # 1. Start FastAPI Backend
    print("🚀 [1/3] Starting FastAPI Engine (Persistence Lock: ON)...")
    api_cmd = [
        str(venv_python),
        "api.py",
        "--host",
        "127.0.0.1",
        "--port",
        "8890",
    ]

    api_env = os.environ.copy()
    api_env["UVICORN_RELOAD"] = "0"
    api_env["WATCHFILES_FORCE_NON_RECURSIVE"] = "true"
    api_env["MYTH_DESKTOP"] = "1"
    api_env["TAURI_DEBUG"] = "1"
    
    # 100% Accuracy: Inject standard Tauri 2 matrix
    import platform
    machine = platform.machine().lower()
    arch_map = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}
    
    api_env["TAURI_PLATFORM"] = "windows" if sys.platform == "win32" else "linux"
    api_env["TAURI_ARCH"] = arch_map.get(machine, machine)
    api_env["TAURI_FAMILY"] = "windows" if sys.platform == "win32" else "unix"
    
    # Industrial: Pull Version from tauri.conf.json
    try:
        conf_path = ui_dir / "src-tauri" / "tauri.conf.json"
        if conf_path.exists():
            with open(conf_path, "r") as f:
                conf_data = json.load(f)
                api_env["TAURI_VERSION"] = conf_data.get("version", "1.1.0")
    except Exception:
        api_env["TAURI_VERSION"] = "1.1.0"

    api_process = subprocess.Popen(
        api_cmd,
        cwd=root_dir,
        env=api_env,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        if sys.platform == "win32"
        else 0,
    )

    # Wait for backend to be ready
    print("⏳ Waiting for backend to initialize (MCP tools, RAG, etc.)...")
    import urllib.error
    import urllib.request

    time.sleep(5)
    max_retries = 150
    retry_count = 0
    last_status_str = None

    while retry_count < max_retries:
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:8890/health", timeout=40
            ) as response:
                if response.getcode() == 200:
                    data = json.loads(response.read().decode())

                    # Verify BOOT_ID
                    boot_id = data.get("boot_id")
                    if not boot_id:
                        retry_count += 1
                        time.sleep(2)
                        continue

                    # 1.5 CRITICAL: Verify we're talking to the NEW backend, not a stale one
                    log_file = root_dir / f"{prefix}_system.log"
                    expected_boot_id = None
                    if log_file.exists():
                        try:
                            with open(
                                log_file, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                lines = f.readlines()
                                for line in reversed(lines):
                                    if "[BOOT_ID]" in line:
                                        parts = line.split("[BOOT_ID]")
                                        if len(parts) > 1:
                                            expected_boot_id = (
                                                parts[1].strip().split()[0]
                                            )
                                            break
                        except Exception:
                            pass

                    if expected_boot_id and boot_id != expected_boot_id:
                        print(
                            f"   ⏳ Waiting for new backend (stale: {boot_id}, expected: {expected_boot_id})...",
                            end="\r",
                        )
                        retry_count += 1
                        time.sleep(2)
                        continue

                    comp = data.get("components", {})
                    if (
                        data.get("ready")
                        and comp.get("agent") == "ACTIVE"
                        and comp.get("rag") == "READY"
                        and comp.get("mcp") == "SECURE"
                    ):
                        print(
                            f"\n✅ Backend Infrastructure: READY. [BOOT_ID: {boot_id}]"
                        )
                        break
                    else:
                        status_str = f"Agent: {comp.get('agent', 'INIT')} | RAG: {comp.get('rag', 'INIT')} | MCP: {comp.get('mcp', 'INIT')}"
                        if status_str != last_status_str:
                            print(
                                f"   ⏳ Backend online. Status: [{status_str}]",
                                flush=True,
                            )
                            last_status_str = status_str
        except Exception:
            pass
        retry_count += 1
        time.sleep(2)

    if retry_count >= max_retries:
        print("\n❌ Error: Backend failed to respond.")
        api_process.terminate()
        return

    print("🚀 [2/3] Starting Tauri Industrial Dashboard...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    tauri_process = subprocess.Popen(
        [npm_cmd, "run", "tauri:dev"],
        cwd=ui_dir,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        if sys.platform == "win32"
        else 0,
    )

    print("\n✅ TAURI SYSTEM ONLINE. Press Ctrl+C to terminate all services.\n")

    shutdown_flag = False

    def handle_exit(sig, frame):
        nonlocal shutdown_flag
        if not shutdown_flag:
            print("\n🛑 SHUTTING DOWN SYSTEM...")
            shutdown_flag = True
        else:
            sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    try:
        while not shutdown_flag:
            time.sleep(1)
            # Monitor Backend
            if api_process.poll() is not None:
                if not shutdown_flag:
                    print("⚠️  [ORCHESTRATOR] Backend service dropped. Restarting...")
                    api_process = subprocess.Popen(
                        api_cmd,
                        cwd=root_dir,
                        env=api_env,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                        if sys.platform == "win32"
                        else 0,
                    )

            # Monitor Tauri
            if tauri_process.poll() is not None:
                if not shutdown_flag:
                    print("⚠️  [ORCHESTRATOR] Tauri interface closed.")
                    # Note: We don't auto-restart Tauri as it's the main UI; if user closes it, they usually want to stop.
                    break
    except Exception:
        pass
    finally:
        print("🧼 [CLEANUP] Terminating sibling processes...")
        try:
            if sys.platform == "win32":
                subprocess.run(
                    f"taskkill /F /T /PID {api_process.pid}",
                    shell=True,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    f"taskkill /F /T /PID {tauri_process.pid}",
                    shell=True,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                api_process.terminate()
                tauri_process.terminate()
        except Exception:
            pass
        kill_process_on_port(8890)
        kill_process_on_port(5173)
        print("✅ Session closed.")


if __name__ == "__main__":
    run_myth_tauri()
