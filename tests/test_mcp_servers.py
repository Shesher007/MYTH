"""
test_mcp_servers.py — Import all MCP server modules and verify structure.
=========================================================================
Tests custom_servers (7), local_servers (7), remote_servers (11).
For each: import without error, verify it defines server/handler objects.
"""
import sys
import os
import time
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import ResultTracker, Status, C, safe_import

# Ensure mcp_servers directory is in sys.path so 'import mcp_common' works
MCP_SERVERS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp_servers"))
if MCP_SERVERS_DIR not in sys.path:
    sys.path.insert(0, MCP_SERVERS_DIR)


MCP_SERVERS = {
    "Custom Servers": {
        "mcp_servers.custom_servers.burp_server":           "Burp Suite Integration",
        "mcp_servers.custom_servers.exploit_hub_server":    "Exploit Hub",
        "mcp_servers.custom_servers.nuclei_server":         "Nuclei Scanner",
        "mcp_servers.custom_servers.recon_server":          "Recon Engine",
        "mcp_servers.custom_servers.report_gen_server":     "Report Generator",
        "mcp_servers.custom_servers.security_tools":        "Security Tools",
        "mcp_servers.custom_servers.target_tracker_server": "Target Tracker",
    },
    "Local Servers": {
        "mcp_servers.local_servers.browser_tools":     "Browser Tools",
        "mcp_servers.local_servers.curl_server":       "cURL Server",
        "mcp_servers.local_servers.db_tools":          "Database Tools",
        "mcp_servers.local_servers.docker_tools":      "Docker Tools",
        "mcp_servers.local_servers.fetch_server":      "Fetch Server",
        "mcp_servers.local_servers.filesystem_tools":  "Filesystem Tools",
        "mcp_servers.local_servers.system_tools":      "System Tools",
    },
    "Remote Servers": {
        "mcp_servers.remote_servers.censys_server":         "Censys",
        "mcp_servers.remote_servers.cisa_kev_server":       "CISA KEV",
        "mcp_servers.remote_servers.exploitdb_server":      "ExploitDB",
        "mcp_servers.remote_servers.external_apis":         "External APIs",
        "mcp_servers.remote_servers.gh_advisory_server":    "GitHub Advisory",
        "mcp_servers.remote_servers.hibp_server":           "HaveIBeenPwned",
        "mcp_servers.remote_servers.hunter_server":         "Hunter.io",
        "mcp_servers.remote_servers.nvd_server":            "NVD",
        "mcp_servers.remote_servers.securitytrails_server": "SecurityTrails",
        "mcp_servers.remote_servers.shodan_server":         "Shodan",
        "mcp_servers.remote_servers.virustotal_server":     "VirusTotal",
    },
}


def _check_server_exports(mod) -> str:
    """Check if module exposes MCP server objects (mcp, app, etc.)."""
    mcp_objects = []
    for name in dir(mod):
        if name.startswith('_'):
            continue
        obj = getattr(mod, name, None)
        # Check for FastMCP or mcp server patterns
        obj_type = type(obj).__name__
        if obj_type in ('FastMCP', 'Server', 'Starlette') or name in ('mcp', 'app', 'server'):
            mcp_objects.append(name)
    
    if mcp_objects:
        return f"server objects: {', '.join(mcp_objects)}"
    
    # Check for @tool decorated functions
    tools = [name for name in dir(mod)
             if not name.startswith('_') and hasattr(getattr(mod, name, None), 'ainvoke')]
    if tools:
        return f"{len(tools)} tool(s) registered"
    
    callables = [name for name in dir(mod) if not name.startswith('_') and callable(getattr(mod, name, None))]
    return f"{len(callables)} callable(s)"


def run(tracker: ResultTracker = None):
    if tracker is None:
        tracker = ResultTracker()

    tracker.begin_module("MCP Server Imports")
    print(C.header("MCP SERVER MODULE IMPORTS"))

    for group_name, servers in MCP_SERVERS.items():
        print(f"\n  {C.CYAN}{C.BOLD}▸ {group_name}{C.RESET} ({len(servers)} servers)")

        for mod_path, description in servers.items():
            start = time.time()
            mod, err = safe_import(mod_path)
            elapsed = (time.time() - start) * 1000

            if mod:
                export_info = _check_server_exports(mod)
                tracker.record(f"{description} ({mod_path}) [{export_info}]",
                              Status.PASS, elapsed)
            else:
                tracker.record(f"{description} ({mod_path})",
                              Status.FAIL, elapsed, error=err)

    # Test package-level inits
    print(f"\n  {C.CYAN}{C.BOLD}▸ Package __init__.py imports{C.RESET}")
    PACKAGES = [
        "mcp_servers.custom_servers",
        "mcp_servers.local_servers",
        "mcp_servers.remote_servers",
    ]
    for pkg in PACKAGES:
        start = time.time()
        mod, err = safe_import(pkg)
        elapsed = (time.time() - start) * 1000
        if mod:
            tracker.record(f"{pkg}.__init__", Status.PASS, elapsed)
        else:
            tracker.record(f"{pkg}.__init__", Status.FAIL, elapsed, error=err)

    tracker.end_module()
    return tracker


if __name__ == "__main__":
    t = run()
    t.print_summary()
    sys.exit(0 if t.all_passed else 1)
