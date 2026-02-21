"""
test_mcp_client.py — Test the MCP client infrastructure.
=========================================================
Tests: SSE_CONFIGS validation, MCPManager instantiation,
       TitanSessionPool singleton, utility functions.
"""

import os
import sys
import time
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import C, ResultTracker, Status, safe_import


def run(tracker: ResultTracker = None):
    if tracker is None:
        tracker = ResultTracker()

    tracker.begin_module("MCP Client Infrastructure")
    print(C.header("MCP CLIENT INFRASTRUCTURE"))

    # Import mcp_client
    start = time.time()
    mod, err = safe_import("mcp_servers.mcp_client")
    elapsed = (time.time() - start) * 1000
    if not mod:
        tracker.record("import mcp_servers.mcp_client", Status.FAIL, elapsed, error=err)
        tracker.end_module()
        return tracker
    tracker.record("import mcp_servers.mcp_client", Status.PASS, elapsed)

    # --- SSE_CONFIGS validation ---
    print(f"\n  {C.CYAN}{C.BOLD}▸ SSE_CONFIGS Validation{C.RESET}")
    try:
        configs = mod.SSE_CONFIGS
        assert isinstance(configs, dict), f"Expected dict, got {type(configs)}"
        assert len(configs) > 0, "SSE_CONFIGS is empty"
        tracker.record(f"SSE_CONFIGS has {len(configs)} server entries", Status.PASS, 0)

        # Validate each entry has required fields
        required_keys = {"path", "port", "name"}
        for key, cfg in configs.items():
            missing = required_keys - set(cfg.keys())
            if missing:
                tracker.record(
                    f"SSE_CONFIGS['{key}'] missing: {missing}", Status.FAIL, 0
                )
            else:
                tracker.record(
                    f"SSE_CONFIGS['{key}'] → port {cfg['port']}, {cfg['name']}",
                    Status.PASS,
                    0,
                )

        # Check for port collisions
        ports = [cfg["port"] for cfg in configs.values()]
        if len(ports) != len(set(ports)):
            dupes = [p for p in ports if ports.count(p) > 1]
            tracker.record(f"Port collision detected: {set(dupes)}", Status.FAIL, 0)
        else:
            tracker.record(
                f"No port collisions ({len(ports)} unique ports)", Status.PASS, 0
            )

    except Exception:
        tracker.record(
            "SSE_CONFIGS validation", Status.FAIL, 0, error=traceback.format_exc()
        )

    # --- MCPManager ---
    print(f"\n  {C.CYAN}{C.BOLD}▸ MCPManager{C.RESET}")
    try:
        mgr_cls = mod.MCPManager
        assert mgr_cls is not None
        tracker.record("MCPManager class exists", Status.PASS, 0)

        # Check it has expected methods
        expected_methods = [
            "bootstrap",
            "ensure_server_running",
            "shutdown",
            "_purge_zombies",
            "_watchdog_loop",
            "_is_server_healthy",
        ]
        for method in expected_methods:
            if hasattr(mgr_cls, method):
                tracker.record(f"MCPManager.{method}() exists", Status.PASS, 0)
            else:
                tracker.record(f"MCPManager.{method}() missing", Status.FAIL, 0)

        # Check global manager instance
        if mod.manager is not None:
            tracker.record("Global manager instance exists", Status.PASS, 0)
        else:
            tracker.record("Global manager instance is None", Status.WARN, 0)
    except Exception:
        tracker.record("MCPManager", Status.FAIL, 0, error=traceback.format_exc())

    # --- TitanSessionPool ---
    print(f"\n  {C.CYAN}{C.BOLD}▸ TitanSessionPool{C.RESET}")
    try:
        pool_cls = mod.TitanSessionPool
        assert pool_cls is not None
        tracker.record("TitanSessionPool class exists", Status.PASS, 0)

        # Singleton test
        pool1 = pool_cls()
        pool2 = pool_cls()
        if pool1 is pool2:
            tracker.record("TitanSessionPool singleton pattern works", Status.PASS, 0)
        else:
            tracker.record(
                "TitanSessionPool singleton broken (different instances)",
                Status.FAIL,
                0,
            )

        # Check methods
        for method in ["get_session", "purge_session", "shutdown"]:
            if hasattr(pool_cls, method):
                tracker.record(f"TitanSessionPool.{method}() exists", Status.PASS, 0)
            else:
                tracker.record(f"TitanSessionPool.{method}() missing", Status.FAIL, 0)

    except Exception:
        tracker.record("TitanSessionPool", Status.FAIL, 0, error=traceback.format_exc())

    # --- Utility Functions ---
    print(f"\n  {C.CYAN}{C.BOLD}▸ Utility Functions{C.RESET}")

    # _refine_category
    try:
        fn = mod._refine_category
        result = fn("nmap_scanner", "uncategorized")
        assert isinstance(result, str)
        tracker.record(
            f"_refine_category('nmap_scanner', 'uncategorized') → '{result}'",
            Status.PASS,
            0,
        )
    except Exception:
        tracker.record(
            "_refine_category()", Status.FAIL, 0, error=traceback.format_exc()
        )

    # _sanitize_schema
    try:
        fn = mod._sanitize_schema
        result = fn({"type": "object", "properties": {"test": {"type": "string"}}})
        assert isinstance(result, dict)
        tracker.record("_sanitize_schema(dict) works", Status.PASS, 0)

        fn(None)
        tracker.record("_sanitize_schema(None) works", Status.PASS, 0)
    except Exception:
        tracker.record(
            "_sanitize_schema()", Status.FAIL, 0, error=traceback.format_exc()
        )

    # _is_port_open
    try:
        fn = mod._is_port_open
        result = fn(99999)  # Should return False (no server on this port)
        assert result is False, f"Expected False for port 99999, got {result}"
        tracker.record("_is_port_open(99999) → False", Status.PASS, 0)
    except Exception:
        tracker.record("_is_port_open()", Status.FAIL, 0, error=traceback.format_exc())

    # _get_config_fingerprint
    try:
        fn = mod._get_config_fingerprint
        fp = fn()
        assert isinstance(fp, str)
        assert len(fp) > 0
        tracker.record(f"_get_config_fingerprint() → {fp[:16]}...", Status.PASS, 0)
    except Exception:
        tracker.record(
            "_get_config_fingerprint()", Status.FAIL, 0, error=traceback.format_exc()
        )

    # mcp_common
    start = time.time()
    common_mod, err = safe_import("mcp_servers.mcp_common")
    elapsed = (time.time() - start) * 1000
    if common_mod:
        tracker.record("import mcp_servers.mcp_common", Status.PASS, elapsed)
    else:
        tracker.record("import mcp_servers.mcp_common", Status.FAIL, elapsed, error=err)

    tracker.end_module()
    return tracker


if __name__ == "__main__":
    t = run()
    t.print_summary()
    sys.exit(0 if t.all_passed else 1)
