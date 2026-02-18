"""
test_tool_discovery.py — Test the tools/__init__.py unified discovery system.
==============================================================================
Verifies: get_all_tools, get_tools_by_category, search_tools, get_tool_stats,
          health_check, get_omni_manifest, get_tool_manifest, suggest_tools_for_target
All discovery functions are async, so we use asyncio.run() for the entire test.
"""
import sys
import os
import time
import asyncio
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import ResultTracker, Status, C, safe_import


EXPECTED_CATEGORIES = [
    "recon", "intelligence", "exploitation", "evasion",
    "ctf", "re", "vr", "cloud", "utilities", "system"
]


async def run_async(tracker: ResultTracker):
    print(C.header("TOOL DISCOVERY SYSTEM"))

    # Import the tools package
    start = time.time()
    mod, err = safe_import("tools")
    elapsed = (time.time() - start) * 1000
    if not mod:
        tracker.record("import tools", Status.FAIL, elapsed, error=err)
        return
    tracker.record("import tools", Status.PASS, elapsed)

    all_tools = None

    # --- get_all_tools ---
    try:
        start = time.time()
        all_tools = await mod.get_all_tools()
        elapsed = (time.time() - start) * 1000
        assert isinstance(all_tools, list), f"Expected list, got {type(all_tools)}"
        assert len(all_tools) > 0, "get_all_tools() returned empty list"
        tracker.record(f"get_all_tools() → {len(all_tools)} tools", Status.PASS, elapsed)
    except Exception as e:
        tracker.record("get_all_tools()", Status.FAIL, 0, error=traceback.format_exc())

    # --- TOOL_CATEGORIES ---
    try:
        cats = mod.TOOL_CATEGORIES
        assert isinstance(cats, dict), f"Expected dict, got {type(cats)}"
        for cat in EXPECTED_CATEGORIES:
            assert cat in cats, f"Missing category: {cat}"
        tracker.record(f"TOOL_CATEGORIES → {len(cats)} categories", Status.PASS, 0)
    except Exception as e:
        tracker.record("TOOL_CATEGORIES", Status.FAIL, 0, error=traceback.format_exc())

    # --- get_tools_by_category ---
    for cat in EXPECTED_CATEGORIES:
        try:
            start = time.time()
            tools = await mod.get_tools_by_category([cat])
            elapsed = (time.time() - start) * 1000
            assert isinstance(tools, list), f"Expected list, got {type(tools)}"
            tracker.record(f"get_tools_by_category(['{cat}']) → {len(tools)}", Status.PASS, elapsed)
        except Exception as e:
            tracker.record(f"get_tools_by_category(['{cat}'])", Status.FAIL, 0, error=traceback.format_exc())

    # --- search_tools ---
    search_queries = ["scan", "exploit", "dns", "password", "file", "shell"]
    for q in search_queries:
        try:
            start = time.time()
            results = await mod.search_tools(q)
            elapsed = (time.time() - start) * 1000
            assert isinstance(results, list), f"Expected list, got {type(results)}"
            tracker.record(f"search_tools('{q}') → {len(results)} results", Status.PASS, elapsed)
        except Exception as e:
            tracker.record(f"search_tools('{q}')", Status.FAIL, 0, error=traceback.format_exc())

    # --- get_tool_stats ---
    try:
        start = time.time()
        stats = await mod.get_tool_stats()
        elapsed = (time.time() - start) * 1000
        assert isinstance(stats, dict), f"Expected dict, got {type(stats)}"
        tracker.record(f"get_tool_stats() → total={stats.get('total_tools', '?')}", Status.PASS, elapsed)
    except Exception as e:
        tracker.record("get_tool_stats()", Status.FAIL, 0, error=traceback.format_exc())

    # --- health_check ---
    try:
        start = time.time()
        health = await mod.health_check()
        elapsed = (time.time() - start) * 1000
        tracker.record(f"health_check() → {health.get('status', '?')}", Status.PASS, elapsed)
    except Exception as e:
        tracker.record("health_check()", Status.FAIL, 0, error=traceback.format_exc())

    # --- get_omni_manifest ---
    try:
        start = time.time()
        manifest = await mod.get_omni_manifest()
        elapsed = (time.time() - start) * 1000
        assert isinstance(manifest, dict), f"Expected dict, got {type(manifest)}"
        tracker.record(f"get_omni_manifest() → {len(manifest)} keys", Status.PASS, elapsed)
    except Exception as e:
        tracker.record("get_omni_manifest()", Status.FAIL, 0, error=traceback.format_exc())

    # --- get_tool_manifest ---
    try:
        start = time.time()
        flat = await mod.get_tool_manifest()
        elapsed = (time.time() - start) * 1000
        assert isinstance(flat, dict), f"Expected dict, got {type(flat)}"
        tracker.record(f"get_tool_manifest() → {flat.get('total', '?')} tools", Status.PASS, elapsed)
    except Exception as e:
        tracker.record("get_tool_manifest()", Status.FAIL, 0, error=traceback.format_exc())

    # --- suggest_tools_for_target ---
    targets = ["web", "network", "binary", "cloud"]
    for t_type in targets:
        try:
            start = time.time()
            suggestions = await mod.suggest_tools_for_target(t_type)
            elapsed = (time.time() - start) * 1000
            assert isinstance(suggestions, list), f"Expected list, got {type(suggestions)}"
            tracker.record(f"suggest_tools_for_target('{t_type}') → {len(suggestions)}", Status.PASS, elapsed)
        except Exception as e:
            tracker.record(f"suggest_tools_for_target('{t_type}')", Status.FAIL, 0, error=traceback.format_exc())

    # --- get_tool_by_name ---
    if all_tools:
        test_name = all_tools[0].name if hasattr(all_tools[0], 'name') else None
        if test_name:
            try:
                start = time.time()
                found = await mod.get_tool_by_name(test_name)
                elapsed = (time.time() - start) * 1000
                assert found is not None, f"Tool '{test_name}' not found"
                tracker.record(f"get_tool_by_name('{test_name}')", Status.PASS, elapsed)
            except Exception as e:
                tracker.record(f"get_tool_by_name('{test_name}')", Status.FAIL, 0, error=traceback.format_exc())


def run(tracker: ResultTracker = None):
    if tracker is None:
        tracker = ResultTracker()

    tracker.begin_module("Tool Discovery")
    asyncio.run(run_async(tracker))
    tracker.end_module()
    return tracker


if __name__ == "__main__":
    t = run()
    t.print_summary()
    sys.exit(0 if t.all_passed else 1)
