"""
test_core_imports.py — Verify every core module imports without errors.
========================================================================
Tests: config_loader, myth_config, myth_llm, backend, api, run_desktop,
       dialog_worker, myth_utils.sanitizer
"""

import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import C, ResultTracker, Status, safe_import

CORE_MODULES = [
    ("config_loader", "ConfigurationManager, AgentConfig, Pydantic models"),
    ("myth_config", "Global config object, load_dotenv"),
    ("myth_llm", "LLM provider factory"),
    ("dialog_worker", "Dialog worker utilities"),
    ("myth_utils.sanitizer", "Input sanitization utilities"),
]

# These are heavy modules that start servers/graphs — import-only, no init
HEAVY_MODULES = [
    ("backend", "LangGraph agent graph & nodes"),
    ("api", "FastAPI application & endpoints"),
    ("run_desktop", "Desktop launcher script"),
]


def run(tracker: ResultTracker = None):
    if tracker is None:
        tracker = ResultTracker()

    tracker.begin_module("Core Imports")
    print(C.header("CORE MODULE IMPORTS"))

    for mod_path, description in CORE_MODULES:
        start = time.time()
        mod, err = safe_import(mod_path)
        elapsed = (time.time() - start) * 1000
        if mod:
            tracker.record(f"{mod_path} — {description}", Status.PASS, elapsed)
        else:
            tracker.record(
                f"{mod_path} — {description}", Status.FAIL, elapsed, error=err
            )

    print(f"\n  {C.DIM}Heavy modules (import only, may be slow):{C.RESET}")
    for mod_path, description in HEAVY_MODULES:
        start = time.time()
        mod, err = safe_import(mod_path)
        elapsed = (time.time() - start) * 1000
        if mod:
            tracker.record(f"{mod_path} — {description}", Status.PASS, elapsed)
        else:
            tracker.record(
                f"{mod_path} — {description}", Status.FAIL, elapsed, error=err
            )

    tracker.end_module()
    return tracker


if __name__ == "__main__":
    t = run()
    t.print_summary()
    sys.exit(0 if t.all_passed else 1)
