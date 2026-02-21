#!/usr/bin/env python3
"""
run_all.py — MYTH Master Test Runner
======================================
Runs every test module in sequence and produces a rich summary report.

Usage:
    python testing/run_all.py              # Run all tests
    python testing/run_all.py --fast       # Skip slow invocation tests
    python testing/run_all.py --module X   # Run only module X
"""

import argparse
import os
import sys
import time
import warnings

# Industry Grade: Suppress noisy third-party SyntaxWarnings (e.g., from ropper)
warnings.filterwarnings("ignore", category=SyntaxWarning)

# Path setup
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

from conftest import C, ResultTracker  # noqa: E402

# ─── Test Module Registry ─────────────────────────────────────────────────────
# Order matters: lightweight tests first, heavy tests last
TEST_MODULES = [
    ("test_config", "Configuration & Manifests"),
    ("test_core_imports", "Core Module Imports"),
    ("test_tool_imports", "Tool Module Imports (100+ files)"),
    ("test_tool_discovery", "Tool Discovery System"),
    ("test_mcp_servers", "MCP Server Modules (25 servers)"),
    ("test_mcp_client", "MCP Client Infrastructure"),
    ("test_rag_system", "RAG System Modules (13 files)"),
    ("test_tool_invocations", "Tool Invocations (ainvoke)"),
]


def main():
    parser = argparse.ArgumentParser(description="MYTH Comprehensive Test Runner")
    parser.add_argument(
        "--fast", action="store_true", help="Skip slow tool invocation tests"
    )
    parser.add_argument(
        "--module",
        type=str,
        default=None,
        help="Run only a specific test module (e.g. test_config)",
    )
    args = parser.parse_args()

    banner = """
{C.BOLD}{C.CYAN}
 ███╗   ███╗██╗   ██╗████████╗██╗  ██╗
 ████╗ ████║╚██╗ ██╔╝╚══██╔══╝██║  ██║
 ██╔████╔██║ ╚████╔╝    ██║   ███████║
 ██║╚██╔╝██║  ╚██╔╝     ██║   ██╔══██║
 ██║ ╚═╝ ██║   ██║      ██║   ██║  ██║
 ╚═╝     ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝
 ┌─────────────────────────────────────────┐
 │   Comprehensive Test Suite Runner       │
 └─────────────────────────────────────────┘{C.RESET}
"""
    try:
        print(banner)
    except UnicodeEncodeError:
        # Fallback to plain ASCII for limited terminals (Windows PowerShell/CMD)
        print(f"\n{C.BOLD}{C.CYAN}  MYTH COMPREHENSIVE TEST RUNNER{C.RESET}\n")

    tracker = ResultTracker()
    start_time = time.time()

    modules_to_run = TEST_MODULES
    if args.module:
        modules_to_run = [(m, d) for m, d in TEST_MODULES if m == args.module]
        if not modules_to_run:
            print(f"{C.RED}Module '{args.module}' not found. Available:{C.RESET}")
            for m, d in TEST_MODULES:
                print(f"  - {m}: {d}")
            sys.exit(1)

    if args.fast:
        modules_to_run = [
            (m, d) for m, d in modules_to_run if m != "test_tool_invocations"
        ]
        print(f"  {C.warn('Fast mode: skipping tool invocation tests')}\n")

    for module_name, description in modules_to_run:
        print(f"\n{C.BOLD}{'▬' * 70}{C.RESET}")
        print(f"{C.BOLD}  Module: {description}{C.RESET}")
        print(f"{C.BOLD}{'▬' * 70}{C.RESET}")

        try:
            # Dynamic import of the test module
            test_module = __import__(f"tests.{module_name}", fromlist=["run"])
            test_module.run(tracker)
        except Exception:
            import traceback

            tracker.begin_module(module_name)
            tracker.record(
                f"MODULE CRASH: {module_name}",
                __import__("testing.conftest", fromlist=["Status"]).Status.FAIL,
                0,
                error=traceback.format_exc(),
            )
            tracker.end_module()

    total_time = time.time() - start_time

    # Final summary
    tracker.print_summary()

    print(f"  {C.DIM}Total execution time: {total_time:.1f}s{C.RESET}")
    print(f"  {C.DIM}Tested on: {os.name} | Python {sys.version.split()[0]}{C.RESET}")
    print()

    return tracker


if __name__ == "__main__":
    tracker = ResultTracker()
    try:
        main_tracker = main()
        if main_tracker:
            tracker = main_tracker
    except Exception:
        import traceback

        traceback.print_exc()
    finally:
        error_file = os.path.join(ROOT, "tests", "test_errors.txt")
        junit_file = os.path.join(ROOT, "tests", "results.xml")
        tracker.export_errors(error_file)
        tracker.to_junit_xml(junit_file)
        sys.exit(0 if tracker.all_passed else 1)
