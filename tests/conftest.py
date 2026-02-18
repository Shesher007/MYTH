"""
MYTH Test Suite — Shared Configuration & Utilities
===================================================
Central fixtures, path setup, and result tracking for the entire test suite.
"""
import sys
import os
import time
import importlib
import traceback
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum

# ─── Path Setup ───────────────────────────────────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ─── ANSI Colors ──────────────────────────────────────────────────────────────
class C:
    """Terminal color codes."""
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @staticmethod
    def ok(msg):    return f"{C.GREEN}✓ {msg}{C.RESET}"
    @staticmethod
    def fail(msg):  return f"{C.RED}✗ {msg}{C.RESET}"
    @staticmethod
    def warn(msg):  return f"{C.YELLOW}⚠ {msg}{C.RESET}"
    @staticmethod
    def info(msg):  return f"{C.CYAN}ℹ {msg}{C.RESET}"
    @staticmethod
    def header(msg): return f"\n{C.BOLD}{C.CYAN}{'═'*70}\n  {msg}\n{'═'*70}{C.RESET}"


# ─── Result Tracking ──────────────────────────────────────────────────────────
class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    WARN = "WARN"


@dataclass
class TestResult:
    name: str
    status: Status
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    detail: Optional[str] = None


@dataclass
class ModuleResults:
    module_name: str
    results: List[TestResult] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0

    def add(self, result: TestResult):
        self.results.append(result)

    @property
    def passed(self): return sum(1 for r in self.results if r.status == Status.PASS)
    @property
    def failed(self): return sum(1 for r in self.results if r.status == Status.FAIL)
    @property
    def skipped(self): return sum(1 for r in self.results if r.status == Status.SKIP)
    @property
    def warned(self): return sum(1 for r in self.results if r.status == Status.WARN)
    @property
    def total(self): return len(self.results)
    @property
    def elapsed(self): return self.end_time - self.start_time


class ResultTracker:
    """Collects results across all test modules."""

    def __init__(self):
        self.modules: List[ModuleResults] = []
        self._current: Optional[ModuleResults] = None

    def begin_module(self, name: str):
        self._current = ModuleResults(module_name=name, start_time=time.time())
        self.modules.append(self._current)

    def end_module(self):
        if self._current:
            self._current.end_time = time.time()
        self._current = None

    def record(self, name: str, status: Status, elapsed_ms: float = 0,
               error: str = None, detail: str = None):
        result = TestResult(name=name, status=status, elapsed_ms=elapsed_ms,
                            error=error, detail=detail)
        if self._current:
            self._current.add(result)
        # Live output
        if status == Status.PASS:
            print(f"    {C.ok(name)} {C.DIM}({elapsed_ms:.0f}ms){C.RESET}")
        elif status == Status.FAIL:
            print(f"    {C.fail(name)} {C.DIM}({elapsed_ms:.0f}ms){C.RESET}")
            if error:
                for line in error.strip().split('\n')[-3:]:
                    print(f"      {C.RED}│ {line}{C.RESET}")
        elif status == Status.SKIP:
            print(f"    {C.warn(name)} [SKIPPED]")
        elif status == Status.WARN:
            print(f"    {C.warn(name)} {C.DIM}({elapsed_ms:.0f}ms){C.RESET}")

    @property
    def total_passed(self): return sum(m.passed for m in self.modules)
    @property
    def total_failed(self): return sum(m.failed for m in self.modules)
    @property
    def total_skipped(self): return sum(m.skipped for m in self.modules)
    @property
    def total_tests(self): return sum(m.total for m in self.modules)
    @property
    def all_passed(self): return self.total_failed == 0

    def print_summary(self):
        """Print a rich summary table."""
        print(C.header("FINAL RESULTS"))

        # Table header
        hdr = f"  {'Module':<35} {'Pass':>6} {'Fail':>6} {'Skip':>6} {'Time':>8}"
        print(f"{C.BOLD}{hdr}{C.RESET}")
        print(f"  {'─'*61}")

        for m in self.modules:
            fail_color = C.RED if m.failed else ""
            reset = C.RESET if m.failed else ""
            print(f"  {m.module_name:<35} "
                  f"{C.GREEN}{m.passed:>6}{C.RESET} "
                  f"{fail_color}{m.failed:>6}{reset} "
                  f"{C.YELLOW}{m.skipped:>6}{C.RESET} "
                  f"{m.elapsed:>7.1f}s")

        print(f"  {'─'*61}")
        total_time = sum(m.elapsed for m in self.modules)
        status_str = f"{C.GREEN}{C.BOLD}ALL PASSED{C.RESET}" if self.all_passed else f"{C.RED}{C.BOLD}FAILURES DETECTED{C.RESET}"
        print(f"  {'TOTAL':<35} "
              f"{C.GREEN}{self.total_passed:>6}{C.RESET} "
              f"{C.RED}{self.total_failed:>6}{C.RESET} "
              f"{C.YELLOW}{self.total_skipped:>6}{C.RESET} "
              f"{total_time:>7.1f}s")
        print(f"\n  Status: {status_str}")

        # Print failed tests detail
        if not self.all_passed:
            print(f"\n{C.RED}{C.BOLD}  Failed Tests:{C.RESET}")
            for m in self.modules:
                for r in m.results:
                    if r.status == Status.FAIL:
                        print(f"    {C.RED}✗ [{m.module_name}] {r.name}{C.RESET}")
                        if r.error:
                            last_line = r.error.strip().split('\n')[-1]
                            print(f"      {C.DIM}{last_line}{C.RESET}")
        print()

    def export_errors(self, filename: str):
        """Export test results to a text file (refreshed every run)."""
        with open(filename, "w", encoding="utf-8") as f:
            f.write("="*70 + "\n")
            f.write(f"  MYTH TEST SUITE — {'FAILURE' if not self.all_passed else 'SUCCESS'} REPORT\n")
            f.write(f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")

            if self.all_passed:
                f.write("✨ ALL TESTS PASSED SUCCESSFULLY! No errors detected.\n")
                f.write(f"Total Tests: {self.total_tests}\n")
            else:
                for m in self.modules:
                    # Export both FAIL and WARN status results
                    failures = [r for r in m.results if r.status in (Status.FAIL, Status.WARN)]
                    if not failures:
                        continue

                    f.write(f"--- Module: {m.module_name} ---\n")
                    for r in failures:
                        f.write(f"{r.status.value}: {r.name}\n")
                        if r.elapsed_ms:
                            f.write(f"Time: {r.elapsed_ms:.0f}ms\n")
                        if r.detail:
                            f.write(f"Details: {r.detail}\n")
                        if r.error:
                            f.write("Error Body:\n")
                            f.write(r.error.strip())
                            f.write("\n")
                        f.write("-" * 40 + "\n")
                    f.write("\n")
                
                f.write(f"\nSummary: {self.total_failed} failures and {sum(m.warned for m in self.modules)} warnings in {self.total_tests} tests.\n")
        
        status_msg = f"Report refreshed: {filename}" if self.all_passed else f"Failure report updated: {filename}"
        print(f"  {C.info(status_msg)}")


# ─── Test Helpers ──────────────────────────────────────────────────────────────
def safe_import(module_path: str) -> tuple:
    """Try to import a module, return (module, None) or (None, error_str)."""
    try:
        mod = importlib.import_module(module_path)
        return mod, None
    except Exception as e:
        tb = traceback.format_exc()
        return None, tb


def timed_test(func):
    """Decorator to time a test function."""
    def wrapper(*args, **kwargs):
        start = time.time()
        try:
            result = func(*args, **kwargs)
            elapsed = (time.time() - start) * 1000
            return result, elapsed
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            raise
    return wrapper
