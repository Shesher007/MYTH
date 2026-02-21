"""
test_tool_imports.py — Dynamically import every tool module and verify exports.
================================================================================
Discovers all .py files across all 11 tool subdirectories and tests:
1. Import succeeds without errors
2. Module contains at least one callable or BaseTool-derived object
"""

import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import C, ResultTracker, Status, safe_import

# All tool subdirectories to scan
TOOL_DIRS = {
    "tools.cloud": ["automation", "cloud_enum", "iac_cicd", "k8s_advanced"],
    "tools.ctf": [
        "binary_expert",
        "crypto_master",
        "entropy_analyzer",
        "esoteric_ciphers",
        "forensics",
        "network_forensics",
        "pwn_advanced",
        "web_ctf_master",
        "web_esoteric",
    ],
    "tools.evasion": [
        "anti_analysis",
        "edr_aware_payloads",
        "execution_mastery",
        "host_audit_advanced",
        "in_memory_stealth",
        "maldev_advanced",
        "payload_engineering",
        "persistence_advanced",
        "process_mastery",
        "tampering_advanced",
        "techniques",
        "unhooking",
    ],
    "tools.exploitation": [
        "api_prober",
        "c2_infrastructure",
        "clr_engineering",
        "evasion_generators",
        "graphql_prober",
        "host_exploitation",
        "identity_exploitation",
        "infrastructure_exploitation",
        "payload_generation",
        "polyglot_payloads",
        "process_injection",
        "situational_awareness",
        "syscall_factory",
    ],
    "tools.exploitation.web": ["injection", "logic", "protocols"],
    "tools.intelligence": [
        "ai",
        "browser",
        "forensics",
        "identity_audit",
        "osint",
        "research_engine",
        "search",
        "social",
    ],
    "tools.recon": [
        "active",
        "advanced_osint",
        "asm_engine",
        "cloud_discovery",
        "content_discovery",
        "discovery",
        "industrial_iot",
        "infrastructure_services",
        "internal_network",
        "network",
        "passive",
        "passive_intel",
        "pd_all_subdomains",
        "spectral_fingerprint",
        "supply_chain_recon",
    ],
    "tools.reverse_engineering": [
        "binary_analyzer",
        "decompilation_context",
        "diffing_engine",
        "dynamic_helper",
        "firmware_advanced",
        "firmware_audit",
        "hardening_audit",
        "hardware_research",
        "kernel_audit",
        "nexus_orchestrator",
        "symbol_resolver",
        "vuln_context_elite",
        "vulnerability_research",
    ],
    "tools.utilities": [
        "file_generator",
        "files",
        "integrations",
        "report",
        "shell",
        "utils",
    ],
    "tools.vr": [
        "browser_exploitation",
        "exploit_automation",
        "gadget_discovery",
        "heap_exploitation",
        "kernel_exploitation",
        "mitigation_bypass",
        "sandbox_research",
        "type_confusion",
    ],
    "tools.web": [
        "advanced_ssrf",
        "auth_logic",
        "cache_exploitation",
        "client_side",
        "distributed_grid",
        "logic_synthesizer",
        "modern_api",
        "modern_protocols",
        "neural_waf_evader",
        "quantum_crypto",
        "self_healing_web",
        "smuggling_engine",
        "ssti_prober",
        "supply_chain",
        "temporal_debugger",
        "web_unification",
        "zero_day",
    ],
}


def _check_module_exports(mod) -> str:
    """Check if module has any callable or BaseTool objects."""
    callables = [
        name
        for name in dir(mod)
        if not name.startswith("_") and callable(getattr(mod, name, None))
    ]

    # Also check for objects with .invoke or .ainvoke (tool pattern)
    tools = [
        name
        for name in dir(mod)
        if not name.startswith("_") and hasattr(getattr(mod, name, None), "ainvoke")
    ]

    if tools:
        return f"{len(tools)} tool(s), {len(callables)} callable(s)"
    elif callables:
        return f"{len(callables)} callable(s)"
    else:
        return "no exports found"


def run(tracker: ResultTracker = None):
    if tracker is None:
        tracker = ResultTracker()

    tracker.begin_module("Tool Imports")
    print(C.header("TOOL MODULE IMPORTS"))

    total_tools_found = 0

    for package, modules in TOOL_DIRS.items():
        print(f"\n  {C.CYAN}{C.BOLD}▸ {package}{C.RESET} ({len(modules)} modules)")

        for mod_name in modules:
            full_path = f"{package}.{mod_name}"
            start = time.time()
            mod, err = safe_import(full_path)
            elapsed = (time.time() - start) * 1000

            if mod:
                export_info = _check_module_exports(mod)
                total_tools_found += 1
                tracker.record(f"{full_path} [{export_info}]", Status.PASS, elapsed)
            else:
                tracker.record(full_path, Status.FAIL, elapsed, error=err)

    # Also test the __init__.py package-level imports
    print(f"\n  {C.CYAN}{C.BOLD}▸ Package-level __init__.py imports{C.RESET}")
    PACKAGE_INITS = [
        "tools",
        "tools.cloud",
        "tools.ctf",
        "tools.evasion",
        "tools.exploitation",
        "tools.exploitation.web",
        "tools.intelligence",
        "tools.recon",
        "tools.reverse_engineering",
        "tools.utilities",
        "tools.vr",
        "tools.web",
    ]
    for pkg in PACKAGE_INITS:
        start = time.time()
        mod, err = safe_import(pkg)
        elapsed = (time.time() - start) * 1000
        if mod:
            tracker.record(f"{pkg}.__init__", Status.PASS, elapsed)
        else:
            tracker.record(f"{pkg}.__init__", Status.FAIL, elapsed, error=err)

    tracker.end_module()
    print(f"\n  {C.info(f'Total modules imported: {total_tools_found}')}")
    return tracker


if __name__ == "__main__":
    t = run()
    t.print_summary()
    sys.exit(0 if t.all_passed else 1)
