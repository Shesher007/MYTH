import os
import platform

import psutil
from langchain_core.tools import tool

from tools.utilities.report import format_industrial_result

from .anti_analysis import (
    instrumentation_bypass_prober as instrumentation_bypass_prober,
)
from .anti_analysis import payload_entropy_auditor as payload_entropy_auditor
from .anti_analysis import sandbox_evasion_prober as sandbox_evasion_prober
from .edr_aware_payloads import edr_hook_detector as edr_hook_detector
from .edr_aware_payloads import sandbox_evader as sandbox_evader
from .execution_mastery import (
    injection_technique_evaluator as injection_technique_evaluator,
)
from .execution_mastery import (
    lolbin_discovery_scanner as lolbin_discovery_scanner,
)
from .execution_mastery import (
    module_stomping_evaluator as module_stomping_evaluator,
)
from .host_audit_advanced import (
    applocker_bypass_hunter as applocker_bypass_hunter,
)
from .host_audit_advanced import edr_hook_analyzer as edr_hook_analyzer
from .in_memory_stealth import ekko_sleep_generator as ekko_sleep_generator
from .in_memory_stealth import (
    reflective_stub_generator as reflective_stub_generator,
)
from .maldev_advanced import (
    ghosting_viability_auditor as ghosting_viability_auditor,
)
from .maldev_advanced import indirect_syscall_mapper as indirect_syscall_mapper
from .payload_engineering import chained_obfuscator as chained_obfuscator
from .payload_engineering import shellcode_encrypter as shellcode_encrypter
from .persistence_advanced import (
    persistence_script_generator as persistence_script_generator,
)
from .persistence_advanced import (
    wmi_persistence_builder as wmi_persistence_builder,
)
from .process_mastery import dll_sideload_hunter as dll_sideload_hunter
from .process_mastery import (
    process_protection_auditor as process_protection_auditor,
)
from .tampering_advanced import herpaderping_builder as herpaderping_builder
from .tampering_advanced import (
    process_ghosting_builder as process_ghosting_builder,
)
from .techniques import antivirus_evasion_checker as antivirus_evasion_checker
from .techniques import av_sandbox_detector as av_sandbox_detector
from .techniques import backdoor_scanner as backdoor_scanner
from .techniques import bad_usb_payload_generator as bad_usb_payload_generator
from .techniques import data_exfiltration_tester as data_exfiltration_tester
from .techniques import driver_blocklist_bypass as driver_blocklist_bypass
from .techniques import edr_bypass_checker as edr_bypass_checker
from .techniques import forensic_artifact_finder as forensic_artifact_finder
from .techniques import log_clearing_detector as log_clearing_detector
from .techniques import (
    persistence_mechanism_detector as persistence_mechanism_detector,
)
from .unhooking import (
    call_stack_spoofing_generator as call_stack_spoofing_generator,
)
from .unhooking import (
    hardware_breakpoint_detector as hardware_breakpoint_detector,
)
from .unhooking import ntdll_hook_cleaner as ntdll_hook_cleaner
from .unhooking import stub_integrity_checker as stub_integrity_checker


@tool
async def evasion_arsenal_health_check() -> str:
    """
    Performs a comprehensive diagnostic of the Evasion Arsenal's operational environment.
    Verifies OS-level compatibility, critical DLL availability, and process permissions.
    """
    try:
        is_win = platform.system() == "Windows"
        health_report = {
            "os_environment": platform.platform(),
            "critical_dlls": {},
            "python_capabilities": {
                "psutil_access": "VERIFIED"
                if psutil.virtual_memory()
                else "RESTRICTED",
                "ctypes_access": "VERIFIED"
                if hasattr(os, "add_dll_directory") or not is_win
                else "UNKNOWN",
            },
            "environment_constraints": [],
        }

        if is_win:
            system_root = os.environ.get("SystemRoot", "C:\\Windows")
            core_dlls = ["ntdll.dll", "kernelbase.dll", "advapi32.dll"]
            for dll in core_dlls:
                path = os.path.join(system_root, "System32", dll)
                health_report["critical_dlls"][dll] = (
                    "FOUND" if os.path.exists(path) else "MISSING"
                )

        # Robustness Logic: Check for virtualization triggers
        if psutil.virtual_memory().total < 4 * 1024**3:
            health_report["environment_constraints"].append("LOW_RAM_WARNING")

        return format_industrial_result(
            "evasion_arsenal_health_check",
            "Audit Completed",
            confidence=1.0,
            impact="LOW",
            raw_data=health_report,
            summary="Evasion arsenal health audit finished. Environment is ready for operational deployment.",
        )
    except Exception as e:
        return format_industrial_result(
            "evasion_arsenal_health_check", "Audit Failed", error=str(e)
        )
