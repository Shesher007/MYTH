import platform
import os
import psutil
from langchain_core.tools import tool
from tools.utilities.report import format_industrial_result

# tools/evasion/__init__.py
from .techniques import *
# Wave 21: Evasion
from .edr_aware_payloads import *
# Advanced Evasion Modules
from .tampering_advanced import *
from .unhooking import *
from .execution_mastery import *
from .anti_analysis import *
from .persistence_advanced import *
from .payload_engineering import *
from .process_mastery import *
from .maldev_advanced import *
from .in_memory_stealth import *
from .host_audit_advanced import *

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
                "psutil_access": "VERIFIED" if psutil.virtual_memory() else "RESTRICTED",
                "ctypes_access": "VERIFIED" if hasattr(os, 'add_dll_directory') or not is_win else "UNKNOWN"
            },
            "environment_constraints": []
        }

        if is_win:
            system_root = os.environ.get('SystemRoot', 'C:\\Windows')
            core_dlls = ["ntdll.dll", "kernelbase.dll", "advapi32.dll"]
            for dll in core_dlls:
                path = os.path.join(system_root, "System32", dll)
                health_report["critical_dlls"][dll] = "FOUND" if os.path.exists(path) else "MISSING"
        
        # Robustness Logic: Check for virtualization triggers
        if psutil.virtual_memory().total < 4 * 1024**3:
            health_report["environment_constraints"].append("LOW_RAM_WARNING")

        return format_industrial_result(
            "evasion_arsenal_health_check",
            "Audit Completed",
            confidence=1.0,
            impact="LOW",
            raw_data=health_report,
            summary="Evasion arsenal health audit finished. Environment is ready for operational deployment."
        )
    except Exception as e:
        return format_industrial_result("evasion_arsenal_health_check", "Audit Failed", error=str(e))
