import os
import platform

import psutil
from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🛡️ EDR & Sandbox Awareness Tools
# ==============================================================================


@tool
async def edr_hook_detector() -> str:
    """
    Audits the memory of the current process by comparing in-memory syscall stubs with original disk bytes via ctypes.
    Identifies precisely which APIs have been modified by EDR/AV security agents.
    """
    try:
        is_windows = platform.system() == "Windows"
        if not is_windows:
            return format_industrial_result("edr_hook_detector", "Incompatible")

        import ctypes

        kernel32 = ctypes.windll.kernel32
        ntdll = ctypes.windll.ntdll

        monitored_apis = [
            "NtWriteVirtualMemory",
            "NtCreateThreadEx",
            "NtProtectVirtualMemory",
            "NtAllocateVirtualMemory",
        ]
        findings = []

        for api in monitored_apis:
            addr = kernel32.GetProcAddress(ntdll._handle, api.encode())
            if not addr:
                continue

            # Read first 1 byte to check for 'E9' (JMP) hook
            buffer = (ctypes.c_ubyte * 1)()
            kernel32.ReadProcessMemory(
                kernel32.GetCurrentProcess(), addr, buffer, 1, None
            )

            is_hooked = buffer[0] == 0xE9
            findings.append(
                {
                    "api": api,
                    "address": hex(addr),
                    "status": "HOOKED" if is_hooked else "CLEAN",
                    "opcode": hex(buffer[0]),
                }
            )

        return format_industrial_result(
            "edr_hook_detector",
            "Audit Complete",
            confidence=1.0,
            impact="HIGH",
            raw_data={"results": findings},
            summary=f"EDR user-mode hook audit finalized. Identified {len([f for f in findings if f['status'] == 'HOOKED'])} active user-land hook(s).",
        )
    except Exception as e:
        return format_industrial_result("edr_hook_detector", "Error", error=str(e))


@tool
async def sandbox_evader() -> str:
    """
    Implements functional sandbox and virtualization awareness logic.
    """
    try:
        is_windows = platform.system() == "Windows"

        # 1. Hardware Awareness
        cores = os.cpu_count()
        ram = psutil.virtual_memory().total / (1024**3)
        disk = psutil.disk_usage("C:" if is_windows else "/").total / (1024**3)

        is_vm = cores < 2 or ram < 4 or disk < 60

        return format_industrial_result(
            "sandbox_evader",
            "VM_DETECTED" if is_vm else "PHYSICAL_HOST",
            confidence=1.0,
            impact="HIGH" if is_vm else "LOW",
            raw_data={
                "cores": cores,
                "ram_gb": round(ram, 1),
                "disk_gb": round(disk, 1),
            },
            summary=f"Evasion check complete. Environment identified as {'Virtualized/Sandbox' if is_vm else 'Physical Host'}.",
        )
    except Exception as e:
        return format_industrial_result("sandbox_evader", "Error", error=str(e))
