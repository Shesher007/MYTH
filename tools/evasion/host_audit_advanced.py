import json
import asyncio
import os
import platform
import ctypes
from datetime import datetime
from myth_config import load_dotenv
from langchain_core.tools import tool
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 👻 Advanced Host-Level Evasion (The Ultimate Tier)
# ==============================================================================

@tool
async def applocker_bypass_hunter() -> str:
    r"""
    Scans the local Windows filesystem for globally writable directories that allow 
    executable execution, bypassing AppLocker/WDAC.
    Highly optimized parallel audit of known candidate paths.
    """
    try:
        is_windows = platform.system() == "Windows"
        if not is_windows:
            return format_industrial_result("applocker_bypass_hunter", "Incompatible", summary="This tool requires a Windows host.")

        # Standard bypass candidates (Red Team Gold Mine)
        targets = [
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Tasks'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Temp'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'tracing'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'registration'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32\\driverstore'),
            os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32\\com\\dmp'),
        ]

        async def check_path(path):
            if os.path.exists(path):
                # Check for write permission
                test_file = os.path.join(path, f"io_check_{random.randint(100, 999)}")
                try:
                    with open(test_file, 'w') as f:
                        f.write("Industrial Audit Probe")
                    os.remove(test_file)
                    return {"path": path, "writable": True, "class": "High-Value Bypass"}
                except: pass
            return None

        # PARALLEL EXECUTION
        results = await asyncio.gather(*(check_path(t) for t in targets))
        findings = [r for r in results if r is not None]

        return format_industrial_result(
            "applocker_bypass_hunter",
            "Audit Successful",
            confidence=1.0,
            impact="HIGH" if findings else "LOW",
            raw_data={"bypass_candidates": findings},
            summary=f"Parallel filesystem audit complete. Identified {len(findings)} writable system paths available for binary execution."
        )
    except Exception as e:
        return format_industrial_result("applocker_bypass_hunter", "Error", error=str(e))

@tool
async def edr_hook_analyzer() -> str:
    """
    Analyzes the 'ntdll.dll' in-memory image to detect EDR/AV user-land hooks.
    Checks for 'jmp' or 'ret' instructions at the start of critical system call stubs using ctypes.
    """
    try:
        is_windows = platform.system() == "Windows"
        if not is_windows:
            return format_industrial_result("edr_hook_analyzer", "Incompatible")

        findings = []
        # Critical APIs to check for hooks
        critical_apis = ["NtCreateThreadEx", "NtWriteVirtualMemory", "NtAllocateVirtualMemory", "NtProtectVirtualMemory"]
        
        # Industrial Pass: Use ctypes for memory audit
        kernel32 = ctypes.windll.kernel32
        ntdll = ctypes.windll.ntdll
        
        for api in critical_apis:
            addr = kernel32.GetProcAddress(ntdll._handle, api.encode())
            if not addr: continue
            
            # Read first 5 bytes
            buffer = (ctypes.c_ubyte * 5)()
            kernel32.ReadProcessMemory(kernel32.GetCurrentProcess(), addr, buffer, 5, None)
            
            # Check for common hook patterns: E9 (JMP), 48 B8 (MOV RAX, [8]), C3 (RET)
            is_hooked = buffer[0] == 0xE9 or buffer[0] == 0xC3 or (buffer[0] == 0x48 and buffer[1] == 0xB8)
            
            findings.append({
                "api": api,
                "address": hex(addr),
                "hook_detected": is_hooked,
                "stub_bytes": [hex(b) for b in list(buffer)]
            })

        return format_industrial_result(
            "edr_hook_analyzer",
            "Detected" if any(f['hook_detected'] for f in findings) else "Clean",
            confidence=1.0,
            impact="HIGH",
            raw_data={"results": findings},
            summary=f"ntdll.dll memory audit finished. Found {len([f for f in findings if f['hook_detected']])} active inline hook(s) on critical syscall stubs."
        )
    except Exception as e:
        return format_industrial_result("edr_hook_analyzer", "Error", error=str(e))
