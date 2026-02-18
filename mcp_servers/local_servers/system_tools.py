#!/usr/bin/env python3
from fastmcp import FastMCP
from myth_config import load_dotenv
load_dotenv()
import os
import sys
import platform
import subprocess
import json
import tempfile
import psutil
import time
from datetime import datetime
from typing import Dict, List, Optional
from mcp_common import (
    MCPUtils, PlatformGuard, AccelerationGuard, TitanResponse, 
    NexusState, tool_exception_handler, logger
)

# Initialize MCP server
mcp = FastMCP("System Tools Server")

@mcp.tool()
@tool_exception_handler
async def get_system_info() -> TitanResponse:
    """Titan-Grade multi-platform system diagnostic."""
    info = {
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": sys.version,
        "is_windows": PlatformGuard.is_windows(),
        "hardware": AccelerationGuard.get_hardware_profile(),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
    }
    return TitanResponse(success=True, data=info)

@mcp.tool()
@tool_exception_handler
async def analyze_process_tree(pid: Optional[int] = None) -> TitanResponse:
    """Deep forensic analysis of process ancestry and children."""
    target_pid = pid or os.getpid()
    try:
        proc = psutil.Process(target_pid)
        tree = {
            "pid": proc.pid,
            "name": proc.name(),
            "parent": proc.parent().pid if proc.parent() else None,
            "children": [c.pid for c in proc.children()],
            "cmdline": proc.cmdline(),
            "status": proc.status(),
            "created": datetime.fromtimestamp(proc.create_time()).isoformat(),
            "threads": proc.num_threads(),
            "connections": len(proc.connections())
        }
        return TitanResponse(success=True, data=tree)
    except psutil.NoSuchProcess:
        return TitanResponse(success=False, data={}, metadata={"error": f"PID {target_pid} not found"})

@mcp.tool()
@tool_exception_handler
async def get_realtime_telemetry() -> TitanResponse:
    """High-fidelity real-time system performance telemetry."""
    telemetry = {
        "cpu": {
            "percent": psutil.cpu_percent(interval=None),
            "freq": psutil.cpu_freq().current if psutil.cpu_freq() else None,
            "count": psutil.cpu_count()
        },
        "memory": {
            "total": psutil.virtual_memory().total,
            "available": psutil.virtual_memory().available,
            "percent": psutil.virtual_memory().percent
        },
        "io": {
            "read": psutil.disk_io_counters().read_bytes,
            "write": psutil.disk_io_counters().write_bytes
        },
        "net": {
            "sent": psutil.net_io_counters().bytes_sent,
            "recv": psutil.net_io_counters().bytes_recv
        }
    }
    return TitanResponse(success=True, data=telemetry)
    """Retrieves the "ID Card" of the machine: OS version, kernel architecture (e.g., AMD64), hostname, and the current active user."""
    try:
        system_info = {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "hostname": platform.node(),
            "username": os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USERNAME', 'Unknown')
        }
        
        # Windows specific info
        if platform.system() == "Windows":
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                system_info["windows_product_name"] = winreg.QueryValueEx(key, "ProductName")[0]
                system_info["windows_build"] = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
                winreg.CloseKey(key)
            except:
                pass
        
        return system_info
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def get_disk_usage() -> Dict:
    """Reports on storage health, showing total, used, and free space across all partitions to ensure logs or tools have room to run."""
    try:
        partitions = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                partitions.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "fstype": partition.fstype,
                    "total_gb": usage.total / (1024**3),
                    "used_gb": usage.used / (1024**3),
                    "free_gb": usage.free / (1024**3),
                    "percent_used": usage.percent
                })
            except:
                continue
        
        return {
            "partitions": partitions,
            "total_partitions": len(partitions)
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def get_network_info() -> Dict:
    """Get network interface information."""
    try:
        interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            interface_info = {
                "name": interface,
                "addresses": []
            }
            
            for addr in addrs:
                if addr.family.name == 'AF_INET' or addr.family.name == 'AF_INET6':
                    interface_info["addresses"].append({
                        "family": addr.family.name,
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast if hasattr(addr, 'broadcast') else None
                    })
            
            interfaces.append(interface_info)
        
        return {
            "interfaces": interfaces,
            "total_interfaces": len(interfaces)
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def get_process_info(pid: int = None, name: str = None) -> Dict:
    """Get information about running processes."""
    try:
        processes = []
        
        if pid:
            try:
                proc = psutil.Process(pid)
                processes.append({
                    "pid": proc.pid,
                    "name": proc.name(),
                    "status": proc.status(),
                    "cpu_percent": proc.cpu_percent(interval=0.1),
                    "memory_percent": proc.memory_percent(),
                    "memory_rss_mb": proc.memory_info().rss / (1024*1024),
                    "command_line": " ".join(proc.cmdline()) if proc.cmdline() else "",
                    "username": proc.username(),
                    "create_time": proc.create_time()
                })
            except psutil.NoSuchProcess:
                return {"error": f"Process with PID {pid} not found"}
        
        elif name:
            for proc in psutil.process_iter(['pid', 'name', 'status']):
                try:
                    if name.lower() in proc.info['name'].lower():
                        p = psutil.Process(proc.info['pid'])
                        processes.append({
                            "pid": p.pid,
                            "name": p.name(),
                            "status": p.status(),
                            "cpu_percent": p.cpu_percent(interval=0.1),
                            "memory_percent": p.memory_percent(),
                            "memory_rss_mb": p.memory_info().rss / (1024*1024),
                            "command_line": " ".join(p.cmdline()) if p.cmdline() else "",
                            "username": p.username(),
                            "create_time": p.create_time()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        else:
            # Get top 20 processes by CPU
            for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), 
                              key=lambda p: p.info['cpu_percent'] or 0, 
                              reverse=True)[:20]:
                try:
                    p = psutil.Process(proc.info['pid'])
                    processes.append({
                        "pid": p.pid,
                        "name": p.name(),
                        "cpu_percent": p.cpu_percent(interval=0.1),
                        "memory_percent": p.memory_percent(),
                        "memory_rss_mb": p.memory_info().rss / (1024*1024),
                        "status": p.status()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        return {
            "processes": processes,
            "total_found": len(processes)
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def execute_command(command: str, timeout: int = 600, cwd: str = None) -> Dict:
    """Execute a shell command with a specified working directory and timeout. Includes safety pattern matching."""
    try:
        # Security check - prevent dangerous commands
        dangerous_patterns = ['rm -rf', 'format', 'del /', 'rd /s /q', ':(){:|:&};:', 'mkfs', 'dd if=']
        if any(pattern in command.lower() for pattern in dangerous_patterns):
            return {"error": "Command contains potentially dangerous patterns"}
        
        target_cwd = cwd if cwd and os.path.exists(cwd) else os.getcwd()
        
        # Execute command
        import subprocess
        result = subprocess.run(
            command,
            cwd=target_cwd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return {
            "command": command,
            "cwd": target_cwd,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {timeout} seconds"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def get_active_connections() -> Dict:
    """Maps active network connections (established or listening) directly to process PIDs and names for forensic visibility."""
    import psutil
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            
            # Get process info
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                pname = proc.name() if proc else "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "Unknown"

            connections.append({
                "pid": conn.pid,
                "process_name": pname,
                "protocol": "TCP" if conn.type == 1 else "UDP",
                "local_address": laddr,
                "remote_address": raddr,
                "status": conn.status
            })
            
        return {
            "total_connections": len(connections),
            "connections": sorted(connections, key=lambda x: x['status'])
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def get_system_health() -> Dict:
    """Get overall system health metrics."""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        # Memory usage
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk I/O
        disk_io = psutil.disk_io_counters()
        
        # Network I/O
        net_io = psutil.net_io_counters()
        
        # Boot time
        boot_time = psutil.boot_time()
        
        return {
            "cpu": {
                "percent_used": cpu_percent,
                "cores_physical": cpu_count,
                "cores_logical": psutil.cpu_count(logical=True),
                "frequency_current": cpu_freq.current if cpu_freq else None,
                "frequency_max": cpu_freq.max if cpu_freq else None
            },
            "memory": {
                "total_gb": memory.total / (1024**3),
                "available_gb": memory.available / (1024**3),
                "percent_used": memory.percent,
                "used_gb": memory.used / (1024**3)
            },
            "swap": {
                "total_gb": swap.total / (1024**3),
                "used_gb": swap.used / (1024**3),
                "percent_used": swap.percent
            },
            "disk_io": {
                "read_mb": disk_io.read_bytes / (1024**2) if disk_io else 0,
                "write_mb": disk_io.write_bytes / (1024**2) if disk_io else 0
            },
            "network_io": {
                "bytes_sent_mb": net_io.bytes_sent / (1024**2),
                "bytes_recv_mb": net_io.bytes_recv / (1024**2)
            },
            "system": {
                "boot_time": boot_time,
                "uptime_hours": (time.time() - boot_time) / 3600,
                "users": [user.name for user in psutil.users()]
            }
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def registry_read(root_key: str, subkey: str, value_name: str = None) -> Dict:
    """Read a Windows Registry key/value. Supported Roots: HKLM, HKCU, HKCR, HKU, HKCC."""
    if platform.system() != "Windows":
        return {"error": "Registry tools only available on Windows"}
    
    import winreg
    root_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG
    }
    
    root_hkey = root_map.get(root_key.upper())
    if not root_hkey:
        return {"error": f"Invalid Root Key. Use: {list(root_map.keys())}"}
        
    try:
        key = winreg.OpenKey(root_hkey, subkey, 0, winreg.KEY_READ)
        
        # Read specific value
        if value_name:
            val, val_type = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return {"root": root_key, "key": subkey, "value_name": value_name, "value": val, "type": val_type}
            
        # Or list all values in key
        values = []
        try:
            i = 0
            while True:
                v_name, v_data, v_type = winreg.EnumValue(key, i)
                values.append({"name": v_name, "data": str(v_data), "type": v_type})
                i += 1
        except OSError:
            pass # End of list
            
        winreg.CloseKey(key)
        return {"root": root_key, "key": subkey, "values": values, "count": len(values)}
        
    except FileNotFoundError:
        return {"error": "Key or Value not found"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
def list_services(status_filter: str = None) -> Dict:
    """List Windows services. Filter by 'running', 'stopped', or 'paused'."""
    if platform.system() != "Windows":
        return {"error": "Service tools only available on Windows"}
        
    services = []
    try:
        for service in psutil.win_service_iter():
            try:
                s_info = service.as_dict()
                if status_filter and s_info['status'] != status_filter:
                    continue
                    
                services.append({
                    "name": s_info['name'],
                    "display_name": s_info['display_name'],
                    "status": s_info['status'],
                    "start_type": s_info['start_type'],
                    "pid": s_info['pid']
                })
            except Exception:
                continue
                
        return {
            "services": sorted(services, key=lambda x: x['name']),
            "total_found": len(services),
            "filter": status_filter or "all"
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import os
    # Default to 8002 for the system tools server
    port = int(os.getenv("FASTMCP_PORT", 8002))
    mcp.run(transport="sse", port=port, show_banner=False)
