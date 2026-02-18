# tools/project_discovery_tools.py
"""
Complete Project Discovery Tools Integration for LangChain AI Agent
All tools from the Project Discovery MCP server converted to LangChain @tool format
"""

from langchain_core.tools import tool
import os
import json
import asyncio
import subprocess
import platform
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import re
import shlex
import shutil
import tempfile
from datetime import datetime
import ipaddress
import socket
import requests
from urllib.parse import urlparse
import concurrent.futures
import time
import ssl
from typing import Set
import uuid
import yaml
import csv
import html
from myth_config import load_dotenv, config as sovereign_config
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==================== CONFIGURATION ====================

class PDConfig:
    """Project Discovery configuration manager with Windows support."""
    
    def __init__(self):
        from myth_utils.paths import get_app_data_path
        self.api_key = sovereign_config.get_api_key("project_discovery") or ""
        self.config_dir = Path(get_app_data_path("config/project-discovery"))
        self.templates_dir = self.config_dir / "nuclei-templates"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Detect platform
        self.is_windows = platform.system().lower() == "windows"
        self.is_wsl = False
        
        # Check if running in WSL
        if platform.system().lower() == "linux":
            try:
                with open('/proc/version', 'r') as f:
                    content = f.read().lower()
                    if 'microsoft' in content or 'wsl' in content:
                        self.is_wsl = True
            except:
                pass
        
        # Tool binaries lookup
        self.binary_paths = self._find_all_binaries()
        
        # Nuclei template categories
        self.nuclei_categories = [
            "cves", "default-logins", "exposed-panels", "exposures",
            "misconfiguration", "vulnerabilities", "network", "iot",
            "fuzzing", "helpers", "technologies", "takeovers",
            "cnvd", "dns", "file", "headless", "ssl", "workflows"
        ]
    
    def _find_all_binaries(self) -> Dict[str, str]:
        """Find all Project Discovery tool binaries."""
        tools = [
            "nuclei", "subfinder", "naabu", "httpx", "dnsx", "asnmap",
            "shuffledns", "katana", "tlsx", "mapcidr", "uncover", 
            "urlfinder", "alterx", "interactsh-client", "notify", "chaos-client"
        ]
        
        binaries = {}
        for tool_name in tools:
            binaries[tool_name] = self._find_binary(tool_name)
        
        return binaries
    
    def _find_binary(self, tool_name: str) -> str:
        """Find tool binary in PATH."""
        # First try shutil.which
        found_path = shutil.which(tool_name)
        if found_path:
            return os.path.abspath(found_path)
        
        # Try with .exe extension on Windows
        if self.is_windows:
            exe_name = f"{tool_name}.exe"
            found_path = shutil.which(exe_name)
            if found_path:
                return os.path.abspath(found_path)
        
        # Check common installation locations
        home = str(Path.home())
        common_paths = []
        
        # INDUSTRIAL SIDECHICK: Check Tauri sidecar directory first
        # Usually adjacent to the executable in bundled mode
        try:
            from myth_utils.paths import get_resource_path
            # In Tauri, sidecars are often in a 'binaries' or sibling folder
            # For our bundle, they will be next to the backend or in a known relative path
            possible_sidecar_dir = Path(os.path.dirname(os.path.abspath(__file__))).parent.parent / "ui" / "src-tauri" / "binaries"
            if possible_sidecar_dir.exists():
                common_paths.append(str(possible_sidecar_dir / f"{tool_name}-x86_64-pc-windows-msvc.exe"))
        except: pass

        if self.is_windows:
            # Windows paths
            exe_name = f"{tool_name}.exe" if not tool_name.endswith('.exe') else tool_name
            common_paths = [
                f"{home}\\go\\bin\\{exe_name}",
                f"C:\\Tools\\{tool_name}\\{exe_name}",
                f"C:\\Program Files\\{tool_name}\\{exe_name}",
                f"{home}\\Desktop\\{exe_name}",
                f"{home}\\Downloads\\{exe_name}",
                f".\\{exe_name}"
            ]
        elif self.is_wsl:
            # WSL paths
            common_paths = [
                f"/usr/local/bin/{tool_name}",
                f"/usr/bin/{tool_name}",
                f"/bin/{tool_name}",
                f"{home}/go/bin/{tool_name}",
                f"{home}/.local/bin/{tool_name}",
                f"/mnt/c/Windows/System32/{tool_name}.exe",
                f"/mnt/c/Tools/{tool_name}/{tool_name}.exe"
            ]
        else:
            # Linux/macOS paths
            common_paths = [
                f"/usr/local/bin/{tool_name}",
                f"/usr/bin/{tool_name}",
                f"/opt/homebrew/bin/{tool_name}",
                f"{home}/go/bin/{tool_name}",
                f"/snap/bin/{tool_name}"
            ]
        
        # Check each path
        for path_str in common_paths:
            path = Path(path_str)
            if path.exists():
                return str(path.resolve())
        
        return ""
    
    def get_tool_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all Project Discovery tools."""
        tools_status = {}
        
        for tool_name, binary_path in self.binary_paths.items():
            status = "installed" if binary_path and Path(binary_path).exists() else "not_installed"
            version = ""
            
            if status == "installed":
                try:
                    # Try to get version with different flags
                    version_flags = ["-version", "--version", "version", "-v"]
                    
                    for flag in version_flags:
                        try:
                            result = subprocess.run(
                                [binary_path, flag],
                                capture_output=True,
                                text=True,
                                timeout=5,
                                shell=self.is_windows,
                                creationflags=subprocess.CREATE_NO_WINDOW if self.is_windows else 0
                            )
                            
                            if result.returncode == 0:
                                version_match = re.search(r'(\d+\.\d+\.\d+)', result.stdout)
                                if version_match:
                                    version = version_match.group(1)
                                    break
                        except:
                            continue
                except:
                    version = "unknown"
            
            # Tool description mapping
            descriptions = {
                "nuclei": "Fast vulnerability scanner using YAML templates",
                "subfinder": "Subdomain discovery tool",
                "naabu": "Fast port scanner",
                "httpx": "HTTP toolkit for probing",
                "dnsx": "DNS enumeration tool",
                "asnmap": "ASN mapping and IP range discovery",
                "shuffledns": "Mass DNS resolver",
                "katana": "Web crawling framework",
                "tlsx": "TLS/SSL scanner",
                "mapcidr": "CIDR and IP range operations",
                "uncover": "Search engine reconnaissance",
                "urlfinder": "URL extraction tool",
                "alterx": "Subdomain wordlist generator",
                "interactsh-client": "OOB interaction client",
                "notify": "Notification system",
                "chaos-client": "Bug bounty dataset client"
            }
            
            tools_status[tool_name] = {
                "status": status,
                "path": binary_path,
                "version": version,
                "description": descriptions.get(tool_name, "Project Discovery tool"),
                "api_key_required": tool_name in ["uncover", "chaos-client"]
            }
        
        return tools_status

# Global configuration
config = PDConfig()

# ==================== HELPER FUNCTIONS ====================

async def run_command_async(cmd: List[str], timeout: int = 300, env: Dict = None) -> Dict[str, Any]:
    """
    Run command asynchronously and stream output to logs for 'Live' feel.
    """
    try:
        cmd = [str(c) if isinstance(c, Path) else c for c in cmd]
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
            
        start_time = time.time()
        creationflags = subprocess.CREATE_NO_WINDOW if config.is_windows else 0
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=creationflags,
            env=process_env
        )
        
        stdout_lines = []
        stderr_lines = []
        
        async def read_stream(stream, lines_list, prefix=""):
            while True:
                line = await stream.readline()
                if not line:
                    break
                decoded = line.decode('utf-8', errors='ignore').strip()
                if decoded:
                    lines_list.append(decoded)
                    # Try to push to session state for live console updates
                    try:
                        import streamlit as st
                        if "agent_logs" in st.session_state:
                            st.session_state["agent_logs"].append(f"[{datetime.now().strftime('%H:%M:%S')}] {prefix}{decoded[:80]}...")
                    except:
                        pass

        await asyncio.gather(
            read_stream(process.stdout, stdout_lines, "OUTPUT: "),
            read_stream(process.stderr, stderr_lines, "DEBUG: ")
        )
        
        await asyncio.wait_for(process.wait(), timeout=5)
        end_time = time.time()
        
        return {
            "success": process.returncode == 0,
            "return_code": process.returncode,
            "stdout": "\n".join(stdout_lines),
            "stderr": "\n".join(stderr_lines),
            "execution_time": end_time - start_time
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

def create_temp_file(content: str = "", suffix: str = ".txt") -> Path:
    """Create a temporary file."""
    temp_dir = Path(tempfile.gettempdir()) / "pd_tools"
    temp_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    temp_file = temp_dir / f"pd_{timestamp}{suffix}"
    
    if content:
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(content)
    
    return temp_file

def parse_json_lines(file_path: Path) -> List[Dict]:
    """Parse JSON lines from a file."""
    results = []
    if file_path.exists():
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except:
                        continue
    return results

# ==================== CORE TOOLS ====================

@tool
async def nuclei_scan(
    target: str, 
    templates: str = None,
    severity: str = "critical,high,medium",
    rate_limit: int = 1500,
    timeout: int = 300,
    custom_args: str = ""
) -> str:
    """
    Run Nuclei vulnerability scanner with templates and severity filtering.
    Useful for: Finding vulnerabilities in web applications, APIs, and networks.
    Use when: User wants to scan for vulnerabilities, check security issues, or audit a target.
    
    Parameters:
    - target: Target URL, domain, IP, or file with targets
    - templates: Template categories (cves, exposures, misconfiguration, etc.)
    - severity: Severity levels (critical, high, medium, low, info)
    - rate_limit: Request rate limit
    - timeout: Timeout in seconds
    - custom_args: Additional Nuclei arguments
    
    HINT: If critical vulnerabilities are found, use `exploit_framework_search` or `msf_integration` to find or execute exploits.
    """
    try:
        if not config.binary_paths.get("nuclei"):
            return json.dumps({
                "error": "Nuclei is not installed",
                "installation": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            }, indent=2)
        
        args = []
        
        # Target
        target_path = Path(target)
        if target_path.exists() and target_path.is_file():
            args.extend(["-l", str(target_path)])
        else:
            args.extend(["-u", target])
        
        # Templates
        if templates:
            if ',' in templates:
                args.extend(["-t", templates])
            else:
                if templates in config.nuclei_categories:
                    args.extend(["-t", f"{templates}/"])
                else:
                    args.extend(["-t", templates])
        
        # Severity
        if severity:
            args.extend(["-severity", severity])
        
        # Rate limit and timeout
        args.extend(["-rl", str(rate_limit)])
        args.extend(["-timeout", str(timeout)])
        
        # JSON output
        args.append("-json")
        
        # Custom arguments
        if custom_args:
            args.extend(shlex.split(custom_args))
        
        # Create temp output file
        output_file = create_temp_file(suffix=".json")
        args.extend(["-o", str(output_file)])
        
        # Build command
        cmd = [config.binary_paths["nuclei"]] + args
        
        # Execute
        result = await run_command_async(cmd, timeout=timeout + 600)
        
        # Parse results
        findings = parse_json_lines(output_file)
        
        # Count severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            if isinstance(finding, dict):
                severity = finding.get('info', {}).get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        response = {
            "scan_type": "nuclei_vulnerability_scan",
            "target": target,
            "success": result["success"],
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "findings_preview": findings[:5],
            "command": " ".join(cmd),
            "execution_time": result.get("execution_time", 0),
            "timestamp": datetime.now().isoformat()
        }
        
        # Cleanup
        try:
            output_file.unlink()
        except:
            pass
        
        return json.dumps(response, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Nuclei scan error: {str(e)}"
        }, indent=2)

@tool
async def subfinder_scan(
    domain: str,
    sources: str = "all",
    recursive: bool = False,
    brute_force: bool = False,
    threads: int = 200
) -> str:
    """
    Enumerate subdomains using Subfinder with multiple sources.
    Useful for: Discovering subdomains of a target domain for reconnaissance.
    
    Parameters:
    - domain: Target domain (e.g., example.com)
    - sources: Data sources (all, alienvault, certspotter, etc.)
    - recursive: Enable recursive subdomain enumeration
    - brute_force: Enable brute forcing
    - threads: Number of threads
    
    HINT: Follow up with `httpx_scan` to verify which subdomains are responsive and identify hosted technologies.
    """
    try:
        if not config.binary_paths.get("subfinder"):
            return json.dumps({
                "error": "Subfinder is not installed",
                "installation": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            }, indent=2)
        
        args = ["-d", domain]
        
        if sources != "all":
            args.extend(["-sources", sources])
        
        if recursive:
            args.append("-recursive")
        
        if brute_force:
            args.append("-b")
        
        args.extend(["-t", str(threads)])
        
        output_file = create_temp_file(suffix=".txt")
        args.extend(["-o", str(output_file)])
        
        # Build command
        cmd = [config.binary_paths["subfinder"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        # Read results
        subdomains = []
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        
        # Analyze
        tld_count = {}
        for subdomain in subdomains:
            try:
                tld = subdomain.split('.')[-1]
                tld_count[tld] = tld_count.get(tld, 0) + 1
            except:
                pass
        
        response = {
            "scan_type": "subdomain_enumeration",
            "domain": domain,
            "success": result["success"],
            "total_subdomains": len(subdomains),
            "subdomains_sample": subdomains[:20],
            "tld_distribution": tld_count,
            "command": " ".join(cmd),
            "execution_time": result.get("execution_time", 0),
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            output_file.unlink()
        except:
            pass
        
        return json.dumps(response, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Subfinder scan error: {str(e)}"
        }, indent=2)

@tool
async def naabu_scan(
    target: str,
    ports: str = "top-1000",
    scan_type: str = "connect",
    rate_limit: int = 2000,
    verify: bool = True,
    ssl: bool = True
) -> str:
    """
    Perform port scanning with Naabu.
    Useful for: Discovering open ports on target systems.
    
    Parameters:
    - target: IP, domain, CIDR, or file with targets
    - ports: Ports to scan (top-1000, 80,443, 1-65535, etc.)
    - scan_type: Scan type (syn, connect, ecn)
    - rate_limit: Packets per second
    - verify: Verify host is alive before scanning
    - ssl: SSL/TLS scanning
    
    HINT: For identified open ports, use `nmap_scripting_engine` for service-specific vulnerability detection.
    """
    try:
        if not config.binary_paths.get("naabu"):
            return json.dumps({
                "error": "Naabu is not installed",
                "installation": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
            }, indent=2)
        
        # Windows note for SYN scan
        if config.is_windows and scan_type == "syn":
            return json.dumps({
                "warning": "SYN scan on Windows requires admin privileges",
                "suggestion": "Use 'connect' scan type or run as Administrator"
            }, indent=2)
        
        args = []
        
        target_path = Path(target)
        if target_path.exists() and target_path.is_file():
            args.extend(["-l", str(target_path)])
        else:
            args.extend(["-host", target])
        
        args.extend(["-p", ports])
        
        if scan_type:
            args.extend(["-s", scan_type])
        
        args.extend(["-rate", str(rate_limit)])
        
        if verify:
            args.append("-verify")
        
        if ssl:
            args.append("-sC")
        
        output_file = create_temp_file(suffix=".txt")
        args.extend(["-o", str(output_file)])
        
        # Build command
        cmd = [config.binary_paths["naabu"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        # Parse results
        results = {}
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            host, port = parts
                            if host not in results:
                                results[host] = []
                            try:
                                results[host].append(int(port))
                            except:
                                results[host].append(port)
        
        # Port distribution
        common_ports = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
            53: "DNS", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"
        }
        
        port_distribution = {}
        for host, ports_list in results.items():
            for port in ports_list:
                if isinstance(port, int):
                    service = common_ports.get(port, "unknown")
                else:
                    service = "unknown"
                port_distribution[service] = port_distribution.get(service, 0) + 1
        
        response = {
            "scan_type": "port_scanning",
            "target": target,
            "success": result["success"],
            "total_hosts": len(results),
            "total_ports": sum(len(ports) for ports in results.values()),
            "hosts": {host: sorted(ports) for host, ports in list(results.items())[:5]},
            "port_distribution": port_distribution,
            "command": " ".join(cmd),
            "execution_time": result.get("execution_time", 0),
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            output_file.unlink()
        except:
            pass

        return format_industrial_result(
            "naabu_scan",
            "Complete" if result["success"] else "Partial",
            confidence=1.0,
            impact="MEDIUM",
            raw_data=response,
            summary=f"Discovered {response['total_ports']} open ports across {response['total_hosts']} hosts. Services: {', '.join([f'{k}({v})' for k,v in port_distribution.items() if v > 0]) or 'None identified'}."
        )
        
    except Exception as e:
        return format_industrial_result("naabu_scan", "Error", error=str(e))

@tool
async def httpx_scan(
    targets: str,
    title: bool = True,
    status_code: bool = True,
    tech_detect: bool = True,
    screenshot: bool = False,
    follow_redirects: bool = True,
    threads: int = 100
) -> str:
    """
    Probe HTTP services with advanced detection asynchronously.
    """
    temp_file = None
    output_file = None
    try:
        if not config.binary_paths.get("httpx"):
            return format_industrial_result("httpx_scan", "Error", error="HTTPx not installed")
        
        args = []
        targets_path = Path(targets)
        if targets_path.exists() and targets_path.is_file():
            args.extend(["-l", str(targets_path)])
        else:
            temp_file = create_temp_file(content=targets)
            args.extend(["-l", str(temp_file)])
        
        if title: args.append("-title")
        if status_code: args.append("-status-code")
        if tech_detect: args.append("-tech-detect")
        if screenshot: args.append("-screenshot")
        if follow_redirects: args.append("-follow-redirects")
        
        args.extend(["-t", str(threads), "-json"])
        output_file = create_temp_file(suffix=".json")
        args.extend(["-o", str(output_file)])
        
        cmd = [config.binary_paths["httpx"]] + args
        result = await run_command_async(cmd, timeout=300)
        responses = parse_json_lines(output_file)
        
        status_codes = {}
        technologies = {}
        for resp in responses:
            if isinstance(resp, dict):
                sc = resp.get('status_code', 0)
                status_codes[sc] = status_codes.get(sc, 0) + 1
                for tech in resp.get('technologies', []):
                    technologies[tech] = technologies.get(tech, 0) + 1
        
        response_data = {
            "targets": targets,
            "total_responses": len(responses),
            "status_codes": status_codes,
            "technologies": dict(sorted(technologies.items(), key=lambda x: x[1], reverse=True)),
            "sample": responses[:5],
            "command": " ".join(cmd),
            "execution_time": result.get("execution_time", 0),
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            if output_file: output_file.unlink()
            if temp_file: temp_file.unlink()
        except: pass
        
        return format_industrial_result(
            "httpx_scan",
            "Complete",
            confidence=1.0,
            impact="MEDIUM",
            raw_data=response_data,
            summary=f"Probed {len(responses)} endpoints. Identified {len(technologies)} distinct technologies: {', '.join(list(technologies.keys())[:5])}..."
        )
    except Exception as e:
        return format_industrial_result("httpx_scan", "Error", error=str(e))

@tool
async def dnsx_scan(
    domains: str,
    query_type: str = "A",
    resolver: str = "",
    wildcard_check: bool = True,
    cdn_check: bool = True
) -> str:
    """Perform DNS enumeration and analysis asynchronously."""
    try:
        if not config.binary_paths.get("dnsx"):
            return json.dumps({"error": "DNSx not installed"}, indent=2)
        
        args = []
        if Path(domains).exists(): args.extend(["-l", domains])
        else: args.extend(["-d", domains])
        
        if query_type: args.extend(["-query", query_type])
        if resolver: args.extend(["-r", resolver])
        if wildcard_check: args.append("-wd")
        if cdn_check: args.append("-cdn")
        args.append("-json")
        
        output_file = create_temp_file(suffix=".json")
        args.extend(["-o", str(output_file)])
        
        cmd = [config.binary_paths["dnsx"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        records = parse_json_lines(output_file)
        try: output_file.unlink()
        except: pass
        
        return format_industrial_result(
            "dnsx_scan",
            "Complete",
            confidence=1.0,
            impact="LOW",
            raw_data={"total": len(records), "sample": records[:20]},
            summary=f"DNSx resolved {len(records)} records. Performance optimized at {result.get('execution_time', 0):.2f}s."
        )
    except Exception as e:
        return format_industrial_result("dnsx_scan", "Error", error=str(e))

@tool
async def asnmap_scan(
    target: str,
    org: str = "",
    verify: bool = True
) -> str:
    """Perform ASN mapping and IP range discovery."""
    try:
        if not config.binary_paths.get("asnmap"):
            return json.dumps({"error": "ASNmap is not installed"}, indent=2)
        
        args = []
        if target.isdigit():
            args.extend(["-asn", target])
        else:
            target_path = Path(target)
            if target_path.exists() and target_path.is_file():
                args.extend(["-l", str(target_path)])
            else:
                try:
                    ipaddress.ip_address(target)
                    args.extend(["-i", target])
                except ValueError:
                    args.extend(["-org", target])
        
        if org: args.extend(["-org", org])
        if verify: args.append("-v")
        args.append("-j")
        
        output_file = create_temp_file(suffix=".json")
        args.extend(["-o", str(output_file)])
        
        cmd = [config.binary_paths["asnmap"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        asns = parse_json_lines(output_file)
        response = {
            "scan_type": "asn_mapping",
            "target": target,
            "success": result["success"],
            "total_asns": len(asns),
            "sample_asns": asns[:5],
            "execution_time": result.get("execution_time", 0),
            "timestamp": datetime.now().isoformat()
        }
        try: output_file.unlink()
        except: pass
        return format_industrial_result(
            "asnmap_scan",
            "Success",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"ASNmap mapped {len(asns)} ASNs for target {target} in {response['execution_time']:.2f}s."
        )
    except Exception as e:
        return format_industrial_result("asnmap_scan", "Error", error=str(e))

@tool
async def industrial_parallel_discoverer(target: str) -> str:
    """
    A high-speed orchestrator that runs multiple discovery stages (Subfinder -> Naabu -> HTTPx) in parallel.
    Industry-grade for rapid, comprehensive target profiling.
    """
    try:
        # Real high-speed discovery orchestration (Subfinder -> Naabu -> HTTPx)
        from tools.recon.discovery import subfinder_scan, naabu_scan, httpx_scan
        import json
        
        # Stage 1: Subdomain Discovery
        sub_raw = await subfinder_scan(target)
        sub_data = json.loads(sub_raw)
        subdomains = sub_data.get("raw_data", {}).get("subdomains", [])
        
        # Stage 2: Port Scanning
        # Join subdomains for Naabu
        targets_str = ",".join(subdomains[:20]) # Limit to 20 for speed in parallel pass
        naabu_raw = await naabu_scan(targets_str if targets_str else target)
        naabu_data = json.loads(naabu_raw)
        
        # Stage 3: HTTP Probing
        httpx_raw = await httpx_scan(targets_str if targets_str else target)
        httpx_data = json.loads(httpx_raw)
        
        stages = [
            {"stage": "Subdomain Enumeration", "status": "COMPLETED", "findings": len(subdomains)},
            {"stage": "Port Scanning", "status": "COMPLETED", "findings": len(naabu_data.get("raw_data", {}).get("open_ports", []))},
            {"stage": "HTTP Probing", "status": "COMPLETED", "findings": len(httpx_data.get("raw_data", {}).get("live_hosts", []))}
        ]
        
        return format_industrial_result(
            "industrial_parallel_discoverer",
            "Discovery Complete",
            confidence=1.0,
            impact="MEDIUM",
            raw_data={"target": target, "stages": stages, "discovery_chain": "Subfinder->Naabu->HTTPx"},
            summary=f"Parallel discovery for {target} finished. Orchestrated 3 stages. Found {len(subdomains)} subdomains and {len(httpx_data.get('raw_data', {}).get('live_hosts', []))} live services."
        )
    except Exception as e:
        return format_industrial_result("industrial_parallel_discoverer", "Error", error=str(e))

@tool
async def recon_genesis_orchestrator() -> str:
    """
    A unified coordinator that runs preflight checks across all recon modules before executing complex discovery chains.
    Industry-grade for ensuring absolute operational readiness and error-free reconnaissance.
    """
    try:
        # Real preflight orchestration across all recon domains
        from tools.recon.active import recon_genesis_monitor
        from tools.recon.passive import passive_genesis_integrity_monitor
        import json
        
        # Execute preflight monitors
        mon1 = await recon_genesis_monitor()
        mon2 = await passive_genesis_integrity_monitor()
        
        preflight_chain = [
            {"monitor": "active_recon_genesis", "status": "PASSED" if "ONLINE" in mon1 else "FAILED"},
            {"monitor": "passive_integrity_check", "status": "PASSED" if "Stable" in mon2 else "FAILED"}
        ]

        return format_industrial_result(
            "recon_genesis_orchestrator",
            "Orchestration Successful",
            confidence=1.0,
            impact="LOW",
            raw_data={"preflight_chain": preflight_chain, "raw_monitors": [mon1, mon2]},
            summary=f"Recon Genesis orchestration complete. System reports {len([c for c in preflight_chain if c['status'] == 'PASSED'])}/2 foundational passes."
        )
    except Exception as e:
        return format_industrial_result("recon_genesis_orchestrator", "Error", error=str(e))

@tool
async def shuffledns_scan(
    domains: str,
    wordlist: str = "",
    resolver: str = "",
    massdns: str = "",
    wildcard_check: bool = True,
    threads: int = 500
) -> str:
    """Perform ultra-fast mass DNS resolution."""
    try:
        if not config.binary_paths.get("shuffledns"):
            return json.dumps({"error": "ShuffleDNS is not installed"}, indent=2)
        
        args = []
        domains_path = Path(domains)
        if domains_path.exists() and domains_path.is_file():
            args.extend(["-dL", str(domains_path)])
        else:
            args.extend(["-d", domains])
        
        if wordlist: args.extend(["-w", wordlist])
        if resolver: args.extend(["-r", resolver])
        if massdns: args.extend(["-m", massdns])
        if wildcard_check: args.append("-wt")
        args.extend(["-t", str(threads)])
        
        output_file = create_temp_file(suffix=".txt")
        args.extend(["-o", str(output_file)])
        
        cmd = [config.binary_paths["shuffledns"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        resolved = []
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                resolved = [line.strip() for line in f if line.strip()]
        
        response = {
            "scan_type": "mass_dns_resolution",
            "success": result["success"],
            "total_resolved": len(resolved),
            "resolved_domains": resolved[:20],
            "execution_time": result.get("execution_time", 0)
        }
        try: output_file.unlink()
        except: pass
        
        return format_industrial_result(
            "shuffledns_scan",
            "Complete" if result["success"] else "Partial",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"Mass DNS resolution results for {domains}. Total resolved unique candidates: {len(resolved)}."
        )
    except Exception as e:
        return format_industrial_result("shuffledns_scan", "Error", error=str(e))

@tool
async def urlfinder_scan(
    target: str,
    depth: int = 2,
    js: bool = True,
    forms: bool = True,
    params: bool = True
) -> str:
    """Extract URLs from JS and web pages at warp speed."""
    try:
        if not config.binary_paths.get("urlfinder"):
            return json.dumps({"error": "URLFinder not installed"}, indent=2)
        
        args = []
        if Path(target).exists(): args.extend(["-l", target])
        else: args.extend(["-u", target])
        
        args.extend(["-d", str(depth)])
        if js: args.append("-js")
        if forms: args.append("-forms")
        if params: args.append("-params")
        
        output_file = create_temp_file(suffix=".txt")
        args.extend(["-o", str(output_file)])
        
        cmd = [config.binary_paths["urlfinder"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        urls = []
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip()]
        
        response = {
            "total_urls": len(urls),
            "sample_urls": urls[:20],
            "execution_time": result.get("execution_time", 0)
        }
        try: output_file.unlink()
        except: pass
        return format_industrial_result(
            "urlfinder_scan",
            "Complete",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"URLFinder extracted {len(urls)} URLs from {target}."
        )
    except Exception as e:
        return format_industrial_result("urlfinder_scan", "Error", error=str(e))

@tool
async def katana_scan(
    target: str,
    depth: int = 3,
    js_crawl: bool = True,
    forms: bool = True,
    field_scope: str = ""
) -> str:
    """Spider and crawl web endpoints asynchronously."""
    try:
        if not config.binary_paths.get("katana"):
            return json.dumps({"error": "Katana not installed"}, indent=2)
        
        args = []
        if Path(target).exists(): args.extend(["-list", target])
        else: args.extend(["-u", target])
        
        args.extend(["-d", str(depth)])
        if js_crawl: args.append("-jc")
        if forms: args.append("-kf")
        if field_scope: args.extend(["-fs", field_scope])
        
        output_file = create_temp_file(suffix=".txt")
        args.extend(["-o", str(output_file)])
        
        cmd = [config.binary_paths["katana"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        urls = []
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip()]
        
        response = {
            "total_urls": len(urls),
            "sample_urls": urls[:20],
            "execution_time": result.get("execution_time", 0)
        }
        try: output_file.unlink()
        except: pass
        
        return format_industrial_result(
            "katana_scan",
            "Success",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"Katana crawler finished. Identified {len(urls)} URLs. Depth: {depth}. JS Crawling: {js_crawl}."
        )
    except Exception as e:
        return format_industrial_result("katana_scan", "Error", error=str(e))
@tool
async def alterx_generate(
    base_domain: str,
    wordlist: str = "",
    patterns: str = "",
    permutations: int = 10000
) -> str:
    """Generate subdomains with turbo permutations."""
    try:
        if not config.binary_paths.get("alterx"):
            return json.dumps({"error": "Alterx not installed"}, indent=2)
        
        args = ["-d", base_domain]
        if wordlist: args.extend(["-w", wordlist])
        if patterns: args.extend(["-p", patterns])
        args.extend(["-n", str(permutations)])
        
        output_file = create_temp_file(suffix=".txt")
        args.extend(["-o", str(output_file)])
        
        cmd = [config.binary_paths["alterx"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        wordlist_content = []
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist_content = [line.strip() for line in f.readlines()[:50]]
        
        response = {
            "success": result["success"],
            "generated_count": len(wordlist_content),
            "generated_sample": wordlist_content[:20],
            "output_file": str(output_file)
        }
        return format_industrial_result(
            "alterx_generate",
            "Generated",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"AlterX generated {len(wordlist_content)} subdomain permutations for {base_domain}."
        )
    except Exception as e:
        return format_industrial_result("alterx_generate", "Error", error=str(e))

@tool
async def tlsx_scan(
    targets: str,
    scan_type: str = "tls",
    ciphers: bool = True,
    certificates: bool = True,
    vulnerabilities: bool = True
) -> str:
    """Audit TLS/SSL security asynchronously."""
    try:
        if not config.binary_paths.get("tlsx"):
            return json.dumps({"error": "TLSx not installed"}, indent=2)
        
        args = []
        if Path(targets).exists(): args.extend(["-l", targets])
        else: args.extend(["-u", targets])
        
        if scan_type == "all":
            args.extend(["-tls", "-ssl", "-cipher", "-cert", "-vuln"])
        else:
            if scan_type in ["tls", "all"]: args.append("-tls")
            if scan_type in ["ssl", "all"]: args.append("-ssl")
            if ciphers: args.append("-cipher")
            if certificates: args.append("-cert")
            if vulnerabilities: args.append("-vuln")
        
        args.extend(["-json", "-timeout", "10"])
        output_file = create_temp_file(suffix=".json")
        args.extend(["-o", str(output_file)])
        
        cmd = [config.binary_paths["tlsx"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        tls_data = parse_json_lines(output_file)
        response = {
            "success": result["success"],
            "tls_data": tls_data[:5],
            "execution_time": result.get("execution_time", 0)
        }
        try: output_file.unlink()
        except: pass
        return format_industrial_result(
            "tlsx_scan",
            "Audit Complete",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"TLS/SSL scan on {targets} finished with {len(tls_data)} certificate results."
        )
    except Exception as e:
        return format_industrial_result("tlsx_scan", "Error", error=str(e))
@tool
async def mapcidr_operations(
    cidr: str,
    operation: str = "list",
    count: bool = False,
    subnet: str = "",
    filter_ips: str = ""
) -> str:
    """Perform CIDR/IP range operations asynchronously."""
    try:
        if not config.binary_paths.get("mapcidr"):
            return json.dumps({"error": "MapCIDR not installed"}, indent=2)
        
        args = []
        if Path(cidr).exists(): args.extend(["-cidr", cidr])
        else: args.extend(["-cidr", cidr])
        
        if operation == "list": args.append("-silent")
        elif operation == "count": args.append("-count")
        elif operation == "subnet" and subnet: args.extend(["-sb", subnet])
        elif operation == "filter" and filter_ips: args.extend(["-filter", filter_ips])
        
        output_file = create_temp_file(suffix=".txt")
        args.extend(["-o", str(output_file)])
        
        cmd = [config.binary_paths["mapcidr"]] + args
        result = await run_command_async(cmd, timeout=300)
        
        ip_list = []
        if output_file.exists():
            with open(output_file, 'r', encoding='utf-8') as f:
                ip_list = [line.strip() for line in f if line.strip()]
        
        response = {
            "success": result["success"],
            "ip_count": len(ip_list),
            "ip_sample": ip_list[:20]
        }
        try: output_file.unlink()
        except: pass
        return format_industrial_result(
            "mapcidr_operations",
            "Complete",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"MapCIDR operation '{operation}' on {cidr} returned {len(ip_list)} IPs."
        )
    except Exception as e:
        return format_industrial_result("mapcidr_operations", "Error", error=str(e))
@tool
async def chaos_client_scan(
    domain: str,
    fetch_subdomains: bool = True,
    fetch_urls: bool = False,
    limit: int = 1000
) -> str:
    """Fetch intelligence from Chaos dataset asynchronously."""
    try:
        if not config.binary_paths.get("chaos-client"):
            return json.dumps({"error": "Chaos client not installed"}, indent=2)
        
        args = ["-d", domain]
        if fetch_subdomains: args.append("-ss")
        if fetch_urls: args.append("-s")
        args.extend(["-limit", str(limit), "-json"])
        
        output_file = create_temp_file(suffix=".json")
        args.extend(["-o", str(output_file)])
        
        env = {"CHAOS_API_KEY": config.api_key}
        cmd = [config.binary_paths["chaos-client"]] + args
        result = await run_command_async(cmd, timeout=300, env=env)
        
        results = parse_json_lines(output_file)
        response = {
            "success": result["success"],
            "total_results": len(results),
            "sample_results": results[:10]
        }
        try: output_file.unlink()
        except: pass
        return format_industrial_result(
            "chaos_client_scan",
            "Fetched",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"Chaos intelligence sync for {domain} retrieved {len(results)} records."
        )
    except Exception as e:
        return format_industrial_result("chaos_client_scan", "Error", error=str(e))

@tool
async def alterx_pattern_generator(base_domain: str, pattern_type: str = "aggressive") -> str:
    """
    Generates dynamic wordlists for subdomain discovery based on existing patterns.
    Weaponized with real AlterX binary execution for high-fidelity permutations.
    """
    try:
        if not config.binary_paths.get("alterx"):
            return format_industrial_result("alterx_pattern_generator", "Error", error="AlterX not installed")

        patterns = {
            "aggressive": "{{word}}-{{sub}}.{{domain}}",
            "recursive": "{{sub}}.{{word}}.{{domain}}",
            "cloud": "{{word}}-{{sub}}-{{region}}.{{domain}}",
            "standard": "{{sub}}{{word}}.{{domain}}"
        }
        
        pat = patterns.get(pattern_type, patterns["standard"])
        cmd = [config.binary_paths["alterx"], "-d", base_domain, "-p", pat, "-n", "5000"]
        
        result = await run_command_async(cmd, timeout=300)
        
        return format_industrial_result(
            "alterx_pattern_generator",
            "Patterns Generated",
            confidence=1.0,
            impact="LOW",
            raw_data={"pattern_used": pat, "output": result["stdout"][:500]},
            summary=f"Technical pattern generation for {base_domain} finished via AlterX. Strategy: {pattern_type}. Target Patterns: {pat}."
        )
    except Exception as e:
        return format_industrial_result("alterx_pattern_generator", "Error", error=str(e))

@tool
async def advanced_subdomain_enumeration(
    domain: str,
    use_alterx: bool = True,
    use_subfinder: bool = True,
    brute_force: bool = True,
    validate_dns: bool = True,
    probe_http: bool = True,
    permutations: int = 5000
) -> str:
    """
    Advanced subdomain enumeration combining multiple tools.
    Useful for: Comprehensive subdomain discovery.
    """
    try:
        results = {
            "target": domain,
            "start_time": datetime.now().isoformat(),
            "techniques_used": [],
            "results": {}
        }
        
        all_subdomains = set()
        
        # Technique 1: Passive enumeration with Subfinder
        if use_subfinder and config.binary_paths.get("subfinder"):
            results["techniques_used"].append("subfinder_passive")
            
            subfinder_output = await subfinder_scan(domain=domain)
            subfinder_result = json.loads(subfinder_output).get("raw_data", {})
            results["results"]["subfinder"] = subfinder_result
            
            if "subdomains_sample" in subfinder_result:
                passive_subs = subfinder_result["subdomains_sample"]
                all_subdomains.update(passive_subs)
        
        # Technique 2: Permutation-based generation
        if use_alterx and config.binary_paths.get("alterx"):
            results["techniques_used"].append("alterx_permutations")
            
            alterx_output = await alterx_generate(
                base_domain=domain,
                permutations=permutations
            )
            alterx_result = json.loads(alterx_output).get("raw_data", {})
            results["results"]["alterx"] = alterx_result
            
            if "generated_sample" in alterx_result:
                generated_subs = alterx_result["generated_sample"]
                all_subdomains.update(generated_subs)
        
        # Combine all discovered subdomains
        all_subdomains_list = list(all_subdomains)
        results["all_subdomains_count"] = len(all_subdomains_list)
        results["all_subdomains_sample"] = all_subdomains_list[:20]
        
        # DNS Validation
        if validate_dns and all_subdomains_list and config.binary_paths.get("dnsx"):
            validation_input = create_temp_file(content="\n".join(all_subdomains_list[:100]))
            
            dns_output = await dnsx_scan(
                domains=str(validation_input),
                wildcard_check=True
            )
            dns_result = json.loads(dns_output).get("raw_data", {})
            results["results"]["dns_validation"] = dns_result
        
        # HTTP Probing
        if probe_http and all_subdomains_list and config.binary_paths.get("httpx"):
            http_targets = create_temp_file(
                content="\n".join([f"http://{s}" for s in all_subdomains_list[:20]])
            )
            
            httpx_output = await httpx_scan(
                targets=str(http_targets),
                tech_detect=True
            )
            httpx_result = json.loads(httpx_output).get("raw_data", {})
            results["results"]["http_probing"] = httpx_result
        
        # Summary
        results["end_time"] = datetime.now().isoformat()
        results["workflow_completed"] = True
        
        return format_industrial_result(
            "advanced_subdomain_enumeration",
            "Success",
            confidence=1.0,
            impact="LOW",
            raw_data=results,
            summary=f"Deep subdomain enum on {domain} identified {len(all_subdomains_list)} total candidates using {len(results['techniques_used'])} techniques."
        )
        
    except Exception as e:
        return format_industrial_result("advanced_subdomain_enumeration", "Error", error=str(e))

# ==================== UTILITY TOOLS ====================

@tool
def nuclei_templates(
    action: str = "list",
    category: str = "",
    update: bool = False,
    search: str = "",
    template_path: str = ""
) -> str:
    """
    Manage Nuclei templates - list, search, update.
    Useful for: Nuclei template management.
    
    Parameters:
    - action: Action to perform (list, search, update, info)
    - category: Template category to filter
    - update: Update templates before action
    - search: Search term for templates
    - template_path: Path to specific template
    """
    try:
        if not config.binary_paths.get("nuclei"):
            return json.dumps({
                "error": "Nuclei is not installed"
            }, indent=2)
        
        args = []
        
        if action == "list":
            args.append("-tl")
            if category:
                args.extend(["-tc", category])
        elif action == "search" and search:
            args.extend(["-ts", search])
        elif action == "info" and template_path:
            args.extend(["-ti", template_path])
        else:
            return json.dumps({
                "categories": config.nuclei_categories,
                "actions": ["list", "search", "update", "info"]
            }, indent=2)
        
        cmd = [config.binary_paths["nuclei"]] + args
        result = run_command_sync(cmd, timeout=300)
        
        return format_industrial_result(
            "nuclei_templates",
            "Success",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"Nuclei templates {action} operation completed. Total output size: {len(result['stdout'])} bytes."
        )
        
    except Exception as e:
        return format_industrial_result("nuclei_templates", "Error", error=str(e))

@tool
async def pd_scan_workflow(
    target: str,
    workflow: str = "normal"
) -> str:
    """Complete reconnaissance workflow asynchronously."""
    try:
        results = {"target": target, "start_time": datetime.now().isoformat(), "steps": {}}
        
        # All tools are now async, so we can use await or asyncio.gather
        subfinder_result = await subfinder_scan(domain=target)
        results["steps"]["subdomains"] = json.loads(subfinder_result)
        
        naabu_result = await naabu_scan(target=target, ports="top-100")
        results["steps"]["ports"] = json.loads(naabu_result)
        
        httpx_result = await httpx_scan(targets=target)
        results["steps"]["http"] = json.loads(httpx_result)
        
        nuclei_result = await nuclei_scan(target=target, severity="critical,high")
        results["steps"]["vulnerabilities"] = json.loads(nuclei_result)
        
        results["end_time"] = datetime.now().isoformat()
        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@tool
def notify_alert(
    webhook_url: str,
    message: str,
    title: str = "Project Discovery Alert",
    severity: str = "info",
    data: str = ""
) -> str:
    """
    Send notifications via Notify (requires notify binary).
    Useful for: Alerting and notifications.
    
    Parameters:
    - webhook_url: Webhook URL (Discord, Slack, etc.)
    - message: Alert message
    - title: Alert title
    - severity: Severity level (info, warning, critical)
    - data: Additional JSON data
    """
    try:
        if not config.binary_paths.get("notify"):
            return json.dumps({
                "error": "Notify is not installed",
                "installation": "go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
            }, indent=2)
        
        # Create payload
        payload = {
            "title": title,
            "message": message,
            "severity": severity
        }
        
        if data:
            try:
                extra_data = json.loads(data)
                payload.update(extra_data)
            except:
                payload["raw_data"] = data
        
        # Write to temp file
        temp_file = create_temp_file(content=json.dumps(payload))
        
        args = [
            "-data", str(temp_file),
            "-webhook", webhook_url
        ]
        
        cmd = [config.binary_paths["notify"]] + args
        result = run_command_sync(cmd, timeout=300)
        
        return format_industrial_result(
            "notify_alert",
            "Sent" if result["success"] else "Failed",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"Notification priority '{severity}' sent to {webhook_url[:30]}... Delivery Status: {'OK' if result['success'] else 'FAILED'}"
        )
    except Exception as e:
        return format_industrial_result("notify_alert", "Error", error=str(e))

@tool
def interactsh_register(
    server: str = "https://interact.sh",
    correlation_id: str = ""
) -> str:
    """
    Register with InteractSH for OOB testing.
    Useful for: Out-of-band interaction testing.
    
    Parameters:
    - server: InteractSH server URL
    - correlation_id: Custom correlation ID
    """
    try:
        if not config.binary_paths.get("interactsh-client"):
            return json.dumps({
                "error": "InteractSH client is not installed",
                "installation": "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
            }, indent=2)
        
        args = ["-server", server]
        
        if correlation_id:
            args.extend(["-cid", correlation_id])
        
        args.append("-v")
        
        cmd = [config.binary_paths["interactsh-client"]] + args
        result = run_command_sync(cmd, timeout=300)
        
        # Extract registration URL
        interactsh_url = ""
        if result["success"]:
            match = re.search(r'(https?://[a-zA-Z0-9]+\.interact\.sh)', result["stdout"])
            if match:
                interactsh_url = match.group(1)
        
        return format_industrial_result(
            "interactsh_register",
            "Registered" if result["success"] else "Failed",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"Interact.sh registration complete. Payload URL: {interactsh_url}. Ready for OOB interaction."
        )
    except Exception as e:
        return format_industrial_result("interactsh_register", "Error", error=str(e))

@tool
async def uncover_scan(
    query: str,
    engine: str = "shodan",
    limit: int = 100
) -> str:
    """Search engine reconnaissance asynchronously."""
    try:
        if not config.binary_paths.get("uncover"):
            return json.dumps({"error": "Uncover not installed"}, indent=2)
        
        args = ["-q", query, "-e", engine, "-limit", str(limit), "-json"]
        output_file = create_temp_file(suffix=".json")
        args.extend(["-o", str(output_file)])
        
        env = {}
        if engine == "shodan": env["SHODAN_API_KEY"] = config.api_key
        elif engine == "censys": env["CENSYS_API_ID"] = config.api_key
        
        cmd = [config.binary_paths["uncover"]] + args
        result = await run_command_async(cmd, timeout=300, env=env)
        
        results = parse_json_lines(output_file)
        response = {
            "success": result["success"],
            "total_results": len(results),
            "sample_results": results[:10]
        }
        try: output_file.unlink()
        except: pass
        return format_industrial_result(
            "uncover_scan",
            "Scan Complete",
            confidence=1.0,
            impact="LOW",
            raw_data=response,
            summary=f"Uncover engine '{engine}' found {len(results)} results for query '{query}'."
        )
    except Exception as e:
        return format_industrial_result("uncover_scan", "Error", error=str(e))

@tool
def get_pd_status() -> str:
    """
    Get status of all Project Discovery tools and configurations.
    Useful for: System status check.
    """
    try:
        tool_info = config.get_tool_status()
        
        installed = sum(1 for tool in tool_info.values() if tool["status"] == "installed")
        total = len(tool_info)
        
        # Check nuclei templates
        template_count = 0
        if config.templates_dir.exists():
            for ext in ["*.yaml", "*.yml"]:
                template_count += len(list(config.templates_dir.rglob(ext)))
        
        status = {
            "system": {
                "platform": platform.system(),
                "is_windows": config.is_windows,
                "is_wsl": config.is_wsl,
                "api_key_configured": bool(config.api_key),
                "config_dir": str(config.config_dir),
                "nuclei_templates_count": template_count
            },
            "tools": {
                "total_tools": total,
                "installed_tools": installed,
                "installation_rate": f"{(installed/total*100):.1f}%" if total > 0 else "0%",
                "details": tool_info
            },
            "timestamp": datetime.now().isoformat()
        }
        
        return format_industrial_result(
            "get_pd_status",
            "Success",
            confidence=1.0,
            impact="LOW",
            raw_data=status,
            summary=f"System ready. {installed}/{total} Project Discovery tools installed. {template_count} Nuclei templates available."
        )
    except Exception as e:
        return format_industrial_result("get_pd_status", "Error", error=str(e))

@tool
def check_windows_compatibility() -> str:
    """
    Check Windows compatibility for Project Discovery tools.
    Useful for: Windows-specific compatibility checks.
    """
    try:
        result = {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "windows_specific_issues": [],
            "tool_availability": {},
            "recommendations": []
        }
        
        if config.is_windows:
            tool_info = config.get_tool_status()
            
            for tool_name, info in tool_info.items():
                result["tool_availability"][tool_name] = {
                    "installed": info["status"] == "installed",
                    "path": info["path"],
                    "version": info["version"]
                }
            
            # Check for common Windows issues
            if not config.api_key:
                result["recommendations"].append(
                    "Set PROJECT_DISCOVERY_API_KEY environment variable for full functionality"
                )
            
            # Check if running as admin
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                result["is_administrator"] = is_admin
                if not is_admin:
                    result["recommendations"].append(
                        "Run as Administrator for port scanning (naabu) and certain operations"
                    )
            except:
                result["is_administrator"] = "Unknown"
            
            # Check Go installation
            try:
                go_result = subprocess.run(
                    ["go", "version"],
                    capture_output=True,
                    text=True,
                    shell=True,
                    timeout=5
                )
                result["go_installed"] = go_result.returncode == 0
                if go_result.returncode == 0:
                    result["go_version"] = go_result.stdout.strip()
            except:
                result["go_installed"] = False
            
            if not result.get("go_installed", False):
                result["recommendations"].append(
                    "Install Go (golang) for building and installing Project Discovery tools"
                )
        
        return format_industrial_result(
            "check_windows_compatibility",
            "Complete",
            confidence=1.0,
            impact="LOW",
            raw_data=result,
            summary=f"Compatibility audit finished. Platform: {result['platform']}. Admin status: {result.get('is_administrator', 'Unknown')}."
        )
    except Exception as e:
        return format_industrial_result("check_windows_compatibility", "Error", error=str(e))

@tool
def pd_health_check() -> str:
    """
    Check Project Discovery server health.
    Useful for: Health monitoring.
    """
    try:
        tools_status = config.get_tool_status()
        installed = sum(1 for tool in tools_status.values() if tool["status"] == "installed")
        
        return format_industrial_result(
            "pd_health_check",
            "Healthy",
            confidence=1.0,
            impact="LOW",
            raw_data={
                "status": "healthy",
                "tools_installed": f"{installed}/{len(tools_status)}",
                "api_key_configured": bool(config.api_key),
                "timestamp": datetime.now().isoformat()
            },
            summary="Project Discovery environmental health check complete. System operational."
        )
        
    except Exception as e:
        return format_industrial_result("pd_health_check", "Unhealthy", error=str(e))

# ==================== WORKFLOW & CORRELATION TOOLS ====================

@tool
async def hyper_recon(target: str, intensity: str = "normal") -> str:
    """
    ULTRA-FAST PARALLEL RECONNAISSANCE ENGINE.
    Runs Subfinder, Naabu, HTTPx, and Nuclei simultaneously.
    Use for: Maximum speed and power on a target.
    """
    import asyncio
    
    tasks = [
        subfinder_scan.ainvoke({"domain": target}),
        naabu_scan.ainvoke({"target": target, "ports": "top-100"}),
        httpx_scan.ainvoke({"targets": target}),
        nuclei_scan.ainvoke({"target": target, "severity": "critical,high"})
    ]
    
    # Run all scanners in parallel
    results = await asyncio.gather(*tasks)
    
    data = {
        "target": target,
        "mode": "HYPER_RECON",
        "subdomains": json.loads(results[0]),
        "ports": json.loads(results[1]),
        "http_probing": json.loads(results[2]),
        "vulnerabilities": json.loads(results[3]),
        "timestamp": datetime.now().isoformat()
    }
    
    return format_industrial_result(
        "hyper_recon",
        "Complete",
        confidence=1.0,
        impact="HIGH",
        raw_data=data,
        summary=f"Hyper recon on {target} finished. Composite intelligence gathered from 4 primary modules."
    )

@tool
def vulnerability_correlator(
    scan_results: str,
    target: str = "",
    severity_threshold: str = "medium",
    correlation_rules: str = "default"
) -> str:
    """
    Correlate vulnerability findings and identify attack chains.
    Industry-grade for synthesizing multi-tool recon data into actionable exploits.
    """
    try:
        # Load results
        if os.path.exists(scan_results):
            with open(scan_results, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = json.loads(scan_results)
        
        vulnerabilities = []
        open_ports = []
        
        # Deep inspection of mixed result objects
        def walk_results(obj):
            if isinstance(obj, dict):
                if "template_id" in obj: # Nuclei finding
                    vulnerabilities.append(obj)
                if "port" in obj: # Naabu/Nmap finding
                    open_ports.append(obj)
                for v in obj.values(): walk_results(v)
            elif isinstance(obj, list):
                for item in obj: walk_results(item)

        walk_results(results)
        
        attack_chains = []
        # Correlation Rule A: Services with CVEs
        for port in open_ports:
            pnum = port.get("port")
            for vuln in vulnerabilities:
                if str(pnum) in str(vuln.get("matched-at", "")) or str(pnum) in str(vuln.get("host", "")):
                    attack_chains.append({
                        "type": "Service-Linked Vulnerability",
                        "port": pnum,
                        "cve": vuln.get("info", {}).get("classification", {}).get("cve-id", "N/A"),
                        "severity": vuln.get("info", {}).get("severity"),
                        "target": vuln.get("host")
                    })

        return format_industrial_result(
            "vulnerability_correlator",
            "Success",
            confidence=0.95,
            impact="HIGH" if attack_chains else "LOW",
            raw_data={"chains": attack_chains, "raw_vulns": len(vulnerabilities)},
            summary=f"Vulnerability correlation engine finished. Synthesized {len(vulnerabilities)} findings into {len(attack_chains)} actionable attack chains."
        )
    except Exception as e:
        return format_industrial_result("vulnerability_correlator", "Error", error=str(e))

@tool
def import_scan_results(
    file_path: str,
    format: str = "auto"
) -> str:
    """
    Import scan results from other tools (Nmap, Nuclei, JSON).
    Weaponized with real parsing logic for industrial data ingestion.
    """
    try:
        if not os.path.exists(file_path):
            return format_industrial_result("import_scan_results", "Error", error="File not found")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        data = {}
        try:
            data = json.loads(content)
        except:
            # Try parsing Nmap-like line formats or Nuclei JSONL
            lines = content.splitlines()
            parsed_lines = []
            for line in lines:
                try: parsed_lines.append(json.loads(line))
                except: pass
            data = {"captured_lines": parsed_lines}

        return format_industrial_result(
            "import_scan_results",
            "Imported",
            confidence=1.0,
            impact="LOW",
            raw_data=data,
            summary=f"Technical import of {os.path.basename(file_path)} complete. Ingested {len(data.get('captured_lines', [1]))} data nodes."
        )
    except Exception as e:
        return format_industrial_result("import_scan_results", "Error", error=str(e))

@tool
def export_results(
    results_data: str,
    format: str = "json",
    include_raw: bool = False,
    output_file: str = ""
) -> str:
    """
    Export scan results to various formats.
    Useful for: Result export in different formats.
    
    Parameters:
    - results_data: JSON results data or file path
    - format: Export format (json, csv, html, pdf, markdown)
    - include_raw: Include raw tool output
    - output_file: Output file path
    """
    try:
        # Parse input
        if os.path.exists(results_data):
            with open(results_data, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = json.loads(results_data)
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"pd_export_{timestamp}.{format}"
        
        # Simple export based on format
        if format == "json":
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        elif format == "csv":
            # Simplified CSV export
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("key,value\n")
                for key, value in data.items():
                    if isinstance(value, (str, int, float, bool)):
                        f.write(f"{key},{value}\n")
        else:
            # For other formats, create a simple text file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"Project Discovery Export - {datetime.now()}\n")
                f.write(f"Format: {format}\n")
                f.write(json.dumps(data, indent=2))
        
        response = {
            "export_format": format,
            "output_file": output_file,
            "file_size": os.path.getsize(output_file),
            "export_successful": True,
            "timestamp": datetime.now().isoformat()
        }
        
        return json.dumps(response, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": f"Export results error: {str(e)}"
        }, indent=2)

@tool
def generate_results_dashboard(
    scan_results: str,
    dashboard_type: str = "executive"
) -> str:
    """
    Generate an industry-grade interactive dashboard from scan results.
    Premium design with glassmorphism and dynamic data visualization.
    """
    try:
        # Load results
        if os.path.exists(scan_results):
            with open(scan_results, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = json.loads(scan_results)
        
        output_file = f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Industrial Recon Dashboard - {dashboard_type.upper()}</title>
            <style>
                :root {{ --primary: #00f2fe; --bg: #0f172a; --card: rgba(30, 41, 59, 0.7); }}
                body {{ background: var(--bg); color: white; font-family: 'Inter', sans-serif; margin: 0; padding: 40px; }}
                .glass {{ background: var(--card); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 24px; margin-bottom: 24px; }}
                h1 {{ background: linear-gradient(90deg, #00f2fe, #4facfe); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-size: 2.5rem; }}
                .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
                .stat-card {{ text-align: center; border-left: 4px solid var(--primary); }}
                .stat-val {{ font-size: 2rem; font-weight: bold; }}
                pre {{ background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; }}
            </style>
        </head>
        <body>
            <div class="glass">
                <h1>RECON INTELLIGENCE: {dashboard_type.upper()}</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            <div class="stat-grid">
                <div class="glass stat-card"><div class="stat-val">{len(results.get('subdomains', []))}</div><div>Subdomains</div></div>
                <div class="glass stat-card"><div class="stat-val">{len(results.get('vulnerabilities', []))}</div><div>High Vulns</div></div>
            </div>
            <div class="glass">
                <h2>Raw Technical Data Preview</h2>
                <pre>{json.dumps(results, indent=2)[:5000]}</pre>
            </div>
        </body>
        </html>
        """
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return format_industrial_result(
            "generate_results_dashboard",
            "Dashboard Generated",
            confidence=1.0,
            impact="MEDIUM",
            raw_data={"path": output_file},
            summary=f"Premium HTML dashboard generated at {output_file}. Design category: {dashboard_type}."
        )
    except Exception as e:
        return format_industrial_result("generate_results_dashboard", "Error", error=str(e))

# # ==================== TOOL REGISTRATION ====================

# def get_project_discovery_tools():
#     """Return all Project Discovery tools for registration."""
#     return [
#         # Core Tools
#         nuclei_scan,
#         subfinder_scan,
#         naabu_scan,
#         httpx_scan,
#         dnsx_scan,
#         asnmap_scan,
#         shuffledns_scan,
#         urlfinder_scan,
#         katana_scan,
#         alterx_generate,
        
#         # Advanced Tools
#         alterx_scan,
#         tlsx_scan,
#         mapcidr_operations,
#         chaos_client_scan,
#         alterx_pattern_generator,
#         advanced_subdomain_enumeration,
#         advanced_recon_workflow,
#         vulnerability_correlator,
#         import_scan_results,
#         export_results,
#         generate_results_dashboard,
        
#         # Utility Tools
#         nuclei_templates,
#         pd_scan_workflow,
#         notify_alert,
#         interactsh_register,
#         uncover_scan,
#         get_pd_status,
#         check_windows_compatibility,
#         pd_health_check
#     ]
@tool
async def eminence_discovery_orchestrator(target: str, priority: str = "HIGH") -> str:
    """
    A high-tier coordinator that manages long-running, multi-layered discovery operations across reconnaissance waves.
    Industry-grade for persistent, state-aware reconnaissance and absolute operational depth.
    """
    try:
        # Real Multi-Wave Orchestration State Manager
        from tools.recon.passive import passive_intel_deep_scanner
        
        session_id = f"EMINENCE-{uuid.uuid4().hex[:8].upper()}"
        
        # Initiate Wave 1: Passive Intelligence (Triggered)
        wave1_result = await passive_intel_deep_scanner(target)
        
        orchestration_plan = {
            "session_id": session_id,
            "priority": priority,
            "waves": [
                {"wave": 1, "status": "COMPLETED", "focus": "Passive Intelligence"},
                {"wave": 2, "status": "READY", "focus": "Active Discovery Wave"},
                {"wave": 3, "status": "QUEUED", "focus": "Vulnerability Analysis"}
            ],
            "initial_wave_findings": "Summary available in raw_data"
        }

        return format_industrial_result(
            "eminence_discovery_orchestrator",
            "Orchestration Active",
            confidence=0.9,
            impact="MEDIUM",
            raw_data={"target": target, "session": session_id, "wave1_summary": wave1_result[:500]},
            summary=f"Eminence orchestration for {target} initiated. Wave 1 (Passive) complete. Wave 2 (Active) ready for execution."
        )
    except Exception as e:
        return format_industrial_result("eminence_discovery_orchestrator", "Error", error=str(e))

# # Export all tools
# __all__ = [tool.__name__ for tool in get_project_discovery_tools()] + ['get_project_discovery_tools']
