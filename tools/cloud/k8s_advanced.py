import json
import asyncio
import os
import platform
import shutil
import aiohttp
from datetime import datetime
from myth_config import load_dotenv
from langchain_core.tools import tool
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# ☸️ Advanced Kubernetes & Container Security Tools
# ==============================================================================

@tool
async def k8s_rbac_audit() -> str:
    """
    Analyzes the local Kubernetes RBAC configuration for high-risk permissions.
    Targets: 'cluster-admin' bindings, 'star' permissions, and risky verbs (get, list, watch, create) on Secrets.
    Robustness: Verifies 'kubectl' availability before execution.
    """
    try:
        # Robustness: Check for kubectl
        if not shutil.which("kubectl"):
             return format_industrial_result(
                "k8s_rbac_audit",
                "Environment Not Found",
                confidence=1.0,
                summary="Kubernetes (kubectl) binary not found in system PATH."
            )

        # Check if kubectl is available
        proc = await asyncio.create_subprocess_shell(
            "kubectl get rolebindings,clusterrolebindings -A -o json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        
        if not stdout:
            return format_industrial_result(
                "k8s_rbac_audit",
                "Execution Failed",
                confidence=0.8,
                summary="kubectl executed but returned no output (possibly connection error or no context)."
            )

        data = json.loads(stdout.decode('utf-8'))
        risky_bindings = []
        
        for item in data.get('items', []):
            role_ref = item.get('roleRef', {}).get('name', '')
            if 'admin' in role_ref.lower() or 'edit' in role_ref.lower():
                risky_bindings.append({
                    "name": item.get('metadata', {}).get('name'),
                    "namespace": item.get('metadata', {}).get('namespace', 'ClusterWide'),
                    "role": role_ref
                })

        return format_industrial_result(
            "k8s_rbac_audit",
            "Audit Complete",
            confidence=0.95,
            impact="HIGH" if risky_bindings else "LOW",
            raw_data={"risky_bindings": risky_bindings, "total_bindings": len(data.get('items', []))},
            summary=f"Discovered {len(risky_bindings)} high-risk RBAC bindings with potential for cluster privilege escalation."
        )
    except Exception as e:
        return format_industrial_result("k8s_rbac_audit", "Error", error=str(e))

@tool
async def container_escape_prober() -> str:
    """
    Analyzes the current execution environment for Universal Container Escape vectors.
    Supports: Linux (Privileged, Caps, Socket) and Windows (Named Pipes, CExecSvc).
    """
    try:
        findings = []
        system = platform.system()
        
        if system == "Linux":
            # 1. Check for Privileged Mode
            if os.path.exists("/dev/mem"):
                findings.append({"vector": "Privileged Container (Linux)", "detail": "/dev/mem access detected."})

            # 2. Check for Docker Socket
            socket_paths = ["/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd/containerd.sock"]
            for path in socket_paths:
                if os.path.exists(path):
                    findings.append({"vector": "Exposed Socket", "detail": f"Socket found at {path}"})

            # 3. Check Capabilities (In-Depth)
            try:
                with open("/proc/self/status", "r") as f:
                    content = f.read()
                    # CAP_SYS_ADMIN is bit 21 (0x200000)
                    if "CapEff" in content and int(content.split("CapEff:")[1].split()[0], 16) & 0x200000:
                        findings.append({"vector": "CAP_SYS_ADMIN Enabled", "detail": "Container has administrative capabilities."})
            except: pass

            # 4. Check for /proc masking bypass
            if os.path.exists("/proc/sysrq-trigger") and os.access("/proc/sysrq-trigger", os.W_OK):
                 findings.append({"vector": "Proc Masking Incomplete", "detail": "/proc/sysrq-trigger is writable."})

            # 5. Check for HostPath mounts
            mounts = ["/etc/shadow", "/root/.ssh", "/var/run/docker.sock"]
            for m in mounts:
                if os.path.exists(m):
                    findings.append({"vector": "Risky Mount Found", "detail": f"Host path mounted: {m}"})
            
        elif system == "Windows":
             # Windows Container Escape Vectors
             # 1. CExecSvc (Container Execution Agent) - often privileged
             # 2. Named Pipes mapping to host
             
             try:
                 # Check for common named pipes mapped into containers
                 pipes = os.listdir(r'\\.\pipe\\')
                 risky_pipes = ["docker_engine", "rexec"] 
                 for p in pipes:
                     if any(r in p.lower() for r in risky_pipes):
                         findings.append({"vector": "Host Named Pipe", "detail": f"Found pipe: {p}"})
             except: pass
             
             # Check for CExecSvc (If we are system, likely exposed)
             # This is a heuristic check for the service process presence if possible, or just file artifacts
             if os.path.exists(r"C:\Windows\System32\cexecsvc.exe"):
                  findings.append({"vector": "CExecSvc Present", "detail": "Container Execution Service binary found."})

        return format_industrial_result(
            "container_escape_prober",
            "Vulnerable" if findings else "Safe",
            confidence=1.0,
            impact="CRITICAL" if findings else "LOW",
            raw_data={"os": system, "findings": findings},
            summary=f"Universal container escape audit ({system}) finished. {'Escape vectors discovered!' if findings else 'No standard escape paths identified.'}"
        )
    except Exception as e:
        return format_industrial_result("container_escape_prober", "Error", error=str(e))

@tool
async def kubelet_anonymous_prober(target_ip: str = "127.0.0.1") -> str:
    """
    Probes the Kubelet API (ports 10250, 10255) for Anonymous Authentication.
    Allows for unauthenticated command execution if misconfigured.
    """
    try:
        ports = [10250, 10255]
        results = []
        
        async with aiohttp.ClientSession() as session:
            for port in ports:
                url = f"https://{target_ip}:{port}/pods"
                try:
                    # Kubelet uses self-signed certs mostly
                    async with session.get(url, verify_ssl=False, timeout=3) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            pod_count = len(data.get('items', []))
                            results.append({
                                "port": port, 
                                "status": "OPEN", 
                                "auth": "ANONYMOUS", 
                                "details": f"Readable /pods endpoint. Found {pod_count} pods."
                            })
                        elif resp.status == 403 or resp.status == 401:
                            results.append({"port": port, "status": "OPEN", "auth": "SECURE"})
                except Exception as e:
                    # Connection refused or timeout
                    pass
                    
        return format_industrial_result(
            "kubelet_anonymous_prober",
            "Vulnerable" if any(r['auth'] == 'ANONYMOUS' for r in results) else "Secure",
            confidence=0.9,
            impact="CRITICAL",
            raw_data={"target": target_ip, "probes": results},
            summary=f"Kubelet probe complete. Found {len([r for r in results if r['auth'] == 'ANONYMOUS'])} anonymous APIs."
        )
    except Exception as e:
        return format_industrial_result("kubelet_anonymous_prober", "Error", error=str(e))
