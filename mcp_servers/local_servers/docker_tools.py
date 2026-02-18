#!/usr/bin/env python3
import os
import docker
import asyncio
import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from fastmcp import FastMCP
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import MCPUtils, QuantumEnricher, PlatformGuard, AccelerationGuard, DependencyGuard, ironclad_guard, tool_exception_handler, logger

# --- Models ---
class ContainerRunModel(BaseModel):
    image: str = Field(..., description="Docker image name")
    command: Optional[str] = Field(None, description="Command to run")
    mem_limit: str = Field("512m", description="Memory limit (e.g., 512m)")
    cpu_period: int = Field(100000)
    cpu_quota: int = Field(50000, description="CPU quota (50% of one core)")

    @field_validator('image')
    @classmethod
    def sanitize_image(cls, v):
        if not re.match(r'^[a-zA-Z0-9_./:-]+$', v):
            raise ValueError(f"Invalid image name: {v}")
        return v

# --- Server ---
mcp = FastMCP("Docker Tools")
try:
    client = docker.from_env()
except Exception:
    client = None

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@DependencyGuard.require(["docker"])
async def security_run_container(image: str, command: str = None) -> Dict:
    """Run a container with mandatory resource limits and isolation."""
    if not client: return {"error": "Docker unavailable"}
    args = ContainerRunModel(image=image, command=command)
    
    def _run():
        container = client.containers.run(
            args.image,
            command=args.command,
            mem_limit=args.mem_limit,
            cpu_period=args.cpu_period,
            cpu_quota=args.cpu_quota,
            detach=True,
            remove=True # Industry grade - clean up immediately
        )
        return {"id": container.short_id, "status": container.status}
        
    return await asyncio.to_thread(_run)

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@DependencyGuard.require(["docker"])
async def live_container_forensics(container_id: str) -> Dict:
    """Deep runtime inspection: Process tree and open sockets (Cross-Platform)."""
    if not client: return {"error": "Docker unavailable"}
    container = client.containers.get(container_id)
    start = asyncio.get_event_loop().time()
    
    # Choose commands based on container OS (usually Linux, but guard anyway)
    if PlatformGuard.is_windows():
        # Windows containers use tasklist
        ps_cmd = "tasklist"
        net_cmd = "netstat -ano"
    else:
        ps_cmd = "ps aux --forest"
        net_cmd = "ss -tunap"
    
    try:
        ps = container.exec_run(ps_cmd).output.decode()
        net = container.exec_run(net_cmd).output.decode()
    except Exception as e:
        return {"error": f"Exec failed: {str(e)}", "note": "Is the container running a supported shell/OS?"}
    
    return {
        "container": container.name,
        "process_tree": ps,
        "active_sockets": net,
        "telemetry": QuantumEnricher.get_telemetry(start)
    }

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@DependencyGuard.require(["docker"])
async def docker_cleanup() -> Dict:
    """Prune unused Docker assets to maintain system health."""
    if not client: return {"error": "Docker unavailable"}
    def _prune():
        c = client.containers.prune()
        i = client.images.prune()
        return {"containers_deleted": len(c.get('ContainersDeleted', [])), "space_reclaimed": c.get('SpaceReclaimed', 0)}
    return await asyncio.to_thread(_prune)

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8006))
    mcp.run(transport="sse", port=port, show_banner=False)
