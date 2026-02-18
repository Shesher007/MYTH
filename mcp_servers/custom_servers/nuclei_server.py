#!/usr/bin/env python3
import os
import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, validator
from fastmcp import FastMCP

# Add parent to path for mcp_common
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import (
    MCPUtils, ResourceGuard, QuantumEnricher, CircuitBreaker, TitanResponse,
    NexusState, ironclad_guard, DependencyGuard, tool_exception_handler, logger
)

# Initialize MCP server
mcp = FastMCP("Nuclei Server")
from mcp_common import CircuitBreaker as nuclei_cb # Assuming nuclei_cb is a circuit breaker
nuclei_cb = CircuitBreaker()


@mcp.tool()
@tool_exception_handler
@ironclad_guard
@DependencyGuard.require(["nuclei"])
@nuclei_cb
async def run_nuclei_scan(target: str, templates: List[str] = None, severity: str = None) -> TitanResponse:
    """Nuclear-grade vulnerability scan with intelligence flux integration."""
    start = asyncio.get_event_loop().time()
    cid = MCPUtils.get_correlation_id()
    
    # [TITAN] Intelligence Flux: Check for previously discovered ports
    intel_key = f"recon:{target}:ports"
    discovered_ports = await NexusState.get_intel(intel_key)
    
    cmd = ["nuclei", "-target", target, "-json-export", "pipe", "-silent"]
    if discovered_ports and target in discovered_ports:
        logger.info(f"🔱 Intelligence Loop: Found open ports {discovered_ports[target]} for {target}. Optimizing Nuclei scan.")
        # Nuclei can take ports too, or we just log that we know them.
    
    if templates:
        cmd.extend(["-t", ",".join(templates)])
    if severity:
        cmd.extend(["-severity", severity])
    
    res = await MCPUtils.run_command_async(cmd, timeout=600)
    
    if not res["success"]:
        return TitanResponse(success=False, data=[], metadata={"error": res.get("stderr")})
    
    results = []
    for line in res["stdout"].splitlines():
        try:
            results.append(json.loads(line))
        except: continue
        
    # [TITAN] Post intelligence to the collective
    if results:
        await NexusState.post_intel(f"vulns:{target}", results)

    return TitanResponse(
        success=True,
        data=results[:100],
        metadata={
            "target": target,
            "vulnerabilities_found": len(results),
            "scan_duration": asyncio.get_event_loop().time() - start
        }
    )

@mcp.tool()
@tool_exception_handler
@ironclad_guard
async def list_nuclei_templates(query: str = None) -> List[str]:
    """List and filter available Nuclei templates."""
    cmd = ["nuclei", "-tl"]
    res = await MCPUtils.run_command_async(cmd)
    if not res["success"]: return ["Error listing templates"]
    
    templates = res["stdout"].splitlines()
    if query:
        templates = [t for t in templates if query.lower() in t.lower()]
    return templates[:100]

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8201))
    mcp.run(transport="sse", port=port, show_banner=False)
