#!/usr/bin/env python3
import os
import aiohttp
import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from fastmcp import FastMCP

# Add parent to path for mcp_common
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import MCPUtils, AdaptiveRateLimiter, QuantumEnricher, CircuitBreaker, NexusState, ironclad_guard, tool_exception_handler, logger
from myth_config import config, load_dotenv

load_dotenv()

# Circuit Breaker for VirusTotal
vt_cb = CircuitBreaker()

# --- Models ---
class VTModel(BaseModel):
    target: str = Field(..., description="Domain, IP, URL, or File Hash")
    key: Optional[str] = Field(None, description="VirusTotal API Key")

# --- Server ---
mcp = FastMCP("VirusTotal Server")

async def get_vt_key(provided_key: Optional[str]) -> str:
    key = provided_key or config.get_api_key("virustotal")
    if not key:
        raise ValueError("VirusTotal API Key not found. Ensure it is in secrets.yaml.")
    return key

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@vt_cb
@MCPUtils.cache_result(ttl_seconds=3600)
async def virustotal_domain_report(domain: str, key: str = None) -> Dict:
    """Get domain report with smart rate handling."""
    start = asyncio.get_event_loop().time()
    api_key = await get_vt_key(key)
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    
    async with aiohttp.ClientSession(headers=headers) as session:
        for attempt in range(3):
            async with session.get(url) as resp:
                if await AdaptiveRateLimiter.handle_resp(resp, attempt): continue
                if resp.status != 200:
                    if resp.status in [401, 403, 429]:
                        config.invalidate_key("virustotal", api_key)
                    return {"error": f"API error {resp.status}"}
                
                data = await resp.json()
                data["telemetry"] = QuantumEnricher.get_telemetry(start)
                
                # Predictive Intel: Broadcast potentially malicious artifacts
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if stats.get("malicious", 0) > 0:
                    await NexusState.post_intel(f"malicious:{domain}", stats)
                
                return data

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@vt_cb
@MCPUtils.cache_result(ttl_seconds=3600)
async def virustotal_ip_report(ip: str, key: str = None) -> Dict:
    """Get a reputation report for an IP address."""
    api_key = await get_vt_key(key)
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                return {"error": f"VT API returned {resp.status}"}
            return await resp.json()

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8104))
    mcp.run(transport="sse", port=port, show_banner=False)
