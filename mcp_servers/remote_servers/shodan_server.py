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

# Circuit Breaker for Shodan
shodan_cb = CircuitBreaker()

# --- Models ---
class ShodanHostModel(BaseModel):
    ip: str = Field(..., description="IP address to query")
    key: Optional[str] = Field(None, description="Shodan API Key (default: SHODAN_API_KEY env)")

class ShodanSearchModel(BaseModel):
    query: str = Field(..., description="Shodan search query")
    facets: Optional[str] = Field(None, description="Facets to include (e.g., 'port,os')")
    page: int = Field(1)
    key: Optional[str] = Field(None)

# --- Server ---
mcp = FastMCP("Shodan Server")

async def get_shodan_key(provided_key: Optional[str]) -> str:
    key = provided_key or config.get_api_key("shodan")
    if not key:
        raise ValueError("Shodan API Key not found. Provide it as a tool argument or ensure it is in secrets.yaml.")
    return key

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@shodan_cb
@MCPUtils.cache_result(ttl_seconds=3600)
async def shodan_host_info(ip: str, key: str = None) -> Dict:
    """Get host info with automatic CVE risk mapping."""
    start = asyncio.get_event_loop().time()
    args = ShodanHostModel(ip=ip, key=key)
    api_key = await get_shodan_key(args.key)
    
    url = f"https://api.shodan.io/shodan/host/{args.ip}?key={api_key}"
    async with aiohttp.ClientSession() as session:
        for attempt in range(3):
            async with session.get(url) as resp:
                if await AdaptiveRateLimiter.handle_resp(resp, attempt): continue
                if resp.status != 200:
                    if resp.status in [401, 403, 429]:
                        config.invalidate_key("shodan", api_key)
                    return {"error": f"API error {resp.status}"}
                
                data = await resp.json()
                
                # Predictive Intel: Broadcast critical findings
                if vulns:
                    await NexusState.post_intel(f"vulns:{args.ip}", vulns)
                if data.get("ports"):
                    await NexusState.post_intel(f"ports:{args.ip}", data["ports"])
                    
                return data

@mcp.tool()
@tool_exception_handler
@MCPUtils.cache_result(ttl_seconds=1800)
async def shodan_search(query: str, facets: str = None, page: int = 1, key: str = None) -> Dict:
    """Search Shodan for devices/services matching a query."""
    args = ShodanSearchModel(query=query, facets=facets, page=page, key=key)
    api_key = await get_shodan_key(args.key)
    
    url = "https://api.shodan.io/shodan/host/search"
    params = {
        "key": api_key,
        "query": args.query,
        "page": args.page
    }
    if args.facets: params["facets"] = args.facets
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params) as resp:
            if resp.status != 200:
                return {"error": f"Shodan Search returned {resp.status}", "details": await resp.text()}
            return await resp.json()

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8101))
    mcp.run(transport="sse", port=port, show_banner=False)
