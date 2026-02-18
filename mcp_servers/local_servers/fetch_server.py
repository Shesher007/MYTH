#!/usr/bin/env python3
import os
import aiohttp
import asyncio
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field, HttpUrl
from fastmcp import FastMCP
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import MCPUtils, AdaptiveRateLimiter, GhostProtocol, NexusState, ironclad_guard, tool_exception_handler, logger

# --- Models ---
class ReconFetchModel(BaseModel):
    url: str = Field(..., description="Target URL")
    headers: Optional[Dict] = Field(None)
    proxy: Optional[str] = Field(None)

# --- Server ---
mcp = FastMCP("Fetch Tools")

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@MCPUtils.cache_result(ttl_seconds=3600)
async def recon_fetch(url: str, headers: Dict = None, proxy: str = None, ghost_mode: bool = True) -> Dict:
    """God-tier recon fetch with Ghost Protocol and Predictive Intelligence."""
    args = ReconFetchModel(url=url, headers=headers, proxy=proxy)
    timeout = aiohttp.ClientTimeout(total=15)
    
    # Nexus Ghost Protocol logic
    final_headers = args.headers or {}
    if ghost_mode:
        final_headers.update(GhostProtocol.get_stealth_config().get("userAgent", GhostProtocol.get_random_ua()))
        if isinstance(final_headers, str): final_headers = {"User-Agent": final_headers} # Handle potential dict conversion edge
    
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(args.url, headers=final_headers, proxy=args.proxy, allow_redirects=True) as resp:
            text = await resp.text()
            server_header = resp.headers.get('Server', 'Unknown')
            
            # Predictive Intel: Broadcast server discovery
            await NexusState.post_intel(f"discovery:{url}", {"server": server_header, "status": resp.status})
            return {
                "status": resp.status,
                "server": resp.headers.get('Server', 'Unknown'),
                "security_headers": {k: v for k, v in resp.headers.items() if "security" in k.lower()},
                "body_snippet": text[:1000]
            }

@mcp.tool()
@tool_exception_handler
async def bulk_recon_scan(urls: List[str], max_concurrency: int = 10) -> List[Dict]:
    """Massive parallel reconnaissance with concurrency control."""
    sem = asyncio.Semaphore(min(max_concurrency, 20)) # Cap at 20
    async def _fetch(url):
        async with sem:
            return await recon_fetch(url)
    return await asyncio.gather(*[_fetch(u) for u in urls])

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8008))
    mcp.run(transport="sse", port=port, show_banner=False)
