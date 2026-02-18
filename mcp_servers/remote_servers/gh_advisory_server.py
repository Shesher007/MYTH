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
from mcp_common import MCPUtils, AdaptiveRateLimiter, QuantumEnricher, CircuitBreaker, tool_exception_handler, logger

# Circuit Breaker for GH Advisory
gh_cb = CircuitBreaker()

# --- Models ---
class GHAdvisoryModel(BaseModel):
    ecosystem: str = Field(..., description="Ecosystem (npm, pip, maven, etc.)")
    package: str = Field(..., description="Package name")

# --- Server ---
mcp = FastMCP("GitHub Advisory Server")

@mcp.tool()
@tool_exception_handler
@gh_cb
@MCPUtils.cache_result(ttl_seconds=86400)
async def github_get_advisories(ecosystem: str, package: str) -> List[Dict]:
    """Get security advisories with telemetry."""
    start = asyncio.get_event_loop().time()
    url = f"https://api.github.com/advisories"
    params = {"ecosystem": ecosystem, "package": package}
    
    async with aiohttp.ClientSession() as session:
        for attempt in range(3):
            async with session.get(url, params=params) as resp:
                if await AdaptiveRateLimiter.handle_resp(resp, attempt): continue
                if resp.status != 200: return [{"error": f"API error {resp.status}"}]
                data = await resp.json()
                if isinstance(data, list): data.append({"telemetry": QuantumEnricher.get_telemetry(start)})
                return data

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8109))
    mcp.run(transport="sse", port=port, show_banner=False)
