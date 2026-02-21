#!/usr/bin/env python3
import asyncio
import os
import sys
from pathlib import Path
from typing import Dict, Optional

import aiohttp
from fastmcp import FastMCP
from pydantic import BaseModel, Field

# Add parent to path for mcp_common
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import (
    AdaptiveRateLimiter,
    CircuitBreaker,
    MCPUtils,
    QuantumEnricher,
    tool_exception_handler,
)

from myth_config import config, load_dotenv

load_dotenv()

# Circuit Breaker for SecurityTrails
st_cb = CircuitBreaker()


# --- Models ---
class SecurityTrailsModel(BaseModel):
    domain: str = Field(..., description="Domain to query")
    key: Optional[str] = Field(None, description="SecurityTrails API Key")


# --- Server ---
mcp = FastMCP("SecurityTrails Server")


async def get_st_key(provided_key: Optional[str]) -> str:
    key = provided_key or config.get_api_key("securitytrails")
    if not key:
        raise ValueError(
            "SecurityTrails API Key not found. Ensure it is in secrets.yaml."
        )
    return key


@mcp.tool()
@tool_exception_handler
@st_cb
@MCPUtils.cache_result(ttl_seconds=7200)
async def securitytrails_subdomains(domain: str, key: str = None) -> Dict:
    """Enumerate subdomains with smart rate limiting."""
    start = asyncio.get_event_loop().time()
    api_key = await get_st_key(key)
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key, "Accept": "application/json"}

    async with aiohttp.ClientSession(headers=headers) as session:
        for attempt in range(3):
            async with session.get(url) as resp:
                if await AdaptiveRateLimiter.handle_resp(resp, attempt):
                    continue
                if resp.status != 200:
                    if resp.status in [401, 403, 429]:
                        config.invalidate_key("securitytrails", api_key)
                    return {"error": f"API error {resp.status}"}
                data = await resp.json()
                data["telemetry"] = QuantumEnricher.get_telemetry(start)
                return data


@mcp.tool()
@tool_exception_handler
@MCPUtils.cache_result(ttl_seconds=86400)
async def securitytrails_dns_history(
    domain: str, record_type: str = "a", key: str = None
) -> Dict:
    """Get historical DNS records (a, aaaa, mx, ns, txt)."""
    api_key = await get_st_key(key)
    url = (
        f"https://api.securitytrails.com/v1/history/{domain}/dns/{record_type.lower()}"
    )
    headers = {"APIKEY": api_key, "Accept": "application/json"}

    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                return {"error": f"API returned {resp.status}"}
            return await resp.json()


if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8103))
    mcp.run(transport="sse", port=port, show_banner=False)
