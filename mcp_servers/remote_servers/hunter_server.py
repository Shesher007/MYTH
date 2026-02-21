#!/usr/bin/env python3
import asyncio
import os
import sys
from pathlib import Path
from typing import Dict, Optional

import aiohttp
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from myth_config import config

# Add parent to path for mcp_common
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import (
    AdaptiveRateLimiter,
    CircuitBreaker,
    MCPUtils,
    QuantumEnricher,
    tool_exception_handler,
)

# Circuit Breaker for Hunter
hunter_cb = CircuitBreaker()


# --- Models ---
class HunterModel(BaseModel):
    domain: str = Field(..., description="Domain to search emails for")
    key: Optional[str] = Field(None)


# --- Server ---
mcp = FastMCP("Hunter.io Server")


async def get_hunter_key(provided_key: Optional[str]) -> str:
    # Use config manager for rotation
    if provided_key:
        return provided_key
    key = config.get_api_key("hunter_io", rotate=True)
    if not key:
        raise ValueError("Hunter API Key not found in rotation pool.")
    return key


@mcp.tool()
@tool_exception_handler
@hunter_cb
@MCPUtils.cache_result(ttl_seconds=86400)
async def hunter_domain_search(domain: str, key: str = None) -> Dict:
    """Find emails with smart rate limits."""
    start = asyncio.get_event_loop().time()

    # Retry loop for key rotation on failure
    for attempt in range(3):
        try:
            api_key = await get_hunter_key(key)
            url = "https://api.hunter.io/v2/domain-search"
            params = {"domain": domain, "api_key": api_key}

            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as resp:
                    if await AdaptiveRateLimiter.handle_resp(resp, attempt):
                        continue

                    if resp.status == 401:  # Unauthorized/Bad Key
                        config.invalidate_key("hunter_io", api_key)
                        continue

                    if resp.status != 200:
                        return {"error": f"API error {resp.status}"}

                    data = await resp.json()
                    data["telemetry"] = QuantumEnricher.get_telemetry(start)
                    return data
        except Exception as e:
            if attempt == 2:
                raise e
            await asyncio.sleep(1)

    return {"error": "Hunter.io failed after retries."}


if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8105))
    mcp.run(transport="sse", port=port, show_banner=False)
