#!/usr/bin/env python3
import asyncio
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

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

# Circuit Breaker for HIBP
hibp_cb = CircuitBreaker()


# --- Models ---
class HIBPModel(BaseModel):
    account: str = Field(..., description="Email or Username to check")
    key: Optional[str] = Field(None)


# --- Server ---
mcp = FastMCP("HaveIBeenPwned Server")


async def get_hibp_key(provided_key: Optional[str]) -> str:
    # Use config manager for rotation
    if provided_key:
        return provided_key
    key = config.get_api_key("hibp_breach", rotate=True)
    if not key:
        raise ValueError("HIBP API Key not found in rotation pool.")
    return key


@mcp.tool()
@tool_exception_handler
@hibp_cb
@MCPUtils.cache_result(ttl_seconds=86400)
async def hibp_check_account(account: str, key: str = None) -> List[Dict]:
    """Check compromised accounts with smart backoff."""
    start = asyncio.get_event_loop().time()

    async with aiohttp.ClientSession() as session:
        for attempt in range(5):  # HIBP is very strict
            api_key = await get_hibp_key(key)
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
            headers = {"hibp-api-key": api_key, "user-agent": "MYTH-Quantum-Leap"}

            try:
                async with session.get(url, headers=headers) as resp:
                    if await AdaptiveRateLimiter.handle_resp(resp, attempt):
                        continue

                    if resp.status == 401 or resp.status == 403:  # Unauthorized/Bad Key
                        config.invalidate_key("hibp_breach", api_key)
                        continue

                    if resp.status == 404:
                        return [{"status": "clean"}]
                    if resp.status != 200:
                        return [{"error": f"API error {resp.status}"}]

                    data = await resp.json()
                    # Meta-Enrichment: Telemetry
                    if isinstance(data, list):
                        data.append({"telemetry": QuantumEnricher.get_telemetry(start)})
                    return data
            except Exception as e:
                if attempt == 4:
                    return [{"error": f"HIBP check failed: {str(e)}"}]
                await asyncio.sleep(1)


if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8106))
    mcp.run(transport="sse", port=port, show_banner=False)
