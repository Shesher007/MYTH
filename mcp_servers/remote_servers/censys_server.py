#!/usr/bin/env python3
import asyncio
import base64
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
    NexusState,
    QuantumEnricher,
    ironclad_guard,
    tool_exception_handler,
)

from myth_config import config, load_dotenv

load_dotenv()

# Circuit Breaker for Censys
censys_cb = CircuitBreaker()


# --- Models ---
class CensysSearchModel(BaseModel):
    query: str = Field(..., description="Censys SQL or key:value query")
    api_id: Optional[str] = Field(None, description="Censys API ID")
    api_secret: Optional[str] = Field(None, description="Censys API Secret")


# --- Server ---
mcp = FastMCP("Censys Server")


async def get_censys_creds(
    provided_id: Optional[str], provided_secret: Optional[str]
) -> tuple:
    if provided_id and provided_secret:
        return provided_id, provided_secret

    creds = config.get_credentials("censys")
    if isinstance(creds, dict):
        return creds.get("id"), creds.get("secret")

    # Industrial Standard: credentials MUST be in secrets.yaml or provided
    raise ValueError("Censys credentials not found in SovereignConfig rotation.")


@mcp.tool()
@tool_exception_handler
@ironclad_guard
@censys_cb
@MCPUtils.cache_result(ttl_seconds=3600)
async def censys_search_hosts(
    query: str, api_id: str = None, api_secret: str = None
) -> Dict:
    """Search Censys Hosts with smart backoff."""
    start = asyncio.get_event_loop().time()
    args = CensysSearchModel(query=query, api_id=api_id, api_secret=api_secret)
    cid, sec = await get_censys_creds(args.api_id, args.api_secret)

    url = "https://search.censys.io/api/v2/hosts/search"
    params = {"q": args.query, "per_page": 50}

    auth_header = base64.b64encode(f"{cid}:{sec}".encode()).decode()
    headers = {"Authorization": f"Basic {auth_header}"}

    async with aiohttp.ClientSession(headers=headers) as session:
        for attempt in range(3):
            async with session.get(url, params=params) as resp:
                if await AdaptiveRateLimiter.handle_resp(resp, attempt):
                    continue
                if resp.status != 200:
                    if resp.status in [401, 403, 429]:
                        config.invalidate_key("censys", {"id": cid, "secret": sec})
                    return {"error": f"API error {resp.status}"}

                data = await resp.json()
                data["telemetry"] = QuantumEnricher.get_telemetry(start)

                # Predictive Intel: Broadcast newly discovered hosts
                hosts = [h.get("ip") for h in data.get("results", []) if h.get("ip")]
                if hosts:
                    await NexusState.post_intel(f"new_hosts:{query[:32]}", hosts)

                return data


@mcp.tool()
@tool_exception_handler
@ironclad_guard
@censys_cb
@MCPUtils.cache_result(ttl_seconds=3600)
async def cens_cert_search(
    fingerprint: str, api_id: str = None, api_secret: str = None
) -> Dict:
    """Get detailed certificate info by SHA256 fingerprint."""
    cid, sec = await get_censys_creds(api_id, api_secret)
    url = f"https://search.censys.io/api/v2/certificates/{fingerprint}"

    auth_header = base64.b64encode(f"{cid}:{sec}".encode()).decode()
    headers = {"Authorization": f"Basic {auth_header}"}

    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                return {"error": f"Censys API returned {resp.status}"}
            return await resp.json()


if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8102))
    mcp.run(transport="sse", port=port, show_banner=False)
