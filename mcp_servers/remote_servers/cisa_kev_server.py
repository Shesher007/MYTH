#!/usr/bin/env python3
import asyncio
import os
import sys
from pathlib import Path
from typing import Dict, List

import aiohttp
from fastmcp import FastMCP

# Add parent to path for mcp_common
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import CircuitBreaker, MCPUtils, QuantumEnricher, tool_exception_handler

# --- Server ---
mcp = FastMCP("CISA KEV Server")
cisa_cb = CircuitBreaker()


@mcp.tool()
@tool_exception_handler
@cisa_cb
@MCPUtils.cache_result(ttl_seconds=86400)
async def cisa_get_kev_catalog() -> Dict:
    """Retrieve full CISA catalog with Quantum Telemetry."""
    start = asyncio.get_event_loop().time()
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                return {"error": "CISA unreachable"}
            data = await resp.json()
            data["telemetry"] = QuantumEnricher.get_telemetry(start)
            return data


@mcp.tool()
@tool_exception_handler
@MCPUtils.cache_result(ttl_seconds=86400)
async def cisa_search_kev(query: str) -> List[Dict]:
    """Search for a specific vulnerability in the CISA KEV catalog."""
    catalog = await cisa_get_kev_catalog()
    if "error" in catalog:
        return [catalog]

    vulnerabilities = catalog.get("vulnerabilities", [])
    return [v for v in vulnerabilities if query.lower() in str(v).lower()][:20]


if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8110))
    mcp.run(transport="sse", port=port, show_banner=False)
