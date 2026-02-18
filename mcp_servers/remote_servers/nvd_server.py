#!/usr/bin/env python3
import os
import aiohttp
import asyncio
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from fastmcp import FastMCP
from myth_config import config

# Add parent to path for mcp_common
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import MCPUtils, AdaptiveRateLimiter, QuantumEnricher, CircuitBreaker, tool_exception_handler, logger

# Circuit Breaker for NVD
nvd_cb = CircuitBreaker()

# --- Models ---
class CVEModel(BaseModel):
    cve_id: str = Field(..., description="CVE ID (e.g., CVE-2023-1234)")
    key: Optional[str] = Field(None)

# --- Server ---
mcp = FastMCP("NVD Server")

@mcp.tool()
@tool_exception_handler
@nvd_cb
@MCPUtils.cache_result(ttl_seconds=86400)
async def nvd_get_cve(cve_id: str, key: str = None) -> Dict:
    """Get CVE info with 'Quantum Leap' exploit cross-referencing."""
    start = asyncio.get_event_loop().time()
    
    async with aiohttp.ClientSession() as session:
        for attempt in range(3):
            # Dynamic Key Rotation
            api_key = key or config.get_api_key("nvd_cve", rotate=True)
            headers = {"apiKey": api_key} if api_key else {}
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            
            try:
                async with session.get(url, headers=headers) as resp:
                    if await AdaptiveRateLimiter.handle_resp(resp, attempt): continue
                    
                    if resp.status == 403 or resp.status == 401:
                         if api_key: config.invalidate_key("nvd_cve", api_key)
                         continue
                         
                    if resp.status != 200: return {"error": f"API error {resp.status}"}
                    data = await resp.json()
                    
                    # Cross-Referencing Intel
                    exploit_url = f"https://gitlab.com/api/v4/projects/exploit-database%2Fexploit-database/repository/tree?path=exploits&recursive=true"
                    async with session.get(exploit_url) as ex_resp:
                        if ex_resp.status == 200:
                            ex_data = await ex_resp.json()
                            data["exploit_matches"] = [e for e in ex_data if cve_id.lower() in e['name'].lower()]
                    
                    data["telemetry"] = QuantumEnricher.get_telemetry(start)
                    return data
            except Exception as e:
                if attempt == 2: return {"error": f"NVD/ExploitDB failed: {e}"}
                await asyncio.sleep(1)

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8107))
    mcp.run(transport="sse", port=port, show_banner=False)
