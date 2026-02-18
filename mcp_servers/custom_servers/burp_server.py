#!/usr/bin/env python3
import os
import asyncio
import json
import aiohttp
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastmcp import FastMCP

# Add parent to path for mcp_common
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import (
    MCPUtils, AdaptiveRateLimiter, QuantumEnricher, CircuitBreaker, 
    ironclad_guard, tool_exception_handler, logger
)
from myth_config import config, load_dotenv

load_dotenv()

# --- Server ---
mcp = FastMCP("Burp Suite Connector")

# Circuit Breaker for Burp API (usually flaky or high latency)
burp_cb = CircuitBreaker()

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@burp_cb
async def burp_send_to_repeater(host: str, port: int, use_https: bool, request_b64: str) -> Dict:
    """Industrial integration: Forward requests to Burp Suite Repeater."""
    burp_api_url = config.get_api_key("burp_api_url") or os.getenv("BURP_API_URL", "http://localhost:1337")
    api_key = config.get_api_key("burp")
    
    if not api_key:
        return {"error": "BURP_API_KEY not set", "type": "ConfigurationMissing"}
        
    payload = {
        "host": host,
        "port": port,
        "protocol": "https" if use_https else "http",
        "request": request_b64
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{burp_api_url}/v1/repeater", json=payload, headers={"Authorization": api_key}) as resp:
            if resp.status != 200:
                raise Exception(f"Burp API returned {resp.status}")
            return await resp.json()

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@burp_cb
async def burp_trigger_scan(target_url: str) -> Dict:
    """Trigger an active scan in Burp Suite Enterprise/Pro."""
    burp_api_url = config.get_api_key("burp_api_url") or os.getenv("BURP_API_URL", "http://localhost:1337")
    api_key = config.get_api_key("burp")
    
    payload = {"urls": [target_url]}
    
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{burp_api_url}/v1/scan", json=payload, headers={"Authorization": api_key}) as resp:
            return await resp.json()

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8202))
    mcp.run(transport="sse", port=port, show_banner=False)
