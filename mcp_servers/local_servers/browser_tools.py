#!/usr/bin/env python3
import os
import asyncio
import base64
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, HttpUrl
from fastmcp import FastMCP
from playwright.async_api import async_playwright
from playwright_stealth import Stealth
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import (
    MCPUtils, QuantumEnricher, DependencyGuard, GhostProtocol, NexusState, 
    PlatformGuard, AccelerationGuard, ironclad_guard, tool_exception_handler, logger
)
import markdownify

# --- Models ---
class BrowseModel(BaseModel):
    url: str = Field(..., description="URL to browse")
    extract_markdown: bool = Field(True)

# --- Server ---
mcp = FastMCP("Browser Tools")

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@DependencyGuard.require(["playwright", "playwright_stealth"])
@MCPUtils.cache_result(ttl_seconds=1800)
async def forensic_browse(url: str, capture_har: bool = True) -> Dict:
    """Stealth browsing with network traffic (HAR) capture for C2 discovery."""
    start = asyncio.get_event_loop().time()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            # Nexus Ghost Protocol integration
            stealth_config = GhostProtocol.get_stealth_config()
            context = await browser.new_context(
                **stealth_config,
                record_har_path="temp_trace.har" if capture_har else None
            )
            page = await context.new_page()
            await Stealth().apply_stealth_async(page)
            
            resp = await page.goto(url, wait_until="networkidle", timeout=30000)
            
            result = {
                "title": await page.title(),
                "status": resp.status,
                "telemetry": QuantumEnricher.get_telemetry(start)
            }
            
            if capture_har and os.path.exists("temp_trace.har"):
                with open("temp_trace.har", "r", encoding="utf-8", errors="ignore") as f:
                    har_data = json.load(f)
                    # Extract only critical network intelligence to save space
                    result["network_summary"] = {
                        "total_requests": len(har_data.get("log", {}).get("entries", [])),
                        "domains_contacted": list(set([re.search(r'//([^/]+)', e['request']['url']).group(1) 
                                                     for e in har_data["log"]["entries"] if "//" in e['request']['url']]))
                    }
                os.remove("temp_trace.har")
                
            return result
        finally:
            await browser.close()

@mcp.tool()
@tool_exception_handler
@ironclad_guard
@DependencyGuard.require(["playwright"])
async def capture_scout(url: str, full_page: bool = True) -> str:
    """Capture high-res screenshot with guaranteed cleanup."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.goto(url, timeout=30000)
            screenshot = await page.screenshot(full_page=full_page)
            return base64.b64encode(screenshot).decode('utf-8')
        finally:
            await browser.close()

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8007))
    mcp.run(transport="sse", port=port, show_banner=False)
