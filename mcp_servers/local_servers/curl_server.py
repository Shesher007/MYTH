#!/usr/bin/env python3
import asyncio
import os
import sys
from pathlib import Path
from typing import Dict, List

from fastmcp import FastMCP
from pydantic import BaseModel, Field

sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import tool_exception_handler


# --- Models ---
class FingerprintModel(BaseModel):
    host: str = Field(..., description="Target hostname or IP")
    port: int = Field(..., ge=1, le=65535)


# --- Server ---
mcp = FastMCP("Curl Tools")


@mcp.tool()
@tool_exception_handler
async def deep_fingerprint_scout(host: str, ports: List[int]) -> List[Dict]:
    """Industry-standard parallel protocol fingerprinting."""
    tasks = [protocol_fingerprint(host, p) for p in ports]
    return await asyncio.gather(*tasks)


@mcp.tool()
@tool_exception_handler
async def protocol_fingerprint(host: str, port: int) -> Dict:
    """Banner grabbing with strict timeouts and isolation."""
    args = FingerprintModel(host=host, port=port)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(args.host, args.port), timeout=5
        )

        banner = await asyncio.wait_for(reader.read(1024), timeout=3)
        writer.close()
        await writer.wait_closed()

        raw_banner = banner.decode("utf-8", errors="ignore").strip()
        return {
            "port": args.port,
            "banner": raw_banner,
            "possible_service": "SSH" if "SSH" in raw_banner else "Unknown",
        }
    except Exception as e:
        return {"port": port, "error": str(e)}


if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8009))
    mcp.run(transport="sse", port=port, show_banner=False)
