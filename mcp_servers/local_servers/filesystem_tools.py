#!/usr/bin/env python3
import fnmatch
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import aiofiles
from fastmcp import FastMCP
from pydantic import BaseModel, Field

sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import (
    ComputeGuard,
    MCPUtils,
    PlatformGuard,
    QuantumEnricher,
    ResourceGuard,
    TitanResponse,
    ironclad_guard,
    logger,
    tool_exception_handler,
)


# --- Models ---
class ScanModel(BaseModel):
    path: str = Field(..., description="Root directory to scan")
    pattern: str = Field("*", description="Glob pattern")
    recursive: bool = Field(True, description="Search recursively")


class ReadModel(BaseModel):
    path: str = Field(..., description="File path to read")
    encoding: str = Field("utf-8")
    head: int = Field(0, description="Read first N lines only")


# --- Server ---
mcp = FastMCP("Advanced Filesystem Tools")


@mcp.tool()
@tool_exception_handler
@ironclad_guard
async def scan_directory(
    path: str, pattern: str = "*", recursive: bool = True
) -> List[Dict]:
    """Universal high-performance directory scanner."""
    # Validation via model
    args = ScanModel(path=path, pattern=pattern, recursive=recursive)
    # Omni-Path: Map paths across WSL/Win/Linux
    mapped_path = PlatformGuard.map_path(args.path)
    safe_path = MCPUtils.get_safe_path(mapped_path)

    if not safe_path.exists():
        return [{"error": "Path not found"}]

    def _walk():
        matches = []
        if args.recursive:
            for root, _, files in os.walk(safe_path):
                for filename in fnmatch.filter(files, args.pattern):
                    matches.append(Path(root) / filename)
                    if len(matches) > 1000:
                        break  # Protection
        else:
            for item in safe_path.iterdir():
                if item.is_file() and fnmatch.fnmatch(item.name, args.pattern):
                    matches.append(item)
        return matches

    found_files = await ComputeGuard.run_in_pool(_walk)
    results = []
    for f_path in found_files[:100]:
        try:
            stats = f_path.stat()
            results.append(
                {
                    "name": f_path.name,
                    "path": str(f_path.absolute()),
                    "size_bytes": stats.st_size,
                    "type": "file",
                }
            )
        except Exception:
            continue
    return results


@mcp.tool()
@tool_exception_handler
@ironclad_guard
async def read_file_content(
    path: str, encoding: str = "utf-8", head: int = 0
) -> TitanResponse:
    """Industry-grade file reader with streaming and rich metadata."""
    safe_path = MCPUtils.get_safe_path(path)
    stats = safe_path.stat()

    # [TITAN] Safe Read Enforcement: Prevent OOM on massive files
    if stats.st_size > ResourceGuard.MAX_FILE_READ_SIZE:
        logger.warning(f"Safe Read triggered for {path}. Size: {stats.st_size}")
        head = head or 1000  # Force head if too large

    async def _stream_read():
        async with aiofiles.open(
            safe_path, mode="r", encoding=encoding, errors="ignore"
        ) as f:
            if head > 0:
                lines = []
                for _ in range(head):
                    line = await f.readline()
                    if not line:
                        break
                    lines.append(line)
                return "".join(lines)
            return await f.read()

    content = await _stream_read()

    return TitanResponse(
        success=True,
        data=content,
        metadata={
            "size_bytes": stats.st_size,
            "encoding": encoding,
            "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
            "entropy": QuantumEnricher.calculate_entropy(content.encode()[:8192]),
            "safe_read": stats.st_size > ResourceGuard.MAX_FILE_READ_SIZE,
        },
    )


@mcp.tool()
@tool_exception_handler
@ironclad_guard
async def atomic_write_file(path: str, content: str) -> TitanResponse:
    """Atomic file write to prevent data corruption during power loss."""
    safe_path = MCPUtils.get_safe_path(path)
    tmp_path = safe_path.with_suffix(".tmp")

    async with aiofiles.open(tmp_path, mode="w", encoding="utf-8") as f:
        await f.write(content)
        await f.flush()
        if hasattr(f, "fileno"):
            os.fsync(f.fileno())

    os.replace(tmp_path, safe_path)

    return TitanResponse(
        success=True,
        data=str(safe_path),
        metadata={"action": "atomic_write", "bytes": len(content)},
    )


@mcp.tool()
@tool_exception_handler
async def secure_delete_file(path: str) -> Dict:
    """Overwrites file with random data before deletion for forensic security."""
    safe_path = MCPUtils.get_safe_path(path)
    if not safe_path.is_file():
        return {"error": "Target is not a file"}

    size = safe_path.stat().st_size
    async with aiofiles.open(safe_path, mode="wb") as f:
        # One pass of random data is usually sufficient for industry grade
        await f.write(os.urandom(size))

    os.remove(safe_path)
    return {"status": "securely_deleted", "path": str(safe_path)}


if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8004))
    mcp.run(transport="sse", port=port, show_banner=False)
