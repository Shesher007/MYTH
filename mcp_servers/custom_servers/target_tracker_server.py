#!/usr/bin/env python3
import os
import sqlite3
import hashlib
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastmcp import FastMCP

# Add parent to path for mcp_common
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import MCPUtils, ironclad_guard, tool_exception_handler, logger

# --- DB Layer ---
DB_PATH = Path(__file__).parent / "targets.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS targets 
                 (id TEXT PRIMARY KEY, host TEXT, program TEXT, scope_status TEXT, discovered_at TEXT)''')
    conn.commit()
    conn.close()

# --- Server ---
mcp = FastMCP("Target Tracker")
init_db()

@mcp.tool()
@tool_exception_handler
@ironclad_guard
async def track_new_asset(host: str, program: str, in_scope: bool = True) -> Dict:
    """Store and deduplicate discovered assets in the bug bounty database."""
    asset_id = hashlib.sha256(f"{host}:{program}".encode()).hexdigest()
    ts = datetime.now().isoformat()
    
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO targets VALUES (?, ?, ?, ?, ?)", 
                  (asset_id, host, program, "IN" if in_scope else "OUT", ts))
        conn.commit()
        return {"status": "tracked", "id": asset_id, "host": host}
    finally:
        conn.close()

@mcp.tool()
@tool_exception_handler
@ironclad_guard
async def check_asset_scope(host: str) -> Dict:
    """Verify if a host is already tracked and its scope status."""
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.cursor()
        c.execute("SELECT program, scope_status FROM targets WHERE host = ?", (host,))
        res = c.fetchone()
        if res:
            return {"known": True, "program": res[0], "status": res[1]}
        return {"known": False, "status": "UNKNOWN"}
    finally:
        conn.close()

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8203))
    mcp.run(transport="sse", port=port, show_banner=False)
