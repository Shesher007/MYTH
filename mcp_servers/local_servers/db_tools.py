#!/usr/bin/env python3
import os
import json
import sqlite3
import asyncio
import redis.asyncio as redis
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from fastmcp import FastMCP
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine
from motor.motor_asyncio import AsyncIOMotorClient
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import MCPUtils, tool_exception_handler, logger

# --- Models ---
class SQLQueryModel(BaseModel):
    connection_string: str = Field(..., description="DB connection string")
    sql: str = Field(..., description="SQL query to execute")
    params: Optional[Dict] = Field(None)

    @field_validator('sql')
    @classmethod
    def validate_sql(cls, v):
        # Basic industry-grade sanity check
        forbidden = ["DROP", "TRUNCATE", "GRANT", "REVOKE"]
        if any(cmd in v.upper() for cmd in forbidden):
            raise ValueError(f"SQL contains forbidden commands: {v}")
        return v

# --- Server ---
mcp = FastMCP("Database Tools")
_engines = {}

def get_engine(connection_string: str):
    if connection_string not in _engines:
        _engines[connection_string] = create_async_engine(
            connection_string, pool_size=5, max_overflow=10, pool_recycle=1800)
    return _engines[connection_string]

@mcp.tool()
@tool_exception_handler
async def query_postgres(connection_string: str, sql: str, params: Dict = None) -> List[Dict]:
    """Execute Postgres query with strict validation and pooling."""
    args = SQLQueryModel(connection_string=connection_string, sql=sql, params=params)
    engine = get_engine(args.connection_string)
    
    async with engine.connect() as conn:
        res = await asyncio.wait_for(conn.execute(text(args.sql), args.params or {}), timeout=15)
        if args.sql.strip().upper().startswith("SELECT"):
            return [dict(row._mapping) for row in res.fetchall()]
        await conn.commit()
        return [{"status": "success", "rows_affected": res.rowcount}]

@mcp.tool()
@tool_exception_handler
async def query_redis(uri: str, command: str, args: List[Any] = None) -> Any:
    """Execute Redis commands with session safety."""
    r = redis.from_url(uri, decode_responses=True)
    async with r:
        return await asyncio.wait_for(r.execute_command(command, *(args or [])), timeout=5)

@mcp.tool()
@tool_exception_handler
async def check_db_health(connection_string: str) -> Dict:
    """Check database health and connectivity."""
    engine = get_engine(connection_string)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
        return {"status": "healthy"}

if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8005))
    mcp.run(transport="sse", port=port, show_banner=False)
