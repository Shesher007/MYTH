"""
MYTH Tool Command & Control System
==========================================
Industry Grade Tool Management Framework with Unified MCP Bridge.
NOW FEATURING: Zero-Latency Lazy Loading.
"""
from myth_config import load_dotenv
load_dotenv()

import logging
import os
import json
import importlib
from typing import List, Dict, Any, Optional, Set, Union, Type
from langchain_core.tools import BaseTool
from langchain_core.callbacks import CallbackManagerForToolRun
from pydantic import Field, BaseModel, create_model

# =============================================================================
# Logging Configuration
# =============================================================================
logger = logging.getLogger("MYTH.tools")

# =============================================================================
# Lazy Loading Infrastructure
# =============================================================================

CACHE_FILE = os.path.join(os.path.dirname(__file__), ".internal_tool_cache.json")

class LazyTool(BaseTool):
    """
    A lightweight proxy that only imports the heavy actual tool when run.
    """
    name: str
    description: str
    module_path: str
    variable_name: str
    category: str = "uncategorized"
    
    # Internal state
    _real_tool: Optional[BaseTool] = None

    def __init__(self, **kwargs):
        # Reconstruct args_schema if provided in metadata
        if 'input_schema' in kwargs and kwargs['input_schema']:
            try:
                schema = kwargs.pop('input_schema')
                # Basic Pydantic reconstruction
                fields = {}
                properties = schema.get('properties', {})
                required = schema.get('required', [])
                
                for prop_name, prop_info in properties.items():
                    prop_type = Any
                    json_type = prop_info.get('type')
                    if json_type == 'string': prop_type = str
                    elif json_type == 'integer': prop_type = int
                    elif json_type == 'boolean': prop_type = bool
                    elif json_type == 'object': prop_type = Dict
                    elif json_type == 'array': prop_type = List
                    
                    is_required = prop_name in required
                    default_val = prop_info.get('default', None)
                    
                    # Pydantic v2: If it's not required and defaults to None, Ensure it's Optional
                    if not is_required:
                        # Allow either the specific type or None
                        fields[prop_name] = (Optional[prop_type], Field(default=default_val))
                    else:
                        fields[prop_name] = (prop_type, Field(default=...))
                
                if fields:
                    kwargs['args_schema'] = create_model(f"{kwargs['name']}Args", **fields)
            except Exception as e:
                logger.error(f"Failed to reconstruct args_schema for {kwargs.get('name')}: {e}")
            
        super().__init__(**kwargs)

    def _load_real_tool(self) -> BaseTool:
        if self._real_tool:
            return self._real_tool
        
        try:
            logger.debug(f"Lazy loading tool: {self.name} from {self.module_path}")
            module = importlib.import_module(self.module_path)
            tool_instance = getattr(module, self.variable_name)
            self._real_tool = tool_instance
            return tool_instance
        except Exception as e:
            logger.error(f"Failed to lazy load {self.name}: {e}")
            raise

    def _run(self, *args, **kwargs):
        tool = self._load_real_tool()
        # Use public run() to handle LangChain's internal argument requirements (like config)
        # But we must be careful not to cause recursion.
        # However, since self._real_tool is NOT self, tool.run() is safe.
        # We use tool.run instead of tool._run to let LangChain handle version-specific signatures.
        return tool.run(kwargs if not args else args[0])
        
    async def _arun(self, *args, **kwargs):
        tool = self._load_real_tool()
        return await tool.arun(kwargs if not args else args[0])

# =============================================================================
# Tool Categorization
# =============================================================================

TOOL_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "recon": {
        "description": "Port scanning, service discovery, DNS, WHOIS, subdomain enumeration.",
        "packages": ["tools.recon"],
        "keywords": ["scan", "port", "dns", "whois", "subdomain", "discover", "enum", "nmap", "masscan"]
    },
    "exploitation": {
        "description": "SQLi, XSS, credential attacks, privilege escalation, network exploits.",
        "packages": ["tools.exploitation", "tools.web"],
        "keywords": ["exploit", "sqli", "xss", "inject", "priv", "escalat", "payload", "rce", "lfi", "rfi"]
    },
    "intelligence": {
        "description": "Web search, CVE intelligence, social media OSINT, threat feeds.",
        "packages": ["tools.intelligence", "rag_system", "backend"],
        "keywords": ["query", "knowledge", "search", "vuln", "cve", "osint", "intel", "threat", "research"]
    },
    "utilities": {
        "description": "Shell execution, file management, report generation, integrations.",
        "packages": ["tools.utilities", "mcp_servers"],
        "keywords": ["list", "read", "write", "file", "shell", "exec", "report", "hash", "encode", "decode", "create", "generate"]
    },
    "cloud": {
        "description": "AWS, Azure, GCP, and container (Docker/K8s) security tools.",
        "packages": ["tools.cloud"],
        "keywords": ["aws", "azure", "gcp", "s3", "bucket", "iam", "k8s", "kubernetes", "docker", "cloud"]
    },
    "evasion": {
        "description": "Antivirus bypass, EDR detection, defense evasion techniques.",
        "packages": ["tools.evasion"],
        "keywords": ["evasion", "bypass", "edr", "av", "obfuscat", "unhook", "inject", "stealth", "amsi"]
    },
    "ctf": {
        "description": "Capture The Flag utilities for crypto, forensics, pwn, web challenges.",
        "packages": ["tools.ctf"],
        "keywords": ["ctf", "crypto", "forensic", "pwn", "stego", "cipher", "base64", "rot13", "reversing"]
    },
    "re": {
        "description": "Reverse Engineering: binary analysis, firmware auditing, decompilation.",
        "packages": ["tools.re"],
        "keywords": ["reverse", "binary", "disassembl", "decompil", "firmware", "elf", "pe", "gadget", "rop"]
    },
    "vr": {
        "description": "Vulnerability Research: heap/kernel exploitation, fuzzing, mitigations.",
        "packages": ["tools.vr"],
        "keywords": ["heap", "kernel", "fuzz", "exploit", "mitigation", "bypass", "sandbox", "browser"]
    },
    "system": {
        "description": "System forensics, process management, registry auditing, and hardware diagnostics.",
        "packages": ["tools.utilities"],
        "keywords": ["process", "registry", "service", "system", "health", "disk", "net", "bash", "shell", "cmd"]
    }
}

# =============================================================================
# Unified Tool Discovery (Omni-Channel)
# =============================================================================

_tool_cache: Optional[List[BaseTool]] = None

async def _load_internal_cache() -> List[BaseTool]:
    """Loads internal tools from JSON cache as LazyTools."""
    if not os.path.exists(CACHE_FILE):
        logger.warning("Internal tool cache missing. Rebuilding...")
        try:
            # We must run this in a thread to keep it sync if needed, 
            # but rebuild_cache is currently sync.
            from .cache_manager import rebuild_cache
            rebuild_cache()
        except Exception as e:
            logger.error(f"Failed to rebuild cache: {e}")
            return []
            
    try:
        import asyncio
        # Async read for industrial performance
        import aiofiles
        async with aiofiles.open(CACHE_FILE, mode='r') as f:
            content = await f.read()
            data = json.loads(content)
            
        # INDUSTRIAL ENHANCEMENT: Tool Fingerprint Validation
        from .cache_manager import get_tools_signature, rebuild_cache
        current_sig = get_tools_signature()
        cached_sig = data.get("metadata", {}).get("signature")
        
        if cached_sig != current_sig:
            logger.info("🔄 [CACHE] Internal tools drift detected. Rebuilding...")
            # INDUSTRIAL ENHANCEMENT: Rebuild in a thread to avoid blocking the event loop
            rebuilt_tools = await asyncio.to_thread(rebuild_cache)
            data = {"tools": rebuilt_tools}
            
        tools = []
        for t_data in data.get("tools", []):
            tools.append(LazyTool(
                name=t_data["name"],
                description=t_data["description"] or "",
                module_path=t_data["module_path"],
                variable_name=t_data["variable_name"],
                category=t_data.get("category", "uncategorized"),
                input_schema=t_data.get("input_schema")
            ))
        return tools
    except ImportError:
        # Fallback to standard open if aiofiles missing
        with open(CACHE_FILE, 'r') as f:
            data = json.load(f)
        tools = []
        for t_data in data.get("tools", []):
            tools.append(LazyTool(
                name=t_data["name"],
                description=t_data["description"] or "",
                module_path=t_data["module_path"],
                variable_name=t_data["variable_name"],
                category=t_data.get("category", "uncategorized"),
                input_schema=t_data.get("input_schema")
            ))
        return tools
    except Exception as e:
        logger.error(f"Failed to load internal tool cache: {e}")
        return []

async def get_all_tools(force_refresh: bool = False) -> List[BaseTool]:
    """
    Returns a unified list of all tools (Lazy Internal + Dynamic MCP).
    """
    global _tool_cache
    if _tool_cache is not None and not force_refresh:
        return _tool_cache
    
    all_tools = []
    seen_names: Set[str] = set()
    
    # 1. Internal Lazy Tools
    internal_tools = await _load_internal_cache()
    for tool in internal_tools:
        if tool.name not in seen_names:
            all_tools.append(tool)
            seen_names.add(tool.name)
    
    # 2. Dynamic MCP Tools (Bridge)
    try:
        from mcp_servers.mcp_client import discover_mcp_tools_async
        # Direct async discovery - no thread pooling needed anymore!
        mcp_tools = await discover_mcp_tools_async()
        for tool in mcp_tools:
            if tool.name not in seen_names:
                all_tools.append(tool)
                seen_names.add(tool.name)
    except Exception as e:
        logger.warning(f"MCP Bridge partially unavailable: {e}")
    
    _tool_cache = all_tools
    logger.info(f"Omni-Hub Built: {len(all_tools)} tools online (Lazy Loaded)")
    return all_tools

async def get_tools_by_category(categories: Optional[List[str]] = None, provided_tools: Optional[List[BaseTool]] = None) -> List[BaseTool]:
    source_list = provided_tools if provided_tools is not None else await get_all_tools()
    if not categories: return source_list
    
    filtered_tools = []
    for tool in source_list:
        tool_category = getattr(tool, "category", None)
        # Use description/name matching for LazyTools since we might not have exact package info without loading
        tool_name = tool.name.lower()
        tool_desc = (tool.description or "").lower()
        
        for cat_name in categories:
            if cat_name not in TOOL_CATEGORIES: continue
            
            # Direct Meta Match
            if tool_category == cat_name:
                filtered_tools.append(tool)
                break
                
            cat_info = TOOL_CATEGORIES[cat_name]
            # Keyword Match
            keywords = cat_info.get("keywords", [])
            if any(kw in tool_name or kw in tool_desc for kw in keywords):
                filtered_tools.append(tool)
                break
    return filtered_tools

async def search_tools(query: str, max_results: int = 10) -> List[Dict[str, Any]]:
    """Natural language tool search with relevance scoring."""
    query_lower = query.lower()
    query_words = set(query_lower.split())
    results = []
    
    for tool in await get_all_tools():
        score = 0
        reasons = []
        tool_name = tool.name.lower()
        tool_desc = (tool.description or "").lower()
        
        if query_lower in tool_name:
            score += 100
            reasons.append("name_match")
            
        overlap = len(query_words & set(tool_name.replace("_", " ").split()))
        if overlap > 0: score += overlap * 20
        
        desc_matches = sum(1 for w in query_words if w in tool_desc and len(w) > 2)
        if desc_matches > 0: score += desc_matches * 10
        
        if score > 0:
            # Extract args schema
            args_schema = {}
            if hasattr(tool, "args_schema") and tool.args_schema:
                try:
                    args_schema = tool.args_schema.model_json_schema()
                except:
                    # Fallback to string only if schema retrieval fails, but wrap it to keep dict access safe
                    args_schema = {"properties": {}, "raw_schema": str(tool.args_schema)}
            elif hasattr(tool, "input_schema"):
                 args_schema = tool.input_schema
                 if not isinstance(args_schema, dict):
                     args_schema = {"properties": {}, "raw_schema": str(args_schema)}

            results.append({
                "tool": tool,
                "name": tool.name,
                "score": score,
                "reason": ", ".join(reasons),
                "description": (tool.description or "")[:200],
                "args": args_schema
            })
    
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:max_results]

# =============================================================================
# Agent Navigators
# =============================================================================

async def get_omni_manifest(force_refresh: bool = False) -> Dict[str, Any]:
    """Hierarchical capability navigator for the agent."""
    tools = await get_all_tools(force_refresh=force_refresh)
    manifest = {
        "status": "Singularity-Active",
        "total_capability_count": len(tools),
        "mission_areas": {}
    }
    for cat_name, cat_info in TOOL_CATEGORIES.items():
        cat_tools = await get_tools_by_category([cat_name], tools)
        manifest["mission_areas"][cat_name] = {
            "description": cat_info["description"],
            "tool_count": len(cat_tools),
            "top_tools": [t.name for t in cat_tools[:10]],
            "servers": list(set([getattr(t, "port", "local") for t in cat_tools]))
        }
    return manifest

async def get_tool_manifest() -> Dict[str, Any]:
    """Complete flat manifest of all tools."""
    tools = await get_all_tools()
    manifest = {"total": len(tools), "tools": []}
    for tool in tools:
        manifest["tools"].append({
            "name": tool.name,
            "category": getattr(tool, "category", "uncategorized"),
            "description": (tool.description or "")[:150]
        })
    return manifest

async def get_tool_by_name(name: str) -> Optional[BaseTool]:
    for tool in await get_all_tools():
        if tool.name == name: return tool
    return None

async def health_check() -> Dict[str, Any]:
    stats = await get_tool_stats()
    return {
        "status": "HEALTHY",
        "total_tools": stats["total_tools"],
        "cache_active": True
    }

async def get_tool_stats() -> Dict[str, Any]:
    tools = await get_all_tools()
    category_counts = {}
    for cat in TOOL_CATEGORIES:
        cat_tools = await get_tools_by_category([cat], tools)
        category_counts[cat] = len(cat_tools)
        
    return {
        "total_tools": len(tools),
        "tools_per_category": category_counts,
        "lazy_loading": True
    }

async def suggest_tools_for_target(target_type: str) -> List[str]:
    suggestions = {
        "web": ["exploitation", "web", "intelligence"],
        "network": ["recon", "exploitation"],
        "cloud": ["cloud", "recon"],
        "binary": ["re", "vr"],
    }
    cats = suggestions.get(target_type.lower(), ["recon", "intelligence"])
    tools = []
    for cat in cats:
        cat_tools = await get_tools_by_category([cat])
        tools.extend([t.name for t in cat_tools])
    return tools[:20]


__all__ = [
    "get_all_tools",
    "get_tools_by_category",
    "get_tool_by_name",
    "get_tool_stats",
    "health_check",
    "search_tools",
    "get_tool_manifest",
    "get_omni_manifest",
    "suggest_tools_for_target",
    "TOOL_CATEGORIES"
]
