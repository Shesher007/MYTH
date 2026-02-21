import asyncio
import re
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup
from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🔍 Advanced Content Discovery Tools
# ==============================================================================


@tool
async def heuristic_spider(start_url: str) -> str:
    """
    Advanced JS-aware spider that extracts hidden endpoints from webpack bundles and scripts.
    Parses relative paths and API routes using real BeautifulSoup and Regex analysis.
    """
    try:
        if not start_url.startswith(("http://", "https://")):
            start_url = f"https://{start_url}"

        async with httpx.AsyncClient(
            timeout=20, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(start_url)
            soup = BeautifulSoup(resp.text, "html.parser")

            # 1. Extract normal links
            links = set()
            for a in soup.find_all("a", href=True):
                links.add(urljoin(start_url, a["href"]))

            # 2. Extract scripts and scan for paths
            script_srcs = [
                urljoin(start_url, s["src"]) for s in soup.find_all("script", src=True)
            ]
            extracted_paths = set()

            # Simple path regex
            path_regex = r'["\'](/api/[\w\-/]+|/[\w\-/]+\.\w+)["\']'

            async def scan_script(url):
                try:
                    s_resp = await client.get(url)
                    matches = re.findall(path_regex, s_resp.text)
                    return set(matches)
                except Exception:
                    return set()

            results = await asyncio.gather(*(scan_script(u) for u in script_srcs[:10]))
            for r in results:
                extracted_paths.update(r)

            # 3. Check for .js.map
            map_found = False
            for src in script_srcs:
                if src.endswith(".js"):
                    try:
                        m_resp = await client.head(f"{src}.map")
                        if m_resp.status_code == 200:
                            map_found = True
                            break
                    except Exception:
                        pass

        return format_industrial_result(
            "heuristic_spider",
            "Spidering Complete",
            confidence=0.9,
            impact="MEDIUM",
            raw_data={
                "start_url": start_url,
                "links": list(links)[:20],
                "extracted_paths": list(extracted_paths),
                "source_map_exposed": map_found,
            },
            summary=f"Heuristic spider for {start_url} complete. Found {len(links)} links and extracted {len(extracted_paths)} hidden paths from JS. Map exposure: {map_found}.",
        )
    except Exception as e:
        return format_industrial_result("heuristic_spider", "Error", error=str(e))


@tool
async def hidden_parameter_fuzzer(target_url: str) -> str:
    """
    Probes known endpoints for hidden GET parameters using real differential response analysis.
    """
    try:
        common_params = ["debug", "admin", "test", "v", "id", "user", "config"]
        discovered_params = []

        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # Baseline
            base = await client.get(target_url)
            base_len = len(base.text)

            async def probe_param(p):
                try:
                    # Test with common bypass values
                    test_url = (
                        f"{target_url}{'&' if '?' in target_url else '?'}{p}=true"
                    )
                    resp = await client.get(test_url)
                    if (
                        len(resp.text) != base_len
                        or resp.status_code != base.status_code
                    ):
                        return {
                            "param": p,
                            "effect": "Content Length Difference",
                            "risk": "MEDIUM",
                        }
                except Exception:
                    pass
                return None

            results = await asyncio.gather(*(probe_param(p) for p in common_params))
            discovered_params = [r for r in results if r]

        return format_industrial_result(
            "hidden_parameter_fuzzer",
            "Parameters Found",
            confidence=0.85,
            impact="MEDIUM" if discovered_params else "LOW",
            raw_data={"target": target_url, "discovered_params": discovered_params},
            summary=f"Hidden parameter fuzzing for {target_url} finished. Identified {len(discovered_params)} params causing response variance.",
        )
    except Exception as e:
        return format_industrial_result(
            "hidden_parameter_fuzzer", "Error", error=str(e)
        )


@tool
async def semantic_content_prober(target_url: str) -> str:
    """
    Identifies sensitive artifacts (.git, .env, backups) using real HTTP probing.
    """
    try:
        sensitive_paths = [
            ".git/config",
            ".env",
            "phpinfo.php",
            "status",
            "server-status",
            "robots.txt",
            "sitemap.xml",
            ".svn/entries",
            ".htaccess",
        ]

        base_url = target_url.rstrip("/")
        findings = []

        async with httpx.AsyncClient(
            timeout=10, follow_redirects=False, verify=False
        ) as client:

            async def check_path(p):
                url = f"{base_url}/{p}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        risk = "CRITICAL" if p.startswith(".") else "LOW"
                        return {"type": p, "path": url, "risk": risk}
                except Exception:
                    pass
                return None

            results = await asyncio.gather(*(check_path(p) for p in sensitive_paths))
            findings = [r for r in results if r]

        return format_industrial_result(
            "semantic_content_prober",
            "Probing Complete",
            confidence=1.0,
            impact="HIGH" if findings else "LOW",
            raw_data={"url": target_url, "findings": findings},
            summary=f"Semantic content probe for {target_url} finished. Identified {len(findings)} sensitive artifacts.",
        )
    except Exception as e:
        return format_industrial_result(
            "semantic_content_prober", "Error", error=str(e)
        )


@tool
async def high_fidelity_protocol_fuzzer(
    target_url: str, protocol: str = "GraphQL"
) -> str:
    """
    Performs deep fuzing of modern APIs (GraphQL) by identifying and introspecting endpoints.
    """
    try:
        # Technical logic: Probe for /graphql, /graphiql, /gql
        endpoints = ["graphql", "graphiql", "gql", "api/graphql"]
        base_url = target_url.rstrip("/")

        discovered = []
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for p in endpoints:
                url = f"{base_url}/{p}"
                try:
                    # Introspection query
                    intro_query = {"query": "{__schema{queryType{name}}}"}
                    resp = await client.post(url, json=intro_query)
                    if resp.status_code == 200 and "data" in resp.json():
                        discovered.append(
                            {
                                "endpoint": url,
                                "introspection": "ENABLED",
                                "risk": "HIGH",
                            }
                        )
                except Exception:
                    pass

        return format_industrial_result(
            "high_fidelity_protocol_fuzzer",
            "Fuzzing Complete",
            confidence=0.9,
            impact="HIGH" if discovered else "LOW",
            raw_data={
                "target": target_url,
                "protocol": protocol,
                "findings": discovered,
            },
            summary=f"Protocol fuzzing ({protocol}) for {target_url} complete. Found {len(discovered)} vulnerable endpoints.",
        )
    except Exception as e:
        return format_industrial_result(
            "high_fidelity_protocol_fuzzer", "Error", error=str(e)
        )
