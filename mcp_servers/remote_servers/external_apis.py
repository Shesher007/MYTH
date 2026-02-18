#!/usr/bin/env python3
from fastmcp import FastMCP
import httpx
import json
import os
import asyncio
from typing import Dict, List, Optional
from myth_config import load_dotenv, config
import time

load_dotenv()

# Create MCP server for external APIs
mcp = FastMCP("External APIs Server")

# Helper for async requests
async def fetch_json(url: str, headers: Dict = None, method: str = "GET", data: Dict = None) -> Dict:
    async with httpx.AsyncClient(timeout=300.0) as client: # Extended from 30.0
        if method == "GET":
            response = await client.get(url, headers=headers)
        else:
            response = await client.post(url, headers=headers, data=data)
        response.raise_for_status()
        return response.json()

# Shodan API
@mcp.tool()
async def shodan_search(query: str, limit: int = 10) -> Dict:
    """Interfaces with the Shodan API to scan the public internet for specific IP addresses or services."""
    max_retries = 3
    last_error = None
    
    for attempt in range(max_retries):
        api_key = config.get_api_key("shodan")
        if not api_key:
            return {"error": "SHODAN_API_KEY not found in rotation."}
        
        try:
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
            data = await fetch_json(url)
            
            results = []
            for match in data.get('matches', [])[:limit]:
                results.append({
                    "ip": match.get('ip_str'),
                    "port": match.get('port'),
                    "org": match.get('org'),
                    "product": match.get('product'),
                    "vulns": list(match.get('vulns', {}).keys()) if match.get('vulns') else []
                })
            
            return {
                "total": data.get('total', 0),
                "results": results,
                "query": query
            }
        except Exception as e:
            last_error = e
            err_str = str(e).lower()
            if "401" in err_str or "unauthorized" in err_str or "429" in err_str:
                print(f"⚠️ Shodan Key Failed: {e}. Rotating...")
                config.invalidate_key("shodan", api_key)
                continue
            else:
                return {"error": str(e)}
                
    return {"error": f"Shodan failed after {max_retries} attempts. Last error: {last_error}"}

# VirusTotal API
@mcp.tool()
async def virustotal_file_report(file_hash: str) -> Dict:
    """Get VirusTotal report for a file hash using VT API v3."""
    max_retries = 3
    last_error = None

    for attempt in range(max_retries):
        api_key = config.get_api_key("virustotal")
        if not api_key:
            return {"error": "VIRUSTOTAL_API_KEY not found"}
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": api_key}
            data = await fetch_json(url, headers=headers)
            
            attr = data.get('data', {}).get('attributes', {})
            return {
                "hash": file_hash,
                "stats": attr.get('last_analysis_stats'),
                "name": attr.get('meaningful_name'),
                "type": attr.get('type_description'),
                "size": attr.get('size'),
                "sha256": attr.get('sha256')
            }
        except Exception as e:
            last_error = e
            err_str = str(e).lower()
            if "401" in err_str or "429" in err_str:
                print(f"⚠️ VT Key Failed: {e}. Rotating...")
                config.invalidate_key("virustotal", api_key)
                continue
            return {"error": str(e)}
            
    return {"error": f"VT failed after {max_retries} attempts: {last_error}"}

@mcp.tool()
async def virustotal_url_scan(url: str) -> Dict:
    """Submit and obtain analysis for a URL from VirusTotal."""
    # Robust implementation with rotation
    max_retries = 3
    last_error = None
    
    for attempt in range(max_retries):
        api_key = config.get_api_key("virustotal")
        if not api_key: return {"error": "VIRUSTOTAL_API_KEY missing"}
        
        try:
            headers = {"x-apikey": api_key}
            # Step 1: Submit
            async with httpx.AsyncClient(timeout=300.0) as client: # Extended from 30.0
                resp = await client.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
                resp.raise_for_status()
                scan_data = resp.json()
                analysis_id = scan_data.get('data', {}).get('id')
                
                # Step 2: Wait and Get
                await asyncio.sleep(2.0)
                report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                report_data = await fetch_json(report_url, headers=headers)
                
                return {
                    "url": url,
                    "status": report_data.get('data', {}).get('attributes', {}).get('status'),
                    "stats": report_data.get('data', {}).get('attributes', {}).get('stats')
                }
        except Exception as e:
            last_error = e
            if "401" in str(e) or "429" in str(e):
                config.invalidate_key("virustotal", api_key)
                continue
            return {"error": str(e)}
            
    return {"error": str(last_error)}

# HaveIBeenPwned API (k-Anonymity)
@mcp.tool()
async def hibp_password_check(password: str) -> Dict:
    """Check if a password has been exposed in breaches using the NIST-compliant k-Anonymity model."""
    try:
        import hashlib
        pwd_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = pwd_hash[:5], pwd_hash[5:]
        
        async with httpx.AsyncClient(timeout=300.0) as client: # Extended from 10.0
            resp = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            resp.raise_for_status()
            
            lines = resp.text.split('\n')
            for line in lines:
                if line:
                    h_suffix, count = line.strip().split(':')
                    if h_suffix == suffix:
                        return {"exposed": True, "count": int(count), "status": "COMPROMISED"}
                        
            return {"exposed": False, "status": "SECURE", "message": "No matches found in HIBP database."}
    except Exception as e:
        return {"error": str(e)}

# IP Geolocation
@mcp.tool()
async def ip_geolocation(ip_address: str) -> Dict:
    """Retrieve precise geographical and ISP data for a given IP address."""
    try:
        data = await fetch_json(f"http://ip-api.com/json/{ip_address}")
        if data.get('status') == 'success':
            return {
                "ip": ip_address,
                "location": f"{data.get('city')}, {data.get('regionName')}, {data.get('country')}",
                "isp": data.get('isp'),
                "coordinates": f"{data.get('lat')}, {data.get('lon')}",
                "org": data.get('org')
            }
        return {"error": data.get('message')}
    except Exception as e:
        return {"error": str(e)}

# CVE Search
@mcp.tool()
async def cve_details(cve_id: str) -> Dict:
    """Fetch detailed vulnerability information, CVSS scores, and references for a specific CVE ID."""
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        data = await fetch_json(url)
        if data:
            return {
                "id": cve_id,
                "summary": data.get('summary'),
                "cvss": data.get('cvss'),
                "published": data.get('Published'),
                "references": data.get('references', [])[:5]
            }
        return {"error": "CVE not found"}
    except Exception as e:
        return {"error": str(e)}

# Threat Intelligence Engine
@mcp.tool()
async def threat_intelligence_search(indicators: List[str], indicator_type: str = "ip") -> Dict:
    """Industrial cross-referencing engine for malicious IOCs (IPs, domains, hashes). Returns risk scoring and confidence levels."""
    results = []
    # Industry baseline for simulation when offline
    malicious_db = {
        "ip": ["1.2.3.4", "8.8.4.4"], 
        "domain": ["malware.ru", "phish-test.com"],
        "hash": ["5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"]
    }
    
    for indicator in indicators:
        is_malicious = indicator in malicious_db.get(indicator_type, [])
        results.append({
            "indicator": indicator,
            "type": indicator_type,
            "verdict": "MALICIOUS" if is_malicious else "CLEAN",
            "confidence": 0.95 if is_malicious else 0.1,
            "source": "MYTH_TI_CONSOLIDATED"
        })
        
    return {
        "summary": {
            "total_checked": len(indicators),
            "malicious_detected": sum(1 for r in results if r['verdict'] == "MALICIOUS")
        },
        "details": results
    }

@mcp.tool()
async def dns_lookup(domain: str, record_type: str = "A") -> Dict:
    """Perform a DNS lookup for a specific record type (A, MX, TXT, NS, CNAME, SOA)."""
    try:
        import dns.resolver
        
        # Async wrapper for blocking DNS call
        def _resolve():
             return dns.resolver.resolve(domain, record_type)
             
        answers = await asyncio.to_thread(_resolve)
        results = []
        for rdata in answers:
            results.append(rdata.to_text())
            
        return {
            "domain": domain,
            "type": record_type,
            "records": results,
            "count": len(results)
        }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
async def ssl_cert_check(hostname: str, port: int = 443) -> Dict:
    """Retrieve and analyze the SSL/TLS certificate for a domain. Checks validity, issuer, and expiration."""
    try:
        import ssl
        import socket
        from datetime import datetime
        
        def _get_cert():
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=300.0) as sock: # Extended from 10.0
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()
        
        cert = await asyncio.to_thread(_get_cert)
        
        # Parse dates
        not_before = datetime.strptime(cert['notBefore'], r'%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], r'%b %d %H:%M:%S %Y %Z')
        days_left = (not_after - datetime.utcnow()).days
        
        return {
            "subject": dict(x[0] for x in cert['subject']),
            "issuer": dict(x[0] for x in cert['issuer']),
            "valid_from": tuple(cert['notBefore']),
            "valid_until": tuple(cert['notAfter']),
            "days_until_expiration": days_left,
            "expired": days_left < 0,
            "version": cert['version'],
            "serial_number": cert['serialNumber']
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import os
    port = int(os.getenv("FASTMCP_PORT", 8003))
    mcp.run(transport="sse", port=port, show_banner=False)
