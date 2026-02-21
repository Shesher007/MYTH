import asyncio
import socket
import ssl
from typing import List, Optional

import httpx
from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🎯 Wordlists & Signatures (Consolidated)
# ==============================================================================

COMMON_WEB_PATHS = [
    "admin/",
    "administrator/",
    "test/",
    "dev/",
    "config/",
    ".git/",
    "robots.txt",
    "sitemap.xml",
    "phpinfo.php",
    ".env",
    "api/v1/",
    "backup/",
    "wp-admin/",
    "license.txt",
]

TECHNOLOGY_SIGS = {
    "WordPress": ["wp-login.php", "wp-content/", 'generator content="WordPress'],
    "Joomla": ["/administrator/index.php", 'generator content="Joomla'],
    "Drupal": ["/core/install.php", "Drupal.settings"],
    "NGINX": ["Server: nginx"],
    "Apache": ["Server: Apache"],
    "Cloudflare": ["Server: cloudflare", "__cf_"],
    "React/SPA": ['<div id="root">', "manifest.json"],
}

# ==============================================================================
# 🚀 Network Scanning Tools
# ==============================================================================


@tool
async def port_scan(
    target: str,
    ports: str = "1-1000",
    max_concurrency: int = 100,
    aggressiveness: int = 3,
) -> str:
    """
    Perform high-performance asynchronous TCP port scanning on a target host.
    Includes T1-T5 aggressiveness levels for evasion/speed control.
    """
    try:
        # Aggressiveness logic (T1-T5)
        # T1: stealthy, T3: balanced, T5: insane speed
        timeout_map = {1: 3.0, 2: 2.0, 3: 1.0, 4: 0.5, 5: 0.2}
        timeout = timeout_map.get(aggressiveness, 1.0)

        # Parse port range
        if "-" in ports:
            start_port, end_port = map(int, ports.split("-"))
            port_list = range(start_port, end_port + 1)
        elif "," in ports:
            port_list = [int(p) for p in ports.split(",")]
        else:
            port_list = [int(ports)]

        semaphore = asyncio.Semaphore(max_concurrency)

        async def scan_port(port):
            async with semaphore:
                try:
                    conn = asyncio.open_connection(target, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                    writer.close()
                    await writer.wait_closed()
                    return port
                except Exception:
                    return None

        tasks = [scan_port(port) for port in port_list]
        results = await asyncio.gather(*tasks)
        open_ports = [p for p in results if p is not None]

        return format_industrial_result(
            "port_scan",
            "Success",
            confidence=1.0,
            impact="MEDIUM",
            raw_data={
                "target": target,
                "open": sorted(open_ports),
                "scanned": len(port_list),
                "aggressiveness": aggressiveness,
            },
            summary=f"Discovered {len(open_ports)} open ports on {target} at T{aggressiveness} speed.",
        )
    except Exception as e:
        return format_industrial_result("port_scan", "Error", error=str(e))


@tool
async def service_fingerprint(target: str, port: int) -> str:
    """
    Fingerprint services running on open ports using asynchronous I/O.
    """
    try:
        services = {
            21: "FTP",
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
        }
        banner = "No banner"
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=3.0)
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=1.0)
            banner = data.decode("utf-8", errors="ignore").strip()
            writer.close()
        except Exception:
            pass

        return format_industrial_result(
            "service_fingerprint",
            "Fingerprinted",
            confidence=0.9,
            impact="Low",
            raw_data={
                "target": target,
                "port": port,
                "service": services.get(port, "Unknown"),
                "banner": banner,
            },
            summary=f"Port {port} identified as {services.get(port, 'Unknown')} service.",
        )
    except Exception as e:
        return format_industrial_result("service_fingerprint", "Error", error=str(e))


# ==============================================================================
# 🎯 Web Reconnaissance Tools
# ==============================================================================


@tool
async def directory_bruteforce(
    url: str, wordlist: Optional[List[str]] = None, max_concurrency: int = 50
) -> str:
    """
    High-performance asynchronous directory discovery.
    """
    try:
        url = url.rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        paths = wordlist if wordlist else COMMON_WEB_PATHS
        found = []
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            semaphore = asyncio.Semaphore(max_concurrency)

            async def check(path):
                async with semaphore:
                    try:
                        resp = await client.head(f"{url}/{path.lstrip('/')}")
                        if resp.status_code < 400:
                            return {"path": path, "status": resp.status_code}
                    except Exception:
                        return None

            tasks = [check(p) for p in paths]
            results = await asyncio.gather(*tasks)
            found = [r for r in results if r]

        return format_industrial_result(
            "directory_bruteforce",
            "Complete",
            confidence=1.0,
            impact="MEDIUM",
            raw_data={"url": url, "found": found, "scanned": len(paths)},
            summary=f"Discovered {len(found)} accessible directories on {url}.",
        )
    except Exception as e:
        return format_industrial_result("directory_bruteforce", "Error", error=str(e))


@tool
async def web_technology_fingerprint(url: str) -> str:
    """
    Extracts technologies (CMS, JS libraries, Servers) from a web page.
    """
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.get(url)
            text = resp.text
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            techs = {}
            for tech, sigs in TECHNOLOGY_SIGS.items():
                for sig in sigs:
                    if sig.lower() in text.lower() or any(
                        sig.lower() in v for v in headers.values()
                    ):
                        techs[tech] = "Detected"
                        break
        return format_industrial_result(
            "web_technology_fingerprint",
            "Identified",
            confidence=0.85,
            impact="Low",
            raw_data={"url": url, "technologies": techs},
            summary=f"Identified {len(techs)} technologies on the target page.",
        )
    except Exception as e:
        return format_industrial_result(
            "web_technology_fingerprint", "Error", error=str(e)
        )


@tool
async def service_config_audit(target_url: str) -> str:
    """
    Performs a real configuration audit of a web service.
    """
    try:
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.get(target_url)
            missing = [
                h
                for h in [
                    "Content-Security-Policy",
                    "Strict-Transport-Security",
                    "X-Frame-Options",
                ]
                if h not in resp.headers
            ]

        return format_industrial_result(
            "service_config_audit",
            "Vulnerable" if missing else "Secure",
            confidence=0.9,
            impact="MEDIUM" if missing else "Low",
            raw_data={
                "url": target_url,
                "missing_headers": missing,
                "server": resp.headers.get("Server"),
            },
            summary=f"Configuration audit for {target_url} found {len(missing)} missing security headers.",
        )
    except Exception as e:
        return format_industrial_result("service_config_audit", "Error", error=str(e))


@tool
async def banner_grabbing(target: str, port: int = 80) -> str:
    """
    Retrieves the service's banner via HTTP request.
    """
    try:
        url = f"http://{target}:{port}" if port == 80 else f"https://{target}:{port}"
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            resp = await client.head(url)

        return format_industrial_result(
            "banner_grabbing",
            "Success",
            confidence=1.0,
            impact="Low",
            raw_data={
                "target": target,
                "port": port,
                "server": resp.headers.get("Server"),
                "x_powered_by": resp.headers.get("X-Powered-By"),
            },
            summary=f"Retrieved banner for {target}:{port}. Server: {resp.headers.get('Server', 'Unknown')}.",
        )
    except Exception as e:
        return format_industrial_result("banner_grabbing", "Error", error=str(e))


@tool
async def robots_sitemap_analysis(url: str) -> str:
    """
    Retrieves the robots.txt and sitemap.xml files from the target.
    """
    try:
        base_url = url.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = "https://" + base_url
        results = {}
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            for file in ["robots.txt", "sitemap.xml"]:
                try:
                    r = await client.get(f"{base_url}/{file}")
                    if r.status_code == 200:
                        results[file] = "Found"
                    else:
                        results[file] = f"Missing ({r.status_code})"
                except Exception:
                    results[file] = "Error"

        return format_industrial_result(
            "robots_sitemap_analysis",
            "Complete",
            confidence=1.0,
            impact="Low",
            raw_data={"url": url, "results": results},
            summary=f"Analysis of robots.txt and sitemap.xml for {url} complete.",
        )
    except Exception as e:
        return format_industrial_result(
            "robots_sitemap_analysis", "Error", error=str(e)
        )


@tool
async def http_header_analysis(url: str) -> str:
    """
    Analyze HTTP headers for security configurations asynchronously.
    """
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        async with httpx.AsyncClient(
            timeout=30.0, follow_redirects=True, verify=False
        ) as client:
            response = await client.get(url)
            headers = dict(response.headers)

            return format_industrial_result(
                "http_header_analysis",
                "Success",
                confidence=1.0,
                impact="LOW",
                raw_data={
                    "url": url,
                    "status": response.status_code,
                    "headers": headers,
                },
                summary=f"Analyzed {len(headers)} headers for {url}. Status: {response.status_code}.",
            )
    except Exception as e:
        return format_industrial_result("http_header_analysis", "Error", error=str(e))


@tool
async def ssl_tls_scan(hostname: str) -> str:
    """
    Scan SSL/TLS configuration for security issues.
    """
    try:
        context = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def do_scan():
            with socket.create_connection((hostname, 443), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                    }

        cert_info = await loop.run_in_executor(None, do_scan)
        return format_industrial_result(
            "ssl_tls_scan",
            "Scanned",
            confidence=1.0,
            impact="Low",
            raw_data={"hostname": hostname, "cert": cert_info},
            summary=f"SSL/TLS scan for {hostname} complete. Protocol: {cert_info.get('version')}.",
        )
    except Exception as e:
        return format_industrial_result("ssl_tls_scan", "Error", error=str(e))


@tool
async def adaptive_service_prober(target: str, port: int) -> str:
    """
    Dynamically adjusts probing techniques to identify hidden services.
    Sends specific probes (HTTP, SSH, FTP, SMTP) based on initial connection behavior.
    """
    try:
        identified_service = "Unknown"
        raw_banner = ""

        # 1. TCP Connect & Banner Grab
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=3.0)

            # Send nothing first, waiting for server greeting (SSH/SMTP/FTP)
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                raw_banner = data.decode(errors="ignore").strip()
            except asyncio.TimeoutError:
                # If no greeting, likely HTTP or Client-First protocol. Send HTTP GET.
                writer.write(
                    b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
                )
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    raw_banner = data.decode(errors="ignore").strip()
                except Exception:
                    pass

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            return format_industrial_result(
                "adaptive_service_prober", "Failed", error=str(e)
            )

        # 2. Analysis
        if "SSH" in raw_banner:
            identified_service = "SSH"
        elif "HTTP" in raw_banner or "html" in raw_banner.lower():
            identified_service = "HTTP/Web"
        elif "FTP" in raw_banner:
            identified_service = "FTP"
        elif "SMTP" in raw_banner or "220" in raw_banner:
            identified_service = "SMTP"
        elif "mysql" in raw_banner.lower():
            identified_service = "MySQL"
        elif raw_banner:
            identified_service = "Custom/Unknown Service"
        else:
            identified_service = "Silent/Filtered"

        return format_industrial_result(
            "adaptive_service_prober",
            "Probing Complete",
            confidence=0.9,
            impact="MEDIUM",
            raw_data={
                "target": target,
                "port": port,
                "raw_banner": raw_banner,
                "identified_service": identified_service,
            },
            summary=f"Adaptive probing for {target}:{port} identified: {identified_service}.",
        )
    except Exception as e:
        return format_industrial_result(
            "adaptive_service_prober", "Error", error=str(e)
        )


@tool
async def recon_genesis_monitor() -> str:
    """
    Validates network environment for scanning (Connectivity, Permissions).
    """
    try:
        import os
        import socket

        checks = {}

        # 1. Connectivity
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=2)
            checks["Internet"] = "ONLINE"
        except Exception:
            checks["Internet"] = "OFFLINE"

        # 2. Permissions (Simulated 'Admin' check on Windows usually requires ctypes, on Linux os.geteuid)
        try:
            is_admin = False
            if os.name == "nt":
                import ctypes

                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                is_admin = os.geteuid() == 0
            checks["Privileges"] = (
                "ADMIN/ROOT" if is_admin else "USER (Limited active scanning)"
            )
        except Exception:
            checks["Privileges"] = "Unknown"

        return format_industrial_result(
            "recon_genesis_monitor",
            "Environment Validated",
            confidence=1.0,
            impact="LOW",
            raw_data=checks,
            summary=f"Genesis Monitor: Internet {checks['Internet']}, Privileges {checks['Privileges']}.",
        )
    except Exception as e:
        return format_industrial_result("recon_genesis_monitor", "Error", error=str(e))


@tool
async def dynamic_probe_mutator(target_url: str, base_payload: str = "") -> str:
    """
    Generates mutated HTTP/TCP probe payloads to bypass filters.
    """
    try:
        from urllib.parse import quote

        mutations = []
        base = base_payload if base_payload else "<script>alert(1)</script>"

        # 1. URL Encoding
        mutations.append({"type": "URL Encoded", "payload": quote(base)})

        # 2. Double URL Encoding
        mutations.append({"type": "Double URL Encoded", "payload": quote(quote(base))})

        # 3. Case Variation (Random)
        mutations.append(
            {
                "type": "Case Variation",
                "payload": base.replace("script", "ScRiPt").replace("alert", "AlErT"),
            }
        )

        # 4. Null Byte
        mutations.append({"type": "Null Byte Inj", "payload": base + "%00"})

        return format_industrial_result(
            "dynamic_probe_mutator",
            "Mutation Complete",
            confidence=1.0,
            impact="MEDIUM",
            raw_data={"base": base, "mutations": mutations},
            summary=f"Generated {len(mutations)} active mutations for bypass attempts.",
        )
    except Exception as e:
        return format_industrial_result("dynamic_probe_mutator", "Error", error=str(e))


@tool
async def apex_evasion_profiler(target_url: str) -> str:
    """
    Active WAF Detection: Sends benign vs suspicious requests to detect blocking.
    """
    try:
        if not target_url.startswith("http"):
            target_url = "http://" + target_url

        evasion_profile = {"detected_protection": "None", "blocking_behavior": "None"}

        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            # 1. Baseline Request
            r_base = await client.get(target_url)

            # 2. Suspicious Request (SQLi-like)
            r_suspicious = await client.get(f"{target_url}?id=1' OR 1=1")

            if (
                r_suspicious.status_code in [403, 406, 501]
                and r_base.status_code == 200
            ):
                evasion_profile["blocking_behavior"] = (
                    f"Blocks Suspicious (HTTP {r_suspicious.status_code})"
                )

                # Identify via Headers
                server = r_suspicious.headers.get("Server", "").lower()
                if "cloudflare" in server:
                    evasion_profile["detected_protection"] = "Cloudflare"
                elif "akamai" in server:
                    evasion_profile["detected_protection"] = "Akamai"
                elif "aws" in server:
                    evasion_profile["detected_protection"] = "AWS WAF"
                else:
                    evasion_profile["detected_protection"] = "Generic WAF"
            else:
                evasion_profile["blocking_behavior"] = "Permissive (No Block Detected)"

        return format_industrial_result(
            "apex_evasion_profiler",
            "Evasion Profile Generated",
            confidence=0.9,
            impact="HIGH"
            if evasion_profile["detected_protection"] != "None"
            else "LOW",
            raw_data={"target": target_url, "profile": evasion_profile},
            summary=f"Evasion profiling complete. Protection: {evasion_profile['detected_protection']} behavior: {evasion_profile['blocking_behavior']}.",
        )
    except Exception as e:
        return format_industrial_result("apex_evasion_profiler", "Error", error=str(e))
