import json
import asyncio
import re
import os
from datetime import datetime
from myth_config import load_dotenv
from langchain_core.tools import tool
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🔍 Network & Memory Forensics God Tier Tools
# ==============================================================================

@tool
async def pcap_sensitive_extractor(pcap_file: str) -> str:
    """
    Analyzes a PCAP or PCAPNG file using shell-safe TShark execution.
    Targets: FTP, Telnet, HTTP Basic Auth, SNMP.
    """
    try:
        if not os.path.exists(pcap_file):
             raise FileNotFoundError(f"PCAP not found: {pcap_file}")

        found = []
        
        # 1. Attempt High-Fidelity TShark (Deep Inspection)
        tshark_path = shutil.which("tshark")
        if tshark_path:
            try:
                # High-value fields: 
                # dns.qry.name (DNS queries)
                # tls.handshake.extensions_server_name (SNI)
                # http.user_agent (User-Agents)
                # ftp.request.arg / http.authbasic (Already targeted)
                proc = await asyncio.create_subprocess_exec(
                    tshark_path, "-r", pcap_file, "-Y", "ftp or http or snmp or dns or tls", 
                    "-T", "fields", 
                    "-e", "frame.number", 
                    "-e", "dns.qry.name", 
                    "-e", "tls.handshake.extensions_server_name", 
                    "-e", "http.user_agent", 
                    "-e", "ftp.request.arg", 
                    "-e", "http.authbasic",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                if stdout:
                    found = [l for l in stdout.decode(errors='ignore').splitlines() if l.strip()]
            except Exception: pass

        # 2. Universal Fallback: Strings-style extraction (Memory-Safe)
        if not found:
            CHUNK_SIZE = 1024 * 1024 # 1MB
            creds_pat = re.compile(br'(?:USER|PASS|AUTH|pwd|secret)[:\s=]([^\s]+)', re.IGNORECASE)
            with open(pcap_file, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk: break
                    raw_matches = creds_pat.findall(chunk)
                    for m in raw_matches:
                        found.append(m.decode(errors='ignore'))
                    if len(found) >= 50: break

        return format_industrial_result(
            "pcap_sensitive_extractor",
            "Review Results" if found else "Clean",
            confidence=0.8,
            impact="HIGH" if found else "LOW",
            raw_data={"findings": found[:50]},
            summary=f"Hardened PCAP extraction specialized for {os.path.basename(pcap_file)}. Results: {'Credentials found' if found else 'No obvious auth detected'}."
        )
    except FileNotFoundError as e:
        return format_industrial_result("pcap_sensitive_extractor", "File Error", error=str(e))
    except Exception as e:
        return format_industrial_result("pcap_sensitive_extractor", "Error", error=str(e))

@tool
async def advanced_string_classifier(buffer: str) -> str:
    """
    Analyzes a large string or binary blob and classifies extracted strings into high-value categories.
    Categories: Internal IPs, URLs, JWT Tokens, File Paths, and Potential Keys.
    """
    try:
        patterns = {
            "Internal_IP": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "URL": r"https?://[^\s/$.?#].[^\s]*",
            "JWT": r"ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
            "Windows_Path": r"[a-zA-Z]:\\[\\\w\s.]+",
            "Linux_Path": r"/(?:[\w.-]+/)+[\w.-]+",
            "Potential_Key": r"(?:key|secret|token|auth)[:=]\s*['\"]?[a-zA-Z0-9._-]{20,}"
        }

        classification = {}
        for cat, regex in patterns.items():
            matches = list(set(re.findall(regex, buffer, re.IGNORECASE)))
            if matches:
                classification[cat] = matches[:10] # Limit output density

        return format_industrial_result(
            "advanced_string_classifier",
            "Classification Complete",
            confidence=1.0,
            impact="MEDIUM" if classification else "LOW",
            raw_data={"classification": classification},
            summary=f"Identified {len(classification)} categories of sensitive strings within the provided blob."
        )
    except Exception as e:
        return format_industrial_result("advanced_string_classifier", "Error", error=str(e))
