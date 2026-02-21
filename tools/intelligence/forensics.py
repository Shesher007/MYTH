"""
Intel Forensics Tool
====================
Provides deep-level inspection of internet assets (URLs) for forensic analysis.
"""

import httpx
from langchain_core.tools import tool


@tool
async def inspect_internet_asset(url: str) -> str:
    """
    Performs forensic analysis on a remote URL.
    Extracts headers, MIME type, first-page text, and generates a Hex dump of the byte stream.
    Stand-alone implementation for deep inspection without execution.
    """
    try:
        # Industrial Pass: Standalone forensics using httpx
        async with httpx.AsyncClient(
            timeout=30.0, verify=False, follow_redirects=True
        ) as client:
            resp = await client.get(url)

            # 1. Header Analysis
            headers = dict(resp.headers)
            mime_type = headers.get("content-type", "unknown/unknown").split(";")[0]
            size = len(resp.content)

            # 2. Binary vs Text Detection
            is_binary = False
            text_preview = ""
            try:
                text_content = resp.content.decode("utf-8")
                text_preview = text_content[:1000]  # First 1KB
            except UnicodeDecodeError:
                is_binary = True
                text_preview = "BINARY_DATA_DETECTED"

            # 3. Hex Dump (First 128 bytes)
            hex_dump = []
            for i in range(0, min(128, size), 16):
                chunk = resp.content[i : i + 16]
                hex_line = " ".join(f"{b:02x}" for b in chunk)
                ascii_line = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                hex_dump.append(f"{i:04x}  {hex_line:<48}  |{ascii_line}|")

            if size > 128:
                hex_dump.append("... (truncated)")

            # Format Report
            summary = [
                f"🛡️ FORENSIC_REPORT: {url}",
                f"STATUS: {resp.status_code} {resp.reason_phrase}",
                f"MIME_TYPE: {mime_type}",
                f"SIZE: {size} bytes",
                f"ENCODING: {'BINARY' if is_binary else 'UTF-8'}",
                "-" * 40,
                "HEADERS:",
            ]
            for k, v in list(headers.items())[:10]:  # Top 10 headers
                summary.append(f"  {k}: {v}")

            summary.append("-" * 40)
            if not is_binary:
                summary.append("TEXT_SNIPPET (First 1KB):")
                summary.append(text_preview)
            else:
                summary.append("HEX_DUMP (First 128 bytes):")
                summary.append("\n".join(hex_dump))

            return "\n".join(summary)

    except Exception as e:
        return f"❌ Forensic Analysis Failed: {str(e)}"
