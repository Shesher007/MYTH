#!/usr/bin/env python3
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from fastmcp import FastMCP

# Add parent to path for mcp_common
sys.path.append(str(Path(__file__).parent.parent))
from mcp_common import ironclad_guard, tool_exception_handler

# --- Server ---
mcp = FastMCP("Industrial Report Engine")


@mcp.tool()
@tool_exception_handler
@ironclad_guard
async def calculate_cvss_v3(vector: str) -> Dict:
    """Calculate CVSS v3.1 score from a vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)."""
    try:
        from cvss import CVSS3

        c = CVSS3(vector)
        return {"base_score": c.base_score, "severity": c.severity[0], "vector": vector}
    except ImportError:
        return {"error": "cvss library not installed", "note": "pip install cvss"}
    except Exception as e:
        return {"error": f"Invalid vector: {str(e)}"}


@mcp.tool()
@tool_exception_handler
@ironclad_guard
async def generate_markdown_report(title: str, findings: List[Dict]) -> str:
    """Generate a professionally formatted security finding report in Markdown."""
    report = f"# {title}\n\n"
    report += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    for i, f in enumerate(findings):
        report += f"## Finding {i + 1}: {f.get('name', 'Unnamed Finding')}\n"
        report += f"- **Severity**: {f.get('severity', 'Unknown')}\n"
        report += f"- **Target**: {f.get('target', 'N/A')}\n\n"
        report += (
            f"### Description\n{f.get('description', 'No description provided.')}\n\n"
        )
        if f.get("remediation"):
            report += f"### Remediation\n{f['remediation']}\n\n"
        report += "---\n\n"

    return report


if __name__ == "__main__":
    port = int(os.getenv("FASTMCP_PORT", 8206))
    mcp.run(transport="sse", port=port, show_banner=False)
