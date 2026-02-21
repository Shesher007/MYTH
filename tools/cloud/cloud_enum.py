import asyncio
import platform
from typing import Any

import aiohttp
from langchain_core.tools import tool

from tools.utilities.report import format_industrial_result

# ==============================================================================
# ☁️ Universal Cloud Enumerator (OS-Agnostic)
# ==============================================================================


@tool
async def universal_metadata_probe(timeout: Any = 2) -> str:
    """
    Safely probes for Cloud Metadata Services (AWS, Azure, GCP, DigitalOcean) to determine the hosting environment.
    Strategy: Attempts short-timeout connections to 169.254.169.254 (universal link-local address).
    Works on: Windows, Linux, macOS.
    """
    results = {}
    detected_provider = "Unknown (On-Prem / Local)"

    # 1. Probe Definitions
    # (method, header, path) -> We use these to fingerprint
    probes = {
        "AWS": {
            "url": "http://169.254.169.254/latest/meta-data/instance-id",
            "headers": {},  # AWS IMDSv1 (simple)
            "method": "GET",
        },
        "GCP": {
            "url": "http://169.254.169.254/computeMetadata/v1/project/project-id",
            "headers": {"Metadata-Flavor": "Google"},
            "method": "GET",
        },
        "Azure": {
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "headers": {"Metadata": "true"},
            "method": "GET",
        },
        "DigitalOcean": {
            "url": "http://169.254.169.254/metadata/v1.json",
            "headers": {},
            "method": "GET",
        },
        "ECS_Container": {
            # ECS_CONTAINER_METADATA_URI is env var typically, but we can verify via env check first
            "env": "ECS_CONTAINER_METADATA_URI"
        },
    }

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as session:
            tasks = []

            # Helper to fetch
            async def check_cloud(name, config):
                if "env" in config:
                    # Check Env Var
                    import os

                    if os.environ.get(config["env"]):
                        return (name, True, "Environment Variable Found")
                    return (name, False, None)

                try:
                    async with session.get(
                        config["url"], headers=config["headers"]
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            return (name, True, text.strip())
                except Exception:
                    pass
                return (name, False, None)

            # Launch Probes
            for provider, config in probes.items():
                tasks.append(check_cloud(provider, config))

            responses = await asyncio.gather(*tasks)

            # Analyze Responses
            for provider, success, data in responses:
                if success:
                    detected_provider = provider
                    results[provider] = data
                    # Special check: If we found one, we usually stop, but multiple could exist (e.g. k8s on aws)

            # Additional Context
            results["os"] = f"{platform.system()} {platform.release()}"
            results["machine"] = platform.machine()

            impact = (
                "HIGH" if detected_provider != "Unknown (On-Prem / Local)" else "LOW"
            )

            return format_industrial_result(
                "universal_metadata_probe",
                "Probe Complete",
                confidence=1.0,
                impact=impact,
                raw_data=results,
                summary=f"Cloud Enumeration finished. Environment: {detected_provider}.",
            )

    except Exception as e:
        return format_industrial_result(
            "universal_metadata_probe", "Error", error=str(e)
        )
