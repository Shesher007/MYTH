import asyncio
import math
import os
import re

from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🏗️ IaC & CI/CD Security Frontier Tools
# ==============================================================================


def should_skip(path: str) -> bool:
    """Helper to skip noisy directories."""
    skip_dirs = {
        ".git",
        "node_modules",
        "__pycache__",
        "venv",
        ".venv",
        "dist",
        "build",
    }
    for part in path.split(os.sep):
        if part in skip_dirs:
            return True
    return False


async def scan_single_file(fpath: str) -> list:
    """Helper to scan a single file for misconfigurations concurrently."""
    findings = []
    try:
        # Offload file I/O to thread
        content = await asyncio.to_thread(
            lambda: open(fpath, "r", errors="ignore").read()
        )

        # Context-Aware Checks
        # 1. Terraform Public S3
        if fpath.endswith(".tf") and re.search(r'acl\s*=\s*"public-read"', content):
            findings.append(
                {"file": fpath, "vector": "Public S3 Bucket", "severity": "HIGH"}
            )

        # 2. General Open Ingress (SG/Firewalls)
        if re.search(
            r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', content
        ) or re.search(r"allow\s+.*\s+0\.0\.0\.0/0", content):
            findings.append(
                {
                    "file": fpath,
                    "vector": "Permissive Security Group",
                    "severity": "HIGH",
                }
            )

        # 3. Docker Root User
        if fpath.lower().endswith("dockerfile") and "USER root" in content:
            findings.append(
                {
                    "file": fpath,
                    "vector": "Running as Root (Docker)",
                    "severity": "MEDIUM",
                }
            )

        # 4. Kubernetes Security Context (Advanced)
        if fpath.endswith((".yaml", ".yml")) and "kind: Pod" in content:
            if "privileged: true" in content:
                findings.append(
                    {
                        "file": fpath,
                        "vector": "Privileged K8s Container",
                        "severity": "CRITICAL",
                    }
                )
            if "readOnlyRootFilesystem: false" in content:
                findings.append(
                    {
                        "file": fpath,
                        "vector": "Writable Root FS (K8s)",
                        "severity": "MEDIUM",
                    }
                )

        # 5. CloudFormation Unencrypted Volumes
        if fpath.endswith((".json", ".template")) and '"Encrypted": "false"' in content:
            findings.append(
                {
                    "file": fpath,
                    "vector": "Unencrypted EBS/RDS (CFN)",
                    "severity": "MEDIUM",
                }
            )

    except Exception:
        pass
    return findings


@tool
async def iac_misconfig_scanner(file_path: str) -> str:
    """
    Analyzes Infrastructure-as-Code for misconfigurations with parallel processing and size guards.
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Path not found: {file_path}")

        files_to_scan = []
        MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB limit

        if os.path.isdir(file_path):
            for root, _, files in os.walk(file_path):
                if should_skip(root):
                    continue
                for file in files:
                    fpath = os.path.join(root, file)
                    if file.lower().endswith(
                        (".t", ".json", ".yaml", ".yml", ".dockerfile")
                    ):
                        try:
                            if os.path.getsize(fpath) < MAX_FILE_SIZE:
                                files_to_scan.append(fpath)
                        except Exception:
                            pass
        else:
            if os.path.getsize(file_path) < MAX_FILE_SIZE:
                files_to_scan.append(file_path)

        tasks = [scan_single_file(f) for f in files_to_scan]
        results = await asyncio.gather(*tasks)
        all_findings = [r for sub in results for r in sub]

        return format_industrial_result(
            "iac_misconfig_scanner",
            "Scan Complete",
            impact="HIGH" if all_findings else "LOW",
            raw_data={"scanned": len(files_to_scan), "violations": len(all_findings)},
            summary=f"Parallel IaC scan finished. Analyzed {len(files_to_scan)} files. Found {len(all_findings)} issues.",
        )
    except Exception as e:
        return format_industrial_result("iac_misconfig_scanner", "Error", error=str(e))


@tool
async def cicd_pipeline_audit(pipeline_file: str) -> str:
    """
    Analyzes CI/CD pipeline configurations (GitHub Actions, GitLab CI/CD) for risky patterns.
    Targets: Secret leaks (echo), risky permissions, insecure runners.
    """
    try:
        if not os.path.exists(pipeline_file):
            return format_industrial_result(
                "cicd_pipeline_audit", "Error", error="Pipeline file not found"
            )

        with open(pipeline_file, "r", errors="ignore") as f:
            content = f.read()

        findings = []
        # Risky 1: Echoing secrets
        if re.search(r"echo\s+\$[\{]?SECRET", content, re.IGNORECASE):
            findings.append(
                {"vector": "Secret Leakage in Logs", "severity": "CRITICAL"}
            )

        # Risky 2: Pull request triggers with write access
        if (
            "pull_request:" in content
            and "permissions:" in content
            and "write" in content.lower()
        ):
            findings.append({"vector": "Risky PR Permissions", "severity": "HIGH"})

        # Risky 3: Script Injection (eval variables)
        if re.search(r'eval\s+"\$.+"', content):
            findings.append({"vector": "Potentially Unsafe Eval", "severity": "MEDIUM"})

        return format_industrial_result(
            "cicd_pipeline_audit",
            "Audit Complete",
            confidence=1.0,
            impact="HIGH" if findings else "LOW",
            raw_data={"file": pipeline_file, "findings": findings},
            summary=f"CI/CD audit for {pipeline_file} complete. {len(findings)} risky patterns identifies.",
        )
    except Exception as e:
        return format_industrial_result("cicd_pipeline_audit", "Error", error=str(e))


def _calculate_entropy(text: str) -> float:
    """Optimized entropy calculation (v2)."""
    if not text:
        return 0.0
    from collections import Counter

    counts = Counter(text)
    total = len(text)
    return -sum(
        (count / total) * math.log(count / total, 2) for count in counts.values()
    )


async def check_file_secrets(fpath: str) -> list:
    """Scans a file for secrets using regex and threaded entropy."""
    findings = []
    try:
        # Offload I/O
        content = await asyncio.to_thread(
            lambda: open(fpath, "r", errors="ignore").read()
        )

        # 1. Regex High Confidence
        patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
            "Private Key Block": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
            "GCP Service Account": r"\"type\":\s*\"service_account\"",
            "Azure Connection String": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;",
            "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        }

        for name, pat in patterns.items():
            if re.search(pat, content):
                findings.append({"file": fpath, "type": name, "confidence": "HIGH"})

        # 2. Entropy Check (CPU bound -> Offload)
        candidates = re.findall(
            r'(?:key|token|secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
            content,
            re.IGNORECASE,
        )
        for c in candidates:
            # Run math in thread pool
            entropy = await asyncio.to_thread(_calculate_entropy, c)

            if entropy > 4.5:
                findings.append(
                    {
                        "file": fpath,
                        "type": "High Entropy Credential",
                        "snippet": c[:4] + "...",
                    }
                )

    except Exception:
        pass
    return findings


@tool
async def secrets_in_depth(file_path: str) -> str:
    """
    In-depth secret scanning with optimized entropy and file size protection.
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Path not found: {file_path}")

        files_to_scan = []
        MAX_SIZE = 5 * 1024 * 1024
        if os.path.isdir(file_path):
            for r, _, fs in os.walk(file_path):
                if should_skip(r):
                    continue
                for f in fs:
                    fp = os.path.join(r, f)
                    try:
                        if os.path.getsize(fp) < MAX_SIZE:
                            files_to_scan.append(fp)
                    except Exception:
                        pass
        else:
            if os.path.getsize(file_path) < MAX_SIZE:
                files_to_scan.append(file_path)

        tasks = [check_file_secrets(f) for f in files_to_scan]
        results = await asyncio.gather(*tasks)
        all_findings = [r for sub in results for r in sub]

        return format_industrial_result(
            "secrets_in_depth",
            "Deep Scan Complete",
            confidence=0.95,
            impact="CRITICAL" if all_findings else "LOW",
            raw_data={"secrets_found": len(all_findings)},
            summary=f"Secrets-in-depth scan finished. Identified {len(all_findings)} potential credentials with size guards.",
        )
    except Exception as e:
        return format_industrial_result("secrets_in_depth", "Error", error=str(e))
