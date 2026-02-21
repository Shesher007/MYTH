import math
import os
import re

from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 📟 Firmware & IoT Auditing RE Tools
# ==============================================================================


@tool
async def firmware_magic_identifier(file_path: str) -> str:
    """
    Identifies firmware file formats and partitions within a raw binary blob.
    Targets: U-Boot, SquashFS, CramFS, JFFS2, and common bootloaders.
    """
    try:
        if not os.path.exists(file_path):
            return format_industrial_result(
                "firmware_magic_identifier", "Error", error="File not found"
            )

        magic_signatures = {
            "U-Boot Image": b"\x27\x05\x19\x56",
            "SquashFS (LE)": b"hsqs",
            "SquashFS (BE)": b"sqsh",
            "CramFS": b"\x45\x3d\xcd\x28",
            "JFFS2": b"\x19\x85",
            "LZMA Compressed": b"\x5d\x00\x00\x00",
            "GZIP Compressed": b"\x1f\x8b\x08",
        }

        with open(file_path, "rb") as f:
            data = f.read()

        findings = []
        for name, sig in magic_signatures.items():
            for match in re.finditer(re.escape(sig), data):
                findings.append({"type": name, "offset": hex(match.start())})

        # Real structural verification via LIEF
        try:
            import lief

            binary = lief.parse(file_path)
            if binary:
                findings.append(
                    {
                        "type": "LIEF_Verified_Structure",
                        "format": str(binary.format),
                        "is_executable": binary.is_pie or binary.has_nx,
                    }
                )
            engine = "Hybrid (Grep + LIEF)"
        except (ImportError, Exception):
            engine = "Marker-based Grep"

        return format_industrial_result(
            "firmware_magic_identifier",
            "Analysis Complete",
            confidence=1.0 if engine == "Hybrid (Grep + LIEF)" else 0.8,
            impact="MEDIUM",
            raw_data={
                "file": file_path,
                "identified_signatures": findings,
                "engine": engine,
            },
            summary=f"Firmware identification via {engine} finished. Identified {len(findings)} technical sections.",
        )
    except Exception as e:
        return format_industrial_result(
            "firmware_magic_identifier", "Error", error=str(e)
        )


@tool
async def hardcoded_secret_hunter(file_path: str) -> str:
    """
    A specialized secret hunter for firmware images and raw binary blobs.
    Searches for Private Keys, SSL Certificates, SSH Keys, and typical API token formats.
    """
    try:
        if not os.path.exists(file_path):
            return format_industrial_result(
                "hardcoded_secret_hunter", "Error", error="File not found"
            )

        # Industry-grade entropy-based secret hunting
        def calculate_entropy(chunk):
            if not chunk:
                return 0
            entropy = 0
            for x in range(256):
                p_x = chunk.count(
                    chr(x).encode() if isinstance(chunk, bytes) else chr(x)
                ) / len(chunk)
                if p_x > 0:
                    entropy += -p_x * math.log(p_x, 2)
            return entropy

        secret_patterns = {
            "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
            "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
            "SSL Certificate": r"-----BEGIN CERTIFICATE-----",
            "Amazon AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Generic API Key": r"(?:api|secret|token|pass)[:=]\s*['\"]?[a-zA-Z0-9._-]{20,}",
        }

        with open(file_path, "rb") as f:
            data = f.read()

        findings = []
        # Pattern-based search
        for name, pattern in secret_patterns.items():
            regex = re.compile(pattern.encode("ascii"), re.IGNORECASE)
            matches = list(set(regex.findall(data)))
            if matches:
                findings.append(
                    {
                        "type": name,
                        "count": len(matches),
                        "examples": [
                            m.decode("ascii", errors="ignore")[:40] for m in matches[:3]
                        ],
                    }
                )

        # Entropy-based search (Identify high-entropy strings likely to be keys)
        # Scan for printable strings > 20 chars with entropy > 4.5
        potential_keys = re.findall(rb"[a-zA-Z0-9+/=]{20,}", data)
        for pk in potential_keys:
            ent = calculate_entropy(pk)
            if ent > 4.5:
                findings.append(
                    {
                        "type": "High-Entropy String (Potential Key)",
                        "entropy": round(ent, 2),
                        "preview": pk[:40].decode("ascii", errors="ignore"),
                    }
                )

        # Calculate score based on findings
        score = 0
        if findings:
            score += 5  # Base score for any findings
            for finding in findings:
                # Example scoring logic, adjust as needed
                if finding.get("type") in ["RSA Private Key", "OpenSSH Private Key"]:
                    score += 5
                elif finding.get("type") == "Amazon AWS Access Key":
                    score += 4
                elif finding.get("type") == "High-Entropy String (Potential Key)":
                    score += 2

        # Determine impact and confidence based on score
        impact = "LOW"
        confidence = 0.7
        if score >= 10:
            impact = "CRITICAL"
            confidence = 0.99
        elif score >= 5:
            impact = "HIGH"
            confidence = 0.95
        elif score > 0:
            impact = "MEDIUM"
            confidence = 0.85

        return format_industrial_result(
            "hardcoded_secret_hunter",
            "Secrets Found" if findings else "Secure",
            confidence=confidence,
            impact=impact,
            raw_data={"findings": findings[:20]},  # Cap for brevity
            summary=f"Specialized entropy-aware secret hunt in {os.path.basename(file_path)} complete. Found {len(findings)} categories of potential secrets.",
        )
    except Exception as e:
        return format_industrial_result(
            "hardcoded_secret_hunter", "Error", error=str(e)
        )


@tool
async def firmware_iot_vulnerability_scanner(file_path: str) -> str:
    """
    Targeted detection of IoT-specific flaws such as default credentials and insecure backdoors.
    Industry-grade for automated IoT security auditing and discovery.
    """
    try:
        if not os.path.exists(file_path):
            return format_industrial_result(
                "firmware_iot_vulnerability_scanner", "Error", error="File not found"
            )

        # Industry-grade IoT vulnerability scanning with LIEF section mapping
        try:
            import lief

            binary = lief.parse(file_path)

            with open(file_path, "rb") as f:
                data = f.read()

            iot_flaws = {
                "Hardcoded_Credentials": rb"(?:admin|root|password|123456)[:=]\s*['\"]?[a-zA-Z0-9._-]{5,}",
                "Telnet_Backdoor": rb"telnetd|/bin/telnet",
                "Insecure_Web_Interface": rb"httpd|goahead|lighttpd",
                "Hidden_Shell": b"/bin/sh -i",
                "Debug_Artifacts": b"gdbserver|strace|tcpdump",
            }

            findings = []
            for name, pattern in iot_flaws.items():
                for match in re.finditer(pattern, data):
                    offset = match.start()
                    # Technical verification: Check which section this string resides in
                    section = binary.section_from_offset(offset)
                    section_name = section.name if section else "Unknown"

                    findings.append(
                        {
                            "vulnerability": name,
                            "offset": hex(offset),
                            "section": section_name,
                            "risk": "CRITICAL"
                            if section_name in [".text", ".rodata"]
                            else "HIGH",
                        }
                    )

            engine = "LIEF String-Section Correlator"
            confidence = 0.95
        except (ImportError, Exception):
            # Fallback to pure pattern matching
            with open(file_path, "rb") as f:
                data = f.read()
            iot_flaws = {
                "Hardcoded_Credentials": rb"(?:admin|root|password|123456)[:=]\s*['\"]?[a-zA-Z0-9._-]{5,}",
                "Telnet_Backdoor": rb"telnetd|/bin/telnet",
            }
            findings = []
            for name, pattern in iot_flaws.items():
                if pattern in data:
                    findings.append(
                        {"vulnerability": name, "occurrences": data.count(pattern)}
                    )
            engine = "Pattern Distribution Fallback"
            confidence = 0.7

        return format_industrial_result(
            "firmware_iot_vulnerability_scanner",
            "Scan Complete",
            confidence=confidence,
            impact="HIGH" if findings else "LOW",
            raw_data={"file": file_path, "findings": findings, "engine": engine},
            summary=f"IoT firmware vulnerability scan via {engine} finished. Identified {len(findings)} potential security flaws across binary sections.",
        )
    except Exception as e:
        return format_industrial_result(
            "firmware_iot_vulnerability_scanner", "Error", error=str(e)
        )
