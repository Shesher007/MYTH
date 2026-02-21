import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class SecretScanner:
    """Industrial-grade secret discovery for the Pentesting AI Agent"""

    # Common Patterns for High-Value Secrets
    PATTERNS = {
        "NVIDIA_API_KEY": r"nvapi-[a-zA-Z0-9_-]{60,}",
        "MISTRAL_API_KEY": r"[a-zA-Z0-9]{32,48}",  # Generic high-entropy, usually inside auth headers
        "OPENAI_API_KEY": r"sk-[a-zA-Z0-9]{48}",
        "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
        "AWS_SECRET_KEY": r"(?i)aws_secret_access_key\s*[:=]\s*[a-zA-Z0-9/+=]{40}",
        "GITHUB_TOKEN": r"ghp_[a-zA-Z0-9]{36}",
        "GENERIC_PASSWORD": r"(?i)(password|passwd|pwd|secret|token)\s*[:=]\s*['\"]?([a-zA-Z0-9@#$%^&*()_+=-]{8,})['\"]?",
        "PRIVATE_KEY": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
        "DATABASE_URL": r"(postgres|mysql|mongodb|redis|sqlite):\/\/[^:]+:[^@]+@[^/]+\/[^?\s]+",
    }

    def __init__(self):
        self.compiled_patterns = {
            name: re.compile(pat) for name, pat in self.PATTERNS.items()
        }

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        """Scan text and return findings with type and position"""
        findings = []
        if not text:
            return findings

        for name, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(text):
                # We don't return the secret itself in logs, just the type and location
                # But for the RAG entry, we might want to flag the doc.
                findings.append(
                    {
                        "type": name,
                        "start": match.start(),
                        "end": match.end(),
                        "snippet": text[
                            max(0, match.start() - 20) : min(
                                len(text), match.end() + 20
                            )
                        ].strip(),
                    }
                )

        return findings

    def flag_document(self, text: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Update metadata with secret findings"""
        findings = self.scan_text(text)
        if findings:
            metadata["contains_secrets"] = True
            metadata["secret_types"] = list(set(f["type"] for f in findings))
            metadata["secret_count"] = len(findings)
            # Add snippet of the first finding for quick reference
            metadata["secret_hint"] = findings[0]["snippet"]
        else:
            metadata["contains_secrets"] = False

        return metadata


def scan_for_secrets(text: str) -> List[Dict[str, Any]]:
    """
    Wrapper for SecretScanner to match RAG system interface.
    Instantiates a scanner and runs it on the provided text.
    """
    scanner = SecretScanner()
    return scanner.scan_text(text)
