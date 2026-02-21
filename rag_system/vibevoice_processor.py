"""
VibeVoice TTS Processor - Google Gemini Voice Implementation
=============================================================
High-performance, cloud-based speech synthesis using gemini-2.5-flash-live.
Specifically optimized for ultra-low latency and human-like prosody.
"""

import asyncio
import base64
import logging
import random
import re
from typing import Any, AsyncGenerator, List, Optional

from langchain_core.runnables import RunnableSerializable
from pydantic import Field

logger = logging.getLogger(__name__)

from myth_config import load_dotenv  # noqa: E402

load_dotenv()
_google_voice_client = None


def get_google_voice_client(force_refresh: bool = False) -> Any:
    """Get or create a persistent Google GenAI client for TTS."""
    global _google_voice_client
    if _google_voice_client is None or force_refresh:
        try:
            from google import genai

            from myth_config import config

            # Use rotate=force_refresh to ensure we pick the next one if invalidating
            api_key = config.get_api_key("google_ai_studio", rotate=force_refresh)
            if not api_key:
                logger.error("❌ [TTS] Google AI Studio API key missing. TTS disabled.")
                return None

            _google_voice_client = genai.Client(api_key=api_key)
            logger.info(
                "✅ [TTS] Google Gemini Voice Matrix Online (Using google-genai)."
            )
        except Exception as e:
            logger.error(f"❌ [TTS] Failed to initialize Google Voice client: {e}")
            return None
    return _google_voice_client


class NeuroMimeticEngine:
    """
    The Humanizer Layer.
    Injects human-like rhythm, breath, emotion, and conversational flow.
    """

    @classmethod
    def inject_interjections(cls, text: str, vibe: str) -> str:
        """Injects personality-driven interjections based on vibe."""
        # 30% chance to inject an emote to avoid being annoying
        if random.random() > 0.3:
            return text

        interjections = []
        if vibe == "EXCITED":
            interjections = ["Nice, ", "Boom, ", "Great, ", "Sweet, ", "There we go, "]
        elif vibe == "APOLOGETIC":
            interjections = ["Uh oh, ", "Oops, ", "Ah, ", "My bad, ", "Ouch, "]
        elif vibe == "CONFUSED":
            interjections = ["Wait, ", "Hang on, ", "Hold up, ", "Hmm, "]
        elif vibe == "FRIENDLY":
            interjections = ["Okay, ", "Sure, ", "Alright, "]  # Gentle starters

        if interjections:
            # Prepend with a random choice
            return random.choice(interjections) + text
        return text

    @classmethod
    def detect_vibe(cls, text: str) -> str:
        """Autonomously infer emotional context from keywords."""
        text_lower = text.lower()

        # URGENT (Critical failure/Security)
        if "traceback (most recent call last)" in text_lower:
            return "URGENT"
        if any(
            w in text_lower
            for w in [
                "fatal",
                "critical",
                "danger",
                "warning",
                "denied",
                "unauthorized",
                "sigkill",
                "sigsegv",
            ]
        ):
            return "URGENT"

        # APOLOGETIC (Mistakes/Bugs)
        if any(
            w in text_lower
            for w in [
                "error",
                "failed",
                "bug",
                "mistake",
                "invalid",
                "syntax",
                "exception",
            ]
        ):
            return "APOLOGETIC"

        # CONFUSED (Unexpected)
        if any(
            w in text_lower
            for w in ["unexpected", "unknown", "strange", "weird", "why", "what the"]
        ):
            return "CONFUSED"

        # EXCITED (Success/Fixes)
        if any(
            w in text_lower
            for w in [
                "success",
                "completed",
                "great",
                "perfect",
                "deployed",
                "online",
                "ready",
                "fixed",
                "optimized",
                "solved",
                "passed",
            ]
        ):
            return "EXCITED"

        # THOUGHTFUL (Processing)
        if any(
            w in text_lower
            for w in [
                "analyzing",
                "calculating",
                "thinking",
                "processing",
                "let's see",
                "hmm",
            ]
        ):
            return "THOUGHTFUL"

        # CAUTIONARY (Advice)
        if any(
            w in text_lower
            for w in ["caution", "careful", "attention", "deprecated", "security risk"]
        ):
            return "CAUTIONARY"

        return "TECHNICAL"  # Default neutral

    @classmethod
    def apply_rhythm(cls, text: str) -> str:
        """Inject breath markers (commas) and chunk long data."""

        # Fluid Connector Logic (Natural Continuity)
        # Soften "Hard Attacks" on conjunctions to simulate continuous thought
        if text.startswith(("And ", "But ", "So ", "Also ", "Then ")):
            # Lowercase the start to cue the TTS engine for a "continuation" tone
            # e.g. "And then..." -> "and then..."
            text = text[0].lower() + text[1:]

        # Conversational Fillers for THOUGHTFUL vibe
        if "analyzing" in text.lower() or "thinking" in text.lower():
            text = random.choice(["Hmm, ", "Let's see, ", "Thinking, "]) + text

        # 1. Rhythmic Chunking for Hash-like strings (that survived normalization)
        text = text.replace(" slash ", ", slash ")
        text = text.replace(" backslash ", ", backslash ")
        text = text.replace(" dot ", " dot ")

        # 2. Kernel & Payload Fluency
        text = text.replace(" /var/log/", ", slash var slash log slash ")
        text = text.replace(" /etc/", ", slash etc slash ")
        text = text.replace(" 0x", ", hex zero x ")
        text = text.replace(" nop ", " nop sled ")

        # Clean up double commas
        text = text.replace(", ,", ",")
        text = text.replace(" dash ", ", dash ")

        return text

    @classmethod
    def get_code_intro(cls, lang: str, entity: str = None, name: str = None) -> str:
        """Generate a varied, conversational intro for code blocks."""
        intros = [
            f"Here is the {lang} code.",
            f"Check out this {lang} snippet.",
            f"I've written this in {lang}.",
            f"Take a look at this {lang} logic.",
        ]

        if entity and name:
            intros.extend(
                [
                    f"Here's the {entity} for {name}.",
                    f"Defining the {name} {entity} in {lang}.",
                    f"This {lang} {entity} handles {name}.",
                ]
            )

        return " [TECHNICAL VIBE] " + random.choice(intros) + " "


class CodeBlockNormalizer:
    """
    Intelligently handles markdown code blocks for audio delivery.
    Now uses NeuroMimeticEngine for conversational intros.
    """

    @classmethod
    def process(cls, text: str) -> str:
        # Detect full or partial code blocks
        if "```" in text:
            import re

            def _replace_code(match):
                lang = match.group(1) or "code"
                code_content = match.group(2) or ""

                # Context-Aware Intro
                entity_type = None
                name = None

                if lang in [
                    "python",
                    "javascript",
                    "js",
                    "ts",
                    "typescript",
                    "c",
                    "cpp",
                ]:
                    # Look for function def or class def
                    func_match = re.search(
                        r"(?:def|function|class)\s+(\w+)", code_content
                    )
                    if func_match:
                        entity_type = (
                            "class" if "class" in match.group(0) else "function"
                        )
                        name = TechnicalNormalizer.normalize_variables(
                            func_match.group(1)
                        )

                return NeuroMimeticEngine.get_code_intro(lang, entity_type, name)

            # This regex looks for ```lang\ncode\n```
            text = re.sub(r"```(\w+)?\n([\s\S]*?)```", _replace_code, text)

            # Handle unclosed blocks (streaming case)
            if "```" in text:
                parts = text.split("```")
                if len(parts) % 2 == 0:
                    text = (
                        parts[0]
                        + " [TECHNICAL VIBE] "
                        + random.choice(["Adding some code...", "Starting a block..."])
                        + " "
                    )
        return text


class SingularityNormalizer:
    """
    The Unspeakable Layer.
    Handles Regex, Cron, JWTs, HTTP Lines, Big-O, SHELLCODE, MATH, and SYSTEM.
    """

    @classmethod
    def normalize(cls, text: str) -> str:
        # 1. Payload & Shellcode
        text = text.replace(r"\x00", " null byte ")
        text = text.replace(r"\x90", " hex ninety ")  # NOP Sled specific
        text = re.sub(r"\\x([0-9a-fA-F]{2})", r" hex \1 ", text)  # General hex escape

        # 2. Big-O Notation
        text = re.sub(r"\bO\(1\)", "Big O of one", text)
        text = re.sub(r"\bO\(n\)", "Big O of N", text)
        text = re.sub(r"\bO\(n\^2\)", "Big O of N squared", text)
        text = re.sub(r"\bO\(log n\)", "Big O of log N", text)
        text = re.sub(r"\bO\(n log n\)", "Big O of N log N", text)

        # 3. HTTP Request Lines
        def _speak_http(match):
            method = match.group(1)
            path = match.group(2).replace("/", " slash ")
            return f" H-T-T-P {method} request to {path} "

        text = re.sub(
            r"\b(GET|POST|PUT|DELETE|PATCH) (/[A-Za-z0-9._/-]+) HTTP/\d\.\d",
            _speak_http,
            text,
        )

        # 4. Cron Schedules
        if re.search(r"\*/5 \* \* \* \*", text):
            text = text.replace("*/5 * * * *", " cron schedule: every 5 minutes ")
        if re.search(r"0 0 \* \* \*", text):
            text = text.replace("0 0 * * *", " cron schedule: daily at midnight ")

        # 5. JWT / Base64
        text = re.sub(
            r"\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b",
            " J-W-T Token ",
            text,
        )
        text = re.sub(r"\b[A-Za-z0-9+/]{50,}={0,2}\b", " Base-sixty-four string ", text)

        # 6. Regex Fluency
        if "^" in text and "$" in text:
            text = text.replace("^", " caret ")
            text = text.replace("$", " dollar ")
            text = text.replace(r"\d", " backslash D ")
            text = text.replace(r"\w", " backslash W ")
            text = text.replace(r"\s", " backslash S ")
            text = text.replace(".*", " dot star ")

        # 7. Python Async
        text = text.replace("async def ", "async def ")
        text = text.replace("await ", "await ")

        # 8. Visual Artifacts
        text = re.sub(r"\[[=#-]{5,}\]", " progress bar ", text)
        text = text.replace("<<<<<<< HEAD", " Git merge conflict HEAD ")
        text = re.sub(r"[└├]──", " tree branch ", text)

        # 9. Math & Greek (Singularity Certification)
        text = text.replace("λ", " lambda ")
        text = text.replace("π", " pi ")
        text = text.replace("Σ", " sigma ")
        text = text.replace("Δ", " delta ")
        text = text.replace("μ", " micro ")

        # 10. System Hardening (Signals & Exit Codes)
        text = text.replace("SIGKILL", " sig kill ")
        text = text.replace("SIGTERM", " sig term ")
        text = text.replace("SIGSEGV", " sig segv ")
        text = re.sub(r"\bexit code 0\b", " exit code zero (success) ", text)
        text = re.sub(r"\bexit code (\d+)\b", r" exit code \1 (failure) ", text)

        # 11. ISO Timestamps (Human Parity)
        # 2023-10-10T10:10:10 -> " timestamp "
        text = re.sub(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
            " timestamp ",
            text,
        )

        # 12. Git Diffs (Naturalized)
        text = re.sub(r"(^|\n)\+ ", r"\1 Added ", text)
        text = re.sub(r"(^|\n)- ", r"\1 Removed ", text)

        # 13. URL Queries (Fluent)
        if "?" in text and "=" in text:

            def _speak_query(match):
                return " query " + match.group(1).replace("&", ", and ").replace(
                    "=", " equals "
                )

            text = re.sub(r"\?([a-zA-Z0-9_=&%-]+)", _speak_query, text)

        return text


class TechnicalNormalizer:
    """
    Evolved technical normalization for absolute voice robustness.
    Covers Registry, Shebangs, UUIDs, Assembly, and OOP Scope Resolution.
    """

    ACRONYMS = {
        "XSS": "Cross-site scripting",
        "SQLi": "SQL injection",
        "SSRF": "Server-side request forgery",
        "LFI": "Local file inclusion",
        "RCE": "Remote code execution",
        "IDS": "I-D-S",
        "IPS": "I-P-S",
        "SIEM": "seam",
        "SOC": "sock",
        "OSINT": "O-S-intel",
        "CVE": "C-V-E",
        "FIM": "fim",
        "RAG": "rag",
        "TTS": "T-T-S",
        "STT": "S-T-T",
        "IAM": "I-A-M",
        "CLI": "C-L-I",
        "SDK": "S-D-K",
        "VPC": "V-P-C",
        "SSH": "S-S-H",
        "TLS": "T-L-S",
        "SSL": "S-S-L",
    }

    CYBER_TOOLS = {
        "nmap": "N-map",
        "metasploit": "meta-sploit",
        "ghidra": "gee-dra",
        "wireshark": "wire-shark",
        "ffuf": "fuff",
        "gobuster": "go-buster",
        "burp": "burp suite",
        "sqlmap": "S-Q-L map",
        "hashcat": "hash-cat",
        "john": "john the ripper",
        "socat": "so-cat",
        "netcat": "net-cat",
        "nc": "N-C",
    }

    DEVOPS_TOOLS = {
        "kubectl": "kube-control",
        "k8s": "K-eight-S",
        "terraform": "terra-form",
        "ansible": "ansi-bull",
        "docker": "docker",
        "kubernetes": "koober-net-ees",
        "aws": "A-W-S",
        "azure": "azure",
        "gcp": "G-C-P",
        "jenkins": "jenkins",
        "gitlab": "git-lab",
        "github": "git-hub",
    }

    SYMBOLS = {
        "= ": " equals ",
        "==": " equals ",
        "!=": " does not equal ",
        ">=": " greater than or equal to ",
        "<=": " less than or equal to ",
        "&&": " and ",
        "||": " or ",
        "=>": " returns ",
        "->": " member access ",
        "++": " increment ",
        "--": " decrement ",
        "+=": " plus equals ",
        "-=": " minus equals ",
        "*=": " times equals ",
        "/=": " divided by equals ",
        "|=": " bitwise or equals ",
        "&=": " bitwise and equals ",
        "^=": " bitwise xor equals ",
        "<<": " shift left ",
        ">>": " shift right ",
        "**": " power ",
        "|": " pipe ",
        ">": " redirect ",
        "<": " input redirect ",
        "::": " scope resolution ",
    }

    UNITS = {
        "MB": " megabytes ",
        "GB": " gigabytes ",
        "KB": " kilobytes ",
        "ms": " milliseconds ",
        "GHz": " gigahertz ",
        "MHz": " megahertz ",
        "Hz": " hertz ",
        "kbps": " kilobits per second ",
        "mbps": " megabits per second ",
    }

    EXTENSIONS = {
        ".exe": " dot E-X-E ",
        ".py": " dot P-Y ",
        ".js": " dot J-S ",
        ".sh": " dot shell ",
        ".bat": " dot bat ",
        ".ps1": " dot P-S-one ",
        ".yaml": " dot yaml ",
        ".yml": " dot yaml ",
        ".json": " dot json ",
        ".txt": " dot text ",
        ".md": " dot markdown ",
        ".cfg": " dot config ",
        ".ini": " dot ini ",
        ".dll": " dot D-L-L ",
        ".so": " dot S-O ",
        ".bin": " dot bin ",
        ".hex": " dot hex ",
    }

    @classmethod
    def normalize_variables(cls, text: str) -> str:
        """Split snake_case and CamelCase for smooth TTS."""
        # 0. Handle Dunder Methods (__init__ -> dunder init)
        text = re.sub(r"__([a-zA-Z0-9_]+)__", r" dunder \1 ", text)
        # 1. Split snake_case
        text = text.replace("_", " ")
        # 2. Split CamelCase (e.g., UserId -> User Id)
        text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
        # 3. Handle trailing numbers (var123 -> var one two three)
        text = re.sub(
            r"([a-zA-Z])(\d+)", lambda m: f"{m.group(1)} {' '.join(m.group(2))}", text
        )
        return text

    @classmethod
    def normalize_hash_or_uuid(cls, text: str) -> str:
        """Speak hex sequences in rhythmic chunks."""
        # Detect MD5/SHA or UUID patterns
        is_hex = all(c in "0123456789abcdefABCDEF-" for c in text)

        if is_hex and (len(text) >= 32 or "-" in text):
            label = " U-U-I-D " if "-" in text else " hash "

            # Remove dashes for raw processing
            clean_text = text.replace("-", "")

            # --- Neuro-Mimetic Chunking ---
            # Group into chunks of 4 characters for readability
            chunks = [clean_text[i : i + 4] for i in range(0, len(clean_text), 4)]
            # Join with commas for breath pauses
            spoken_seq = ", ".join(chunks)
            # Add spaces between chars within chunks for articulation?
            # Rhythmic chunking for better articulation.
            # Let's just do comma-separated blocks.

            return label + spoken_seq

        return text

    @classmethod
    def normalize_ports(cls, text: str) -> str:
        """Naturalize common technical ports."""
        port_map = {
            "80": "port eighty",
            "443": "port four forty-three",
            "8080": "port eighty eighty",
            "22": "port twenty-two",
            "21": "port twenty-one",
            "3306": "port thirty-three zero six",
            "5432": "port fifty-four thirty-two",
            "27017": "port twenty-seven zero seventeen",
        }

        def _repl(match):
            val = match.group(1)
            return port_map.get(val, f"port {val}")

        return re.sub(r"\bport (\d{2,5})\b", _repl, text, flags=re.IGNORECASE)

    @classmethod
    def normalize_shortcuts(cls, text: str) -> str:
        """Naturalize keyboard shortcuts."""
        text = re.sub(r"\bCtrl\+", " Control ", text, flags=re.IGNORECASE)
        text = re.sub(r"\bCmd\+", " Command ", text, flags=re.IGNORECASE)
        text = re.sub(r"\bShift\+", " Shift ", text, flags=re.IGNORECASE)
        text = re.sub(r"\bAlt\+", " Alt ", text, flags=re.IGNORECASE)
        return text

    @classmethod
    def normalize(cls, text: str) -> str:
        # -1. Apply Singularity Normalization (Unspeakables)
        text = SingularityNormalizer.normalize(text)

        # 0. Handle Code Blocks (now with Neuro-Intros)
        text = CodeBlockNormalizer.process(text)

        # 1. Normalize Shebangs
        def _speak_shebang(match):
            return " script header, " + match.group(0).replace("#!", "").replace(
                "/", " slash "
            )

        text = re.sub(r"#!(/[A-Za-z0-9._/-]+)", _speak_shebang, text)

        # 2. Registry Keys
        text = re.sub(r"\bHKLM\b", "H-K-local-machine", text)
        text = re.sub(r"\bHKCU\b", "H-K-current-user", text)
        text = re.sub(r"\bHKCR\b", "H-K-classes-root", text)
        text = re.sub(r"\bHKU\b", "H-K-users", text)

        # 3. Assembly Offsets
        def _speak_offset(match):
            reg = match.group(1)
            op = "minus" if match.group(2) == "-" else "plus"
            offset = match.group(3)
            return f"offset {' '.join(reg)} {op} hex zero x {' '.join(offset[2:])}"

        text = re.sub(
            r"\[([a-z]{3})([+-])(0x[0-9a-fA-F]+)\]",
            _speak_offset,
            text,
            flags=re.IGNORECASE,
        )

        # 4. HEX Addresses
        def _speak_hex(match):
            val = match.group(0).lower()
            digits = " ".join(val[2:])
            return f"hex zero x {digits}"

        text = re.sub(r"0x[0-9a-fA-F]+", _speak_hex, text)

        # 5. CVEs
        def _speak_cve(match):
            parts = match.group(0).split("-")
            year = parts[1]
            id_num = parts[2]
            year_spoken = f"{year[:2]} {year[2:]}"
            return f"C-V-E {year_spoken}, {id_num}"

        text = re.sub(r"CVE-\d{4}-\d+", _speak_cve, text)

        # 6. IPs
        text = re.sub(
            r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})",
            r"\1 dot \2 dot \3 dot \4",
            text,
        )

        # 7. Versions
        def _speak_version(match):
            v = match.group(0)
            if v.startswith("v"):
                v = "version " + v[1:]
            return v.replace(".", " dot ")

        text = re.sub(r"\bv\d+(\.\d+)+\b", _speak_version, text)

        # 8. File Paths
        def _speak_path(match):
            path = match.group(0)
            path = re.sub(r"\b([A-Za-z]):", r"drive \1 ", path)
            return path.replace("/", " slash ").replace("\\", " backslash ")

        text = re.sub(
            r"([A-Za-z]:\\[A-Za-z0-9._\\-]+|/[A-Za-z0-9._/-]+)", _speak_path, text
        )

        # 9. Extensions
        for ext, expansion in cls.EXTENSIONS.items():
            text = re.sub(rf"\{ext}\b", expansion, text)

        # 10. Units
        for unit, expansion in cls.UNITS.items():
            text = re.sub(rf"\b(\d+){unit}\b", rf"\1 {expansion}", text)

        # 11. Symbols
        for symbol, word in cls.SYMBOLS.items():
            text = text.replace(symbol, word)

        # 12. Ports
        text = cls.normalize_ports(text)

        # 13. Tools
        for tool_map in [cls.CYBER_TOOLS, cls.DEVOPS_TOOLS]:
            for tool, expansion in tool_map.items():
                text = re.sub(rf"\b{tool}\b", expansion, text, flags=re.IGNORECASE)

        # 14. Acronyms
        for acronym, expansion in cls.ACRONYMS.items():
            text = re.sub(rf"\b{acronym}\b", expansion, text)

        # 15. CLI Flags
        def _speak_flag(match):
            flag = match.group(0)
            if flag.startswith("--"):
                return " dash dash " + flag[2:].replace("-", " dash ")
            return " dash " + " ".join(flag[1:])

        text = re.sub(r"\b--[a-z0-9-]+\b", _speak_flag, text)
        text = re.sub(r" -[a-z0-9]+\b", _speak_flag, text)

        # 16. Terminal Prompts
        text = re.sub(r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+:.*[#$]", " prompt, ", text)

        # 17. Env Vars
        text = re.sub(
            r"\$[A-Z0-9_]+\b", lambda m: "variable " + m.group(0)[1:].lower(), text
        )
        text = re.sub(
            r"%[A-Z0-9_]+%", lambda m: "variable " + m.group(0)[1:-1].lower(), text
        )

        # 18. Hashes/UUIDs (With Rhythmic Chunking)
        text = re.sub(
            r"\b([0-9a-fA-F-]{32,64})\b",
            lambda m: cls.normalize_hash_or_uuid(m.group(1)),
            text,
        )

        # 19. Pointers
        text = re.sub(r"\*([A-Za-z_][A-Za-z0-9_]*)\b", r" pointer to \1 ", text)
        text = re.sub(r"&([A-Za-z_][A-Za-z0-9_]*)\b", r" address of \1 ", text)

        # 20. Variable Names
        def _norm_id(match):
            return cls.normalize_variables(match.group(0))

        text = re.sub(r"\b[A-Za-z0-9_]+_[A-Za-z0-9_]+\b", _norm_id, text)
        text = re.sub(r"\b[a-z]+[A-Z][A-Za-z0-9]*\b", _norm_id, text)

        # 21. Protocols
        text = text.replace("https://", " H-T-T-P-S colon slash slash ")
        text = text.replace("http://", " H-T-T-P colon slash slash ")
        text = text.replace("ssh://", " S-S-H colon slash slash ")

        # 22. SQL
        sql_keywords = [
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "FROM",
            "WHERE",
            "JOIN",
            "GROUP BY",
            "ORDER BY",
        ]
        for kw in sql_keywords:
            text = re.sub(rf"\b{kw}\b", kw.lower(), text, flags=re.IGNORECASE)

        # 23. Code Markers
        text = re.sub(r"`([^`]+)`", r"\1", text)

        # 24. Shortcuts
        text = cls.normalize_shortcuts(text)

        return text


class VibeModulator:
    """
    Industrial Prosody Engine.
    Parses [VIBE: ...] tags OR uses NeuroMimeticEngine to infer context.
    """

    VIBE_MAP = {
        "URGENT": {"speed": 1.15, "pitch": 1.05},
        "THOUGHTFUL": {"speed": 0.85, "pitch": 0.95},
        "CAUTIONARY": {"speed": 0.92, "pitch": 0.98},
        "DIRECT": {"speed": 1.0, "pitch": 1.0},
        "FRIENDLY": {"speed": 1.05, "pitch": 1.02},
        "TECHNICAL": {"speed": 0.95, "pitch": 1.0},
        # New Personality Vibes
        "EXCITED": {"speed": 1.1, "pitch": 1.05},
        "APOLOGETIC": {"speed": 0.95, "pitch": 0.95},
        "CONFUSED": {"speed": 0.9, "pitch": 1.0},
    }

    @classmethod
    def process_text(cls, text: str) -> tuple[str, dict]:
        """Extract vibe tags and return cleaned text + parameters."""
        match = re.search(r"\[VIBE:\s*(\w+)\]", text)
        vibe_params = {"speed": 1.0}

        # 1. Parsing Vibe
        vibe_type = "TECHNICAL"  # Default
        if match:
            vibe_type = match.group(1).upper()
            text = text.replace(match.group(0), "").strip()
        else:
            # 1b. Auto-Detect Vibe (Neuro-Mimetic)
            vibe_type = NeuroMimeticEngine.detect_vibe(text)

        if vibe_type in cls.VIBE_MAP:
            vibe_params["speed"] = cls.VIBE_MAP[vibe_type]["speed"]
            # Speed modulation is applied via VibeModulator.
            # but we map speed. Pitch would need deeper model hacking or params.

        # 2. Inject Interjections (Personality) - Pre-Normalization
        text = NeuroMimeticEngine.inject_interjections(text, vibe_type)

        # 3. Technical Normalization
        text = TechnicalNormalizer.normalize(text)

        # 4. Neuro-Mimetic Rhythm Injection (Breath markers)
        text = NeuroMimeticEngine.apply_rhythm(text)

        return text.strip(), vibe_params


class BreathAwareSplitter:
    """
    Rhythmic Phrasing Engine.
    Splits text into 'breath-sized' chunks, prioritizing logical pauses.
    """

    def __init__(self, min_len: int = 5, target_len: int = 40, max_len: int = 60):
        self.min_len = min_len
        self.target_len = target_len
        self.max_len = max_len
        self.is_first_chunk = True
        self.major_breaks = re.compile(r"([.!?;:][\s\n\r]+)")
        self.minor_breaks = re.compile(r"([,][\s\n\r]+)")

    def reset(self):
        """Reset state for a new interaction stream."""
        self.is_first_chunk = True

    def split(self, text: str) -> List[str]:
        if not text:
            return []

        # --- ULTRA-LOW LATENCY: Aggressive First Burst ---
        # "Turbo-Start": Emit the first 3 words immediately to minimize TTFB
        if self.is_first_chunk:
            words = text.split()
            if len(words) >= 3:
                first_burst = " ".join(words[:3])
                self.is_first_chunk = False
                return [first_burst]
            elif len(text) >= 5 and any(p in text for p in ".!?"):
                self.is_first_chunk = False
                return [text.strip()]

        # --- UNBREAKABLE CONTINUITY LOCK-IN ---
        # If we are NOT the first chunk, aggressively merge to prevent prosody resets.
        # We hold until 60+ chars OR an explicit newline.
        if not self.is_first_chunk and len(text) < 60:
            if "\n" not in text:
                return []

        chunks = []
        # Standard splitting logic for larger buffers (now targeting 60+ chars)
        while len(text) > self.target_len:
            # Try major breaks (sentences)
            match = self.major_breaks.search(text, pos=self.min_len)
            if match:
                end = match.end()
                if end <= self.max_len:
                    chunks.append(text[:end].strip())
                    text = text[end:]
                    self.is_first_chunk = False  # Ensure we are in batch mode
                    continue

            # Try minor breaks (commas)
            match = self.minor_breaks.search(text, pos=self.min_len)
            if match:
                end = match.end()
                if end <= self.max_len:
                    chunks.append(text[:end].strip())
                    text = text[end:]
                    self.is_first_chunk = False
                    continue

            # Fallback: Hard split at max_len
            split_idx = text.rfind(" ", 0, self.max_len)
            if split_idx == -1:
                split_idx = self.max_len

            chunks.append(text[:split_idx].strip())
            text = text[split_idx:]
            self.is_first_chunk = False

        return chunks


class VibeVoiceProcessor(RunnableSerializable[str, bytes]):
    """
    Local Text-to-Speech Processor using Google Gemini Live.
    """

    model_id: str = Field(default="gemini-2.5-flash-native-audio-latest")
    api_token: Optional[str] = Field(default=None)
    splitter: Any = Field(default_factory=BreathAwareSplitter, exclude=True)
    enabled: bool = Field(default=True)
    voice: str = Field(default="Aoede")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Force default model to native-audio if it's the 404'ing one
        if self.model_id in ["gemini-2.5-flash-live", "gemini-2.0-flash"]:
            self.model_id = "gemini-2.5-flash-native-audio-latest"

        client = get_google_voice_client()
        if not client:
            self.enabled = False
        else:
            logger.info(
                f"🎙️ [TTS] Ready for Cloud-Based Streaming (Model: {self.model_id})"
            )

    async def transcribe(self, audio_data: bytes) -> str:
        pass

    async def astream(
        self, input: str, config: Optional[Any] = None, **kwargs
    ) -> AsyncGenerator[bytes, None]:
        """Stream audio bytes from Google Gemini with dynamic prosody."""
        if not self.enabled or not input or not input.strip():
            return

        max_retries = 3
        for attempt in range(max_retries):
            client = get_google_voice_client(force_refresh=(attempt > 0))
            if not client:
                return

            try:
                # Process text for Vibe/Prosody before sending
                input_cleaned, vibe_params = VibeModulator.process_text(input)

                from google.genai import types

                config_live = types.LiveConnectConfig(response_modalities=["AUDIO"])

                async with client.aio.live.connect(
                    model=self.model_id, config=config_live
                ) as session:
                    await session.send(input=input_cleaned, end_of_turn=True)

                    async for message in session.receive():
                        if message.server_content and message.server_content.model_turn:
                            for part in message.server_content.model_turn.parts:
                                if (
                                    part.inline_data
                                    and part.inline_data.mime_type == "audio/wav"
                                ):
                                    yield part.inline_data.data
                                elif part.inline_data:
                                    if "audio" in part.inline_data.mime_type:
                                        yield part.inline_data.data

                        if (
                            message.server_content
                            and message.server_content.turn_complete
                        ):
                            break
                return  # Success, exit retry loop
            except Exception as e:
                err_str = str(e)
                # Detection: Check for 1008 (Leaked), 1007 (Expired) or 403 (Unauthorized/Forbidden)
                if any(
                    x in err_str
                    for x in [
                        "1008",
                        "1007",
                        "leaked",
                        "expired",
                        "403",
                        "unauthorized",
                    ]
                ):
                    from myth_config import config as m_config

                    # Get the current key used by this client for invalidation
                    # Note: Client doesn't expose key easily, but we know it's the current one in rotation
                    current_key = m_config.get_api_key("google_ai_studio", rotate=False)
                    if current_key:
                        m_config.invalidate_key("google_ai_studio", current_key)

                    logger.warning(
                        f"⚠️ [TTS] API Key Compromised/Failed (Attempt {attempt + 1}): {err_str}. Rotating..."
                    )
                    if attempt == max_retries - 1:
                        logger.error(
                            f"❌ [TTS] All TTS keys exhausted or terminal error: {e}"
                        )
                else:
                    logger.error(
                        f"❌ [TTS] Google Voice Bidi Generation Failed (Attempt {attempt + 1}): {e}"
                    )
                    # For non-auth errors, we still might want to exit if it's a code issue
                    if attempt == max_retries - 1:
                        break

                await asyncio.sleep(0.5)  # Minimum cooloff

    async def ainvoke(
        self, input: str, config: Optional[Any] = None, **kwargs
    ) -> bytes:
        full_audio = b""
        async for chunk in self.astream(input, config, **kwargs):
            full_audio += chunk
        return full_audio

    def invoke(self, input: str, config: Optional[Any] = None, **kwargs) -> bytes:
        """Synchronous wrapper for ainvoke."""
        import asyncio

        try:
            return asyncio.run(self.ainvoke(input, config, **kwargs))
        except RuntimeError:
            # Handle cases where a loop is already running
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self.ainvoke(input, config, **kwargs))

    async def test_connection(self) -> bool:
        if not self.enabled:
            return False
        logger.info("🔍 [TTS] Running Ultra-Low Latency Health Check...")
        found = False
        async for _ in self.astream("Ready."):
            found = True
            break
        return found

    def create_session(self) -> "PersistentVibeSession":
        """Creates a persistent bidirectional session for real-time streaming."""
        return PersistentVibeSession(self.model_id)

    async def stream_audio_chunks(
        self, text_generator: AsyncGenerator[str, None]
    ) -> AsyncGenerator[str, None]:
        if not self.enabled:
            return

        audio_buffers = asyncio.Queue(maxsize=5)

        async def _inference_worker(fragment: str, target_queue: asyncio.Queue):
            try:
                async for chunk in self.astream(fragment):
                    await target_queue.put(base64.b64encode(chunk).decode("utf-8"))
            except Exception as e:
                logger.error(f"❌ [TTS] Background Inference Task Error: {e}")
            finally:
                await target_queue.put(None)

        async def _producer():
            buffer = ""
            async for token in text_generator:
                buffer += token
                frags = self.splitter.split(buffer)
                if frags:
                    for f in frags:
                        frag_buffer = asyncio.Queue()
                        await audio_buffers.put(frag_buffer)
                        asyncio.create_task(_inference_worker(f, frag_buffer))

                    last_frag = frags[-1]
                    idx = buffer.find(last_frag)
                    buffer = buffer[idx + len(last_frag) :]

            if buffer.strip():
                frag_buffer = asyncio.Queue()
                await audio_buffers.put(frag_buffer)
                asyncio.create_task(_inference_worker(buffer.strip(), frag_buffer))

            await audio_buffers.put(None)

        producer_task = asyncio.create_task(_producer())

        try:
            while True:
                frag_buffer = await audio_buffers.get()
                if frag_buffer is None:
                    break

                while True:
                    chunk = await frag_buffer.get()
                    if chunk is None:
                        break
                    yield chunk

                audio_buffers.task_done()
        finally:
            producer_task.cancel()


class PersistentVibeSession:
    """
    Manages a persistent bidirectional connection to Gemini Live for zero-latency TTS.
    """

    def __init__(self, model_id: str):
        self.model_id = model_id
        self._client = get_google_voice_client()
        self._session = None
        self._ctx = None
        self._send_queue = asyncio.Queue()
        self._recv_queue = asyncio.Queue()
        self._tasks = set()
        self._active = False

    async def __aenter__(self):
        if not self._client:
            raise RuntimeError("Google Voice Client not initialized")

        from google.genai import types

        config = types.LiveConnectConfig(response_modalities=["AUDIO"])

        self._ctx = self._client.aio.live.connect(model=self.model_id, config=config)
        self._session = await self._ctx.__aenter__()
        self._active = True

        self._tasks.add(asyncio.create_task(self._sender_loop()))
        self._tasks.add(asyncio.create_task(self._receiver_loop()))

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._active = False
        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()

        if self._ctx:
            await self._ctx.__aexit__(exc_type, exc_val, exc_tb)

    async def send(self, text: str, end_of_turn: bool = False):
        if not text:
            return
        await self._send_queue.put((text, end_of_turn))

    async def receive(self) -> AsyncGenerator[bytes, None]:
        while self._active or not self._recv_queue.empty():
            try:
                chunk = await asyncio.wait_for(self._recv_queue.get(), timeout=0.1)
                yield chunk
            except asyncio.TimeoutError:
                if not self._active:
                    break
                continue
            except Exception:
                break

    async def _sender_loop(self):
        logger.info("🎙️ [TTS-SESSION] Sender loop started")
        while self._active:
            try:
                text, end_of_turn = await self._send_queue.get()
                text_cleaned, _ = VibeModulator.process_text(text)
                if text_cleaned.strip():
                    # logger.info(f"📤 [TTS-SESSION] Sending to Gemini: '{text_cleaned[:30]}...' (EOT={end_of_turn})")
                    # TRY: Forcing end_of_turn to True for every chunk to mirror astream success
                    await self._session.send(input=text_cleaned, end_of_turn=True)
                elif end_of_turn:
                    await self._session.send(input=" ", end_of_turn=True)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ [TTS-SESSION] Sender Error: {e}")

    async def _receiver_loop(self):
        logger.info("🎙️ [TTS-SESSION] Receiver loop started")
        try:
            async for message in self._session.receive():
                if not self._active:
                    break

                # logger.debug(f"📥 [TTS-SESSION] Received message type: {type(message)}")
                if message.server_content and message.server_content.model_turn:
                    for part in message.server_content.model_turn.parts:
                        if part.inline_data and "audio" in part.inline_data.mime_type:
                            await self._recv_queue.put(part.inline_data.data)

                if message.server_content and message.server_content.turn_complete:
                    # logger.debug("🏁 [TTS-SESSION] Turn complete")
                    pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"❌ [TTS-SESSION] Receiver Error: {e}")
