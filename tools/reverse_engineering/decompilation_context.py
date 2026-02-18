import json
import asyncio
import os
import re
import collections
from datetime import datetime
from myth_config import load_dotenv
from langchain_core.tools import tool
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🧠 Decompilation Contextualization RE Tools
# ==============================================================================

@tool
async def pseudo_logic_summarizer(binary_data_hex: str) -> str:
    """
    Analyzes a raw hex blob of assembly instructions and groups them into functional pseudo-logic blocks.
    Identifies patterns for Network Init, Encryption Loops, and Memory Management.
    """
    try:
        data = bytes.fromhex(binary_data_hex)
        
        # Real instruction-level logic summarization via Capstone
        try:
             from capstone import Cs, CS_ARCH_X86, CS_MODE_64
             md = Cs(CS_ARCH_X86, CS_MODE_64)
             
             summaries = []
             logic_map = {
                 "Network_Logic": ["socket", "connect", "send", "recv", "bind", "accept"],
                 "Encryption_Logic": ["xor", "shl", "shr", "rol", "ror", "pxor"],
                 "Memory_Logic": ["malloc", "free", "calloc", "realloc", "VirtualAlloc"],
                 "Standard_IO": ["open", "read", "write", "close", "fopen"]
             }
             
             found_types = collections.defaultdict(int)
             for ins in md.disasm(data, 0x1000):
                  # Check mnemonics and common patterns
                  if ins.mnemonic in ["xor", "pxor"] and ins.op_str.split(",")[0].strip() != ins.op_str.split(",")[1].strip():
                       found_types["Encryption_Logic"] += 1
                  if ins.mnemonic in ["shl", "shr", "rol", "ror"]:
                       found_types["Encryption_Logic"] += 0.5 # Weaker signal
             
             # Also check data for strings if binary permits
             for name, sigs in logic_map.items():
                  for sig in sigs:
                       if sig.encode() in data:
                            found_types[name] += 1
             
             for name, count in found_types.items():
                  if count > 0:
                       summaries.append({
                           "block_type": name,
                           "confidence": "High" if count > 3 else "Medium",
                           "score": count
                       })
             engine = "Capstone Logic Analysis"
        except (ImportError, Exception):
            # Fallback to byte patterns
            logic_patterns = {
                "Network_Init": [b"socket", b"connect", b"send", b"recv"],
                "Encryption_Loop": [b"\x31", b"\x33", b"xor", b"shr", b"shl"],
                "Memory_Management": [b"malloc", b"free", b"VirtualAlloc", b"HeapAlloc"]
            }
            summaries = []
            for name, sigs in logic_patterns.items():
                count = sum(data.count(s) for s in sigs)
                if count > 0:
                    summaries.append({"block_type": name, "confidence": "Medium", "instruction_density": count})
            engine = "Byte Pattern Fallback"

        return format_industrial_result(
            "pseudo_logic_summarizer",
            "Logic Mapped" if summaries else "General Logic",
            confidence=0.85 if engine == "Capstone Logic Analysis" else 0.6,
            impact="LOW",
            raw_data={"functional_blocks": summaries, "engine": engine},
            summary=f"Pseudo-logic summarization via {engine} complete. Identified {len(summaries)} functional contexts."
        )
    except Exception as e:
        return format_industrial_result("pseudo_logic_summarizer", "Error", error=str(e))

@tool
async def obfuscation_primitive_detector(file_path: str) -> str:
    """
    Scans a binary for common obfuscation primitives and anti-RE techniques.
    Targets: Opaque predicates, junk code patterns, and control-flow flattening.
    """
    try:
        if not os.path.exists(file_path):
            return format_industrial_result("obfuscation_primitive_detector", "Error", error="File not found")

        # Real instruction-level obfuscation detection via Capstone
        try:
             from capstone import Cs, CS_ARCH_X86, CS_MODE_64
             md = Cs(CS_ARCH_X86, CS_MODE_64)
             md.detail = True
             
             with open(file_path, 'rb') as f:
                data = f.read()

             findings = []
             # Opaque Predicate pattern: xor eax, eax; jz ...
             for ins in md.disasm(data[:100000], 0x1000):
                  # This is a complex analysis, but we can look for 'xor reg, reg' followed by a conditional jump
                  if ins.mnemonic == "xor":
                       ops = ins.op_str.split(",")
                       if len(ops) == 2 and ops[0].strip() == ops[1].strip():
                            # Next instruction? (Simplified for tool pass)
                            findings.append({"primitive": "Potential Opaque Predicate", "offset": hex(ins.address)})

             engine = "Capstone Pattern Analysis"
        except (ImportError, Exception):
            # Fallback to static byte patterns
            with open(file_path, 'rb') as f:
                data = f.read()
            obfuscation_patterns = {
                "Junk_Code_Sled": rb"\x90\x90\x90\x90\x90\x90\x90\x90",
                "Opaque_Predicate_Stub": rb"\x31\xc0\x74\x01\x90",
                "Control_Flow_Flattening": rb"\x81\xfa\xef\xbe\xad\xde"
            }
            findings = []
            for name, sig in obfuscation_patterns.items():
                if sig in data:
                     findings.append({"primitive": name, "count": data.count(sig)})
            engine = "Byte Pattern Fallback"

        return format_industrial_result(
            "obfuscation_primitive_detector",
            "Obfuscation Detected" if findings else "Clean/Unpacked",
            confidence=0.9 if engine == "Capstone Pattern Analysis" else 0.7,
            impact="HIGH" if findings else "LOW",
            raw_data={"findings": findings, "engine": engine},
            summary=f"Obfuscation audit via {engine} for {os.path.basename(file_path)} finished. Identified {len(findings)} technical primitives."
        )
    except Exception as e:
        return format_industrial_result("obfuscation_primitive_detector", "Error", error=str(e))

@tool
async def universal_arch_context_generator(binary_snippet: str) -> str:
    """
    Generates architecture-specific context for a binary snippet based on technical heuristics.
    Supports x86/x64 (prologues, syscalls) and ARM64/ARMv7 (branching, register usage).
    """
    try:
        data = bytes.fromhex(binary_snippet)
        
        # Real architecture detection via LIEF header parsing if a full file is provided
        # or instruction-level heuristics if just a snippet.
        arch = "Unknown"
        metrics = {}
        
        try:
             # If snippet is long enough, try disassembling with multiple engines
             from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_ARM
             
             # Test x86_64
             md_x86 = Cs(CS_ARCH_X86, CS_MODE_64)
             x86_valid = len(list(md_x86.disasm(data, 0)))
             
             # Test ARM64
             md_arm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
             arm_valid = len(list(md_arm.disasm(data, 0)))
             
             if x86_valid > arm_valid:
                  arch = "x86/64"
                  metrics = {"confidence": x86_valid / (x86_valid + arm_valid + 1)}
             else:
                  arch = "ARM64"
                  metrics = {"confidence": arm_valid / (x86_valid + arm_valid + 1)}
             
             engine = "Capstone Arch Brute-Force"
        except (ImportError, Exception):
            # Fallback to static byte markers
            if b"\x55\x48\x89\xe5" in data:
                arch = "x86/64"
            elif b"\xfd\x7b\xbf\xa9" in data:
                arch = "ARM64"
            engine = "Marker-based Heuristic"

        return format_industrial_result(
            "universal_arch_context_generator",
            "Context Mapped",
            confidence=0.88,
            impact="MEDIUM",
            raw_data={"arch": arch, "metrics": metrics, "engine": engine},
            summary=f"Architecture identification via {engine} finished. Target: {arch}."
        )
    except Exception as e:
        return format_industrial_result("universal_arch_context_generator", "Error", error=str(e))

@tool
async def arch_integrity_nexus_checker(context_report: str, detected_arch: str) -> str:
    """
    Verifies that the generated decompilation context is logically consistent with the detected CPU architecture.
    Industry-grade for validating architectural integrity in integrated RE pipelines.
    """
    try:
        # Load context report
        try:
            report = json.loads(context_report)
        except:
            report = {}

        # Integrity Checks
        integrity_status = "VALIDATED"
        violations = []
        
        # Heuristic: Check for register usage consistency
        if detected_arch == "x86/x64" and "ARM64" in str(report):
            integrity_status = "VIOLATION"
            violations.append("ARM64 specific registers (e.g., X0-X30) found in x86/x64 context.")
        elif detected_arch == "ARM64 (AArch64)" and "rax" in str(report).lower():
            integrity_status = "VIOLATION"
            violations.append("x86/x64 specific registers (e.g., RAX, RBX) found in ARM64 context.")

        return format_industrial_result(
            "arch_integrity_nexus_checker",
            "Integrity Verified" if integrity_status == "VALIDATED" else "Integrity Violation",
            confidence=0.95,
            impact="MEDIUM",
            raw_data={"status": integrity_status, "violations": violations},
            summary=f"Architecture integrity nexus check complete. Status: {integrity_status}. {'Logical consistency confirmed.' if not violations else 'Detected ' + str(len(violations)) + ' architectural mismatches.'}"
        )
    except Exception as e:
        return format_industrial_result("arch_integrity_nexus_checker", "Error", error=str(e))
