import json
import asyncio
import os
import re
import binascii
import base64
from datetime import datetime
from myth_config import load_dotenv
from langchain_core.tools import tool
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🔍 Steganography & Forensic CTF Tools (Industrial Grade)
# ==============================================================================

@tool
async def lsb_stego_prober(file_path: str) -> str:
    """
    Analyzes an image (PNG, BMP) for Least Significant Bit (LSB) steganography patterns with memory safety.
    """
    try:
        if not os.path.exists(file_path):
             raise FileNotFoundError(f"Target file not found: {file_path}")

        # Robustness: Limit read size for LSB probe
        MAX_LSB_READ = 1024 * 512 # 512KB
        with open(file_path, 'rb') as f:
            data = f.read(MAX_LSB_READ)
            
        lsb_bits = "".join([str(b & 1) for b in data])
        
        # Advanced Analysis: Entropy of the LSB plane
        import math
        from collections import Counter
        counts = Counter(lsb_bits)
        total = len(lsb_bits)
        entropy = -sum((count/total) * math.log(count/total, 2) for count in counts.values())
        
        # Standard String check
        potential_strings = ""
        for i in range(0, len(lsb_bits), 8):
            byte = lsb_bits[i:i+8]
            if len(byte) == 8:
                char = chr(int(byte, 2))
                if char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-":
                    potential_strings += char
        
        # High entropy (>0.95 for LSB) or finding flag pattern strings
        is_suspicious = (entropy > 0.98) or (len(potential_strings) > 5)
        confidence = 0.9 if is_suspicious else 0.1
        
        return format_industrial_result(
            "lsb_stego_prober",
            "Anomaly Detected" if confidence > 0.4 else "Clean",
            confidence=confidence,
            impact="MEDIUM",
            raw_data={"extracted_snippet": potential_strings[:50]},
            summary=f"Memory-safe LSB probe finished. Analyzed first {MAX_LSB_READ//1024}KB of {os.path.basename(file_path)}."
        )
    except FileNotFoundError as e:
        return format_industrial_result("lsb_stego_prober", "File Error", error=str(e))
    except Exception as e:
        return format_industrial_result("lsb_stego_prober", "Error", error=str(e))

@tool
async def magic_byte_carver(file_path: str) -> str:
    """
    Extracts embedded files from a binary blob using memory-safe chunked reading.
    Supports: ZIP, PNG, JPEG, PDF, ELF, PE.
    """
    try:
        if not os.path.exists(file_path):
             raise FileNotFoundError(f"Target file not found: {file_path}")

        magic_signatures = {
            "ZIP/Office": b"\x50\x4b\x03\x04",
            "PNG": b"\x89\x50\x4e\x47",
            "JPEG": b"\xff\xd8\xff",
            "PDF": b"\x25\x50\x44\x46",
            "ELF": b"\x7fELF",
            "PE": b"MZ"
        }

        extracted = []
        CHUNK_SIZE = 1024 * 1024 # 1MB chunks
        overlap = 64 # Max signature length
        
        with open(file_path, 'rb') as f:
            offset_base = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk: break
                
                for name, sig in magic_signatures.items():
                    for match in re.finditer(re.escape(sig), chunk):
                        offset = offset_base + match.start()
                        snippet = chunk[match.start():match.start()+64]
                        extracted.append({
                            "type": name,
                            "offset": hex(offset),
                            "snippet_hex": binascii.hexlify(snippet).decode(),
                            "snippet_ascii": snippet.decode('ascii', errors='ignore')
                        })
                        if len(extracted) >= 50: break # Safety limit
                
                if len(extracted) >= 50: break
                offset_base += CHUNK_SIZE
                f.seek(f.tell() - overlap) # Maintain continuity for split signatures

        return format_industrial_result(
            "magic_byte_carver",
            "Carving Complete",
            confidence=1.0,
            impact="MEDIUM",
            raw_data={"findings": extracted[:10]},
            summary=f"Robust magic byte carving for {os.path.basename(file_path)} finished. Identified {len(extracted)} potential items."
        )
    except Exception as e:
        return format_industrial_result("magic_byte_carver", "Error", error=str(e))

@tool
async def universal_flag_hunter(file_path: str, custom_regex: str = r"flag\{[a-zA-Z0-9_\-]+\}") -> str:
    """
    Recursively scans a file for flag patterns using memory-safe chunked reading and multi-decoding.
    """
    try:
        if not os.path.exists(file_path):
             raise FileNotFoundError(f"Target file not found: {file_path}")

        findings = []
        pattern = re.compile(custom_regex.encode(), re.IGNORECASE)
        CHUNK_SIZE = 1024 * 1024 # 1MB
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk: break
                
                # 1. Plaintext search
                for match in pattern.finditer(chunk):
                    findings.append({"method": "Plaintext", "flag": match.group().decode(errors='ignore')})

                # 2. Base64 decoded segments (Robust check)
                b64_pat = re.compile(b"[a-zA-Z0-9+/=]{16,}")
                for match in b64_pat.finditer(chunk):
                    try:
                        decoded = base64.b64decode(match.group())
                        for submatch in pattern.finditer(decoded):
                            findings.append({"method": "Base64 Layer", "flag": submatch.group().decode(errors='ignore')})
                    except: pass
                
                if len(findings) >= 20: break

        return format_industrial_result(
            "universal_flag_hunter",
            "Targets Found" if findings else "No Flags",
            confidence=1.0,
            impact="CRITICAL" if findings else "LOW",
            raw_data={"all_findings": findings},
            summary=f"Hardened flag hunter for {os.path.basename(file_path)} finished. Identified {len(findings)} patterns."
        )
    except Exception as e:
        return format_industrial_result("universal_flag_hunter", "Error", error=str(e))
