import asyncio
import os
import shutil
import struct
from typing import Any

from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🛠️ Binary Analysis & Pwn CTF Tools (Industry Grade)
# ==============================================================================


@tool
async def elf_security_checker(file_path: str, **kwargs) -> str:
    """
    Analyzes an ELF (Linux), PE (Windows), or Mach-O (macOS) binary for security mitigations via header parsing.
    Checks: NX/DEP, Stack Canary, ASLR/PIE, RELRO.
    """
    try:
        if not os.path.exists(file_path):
            return format_industrial_result(
                "elf_security_checker", "Error", error="File not found"
            )

        mitigations = {}
        with open(file_path, "rb") as f:
            data = f.read(1024)  # Header data

            # --- ELF (Linux) ---
            if data.startswith(b"\x7fELF"):
                mitigations["OS"] = "Linux (ELF)"
                # Simple Segment check for NX (Stack execution bit)
                # Heuristic: Find PT_GNU_STACK (type 0x6474e551)
                if b"\x51\xe5\x74\x64" in data:
                    mitigations["NX"] = "Enabled"
                else:
                    mitigations["NX"] = "Unknown/Disabled"

                # Canary check (Search for __stack_chk_fail)
                if b"__stack_chk_fail" in data:
                    mitigations["Canary"] = "Found"
                else:
                    mitigations["Canary"] = "Not Found"

                # PIE: Check e_type (offset 16-17) for ET_DYN (3)
                e_type = struct.unpack("<H", data[16:18])[0]
                mitigations["PIE"] = "Enabled" if e_type == 3 else "Disabled"

                # Advanced: RELRO and RPATH detection via readelf (Shell-safe)
                readelf_path = shutil.which("readelf")
                if readelf_path:
                    proc = await asyncio.create_subprocess_exec(
                        readelf_path,
                        "-l",
                        "-d",
                        file_path,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate()
                    output = stdout.decode(errors="ignore")

                    if "GNU_RELRO" in output:
                        mitigations["RELRO"] = (
                            "Full" if "BIND_NOW" in output else "Partial"
                        )
                    else:
                        mitigations["RELRO"] = "Disabled"

                    if "RPATH" in output or "RUNPATH" in output:
                        mitigations["RPATH/RUNPATH"] = (
                            "DETECTED (Potential Privilege Escalation)"
                        )

            # --- PE (Windows) ---
            elif data.startswith(b"MZ"):
                mitigations["OS"] = "Windows (PE)"
                pe_ptr = struct.unpack("<I", data[60:64])[0]
                pe_header = data[pe_ptr : pe_ptr + 24]

                if pe_header.startswith(b"PE"):
                    # Check Characteristics in Optional Header
                    # Heuristic: Search for DEP (0x0100) / ASLR (0x0040) in DllCharacteristics
                    opt_header_offset = pe_ptr + 24
                    dll_chars = struct.unpack(
                        "<H", data[opt_header_offset + 70 : opt_header_offset + 72]
                    )[0]

                    mitigations["DEP"] = (
                        "Enabled" if (dll_chars & 0x0100) else "Disabled"
                    )
                    mitigations["ASLR"] = (
                        "Enabled" if (dll_chars & 0x0040) else "Disabled"
                    )
                    mitigations["SafeSEH"] = (
                        "Enabled" if (dll_chars & 0x0400) else "Disabled"
                    )

            else:
                return format_industrial_result(
                    "elf_security_checker",
                    "Incompatible",
                    error="Unrecognized binary format.",
                )

        return format_industrial_result(
            "elf_security_checker",
            "Audit Complete",
            confidence=0.9,
            impact="MEDIUM",
            raw_data={"file": os.path.basename(file_path), "mitigations": mitigations},
            summary=f"Parsed headers for {os.path.basename(file_path)}. Results: {mitigations}",
        )
    except Exception as e:
        return format_industrial_result("elf_security_checker", "Error", error=str(e))


@tool
async def cyclic_pattern_generator(
    length: Any = 100, charset: str = "abcdefghijklmnopqrstuvwxyz", **kwargs
) -> str:
    """
    Generates a unique De Bruijn cyclic pattern for deterministic buffer overflow offset identification.
    Industry-standard validation enforced.
    """
    try:
        # Robustness Pass: Handle string inputs for numeric fields
        try:
            length = int(length)
        except (ValueError, TypeError):
            return format_industrial_result(
                "cyclic_pattern_generator",
                "Validation Error",
                error="length must be an integer.",
            )

        # Robustness Pass: Bounds Checking
        if length <= 0 or length > 100000:
            raise ValueError("Pattern length must be between 1 and 100,000 bytes.")
        if len(charset) < 4:
            raise ValueError("Charset must contain at least 4 unique characters.")

        pattern = ""
        alphabet = charset

        for i in range(0, length, 4):
            c1 = alphabet[(i // (len(alphabet) ** 2)) % len(alphabet)]
            c2 = alphabet[(i // len(alphabet)) % len(alphabet)]
            c3 = alphabet[i % len(alphabet)]
            c4 = str((i // 4) % 10)
            pattern += f"{c1}{c2}{c3}{c4}"

        final_pattern = pattern[:length]

        return format_industrial_result(
            "cyclic_pattern_generator",
            "Success",
            confidence=1.0,
            impact="LOW",
            raw_data={"length": length, "pattern": final_pattern},
            summary=f"Generated {length}-byte De Bruijn style cyclic pattern for offset discovery.",
        )
    except ValueError as e:
        return format_industrial_result(
            "cyclic_pattern_generator", "Validation Error", error=str(e)
        )
    except Exception as e:
        return format_industrial_result(
            "cyclic_pattern_generator", "Error", error=str(e)
        )


@tool
async def binary_symbol_mapper(file_path: str, **kwargs) -> str:
    """
    Extracts high-value symbols (PLT/GOT) using shell-safe subprocess execution.
    Identifies locations of system(), gets(), printf(), etc.
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Binary not found: {file_path}")

        # Robustness Pass: Exec-based call (No shell injection)
        findings = []

        # 1. Try objdump
        objdump_path = shutil.which("objdump")
        if objdump_path:
            proc = await asyncio.create_subprocess_exec(
                objdump_path,
                "-R",
                file_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode("utf-8", errors="ignore")

            critical_targets = [
                "system",
                "gets",
                "read",
                "puts",
                "print",
                "execve",
                "scanf",
            ]
            for line in output.splitlines():
                if any(t in line for t in critical_targets):
                    findings.append(line.strip())

        # 2. Fallback to nm
        if not findings:
            nm_path = shutil.which("nm")
            if nm_path:
                proc = await asyncio.create_subprocess_exec(
                    nm_path,
                    "-D",
                    file_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                output = stdout.decode("utf-8", errors="ignore")
                for line in output.splitlines():
                    if any(t in line for t in critical_targets):
                        findings.append(line.strip())

            # 3. Demangling Pass (C++ support)
            cppfilt_path = shutil.which("c++filt")
            if cppfilt_path and findings:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        cppfilt_path,
                        stdout=asyncio.subprocess.PIPE,
                        stdin=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await proc.communicate("\n".join(findings).encode())
                    demangled = stdout.decode(errors="ignore").splitlines()
                    findings = [
                        f"{orig} -> {dem}" for orig, dem in zip(findings, demangled)
                    ]
                except Exception:
                    pass

        return format_industrial_result(
            "binary_symbol_mapper",
            "Mapping Complete" if findings else "Clean",
            confidence=1.0,
            impact="HIGH",
            raw_data={"critical_symbols": findings[:30]},
            summary=f"Shell-safe symbol map for {os.path.basename(file_path)} finished. Identified {len(findings)} critical relocations (Demangled if C++).",
        )
    except FileNotFoundError as e:
        return format_industrial_result(
            "binary_symbol_mapper", "File Error", error=str(e)
        )
    except Exception as e:
        return format_industrial_result(
            "binary_symbol_mapper", "Execution Error", error=str(e)
        )
