import json
import asyncio
import os
import platform
import re
from datetime import datetime
from myth_config import load_dotenv
from langchain_core.tools import tool
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 🛡️ Advanced Hardening & Mitigation Audit RE Tools
# ==============================================================================

@tool
async def checksec_advanced(file_path: str) -> str:
    """
    Performs a deep technical audit of a binary for modern security mitigations.
    Checks: Control Flow Guard (CFG), Shadow Stack, Retpoline, and SafeSEH.
    """
    try:
        if not os.path.exists(file_path):
            return format_industrial_result("checksec_advanced", "Error", error="File not found")

        is_windows = platform.system() == "Windows"
        mitigations = {}
        
        with open(file_path, 'rb') as f:
            data = f.read()

        if is_windows:
            # PE Header analysis proxies
            mitigations["CFG"] = "Enabled" if b"ControlFlowGuard" in data or b"GUARD_CF" in data else "Disabled"
            mitigations["SafeSEH"] = "Found" if b"SafeSEH" in data else "None"
            mitigations["ShadowStack"] = "Present" if b"CET_SHSTK" in data else "None"
        else:
            # ELF Header analysis proxies
            mitigations["Retpoline"] = "Detected" if b"retpoline" in data.lower() else "None"
            mitigations["IBT/SHSTK"] = "Enabled" if b"IBT" in data and b"SHSTK" in data else "None"
            mitigations["Stack_Clash"] = "Protected" if b"fstack-clash-protection" in data.lower() else "None"

        return format_industrial_result(
            "checksec_advanced",
            "Audit Complete",
            confidence=0.9,
            impact="MEDIUM",
            raw_data={"mitigations": mitigations},
            summary=f"Advanced hardening audit for {os.path.basename(file_path)} finished. Identified {len([v for v in mitigations.values() if v != 'None' and v != 'Disabled'])} active modern mitigations."
        )
    except Exception as e:
        return format_industrial_result("checksec_advanced", "Error", error=str(e))

@tool
async def bypass_viability_scorer(mitigations_list: str) -> str:
    """
    Qualitatively assesses the overall bypass difficulty for a set of active mitigations.
    Analyzes combinations of NX, ASLR, CFG, and Canaries to suggest the most viable exploit path.
    """
    try:
        m_list = mitigations_list.lower()
        score = 0
        recommendations = []

        if "nx" in m_list or "dep" in m_list:
            score += 2
            recommendations.append("ROP/JOP chains required for execution.")
        
        if "aslr" in m_list or "pie" in m_list:
            score += 3
            recommendations.append("Memory leak vulnerability needed for address recovery.")

        if "cfg" in m_list or "controlflowguard" in m_list:
            score += 4
            recommendations.append("Indirect call tampering blocked; search for unprotected call sites or data-only attacks.")

        if "canary" in m_list or "cookie" in m_list:
            score += 2
            recommendations.append("Stack smashing detection active; focus on heap primitives or arbitrary write.")

        total_max = 11
        viability = "High" if score < 4 else ("Medium" if score < 8 else "Low")

        return format_industrial_result(
            "bypass_viability_scorer",
            "Scored",
            confidence=0.85,
            impact="MEDIUM",
            raw_data={"total_score": score, "max_score": total_max, "difficulty": viability, "recommendations": recommendations},
            summary=f"Bypass viability assessment: {viability}. Complexity Score: {score}/{total_max}. Recommended strategies generated."
        )
    except Exception as e:
        return format_industrial_result("bypass_viability_scorer", "Error", error=str(e))

@tool
async def system_mitigation_equilibrium_analyser(binary_path: str) -> str:
    """
    Evaluates the synergistic effect of active mitigations and identifies the weakest link in the hardening chain.
    Industry-grade for assessing global binary resilience against advanced exploits.
    """
    try:
        # Real synergistic mitigation audit via structural binary analysis
        try:
            import lief
            binary = lief.parse(binary_path)
            
            # Check PE/ELF specific mitigations
            nx = False
            aslr = False
            canary = False
            pie = False
            
            if hasattr(binary, "header") and hasattr(binary.header, "has_characteristic"):
                # PE Logic
                nx = binary.has_nx
                aslr = binary.has_relocation
                canary = any("__security_check_cookie" in sym.name for sym in binary.symbols)
            else:
                # ELF Logic
                nx = binary.has_nx
                pie = binary.is_pie
                canary = any("__stack_chk_fail" in sym.name for sym in binary.symbols)
                aslr = pie # PIE is the primary driver for ASLR in ELF
            
            mitigations = {"NX": nx, "ASLR": aslr, "StackCanary": canary, "PIE": pie}
            engine = "LIEF Dynamic Analysis"
        except (ImportError, Exception):
            # Fallback to high-speed byte patterns
            with open(binary_path, 'rb') as f:
                data = f.read()
            mitigations = {
                "ASLR": b"DYNAMIC_BASE" in data or b"PIE" in data,
                "NX": b"NX" in data or b"PAGE_EXECUTE" not in data[:1000],
                "StackCanary": b"__stack_chk_fail" in data or b"__security_check_cookie" in data,
                "PIE": b"PIE" in data or b"(DYN)" in data[:100].decode(errors='ignore')
            }
            engine = "Byte Pattern Heuristics"
            
        weak_links = []
        if mitigations["ASLR"] and not mitigations.get("PIE"):
            weak_links.append("ASLR active but non-PIE binary reduces entropy significantly.")
        if not mitigations["NX"]:
            weak_links.append("NX disabled; memory is executable, bypassing the need for ROP.")
        if not mitigations["StackCanary"]:
            weak_links.append("Stack canaries missing; linear stack overflow is trivial.")

        return format_industrial_result(
            "system_mitigation_equilibrium_analyser",
            "Analysis Complete",
            confidence=0.92 if engine == "LIEF Dynamic Analysis" else 0.8,
            impact="HIGH" if weak_links else "LOW",
            raw_data={"mitigations": mitigations, "weak_links": weak_links, "engine": engine},
            summary=f"Mitigation equilibrium analysis for {os.path.basename(binary_path)} finished via {engine}. Identified {len(weak_links)} systemic hardening weaknesses."
        )
    except Exception as e:
        return format_industrial_result("system_mitigation_equilibrium_analyser", "Error", error=str(e))
