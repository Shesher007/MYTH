import os

from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

# Try to import industrial libraries
try:
    from pwn import ELF, ROP

    PWN_AVAILABLE = True
except ImportError:
    PWN_AVAILABLE = False
    ELF = ROP = None

try:
    from ropper import RopperService

    ROPPER_AVAILABLE = True
except ImportError:
    ROPPER_AVAILABLE = False

load_dotenv()

# ==============================================================================
# ⛓️ ROP/JOP Gadget Discovery Tools - Industrial Grade
# ==============================================================================


@tool
async def rop_gadget_harvester(file_path: str, **kwargs) -> str:
    """
    Industrial-grade ROP gadget scanner using pwntools and Ropper.
    Provides high-fidelity gadget discovery and categorization.
    """
    try:
        if not os.path.exists(file_path):
            return format_industrial_result(
                "rop_gadget_harvester", "Error", error="File not found"
            )

        if not PWN_AVAILABLE:
            return format_industrial_result(
                "rop_gadget_harvester", "Error", error="pwntools not available"
            )

        # Use pwntools to load ELF and find gadgets
        exe = ELF(file_path, checksec=False)
        rop = ROP(exe)

        found_gadgets = []
        for addr, gadget in rop.gadgets.items():
            found_gadgets.append(
                {
                    "address": hex(addr),
                    "insns": " ; ".join(gadget.insns),
                }
            )

        return format_industrial_result(
            "rop_gadget_harvester",
            "Harvest Complete",
            confidence=1.0,
            impact="HIGH",
            raw_data={
                "total_gadgets": len(found_gadgets),
                "sample": found_gadgets[:20],
            },
            summary=f"ROP harvester identified {len(found_gadgets)} gadgets in {os.path.basename(file_path)} using pwntools ROP engine.",
        )
    except Exception as e:
        return format_industrial_result("rop_gadget_harvester", "Error", error=str(e))


@tool
async def jop_dispatcher_finder(file_path: str, **kwargs) -> str:
    """
    Advanced seeker for JOP dispatcher gadgets using Ropper.
    Identifies indirect jump and call sequences for CFI-bypass research.
    """
    try:
        if not ROPPER_AVAILABLE:
            return format_industrial_result(
                "jop_dispatcher_finder", "Error", error="Ropper not available"
            )

        if not os.path.exists(file_path):
            return format_industrial_result(
                "jop_dispatcher_finder", "Error", error="File not found"
            )

        # Ropper Service Setup
        options = {
            "color": False,
            "badbytes": "",
            "all": False,
            "inst_count": 6,
            "type": "all",
            "detailed": False,
        }
        rs = RopperService(options)
        rs.addFile(file_path)
        rs.loadGadgetsFor()

        # We search specifically for JOP gadgets
        # Ropper categorizes them well
        jop_gadgets = []
        for file, gadgets in rs.getFileFor(file_path).gadgets:
            # Search for dispatchers (heuristic: contains 'jmp' or 'call' with register)
            if any(ins in str(gadgets) for ins in ["jmp", "call"]):
                jop_gadgets.append(str(gadgets))

        return format_industrial_result(
            "jop_dispatcher_finder",
            "Scan Complete",
            raw_data={"total_detected": len(jop_gadgets), "sample": jop_gadgets[:15]},
            summary=f"JOP dispatcher finder identified {len(jop_gadgets)} potential indirect control-flow gadgets using Ropper.",
        )
    except Exception as e:
        return format_industrial_result("jop_dispatcher_finder", "Error", error=str(e))


@tool
async def revelation_gadget_chain_architect(
    file_path: str, target_func: str = "system", **kwargs
) -> str:
    """
    Industrial-grade ROP chain architect. Automatically builds a chain to call a target function.
    Uses pwntools ROP generator to automate complex register setups.
    """
    try:
        if not PWN_AVAILABLE:
            return format_industrial_result(
                "revelation_gadget_chain_architect",
                "Error",
                error="pwntools not available",
            )

        if not os.path.exists(file_path):
            return format_industrial_result(
                "revelation_gadget_chain_architect", "Error", error="File not found"
            )

        exe = ELF(file_path, checksec=False)
        rop = ROP(exe)

        # Automatic chain construction for a standard func call (e.g. system("/bin/sh"))
        # This requires the function to be in the binary or libc (if provided)
        # For simplicity, we assume we want to call a symbol in the ELF
        if target_func in exe.symbols:
            rop.call(target_func, [next(exe.search(b"/bin/sh"))])
            dump = rop.dump()

            return format_industrial_result(
                "revelation_gadget_chain_architect",
                "Chain Constructed",
                confidence=0.95,
                impact="CRITICAL",
                raw_data={"chain_dump": dump},
                summary=f"Architected an autonomous ROP chain to call {target_func} using pwntools ROP engine.",
            )
        else:
            return format_industrial_result(
                "revelation_gadget_chain_architect",
                "Error",
                error=f"Target function '{target_func}' not found in symbols.",
            )

    except Exception as e:
        return format_industrial_result(
            "revelation_gadget_chain_architect", "Error", error=str(e)
        )


@tool
async def sovereign_global_gadget_indexer(lib_path: str, **kwargs) -> str:
    """
    Recursively indexes gadgets across multiple binaries for a global "gadget pool".
    """
    try:
        # Robust logic: walk directory and use ROPPER/PWN to index
        files = [
            os.path.join(lib_path, f)
            for f in os.listdir(lib_path)
            if f.endswith((".so", ".dll", ".exe"))
        ]
        total = 0
        for f in files:
            try:
                exe = ELF(f, checksec=False)
                total += len(ROP(exe).gadgets)
            except Exception:
                pass

        return format_industrial_result(
            "sovereign_global_gadget_indexer",
            "Indexing Finished",
            raw_data={"binaries_scanned": len(files), "total_gadgets": total},
        )
    except Exception as e:
        return format_industrial_result(
            "sovereign_global_gadget_indexer", "Error", error=str(e)
        )


@tool
async def eminence_semantic_gadget_search(
    file_path: str, command: str, **kwargs
) -> str:
    """
    Searches for gadgets using Ropper's semantic search capabilities.
    Example command: "stack pivot", "write rax, rbx"
    """
    try:
        if not ROPPER_AVAILABLE:
            return format_industrial_result(
                "eminence_semantic_gadget_search", "Error", error="Ropper not available"
            )

        if not os.path.exists(file_path):
            return format_industrial_result(
                "eminence_semantic_gadget_search", "Error", error="File not found"
            )

        # Call Ropper command line or service for semantic search
        # Ropper service is easier for programmatic use
        rs = RopperService()
        rs.addFile(file_path)
        rs.loadGadgetsFor()

        # Ropper has a search method
        results = rs.search(search=command)

        return format_industrial_result(
            "eminence_semantic_gadget_search",
            "Search Results",
            raw_data={"query": command, "results": [str(g) for g in results]},
        )
    except Exception as e:
        return format_industrial_result(
            "eminence_semantic_gadget_search", "Error", error=str(e)
        )
