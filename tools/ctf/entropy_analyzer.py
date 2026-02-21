import math
import os
from collections import Counter

from langchain_core.tools import tool

from myth_config import load_dotenv
from tools.utilities.report import format_industrial_result

load_dotenv()

# ==============================================================================
# 📊 Industrial Entropy & Offset Analysis Tools
# ==============================================================================


@tool
async def file_entropy_mapper(file_path: str, chunk_size: int = 4096) -> str:
    """
    Calculates the Shannon entropy of a file across sliding windows (offsets).
    Identifies hidden encrypted blobs (entropy ~8.0) or compressed segments.
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if not os.path.exists(file_path):
            return format_industrial_result(
                "entropy_analyzer", "Error", error="File not found"
            )
        entropy_map = []

        with open(file_path, "rb") as f:
            offset = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                # Shannon Entropy Calculation
                if len(chunk) == 0:
                    entropy = 0
                else:
                    byte_counts = Counter(chunk)
                    probabilities = [
                        count / len(chunk) for count in byte_counts.values()
                    ]
                    entropy = -sum(p * math.log(p, 2) for p in probabilities)

                entropy_map.append(
                    {
                        "offset": hex(offset),
                        "entropy": round(entropy, 4),
                        "type": "Encrypted/Compressed"
                        if entropy > 7.5
                        else "Data/Code"
                        if entropy > 3.0
                        else "Sparse/Padding",
                    }
                )

                offset += chunk_size
                if len(entropy_map) > 1000:
                    break  # Safety limit for large files

        return format_industrial_result(
            "file_entropy_mapper",
            "Analysis Complete",
            confidence=1.0,
            raw_data={
                "entropy_map": entropy_map[:50],
                "total_chunks": len(entropy_map),
            },
            summary=f"Mapped Shannon entropy across {len(entropy_map)} chunks of {os.path.basename(file_path)}. Detected {len([c for c in entropy_map if c['entropy'] > 7.5])} high-entropy segments.",
        )
    except Exception as e:
        return format_industrial_result("file_entropy_mapper", "Error", error=str(e))


@tool
async def statistical_byte_distributor(file_path: str) -> str:
    """
    Analyzes the byte distribution (00-FF) of a file to identify character encoding or obfuscation schemes.
    """
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        counts = Counter()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                counts.update(chunk)

        total = sum(counts.values())
        distribution = {hex(k): round(v / total, 4) for k, v in sorted(counts.items())}

        return format_industrial_result(
            "statistical_byte_distributor",
            "Analysis Complete",
            confidence=1.0,
            raw_data={"distribution": distribution},
            summary=f"Byte distribution analysis for {os.path.basename(file_path)} finished. Processed {total} bytes.",
        )
    except Exception as e:
        return format_industrial_result(
            "statistical_byte_distributor", "Error", error=str(e)
        )
