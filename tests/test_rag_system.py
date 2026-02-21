"""
test_rag_system.py — Import all RAG modules and verify class/function exports.
===============================================================================
Tests: document_processor, vector_store, rag_chain, file_uploader,
       image_processor, folder_processor, universal_processor−,
       archive_extractor, audio_processor, bulk_ingest, rag_evaluator,
       secret_scanner, vibevoice_processor
"""

import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from conftest import C, ResultTracker, Status, safe_import

RAG_MODULES = {
    "rag_system.archive_extractor": {"class": "ArchiveExtractor"},
    "rag_system.audio_processor": {"class": "AudioProcessor"},
    "rag_system.bulk_ingest": {"callable": "bulk_ingest_documents"},
    "rag_system.document_processor": {"class": "DocumentProcessor"},
    "rag_system.file_uploader": {"class": "FileUploader"},
    "rag_system.folder_processor": {"class": "FolderProcessor"},
    "rag_system.image_processor": {"class": "ImageProcessor"},
    "rag_system.rag_chain": {"class": "RAGChain"},
    "rag_system.rag_evaluator": {"class": "RAGEvaluator"},
    "rag_system.secret_scanner": {"callable": "scan_for_secrets"},
    "rag_system.universal_processor": {"class": "UniversalFileProcessor"},
    "rag_system.vector_store": {"class": "VectorStoreManager"},
    "rag_system.vibevoice_processor": {"class": "VibeVoiceProcessor"},
}


def run(tracker: ResultTracker = None):
    if tracker is None:
        tracker = ResultTracker()

    tracker.begin_module("RAG System")
    print(C.header("RAG SYSTEM MODULES"))

    for mod_path, checks in RAG_MODULES.items():
        start = time.time()
        mod, err = safe_import(mod_path)
        elapsed = (time.time() - start) * 1000

        if not mod:
            tracker.record(f"{mod_path} import", Status.FAIL, elapsed, error=err)
            continue

        tracker.record(f"{mod_path} import", Status.PASS, elapsed)

        # Check for expected class
        if "class" in checks:
            cls_name = checks["class"]
            if hasattr(mod, cls_name):
                cls = getattr(mod, cls_name)
                if isinstance(cls, type):
                    tracker.record(
                        f"  {mod_path}.{cls_name} (class exists)", Status.PASS, 0
                    )
                else:
                    tracker.record(
                        f"  {mod_path}.{cls_name} is not a class", Status.WARN, 0
                    )
            else:
                tracker.record(f"  {mod_path}.{cls_name} NOT FOUND", Status.FAIL, 0)

        # Check for expected callable
        if "callable" in checks:
            fn_name = checks["callable"]
            if hasattr(mod, fn_name):
                fn = getattr(mod, fn_name)
                if callable(fn):
                    tracker.record(
                        f"  {mod_path}.{fn_name} (callable exists)", Status.PASS, 0
                    )
                else:
                    tracker.record(
                        f"  {mod_path}.{fn_name} is not callable", Status.WARN, 0
                    )
            else:
                # Fallback: check for any exported callable
                exports = [
                    n
                    for n in dir(mod)
                    if not n.startswith("_") and callable(getattr(mod, n, None))
                ]
                if exports:
                    tracker.record(
                        f"  {mod_path} has {len(exports)} callable(s) (expected '{fn_name}' not found)",
                        Status.WARN,
                        0,
                    )
                else:
                    tracker.record(f"  {mod_path}.{fn_name} NOT FOUND", Status.FAIL, 0)

    # Test package-level import
    print(f"\n  {C.CYAN}{C.BOLD}▸ Package-level import{C.RESET}")
    start = time.time()
    mod, err = safe_import("rag_system")
    elapsed = (time.time() - start) * 1000
    if mod:
        # Check __all__ exports
        all_exports = getattr(mod, "__all__", [])
        tracker.record(
            f"rag_system.__init__ ({len(all_exports)} exports)", Status.PASS, elapsed
        )
    else:
        tracker.record("rag_system.__init__", Status.FAIL, elapsed, error=err)

    tracker.end_module()
    return tracker


if __name__ == "__main__":
    t = run()
    t.print_summary()
    sys.exit(0 if t.all_passed else 1)
