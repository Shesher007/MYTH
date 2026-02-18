import os
import sys
import logging
import asyncio
from pathlib import Path
from myth_config import load_dotenv
load_dotenv()

# Add parent directory for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rag_system.vector_store import VectorStoreManager
from config_loader import agent_config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("BULK_INGEST")

async def run_ingestion(source_dir: str, collection_name: str, recursive: bool = True):
    """
    Industrial-grade bulk ingestion leveraging parallel processing.
    """
    logger.info("🛠️  Initializing Industrial RAG Ingestion...")
    
    vsm = VectorStoreManager()
    
    try:
        source_path = Path(source_dir).absolute()
        if not source_path.exists():
            logger.error(f"❌ Source path not found: {source_path}")
            return

        logger.info(f"🚀 Processing: {source_path} -> Collection: {collection_name}")
        
        # Leverage the fortified VectorStoreManager.add_directory
        # This handles: Parallel extraction, Zip Slip protection, Metadata normalization
        result = await vsm.add_directory(
            collection_name=collection_name,
            directory_path=str(source_path),
            recursive=recursive
        )
        
        if result.get("success"):
            logger.info("✅ Ingestion Complete!")
            logger.info(f"🗂️  Files Analyzed: {result.get('files_found')}")
            logger.info(f"🧱 Chunks Indexed: {result.get('chunks_added')}")
            
            # Fetch and display stats
            stats = await vsm.get_collection_stats(collection_name)
            logger.info(f"📊 Final Collection State: {stats}")
        else:
            logger.error(f"❌ Ingestion Failed: {result.get('error')}")

    except Exception as e:
        logger.critical(f"💥 Critical Failure during ingestion: {e}")
    finally:
        await vsm.close()

if __name__ == "__main__":
    # Default to "RAG Resources"
    default_dir = os.path.join(os.getcwd(), "RAG Resources")
    path = sys.argv[1] if len(sys.argv) > 1 else default_dir
    collection = sys.argv[2] if len(sys.argv) > 2 else "myth_kb"
    
    asyncio.run(run_ingestion(path, collection))

# Alias for RAG system compatibility
bulk_ingest_documents = run_ingestion
