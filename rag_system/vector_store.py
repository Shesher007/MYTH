import os
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import logging
from datetime import datetime, timezone

from langchain_qdrant import QdrantVectorStore
from qdrant_client import QdrantClient
from qdrant_client.http import models as qdrant_models
from langchain_nvidia_ai_endpoints import NVIDIAEmbeddings
from langchain_core.documents import Document as LangchainDocument
from .document_processor import DocumentProcessor
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)
from myth_config import load_dotenv, config
from config_loader import agent_config
load_dotenv()

class VectorStoreManager:
    """Industrial-grade Vector Store Manager with Qdrant backend (RAM-Only)"""
    
    def __init__(self, nvidia_api_key: Optional[str] = None):
        
        self.nvidia_api_key = nvidia_api_key or config.get_api_key("nvidia")
        self.model_name = agent_config.models.embedding
        self._client = None
        self._client_lock = asyncio.Lock()

        if not self.nvidia_api_key:
            logger.warning("NVIDIA_API_KEY not found in rotation. RAG search will fail.")

        # Initialize embeddings using NVIDIA NIM (Exclusive)
        logger.info(f"🧬 [VECTOR] Initializing NVIDIA embeddings with model: {self.model_name}")
        
        self.embeddings = NVIDIAEmbeddings(
            model=self.model_name
        )
        logger.info("✅ [VECTOR] NVIDIA Neural Matrix Online (Qdrant)")
        
        # Initialize document processor
        self.document_processor = DocumentProcessor(
            nvidia_api_key=self.nvidia_api_key
        )
        
    def _get_client(self) -> QdrantClient:
        """Initialize Qdrant client with persistent local storage"""
        if self._client is None:
            from myth_utils.paths import get_app_data_path
            db_path = get_app_data_path("db/qdrant")
            self._client = QdrantClient(path=db_path)
        return self._client

    async def close(self):
        """Close the connection (Actually not strictly needed for local Qdrant but for consistency)"""
        if self._client:
            self._client.close()
            self._client = None
            logger.info("🔌 [VECTOR] Qdrant local storage closed.")

    def _get_vector_store(self, collection_name: str) -> QdrantVectorStore:
        """Get a QdrantVectorStore instance for a specific collection, ensuring exists"""
        client = self._get_client()
        
        # Industrial Shield: Ensure collection exists (crucial for in-memory persistence loops)
        try:
            client.get_collection(collection_name=collection_name)
        except Exception:
            logger.info(f"🆕 [VECTOR] Initializing clean collection: {collection_name}")
            client.create_collection(
                collection_name=collection_name,
                vectors_config=qdrant_models.VectorParams(
                    size=agent_config.embeddings.dimension, 
                    distance=qdrant_models.Distance.COSINE
                )
            )

        return QdrantVectorStore(
            client=client,
            collection_name=collection_name,
            embedding=self.embeddings,
        )

    async def create_collection(self, collection_name: str) -> QdrantVectorStore:
        """Initialize a Qdrant collection"""
        return self._get_vector_store(collection_name)
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def add_documents(self, collection_name: str, file_path: str, 
                         metadata_override: Optional[Dict] = None) -> Dict[str, Any]:
        """Process and add documents to vector store (Async)"""
        try:
            # Process document
            documents = await self.document_processor.process_document(file_path)
            
            if not documents:
                return {"success": False, "error": "No documents extracted"}
            
            documents = [doc for doc in documents if doc.page_content and doc.page_content.strip()]
            if not documents:
                return {"success": False, "error": "No non-empty documents extracted after filtering"}
            
            ids = []
            now_ts = datetime.now(timezone.utc).timestamp()
            for i, doc in enumerate(documents):
                file_hash = doc.metadata.get("file_hash", "none")
                chunk_id = doc.metadata.get("chunk_id", i)
                doc_id = hashlib.md5(f"{file_hash}_{chunk_id}_{now_ts}".encode()).hexdigest()
                ids.append(doc_id)
                if metadata_override:
                    doc.metadata.update(metadata_override)
                doc.metadata["ingested_at"] = datetime.now(timezone.utc).isoformat()

            vector_store = self._get_vector_store(collection_name)
            await asyncio.to_thread(vector_store.add_documents, documents=documents, ids=ids)
            
            return {
                "success": True,
                "collection": collection_name,
                "documents_added": len(documents),
                "file": file_path,
                "metadata": {
                    "file_hash": documents[0].metadata.get("file_hash"),
                    "file_name": documents[0].metadata.get("file_name"),
                    "total_chunks": len(documents)
                }
            }
        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
            return {"success": False, "error": str(e)}

    async def add_langchain_documents(self, collection_name: str, 
                                   documents: List[LangchainDocument], 
                                   ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Add raw LangChain documents directly to vector store (Async)"""
        try:
            vector_store = self._get_vector_store(collection_name)
            await asyncio.to_thread(vector_store.add_documents, documents=documents, ids=ids)
            return {"success": True, "documents_added": len(documents)}
        except Exception as e:
            logger.error(f"Failed to add langchain documents: {e}")
            return {"success": False, "error": str(e)}

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5)
    )
    async def similarity_search(self, collection_name: str, query: str, 
                             k: int = 10, filter_metadata: Optional[Dict] = None) -> List[Dict]:
        """Async similarity search"""
        try:
            vector_store = self._get_vector_store(collection_name)
            
            # Use LangChain's sync search in thread
            results = await asyncio.to_thread(
                vector_store.similarity_search_with_relevance_scores,
                query=query,
                k=k,
                filter=filter_metadata
            )
            
            formatted_results = []
            for doc, score in results:
                formatted_results.append({
                    "id": doc.metadata.get("id", "unknown"),
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "relevance_score": score
                })
            
            return formatted_results
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []

    async def list_collections(self) -> List[Dict]:
        """List all collections in the vector store"""
        try:
            client = self._get_client()
            response = client.get_collections()
            return [{"name": c.name} for c in response.collections]
        except Exception as e:
            logger.error(f"Failed to list collections: {e}")
            return []

    async def delete_documents(self, collection_name: str, 
                            file_hash: Optional[str] = None,
                            file_name: Optional[str] = None) -> Dict[str, Any]:
        """Delete documents by metadata in Qdrant"""
        try:
            client = self._get_client()
            
            filter_obj = None
            if file_hash:
                filter_obj = qdrant_models.Filter(
                    must=[qdrant_models.FieldCondition(key="metadata.file_hash", match=qdrant_models.MatchValue(value=file_hash))]
                )
            elif file_name:
                filter_obj = qdrant_models.Filter(
                    must=[qdrant_models.FieldCondition(key="metadata.file_name", match=qdrant_models.MatchValue(value=file_name))]
                )
            
            if filter_obj:
                res = client.delete(
                    collection_name=collection_name,
                    points_selector=qdrant_models.FilterSelector(filter=filter_obj)
                )
                return {"success": True, "status": "deleted_filtered"}
            else:
                # Wipe entire collection contents (delete and recreate is safer in Qdrant for full wipe)
                client.delete_collection(collection_name=collection_name)
                client.create_collection(
                    collection_name=collection_name,
                    vectors_config=qdrant_models.VectorParams(size=agent_config.embeddings.dimension, distance=qdrant_models.Distance.COSINE)
                )
                return {"success": True, "status": "collection_wiped"}
                
        except Exception as e:
            logger.error(f"Delete failed: {e}")
            return {"success": False, "error": str(e)}

    async def hybrid_search(self, collection_name: str, query: str, 
                          k: int = 10, vector_weight: float = 0.7) -> List[Dict]:
        """Advanced Hybrid Search with score fusion (Vector + Metadata Keywords)"""
        try:
            # 1. Broad Vector Search
            vector_results = await self.similarity_search(collection_name, query, k=k*3)
            
            # 2. Metadata Keyword Boost
            # We look for exact matches in filenames or secret types for pentesting boost
            keywords = query.lower().split()
            boosted_results = []
            
            for res in vector_results:
                score = res.get("relevance_score", 0.0)
                meta = res.get("metadata", {})
                
                # Boost based on security metadata
                boost = 0.0
                if meta.get("contains_secrets"): boost += 0.2
                if meta.get("is_suspicious"): boost += 0.1
                
                # Keyword matching boost
                content_lower = res["content"].lower()
                for kw in keywords:
                    if kw in content_lower: boost += 0.05
                    if kw in meta.get("file_name", "").lower(): boost += 0.1
                
                # Final fused score
                res["relevance_score"] = (score * vector_weight) + (boost * (1 - vector_weight))
                boosted_results.append(res)
            
            # Sort by fused score
            boosted_results.sort(key=lambda x: x["relevance_score"], reverse=True)
            return boosted_results[:k]
            
        except Exception as e:
            logger.error(f"Hybrid search failed: {e}")
            return await self.similarity_search(collection_name, query, k=k)

    async def add_directory(self, collection_name: str, directory_path: str, 
                         recursive: bool = True, batch_size: int = 50) -> Dict[str, Any]:
        """Ingest an entire directory of documents using FolderProcessor intelligence"""
        try:
            from .folder_processor import FolderProcessor
            fp = FolderProcessor(vector_store=self)
            
            logger.info(f"📁 [INGEST] Scanning directory: {directory_path}...")
            scan_result = fp.scan_folder(directory_path, recursive=recursive)
            
            if "error" in scan_result:
                return {"success": False, "error": scan_result["error"]}
            
            file_paths = [f["path"] for f in scan_result["files"]]
            
            if not file_paths:
                return {"success": True, "documents_added": 0, "message": "No supported files found after filtering"}

            logger.info(f"📁 [INGEST] Found {len(file_paths)} relevant files. Processing in batches...")
            
            total_chunks = 0
            vector_store = self._get_vector_store(collection_name)
            
            for i in range(0, len(file_paths), batch_size):
                batch_paths = file_paths[i:i + batch_size]
                documents = await self.document_processor.process_batch(batch_paths)
                
                if not documents:
                    continue

                batch_ids = []
                now_ts = datetime.now(timezone.utc).timestamp()
                for j, doc in enumerate(documents):
                    file_hash = doc.metadata.get("file_hash", "anon")
                    chunk_id = doc.metadata.get("chunk_id", j)
                    batch_ids.append(hashlib.md5(f"{file_hash}_{chunk_id}_{now_ts}".encode()).hexdigest())
                    doc.metadata["ingested_at"] = datetime.now(timezone.utc).isoformat()

                # Ultra Upgrade: Batch Point Insertion
                await asyncio.to_thread(vector_store.add_documents, documents=documents, ids=batch_ids)
                total_chunks += len(documents)
                logger.info(f"⚡ [INGEST] Batch {i//batch_size + 1} complete. Total chunks: {total_chunks}")
            
            return {
                "success": True,
                "collection": collection_name,
                "files_found": len(file_paths),
                "chunks_added": total_chunks,
                "security_scan": scan_result.get("security_analysis", {})
            }
        except Exception as e:
            logger.error(f"Directory ingestion failed: {e}")
            return {"success": False, "error": str(e)}

    async def get_collection_stats(self, collection_name: str) -> Dict[str, Any]:
        """Fetch Qdrant collection statistics"""
        try:
            client = self._get_client()
            # Industry Shield: Check existence before fetching info
            collections = client.get_collections().collections
            if not any(c.name == collection_name for c in collections):
                return {
                    "collection": collection_name,
                    "total_chunks": 0,
                    "status": "not_initialized",
                    "vectors_count": 0,
                    "config": "none"
                }

            info = client.get_collection(collection_name)
            
            return {
                "collection": collection_name,
                "total_chunks": info.points_count,
                "status": str(info.status),
                "vectors_count": info.vectors_count,
                "config": str(info.config)
            }
        except Exception as e:
            logger.error(f"Stats fetch failed: {e}")
            return {"error": str(e)}

