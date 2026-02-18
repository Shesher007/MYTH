import os
import tempfile
import shutil
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import mimetypes
import logging
from datetime import datetime
import hashlib

from fastapi import UploadFile, HTTPException
import aiofiles
from myth_config import load_dotenv
load_dotenv()
from .document_processor import DocumentProcessor
from .vector_store import VectorStoreManager

logger = logging.getLogger(__name__)

class FileUploader:
    """Handles file uploads and processing"""
    
    def __init__(self, upload_dir: str = "uploads", 
                 vector_store_manager: Optional[VectorStoreManager] = None):
        
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(exist_ok=True)
        
        self.vector_store = vector_store_manager or VectorStoreManager()
        self.document_processor = DocumentProcessor()
        
        self.state_file = self.upload_dir / "uploader_state.json"
        self.uploaded_files = self._load_state()
        
    def _load_state(self) -> Dict[str, Any]:
        """Load uploader state from JSON"""
        if self.state_file.exists():
            try:
                import json
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load uploader state: {e}")
        return {}

    def _save_state(self):
        """Save uploader state to JSON"""
        try:
            import json
            with open(self.state_file, 'w') as f:
                json.dump(self.uploaded_files, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save uploader state: {e}")
        
    async def save_uploaded_file(self, file: UploadFile, 
                                collection_name: str = "default",
                                metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """Save uploaded file and process it"""
        
        try:
            # Create safe filename
            original_filename = file.filename or "uploaded_file"
            safe_filename = self._make_filename_safe(original_filename)
            
            # Generate unique file path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_filename = f"{timestamp}_{safe_filename}"
            file_path = self.upload_dir / unique_filename
            
            # Save file
            async with aiofiles.open(file_path, 'wb') as f:
                content = await file.read()
                await f.write(content)
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Prepare metadata
            file_metadata = {
                "original_filename": original_filename,
                "uploaded_filename": unique_filename,
                "upload_time": datetime.now().isoformat(),
                "file_size": os.path.getsize(file_path),
                "content_type": file.content_type,
                "file_hash": file_hash
            }
            
            if metadata:
                file_metadata.update(metadata)
            
            # Add to vector store (Async)
            result = await self.vector_store.add_documents(
                collection_name=collection_name,
                file_path=str(file_path),
                metadata_override=file_metadata
            )
            
            if result["success"]:
                # Store file info
                self.uploaded_files[file_hash] = {
                    "file_path": str(file_path),
                    "metadata": file_metadata,
                    "collection": collection_name,
                    "processed": True
                }
                self._save_state()
                
                return {
                    "success": True,
                    "message": f"File uploaded and processed successfully",
                    "file_info": {
                        "original_name": original_filename,
                        "saved_as": unique_filename,
                        "file_hash": file_hash,
                        "file_size": file_metadata["file_size"],
                        "chunks_added": result["documents_added"]
                    },
                    "collection": collection_name,
                    "result": result
                }
            else:
                return {
                    "success": False,
                    "error": f"Failed to process file: {result.get('error', 'Unknown error')}",
                    "file_info": file_metadata
                }
        
        except Exception as e:
            logger.error(f"File upload failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _make_filename_safe(self, filename: str) -> str:
        """Make filename safe for storage"""
        # Remove path separators
        filename = os.path.basename(filename)
        
        # Replace unsafe characters
        safe_chars = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        safe_filename = ''.join(c for c in filename if c in safe_chars)
        
        # Limit length
        if len(safe_filename) > 100:
            name, ext = os.path.splitext(safe_filename)
            safe_filename = name[:95] + ext
        
        return safe_filename or "uploaded_file"
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def get_file_info(self, file_hash: str) -> Optional[Dict]:
        """Get information about uploaded file"""
        return self.uploaded_files.get(file_hash)
    
    def list_uploaded_files(self) -> List[Dict]:
        """List all uploaded files"""
        return [
            {
                "hash": hash_val,
                "info": info
            }
            for hash_val, info in self.uploaded_files.items()
        ]
    
    async def delete_file(self, file_hash: str) -> Dict[str, Any]:
        """Delete uploaded file and remove from vector store"""
        try:
            if file_hash not in self.uploaded_files:
                return {"success": False, "error": "File not found"}
            
            file_info = self.uploaded_files[file_hash]
            file_path = Path(file_info["file_path"])
            
            # Delete from vector store
            vector_delete_success = False
            vector_error = None
            try:
                delete_result = await self.vector_store.delete_documents(
                    collection_name=file_info["collection"],
                    file_hash=file_hash
                )
                if delete_result.get("success"):
                    vector_delete_success = True
                else:
                    vector_error = delete_result.get("error")
            except Exception as ve:
                vector_error = str(ve)
                logger.warning(f"Vector deletion failed: {ve}")

            # Delete physical file
            if file_path.exists():
                file_path.unlink()
            
            # Remove from tracking
            del self.uploaded_files[file_hash]
            self._save_state()
            
            return {
                "success": True,
                "message": "File deleted successfully" + (" (Vector data retained)" if vector_error else ""),
                "vector_store_deletion": {"success": vector_delete_success, "error": vector_error},
                "file_hash": file_hash
            }
        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def process_existing_file(self, file_path: str, 
                            collection_name: str = "default",
                            metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """Process an existing file on disk"""
        
        if not os.path.exists(file_path):
            return {"success": False, "error": "File does not exist"}
        
        try:
            # Calculate hash
            file_hash = self._calculate_file_hash(Path(file_path))
            
            # Prepare metadata
            file_metadata = {
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "file_size": os.path.getsize(file_path),
                "file_hash": file_hash,
                "processed_time": datetime.now().isoformat()
            }
            
            if metadata:
                file_metadata.update(metadata)
            
            # Add to vector store (Async)
            result = await self.vector_store.add_documents(
                collection_name=collection_name,
                file_path=file_path,
                metadata_override=file_metadata
            )
            
            if result["success"]:
                # Store file info
                self.uploaded_files[file_hash] = {
                    "file_path": file_path,
                    "metadata": file_metadata,
                    "collection": collection_name,
                    "processed": True
                }
                self._save_state()
                
                return {
                    "success": True,
                    "message": "File processed successfully",
                    "file_info": file_metadata,
                    "result": result
                }
            else:
                return {
                    "success": False,
                    "error": result.get("error", "Unknown error")
                }
        
        except Exception as e:
            return {"success": False, "error": str(e)}
