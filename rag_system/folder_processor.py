import os
import shutil
import tempfile
import hashlib
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator, Tuple
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .document_processor import DocumentProcessor
from .archive_extractor import ArchiveExtractor
from .universal_processor import UniversalFileProcessor
import asyncio
from myth_config import load_dotenv
load_dotenv()
logger = logging.getLogger(__name__)

class FolderProcessor:
    """
    Process entire folders recursively with smart filtering and parallel processing
    """
    
    def __init__(self, 
                 max_workers: int = 4,
                 max_file_size: int = 100 * 1024 * 1024,  # 100MB
                 max_depth: int = 5,
                 vector_store: Optional[Any] = None):
        # NOTE: temp_dir removed - was unused. Any temporary files should use tempfile.TemporaryDirectory()
        self.max_workers = max_workers
        self.max_file_size = max_file_size
        self.max_depth = max_depth
        self.vector_store = vector_store
        
        # Initialize processors
        self.doc_processor = DocumentProcessor()
        self.archive_extractor = ArchiveExtractor()
        self.universal_processor = UniversalFileProcessor()
        
        # Default ignore patterns (like .gitignore)
        self.ignore_patterns = [
            # Version control
            '.git/', '.svn/', '.hg/', '.bzr/', '.vscode/', '.idea/',
            # OS and editor files
            '.DS_Store', 'Thumbs.db', 'desktop.ini',
            '*.swp', '*.swo', '*.pyc', '*.pyo', '__pycache__/',
            'node_modules/', '.npm/', '.yarn/', 'bower_components/',
            # Virtual environments
            'venv/', 'env/', '.env', '.venv/', 'virtualenv/',
            # Build artifacts
            'build/', 'dist/', '*.egg-info/', '*.egg', '*.so', '*.dll',
            '*.exe', '*.bin', '*.class', '*.jar', '*.war',
            # Logs and temp files
            '*.log', '*.tmp', '*.temp', '*.cache',
            # Large binary files (adjust as needed)
            '*.iso', '*.img', '*.vmdk', '*.vdi', '*.qcow2',
            # Media files (large)
            '*.mp4', '*.avi', '*.mov', '*.mkv', '*.wmv',
            '*.mp3', '*.wav', '*.flac', '*.aac',
            # System files
            '/proc/', '/sys/', '/dev/', '/run/',
            # Security-sensitive
            '*.pem', '*.key', '*.crt', '*.pfx', '*.p12', 'id_rsa', 'id_dsa'
        ]
        
        # File categories for organized processing
        self.file_categories = {
            'code': ['.py', '.js', '.java', '.cpp', '.c', '.cs', '.go', 
                    '.rs', '.php', '.rb', '.pl', '.sh', '.ps1', '.bat',
                    '.sql', '.html', '.css', '.xml', '.json', '.yaml', 
                    '.yml', '.toml', '.ini', '.cfg', '.conf'],
            
            'document': ['.txt', '.md', '.rst', '.pdf', '.docx', '.doc',
                        '.pptx', '.ppt', '.odt', '.rtf', '.tex'],
            
            'data': ['.csv', '.tsv', '.xlsx', '.xls', '.ods', '.jsonl',
                    '.parquet', '.feather', '.h5', '.hdf5'],
            
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
                     '.tif', '.webp', '.svg', '.ico', '.heic'],
            
            'archive': ['.zip', '.tar', '.gz', '.bz2', '.xz', '.7z',
                       '.rar', '.tgz', '.tbz2', '.txz', '.zst'],
            
            'executable': ['.exe', '.dll', '.so', '.dylib', '.bin',
                          '.app', '.apk', '.deb', '.rpm', '.msi'],
            
            'config': ['.env', '.config', '.properties', '.settings',
                      '.gitignore', '.dockerignore', '.editorconfig'],
            
            'log': ['.log', '.txt.log', '.error', '.out'],
            
            'network': ['.pcap', '.pcapng', '.har', '.curl'],
            
            'security': ['.pem', '.crt', '.key', '.csr', '.pfx', '.p12',
                        '.jks', '.keystore', '.cert', '.cer']
        }
    
    def should_ignore(self, file_path: Path) -> bool:
        """
        Check if file should be ignored based on patterns
        """
        path_str = str(file_path)
        
        # Check against ignore patterns
        for pattern in self.ignore_patterns:
            if pattern.endswith('/'):
                # Directory pattern
                if pattern[:-1] in path_str:
                    return True
            elif pattern.startswith('*'):
                # Wildcard pattern
                if file_path.match(pattern):
                    return True
            else:
                # Exact match pattern
                if pattern in path_str:
                    return True
        
        # Check file size
        try:
            if file_path.is_file() and file_path.stat().st_size > self.max_file_size:
                logger.warning(f"Ignoring large file: {file_path} ({file_path.stat().st_size} bytes)")
                return True
        except:
            pass
        
        return False
    
    def scan_folder(self, folder_path: str, 
                   recursive: bool = True) -> Dict[str, Any]:
        """
        Scan folder and return file statistics
        """
        folder = Path(folder_path)
        
        if not folder.exists() or not folder.is_dir():
            return {"error": f"Invalid folder: {folder_path}"}
        
        statistics = {
            "folder_path": str(folder.absolute()),
            "total_files": 0,
            "total_size": 0,
            "by_category": {},
            "by_extension": {},
            "files": [],
            "ignored_files": [],
            "scan_time": datetime.now().isoformat()
        }
        
        # Walk through folder
        for root, dirs, files in os.walk(folder):
            # Industry Grade: Recursion depth safety
            rel_path = Path(root).relative_to(folder)
            if len(rel_path.parts) >= self.max_depth:
                logger.warning(f"⚠️ [FOLDER] Max depth reached at {root}. Skipping subdirectories.")
                dirs[:] = []
                continue

            # Skip ignored directories
            dirs[:] = [d for d in dirs if not self.should_ignore(Path(root) / d)]
            
            for file_name in files:
                file_path = Path(root) / file_name
                
                if self.should_ignore(file_path):
                    statistics["ignored_files"].append(str(file_path))
                    continue
                
                try:
                    # Leverage industrial type detection
                    file_type_info = self.universal_processor.detect_file_type(str(file_path))
                    category = file_type_info.get("category", "unknown")
                    extension = file_type_info.get("extension", file_path.suffix.lower() or "no_ext")
                    
                    file_stat = file_path.stat()
                    
                    # Update statistics
                    statistics["total_files"] += 1
                    statistics["total_size"] += file_stat.st_size
                    
                    # Track Category
                    if category not in statistics["by_category"]:
                        statistics["by_category"][category] = 0
                    statistics["by_category"][category] += 1
                    
                    # Track Extension
                    if extension not in statistics["by_extension"]:
                        statistics["by_extension"][extension] = 0
                    statistics["by_extension"][extension] += 1
                    
                    statistics["files"].append({
                        "path": str(file_path.absolute()),
                        "name": file_name,
                        "size": file_stat.st_size,
                        "category": category,
                        "modified": file_stat.st_mtime
                    })
                    
                except Exception as e:
                    logger.warning(f"Failed to analyze {file_path}: {e}")
        
        return statistics
    

    async def aprocess_folder(self, 
                              folder_path: str,
                              collection_name: str = "folder_documents",
                              recursive: bool = True,
                              process_archives: bool = True,
                              extract_text_only: bool = False,
                              skip_categories: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Asynchronously process entire folder
        """
        scan_result = self.scan_folder(folder_path, recursive)
        if "error" in scan_result:
            return {"success": False, "error": scan_result["error"]}

        files_to_process = [f for f in scan_result["files"] 
                           if (not skip_categories or f["category"] not in skip_categories) and
                           (process_archives or f["category"] != "archive") and
                           (not extract_text_only or f["category"] != "executable")]

        results = {
            "success": True,
            "folder": folder_path,
            "collection": collection_name,
            "processing_start": datetime.now().isoformat(),
            "processed_files": 0,
            "failed_files": [],
            "total_chunks_added": 0
        }

        async def process_with_limit(file_info, semaphore):
            async with semaphore:
                return await self._process_single_file(file_info["path"], collection_name, extract_text_only)

        semaphore = asyncio.Semaphore(self.max_workers)
        tasks = [process_with_limit(f, semaphore) for f in files_to_process]
        
        for coro in asyncio.as_completed(tasks):
            try:
                res = await coro
                if res["success"]:
                    results["processed_files"] += 1
                    results["total_chunks_added"] += res.get("chunks_added", 0)
                else:
                    results["failed_files"].append({"file": res.get("file"), "error": res.get("error")})
            except Exception as e:
                results["failed_files"].append({"error": str(e)})

        results["processing_end"] = datetime.now().isoformat()
        return results
    
    async def _process_single_file(self, 
                           file_path: str,
                           collection_name: str,
                           extract_text_only: bool = False) -> Dict[str, Any]:
        """
        Process a single file (internal method for parallel processing)
        """
        try:
            file_path_obj = Path(file_path)
            
            # Handle archives
            if self.categorize_file(file_path_obj) == "archive":
                return await self._process_archive_file(file_path, collection_name)
            
            # Handle regular files
            if extract_text_only:
                # Extract text content only
                content = self._extract_text_content(file_path)
                
                if content:
                    metadata = {
                        "file_name": file_path_obj.name,
                        "file_path": file_path,
                        "file_size": file_path_obj.stat().st_size,
                        "category": self.categorize_file(file_path_obj),
                        "processed_as": "text_extraction"
                    }
                    
                    # Create document from extracted text
                    from langchain_core.documents import Document
                    document = Document(
                        page_content=content[:10000],  # Limit content
                        metadata=metadata
                    )
                    
                    return {
                        "success": True,
                        "file": file_path,
                        "chunks_added": 1,
                        "processing_method": "text_extraction"
                    }
            
            # Use document processor
            documents = await self.doc_processor.process_document(file_path)
            
            if not documents:
                return {
                    "success": False,
                    "error": "No documents extracted",
                    "file": file_path
                }
            
            # Add to vector store if available
            chunks_added = 0
            if self.vector_store:
                try:
                    result = await self.vector_store.add_documents(
                        collection_name=collection_name,
                        file_path=file_path
                    )
                    if result.get("success"):
                        chunks_added = result.get("documents_added", 0)
                except Exception as e:
                    logger.error(f"Failed to add to vector store during folder process: {e}")
            
            return {
                "success": True,
                "file": file_path,
                "chunks_added": chunks_added or len(documents),
                "documents": len(documents),
                "processing_method": "document_processor"
            }
        
        except Exception as e:
            logger.error(f"Failed to process {file_path}: {e}")
            return {
                "success": False,
                "error": str(e),
                "file": file_path
            }
    
    async def _process_archive_file(self, 
                            archive_path: str,
                            collection_name: str) -> Dict[str, Any]:
        """
        Extract and process archive contents
        """
        try:
            # Extract archive
            extract_result = self.archive_extractor.extract_archive(archive_path)
            
            if not extract_result["success"]:
                return extract_result
            
            # Process extracted files
            total_chunks = 0
            processed_files = []
            failed_files = []
            
            for extracted_file in extract_result.get("files", []):
                if os.path.isfile(extracted_file):
                    # Recursively process extracted file
                    file_result = await self._process_single_file(
                        extracted_file,
                        collection_name
                    )
                    
                    if file_result["success"]:
                        total_chunks += file_result.get("chunks_added", 0)
                        processed_files.append(extracted_file)
                    else:
                        failed_files.append({
                            "file": extracted_file,
                            "error": file_result.get("error")
                        })
            
            # Cleanup extracted files
            try:
                extract_dir = Path(extract_result.get("extracted_path", ""))
                if extract_dir.exists():
                    shutil.rmtree(extract_dir)
            except:
                pass
            
            return {
                "success": True,
                "archive": archive_path,
                "chunks_added": total_chunks,
                "extracted_files": len(processed_files),
                "processed_files": processed_files,
                "failed_files": failed_files,
                "archive_type": extract_result.get("archive_type")
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "archive": archive_path
            }
    
    def _extract_text_content(self, file_path: str, 
                            max_length: int = 10000) -> str:
        """
        Extract text content from any file (fallback method)
        """
        try:
            file_path_obj = Path(file_path)
            suffix = file_path_obj.suffix.lower()
            
            # Text files
            if suffix in ['.txt', '.md', '.rst', '.log']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read(max_length)
            
            # Code files
            elif suffix in self.file_categories['code']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read(max_length)
            
            # Config files
            elif suffix in self.file_categories['config']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read(max_length)
            
            # Binary files - try to extract strings
            else:
                strings = self.universal_processor.extract_strings(file_path)
                return "\n".join(strings[:100])  # First 100 strings
        
        except Exception as e:
            logger.warning(f"Text extraction failed for {file_path}: {e}")
            return ""
    
    def create_folder_summary(self, folder_path: str) -> Dict[str, Any]:
        """
        Create a comprehensive summary of folder contents
        """
        scan_result = self.scan_folder(folder_path)
        
        if "error" in scan_result:
            return scan_result
        
        summary = {
            "folder": folder_path,
            "total_files": scan_result["total_files"],
            "total_size": scan_result["total_size"],
            "size_human": self._humanize_size(scan_result["total_size"]),
            "categories": scan_result["by_category"],
            "top_extensions": dict(sorted(
                scan_result["by_extension"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "largest_files": [],
            "recent_files": [],
            "security_analysis": self._analyze_folder_security(scan_result["files"]),
            "scan_time": scan_result["scan_time"]
        }
        
        # Find largest files
        sorted_by_size = sorted(
            scan_result["files"],
            key=lambda x: x["size"],
            reverse=True
        )[:10]
        
        for file_info in sorted_by_size:
            summary["largest_files"].append({
                "name": file_info["name"],
                "size": file_info["size"],
                "size_human": self._humanize_size(file_info["size"]),
                "category": file_info["category"]
            })
        
        # Find most recent files
        sorted_by_mtime = sorted(
            scan_result["files"],
            key=lambda x: x["modified"],
            reverse=True
        )[:10]
        
        for file_info in sorted_by_mtime:
            summary["recent_files"].append({
                "name": file_info["name"],
                "modified": datetime.fromtimestamp(file_info["modified"]).isoformat(),
                "category": file_info["category"]
            })
        
        return summary
    
    def _humanize_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
    
    def _analyze_folder_security(self, files: List[Dict]) -> Dict[str, Any]:
        """
        Perform security analysis on folder contents
        """
        analysis = {
            "sensitive_files": [],
            "executables": [],
            "config_files": [],
            "log_files": [],
            "potential_issues": []
        }
        
        sensitive_patterns = [
            ('password', 'Contains password reference'),
            ('secret', 'Contains secret reference'),
            ('key', 'Contains key reference'),
            ('token', 'Contains token reference'),
            ('credential', 'Contains credential reference'),
            ('.env', 'Environment file'),
            ('.pem', 'Private key file'),
            ('.key', 'Encryption key file'),
            ('id_rsa', 'SSH private key'),
            ('.git/config', 'Git configuration'),
        ]
        
        for file_info in files:
            file_name = file_info["name"].lower()
            file_path = file_info["path"].lower()
            
            # Check for sensitive files
            for pattern, description in sensitive_patterns:
                if pattern in file_name or pattern in file_path:
                    analysis["sensitive_files"].append({
                        "file": file_info["path"],
                        "pattern": pattern,
                        "description": description
                    })
                    break
            
            # Categorize files
            if file_info["category"] == "executable":
                analysis["executables"].append(file_info["path"])
            
            elif file_info["category"] == "config":
                analysis["config_files"].append(file_info["path"])
            
            elif file_info["category"] == "log":
                analysis["log_files"].append(file_info["path"])
        
        # Check for potential issues
        if len(analysis["sensitive_files"]) > 0:
            analysis["potential_issues"].append(
                f"Found {len(analysis['sensitive_files'])} potentially sensitive files"
            )
        
        if len(analysis["executables"]) > 10:
            analysis["potential_issues"].append(
                f"Found {len(analysis['executables'])} executable files - verify legitimacy"
            )
        
        return analysis
