import asyncio
import hashlib
import json
import logging
import mimetypes
import os
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

# Standard 3rd party
import exifread
import pandas as pd
from imagehash import average_hash, phash
from langchain_core.documents import Document as LangchainDocument
from PIL import Image

import backend

try:
    from langchain_text_splitters import RecursiveCharacterTextSplitter
except ImportError:
    try:
        from langchain.text_splitter import RecursiveCharacterTextSplitter
    except ImportError:
        RecursiveCharacterTextSplitter = None

# Availability checks
try:
    from unstructured.partition.auto import partition

    UNSTRUCTURED_AVAILABLE = True
except ImportError:
    partition = None
    UNSTRUCTURED_AVAILABLE = False

try:
    import pypdf

    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

from myth_config import config

from .archive_extractor import ArchiveExtractor
from .secret_scanner import SecretScanner
from .universal_processor import UniversalFileProcessor

# Security: Prevent Decompression Bomb Attacks
Image.MAX_IMAGE_PIXELS = 100_000_000  # 100MP limit

logger = logging.getLogger(__name__)


class DocumentProcessor:
    """Industrial-grade document processor with multi-format intelligence"""

    def __init__(
        self,
        nvidia_api_key: Optional[str] = None,
        mistral_api_key: Optional[str] = None,
    ):
        # NOTE: temp_dir removed - was unused. Any temporary files should use tempfile.TemporaryDirectory()
        self.nvidia_api_key = nvidia_api_key or config.get_api_key("nvidia")
        self.mistral_api_key = mistral_api_key or config.get_api_key("mistral")

        # Initialize processors
        self.universal_processor = UniversalFileProcessor()
        self.secret_scanner = SecretScanner()
        self.archive_extractor = ArchiveExtractor()

        # Performance: Singleton Thread pool for batch ingestion
        # We use a class-level executor to avoid leaking threads per instance
        if not hasattr(DocumentProcessor, "_executor"):
            DocumentProcessor._executor = ThreadPoolExecutor(
                max_workers=os.cpu_count() or 4
            )
        self.executor = DocumentProcessor._executor

        # Ultra Upgrade Components
        self.processed_cache = set()
        self.api_semaphore = asyncio.Semaphore(5)  # Throttling Shield

        self.supported_formats = {
            # Text formats
            ".txt",
            ".md",
            ".rst",
            ".json",
            ".xml",
            ".csv",
            ".yaml",
            ".yml",
            # Document formats
            ".pd",
            ".docx",
            ".doc",
            ".pptx",
            ".ppt",
            ".odt",
            ".rt",
            # Spreadsheet formats
            ".xlsx",
            ".xls",
            ".ods",
            # Image formats
            ".jpg",
            ".jpeg",
            ".png",
            ".bmp",
            ".gi",
            ".tif",
            ".ti",
            ".webp",
            ".jfi",
            # Code formats
            ".py",
            ".js",
            ".java",
            ".cpp",
            ".c",
            ".html",
            ".css",
            ".php",
            ".rb",
            ".go",
            ".rs",
            ".sh",
            ".ps1",
            ".sql",
            # Network formats
            ".pcap",
            ".pcapng",
            ".har",
            # Audio formats
            ".mp3",
            ".wav",
            ".flac",
            ".m4a",
            ".ogg",
            # Security formats
            ".pem",
            ".crt",
            ".key",
            ".pfx",
            ".p12",
        }

        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=2000,
            chunk_overlap=250,
            length_function=len,
            separators=["\n\n", "\n", " ", ""],
        )

    def get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash securely"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(
                lambda: f.read(65536), b""
            ):  # Larger block for speed
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    async def process_batch(
        self, file_paths: List[str], task_id: str = "batch_index"
    ) -> List[LangchainDocument]:
        """Process multiple documents in parallel using asyncio"""
        all_documents = []
        total_files = len(file_paths)
        processed_count = 0

        # Limit concurrency to avoid overloading APIs or System
        semaphore = asyncio.Semaphore(10)

        async def sem_process(path):
            async with semaphore:
                try:
                    docs = await self.process_document(path)
                    nonlocal processed_count
                    processed_count += 1

                    # Report Progress via Global Registry
                    progress = int((processed_count / total_files) * 100)
                    if backend.REGISTRY.get("progress_callback"):
                        cb = backend.REGISTRY["progress_callback"]
                        if asyncio.iscoroutinefunction(cb):
                            await cb(
                                task_id,
                                progress,
                                f"processed {processed_count}/{total_files}: {os.path.basename(path)}",
                            )
                        else:
                            cb(
                                task_id,
                                progress,
                                f"processed {processed_count}/{total_files}: {os.path.basename(path)}",
                            )

                    return docs
                except Exception as e:
                    logger.error(f"❌ Batch failure for {path}: {e}")
                    return []

        # Run all tasks
        results = await asyncio.gather(*(sem_process(path) for path in file_paths))
        for docs in results:
            all_documents.extend(docs)

        return all_documents

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract comprehensive technical metadata"""
        path = Path(file_path)
        stat = path.stat()

        metadata = {
            "file_name": path.name,
            "file_path": str(path.absolute()),
            "file_size_kb": round(stat.st_size / 1024, 2),
            "file_hash": self.get_file_hash(file_path),
            "file_type": mimetypes.guess_type(file_path)[0]
            or "application/octet-stream",
            "extension": path.suffix.lower(),
            "ingested_at": None,  # Will be set by vector store
            "created_at": stat.st_ctime,
            "modified_at": stat.st_mtime,
        }

        if path.suffix.lower() in [
            ".jpg",
            ".jpeg",
            ".png",
            ".tif",
            ".ti",
            ".jfi",
            ".webp",
        ]:
            metadata.update(self._extract_image_metadata(file_path))

        return metadata

    def _extract_image_metadata(self, image_path: str) -> Dict[str, Any]:
        """Extract EXIF and image metadata"""
        metadata = {}

        try:
            # Extract EXIF data
            with open(image_path, "rb") as f:
                tags = exifread.process_file(f)
                if tags:
                    metadata["exif"] = {}
                    for tag, value in tags.items():
                        if tag not in [
                            "JPEGThumbnail",
                            "TIFFThumbnail",
                            "Filename",
                            "EXIF MakerNote",
                        ]:
                            metadata["exif"][tag] = str(value)

            # Extract image properties
            with Image.open(image_path) as img:
                metadata["image_size"] = str(img.size)
                metadata["image_mode"] = img.mode
                metadata["image_format"] = img.format

                # Calculate perceptual hash
                metadata["perceptual_hash"] = str(phash(img))
                metadata["average_hash"] = str(average_hash(img))

        except Exception as e:
            logger.warning(f"Failed to extract image metadata: {e}")

        return metadata

    async def process_document(
        self, file_path: str, current_depth: int = 0
    ) -> List[LangchainDocument]:
        """Process ANY document type with refined routing, Session Cache, and Protection (Async)"""
        if current_depth > 5:  # Industrial base limit
            logger.warning(f"⚠️ [DOC] Max recursion depth reached for {file_path}")
            return []

        file_path = str(Path(file_path).resolve())

        # Ultra Upgrade: Session Cache (Instant Skip)
        file_hash = self.get_file_hash(file_path)
        if file_hash in self.processed_cache:
            logger.info(
                f"⏩ [SKIP] Already processed in this session: {Path(file_path).name}"
            )
            return []

        self.processed_cache.add(file_hash)

        metadata = self.extract_metadata(file_path)
        metadata["file_hash"] = file_hash  # Ensure hash is consistent
        extension = metadata["extension"]

        try:
            # specialized processors
            documents = []  # Changed 'docs' to 'documents' to accumulate all results

            if extension in [".pd", ".docx", ".pptx", ".xlsx", ".doc", ".ppt"]:
                docs = self._process_with_unstructured(file_path, metadata)
                documents.extend(docs)
            # 2. Extract Multimodal Content (Vision/Audio) with Semaphore Protect
            elif extension in {
                ".jpg",
                ".jpeg",
                ".png",
                ".webp",
                ".bmp",
                ".tif",
                ".ti",
                ".jfif",
            }:
                async with self.api_semaphore:
                    docs = await self._process_image(file_path, metadata)
                for d in docs:
                    d.metadata["source_type"] = "vision_analysis"
                documents.extend(docs)

            elif extension in {".mp3", ".wav", ".flac", ".m4a", ".ogg"}:
                async with self.api_semaphore:
                    docs = await self._process_audio(file_path, metadata)
                for d in docs:
                    d.metadata["source_type"] = "audio_transcript"
                documents.extend(docs)
            elif extension in [".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar"]:
                docs = await self._process_archive(file_path, metadata, current_depth)
                documents.extend(docs)
            elif extension in [".pcap", ".pcapng"]:
                docs = self._process_pcap(file_path, metadata)
                documents.extend(docs)
            elif extension in [".xlsx", ".xls", ".csv"]:
                docs = self._process_spreadsheet(file_path, metadata)
                documents.extend(docs)
            elif extension == ".json":
                docs = self._process_security_json(file_path, metadata)
                documents.extend(docs)
            elif extension == ".xml" or extension == ".cwe":
                docs = self._process_security_xml(file_path, metadata)
                documents.extend(docs)
            elif extension in [
                ".txt",
                ".md",
                ".json",
                ".xml",
                ".yaml",
                ".yml",
                ".py",
                ".js",
                ".java",
                ".cpp",
                ".c",
                ".html",
                ".css",
                ".sh",
                ".sql",
            ]:
                docs = self._process_with_unstructured(file_path, metadata)
                documents.extend(docs)
            else:
                docs = self.universal_processor.process_any_file(file_path, metadata)

            # CRITICAL: Multi-Stage Chunking Safety
            # Ensure NO chunk from any processor exceeds the conservative 8000 char limit
            final_docs = []
            for doc in docs:
                if len(doc.page_content) > 8000:
                    logger.info(
                        f"⚡ [DOC] Oversized chunk detected ({len(doc.page_content)} chars). Applying secondary splitting."
                    )
                    sub_chunks = self.text_splitter.split_text(doc.page_content)
                    for i, sub_chunk in enumerate(sub_chunks):
                        new_metadata = doc.metadata.copy()
                        new_metadata["chunk_id"] = (
                            f"{new_metadata.get('chunk_id', 0)}_sub_{i}"
                        )
                        final_docs.append(
                            LangchainDocument(
                                page_content=sub_chunk, metadata=new_metadata
                            )
                        )
                else:
                    final_docs.append(doc)

            # 4. Final Security Pass (Secret Discovery)
            for doc in final_docs:
                doc.metadata = self.secret_scanner.flag_document(
                    doc.page_content, doc.metadata
                )

            return final_docs

        except Exception as e:
            logger.error(f"Primary processing failed for {file_path}: {e}")
            return self.universal_processor.process_any_file(file_path, metadata)

    def _process_image(self, file_path: str, metadata: Dict) -> List[LangchainDocument]:
        """Process image with API-based security analysis and info extraction"""
        documents = []

        try:
            if self.nvidia_api_key:
                from .image_processor import ImageProcessor

                ip = ImageProcessor(nvidia_api_key=self.nvidia_api_key)

                # Level 2: Conduct FULL security analysis for the knowledge base
                logger.info(
                    f"🔬 Conducting deep security audit of {metadata['file_name']} via NVIDIA Vision..."
                )
                analysis_result = ip.security_analysis(file_path)
                report = analysis_result.get("analysis_report", "")

                if report:
                    doc_metadata = metadata.copy()
                    doc_metadata.update(
                        {
                            "content_type": "security_image_analysis",
                            "source_type": "vision_api",
                        }
                    )
                    documents.append(
                        LangchainDocument(page_content=report, metadata=doc_metadata)
                    )

            # Exif and basic info follow...

            # Extract EXIF data as separate document (always fast & local)
            if "exif" in metadata:
                exif_text = "\n".join(
                    [f"{k}: {v}" for k, v in metadata["exif"].items()]
                )
                doc_metadata = metadata.copy()
                doc_metadata.update(
                    {"content_type": "exif_metadata", "source_type": "image_exif"}
                )
                documents.append(
                    LangchainDocument(page_content=exif_text, metadata=doc_metadata)
                )

            # Add basic image info
            image_desc = f"Image file: {metadata['file_name']}\nSize: {metadata.get('image_size', 'Unknown')}\nFormat: {metadata.get('image_format', 'Unknown')}"
            doc_metadata = metadata.copy()
            doc_metadata.update(
                {"content_length": len(image_desc), "source_type": "image_metadata"}
            )
            documents.append(
                LangchainDocument(page_content=image_desc, metadata=doc_metadata)
            )

            return documents

        except Exception as e:
            logger.error(f"Failed to process image {file_path}: {e}")
            # Return basic metadata document
            doc_metadata = metadata.copy()
            doc_metadata["processing_error"] = str(e)
            return [
                LangchainDocument(
                    page_content=f"Image file: {metadata['file_name']} (Failed to process: {e})",
                    metadata=doc_metadata,
                )
            ]

    async def _process_archive(
        self, file_path: str, metadata: Dict, current_depth: int = 0
    ) -> List[LangchainDocument]:
        """Process archive files recursively (Async)"""
        documents = []
        try:
            logger.info(
                f"📦 Extracting archive {metadata['file_name']} for ingestion (Depth: {current_depth})..."
            )
            result = self.archive_extractor.extract_archive(
                file_path, current_depth=current_depth
            )

            if not result.get("success"):
                logger.error(f"Archive extraction failed: {result.get('error')}")
                return self.universal_processor.process_any_file(file_path, metadata)

            extracted_path = result.get("extracted_path")
            extracted_files = result.get("files", [])

            for f_path in extracted_files:
                if os.path.isfile(f_path):
                    # Recursive call to process individual files
                    docs = await self.process_document(f_path, current_depth + 1)
                    documents.extend(docs)

            # Cleanup extracted directory
            if extracted_path and os.path.exists(extracted_path):
                import shutil

                shutil.rmtree(extracted_path, ignore_errors=True)

            return documents
        except Exception as e:
            logger.error(f"Archive processing failed for {file_path}: {e}")
            return self.universal_processor.process_any_file(file_path, metadata)

    async def _process_audio(
        self, file_path: str, metadata: Dict
    ) -> List[LangchainDocument]:
        """Process audio with Voxtral (Async)"""
        documents = []
        try:
            # Use MISTRAL_KEY for Voxtral
            from .audio_processor import AudioProcessor

            ap = AudioProcessor(mistral_api_key=self.mistral_api_key)

            logger.info(
                f"🎙️  Transcribing security audio {metadata['file_name']} via Mistral Voxtral..."
            )
            result = await ap.transcribe_and_analyze(file_path)
            report = result.get("transcription_report", "")

            if report:
                doc_metadata = metadata.copy()
                doc_metadata.update(
                    {
                        "content_type": "security_voice_intel",
                        "source_type": "mistral_voxtral",
                    }
                )
                documents.append(
                    LangchainDocument(page_content=report, metadata=doc_metadata)
                )

            return documents
        except Exception as e:
            logger.error(f"Audio processing failed for {file_path}: {e}")
            return [
                LangchainDocument(
                    page_content=f"Audio file: {metadata['file_name']} (Transcription failed: {e})",
                    metadata=metadata,
                )
            ]

    def _process_with_unstructured(
        self, file_path: str, metadata: Dict
    ) -> List[LangchainDocument]:
        """Process document using unstructured with high-res strategies and semantic chunking"""
        try:
            if not UNSTRUCTURED_AVAILABLE:
                logger.warning(
                    "Unstructured library not available, falling back to text processing"
                )
                return self._process_as_text(file_path, metadata)

            # Industrial grade: Use high-res for PDFs to extract tables/OCR
            # and semantic chunking to keep sections together
            is_pdf = metadata["extension"] == ".pd"

            # Use 'fast' strategy to avoid heavy model loading on low-spec PCs
            elements = partition(
                filename=file_path,
                strategy="fast",  # Changed from "auto" or "hi_res"
                chunking_strategy="by_title",
                max_characters=4000,
                new_after_n_chars=3800,
                combine_text_under_n_chars=2000,
            )

            documents = []
            for i, element in enumerate(elements):
                # Extract text and type
                element_type = getattr(element, "category", "Unknown")
                text = str(element)

                if not text.strip():
                    continue

                doc_metadata = metadata.copy()
                doc_metadata.update(
                    {
                        "chunk_id": i,
                        "element_type": element_type,
                        "source_type": "unstructured_semantic",
                        "page_number": getattr(element.metadata, "page_number", None),
                    }
                )

                documents.append(
                    LangchainDocument(page_content=text, metadata=doc_metadata)
                )

            if not documents:
                if is_pdf and PYPDF_AVAILABLE:
                    return self._process_pdf_pypdf(file_path, metadata)
                return self._process_as_text(file_path, metadata)

            return documents
        except Exception as e:
            logger.error(f"Unstructured high-res failed for {file_path}: {e}")
            if is_pdf and PYPDF_AVAILABLE:
                return self._process_pdf_pypdf(file_path, metadata)
            return self._process_as_text(file_path, metadata)

    def _process_spreadsheet(
        self, file_path: str, metadata: Dict
    ) -> List[LangchainDocument]:
        """Process spreadsheet files"""
        try:
            if file_path.endswith(".csv"):
                df = pd.read_csv(file_path)
            else:
                df = pd.read_excel(file_path)

            # Convert to text representation
            text_parts = []

            # Add sheet info
            text_parts.append(f"Spreadsheet: {metadata['file_name']}")
            text_parts.append(f"Shape: {df.shape[0]} rows × {df.shape[1]} columns")
            text_parts.append("")

            # Add column descriptions
            text_parts.append("Columns:")
            for col in df.columns:
                dtype = str(df[col].dtype)
                unique_count = df[col].nunique()
                text_parts.append(f"  - {col}: {dtype} ({unique_count} unique values)")

            text_parts.append("")

            # Sample data
            text_parts.append("Sample data (first 10 rows):")
            text_parts.append(df.head(10).to_string())

            full_text = "\n".join(text_parts)

            doc_metadata = metadata.copy()
            doc_metadata.update(
                {
                    "source_type": "spreadsheet",
                    "data_shape": f"{df.shape[0]}x{df.shape[1]}",
                    "columns": ", ".join(list(df.columns)),
                }
            )

            return [LangchainDocument(page_content=full_text, metadata=doc_metadata)]

        except Exception as e:
            logger.error(f"Failed to process spreadsheet {file_path}: {e}")
            return self._process_as_text(file_path, metadata)

    def _process_pcap(self, file_path: str, metadata: Dict) -> List[LangchainDocument]:
        """Process network capture files to extract critical forensic metadata"""
        try:
            # We don't want to load scapy globally to keep startup fast
            # Just do basic string extraction of IPs and Protocols if scapy fails
            intel = []
            intel.append(f"Network Analysis: {metadata['file_name']}")
            intel.append("-" * 30)

            # Simple binary-to-text extraction for common patterns (IPs, domain names)
            with open(file_path, "rb") as f:
                content = f.read(100000)  # Only read first 100KB for metadata scanning

                # IP Pattern
                ip_pattern = re.compile(rb"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
                ips = set(ip_pattern.findall(content))
                if ips:
                    intel.append(
                        f"Detected IP Addresses: {', '.join([ip.decode() for ip in ips])}"
                    )

                # ASCII strings check (for protocols/domains)
                ascii_pattern = re.compile(rb"[a-zA-Z0-9.-]{5,}")
                strings = set(ascii_pattern.findall(content))
                security_keywords = {
                    b"HTTP",
                    b"GET",
                    b"POST",
                    b"DNS",
                    b"SSH",
                    b"FTP",
                    b"TLS",
                    b"SSL",
                }
                found_keywords = [s.decode() for s in strings if s in security_keywords]
                if found_keywords:
                    intel.append(
                        f"Detected Protocols/Methods: {', '.join(found_keywords)}"
                    )

            full_text = "\n".join(intel)
            doc_metadata = metadata.copy()
            doc_metadata.update(
                {
                    "source_type": "network_intel",
                    "extracted_ips": len(ips) if "ips" in locals() else 0,
                    "forensic_audit": "Lightweight Binary Scan",
                }
            )

            return [LangchainDocument(page_content=full_text, metadata=doc_metadata)]
        except Exception as e:
            logger.error(f"PCAP processing failed: {e}")
            return self._process_as_text(file_path, metadata)

    def _process_as_text(
        self, file_path: str, metadata: Dict
    ) -> List[LangchainDocument]:
        """Fallback text processing"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read().replace("\x00", "")  # Sanitize NUL bytes

            chunks = self.text_splitter.split_text(text)

            documents = []
            for i, chunk in enumerate(chunks):
                doc_metadata = metadata.copy()
                doc_metadata.update(
                    {
                        "chunk_id": i,
                        "total_chunks": len(chunks),
                        "source_type": "fallback_text",
                    }
                )
                documents.append(
                    LangchainDocument(page_content=chunk, metadata=doc_metadata)
                )

            return documents

        except Exception as e:
            logger.error(f"Fallback processing failed for {file_path}: {e}")
            return [
                LangchainDocument(
                    page_content=f"File: {metadata['file_name']} (Could not extract content)",
                    metadata=metadata,
                )
            ]

    def _process_security_json(
        self, file_path: str, metadata: Dict
    ) -> List[LangchainDocument]:
        """Specialized fast parser for security JSONs (CVE, ATT&CK)"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)

            content = ""
            # Handle ATT&CK Framework
            if "objects" in data and isinstance(data["objects"], list):
                objects = data["objects"]
                for obj in objects[:10]:  # Limit chunks per file if it's a giant bundle
                    name = obj.get("name", "Unknown")
                    desc = obj.get("description", "")
                    if desc:
                        content += f"Name: {name}\nDescription: {desc}\n---\n"

            # Handle CVE v5
            elif "containers" in data:
                cna = data.get("containers", {}).get("cna", {})
                descriptions = cna.get("descriptions", [])
                title = cna.get("title", "")
                desc_text = "\n".join([d.get("value", "") for d in descriptions])
                content = f"Title: {title}\nDescription: {desc_text}"

            # Fallback to pretty print if structure unknown
            if not content:
                content = json.dumps(data, indent=2)[:5000]

            chunks = self.text_splitter.split_text(content)
            documents = []
            for i, chunk in enumerate(chunks):
                doc_metadata = metadata.copy()
                doc_metadata.update(
                    {
                        "chunk_id": i,
                        "total_chunks": len(chunks),
                        "source_type": "security_json",
                    }
                )
                documents.append(
                    LangchainDocument(page_content=chunk, metadata=doc_metadata)
                )
            return documents
        except Exception as e:
            logger.error(f"Security JSON parser failed: {e}")
            return self._process_with_unstructured(file_path, metadata)

    def _process_security_xml(
        self, file_path: str, metadata: Dict
    ) -> List[LangchainDocument]:
        """Specialized fast parser for security XMLs (CWE, CAPEC)"""
        try:
            content = ""
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in range(5000):  # Sample first 5000 lines (Increased from 500)
                    line = f.readline()
                    if not line:
                        break
                    content += line

            chunks = self.text_splitter.split_text(content)
            documents = []
            for i, chunk in enumerate(chunks):
                doc_metadata = metadata.copy()
                doc_metadata.update(
                    {
                        "chunk_id": i,
                        "total_chunks": len(chunks),
                        "source_type": "security_xml",
                    }
                )
                documents.append(
                    LangchainDocument(page_content=chunk, metadata=doc_metadata)
                )
            return documents
        except Exception:
            return self._process_with_unstructured(file_path, metadata)

    def _process_pdf_pypdf(
        self, file_path: str, metadata: Dict
    ) -> List[LangchainDocument]:
        """Robust PDF extraction using pypd"""
        try:
            reader = pypdf.PdfReader(file_path)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\n\n"

            # Sanitize
            text = text.replace("\x00", "")

            if not text.strip():
                return self._process_as_text(file_path, metadata)

            chunks = self.text_splitter.split_text(text)
            documents = []
            for i, chunk in enumerate(chunks):
                doc_metadata = metadata.copy()
                doc_metadata.update(
                    {
                        "chunk_id": i,
                        "total_chunks": len(chunks),
                        "source_type": "pypdf_fallback",
                    }
                )
                documents.append(
                    LangchainDocument(page_content=chunk, metadata=doc_metadata)
                )
            return documents
        except Exception as e:
            logger.error(f"pypdf processing failed for {file_path}: {e}")
            return self._process_as_text(file_path, metadata)
