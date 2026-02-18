import os
import math
import hashlib
import json
import subprocess
import tempfile
import mimetypes
from typing import Dict, Any, List, Optional
from pathlib import Path
import logging
import binascii
from myth_config import load_dotenv
load_dotenv()
from langchain_core.documents import Document as LangchainDocument

logger = logging.getLogger(__name__)

class UniversalFileProcessor:
    """Process ANY file type with cross-platform fallback strategies"""
    
    def __init__(self):
        # Initialize file type detector
        try:
            import magic
            self.mime_detector = magic.Magic(mime=True)
        except:
            self.mime_detector = None
    
    def detect_file_type(self, file_path: str) -> Dict[str, Any]:
        """Detect file type with deep packet inspection style analysis"""
        path = Path(file_path)
        
        # 1. MIME and Extension (Baseline)
        extension = path.suffix.lower()
        mime_type, _ = mimetypes.guess_type(file_path)
        mime_type = mime_type or "application/octet-stream"
        
        if self.mime_detector:
            try: mime_type = self.mime_detector.from_file(file_path)
            except: pass
        
        # 2. Header Analysis
        header_info = self._analyze_file_header(file_path)
        file_description = header_info.get('magic', '')
        
        # 3. Entropy and Randomness (Detect encrypted/compressed)
        # The original entropy calculation was on header_bytes.
        # For full file entropy, we need to calculate it on the whole file.
        # Let's use the header_info's entropy for consistency with the original structure,
        # but the new categorization logic will re-calculate it for the whole file.
        
        # 4. Refined Categorization
        # Calculate entropy to detect packed/encrypted files
        entropy = self._calculate_entropy_full_file(file_path) # Recalculate for full file
        
        # Initialize metadata for categorization
        metadata = {
            "extension": extension,
            "mime_type": mime_type,
            "header_info": header_info,
            "file_description": file_description or header_info.get("magic", "Unknown Binary")
        }

        # Categorize
        category = "Unknown"
        is_suspicious = False
        
        # Security Specialization: Entropy-based Packer/Encryption detection
        if entropy > 7.5:
            metadata["is_high_entropy"] = True
            metadata["entropy_rating"] = "Suspiciously High (Likely Encrypted or Packed)"
            is_suspicious = True
        elif entropy > 6.5:
            metadata["is_high_entropy"] = False
            metadata["entropy_rating"] = "Moderate (Likely Compressed or Media)"
        else:
            metadata["is_high_entropy"] = False
            metadata["entropy_rating"] = "Low (Likely Code or Text)"

        if extension in {'.exe', '.bin', '.elf', '.dll', '.so'}:
            category = "Executable"
            if is_suspicious: category = "Suspicious Executable"
        elif extension in {'.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.wav'}:
            category = "Media"
        elif extension in {'.zip', '.tar', '.gz', '.7z', '.rar'}:
            category = "Archive"
        elif extension in {'.pdf', '.docx', '.doc', '.pptx', '.xlsx'}:
            category = "Document"
        elif extension in {'.py', '.js', '.c', '.cpp', '.h', '.java', '.go', '.rs'}:
            category = "Source Code"
        elif extension in {'.pem', '.crt', '.key', '.pfx', '.p12'}:
            category = "Security Credential"
        elif extension in {'.pcap', '.pcapng', '.har'}:
            category = "Network Traffic"
        elif extension in {'.txt', '.md', '.json', '.xml', '.yaml', '.yml'}:
            category = "Text/Data"
        else:
            # Fallback to mime_type based categorization if extension didn't catch it
            if 'text/' in mime_type or 'json' in mime_type or 'xml' in mime_type:
                category = "Text/Data"
            elif 'image/' in mime_type:
                category = "Media"
            elif 'audio/' in mime_type or 'video/' in mime_type:
                category = "Media"
            elif 'application/zip' in mime_type or 'application/x-tar' in mime_type:
                category = "Archive"
            elif 'application/pdf' in mime_type or 'application/msword' in mime_type or 'application/vnd.openxmlformats' in mime_type:
                category = "Document"
            elif 'application/x-executable' in mime_type:
                category = "Executable"
            
        metadata.update({
            "category": category,
            "entropy": round(entropy, 2),
            "is_suspicious": is_suspicious,
            "detection_method": "Entropy + Magic Number"
        })
        
        return metadata

    def _get_byte_histogram(self, file_path: str) -> List[int]:
        """Calculate frequency of each byte (0-255) for pattern analysis"""
        hist = [0] * 256
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    for b in chunk:
                        hist[b] += 1
        except:
            pass
        return hist
    
    def _analyze_file_header(self, file_path: str) -> Dict[str, Any]:
        """Analyze file header bytes"""
        header_info = {}
        
        try:
            with open(file_path, 'rb') as f:
                # Read first 1024 bytes (slightly more for better detection)
                header_bytes = f.read(1024)
                
                if header_bytes:
                    # Common magic numbers
                    magic_numbers = {
                        b'\x89PNG\r\n\x1a\n': 'PNG Image',
                        b'\xff\xd8\xff': 'JPEG Image',
                        b'GIF87a': 'GIF87a Image',
                        b'GIF89a': 'GIF89a Image',
                        b'%PDF': 'PDF Document',
                        b'PK\x03\x04': 'ZIP Archive (or Office Doc)',
                        b'PK\x05\x06': 'ZIP Archive (empty)',
                        b'PK\x07\x08': 'ZIP Archive (spanned)',
                        b'\x1f\x8b\x08': 'GZIP Archive',
                        b'BZh': 'BZIP2 Archive',
                        b'\xfd7zXZ\x00': 'XZ Archive',
                        b'7z\xbc\xaf\x27\x1c': '7-Zip Archive',
                        b'Rar!\x1a\x07': 'RAR Archive',
                        b'MZ': 'Windows Executable',
                        b'\x7fELF': 'ELF Executable',
                        b'#!': 'Script (Shebang)',
                        b'<?xml': 'XML Document',
                        b'{\\rtf': 'RTF Document',
                        b'\x00\x00\x00\x18': 'QuickTime Movie',
                        b'\x00\x00\x00\x20': 'MP4 Video',
                        b'ID3': 'MP3 Audio',
                        b'OggS': 'Ogg Vorbis',
                        b'RIFF': 'AVI/WAVE',
                        b'WEBP': 'WebP Image',
                        b'fLaC': 'FLAC Audio',
                        b'<html': 'HTML Document',
                        b'<!DOC': 'HTML/XML Document',
                        b'\x25\x21\x50\x53': 'PostScript',
                        b'\x23\x20\x4d\x61\x6b\x65\x66\x69\x6c\x65': 'Makefile'
                    }
                    
                    # Check for magic numbers
                    for magic_bytes, description in magic_numbers.items():
                        if header_bytes.startswith(magic_bytes):
                            header_info['magic'] = description
                            break
                    
                    # Hex dump of first 32 bytes
                    header_info['hex_preview'] = binascii.hexlify(header_bytes[:32]).decode('utf-8')
                    
                    # ASCII representation
                    ascii_preview = ''.join(
                        chr(b) if 32 <= b < 127 else '.' 
                        for b in header_bytes[:64]
                    )
                    header_info['ascii_preview'] = ascii_preview
                    
                    # Entropy calculation (for encryption detection)
                    entropy = self._calculate_entropy(header_bytes)
                    header_info['entropy'] = entropy
                    header_info['likely_encrypted'] = entropy > 7.5
        
        except Exception as e:
            logger.warning(f"Header analysis failed: {e}")
        
        return header_info
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data (Fixed math bug)"""
        if not data:
            return 0.0
        
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        
        return entropy

    def _calculate_entropy_full_file(self, file_path: str) -> float:
        """ULTRA LIGHTNING: Calculate entropy using bit-sampling for zero-latency detection"""
        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0: return 0.0
            
            # Sampling strategy:
            # - If < 1MB, read whole file
            # - If > 1MB, sample first 1MB (enough for highly accurate security entropy)
            max_sample = 1024 * 1024
            with open(file_path, "rb") as f:
                if file_size <= max_sample:
                    data = f.read()
                else:
                    data = f.read(max_sample)
            
            return self._calculate_entropy(data)
        except Exception as e:
            logger.warning(f"Lightning entropy calculation failed: {e}")
            return 0.0
    
    def _categorize_file(self, extension: str, mime_type: str, 
                        file_description: str) -> str:
        """Categorize file for processing strategy"""
        
        # Text and documents
        if any(x in mime_type for x in ['text/', 'application/json', 
                                        'application/xml', 'application/pdf']):
            return "text"
        
        # Images
        elif 'image/' in mime_type:
            return "image"
        
        # Archives
        elif any(x in mime_type for x in ['application/zip', 'application/x-tar',
                                         'application/x-gzip', 'application/x-7z']):
            return "archive"
        
        # Office documents
        elif any(x in mime_type for x in ['application/vnd.openxmlformats',
                                         'application/vnd.ms-',
                                         'application/msword']):
            return "office"
        
        # Audio/Video
        elif any(x in mime_type for x in ['audio/', 'video/']):
            return "media"
        
        # Executables
        elif any(x in mime_type for x in ['application/x-executable',
                                         'application/x-mach-binary',
                                         'application/x-dosexec']):
            return "executable"
        
        # By extension
        ext_categories = {
            '.py': 'code', '.js': 'code', '.java': 'code', '.cpp': 'code',
            '.c': 'code', '.cs': 'code', '.go': 'code', '.rs': 'code',
            '.php': 'code', '.rb': 'code', '.pl': 'code', '.sh': 'code',
            '.ps1': 'code', '.sql': 'code', '.html': 'code', '.css': 'code',
            '.xml': 'code', '.json': 'code', '.yaml': 'code', '.yml': 'code',
            '.csv': 'data', '.tsv': 'data', '.xlsx': 'data', '.xls': 'data',
            '.db': 'database', '.sqlite': 'database', '.pcap': 'network',
            '.pcapng': 'network', '.har': 'network', '.pem': 'security',
            '.crt': 'security', '.key': 'security', '.pfx': 'security',
            '.mp3': 'media', '.wav': 'media', '.flac': 'media', '.m4a': 'media',
            '.exe': 'executable', '.dll': 'executable', '.so': 'executable',
            '.dylib': 'executable', '.class': 'executable', '.jar': 'archive'
        }
        
        if extension in ext_categories:
            return ext_categories[extension]
        
        # By file description
        desc_lower = file_description.lower()
        if any(x in desc_lower for x in ['text', 'ascii']):
            return "text"
        elif any(x in desc_lower for x in ['image', 'jpeg', 'png', 'gif']):
            return "image"
        elif any(x in desc_lower for x in ['archive', 'compressed']):
            return "archive"
        elif any(x in desc_lower for x in ['executable', 'binary']):
            return "executable"
        
        return "unknown"
    
    def extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract human-readable strings from binary files (Pure Python, Chunked)"""
        strings = []
        try:
            with open(file_path, 'rb') as f:
                current_string = []
                while True:
                    chunk = f.read(65536) # 64KB chunks
                    if not chunk:
                        break
                    for byte in chunk:
                        if 32 <= byte < 127: # Printable ASCII
                            current_string.append(chr(byte))
                        else:
                            if len(current_string) >= min_length:
                                strings.append("".join(current_string))
                            current_string = []
                            if len(strings) > 10000: # Absolute safety cap
                                return strings
                
                if len(current_string) >= min_length:
                    strings.append("".join(current_string))
        except Exception as e:
            logger.warning(f"Pure Python string extraction failed: {e}")
        return strings
    
    def process_any_file(self, file_path: str, 
                        metadata: Optional[Dict] = None) -> List[LangchainDocument]:
        """Universal file processor - handles ANY file type"""
        
        # Detect file type
        file_info = self.detect_file_type(file_path)
        category = file_info['category']
        
        # Prepare base metadata
        base_metadata = {
            "file_name": Path(file_path).name,
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "file_type": file_info['mime_type'],
            "file_category": category,
            "file_description": file_info['file_description'],
            "processing_method": "universal_processor"
        }
        
        if metadata:
            base_metadata.update(metadata)
        
        documents = []
        
        # Process based on category
        if category == "text":
            # Fallback text processing if main processor missed it
            logger.info(f"Universal Processor: Handling fallback for text file {file_path}")
            try:
                # Try UTF-8 first
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # If content is empty or looks binary, basic extraction
                if not content or self.mime_detector and 'compressed' in self.mime_detector.from_buffer(content.encode('utf-8')[:1024]):
                     documents.extend(self._process_unknown(file_path, metadata))
                else: 
                     doc_metadata = base_metadata.copy()
                     doc_metadata["source_type"] = "universal_text_fallback"
                     documents.append(LangchainDocument(page_content=content, metadata=doc_metadata))
            except Exception as e:
                logger.warning(f"Universal text fallback failed: {e}")
                documents.extend(self._process_unknown(file_path, metadata))
        
        elif category == "image":
            # Fallback image processing (metadata only)
            logger.info(f"Universal Processor: Handling fallback for image file {file_path}")
            # Identify it but treat as unknown/binary since we lack specific vision tools here
            documents.extend(self._process_unknown(file_path, base_metadata))
        
        elif category == "executable":
            documents.extend(self._process_executable(file_path, base_metadata))
        
        elif category == "archive":
            documents.extend(self._process_archive(file_path, base_metadata))
        
        elif category == "database":
            documents.extend(self._process_database(file_path, base_metadata))
        
        elif category == "network":
            documents.extend(self._process_network_file(file_path, base_metadata))
        
        elif category == "media":
            documents.extend(self._process_media(file_path, base_metadata))
        
        elif category == "unknown":
            documents.extend(self._process_unknown(file_path, base_metadata))
        
        else:
            # Generic binary processing
            documents.extend(self._process_binary(file_path, base_metadata))
        
        return documents
    
    def _process_executable(self, file_path: str, 
                          metadata: Dict) -> List[LangchainDocument]:
        """Process executable/binary files"""
        documents = []
        
        # Extract strings
        strings = self.extract_strings(file_path)
        
        if strings:
            # Group strings for readability
            grouped_strings = []
            current_group = []
            
            for s in strings[:1000]:  # Limit to 1000 strings
                if len(s) > 20:  # Long strings often interesting
                    current_group.append(s)
                    if len(current_group) >= 10:
                        grouped_strings.append("\n".join(current_group))
                        current_group = []
            
            if current_group:
                grouped_strings.append("\n".join(current_group))
            
            # Create document with extracted strings
            content = f"""Executable/Binary File: {metadata['file_name']}
File Type: {metadata['file_type']}
File Description: {metadata.get('file_description', 'Unknown')}

Extracted Strings ({len(strings)} found, showing first {len(grouped_strings)*10}):

"""
            for i, group in enumerate(grouped_strings[:10]):  # Limit groups
                content += f"\n--- String Group {i+1} ---\n{group}\n"
            
            if len(strings) > 1000:
                content += f"\n... and {len(strings) - 1000} more strings"
            
            doc_metadata = metadata.copy()
            doc_metadata.update({
                "content_type": "extracted_strings",
                "total_strings": len(strings),
                "strings_sample": strings[:20]
            })
            
            documents.append(LangchainDocument(
                page_content=content,
                metadata=doc_metadata
            ))
        
        # Add file info document
        info_content = f"""Binary File Analysis:
Name: {metadata['file_name']}
Size: {metadata['file_size']} bytes
Type: {metadata['file_type']}
Category: Executable/Binary
Detected: {metadata.get('file_description', 'Unknown')}

Header Info: {metadata.get('header_info', {}).get('magic', 'Unknown')}
Entropy: {metadata.get('header_info', {}).get('entropy', 'N/A')}
"""
        
        doc_metadata = metadata.copy()
        doc_metadata["content_type"] = "file_analysis"
        
        documents.append(LangchainDocument(
            page_content=info_content,
            metadata=doc_metadata
        ))
        
        return documents
    
    def _process_archive(self, file_path: str, 
                        metadata: Dict) -> List[LangchainDocument]:
        """Process archive files"""
        
        content = f"""Archive File: {metadata['file_name']}
Type: {metadata['file_type']}
Size: {metadata['file_size']} bytes

This appears to be an archive file (ZIP, TAR, etc.).
To analyze contents, the archive needs to be extracted first.

Consider extracting and processing individual files separately.
"""
        
        doc_metadata = metadata.copy()
        doc_metadata["content_type"] = "archive_info"
        doc_metadata["needs_extraction"] = True
        
        return [LangchainDocument(
            page_content=content,
            metadata=doc_metadata
        )]
    
    def _process_database(self, file_path: str, 
                         metadata: Dict) -> List[LangchainDocument]:
        """Process database files"""
        
        content = f"""Database File: {metadata['file_name']}
Type: {metadata['file_type']}
Size: {metadata['file_size']} bytes

This appears to be a database file (SQLite, etc.).
Database files require specialized tools for analysis.

Consider using SQLite or database inspection tools to:
1. List tables
2. Extract schema
3. Query data
"""
        
        doc_metadata = metadata.copy()
        doc_metadata["content_type"] = "database_info"
        doc_metadata["requires_special_tools"] = True
        
        return [LangchainDocument(
            page_content=content,
            metadata=doc_metadata
        )]
    
    def _process_network_file(self, file_path: str, 
                            metadata: Dict) -> List[LangchainDocument]:
        """Process network capture files"""
        
        content = f"""Network Capture File: {metadata['file_name']}
Type: {metadata['file_type']}
Size: {metadata['file_size']} bytes

This appears to be a network capture file (PCAP, PCAPNG, HAR).
Network analysis requires specialized tools like Wireshark, tshark, or scapy.

Recommended analysis steps:
1. Use tshark to list packets
2. Extract HTTP conversations
3. Analyze protocols
4. Look for anomalies
"""
        
        doc_metadata = metadata.copy()
        doc_metadata["content_type"] = "network_capture_info"
        doc_metadata["recommended_tools"] = "Wireshark, tshark, scapy"
        
        return [LangchainDocument(
            page_content=content,
            metadata=doc_metadata
        )]
    
    def _process_media(self, file_path: str, 
                      metadata: Dict) -> List[LangchainDocument]:
        """Process audio/video files"""
        
        # Try to extract metadata with ffprobe if available
        media_info = {}
        try:
            result = subprocess.run(
                ['ffprobe', '-v', 'quiet', '-print_format', 'json', 
                 '-show_format', '-show_streams', file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                media_info = json.loads(result.stdout)
        except:
            pass
        
        content = f"""Media File: {metadata['file_name']}
Type: {metadata['file_type']}
Size: {metadata['file_size']} bytes

Media files (audio/video) contain metadata that can be extracted.
"""
        
        if media_info:
            content += f"\nExtracted Media Information:\n"
            if 'format' in media_info:
                content += f"Format: {media_info['format'].get('format_name', 'Unknown')}\n"
                content += f"Duration: {media_info['format'].get('duration', 'Unknown')}s\n"
                content += f"Bitrate: {media_info['format'].get('bit_rate', 'Unknown')} bps\n"
            
            if 'streams' in media_info:
                for stream in media_info['streams'][:3]:
                    codec_type = stream.get('codec_type', 'unknown')
                    content += f"\n{codec_type.upper()} Stream:\n"
                    content += f"  Codec: {stream.get('codec_name', 'Unknown')}\n"
                    if codec_type == 'video':
                        content += f"  Resolution: {stream.get('width', '?')}x{stream.get('height', '?')}\n"
                    elif codec_type == 'audio':
                        content += f"  Channels: {stream.get('channels', '?')}\n"
                        content += f"  Sample Rate: {stream.get('sample_rate', '?')} Hz\n"
        
        doc_metadata = metadata.copy()
        doc_metadata["content_type"] = "media_info"
        doc_metadata["media_metadata"] = media_info
        
        return [LangchainDocument(
            page_content=content,
            metadata=doc_metadata
        )]
    
    def _process_unknown(self, file_path: str, 
                        metadata: Dict) -> List[LangchainDocument]:
        """Process completely unknown file types"""
        
        # Extract whatever we can
        strings = self.extract_strings(file_path)[:50]  # First 50 strings
        
        content = f"""Unknown File Type: {metadata['file_name']}
Size: {metadata['file_size']} bytes
MIME Type: {metadata['file_type']}
Detected As: {metadata.get('file_description', 'Unknown')}

File header analysis:
Magic: {metadata.get('header_info', {}).get('magic', 'Not recognized')}
Entropy: {metadata.get('header_info', {}).get('entropy', 'N/A')}
Hex Preview: {metadata.get('header_info', {}).get('hex_preview', 'N/A')}
ASCII Preview: {metadata.get('header_info', {}).get('ascii_preview', 'N/A')}

"""
        
        if strings:
            content += f"Extracted Strings ({len(strings)} found):\n"
            content += "\n".join(f"  - {s}" for s in strings[:20])
            if len(strings) > 20:
                content += f"\n  ... and {len(strings) - 20} more"
        else:
            content += "No readable strings found in file."
        
        content += f"""

This file type is not directly supported for content extraction.
Consider using specialized tools for analysis.
"""
        
        doc_metadata = metadata.copy()
        doc_metadata["content_type"] = "unknown_file_analysis"
        doc_metadata["extracted_strings_count"] = len(strings)
        
        return [LangchainDocument(
            page_content=content,
            metadata=doc_metadata
        )]
    
    def _process_binary(self, file_path: str, 
                       metadata: Dict) -> List[LangchainDocument]:
        """Generic binary file processing"""
        return self._process_unknown(file_path, metadata)

    def _to_langchain_doc(self, res: Dict[str, Any]) -> LangchainDocument:
        """Helper to convert dictionary result back to Langchain Document"""
        return LangchainDocument(
            page_content=res.get('content', ''),
            metadata=res.get('metadata', {})
        )
