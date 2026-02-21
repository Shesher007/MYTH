import tarfile
import zipfile

try:
    import py7zr
except ImportError:
    py7zr = None
try:
    import rarfile
except ImportError:
    rarfile = None
import bz2
import gzip
import logging
import lzma
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from myth_config import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class ArchiveExtractor:
    """Extract and process archive files with security and memory efficiency"""

    def __init__(self, extract_dir: str = "asset_inventory", max_depth: int = 5):
        self.extract_dir = Path(extract_dir)
        self.extract_dir.mkdir(parents=True, exist_ok=True)
        self.max_depth = max_depth

        # Security Limits
        self.max_files = 1000
        self.max_decompressed_size_mb = 1024  # 1GB
        self.max_compression_ratio = 100  # 100x ratio

    def _is_safe_path(self, base_dir: Path, target_path: Path) -> bool:
        """Prevent Zip Slip by ensuring target path is within base directory"""
        try:
            base_dir = base_dir.resolve()
            target_path = target_path.resolve()
            if target_path.relative_to(base_dir) is not None:
                return True
            return False
        except ValueError:
            return False

    def extract_archive(
        self, archive_path: str, password: Optional[str] = None, current_depth: int = 0
    ) -> Dict[str, Any]:
        """Extract any supported archive type safely"""
        if current_depth >= self.max_depth:
            return {
                "success": False,
                "error": f"Maximum extraction depth reached ({self.max_depth})",
            }

        path = Path(archive_path)
        archive_type = self._detect_archive_type(path)

        # Unique extraction directory to avoid race conditions
        import uuid

        extract_path = self.extract_dir / f"{path.stem}_{uuid.uuid4().hex[:8]}"
        extract_path.mkdir(exist_ok=True, parents=True)

        extracted_files = []

        try:
            if archive_type == "zip":
                extracted_files = self._extract_zip(path, extract_path, password)
            elif archive_type == "tar":
                extracted_files = self._extract_tar(path, extract_path)
            elif archive_type == "7z":
                extracted_files = self._extract_7z(path, extract_path, password)
            elif archive_type == "rar":
                extracted_files = self._extract_rar(path, extract_path, password)
            elif archive_type == "gzip":
                extracted_files = self._extract_gzip(path, extract_path)
            elif archive_type == "bz2":
                extracted_files = self._extract_bz2(path, extract_path)
            elif archive_type == "xz":
                extracted_files = self._extract_xz(path, extract_path)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported archive type: {archive_type}",
                    "archive_type": archive_type,
                }

            return {
                "success": True,
                "archive_type": archive_type,
                "extracted_path": str(extract_path),
                "files": extracted_files,
                "total_files": len(extracted_files),
            }

        except Exception as e:
            # Cleanup on failure
            if extract_path.exists():
                shutil.rmtree(extract_path, ignore_errors=True)
            return {"success": False, "error": str(e), "archive_type": archive_type}

    def _detect_archive_type(self, path: Path) -> str:
        """Detect archive type by extension and magic bytes"""
        extension = path.suffix.lower()

        if extension == ".zip":
            return "zip"
        elif extension in [".tar", ".gz", ".tgz", ".bz2", ".xz", ".tbz2", ".txz"]:
            # Check for combined extensions
            suffixes = path.suffixes
            if ".tar" in suffixes:
                return "tar"
            elif ".gz" in suffixes:
                return "gzip"
            elif ".bz2" in suffixes:
                return "bz2"
            elif ".xz" in suffixes:
                return "xz"
        elif extension == ".7z":
            return "7z"
        elif extension == ".rar":
            return "rar"

        # Check magic bytes as fallback
        try:
            with open(path, "rb") as f:
                magic = f.read(4)

                if magic.startswith(b"PK"):
                    return "zip"
                elif magic.startswith(b"\x1f\x8b"):
                    return "gzip"
                elif magic.startswith(b"BZh"):
                    return "bz2"
                elif magic.startswith(b"\xfd7zXZ"):
                    return "xz"
                elif magic.startswith(b"7z\xbc\xaf\x27\x1c"):
                    return "7z"
                elif magic.startswith(b"Rar!"):
                    return "rar"
        except Exception:
            pass

        return "unknown"

    def _extract_zip(
        self, path: Path, extract_to: Path, password: Optional[str]
    ) -> List[str]:
        """Extract ZIP archive safely with resource limits"""
        extracted = []
        total_size = 0
        total_files = 0

        with zipfile.ZipFile(path, "r") as zip_ref:
            if password:
                zip_ref.setpassword(password.encode("utf-8"))

            # Pre-scan for Zip Bomb
            for info in zip_ref.infolist():
                total_files += 1
                total_size += info.file_size

                if total_files > self.max_files:
                    raise Exception(
                        f"Archive contains too many files (> {self.max_files})"
                    )

                if total_size > (self.max_decompressed_size_mb * 1024 * 1024):
                    raise Exception(
                        f"Archive decompressed size exceeds limit ({self.max_decompressed_size_mb} MB)"
                    )

                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > self.max_compression_ratio:
                        raise Exception(
                            f"Suspicious compression ratio detected ({ratio:.1f}x) in {info.filename}"
                        )

            for member in zip_ref.namelist():
                # Security: Zip Slip check
                target_path = (extract_to / member).resolve()
                if not self._is_safe_path(extract_to, target_path):
                    logger.warning(f"⚠️ Blocked unsafe file in ZIP: {member}")
                    continue

                # Check for directory
                if member.endswith("/"):
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                # Ensure parent dir exists
                target_path.parent.mkdir(parents=True, exist_ok=True)

                # Stability: Chunked read/write
                with zip_ref.open(member) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                extracted.append(str(target_path))

        return extracted

    def _extract_tar(self, path: Path, extract_to: Path) -> List[str]:
        """Extract TAR archive safely"""
        extracted = []

        mode = "r"
        if path.suffixes and path.suffixes[-1] in [".gz", ".tgz"]:
            mode = "r:gz"
        elif path.suffixes and path.suffixes[-1] in [".bz2", ".tbz2"]:
            mode = "r:bz2"
        elif path.suffixes and path.suffixes[-1] in [".xz", ".txz"]:
            mode = "r:xz"

        with tarfile.open(path, mode) as tar:
            for member in tar.getmembers():
                # Security: Zip Slip check
                target_path = (extract_to / member.name).resolve()
                if not self._is_safe_path(extract_to, target_path):
                    logger.warning(f"⚠️ Blocked unsafe file in TAR: {member.name}")
                    continue

                if member.isdir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)

                # Stability: Chunked extraction
                with (
                    tar.extractfile(member) as source,
                    open(target_path, "wb") as target,
                ):
                    if source:
                        shutil.copyfileobj(source, target)
                extracted.append(str(target_path))

        return extracted

    def _extract_7z(
        self, path: Path, extract_to: Path, password: Optional[str]
    ) -> List[str]:
        """Extract 7-Zip archive safely"""
        if py7zr is None:
            logger.error("py7zr is not installed. 7z extraction disabled.")
            return []
        extracted = []

        with py7zr.SevenZipFile(path, mode="r", password=password) as archive:
            for filename in archive.getnames():
                target_path = (extract_to / filename).resolve()
                if not self._is_safe_path(extract_to, target_path):
                    logger.warning(f"⚠️ Blocked unsafe file in 7Z: {filename}")
                    continue

                # py7zr doesn't support easy chunked extraction per file as nicely as zipfile
                # but we can use extract(path, targets)
                archive.extract(path=extract_to, targets=[filename])
                if target_path.is_file():
                    extracted.append(str(target_path))

        return extracted

    def _extract_rar(
        self, path: Path, extract_to: Path, password: Optional[str]
    ) -> List[str]:
        """Extract RAR archive safely"""
        if rarfile is None:
            logger.error("rarfile is not installed. RAR extraction disabled.")
            return []
        extracted = []

        with rarfile.RarFile(path, "r") as rar:
            if password:
                rar.setpassword(password)

            for file_info in rar.infolist():
                target_path = (extract_to / file_info.filename).resolve()
                if not self._is_safe_path(extract_to, target_path):
                    logger.warning(
                        f"⚠️ Blocked unsafe file in RAR: {file_info.filename}"
                    )
                    continue

                if file_info.isdir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)

                with rar.open(file_info) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                extracted.append(str(target_path))

        return extracted

    def _extract_gzip(self, path: Path, extract_to: Path) -> List[str]:
        """Extract GZIP file safely"""
        output_name = path.stem
        target_path = (extract_to / output_name).resolve()

        with gzip.open(path, "rb") as f_in, open(target_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        return [str(target_path)]

    def _extract_bz2(self, path: Path, extract_to: Path) -> List[str]:
        """Extract BZIP2 file safely"""
        output_name = path.stem.replace(".tar", "")
        target_path = (extract_to / output_name).resolve()

        with bz2.open(path, "rb") as f_in, open(target_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        return [str(target_path)]

    def _extract_xz(self, path: Path, extract_to: Path) -> List[str]:
        """Extract XZ file safely"""
        output_name = path.stem.replace(".tar", "")
        target_path = (extract_to / output_name).resolve()

        with lzma.open(path, "rb") as f_in, open(target_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        return [str(target_path)]
