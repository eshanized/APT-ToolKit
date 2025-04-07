"""
Secure file operations for APT Toolkit

Features:
- Atomic file writes
- Secure temporary files
- File integrity checks
- Safe path operations
- Malware scanning hooks
"""

import os
import tempfile
import hashlib
import shutil
import zipfile
import tarfile
from pathlib import Path
from typing import IO, Any, BinaryIO, Dict, Generator, Optional, Tuple, Union
import logging
import stat
from contextlib import contextmanager
import mmap
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Security constants
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
UNSAFE_EXTENSIONS = {'.exe', '.bat', '.sh', '.py', '.js', '.php'}
SAFE_MIME_TYPES = {
    'text/plain', 'application/json', 
    'text/csv', 'application/xml'
}

class FileSecurityError(Exception):
    """Security violation in file operations"""
    pass

class FileUtils:
    """Secure file operations handler"""
    
    @staticmethod
    def safe_path_resolve(path: Union[str, Path], base: Optional[Path] = None) -> Path:
        """
        Resolve path securely against a base directory to prevent directory traversal
        
        Args:
            path: Path to resolve
            base: Base directory to resolve against (default: config base dir)
            
        Returns:
            Absolute resolved Path
            
        Raises:
            FileSecurityError: If path escapes base directory
        """
        base_dir = base or config.core.base_dir
        try:
            resolved = Path(path).resolve()
            base_resolved = base_dir.resolve()
            
            if not resolved.is_relative_to(base_resolved):
                raise FileSecurityError(
                    f"Path {resolved} escapes base directory {base_resolved}"
                )
                
            return resolved
        except (ValueError, RuntimeError) as e:
            raise FileSecurityError(f"Invalid path: {str(e)}") from e

    @staticmethod
    def atomic_write(
        file_path: Union[str, Path],
        content: Union[str, bytes],
        mode: str = 'w',
        chmod: Optional[int] = None
    ) -> None:
        """
        Atomically write to a file with secure defaults
        
        Args:
            file_path: Target file path
            content: Content to write
            mode: Write mode ('w' for text, 'wb' for binary)
            chmod: Optional permission bits (e.g., 0o600)
            
        Raises:
            FileSecurityError: If file operations violate security policy
        """
        path = Path(file_path)
        if path.is_dir():
            raise FileSecurityError(f"Target is a directory: {path}")
            
        if isinstance(content, str) and 'b' in mode:
            raise ValueError("Content type doesn't match mode")
            
        # Write to temporary file first
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode=mode,
                dir=path.parent,
                prefix=f".{path.name}.tmp",
                delete=False
            ) as temp_file:
                temp_path = Path(temp_file.name)
                temp_file.write(content)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                
                if chmod is not None:
                    os.chmod(temp_path, chmod)
                    
            # Atomic rename
            temp_path.replace(path)
        except Exception as e:
            if temp_path and temp_path.exists():
                temp_path.unlink()
            raise FileSecurityError(f"Atomic write failed: {str(e)}") from e

    @staticmethod
    def calculate_checksums(file_path: Path) -> Dict[str, str]:
        """
        Calculate multiple hash checksums for file verification
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary of {'algorithm': 'hash_value'}
            
        Raises:
            FileSecurityError: If file is too large or unreadable
        """
        if not file_path.is_file():
            raise FileSecurityError(f"Not a file: {file_path}")
            
        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise FileSecurityError(f"File too large: {file_size} bytes")
            
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        try:
            with file_path.open('rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
                        
            return {alg: h.hexdigest() for alg, h in hashes.items()}
        except (IOError, OSError) as e:
            raise FileSecurityError(f"Checksum calculation failed: {str(e)}") from e

    @staticmethod
    @contextmanager
    def secure_temp_file(
        suffix: Optional[str] = None,
        prefix: Optional[str] = None,
        content: Optional[Union[str, bytes]] = None
    ) -> Generator[Path, None, None]:
        """
        Context manager for secure temporary files that are automatically deleted
        
        Args:
            suffix: File suffix
            prefix: File prefix
            content: Optional initial content
            
        Yields:
            Path to temporary file
        """
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=suffix,
                prefix=prefix,
                delete=False
            ) as tf:
                temp_file = Path(tf.name)
                if content is not None:
                    mode = 'wb' if isinstance(content, bytes) else 'w'
                    with open(temp_file, mode) as f:
                        f.write(content)
            yield temp_file
        finally:
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError as e:
                    logger.warning(f"Failed to delete temp file {temp_file}: {str(e)}")

    @staticmethod
    def safe_extract_archive(
        archive_path: Path,
        extract_to: Path,
        password: Optional[str] = None
    ) -> None:
        """
        Securely extract archive files with safety checks
        
        Args:
            archive_path: Path to archive file
            extract_to: Target directory
            password: Optional password for encrypted archives
            
        Raises:
            FileSecurityError: For suspicious archive contents
        """
        if not archive_path.is_file():
            raise FileSecurityError("Archive path is not a file")
            
        if not extract_to.is_dir():
            raise FileSecurityError("Target is not a directory")
            
        # Check for unsafe extensions
        if archive_path.suffix.lower() in UNSAFE_EXTENSIONS:
            raise FileSecurityError(f"Unsafe archive extension: {archive_path.suffix}")
            
        try:
            if zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path) as zip_ref:
                    for member in zip_ref.infolist():
                        if member.filename.startswith(('/', '..')) or '..' in member.filename:
                            raise FileSecurityError(f"Zip slip detected in {member.filename}")
                        if Path(member.filename).suffix.lower() in UNSAFE_EXTENSIONS:
                            raise FileSecurityError(f"Unsafe file in archive: {member.filename}")
                    zip_ref.extractall(extract_to, pwd=password.encode() if password else None)
                    
            elif tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path) as tar_ref:
                    for member in tar_ref.getmembers():
                        if member.name.startswith(('/', '..')) or '..' in member.name:
                            raise FileSecurityError(f"Tar slip detected in {member.name}")
                        if Path(member.name).suffix.lower() in UNSAFE_EXTENSIONS:
                            raise FileSecurityError(f"Unsafe file in archive: {member.name}")
                    tar_ref.extractall(extract_to)
            else:
                raise FileSecurityError("Unsupported archive format")
        except (zipfile.BadZipFile, tarfile.TarError) as e:
            raise FileSecurityError(f"Archive extraction failed: {str(e)}") from e

    @staticmethod
    def is_binary_file(file_path: Path) -> bool:
        """
        Detect if a file is binary (vs text)
        
        Args:
            file_path: Path to file
            
        Returns:
            bool: True if file appears to be binary
        """
        try:
            with file_path.open('rb') as f:
                return b'\0' in f.read(1024)
        except IOError:
            return False

    @staticmethod
    def secure_file_copy(
        src: Path,
        dst: Path,
        verify: bool = True,
        chunk_size: int = 8192
    ) -> None:
        """
        Securely copy file with optional integrity verification
        
        Args:
            src: Source file path
            dst: Destination file path
            verify: Whether to verify copy via checksum
            chunk_size: Copy buffer size
            
        Raises:
            FileSecurityError: If verification fails or paths are invalid
        """
        src = FileUtils.safe_path_resolve(src)
        dst = FileUtils.safe_path_resolve(dst)
        
        if not src.is_file():
            raise FileSecurityError(f"Source not a file: {src}")
            
        if src == dst:
            raise FileSecurityError("Source and destination are the same")
            
        original_hash = FileUtils.calculate_checksums(src)['sha256'] if verify else None
        
        try:
            with src.open('rb') as f_src, dst.open('wb') as f_dst:
                while True:
                    chunk = f_src.read(chunk_size)
                    if not chunk:
                        break
                    f_dst.write(chunk)
                f_dst.flush()
                os.fsync(f_dst.fileno())
                
            if verify:
                new_hash = FileUtils.calculate_checksums(dst)['sha256']
                if new_hash != original_hash:
                    dst.unlink()
                    raise FileSecurityError("File copy verification failed - hashes differ")
        except (IOError, OSError) as e:
            if dst.exists():
                dst.unlink()
            raise FileSecurityError(f"Secure copy failed: {str(e)}") from e

# Utility exports
safe_path_resolve = FileUtils.safe_path_resolve
atomic_write = FileUtils.atomic_write
secure_temp_file = FileUtils.secure_temp_file