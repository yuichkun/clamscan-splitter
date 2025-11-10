"""Mock filesystem utilities for testing.

This module provides utilities to create mock filesystem structures
for testing chunking and scanning functionality using pyfakefs.
"""

import os
import stat
from pathlib import Path
from typing import List, Tuple


class MockFileSystem:
    """Mock filesystem for testing."""

    def __init__(self, fs):
        """Initialize with a pyfakefs filesystem instance.
        
        Args:
            fs: pyfakefs filesystem instance from pytest fixture
        """
        self.fs = fs

    def create_test_structure(
        self,
        base_path: str,
        total_size_gb: float,
        num_files: int,
        max_depth: int,
    ) -> str:
        """Create a mock directory structure for testing.
        
        Args:
            base_path: Base directory path to create structure in
            total_size_gb: Total size in GB to distribute across files
            num_files: Number of files to create
            max_depth: Maximum directory nesting depth
            
        Returns:
            Path to the created base directory
        """
        base_path = Path(base_path)
        self.fs.create_dir(base_path)
        
        total_size_bytes = int(total_size_gb * 1024**3)
        file_size = total_size_bytes // num_files if num_files > 0 else 0
        
        files_created = 0
        current_path = base_path
        
        # Create directory structure with files
        for depth in range(max_depth):
            if files_created >= num_files:
                break
                
            # Create subdirectories at this depth
            dirs_at_depth = min(10, (num_files - files_created) // 10 + 1)
            for i in range(dirs_at_depth):
                if files_created >= num_files:
                    break
                    
                subdir = current_path / f"dir_{depth}_{i}"
                self.fs.create_dir(subdir)
                
                # Create files in this directory
                files_per_dir = min(100, num_files - files_created)
                for j in range(files_per_dir):
                    if files_created >= num_files:
                        break
                        
                    file_path = subdir / f"file_{files_created}.txt"
                    content = b"x" * file_size
                    self.fs.create_file(file_path, contents=content)
                    files_created += 1
                
                current_path = subdir
        
        return str(base_path)

    def create_problematic_files(self, base_path: str) -> List[str]:
        """Create files that typically cause scan issues.
        
        Args:
            base_path: Base directory to create problematic files in
            
        Returns:
            List of paths to problematic files created
        """
        base_path = Path(base_path)
        self.fs.create_dir(base_path)
        problematic_files = []
        
        # Create large file (> 1GB)
        large_file = base_path / "large_file.bin"
        large_size = int(1.5 * 1024**3)  # 1.5GB
        self.fs.create_file(large_file, st_size=large_size)
        problematic_files.append(str(large_file))
        
        # Create archive files
        archive_files = [
            ("archive.zip", b"PK\x03\x04" + b"x" * 1000),
            ("archive.tar.gz", b"\x1f\x8b" + b"x" * 1000),
            ("archive.7z", b"7z\xbc\xaf\x27\x1c" + b"x" * 1000),
            ("archive.rar", b"Rar!\x1a\x07" + b"x" * 1000),
        ]
        for filename, content in archive_files:
            file_path = base_path / filename
            self.fs.create_file(file_path, contents=content)
            problematic_files.append(str(file_path))
        
        # Create large PDF (> 50MB)
        large_pdf = base_path / "large.pdf"
        pdf_size = int(60 * 1024 * 1024)  # 60MB
        pdf_content = b"%PDF-1.4\n" + b"x" * pdf_size
        self.fs.create_file(large_pdf, contents=pdf_content)
        problematic_files.append(str(large_pdf))
        
        # Create disk image files
        disk_images = [".iso", ".img", ".vmdk", ".vdi"]
        for ext in disk_images:
            file_path = base_path / f"disk_image{ext}"
            self.fs.create_file(file_path, st_size=500 * 1024 * 1024)  # 500MB
            problematic_files.append(str(file_path))
        
        return problematic_files

    def create_special_files(self, base_path: str) -> List[str]:
        """Create special files (FIFOs, sockets, device files).
        
        Note: pyfakefs may not fully support all special file types,
        but we can create them with appropriate mode bits.
        
        Args:
            base_path: Base directory to create special files in
            
        Returns:
            List of paths to special files created
        """
        base_path = Path(base_path)
        self.fs.create_dir(base_path)
        special_files = []
        
        # Create FIFO (named pipe)
        fifo_path = base_path / "fifo_pipe"
        self.fs.create_file(fifo_path)
        # Note: Setting FIFO mode may not work in pyfakefs, but we'll try
        try:
            os.chmod(fifo_path, stat.S_IFIFO | 0o666)
        except (OSError, AttributeError):
            # pyfakefs may not support this, that's okay for testing
            pass
        special_files.append(str(fifo_path))
        
        # Create socket file
        socket_path = base_path / "socket_file"
        self.fs.create_file(socket_path)
        try:
            os.chmod(socket_path, stat.S_IFSOCK | 0o666)
        except (OSError, AttributeError):
            pass
        special_files.append(str(socket_path))
        
        return special_files

    def create_deep_nesting(self, base_path: str, depth: int) -> str:
        """Create deeply nested directory structure.
        
        Args:
            base_path: Base directory path
            depth: Number of nesting levels
            
        Returns:
            Path to the deepest directory
        """
        current_path = Path(base_path)
        self.fs.create_dir(current_path)
        
        for i in range(depth):
            current_path = current_path / f"level_{i}"
            self.fs.create_dir(current_path)
            # Add a file at each level
            file_path = current_path / f"file_level_{i}.txt"
            self.fs.create_file(file_path, contents=b"test content")
        
        return str(current_path)

    def create_large_directory(self, base_path: str, num_files: int) -> str:
        """Create a directory with many files (100k+).
        
        Args:
            base_path: Base directory path
            num_files: Number of files to create
            
        Returns:
            Path to the created directory
        """
        dir_path = Path(base_path) / "large_dir"
        self.fs.create_dir(dir_path)
        
        for i in range(num_files):
            file_path = dir_path / f"file_{i:06d}.txt"
            self.fs.create_file(file_path, contents=b"test content")
        
        return str(dir_path)

    def create_sparse_directory(self, base_path: str, depth: int, files_per_level: int) -> str:
        """Create sparse directory structure (few files, deep nesting).
        
        Args:
            base_path: Base directory path
            depth: Nesting depth
            files_per_level: Files to create at each level
            
        Returns:
            Path to the base directory
        """
        base_path = Path(base_path)
        self.fs.create_dir(base_path)
        
        def create_level(path: Path, current_depth: int):
            if current_depth >= depth:
                return
            
            for i in range(files_per_level):
                file_path = path / f"file_{i}.txt"
                self.fs.create_file(file_path, contents=b"sparse content")
            
            subdir = path / f"level_{current_depth}"
            self.fs.create_dir(subdir)
            create_level(subdir, current_depth + 1)
        
        create_level(base_path, 0)
        return str(base_path)

    def create_mixed_structure(
        self,
        base_path: str,
        normal_files: int = 100,
        large_files: int = 5,
        archive_files: int = 10,
    ) -> Tuple[str, List[str]]:
        """Create a mixed structure with normal and problematic files.
        
        Args:
            base_path: Base directory path
            normal_files: Number of normal files to create
            large_files: Number of large files (>1GB) to create
            archive_files: Number of archive files to create
            
        Returns:
            Tuple of (base_path, list of problematic file paths)
        """
        base_path = Path(base_path)
        self.fs.create_dir(base_path)
        problematic = []
        
        # Create normal files
        for i in range(normal_files):
            file_path = base_path / f"normal_{i}.txt"
            self.fs.create_file(file_path, contents=b"normal content")
        
        # Create large files
        for i in range(large_files):
            file_path = base_path / f"large_{i}.bin"
            large_size = int(1.5 * 1024**3)  # 1.5GB
            self.fs.create_file(file_path, st_size=large_size)
            problematic.append(str(file_path))
        
        # Create archive files
        archive_extensions = [".zip", ".tar.gz", ".7z", ".rar"]
        for i in range(archive_files):
            ext = archive_extensions[i % len(archive_extensions)]
            file_path = base_path / f"archive_{i}{ext}"
            self.fs.create_file(file_path, contents=b"archive content")
            problematic.append(str(file_path))
        
        return str(base_path), problematic

