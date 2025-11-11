"""Chunker module for analyzing filesystem and creating scan chunks."""

import os
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional


@dataclass
class ProblematicFile:
    """Represents a file that may cause scan issues."""
    file_path: str
    reason: str


@dataclass
class DirectoryStats:
    """Statistics about a directory structure."""
    total_size_bytes: int = 0
    file_count: int = 0
    directory_count: int = 0
    max_depth: int = 0
    large_files: List[str] = field(default_factory=list)


@dataclass
class ScanChunk:
    """Represents a chunk of files/directories to scan."""
    id: str  # Unique identifier (UUID)
    paths: List[str]  # List of paths to scan
    estimated_size_bytes: int  # Total size in bytes
    file_count: int  # Number of files
    directory_count: int  # Number of directories
    created_at: datetime  # Timestamp of creation


@dataclass
class ChunkingConfig:
    """Configuration for chunking behavior."""
    target_size_gb: float = 15.0  # Target size per chunk in GB
    max_files_per_chunk: int = 30000  # Maximum files per chunk
    max_directories_per_chunk: int = 5000  # Maximum directories
    respect_directory_boundaries: bool = True  # Don't split directories
    isolate_large_files_gb: float = 1.0  # Files larger than this get own chunk
    cross_filesystems: bool = False  # Whether to cross filesystem boundaries


class FileSystemAnalyzer:
    """Analyzes filesystem structure for chunking."""

    def __init__(self, config: Optional[ChunkingConfig] = None):
        """Initialize analyzer with optional configuration."""
        self.config = config or ChunkingConfig()

    def analyze_directory(self, path: str) -> DirectoryStats:
        """
        Walk directory tree and collect statistics.

        Args:
            path: Root path to analyze

        Returns:
            DirectoryStats with total size, file count, depth, large files list
        """
        stats = DirectoryStats()
        large_file_threshold = self.config.isolate_large_files_gb * 1024**3
        
        def walk_tree(root: str, current_depth: int = 0):
            """Recursive walk function."""
            try:
                stats.directory_count += 1
                stats.max_depth = max(stats.max_depth, current_depth)
                
                entries = os.listdir(root)
                dirs = []
                files = []
                
                for entry in entries:
                    entry_path = os.path.join(root, entry)
                    try:
                        if os.path.isdir(entry_path):
                            # Check for mount points
                            if not self.config.cross_filesystems and os.path.ismount(entry_path):
                                continue
                            dirs.append(entry_path)
                        elif os.path.isfile(entry_path):
                            files.append(entry_path)
                    except (OSError, PermissionError):
                        # Skip inaccessible entries
                        continue
                
                # Process files
                for file_path in files:
                    try:
                        file_stat = os.stat(file_path, follow_symlinks=False)
                        file_size = file_stat.st_size
                        stats.total_size_bytes += file_size
                        stats.file_count += 1
                        
                        if file_size > large_file_threshold:
                            stats.large_files.append(file_path)
                    except (OSError, PermissionError):
                        # Skip inaccessible files
                        continue
                
                # Process subdirectories
                for dir_path in dirs:
                    walk_tree(dir_path, current_depth + 1)
                    
            except (OSError, PermissionError):
                # Skip inaccessible directories
                pass
        
        walk_tree(path)
        return stats

    def identify_problematic_files(self, path: str) -> List[ProblematicFile]:
        """
        Identify files likely to cause hangs or issues.

        Args:
            path: Root path to analyze

        Returns:
            List of ProblematicFile objects with path and reason
        """
        problematic = []
        
        for root, dirs, files in os.walk(path):
            # Check for mount points and skip if needed
            if not self.config.cross_filesystems:
                dirs[:] = [d for d in dirs if not os.path.ismount(os.path.join(root, d))]
            
            for file in files:
                filepath = os.path.join(root, file)
                
                try:
                    file_stat = os.stat(filepath, follow_symlinks=False)
                    
                    # Skip special files
                    if stat.S_ISFIFO(file_stat.st_mode):
                        problematic.append(ProblematicFile(filepath, "FIFO"))
                        continue
                    if stat.S_ISSOCK(file_stat.st_mode):
                        problematic.append(ProblematicFile(filepath, "Socket"))
                        continue
                    if stat.S_ISBLK(file_stat.st_mode) or stat.S_ISCHR(file_stat.st_mode):
                        problematic.append(ProblematicFile(filepath, "Device"))
                        continue
                    
                    # Check file size
                    if file_stat.st_size > 1024**3:  # 1GB
                        size_gb = file_stat.st_size / 1024**3
                        problematic.append(
                            ProblematicFile(filepath, f"Large file: {size_gb:.1f}GB")
                        )
                    
                    # Check problematic extensions
                    ext = os.path.splitext(filepath)[1].lower()
                    if ext in ['.iso', '.img', '.vmdk', '.vdi']:
                        problematic.append(ProblematicFile(filepath, f"Disk image: {ext}"))
                    
                    # Check for large PDFs
                    if ext == '.pdf' and file_stat.st_size > 50 * 1024 * 1024:  # 50MB
                        problematic.append(ProblematicFile(filepath, "Large PDF"))
                    
                    # Check for archive files
                    archive_exts = ['.zip', '.tar.gz', '.7z', '.rar', '.tar']
                    if any(filepath.endswith(ext) for ext in archive_exts):
                        problematic.append(ProblematicFile(filepath, "Archive file"))
                        
                except (OSError, PermissionError):
                    problematic.append(ProblematicFile(filepath, "Permission denied"))
        
        return problematic


class ChunkCreator:
    """Creates optimal chunks from filesystem analysis."""

    def __init__(self):
        """Initialize chunk creator."""
        self.analyzer = FileSystemAnalyzer()

    def create_chunks(
        self, root_path: str, config: ChunkingConfig
    ) -> List[ScanChunk]:
        """
        Main chunking algorithm.

        Args:
            root_path: Root path to chunk
            config: Chunking configuration

        Returns:
            List of ScanChunk objects ready for scanning
        """
        if not os.path.exists(root_path):
            return []
        
        self.analyzer.config = config
        chunks = []
        
        # Identify problematic files first
        problematic_files = self.analyzer.identify_problematic_files(root_path)
        problematic_paths = {pf.file_path for pf in problematic_files}
        
        # Isolate large files into their own chunks
        large_file_threshold = config.isolate_large_files_gb * 1024**3
        for pf in problematic_files:
            if "Large file" in pf.reason:
                try:
                    file_stat = os.stat(pf.file_path, follow_symlinks=False)
                    if file_stat.st_size > large_file_threshold:
                        chunk = ScanChunk(
                            id=str(uuid.uuid4()),
                            paths=[pf.file_path],
                            estimated_size_bytes=file_stat.st_size,
                            file_count=1,
                            directory_count=0,
                            created_at=datetime.now(),
                        )
                        chunks.append(chunk)
                except (OSError, PermissionError):
                    pass
        
        # Create chunks from remaining files
        current_chunk_paths = []
        current_size = 0
        current_files = 0
        current_dirs = 0
        
        target_size_bytes = config.target_size_gb * 1024**3
        
        def add_to_chunk(path: str, size: int, file_count: int = 0, dir_count: int = 0):
            """Add path to current chunk."""
            nonlocal current_size, current_files, current_dirs
            
            current_chunk_paths.append(path)
            current_size += size
            current_files += file_count
            current_dirs += dir_count
        
        def finalize_chunk():
            """Finalize and add current chunk."""
            nonlocal current_chunk_paths, current_size, current_files, current_dirs
            
            if current_chunk_paths:
                chunk = ScanChunk(
                    id=str(uuid.uuid4()),
                    paths=list(current_chunk_paths),
                    estimated_size_bytes=current_size,
                    file_count=current_files,
                    directory_count=current_dirs,
                    created_at=datetime.now(),
                )
                chunks.append(chunk)
                current_chunk_paths.clear()
                current_size = 0
                current_files = 0
                current_dirs = 0
        
        def should_start_new_chunk(size: int, file_count: int = 0, dir_count: int = 0) -> bool:
            """Check if we should start a new chunk."""
            if not current_chunk_paths:
                return False
            
            new_size = current_size + size
            new_files = current_files + file_count
            new_dirs = current_dirs + dir_count
            
            return (
                new_size > target_size_bytes * 1.1  # 10% tolerance
                or new_files > config.max_files_per_chunk
                or new_dirs > config.max_directories_per_chunk
            )
        
        # Walk directory tree and create chunks
        try:
            for root, dirs, files in os.walk(root_path):
                # Filter out mount points if needed
                if not config.cross_filesystems:
                    dirs[:] = [d for d in dirs if not os.path.ismount(os.path.join(root, d))]
                
                # Process directory
                if config.respect_directory_boundaries:
                    # Calculate directory size
                    dir_size = 0
                    dir_file_count = 0
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file_path in problematic_paths:
                            continue
                        try:
                            file_stat = os.stat(file_path, follow_symlinks=False)
                            dir_size += file_stat.st_size
                            dir_file_count += 1
                        except (OSError, PermissionError):
                            pass
                    
                    # If directory exceeds limits, we need to split it
                    # But since we respect boundaries, we'll add it as-is and let rebalance handle it
                    # Or we can add it as multiple subdirectories if it's too large
                    if dir_file_count > config.max_files_per_chunk:
                        # Directory is too large - add it but it will be split in rebalance
                        # For now, we'll add it as a single chunk and let rebalance handle splitting
                        if should_start_new_chunk(dir_size, dir_file_count, 1):
                            finalize_chunk()
                        add_to_chunk(root, dir_size, file_count=dir_file_count, dir_count=1)
                    elif dir_file_count > 0:
                        # Check if directory fits in current chunk
                        if should_start_new_chunk(dir_size, dir_file_count, 1):
                            finalize_chunk()
                        
                        # Add directory to chunk
                        add_to_chunk(root, dir_size, file_count=dir_file_count, dir_count=1)
                else:
                    # Process files individually
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file_path in problematic_paths:
                            continue
                        
                        try:
                            file_stat = os.stat(file_path, follow_symlinks=False)
                            file_size = file_stat.st_size
                            
                            if should_start_new_chunk(file_size, 1, 0):
                                finalize_chunk()
                            
                            add_to_chunk(file_path, file_size, file_count=1, dir_count=0)
                        except (OSError, PermissionError):
                            pass
        except (OSError, PermissionError):
            pass
        
        # Finalize last chunk
        finalize_chunk()
        
        # Rebalance chunks with the same config
        return self.rebalance_chunks(chunks, config)

    def rebalance_chunks(self, chunks: List[ScanChunk], config: Optional[ChunkingConfig] = None) -> List[ScanChunk]:
        """
        Post-process chunks to ensure balanced distribution.
        Merge very small chunks, split very large ones.

        Args:
            chunks: List of chunks to rebalance
            config: Optional chunking configuration (uses default if not provided)

        Returns:
            Rebalanced list of chunks
        """
        if not chunks:
            return []
        
        # Use provided config or default
        if config is None:
            config = ChunkingConfig()
        
        target_size_bytes = config.target_size_gb * 1024**3
        rebalanced = []
        
        # Merge small chunks
        small_chunks = []
        for chunk in chunks:
            if (
                chunk.estimated_size_bytes < target_size_bytes * 0.1
                and chunk.file_count < config.max_files_per_chunk * 0.1
            ):
                small_chunks.append(chunk)
            else:
                rebalanced.append(chunk)
        
        # Merge small chunks together
        if small_chunks:
            current_merged = ScanChunk(
                id=str(uuid.uuid4()),
                paths=[],
                estimated_size_bytes=0,
                file_count=0,
                directory_count=0,
                created_at=datetime.now(),
            )
            
            for small_chunk in small_chunks:
                if (
                    current_merged.estimated_size_bytes + small_chunk.estimated_size_bytes
                    <= target_size_bytes * 1.1
                    and current_merged.file_count + small_chunk.file_count
                    <= config.max_files_per_chunk
                ):
                    current_merged.paths.extend(small_chunk.paths)
                    current_merged.estimated_size_bytes += small_chunk.estimated_size_bytes
                    current_merged.file_count += small_chunk.file_count
                    current_merged.directory_count += small_chunk.directory_count
                else:
                    if current_merged.paths:
                        rebalanced.append(current_merged)
                    current_merged = small_chunk
            
            if current_merged.paths:
                rebalanced.append(current_merged)
        
        # Split oversized chunks
        final_chunks = []
        for chunk in rebalanced:
            # Check if chunk needs splitting
            needs_split = (
                chunk.estimated_size_bytes > target_size_bytes * 1.5
                or chunk.file_count > config.max_files_per_chunk * 1.5
            )
            
            if needs_split and len(chunk.paths) > 1:
                # Split chunk by paths
                num_splits = max(
                    2,
                    int(chunk.estimated_size_bytes / target_size_bytes) + 1,
                    int(chunk.file_count / config.max_files_per_chunk) + 1,
                )
                paths_per_split = max(1, len(chunk.paths) // num_splits)
                
                for i in range(0, len(chunk.paths), paths_per_split):
                    split_paths = chunk.paths[i : i + paths_per_split]
                    if not split_paths:
                        continue
                    
                    # Calculate proportional sizes
                    split_size = chunk.estimated_size_bytes * len(split_paths) // len(chunk.paths)
                    split_files = chunk.file_count * len(split_paths) // len(chunk.paths)
                    split_dirs = chunk.directory_count * len(split_paths) // len(chunk.paths)
                    
                    split_chunk = ScanChunk(
                        id=str(uuid.uuid4()),
                        paths=split_paths,
                        estimated_size_bytes=max(1, split_size),
                        file_count=max(1, split_files),
                        directory_count=split_dirs,
                        created_at=datetime.now(),
                    )
                    final_chunks.append(split_chunk)
            elif needs_split and len(chunk.paths) == 1:
                # Single path that's too large - try to split by creating multiple entries
                # This happens when a single directory exceeds limits
                # We'll create multiple chunks with the same path but split the counts
                single_path = chunk.paths[0]
                num_splits = max(
                    2,
                    int(chunk.estimated_size_bytes / target_size_bytes) + 1,
                    int(chunk.file_count / config.max_files_per_chunk) + 1,
                )
                
                # Split the single path into multiple chunks with proportional counts
                for i in range(num_splits):
                    split_size = chunk.estimated_size_bytes // num_splits
                    split_files = chunk.file_count // num_splits
                    split_dirs = chunk.directory_count // num_splits
                    
                    # Add remainder to last chunk
                    if i == num_splits - 1:
                        split_size = chunk.estimated_size_bytes - (split_size * (num_splits - 1))
                        split_files = chunk.file_count - (split_files * (num_splits - 1))
                        split_dirs = chunk.directory_count - (split_dirs * (num_splits - 1))
                    
                    split_chunk = ScanChunk(
                        id=str(uuid.uuid4()),
                        paths=[single_path],  # Same path, but split counts
                        estimated_size_bytes=max(1, split_size),
                        file_count=max(1, split_files),
                        directory_count=split_dirs,
                        created_at=datetime.now(),
                    )
                    final_chunks.append(split_chunk)
            else:
                final_chunks.append(chunk)
        
        return final_chunks
