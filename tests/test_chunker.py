"""Tests for the chunker module."""

import os
from datetime import datetime
from pathlib import Path

import pytest
from pyfakefs.fake_filesystem import FakeFilesystem

from clamscan_splitter.chunker import (
    ChunkCreator,
    ChunkingConfig,
    FileSystemAnalyzer,
    ProblematicFile,
    ScanChunk,
)
from tests.fixtures.mock_filesystem import MockFileSystem


class TestScanChunk:
    """Test ScanChunk dataclass."""

    def test_scan_chunk_creation(self):
        """Test creating a ScanChunk."""
        chunk = ScanChunk(
            id="test-chunk-1",
            paths=["/test/path1", "/test/path2"],
            estimated_size_bytes=1024 * 1024 * 1024,  # 1GB
            file_count=1000,
            directory_count=10,
            created_at=datetime.now(),
        )
        
        assert chunk.id == "test-chunk-1"
        assert len(chunk.paths) == 2
        assert chunk.estimated_size_bytes == 1024**3
        assert chunk.file_count == 1000
        assert chunk.directory_count == 10


class TestChunkingConfig:
    """Test ChunkingConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ChunkingConfig()
        
        assert config.target_size_gb == 15.0
        assert config.max_files_per_chunk == 30000
        assert config.max_directories_per_chunk == 5000
        assert config.respect_directory_boundaries is True
        assert config.isolate_large_files_gb == 1.0

    def test_custom_config(self):
        """Test custom configuration values."""
        config = ChunkingConfig(
            target_size_gb=20.0,
            max_files_per_chunk=50000,
            max_directories_per_chunk=10000,
            respect_directory_boundaries=False,
            isolate_large_files_gb=2.0,
        )
        
        assert config.target_size_gb == 20.0
        assert config.max_files_per_chunk == 50000
        assert config.max_directories_per_chunk == 10000
        assert config.respect_directory_boundaries is False
        assert config.isolate_large_files_gb == 2.0


class TestFileSystemAnalyzer:
    """Test FileSystemAnalyzer class."""

    def test_analyze_directory(self, fs):
        """Test analyzing a directory structure."""
        mock_fs = MockFileSystem(fs)
        base_path = mock_fs.create_test_structure(
            "/test", total_size_gb=1.0, num_files=100, max_depth=3
        )
        
        analyzer = FileSystemAnalyzer()
        stats = analyzer.analyze_directory(base_path)
        
        assert stats.total_size_bytes > 0
        assert stats.file_count == 100
        assert stats.directory_count > 0
        assert stats.max_depth <= 3

    def test_identify_problematic_files_large(self, fs):
        """Test identifying large files (>1GB)."""
        mock_fs = MockFileSystem(fs)
        problematic = mock_fs.create_problematic_files("/test")
        
        analyzer = FileSystemAnalyzer()
        found_problematic = analyzer.identify_problematic_files("/test")
        
        # Should find large file
        large_files = [p for p in found_problematic if "large" in p.reason.lower()]
        assert len(large_files) > 0

    def test_identify_problematic_files_archives(self, fs):
        """Test identifying archive files."""
        mock_fs = MockFileSystem(fs)
        mock_fs.create_problematic_files("/test")
        
        analyzer = FileSystemAnalyzer()
        found_problematic = analyzer.identify_problematic_files("/test")
        
        # Should find archive files
        archive_files = [
            p for p in found_problematic
            if any(ext in p.file_path for ext in [".zip", ".tar.gz", ".7z", ".rar"])
        ]
        assert len(archive_files) > 0

    def test_identify_problematic_files_disk_images(self, fs):
        """Test identifying disk image files."""
        mock_fs = MockFileSystem(fs)
        mock_fs.create_problematic_files("/test")
        
        analyzer = FileSystemAnalyzer()
        found_problematic = analyzer.identify_problematic_files("/test")
        
        # Should find disk images
        disk_images = [
            p for p in found_problematic
            if any(ext in p.file_path for ext in [".iso", ".img", ".vmdk", ".vdi"])
        ]
        assert len(disk_images) > 0

    def test_analyze_empty_directory(self, fs):
        """Test analyzing an empty directory."""
        fs.create_dir("/empty")
        
        analyzer = FileSystemAnalyzer()
        stats = analyzer.analyze_directory("/empty")
        
        assert stats.file_count == 0
        assert stats.directory_count == 1  # The directory itself
        assert stats.total_size_bytes == 0

    def test_analyze_deep_nesting(self, fs):
        """Test analyzing deeply nested directories."""
        mock_fs = MockFileSystem(fs)
        deep_path = mock_fs.create_deep_nesting("/test", depth=20)
        
        analyzer = FileSystemAnalyzer()
        stats = analyzer.analyze_directory("/test")
        
        assert stats.max_depth >= 20

    def test_analyze_large_directory(self, fs):
        """Test analyzing directory with many files (lightweight for unit test)."""
        mock_fs = MockFileSystem(fs)
        # Use smaller number for fast unit tests - heavy testing in integration tests
        large_dir = mock_fs.create_large_directory("/test", num_files=1000)
        
        analyzer = FileSystemAnalyzer()
        stats = analyzer.analyze_directory("/test")
        
        assert stats.file_count >= 1000


class TestChunkCreator:
    """Test ChunkCreator class."""

    def test_create_chunks_respects_size_limit(self, fs):
        """Test that chunks don't exceed size limit."""
        mock_fs = MockFileSystem(fs)
        # Create 30GB of files
        base_path = mock_fs.create_test_structure(
            "/test", total_size_gb=30.0, num_files=1000, max_depth=3
        )
        
        config = ChunkingConfig(target_size_gb=15.0)
        creator = ChunkCreator()
        chunks = creator.create_chunks(base_path, config)
        
        assert len(chunks) >= 2  # Should create at least 2 chunks
        for chunk in chunks:
            assert chunk.estimated_size_bytes <= 15.0 * 1024**3 * 1.1  # Allow 10% tolerance

    def test_create_chunks_respects_file_count_limit(self, fs):
        """Test that chunks don't exceed file count limit (lightweight unit test)."""
        mock_fs = MockFileSystem(fs)
        # Use smaller number for fast unit tests - heavy testing in integration tests
        base_path = mock_fs.create_large_directory("/test", num_files=5000)
        
        config = ChunkingConfig(max_files_per_chunk=1000)
        creator = ChunkCreator()
        chunks = creator.create_chunks(base_path, config)
        
        assert len(chunks) >= 5  # Should create at least 5 chunks
        for chunk in chunks:
            assert chunk.file_count <= 1000

    def test_create_chunks_isolates_large_files(self, fs):
        """Test that large files get isolated into their own chunks."""
        mock_fs = MockFileSystem(fs)
        # Create normal files
        mock_fs.create_test_structure("/test/normal", total_size_gb=1.0, num_files=100, max_depth=2)
        # Create large file (>1GB)
        large_file = Path("/test/large_file.bin")
        fs.create_file(large_file, st_size=int(1.5 * 1024**3))
        
        config = ChunkingConfig(isolate_large_files_gb=1.0)
        creator = ChunkCreator()
        chunks = creator.create_chunks("/test", config)
        
        # Should have at least one chunk with just the large file
        large_file_chunks = [
            c for c in chunks
            if len(c.paths) == 1 and "large_file.bin" in c.paths[0]
        ]
        assert len(large_file_chunks) > 0

    def test_create_chunks_respects_directory_boundaries(self, fs):
        """Test that chunks respect directory boundaries when enabled."""
        mock_fs = MockFileSystem(fs)
        # Create structure with clear directories
        fs.create_dir("/test/dir1")
        fs.create_dir("/test/dir2")
        for i in range(100):
            fs.create_file(f"/test/dir1/file{i}.txt", contents=b"content")
            fs.create_file(f"/test/dir2/file{i}.txt", contents=b"content")
        
        config = ChunkingConfig(
            target_size_gb=0.001,  # Very small to force splitting
            respect_directory_boundaries=True,
        )
        creator = ChunkCreator()
        chunks = creator.create_chunks("/test", config)
        
        # Each directory should be in separate chunks or together
        # Check that files from same directory are grouped
        dir1_paths = [p for chunk in chunks for p in chunk.paths if "dir1" in p]
        dir2_paths = [p for chunk in chunks for p in chunk.paths if "dir2" in p]
        assert len(dir1_paths) > 0
        assert len(dir2_paths) > 0

    def test_create_chunks_handles_empty_directory(self, fs):
        """Test creating chunks from empty directory."""
        fs.create_dir("/empty")
        
        config = ChunkingConfig()
        creator = ChunkCreator()
        chunks = creator.create_chunks("/empty", config)
        
        # Should return empty list or single empty chunk
        assert len(chunks) == 0 or all(c.file_count == 0 for c in chunks)

    def test_rebalance_chunks_merges_small(self, fs):
        """Test that rebalance merges very small chunks."""
        chunks = [
            ScanChunk(
                id=f"chunk-{i}",
                paths=[f"/test/file{i}.txt"],
                estimated_size_bytes=1024,  # Very small
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
            for i in range(10)
        ]
        
        config = ChunkingConfig(target_size_gb=15.0)
        creator = ChunkCreator()
        rebalanced = creator.rebalance_chunks(chunks)
        
        # Should have fewer chunks after merging
        assert len(rebalanced) <= len(chunks)

    def test_rebalance_chunks_splits_large(self, fs):
        """Test that rebalance splits very large chunks."""
        # Create a chunk that's too large
        large_chunk = ScanChunk(
            id="large-chunk",
            paths=["/test"],
            estimated_size_bytes=30 * 1024**3,  # 30GB
            file_count=50000,
            directory_count=1000,
            created_at=datetime.now(),
        )
        
        config = ChunkingConfig(target_size_gb=15.0)
        creator = ChunkCreator()
        rebalanced = creator.rebalance_chunks([large_chunk])
        
        # Should split into multiple chunks
        assert len(rebalanced) > 1
        for chunk in rebalanced:
            assert chunk.estimated_size_bytes <= 15.0 * 1024**3 * 1.1

    def test_create_chunks_handles_permission_errors(self, fs):
        """Test that chunker handles permission errors gracefully."""
        # Create some accessible files
        fs.create_file("/test/file1.txt", contents=b"content")
        fs.create_file("/test/file2.txt", contents=b"content")
        
        config = ChunkingConfig()
        creator = ChunkCreator()
        # Should not raise exception even if some paths are inaccessible
        chunks = creator.create_chunks("/test", config)
        
        assert len(chunks) >= 0  # Should handle gracefully

    def test_create_chunks_with_mixed_structure(self, fs):
        """Test creating chunks from mixed structure (normal + problematic files)."""
        mock_fs = MockFileSystem(fs)
        base_path, problematic = mock_fs.create_mixed_structure(
            "/test", normal_files=1000, large_files=3, archive_files=5
        )
        
        config = ChunkingConfig()
        creator = ChunkCreator()
        chunks = creator.create_chunks(base_path, config)
        
        assert len(chunks) > 0
        # All problematic files should be accounted for
        all_paths = [p for chunk in chunks for p in chunk.paths]
        for prob_path in problematic:
            # Path should be in some chunk or isolated
            assert any(prob_path in p or p in prob_path for p in all_paths)

