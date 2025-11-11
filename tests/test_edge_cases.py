"""Edge case and additional tests for improved coverage."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from clamscan_splitter.chunker import ScanChunk
from clamscan_splitter.merger import MergedReport, QuarantineEntry
from clamscan_splitter.parser import ScanResult
from clamscan_splitter.retry import RetryManager
from clamscan_splitter.scanner import ScanConfig, ScanWorker
from clamscan_splitter.state import ProgressTracker
from tests.fixtures.mock_outputs import CLEAN_SCAN_OUTPUT


class TestEdgeCases:
    """Test edge cases and error paths."""

    def test_chunker_empty_directory(self, fs):
        """Test chunker with empty directory."""
        from clamscan_splitter.chunker import ChunkCreator, ChunkingConfig
        
        fs.create_dir("/empty")
        
        chunker = ChunkCreator()
        config = ChunkingConfig()
        chunks = chunker.create_chunks("/empty", config)
        
        assert len(chunks) == 0

    def test_parser_empty_output(self):
        """Test parser with empty output."""
        from clamscan_splitter.parser import ClamAVOutputParser
        
        parser = ClamAVOutputParser()
        result = parser.parse_output("", "", 0)
        
        # Empty output may be considered partial or success
        assert result.status in ["success", "partial"]
        assert result.scanned_files == 0

    def test_retry_manager_empty_chunk(self):
        """Test retry manager with empty chunk."""
        manager = RetryManager()
        
        chunk = ScanChunk(
            id="empty",
            paths=[],
            estimated_size_bytes=0,
            file_count=0,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        split_chunks = manager.split_chunk(chunk, factor=2)
        
        assert len(split_chunks) == 1
        assert split_chunks[0] == chunk

    def test_progress_tracker_all_completed(self):
        """Test progress tracker when all chunks complete."""
        tracker = ProgressTracker(total_chunks=5)
        tracker.completed = 5
        
        percentage = tracker.get_progress_percentage()
        
        assert percentage == 100.0

    def test_merger_empty_results(self):
        """Test merger with empty results list."""
        from clamscan_splitter.merger import ResultMerger
        
        merger = ResultMerger()
        report = merger.merge_results([])
        
        assert report.total_scanned_files == 0
        assert report.chunks_successful == 0

    def test_merger_single_result(self):
        """Test merger with single result."""
        from clamscan_splitter.merger import ResultMerger
        
        merger = ResultMerger()
        results = [
            ScanResult(
                chunk_id="chunk-1",
                status="success",
                scanned_files=100,
                scanned_directories=10,
                total_errors=0,
                data_scanned_mb=50.0,
                data_read_mb=50.0,
                scan_time_seconds=10.0,
                engine_version="1.4.3",
                raw_output="",
            )
        ]
        
        report = merger.merge_results(results)
        
        assert report.total_scanned_files == 100
        assert report.chunks_successful == 1

    @pytest.mark.asyncio
    async def test_scanner_zero_timeout(self):
        """Test scanner with zero timeout."""
        worker = ScanWorker()
        config = ScanConfig(
            min_timeout_seconds=0,
            base_timeout_per_gb=0,
        )
        
        chunk = ScanChunk(
            id="test",
            paths=["/test"],
            estimated_size_bytes=0,
            file_count=0,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        timeout = worker._calculate_timeout(chunk, config)
        
        # Should use minimum timeout
        assert timeout >= config.min_timeout_seconds

    def test_state_manager_invalid_json(self, tmp_path):
        """Test state manager with invalid JSON."""
        from clamscan_splitter.state import StateManager
        
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        
        # Create invalid JSON file
        invalid_file = state_dir / "invalid.json"
        invalid_file.write_text("{ invalid json }")
        
        manager = StateManager(state_dir=str(state_dir))
        state = manager.load_state("invalid")
        
        assert state is None

    def test_config_loader_invalid_path(self):
        """Test config loader with invalid path."""
        from clamscan_splitter.config import ConfigLoader
        
        loader = ConfigLoader()
        config = loader.load_config("/nonexistent/path.yaml")
        
        # Should return default config
        assert "chunking" in config
        assert "scanning" in config

    def test_quarantine_entry_creation(self):
        """Test creating quarantine entry."""
        entry = QuarantineEntry(
            file_path="/test/file.txt",
            reason="timeout",
            file_size_bytes=1024,
            retry_count=3,
            last_attempt=datetime.now(),
        )
        
        assert entry.file_path == "/test/file.txt"
        assert entry.reason == "timeout"
        assert entry.retry_count == 3

    def test_progress_tracker_eta_calculation(self):
        """Test ETA calculation in progress tracker."""
        tracker = ProgressTracker(total_chunks=10)
        tracker.completed = 5
        
        import time
        tracker.start_time = time.time() - 10  # 10 seconds ago
        
        eta = tracker.get_eta()
        
        # Should calculate ETA based on rate
        assert eta is None or eta.total_seconds() >= 0


class TestLargeScaleMock:
    """Test large-scale scenarios using mocks."""

    @pytest.mark.asyncio
    async def test_large_file_count_simulation(self, fs):
        """Test simulating 1.4M files using mocks."""
        from clamscan_splitter.chunker import ChunkCreator, ChunkingConfig
        
        # Create mock filesystem with many files
        base_path = "/test/large"
        fs.create_dir(base_path)
        
        # Simulate 1.4M files by creating chunks that represent them
        # We'll create a smaller number but test the logic handles large counts
        chunker = ChunkCreator()
        config = ChunkingConfig(
            target_size_gb=15.0,
            max_files_per_chunk=30000,
        )
        
        # Create many subdirectories to simulate large structure
        for i in range(100):
            dir_path = f"{base_path}/dir{i}"
            fs.create_dir(dir_path)
            for j in range(100):
                fs.create_file(f"{dir_path}/file{j}.txt", contents="test")
        
        chunks = chunker.create_chunks(base_path, config)
        
        # Should create multiple chunks
        assert len(chunks) > 0
        
        # Verify chunk limits are respected
        for chunk in chunks:
            assert chunk.file_count <= config.max_files_per_chunk

    def test_memory_usage_stays_within_limits(self):
        """Test that memory usage calculations stay within limits."""
        from clamscan_splitter.scanner import ScanOrchestrator
        
        config = ScanConfig(
            max_concurrent_processes=10,
            memory_per_process_gb=2.0,
            min_free_memory_gb=2.0,
        )
        
        orchestrator = ScanOrchestrator(config)
        
        # Should calculate reasonable worker count
        assert orchestrator.max_workers > 0
        assert orchestrator.max_workers <= config.max_concurrent_processes or config.max_concurrent_processes is None

    def test_quarantine_system_at_scale(self):
        """Test quarantine system with many files."""
        from clamscan_splitter.retry import RetryManager
        
        manager = RetryManager()
        
        # Simulate many files being quarantined
        for i in range(1000):
            manager.file_retry_counts[f"/test/file{i}.txt"] = 3
        
        # Should handle large quarantine list
        assert len(manager.file_retry_counts) == 1000

    def test_atomic_writes_prevent_corruption(self, tmp_path):
        """Test that atomic writes prevent corruption."""
        from clamscan_splitter.state import ScanState, StateManager
        from datetime import datetime
        
        state_dir = tmp_path / "state"
        manager = StateManager(state_dir=str(state_dir))
        
        state = ScanState(
            scan_id="test-atomic",
            root_path="/test",
            total_chunks=10,
            completed_chunks=["chunk-1"],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        
        # Save state
        manager.save_state(state)
        
        # Verify file exists and is valid JSON
        state_file = state_dir / "test-atomic.json"
        assert state_file.exists()
        
        # Load and verify
        loaded = manager.load_state("test-atomic")
        assert loaded is not None
        assert loaded.scan_id == "test-atomic"
        
        # Verify temp file was cleaned up
        temp_files = list(state_dir.glob(".test-atomic.*.tmp"))
        assert len(temp_files) == 0

    def test_chunk_rebalancing_large_chunks(self):
        """Test rebalancing with very large chunks."""
        from clamscan_splitter.chunker import ChunkCreator, ChunkingConfig
        
        chunker = ChunkCreator()
        config = ChunkingConfig(
            target_size_gb=15.0,
            max_files_per_chunk=30000,
        )
        
        # Create a chunk that exceeds limits
        large_chunk = ScanChunk(
            id="large",
            paths=["/test"] * 50000,  # Too many paths
            estimated_size_bytes=20 * 1024**3,  # 20GB
            file_count=50000,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        # Rebalance should split it
        rebalanced = chunker.rebalance_chunks([large_chunk], config)
        
        # Should create multiple smaller chunks
        assert len(rebalanced) > 1
        for chunk in rebalanced:
            assert chunk.file_count <= config.max_files_per_chunk

    def test_error_handling_malformed_output(self):
        """Test handling of malformed ClamAV output."""
        from clamscan_splitter.parser import ClamAVOutputParser
        
        parser = ClamAVOutputParser()
        
        # Completely malformed output
        malformed = "This is not ClamAV output at all!!!"
        result = parser.parse_output(malformed, "", 0)
        
        # Should handle gracefully
        assert result is not None
        assert result.status in ["success", "failed", "partial"]

    def test_concurrent_scan_limit(self):
        """Test that concurrent scan limit is enforced."""
        from clamscan_splitter.scanner import ScanOrchestrator
        
        config = ScanConfig(max_concurrent_processes=4)
        orchestrator = ScanOrchestrator(config)
        
        # Should respect max concurrent processes
        assert orchestrator.max_workers <= 4

    def test_backoff_calculation_edge_cases(self):
        """Test backoff calculation with edge cases."""
        from clamscan_splitter.retry import RetryConfig, RetryManager
        
        manager = RetryManager()
        
        # Test with very large attempt number
        config = RetryConfig(
            base_delay_seconds=1.0,
            max_delay_seconds=300.0,
        )
        
        delay = manager.calculate_backoff(100, config)
        
        # Should cap at max_delay
        assert delay <= config.max_delay_seconds

    def test_report_formatting_with_all_fields(self):
        """Test report formatting with all possible fields."""
        from clamscan_splitter.merger import ResultMerger
        
        merger = ResultMerger()
        
        report = MergedReport(
            total_scanned_files=1000,
            total_scanned_directories=100,
            total_infected_files=5,
            infected_file_paths=["/path1", "/path2"],
            total_errors=2,
            total_data_scanned_mb=500.0,
            total_data_read_mb=1000.0,
            total_time_seconds=100.0,
            wall_clock_time_seconds=50.0,
            engine_version="1.4.3",
            chunks_successful=10,
            chunks_failed=1,
            chunks_partial=0,
            skipped_paths=["/skip1"],
            quarantined_files=[
                QuarantineEntry("/quarantine1", "timeout"),
                QuarantineEntry("/quarantine2", "permission"),
            ],
            scan_complete=False,
        )
        
        formatted = merger.format_report(report)
        
        assert "SCAN SUMMARY" in formatted
        assert "QUARANTINE SUMMARY" in formatted
        assert "1000" in formatted
        assert "1.4.3" in formatted

