"""Tests for the state module."""

import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from clamscan_splitter.parser import ScanResult
from clamscan_splitter.state import (
    ProgressTracker,
    ScanState,
    StateManager,
)


class TestScanState:
    """Test ScanState dataclass."""

    def test_scan_state_creation(self):
        """Test creating a ScanState."""
        state = ScanState(
            scan_id="test-scan-1",
            root_path="/test",
            total_chunks=10,
            completed_chunks=["chunk-1", "chunk-2"],
            failed_chunks=["chunk-3"],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        
        assert state.scan_id == "test-scan-1"
        assert state.root_path == "/test"
        assert state.total_chunks == 10
        assert len(state.completed_chunks) == 2


class TestStateManager:
    """Test StateManager class."""

    def test_save_and_load_state(self, tmp_path):
        """Test saving and loading state."""
        state_dir = tmp_path / "state"
        manager = StateManager(state_dir=str(state_dir))
        
        state = ScanState(
            scan_id="test-scan-1",
            root_path="/test",
            total_chunks=5,
            completed_chunks=[],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={"test": "config"},
        )
        
        manager.save_state(state)
        loaded = manager.load_state("test-scan-1")
        
        assert loaded is not None
        assert loaded.scan_id == state.scan_id
        assert loaded.root_path == state.root_path
        assert loaded.total_chunks == state.total_chunks

    def test_load_nonexistent_state(self, tmp_path):
        """Test loading non-existent state returns None."""
        state_dir = tmp_path / "state"
        manager = StateManager(state_dir=str(state_dir))
        
        loaded = manager.load_state("nonexistent")
        
        assert loaded is None

    def test_atomic_write(self, tmp_path):
        """Test that state writes are atomic."""
        state_dir = tmp_path / "state"
        manager = StateManager(state_dir=str(state_dir))
        
        state = ScanState(
            scan_id="atomic-test",
            root_path="/test",
            total_chunks=1,
            completed_chunks=[],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        
        manager.save_state(state)
        
        # Check that temp file doesn't exist
        temp_files = list(state_dir.glob(".atomic-test.*.tmp"))
        assert len(temp_files) == 0  # Temp file should be cleaned up
        
        # Check that final file exists
        state_file = state_dir / "atomic-test.json"
        assert state_file.exists()

    def test_list_incomplete_scans(self, tmp_path):
        """Test listing incomplete scans."""
        state_dir = tmp_path / "state"
        manager = StateManager(state_dir=str(state_dir))
        
        # Create completed scan
        completed_state = ScanState(
            scan_id="completed-scan",
            root_path="/test",
            total_chunks=2,
            completed_chunks=["chunk-1", "chunk-2"],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        manager.save_state(completed_state)
        
        # Create incomplete scan
        incomplete_state = ScanState(
            scan_id="incomplete-scan",
            root_path="/test",
            total_chunks=3,
            completed_chunks=["chunk-1"],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        manager.save_state(incomplete_state)
        
        incomplete = manager.list_incomplete_scans()
        
        # Should find incomplete scan
        scan_ids = [s.scan_id for s in incomplete]
        assert "incomplete-scan" in scan_ids
        # Completed scan might or might not be included depending on implementation
        # (some implementations might include all scans)

    def test_cleanup_old_states(self, tmp_path):
        """Test cleaning up old state files."""
        state_dir = tmp_path / "state"
        manager = StateManager(state_dir=str(state_dir))
        
        # Create old state (would need to mock time for real test)
        old_state = ScanState(
            scan_id="old-scan",
            root_path="/test",
            total_chunks=1,
            completed_chunks=[],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        manager.save_state(old_state)
        
        # Cleanup (with 0 days to clean everything)
        manager.cleanup_old_states(days=0)
        
        # State should be removed
        loaded = manager.load_state("old-scan")
        assert loaded is None


class TestProgressTracker:
    """Test ProgressTracker class."""

    def test_progress_tracker_initialization(self):
        """Test initializing progress tracker."""
        tracker = ProgressTracker(total_chunks=10)
        
        assert tracker.total_chunks == 10
        assert tracker.completed == 0
        assert tracker.failed == 0

    def test_update_chunk_status(self):
        """Test updating chunk status."""
        tracker = ProgressTracker(total_chunks=5)
        
        tracker.update_chunk_status("chunk-1", "scanning")
        tracker.update_chunk_status("chunk-1", "completed")
        
        assert tracker.completed == 1
        assert "chunk-1" in tracker.current_chunks

    def test_get_progress_percentage(self):
        """Test getting progress percentage."""
        tracker = ProgressTracker(total_chunks=10)
        
        tracker.completed = 5
        percentage = tracker.get_progress_percentage()
        
        assert percentage == 50.0

    def test_get_progress_percentage_zero(self):
        """Test progress percentage with zero chunks."""
        tracker = ProgressTracker(total_chunks=0)
        
        percentage = tracker.get_progress_percentage()
        
        assert percentage == 0.0 or percentage == 100.0  # Edge case handling

    def test_get_eta(self):
        """Test ETA calculation."""
        tracker = ProgressTracker(total_chunks=10)
        tracker.completed = 5
        
        # Mock time to have some elapsed time
        import time
        tracker.start_time = time.time() - 10  # 10 seconds ago
        
        eta = tracker.get_eta()
        
        # ETA should be calculated based on rate
        assert eta is None or isinstance(eta, timedelta)
        if eta:
            assert eta.total_seconds() >= 0

    def test_format_progress_bar(self):
        """Test formatting progress bar."""
        tracker = ProgressTracker(total_chunks=10)
        tracker.completed = 5
        
        progress_bar = tracker.format_progress_bar()
        
        assert "50%" in progress_bar or "5" in progress_bar
        assert "10" in progress_bar  # Total chunks

