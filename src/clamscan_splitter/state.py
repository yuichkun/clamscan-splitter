"""State module for managing persistent scan state."""

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from clamscan_splitter.parser import ScanResult


@dataclass
class ScanState:
    """Persistent state of a scan operation."""
    scan_id: str  # Unique scan identifier
    root_path: str  # Root path being scanned
    total_chunks: int  # Total number of chunks
    completed_chunks: List[str] = field(default_factory=list)  # IDs of completed chunks
    failed_chunks: List[str] = field(default_factory=list)  # IDs of failed chunks
    partial_results: List[dict] = field(default_factory=list)  # Results collected so far (as dicts)
    start_time: datetime = field(default_factory=datetime.now)  # When scan started
    last_update: datetime = field(default_factory=datetime.now)  # Last state update
    configuration: dict = field(default_factory=dict)  # Scan configuration used


class StateManager:
    """Manages persistent state storage."""

    def __init__(self, state_dir: str = "~/.clamscan-splitter/state"):
        """Initialize state manager.
        
        Args:
            state_dir: Directory to store state files
        """
        self.state_dir = Path(state_dir).expanduser()
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def save_state(self, state: ScanState):
        """
        Save state to JSON file with atomic write.

        Atomic write process:
        1. Serialize state to JSON
        2. Write to temp file in same directory
        3. fsync to ensure disk write
        4. Atomic rename to final location

        This prevents corruption if process crashes mid-write.

        Args:
            state: ScanState to save
        """
        state_file = self.state_dir / f"{state.scan_id}.json"
        temp_fd, temp_path = tempfile.mkstemp(
            dir=self.state_dir,
            prefix=f".{state.scan_id}.",
            suffix=".tmp"
        )

        try:
            # Update last_update timestamp
            state.last_update = datetime.now()
            
            # Convert to dict, handling datetime serialization
            state_dict = asdict(state)
            state_dict["start_time"] = state.start_time.isoformat()
            state_dict["last_update"] = state.last_update.isoformat()
            
            # Write to temp file
            with os.fdopen(temp_fd, 'w') as f:
                json.dump(state_dict, f, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk

            # Atomic rename
            os.replace(temp_path, state_file)
        except Exception:
            # Clean up temp file on error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

    def load_state(self, scan_id: str) -> Optional[ScanState]:
        """
        Load state from JSON file.
        
        Args:
            scan_id: Scan ID to load
            
        Returns:
            ScanState if found, None otherwise
        """
        state_file = self.state_dir / f"{scan_id}.json"
        
        if not state_file.exists():
            return None
        
        try:
            with open(state_file, 'r') as f:
                state_dict = json.load(f)
            
            # Convert ISO format strings back to datetime
            if "start_time" in state_dict and isinstance(state_dict["start_time"], str):
                state_dict["start_time"] = datetime.fromisoformat(state_dict["start_time"])
            if "last_update" in state_dict and isinstance(state_dict["last_update"], str):
                state_dict["last_update"] = datetime.fromisoformat(state_dict["last_update"])
            
            return ScanState(**state_dict)
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    def list_incomplete_scans(self) -> List[ScanState]:
        """
        List all scans that haven't completed.
        
        Returns:
            List of incomplete ScanState objects
        """
        incomplete = []
        
        for state_file in self.state_dir.glob("*.json"):
            # Skip temp files
            if state_file.name.startswith("."):
                continue
            
            scan_id = state_file.stem
            state = self.load_state(scan_id)
            
            if state is None:
                continue
            
            # Check if scan is incomplete
            total_completed = len(state.completed_chunks) + len(state.failed_chunks)
            if total_completed < state.total_chunks:
                incomplete.append(state)
        
        return incomplete

    def cleanup_old_states(self, days: int = 30):
        """
        Remove state files older than specified days.
        
        Args:
            days: Number of days after which to remove states
        """
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        
        for state_file in self.state_dir.glob("*.json"):
            # Skip temp files
            if state_file.name.startswith("."):
                continue
            
            try:
                if state_file.stat().st_mtime < cutoff_time:
                    state_file.unlink()
            except OSError:
                pass  # Skip files that can't be accessed


class ProgressTracker:
    """Tracks and displays scan progress."""

    def __init__(self, total_chunks: int):
        """Initialize progress tracker.
        
        Args:
            total_chunks: Total number of chunks to track
        """
        self.total_chunks = total_chunks
        self.completed = 0
        self.failed = 0
        self.current_chunks: Dict[str, str] = {}  # chunk_id -> status
        self.start_time = time.time()

    def update_chunk_status(self, chunk_id: str, status: str):
        """
        Update status of a chunk.
        
        Args:
            chunk_id: ID of the chunk
            status: Status ("scanning", "completed", "failed", "retrying")
        """
        old_status = self.current_chunks.get(chunk_id)
        
        # Update counters
        if old_status == "completed":
            self.completed -= 1
        elif old_status == "failed":
            self.failed -= 1
        
        if status == "completed":
            self.completed += 1
        elif status == "failed":
            self.failed += 1
        
        self.current_chunks[chunk_id] = status

    def get_progress_percentage(self) -> float:
        """Calculate completion percentage.
        
        Returns:
            Percentage complete (0-100)
        """
        if self.total_chunks == 0:
            return 100.0
        
        total_done = self.completed + self.failed
        return (total_done / self.total_chunks) * 100.0

    def get_eta(self) -> Optional[timedelta]:
        """Estimate time to completion.
        
        Returns:
            Estimated time remaining as timedelta, or None if can't calculate
        """
        if self.total_chunks == 0:
            return None
        
        elapsed = time.time() - self.start_time
        total_done = self.completed + self.failed
        
        if total_done == 0:
            return None
        
        rate = total_done / elapsed  # chunks per second
        remaining = self.total_chunks - total_done
        
        if rate <= 0:
            return None
        
        eta_seconds = remaining / rate
        return timedelta(seconds=eta_seconds)

    def format_progress_bar(self) -> str:
        """
        Format progress for display.
        
        Returns:
            Formatted progress string
        """
        percentage = self.get_progress_percentage()
        total_done = self.completed + self.failed
        bar_length = 20
        
        filled = int(bar_length * percentage / 100)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        eta_seconds = self.get_eta()
        if eta_seconds:
            eta_min = int(eta_seconds.total_seconds() // 60)
            eta_sec = int(eta_seconds.total_seconds() % 60)
            eta_str = f"ETA: {eta_min}m {eta_sec}s"
        else:
            eta_str = "ETA: calculating..."
        
        return f"[{bar}] {percentage:.1f}% ({total_done}/{self.total_chunks} chunks) {eta_str}"
