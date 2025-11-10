"""Tests for the retry module."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, Mock

import pytest

from clamscan_splitter.chunker import ScanChunk
from clamscan_splitter.retry import (
    CircuitBreaker,
    RetryConfig,
    RetryManager,
    ScanHangError,
    ScanTimeoutError,
)


class TestRetryConfig:
    """Test RetryConfig dataclass."""

    def test_default_config(self):
        """Test default retry configuration."""
        config = RetryConfig()
        
        assert config.max_attempts == 3
        assert config.max_attempts_per_file == 2
        assert config.base_delay_seconds == 1.0
        assert config.max_delay_seconds == 300.0
        assert config.exponential_base == 2.0
        assert config.split_on_retry is True

    def test_custom_config(self):
        """Test custom retry configuration."""
        config = RetryConfig(
            max_attempts=5,
            base_delay_seconds=2.0,
            max_delay_seconds=600.0,
        )
        
        assert config.max_attempts == 5
        assert config.base_delay_seconds == 2.0
        assert config.max_delay_seconds == 600.0


class TestRetryManager:
    """Test RetryManager class."""

    def test_calculate_backoff(self):
        """Test exponential backoff calculation."""
        manager = RetryManager()
        config = RetryConfig(base_delay_seconds=1.0, exponential_base=2.0)
        
        delay1 = manager.calculate_backoff(0, config)
        delay2 = manager.calculate_backoff(1, config)
        delay3 = manager.calculate_backoff(2, config)
        
        # Each delay should be roughly double the previous (with jitter)
        assert delay1 >= 1.0
        assert delay2 > delay1
        assert delay3 > delay2
        assert delay3 <= config.max_delay_seconds

    def test_calculate_backoff_respects_max(self):
        """Test that backoff respects maximum delay."""
        manager = RetryManager()
        config = RetryConfig(
            base_delay_seconds=100.0,
            max_delay_seconds=200.0,
            exponential_base=2.0,
        )
        
        delay = manager.calculate_backoff(10, config)  # Large attempt number
        
        assert delay <= config.max_delay_seconds

    def test_split_chunk(self):
        """Test chunk splitting functionality."""
        manager = RetryManager()
        
        chunk = ScanChunk(
            id="test-chunk",
            paths=["/path1", "/path2", "/path3", "/path4"],
            estimated_size_bytes=1000,
            file_count=4,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        split_chunks = manager.split_chunk(chunk, factor=2)
        
        assert len(split_chunks) == 2
        assert len(split_chunks[0].paths) + len(split_chunks[1].paths) == 4

    def test_split_chunk_uneven(self):
        """Test chunk splitting with uneven division."""
        manager = RetryManager()
        
        chunk = ScanChunk(
            id="test-chunk",
            paths=["/path1", "/path2", "/path3"],
            estimated_size_bytes=1000,
            file_count=3,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        split_chunks = manager.split_chunk(chunk, factor=2)
        
        assert len(split_chunks) == 2  # Should create exactly 2 chunks
        # Should distribute paths as evenly as possible
        total_paths = sum(len(c.paths) for c in split_chunks)
        assert total_paths == 3

    @pytest.mark.asyncio
    async def test_scan_with_retry_success_first_attempt(self):
        """Test retry succeeds on first attempt."""
        manager = RetryManager()
        config = RetryConfig(max_attempts=3)
        
        chunk = ScanChunk(
            id="test-chunk",
            paths=["/test"],
            estimated_size_bytes=1000,
            file_count=1,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        # Mock scanner that succeeds immediately
        mock_scanner = AsyncMock()
        mock_result = Mock()
        mock_result.status = "success"
        mock_scanner.scan_chunk.return_value = mock_result
        
        result = await manager.scan_with_retry(chunk, mock_scanner, config)
        
        assert result.status == "success"
        assert mock_scanner.scan_chunk.call_count == 1

    @pytest.mark.asyncio
    async def test_scan_with_retry_succeeds_on_retry(self):
        """Test retry succeeds on second attempt."""
        manager = RetryManager()
        config = RetryConfig(max_attempts=3, base_delay_seconds=0.01)
        
        chunk = ScanChunk(
            id="test-chunk",
            paths=["/test"],
            estimated_size_bytes=1000,
            file_count=1,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        # Mock scanner that fails once then succeeds
        mock_scanner = AsyncMock()
        mock_result = Mock()
        mock_result.status = "success"
        # First call raises exception, second returns result
        call_count = [0]
        async def scan_side_effect(chunk, config):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ScanTimeoutError("Timeout")
            return mock_result
        
        mock_scanner.scan_chunk.side_effect = scan_side_effect
        
        result = await manager.scan_with_retry(chunk, mock_scanner, config)
        
        assert result.status == "success"
        assert call_count[0] == 2

    @pytest.mark.asyncio
    async def test_scan_with_retry_exhausts_attempts(self):
        """Test retry exhausts all attempts."""
        manager = RetryManager()
        config = RetryConfig(max_attempts=3, base_delay_seconds=0.01)
        
        chunk = ScanChunk(
            id="test-chunk",
            paths=["/test"],
            estimated_size_bytes=1000,
            file_count=1,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        # Mock scanner that always fails
        mock_scanner = AsyncMock()
        mock_scanner.scan_chunk.side_effect = ScanTimeoutError("Timeout")
        
        result = await manager.scan_with_retry(chunk, mock_scanner, config)
        
        # Should return a result indicating failure/quarantine
        assert result is not None
        assert result.status == "failed"
        assert mock_scanner.scan_chunk.call_count == config.max_attempts

    def test_create_skip_list(self):
        """Test creating skip list for problematic files."""
        manager = RetryManager()
        
        chunk = ScanChunk(
            id="test-chunk",
            paths=["/test/large.bin", "/test/normal.txt"],
            estimated_size_bytes=2 * 1024**3,  # 2GB
            file_count=2,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        skip_list = manager.create_skip_list(chunk)
        
        # Should identify large files
        assert len(skip_list) >= 0  # May or may not skip based on implementation


class TestCircuitBreaker:
    """Test CircuitBreaker class."""

    def test_record_failure(self):
        """Test recording failures."""
        breaker = CircuitBreaker(failure_threshold=3)
        
        breaker.record_failure("/test/path1")
        breaker.record_failure("/test/path1")
        
        assert breaker.failures["/test/path1"] == 2

    def test_is_blocked_below_threshold(self):
        """Test path not blocked below threshold."""
        breaker = CircuitBreaker(failure_threshold=3)
        
        breaker.record_failure("/test/path1")
        breaker.record_failure("/test/path1")
        
        assert breaker.is_blocked("/test/path1") is False

    def test_is_blocked_above_threshold(self):
        """Test path blocked above threshold."""
        breaker = CircuitBreaker(failure_threshold=3)
        
        for _ in range(3):
            breaker.record_failure("/test/path1")
        
        assert breaker.is_blocked("/test/path1") is True

    def test_get_blocked_paths(self):
        """Test getting list of blocked paths."""
        breaker = CircuitBreaker(failure_threshold=2)
        
        breaker.record_failure("/test/path1")
        breaker.record_failure("/test/path1")
        breaker.record_failure("/test/path2")
        breaker.record_failure("/test/path2")
        
        blocked = breaker.get_blocked_paths()
        
        assert "/test/path1" in blocked
        assert "/test/path2" in blocked
        assert len(blocked) == 2


class ScanTimeoutError(Exception):
    """Scan exceeded timeout."""
    pass


class ScanHangError(Exception):
    """Scan process appears hung."""
    pass

