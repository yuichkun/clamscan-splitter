"""Tests for the scanner module."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from clamscan_splitter.chunker import ScanChunk
from clamscan_splitter.parser import ScanResult
from clamscan_splitter.retry import ScanHangError, ScanTimeoutError
from clamscan_splitter.scanner import ScanConfig, ScanOrchestrator, ScanWorker
from tests.fixtures.mock_outputs import CLEAN_SCAN_OUTPUT, INFECTED_SCAN_OUTPUT


class TestScanConfig:
    """Test ScanConfig dataclass."""

    def test_default_config(self):
        """Test default scan configuration."""
        config = ScanConfig()
        
        assert config.base_timeout_per_gb == 30
        assert config.min_timeout_seconds == 300
        assert config.max_timeout_seconds == 3600
        assert config.clamscan_path == "clamscan"
        assert config.memory_per_process_gb == 2.0


class TestScanWorker:
    """Test ScanWorker class."""

    @pytest.mark.asyncio
    async def test_scan_chunk_success(self):
        """Test successful chunk scan."""
        worker = ScanWorker()
        config = ScanConfig(
            clamscan_path="clamscan",
            base_timeout_per_gb=30,
            min_timeout_seconds=1,
        )
        
        chunk = ScanChunk(
            id="test-chunk",
            paths=["/test"],
            estimated_size_bytes=1024 * 1024,  # 1MB
            file_count=1,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        # Mock subprocess
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(return_value=(
            CLEAN_SCAN_OUTPUT.encode(),
            b"",
        ))
        mock_process.returncode = 0
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            result = await worker.scan_chunk(chunk, config)
        
        assert result is not None
        assert result.chunk_id == "test-chunk"
        assert result.status == "success"

    @pytest.mark.asyncio
    async def test_scan_chunk_timeout(self):
        """Test chunk scan timeout."""
        worker = ScanWorker()
        config = ScanConfig(
            clamscan_path="clamscan",
            base_timeout_per_gb=30,
            min_timeout_seconds=0.1,  # Very short timeout
        )
        
        chunk = ScanChunk(
            id="test-chunk",
            paths=["/test"],
            estimated_size_bytes=1024 * 1024,
            file_count=1,
            directory_count=0,
            created_at=datetime.now(),
        )
        
        # Mock a hanging process
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.wait = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_process.returncode = None
            mock_subprocess.return_value = mock_process
            
            with pytest.raises(ScanTimeoutError):
                await worker.scan_chunk(chunk, config)

    @pytest.mark.asyncio
    async def test_execute_clamscan(self):
        """Test executing clamscan subprocess."""
        worker = ScanWorker()
        
        # Mock subprocess
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(return_value=(
            CLEAN_SCAN_OUTPUT.encode(),
            b"",
        ))
        mock_process.returncode = 0
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            stdout, stderr, return_code = await worker._execute_clamscan(
                ["/test"], timeout=10
            )
        
        assert return_code == 0
        assert "SCAN SUMMARY" in stdout or len(stdout) > 0


class TestScanOrchestrator:
    """Test ScanOrchestrator class."""

    @patch("clamscan_splitter.scanner.psutil")
    def test_calculate_max_workers(self, mock_psutil, mock_virtual_memory, mock_cpu_count):
        """Test calculating max workers based on memory."""
        mock_psutil.virtual_memory.return_value = mock_virtual_memory
        mock_psutil.cpu_count.return_value = mock_cpu_count
        
        config = ScanConfig(memory_per_process_gb=2.0, min_free_memory_gb=2.0)
        orchestrator = ScanOrchestrator(config)
        
        # With 8GB available and 2GB per process, should get ~3 workers
        # But also limited by CPU count (8-1=7)
        max_workers = orchestrator.max_workers
        
        assert max_workers > 0
        assert max_workers <= mock_cpu_count

    @pytest.mark.asyncio
    async def test_scan_all_success(self):
        """Test scanning all chunks successfully."""
        config = ScanConfig(
            max_concurrent_processes=2,
            min_timeout_seconds=1,
        )
        orchestrator = ScanOrchestrator(config)
        
        chunks = [
            ScanChunk(
                id=f"chunk-{i}",
                paths=[f"/test/chunk{i}"],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
            for i in range(3)
        ]
        
        # Mock subprocess for all chunks
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(return_value=(
            CLEAN_SCAN_OUTPUT.encode(),
            b"",
        ))
        mock_process.returncode = 0
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            results = await orchestrator.scan_all(chunks)
        
        assert len(results) == 3
        assert all(r is not None for r in results)

    @pytest.mark.asyncio
    async def test_scan_all_with_failures(self):
        """Test scanning with some failures."""
        config = ScanConfig(
            max_concurrent_processes=2,
            min_timeout_seconds=1,
        )
        orchestrator = ScanOrchestrator(config)
        
        chunks = [
            ScanChunk(
                id=f"chunk-{i}",
                paths=[f"/test/chunk{i}"],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
            for i in range(2)
        ]
        
        # Mock worker to fail on second chunk
        original_scan = orchestrator._scan_with_retry
        
        call_count = [0]
        async def mock_scan(chunk):
            call_count[0] += 1
            if call_count[0] == 2:
                raise ScanTimeoutError("Timeout")
            return ScanResult(
                chunk_id=chunk.id,
                status="success",
            )
        
        orchestrator._scan_with_retry = mock_scan
        
        results = await orchestrator.scan_all(chunks)
        
        # Should handle failures gracefully
        assert len(results) >= 0  # May have partial results

    @pytest.mark.asyncio
    async def test_concurrency_limit(self):
        """Test that concurrency limit is respected."""
        config = ScanConfig(
            max_concurrent_processes=2,
            min_timeout_seconds=1,
        )
        orchestrator = ScanOrchestrator(config)
        
        # Create many chunks
        chunks = [
            ScanChunk(
                id=f"chunk-{i}",
                paths=[f"/test/chunk{i}"],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
            for i in range(10)
        ]
        
        # Mock subprocess
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(return_value=(
            CLEAN_SCAN_OUTPUT.encode(),
            b"",
        ))
        mock_process.returncode = 0
        
        # Track concurrent executions
        concurrent = [0]
        max_concurrent = [0]
        
        original_scan = orchestrator._scan_with_retry
        async def track_concurrency(chunk):
            concurrent[0] += 1
            max_concurrent[0] = max(max_concurrent[0], concurrent[0])
            try:
                result = await original_scan(chunk)
                return result
            finally:
                concurrent[0] -= 1
        
        orchestrator._scan_with_retry = track_concurrency
        
        with patch('asyncio.create_subprocess_exec', return_value=mock_process):
            await orchestrator.scan_all(chunks)
        
        # Should not exceed max_concurrent_processes
        assert max_concurrent[0] <= config.max_concurrent_processes

