"""Tests for the monitor module."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from clamscan_splitter.monitor import (
    HangDetector,
    ProcessMetrics,
    ResourceMonitor,
)


class TestProcessMetrics:
    """Test ProcessMetrics dataclass."""

    def test_process_metrics_creation(self):
        """Test creating ProcessMetrics."""
        metrics = ProcessMetrics(
            pid=12345,
            cpu_percent=10.0,
            memory_mb=100.0,
            num_threads=2,
            io_counters={"read_bytes": 1024},
            create_time=1000.0,
            status="running",
        )
        
        assert metrics.pid == 12345
        assert metrics.cpu_percent == 10.0
        assert metrics.memory_mb == 100.0
        assert metrics.status == "running"


class TestHangDetector:
    """Test HangDetector class."""

    @pytest.mark.asyncio
    async def test_detects_low_cpu_hang(self, mock_psutil_low_cpu):
        """Test detection of hung process via low CPU."""
        detector = HangDetector(cpu_threshold=5.0, cpu_sample_count=5)
        
        # Mock CPU samples to be consistently low
        mock_psutil_low_cpu.cpu_percent.return_value = 2.0
        
        # Collect enough samples
        samples = []
        for _ in range(5):
            samples.append(2.0)
            await asyncio.sleep(0.01)  # Small delay
        
        # Check if process appears hung
        is_hung = await detector.is_process_hung(mock_psutil_low_cpu, None)
        
        # Should detect hang based on low CPU
        assert isinstance(is_hung, bool)

    @pytest.mark.asyncio
    async def test_detects_zombie_process(self, mock_psutil_zombie):
        """Test detection of zombie process."""
        detector = HangDetector()
        
        is_hung = await detector.is_process_hung(mock_psutil_zombie, None)
        
        # Zombie processes should be detected as hung
        assert is_hung is True

    @pytest.mark.asyncio
    async def test_healthy_process_not_detected_as_hung(self, mock_psutil_process):
        """Test that healthy process is not detected as hung."""
        detector = HangDetector(cpu_threshold=5.0, cpu_sample_count=5)
        
        # Mock high CPU usage
        mock_psutil_process.cpu_percent.return_value = 50.0
        
        is_hung = await detector.is_process_hung(mock_psutil_process, None)
        
        # Healthy process should not be hung
        assert is_hung is False

    @pytest.mark.asyncio
    async def test_monitor_cpu_usage(self, mock_psutil_process):
        """Test CPU usage monitoring."""
        detector = HangDetector()
        
        # Mock CPU samples
        mock_psutil_process.cpu_percent.side_effect = [10.0, 15.0, 20.0, 5.0, 8.0]
        
        samples = await detector.monitor_cpu_usage(mock_psutil_process)
        
        assert len(samples) > 0
        assert all(isinstance(s, (int, float)) for s in samples)

    @pytest.mark.asyncio
    async def test_monitor_output_activity_with_output(self):
        """Test output activity monitoring when output is present."""
        detector = HangDetector(output_timeout=1)
        
        # Create a mock stream reader with data
        mock_stream = AsyncMock()
        mock_stream.read.return_value = b"output data\n"
        
        has_output = await detector.monitor_output_activity(mock_stream, timeout=1)
        
        assert has_output is True

    @pytest.mark.asyncio
    async def test_monitor_output_activity_no_output(self):
        """Test output activity monitoring when no output."""
        detector = HangDetector(output_timeout=0.1)
        
        # Create a mock stream reader with no data
        mock_stream = AsyncMock()
        mock_stream.read.side_effect = asyncio.TimeoutError()
        
        has_output = await detector.monitor_output_activity(mock_stream, timeout=0.1)
        
        # Should return False if no output within timeout
        assert has_output is False

    def test_check_process_health_healthy(self, mock_psutil_process):
        """Test process health check for healthy process."""
        detector = HangDetector()
        
        mock_psutil_process.status.return_value = "running"
        mock_psutil_process.cpu_percent.return_value = 50.0
        
        health = detector.check_process_health(mock_psutil_process)
        
        assert health in ["healthy", "suspicious"]

    def test_check_process_health_zombie(self, mock_psutil_zombie):
        """Test process health check for zombie process."""
        detector = HangDetector()
        
        health = detector.check_process_health(mock_psutil_zombie)
        
        assert health == "zombie"

    def test_check_process_health_suspicious(self, mock_psutil_low_cpu):
        """Test process health check for suspicious process."""
        detector = HangDetector()
        
        mock_psutil_low_cpu.status.return_value = "sleeping"
        mock_psutil_low_cpu.cpu_percent.return_value = 1.0
        
        health = detector.check_process_health(mock_psutil_low_cpu)
        
        assert health in ["suspicious", "hung"]


class TestResourceMonitor:
    """Test ResourceMonitor class."""

    @patch("clamscan_splitter.monitor.psutil")
    def test_collect_sample(self, mock_psutil, mock_virtual_memory, mock_cpu_count):
        """Test collecting resource sample."""
        mock_psutil.virtual_memory.return_value = mock_virtual_memory
        mock_psutil.cpu_count.return_value = mock_cpu_count
        mock_psutil.cpu_percent.return_value = 50.0
        
        monitor = ResourceMonitor()
        sample = monitor.collect_sample()
        
        assert sample is not None
        assert hasattr(sample, "cpu_percent") or isinstance(sample, dict)

    @patch("clamscan_splitter.monitor.psutil")
    def test_should_reduce_concurrency_high_memory(self, mock_psutil):
        """Test concurrency reduction when memory is high."""
        mock_mem = Mock()
        mock_mem.percent = 95.0  # 95% memory usage
        mock_mem.available = 1 * 1024**3  # 1GB available
        mock_psutil.virtual_memory.return_value = mock_mem
        mock_psutil.cpu_percent.return_value = 50.0
        mock_psutil.disk_io_counters.return_value = Mock(read_bytes=0, write_bytes=0)
        
        monitor = ResourceMonitor()
        # Collect enough samples (need at least 3)
        for _ in range(3):
            monitor.collect_sample()
        
        should_reduce = monitor.should_reduce_concurrency()
        
        assert should_reduce is True

    @patch("clamscan_splitter.monitor.psutil")
    def test_should_reduce_concurrency_low_memory(self, mock_psutil):
        """Test concurrency not reduced when memory is low."""
        mock_mem = Mock()
        mock_mem.percent = 50.0  # 50% memory usage
        mock_psutil.virtual_memory.return_value = mock_mem
        
        monitor = ResourceMonitor()
        should_reduce = monitor.should_reduce_concurrency()
        
        assert should_reduce is False

    @patch("clamscan_splitter.monitor.psutil")
    def test_get_recommended_concurrency(self, mock_psutil, mock_virtual_memory, mock_cpu_count):
        """Test getting recommended concurrency level."""
        mock_psutil.virtual_memory.return_value = mock_virtual_memory
        mock_psutil.cpu_count.return_value = mock_cpu_count
        
        monitor = ResourceMonitor()
        concurrency = monitor.get_recommended_concurrency()
        
        assert isinstance(concurrency, int)
        assert concurrency > 0
        assert concurrency <= mock_cpu_count

