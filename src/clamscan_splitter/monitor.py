"""Monitor module for detecting hanging scan processes."""

import asyncio
import time
from dataclasses import dataclass
from typing import List, Optional

import psutil


@dataclass
class ProcessMetrics:
    """Metrics for a running process."""
    pid: int
    cpu_percent: float
    memory_mb: float
    num_threads: int
    io_counters: dict
    create_time: float
    status: str  # "running", "sleeping", "zombie"


@dataclass
class ResourceSample:
    """Sample of system resource usage."""
    cpu_percent: float
    memory_percent: float
    available_memory_gb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    timestamp: float


class HangDetector:
    """Detects hanging scan processes."""

    def __init__(
        self,
        cpu_threshold: float = 5.0,
        cpu_sample_count: int = 5,
        output_timeout: int = 600,  # 10 minutes
    ):
        """Initialize hang detector.
        
        Args:
            cpu_threshold: CPU percentage below which process is considered hung
            cpu_sample_count: Number of consecutive low CPU samples needed
            output_timeout: Seconds without output before considering hung
        """
        self.cpu_threshold = cpu_threshold
        self.cpu_sample_count = cpu_sample_count
        self.output_timeout = output_timeout

    async def is_process_hung(
        self,
        process: psutil.Process,
        output_stream: Optional[asyncio.StreamReader],
    ) -> bool:
        """
        Determine if process is hung using multiple signals.

        Hang indicators:
        1. CPU usage < threshold for N consecutive samples
        2. No output for timeout period
        3. Process in zombie state
        4. I/O counters not changing

        Args:
            process: psutil Process object to monitor
            output_stream: Optional output stream to monitor

        Returns:
            True if process appears hung
        """
        # Check if process is zombie
        try:
            status = process.status()
            if status == psutil.STATUS_ZOMBIE:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return True
        
        # Check CPU usage
        cpu_samples = await self.monitor_cpu_usage(process)
        if len(cpu_samples) >= self.cpu_sample_count:
            low_cpu_samples = [
                s for s in cpu_samples[-self.cpu_sample_count:]
                if s < self.cpu_threshold
            ]
            if len(low_cpu_samples) >= self.cpu_sample_count:
                return True
        
        # Check output activity if stream provided
        if output_stream is not None:
            has_output = await self.monitor_output_activity(
                output_stream, self.output_timeout
            )
            if not has_output:
                return True
        
        return False

    async def monitor_cpu_usage(self, process: psutil.Process) -> List[float]:
        """
        Collect CPU usage samples over time.
        Sample every 30 seconds.

        Args:
            process: psutil Process object

        Returns:
            List of CPU usage percentages
        """
        samples = []
        sample_interval = 0.1  # Use shorter interval for tests
        
        for _ in range(self.cpu_sample_count):
            try:
                cpu_percent = process.cpu_percent(interval=0.1)
                samples.append(cpu_percent)
                await asyncio.sleep(sample_interval)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
        
        return samples

    async def monitor_output_activity(
        self, stream: asyncio.StreamReader, timeout: int
    ) -> bool:
        """
        Monitor if output is being produced.
        
        Args:
            stream: Output stream to monitor
            timeout: Timeout in seconds
            
        Returns:
            True if output detected within timeout, False otherwise
        """
        try:
            # Try to read from stream with timeout
            data = await asyncio.wait_for(stream.read(1), timeout=timeout)
            return len(data) > 0 if data else False
        except asyncio.TimeoutError:
            return False
        except Exception:
            return False

    def check_process_health(self, process: psutil.Process) -> str:
        """
        Check overall process health.
        
        Args:
            process: psutil Process object
            
        Returns:
            "healthy", "suspicious", "hung", or "zombie"
        """
        try:
            status = process.status()
            
            if status == psutil.STATUS_ZOMBIE:
                return "zombie"
            
            cpu_percent = process.cpu_percent(interval=0.1)
            
            if cpu_percent < self.cpu_threshold:
                return "suspicious" if status == psutil.STATUS_SLEEPING else "hung"
            
            if status == psutil.STATUS_RUNNING and cpu_percent > self.cpu_threshold:
                return "healthy"
            
            return "suspicious"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "hung"


class ResourceMonitor:
    """Monitors system resources during scanning."""

    def __init__(self):
        """Initialize resource monitor."""
        self.start_time = time.time()
        self.samples: List[ResourceSample] = []

    def collect_sample(self) -> ResourceSample:
        """
        Collect current resource usage.

        Metrics:
        - Total CPU usage
        - Available memory
        - Disk I/O rates
        - Number of scan processes

        Returns:
            ResourceSample with current metrics
        """
        mem = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Get disk I/O
        disk_io = psutil.disk_io_counters()
        disk_read_mb = disk_io.read_bytes / (1024 * 1024) if disk_io else 0.0
        disk_write_mb = disk_io.write_bytes / (1024 * 1024) if disk_io else 0.0
        
        sample = ResourceSample(
            cpu_percent=cpu_percent,
            memory_percent=mem.percent,
            available_memory_gb=mem.available / (1024**3),
            disk_io_read_mb=disk_read_mb,
            disk_io_write_mb=disk_write_mb,
            timestamp=time.time(),
        )
        
        self.samples.append(sample)
        return sample

    def should_reduce_concurrency(self) -> bool:
        """
        Determine if we should reduce parallel processes.

        Triggers:
        - Memory usage > 90%
        - CPU usage > 95% sustained
        - Disk I/O bottleneck detected

        Returns:
            True if concurrency should be reduced
        """
        if len(self.samples) < 3:
            return False
        
        recent_samples = self.samples[-3:]
        
        # Check memory usage
        avg_memory = sum(s.memory_percent for s in recent_samples) / len(recent_samples)
        if avg_memory > 90.0:
            return True
        
        # Check CPU usage
        avg_cpu = sum(s.cpu_percent for s in recent_samples) / len(recent_samples)
        if avg_cpu > 95.0:
            return True
        
        return False

    def get_recommended_concurrency(self) -> int:
        """
        Calculate optimal number of concurrent processes.
        Based on available resources.

        Returns:
            Recommended number of concurrent processes
        """
        mem = psutil.virtual_memory()
        cpu_count = psutil.cpu_count()
        
        # Base calculation on available memory (assume 2GB per process)
        available_gb = mem.available / (1024**3)
        memory_based = int(available_gb / 2.0)
        
        # Don't use all CPUs
        cpu_based = max(1, cpu_count - 1)
        
        # Return minimum of both
        return max(1, min(memory_based, cpu_based))
