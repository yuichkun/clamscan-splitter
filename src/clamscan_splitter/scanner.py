"""Scanner module for managing parallel ClamAV scan execution."""

import asyncio
import psutil
from dataclasses import dataclass, field
from typing import List, Optional

from clamscan_splitter.chunker import ScanChunk
from clamscan_splitter.monitor import HangDetector
from clamscan_splitter.parser import ClamAVOutputParser, ScanResult
from clamscan_splitter.retry import RetryManager, ScanHangError, ScanTimeoutError


@dataclass
class ScanConfig:
    """Configuration for scanning behavior."""
    max_concurrent_processes: Optional[int] = None  # Auto-calculated based on memory
    base_timeout_per_gb: int = 30  # seconds
    min_timeout_seconds: int = 300  # 5 minutes
    max_timeout_seconds: int = 3600  # 1 hour
    clamscan_path: str = "clamscan"
    clamscan_options: List[str] = field(default_factory=lambda: ["-r", "--no-summary"])
    memory_per_process_gb: float = 2.0  # Expected memory per clamscan
    min_free_memory_gb: float = 2.0  # Keep this much memory free


class ScanWorker:
    """Executes a single scan with monitoring."""

    def __init__(self):
        """Initialize scan worker."""
        self.parser = ClamAVOutputParser()
        self.hang_detector = HangDetector()

    async def scan_chunk(self, chunk: ScanChunk, config: ScanConfig) -> ScanResult:
        """
        Execute clamscan on a chunk with monitoring.

        Args:
            chunk: Chunk to scan
            config: Scan configuration

        Returns:
            ScanResult object with scan outcome
        """
        # Calculate timeout based on chunk size
        timeout = self._calculate_timeout(chunk, config)
        
        try:
            # Execute clamscan
            stdout, stderr, return_code = await asyncio.wait_for(
                self._execute_clamscan(chunk.paths, timeout),
                timeout=timeout + 10,  # Add buffer for cleanup
            )
            
            # Parse output
            result = self.parser.parse_output(stdout, stderr, return_code)
            result.chunk_id = chunk.id
            
            return result
            
        except asyncio.TimeoutError:
            raise ScanTimeoutError(f"Scan exceeded timeout of {timeout} seconds")
        except Exception as e:
            # Check if it's a hang error
            error_name = type(e).__name__
            if error_name == "ScanHangError":
                raise
            # Otherwise wrap in timeout error
            raise ScanTimeoutError(f"Scan failed: {str(e)}")

    def _calculate_timeout(self, chunk: ScanChunk, config: ScanConfig) -> int:
        """Calculate timeout based on chunk size."""
        size_gb = chunk.estimated_size_bytes / (1024**3)
        timeout = int(size_gb * config.base_timeout_per_gb)
        timeout = max(timeout, config.min_timeout_seconds)
        timeout = min(timeout, config.max_timeout_seconds)
        return timeout

    async def _execute_clamscan(
        self, paths: List[str], timeout: int
    ) -> tuple[str, str, int]:
        """
        Run clamscan subprocess with asyncio.

        Args:
            paths: List of paths to scan
            timeout: Timeout in seconds

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        # Build command
        cmd = ["clamscan", "-r", "--no-summary"] + paths
        
        # Create subprocess
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        try:
            # Wait for completion with timeout
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
            
            return_code = process.returncode
            
            return (
                stdout.decode('utf-8', errors='replace'),
                stderr.decode('utf-8', errors='replace'),
                return_code if return_code is not None else 0,
            )
        except asyncio.TimeoutError:
            # Kill process on timeout
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
            raise
        except Exception as e:
            # Ensure process is killed
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
            raise


class ScanOrchestrator:
    """Coordinates parallel scanning of all chunks."""

    def __init__(self, config: ScanConfig):
        """Initialize orchestrator.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.max_workers = self._calculate_max_workers()
        self.semaphore = asyncio.Semaphore(self.max_workers)
        self.results: List[ScanResult] = []
        self.failed_chunks: List[str] = []
        self.quarantined_files: List[str] = []
        self.worker = ScanWorker()
        self.retry_manager = RetryManager()

    def _calculate_max_workers(self) -> int:
        """
        Calculate maximum workers based on available memory.

        Returns:
            Maximum number of concurrent workers
        """
        mem = psutil.virtual_memory()
        available_gb = (mem.available / (1024**3)) - self.config.min_free_memory_gb
        max_by_memory = int(available_gb / self.config.memory_per_process_gb)
        max_by_cpu = psutil.cpu_count() - 1
        
        if self.config.max_concurrent_processes:
            return min(max_by_memory, max_by_cpu, self.config.max_concurrent_processes)
        return max(1, min(max_by_memory, max_by_cpu))

    async def scan_all(self, chunks: List[ScanChunk]) -> List[ScanResult]:
        """
        Scan all chunks in parallel with concurrency limit.

        Args:
            chunks: List of chunks to scan

        Returns:
            List of scan results
        """
        self.results = []
        self.failed_chunks = []
        
        # Create tasks for all chunks
        tasks = [
            self._scan_with_semaphore(chunk)
            for chunk in chunks
        ]
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                # Create error result
                error_result = ScanResult(
                    chunk_id="unknown",
                    status="failed",
                    error_message=str(result),
                )
                self.results.append(error_result)
                self.failed_chunks.append("unknown")
            elif result:
                self.results.append(result)
                if result.status == "failed":
                    self.failed_chunks.append(result.chunk_id)
        
        return self.results

    async def _scan_with_semaphore(self, chunk: ScanChunk) -> Optional[ScanResult]:
        """Scan chunk with semaphore for concurrency control."""
        async with self.semaphore:
            return await self._scan_with_retry(chunk)

    async def _scan_with_retry(self, chunk: ScanChunk) -> Optional[ScanResult]:
        """
        Scan a chunk with retry logic.
        Delegates to retry.py module.

        Args:
            chunk: Chunk to scan

        Returns:
            ScanResult or None if all retries failed
        """
        from clamscan_splitter.retry import RetryConfig
        
        retry_config = RetryConfig(
            max_attempts=3,
            base_delay_seconds=1.0,
        )
        
        try:
            result = await self.retry_manager.scan_with_retry(
                chunk,
                self.worker,
                retry_config,
                self.config,
            )
            return result
        except Exception as e:
            # Final failure - create error result
            return ScanResult(
                chunk_id=chunk.id,
                status="failed",
                error_message=str(e),
            )
