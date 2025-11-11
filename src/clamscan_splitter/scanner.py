"""Scanner module for managing parallel ClamAV scan execution."""

import asyncio
import contextlib
import inspect
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Optional

import psutil

from clamscan_splitter.chunker import ScanChunk
from clamscan_splitter.monitor import HangDetector, ResourceMonitor
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
            
            return self._build_scan_result(
                chunk,
                stdout,
                stderr,
                return_code,
            )
        
        except asyncio.TimeoutError:
            raise ScanTimeoutError(f"Scan exceeded timeout of {timeout} seconds")
        except ScanHangError:
            raise
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

    def _build_scan_result(
        self,
        chunk: ScanChunk,
        stdout: str,
        stderr: str,
        return_code: int,
    ) -> ScanResult:
        """Convert raw clamscan output into a ScanResult."""
        parsed_result = self.parser.parse_output(stdout, stderr, return_code)
        if not isinstance(parsed_result, ScanResult):
            raise TypeError("Unexpected parser return type")
        
        return ScanResult(
            chunk_id=chunk.id,
            status=parsed_result.status,
            infected_files=parsed_result.infected_files,
            scanned_files=parsed_result.scanned_files,
            scanned_directories=parsed_result.scanned_directories,
            total_errors=parsed_result.total_errors,
            data_scanned_mb=parsed_result.data_scanned_mb,
            data_read_mb=parsed_result.data_read_mb,
            scan_time_seconds=parsed_result.scan_time_seconds,
            engine_version=parsed_result.engine_version,
            raw_output=parsed_result.raw_output,
            error_message=parsed_result.error_message,
        )

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
        
        communicate_task = asyncio.create_task(process.communicate())
        hang_monitor_task = asyncio.create_task(self._monitor_for_hang(process))
        
        try:
            done, _ = await asyncio.wait(
                {communicate_task, hang_monitor_task},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            
            if hang_monitor_task in done and not hang_monitor_task.cancelled():
                hang_monitor_task.result()
            
            if communicate_task not in done:
                raise asyncio.TimeoutError
            
            stdout, stderr = await communicate_task
            return_code = process.returncode
            
            return (
                stdout.decode('utf-8', errors='replace'),
                stderr.decode('utf-8', errors='replace'),
                return_code if return_code is not None else 0,
            )
        except asyncio.TimeoutError:
            await self._stop_process(process)
            raise
        except ScanHangError:
            raise
        except Exception:
            await self._stop_process(process)
            raise
        finally:
            hang_monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await hang_monitor_task

    async def _monitor_for_hang(self, process: asyncio.subprocess.Process):
        """Monitor process using HangDetector and raise when hung."""
        pid = getattr(process, "pid", None)
        if pid is None:
            return
        
        try:
            ps_process = psutil.Process(int(pid))
        except (TypeError, ValueError, psutil.NoSuchProcess, psutil.AccessDenied):
            return
        
        poll_interval = max(0.5, self.hang_detector.output_timeout / 5)
        
        while True:
            if process.returncode is not None:
                return
            
            hung = await self.hang_detector.is_process_hung(ps_process, None)
            if hung:
                await self._stop_process(process)
                raise ScanHangError("Scan process appears hung")
            
            await asyncio.sleep(poll_interval)

    async def _stop_process(self, process: asyncio.subprocess.Process):
        """Terminate and await the given subprocess."""
        try:
            kill_result = process.kill()
            if inspect.isawaitable(kill_result):
                await kill_result
        except Exception:
            pass
        with contextlib.suppress(Exception):
            await process.wait()


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
        self.quarantined_files: List[dict] = []
        self.worker = ScanWorker()
        self.retry_manager = RetryManager()
        self.resource_monitor = ResourceMonitor()
        self.current_worker_limit = self.max_workers
        self._borrowed_tokens = 0

    def _calculate_max_workers(self) -> int:
        """
        Calculate maximum workers based on available memory.

        Returns:
            Maximum number of concurrent workers
        """
        mem = psutil.virtual_memory()
        available_gb = (mem.available / (1024**3)) - self.config.min_free_memory_gb
        max_by_memory = int(available_gb / self.config.memory_per_process_gb)
        cpu_count = psutil.cpu_count() or 1
        max_by_cpu = max(cpu_count - 1, 1)
        
        base_workers = max_by_memory
        if max_by_cpu < base_workers:
            base_workers = max_by_cpu
        configured = self.config.max_concurrent_processes
        if configured is not None and configured < base_workers:
            base_workers = configured
        if base_workers < 1:
            base_workers = 1
        return base_workers

    async def scan_all(
        self,
        chunks: List[ScanChunk],
        on_result: Optional[
            Callable[[ScanResult], Optional[Awaitable[None]]]
        ] = None,
    ) -> List[ScanResult]:
        """
        Scan all chunks in parallel with concurrency limit.

        Args:
            chunks: List of chunks to scan

        Returns:
            List of scan results
        """
        self.results = []
        self.failed_chunks = []
        self.retry_manager.quarantine_list = []
        
        # Create tasks for all chunks so we can process results as they complete
        tasks = [
            asyncio.create_task(self._scan_with_semaphore(chunk))
            for chunk in chunks
        ]
        
        async def _handle_callback(result: ScanResult):
            if on_result is None:
                return
            
            try:
                callback_result = on_result(result)
                if inspect.isawaitable(callback_result):
                    await callback_result
            except Exception:
                # Cancel any in-flight tasks so we don't leak subprocesses
                for task in tasks:
                    if not task.done():
                        task.cancel()
                raise
        
        for completed in asyncio.as_completed(tasks):
            try:
                result = await completed
            except Exception as exc:  # noqa: BLE001
                result = ScanResult(
                    chunk_id="unknown",
                    status="failed",
                    error_message=str(exc),
                )
            
            if not result:
                continue
            
            self.results.append(result)
            if result.status == "failed":
                self.failed_chunks.append(result.chunk_id or "unknown")
            
            await _handle_callback(result)
        
        # Release any borrowed tokens used to throttle concurrency
        for _ in range(self._borrowed_tokens):
            self.semaphore.release()
        self._borrowed_tokens = 0
        self.quarantined_files = list(self.retry_manager.quarantine_list)
        
        return self.results

    async def _scan_with_semaphore(self, chunk: ScanChunk) -> Optional[ScanResult]:
        """Scan chunk with semaphore for concurrency control."""
        await self._maybe_adjust_concurrency()
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

    async def _maybe_adjust_concurrency(self):
        """Collect resource samples and reduce concurrency if required."""
        try:
            self.resource_monitor.collect_sample()
        except Exception:
            return
        
        if not self.resource_monitor.should_reduce_concurrency():
            return
        
        recommended = self.resource_monitor.get_recommended_concurrency()
        if recommended <= 0:
            recommended = 1
        
        new_limit = max(1, min(self.max_workers, recommended))
        if new_limit >= self.current_worker_limit:
            return
        
        tokens_to_acquire = self.current_worker_limit - new_limit
        for _ in range(tokens_to_acquire):
            await self.semaphore.acquire()
            self._borrowed_tokens += 1
        self.current_worker_limit = new_limit
