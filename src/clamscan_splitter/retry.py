"""Retry module for intelligent retry logic with exponential backoff."""

import asyncio
import os
import random
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from clamscan_splitter.chunker import ScanChunk
from clamscan_splitter.parser import ScanResult

class ScanTimeoutError(Exception):
    """Scan exceeded timeout."""
    pass


class ScanHangError(Exception):
    """Scan process appears hung."""
    pass


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    max_attempts_per_file: int = 2  # Per-file retry limit
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 300.0  # 5 minutes
    exponential_base: float = 2.0
    jitter_factor: float = 0.1  # Add 0-10% random jitter
    split_on_retry: bool = True  # Split chunk into smaller pieces on retry
    quarantine_on_final_failure: bool = True  # Add to quarantine list


class RetryManager:
    """Manages retry logic for failed scans."""

    def __init__(self):
        """Initialize retry manager."""
        self.file_retry_counts: defaultdict[str, int] = defaultdict(int)
        self.quarantine_list: List[dict] = []
        self.circuit_breaker = CircuitBreaker()

    async def scan_with_retry(
        self,
        chunk: ScanChunk,
        scanner,
        retry_config: RetryConfig,
        scan_config,
    ) -> ScanResult:
        """Retry scanning a chunk with exponential backoff and splitting."""
        return await self._scan_chunk_with_retry(
            chunk,
            scanner,
            retry_config,
            scan_config,
            original_chunk_id=chunk.id,
        )

    async def _scan_chunk_with_retry(
        self,
        chunk: ScanChunk,
        scanner,
        retry_config: RetryConfig,
        scan_config,
        original_chunk_id: Optional[str] = None,
    ) -> ScanResult:
        """Internal helper that performs retry logic and optional splitting."""
        orig_id = original_chunk_id or chunk.id

        for attempt in range(retry_config.max_attempts):
            try:
                files_to_skip = self._get_files_to_skip(chunk, retry_config)
                if files_to_skip:
                    for path in files_to_skip:
                        self._record_quarantine_entry(path, "retry_limit")
                    chunk = self._exclude_files_from_chunk(chunk, files_to_skip)

                result = await scanner.scan_chunk(chunk, scan_config)
                result.chunk_id = orig_id
                return result

            except Exception as e:  # noqa: BLE001
                error_type_name = type(e).__name__
                is_timeout_or_hang = (
                    isinstance(e, (ScanTimeoutError, ScanHangError))
                    or error_type_name in ("ScanTimeoutError", "ScanHangError")
                )

                if is_timeout_or_hang:
                    self._update_file_retry_counts(chunk)

                    if attempt == retry_config.max_attempts - 1:
                        failure = self._create_quarantine_result(chunk, e)
                        failure.chunk_id = orig_id
                        return failure

                    delay = self.calculate_backoff(attempt, retry_config)
                    await asyncio.sleep(delay)

                    if retry_config.split_on_retry and len(chunk.paths) > 1:
                        split_chunks = self.split_chunk(chunk, 2 ** (attempt + 1))
                        if split_chunks:
                            return await self._scan_split_chunks(
                                split_chunks,
                                scanner,
                                retry_config,
                                scan_config,
                                orig_id,
                            )
                else:
                    raise

        failure = self._create_quarantine_result(
            chunk,
            ScanTimeoutError("Max attempts exceeded"),
        )
        failure.chunk_id = orig_id
        return failure

    async def _scan_split_chunks(
        self,
        split_chunks: List[ScanChunk],
        scanner,
        retry_config: RetryConfig,
        scan_config,
        original_chunk_id: str,
    ) -> ScanResult:
        """Scan each split chunk and merge their results."""
        combined_results: List[ScanResult] = []

        for sub_chunk in split_chunks:
            result = await self._scan_chunk_with_retry(
                sub_chunk,
                scanner,
                retry_config,
                scan_config,
                original_chunk_id=sub_chunk.id,
            )
            combined_results.append(result)

        return self._combine_results(combined_results, original_chunk_id)

    def _combine_results(
        self,
        results: List[ScanResult],
        original_chunk_id: str,
    ) -> ScanResult:
        """Aggregate multiple ScanResult objects into one."""
        combined = ScanResult(chunk_id=original_chunk_id)
        statuses: List[str] = []
        raw_outputs: List[str] = []
        error_messages: List[str] = []

        for result in results:
            if result is None:
                continue

            statuses.append(result.status)
            combined.scanned_files += result.scanned_files
            combined.scanned_directories += result.scanned_directories
            combined.total_errors += result.total_errors
            combined.data_scanned_mb += result.data_scanned_mb
            combined.data_read_mb += result.data_read_mb
            combined.scan_time_seconds += result.scan_time_seconds
            combined.infected_files.extend(result.infected_files)

            if not combined.engine_version and result.engine_version:
                combined.engine_version = result.engine_version

            if result.raw_output:
                raw_outputs.append(result.raw_output)
            if result.error_message:
                error_messages.append(result.error_message)

        if "failed" in statuses:
            combined.status = "failed"
        elif "partial" in statuses:
            combined.status = "partial"
        elif statuses:
            combined.status = "success"

        combined.raw_output = "\n".join(raw_outputs).strip()
        combined.error_message = (
            "\n".join(error_messages).strip() if error_messages else None
        )

        return combined

    def calculate_backoff(self, attempt: int, config: RetryConfig) -> float:
        """
        Calculate exponential backoff with jitter.

        Args:
            attempt: Attempt number (0-indexed)
            config: Retry configuration

        Returns:
            Delay in seconds
        """
        delay = config.base_delay_seconds * (config.exponential_base ** attempt)
        delay = min(delay, config.max_delay_seconds)
        
        # Add jitter (but ensure total doesn't exceed max)
        jitter = random.uniform(0, delay * config.jitter_factor)
        total_delay = delay + jitter
        return min(total_delay, config.max_delay_seconds)

    def split_chunk(self, chunk: ScanChunk, factor: int) -> List[ScanChunk]:
        """
        Split a chunk into smaller pieces.

        Args:
            chunk: Chunk to split
            factor: Number of pieces to split into

        Returns:
            List of split chunks
        """
        if len(chunk.paths) <= 1 or factor <= 1:
            return [chunk]
        
        # Ensure we don't create more chunks than paths
        actual_factor = min(factor, len(chunk.paths))
        # Calculate paths per chunk to get exactly actual_factor chunks
        total_paths = len(chunk.paths)
        base_paths_per_chunk = total_paths // actual_factor
        remainder = total_paths % actual_factor
        
        split_chunks = []
        path_idx = 0
        
        for i in range(actual_factor):
            # Distribute remainder paths to first chunks
            paths_in_this_chunk = base_paths_per_chunk + (1 if i < remainder else 0)
            split_paths = chunk.paths[path_idx : path_idx + paths_in_this_chunk]
            path_idx += paths_in_this_chunk
            
            if not split_paths:
                continue
            
            # Calculate proportional sizes
            split_size = chunk.estimated_size_bytes * len(split_paths) // len(chunk.paths)
            split_files = chunk.file_count * len(split_paths) // len(chunk.paths)
            split_dirs = chunk.directory_count * len(split_paths) // len(chunk.paths)
            
            split_chunk = ScanChunk(
                id=str(uuid.uuid4()),
                paths=split_paths,
                estimated_size_bytes=max(1, split_size),
                file_count=max(1, split_files),
                directory_count=split_dirs,
                created_at=datetime.now(),
            )
            split_chunks.append(split_chunk)
        
        return split_chunks if split_chunks else [chunk]

    def create_skip_list(self, chunk: ScanChunk) -> List[str]:
        """
        Identify files to skip in final retry.

        Args:
            chunk: Chunk to analyze

        Returns:
            List of file paths to skip
        """
        skip_list = []
        
        for path in chunk.paths:
            # Check if file is large
            try:
                if os.path.isfile(path):
                    stat = os.stat(path, follow_symlinks=False)
                    if stat.st_size > 1024**3:  # > 1GB
                        skip_list.append(path)
                        continue
                    
                    # Check for problematic extensions
                    ext = os.path.splitext(path)[1].lower()
                    problematic_exts = ['.zip', '.tar.gz', '.7z', '.rar', '.iso', '.img', '.vmdk', '.vdi']
                    if any(path.endswith(ext) for ext in problematic_exts):
                        skip_list.append(path)
            except (OSError, PermissionError):
                skip_list.append(path)
        
        return skip_list

    def _get_files_to_skip(self, chunk: ScanChunk, config: RetryConfig) -> List[str]:
        """Get files that exceed retry limit."""
        files_to_skip = []
        
        for path in chunk.paths:
            if self.file_retry_counts[path] >= config.max_attempts_per_file:
                files_to_skip.append(path)
                continue
            if self.circuit_breaker.is_blocked(path):
                files_to_skip.append(path)
        
        return files_to_skip

    def _exclude_files_from_chunk(self, chunk: ScanChunk, files_to_skip: List[str]) -> ScanChunk:
        """Create new chunk excluding specified files."""
        remaining_paths = [p for p in chunk.paths if p not in files_to_skip]
        
        if not remaining_paths:
            return chunk  # Can't exclude all paths
        
        # Recalculate sizes proportionally
        remaining_ratio = len(remaining_paths) / len(chunk.paths)
        new_size = int(chunk.estimated_size_bytes * remaining_ratio)
        new_files = int(chunk.file_count * remaining_ratio)
        new_dirs = int(chunk.directory_count * remaining_ratio)
        
        return ScanChunk(
            id=str(uuid.uuid4()),
            paths=remaining_paths,
            estimated_size_bytes=max(1, new_size),
            file_count=max(1, new_files),
            directory_count=new_dirs,
            created_at=datetime.now(),
        )

    def _update_file_retry_counts(self, chunk: ScanChunk):
        """Update retry counts for files in chunk."""
        for path in chunk.paths:
            self.file_retry_counts[path] += 1
            self.circuit_breaker.record_failure(path)

    def _create_quarantine_result(self, chunk: ScanChunk, error: Exception) -> ScanResult:
        """Create result indicating quarantine."""
        reason = self._reason_from_error(error)
        for path in chunk.paths:
            self._record_quarantine_entry(path, reason)
        
        return ScanResult(
            chunk_id=chunk.id,
            status="failed",
            infected_files=[],
            scanned_files=0,
            scanned_directories=0,
            total_errors=len(chunk.paths),
            data_scanned_mb=0.0,
            data_read_mb=0.0,
            scan_time_seconds=0.0,
            engine_version="",
            raw_output="",
            error_message=f"Quarantined: {str(error)}",
        )

    def _record_quarantine_entry(
        self,
        path: str,
        reason: str,
        file_size_bytes: Optional[int] = None,
    ):
        """Record metadata for a quarantined path."""
        self.quarantine_list.append(
            {
                "file_path": path,
                "reason": reason,
                "file_size_bytes": file_size_bytes,
                "retry_count": self.file_retry_counts.get(path, 0),
                "last_attempt": datetime.now(),
            }
        )

    def _reason_from_error(self, error: Exception) -> str:
        """Map exception types to human-readable quarantine reasons."""
        if isinstance(error, ScanTimeoutError):
            return "timeout"
        if isinstance(error, ScanHangError):
            return "hang"
        name = type(error).__name__.lower()
        if "timeout" in name:
            return "timeout"
        if "hang" in name:
            return "hang"
        return name


class CircuitBreaker:
    """Prevents repeated failures on problematic paths."""

    def __init__(self, failure_threshold: int = 3, reset_timeout: int = 300):
        """Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before blocking
            reset_timeout: Seconds before resetting failure count
        """
        self.failures: defaultdict[str, int] = defaultdict(int)
        self.blocked_paths: set[str] = set()
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout

    def record_failure(self, path: str):
        """Record a failure for a path."""
        self.failures[path] += 1
        
        if self.failures[path] >= self.failure_threshold:
            self.blocked_paths.add(path)

    def is_blocked(self, path: str) -> bool:
        """Check if path should be skipped."""
        return path in self.blocked_paths

    def get_blocked_paths(self) -> List[str]:
        """Get list of all blocked paths."""
        return list(self.blocked_paths)
