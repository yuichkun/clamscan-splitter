# ClamAV Scan Splitter - Technical Specification

## 1. Executive Summary

### 1.1 Problem Statement
ClamAV's `clamscan` command, when run recursively on large directories (e.g., home directory with 1.4M+ files), often hangs indefinitely on certain files, making it impossible to complete monthly security scans required for corporate compliance.

### 1.2 Solution Overview
Build a Python-based tool that splits large ClamAV scans into smaller, manageable chunks that run in parallel, with automatic retry mechanisms for failed chunks, ultimately producing a single unified scan report.

### 1.3 Key Requirements
- Split scanning workload into chunks of 10-20GB or 30,000 files
- Detect and handle hanging scan processes
- Retry failed scans with intelligent backoff
- Merge all results into a single report matching corporate format
- Complete scan of ~1.4M files reliably

## 2. Technical Architecture

### 2.1 Technology Stack
- **Language**: Python 3.11+
- **Package Manager**: uv (modern Python package manager)
- **Async Framework**: asyncio for parallel process management
- **Process Monitoring**: psutil for CPU/memory tracking
- **CLI Framework**: Click for command-line interface
- **Progress Display**: Rich for terminal UI
- **Testing**: pytest with pytest-asyncio, pytest-subprocess, pyfakefs

### 2.2 System Architecture Diagram
```
┌─────────────────┐
│   CLI Entry     │
│   (cli.py)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│  File Analyzer  │────▶│   Chunk Creator │
│  (chunker.py)   │     │  (chunker.py)   │
└─────────────────┘     └────────┬────────┘
                                 │
                        ┌────────▼────────┐
                        │  Process Pool   │
                        │  (scanner.py)   │
                        └────────┬────────┘
                                 │
                ┌────────────────┼────────────────┐
                ▼                ▼                ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
        │ Scan Worker  │ │ Scan Worker  │ │ Scan Worker  │
        │ + Monitor    │ │ + Monitor    │ │ + Monitor    │
        └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
               │                 │                 │
               ▼                 ▼                 ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
        │Output Parser │ │Output Parser │ │Output Parser │
        │ (parser.py)  │ │ (parser.py)  │ │ (parser.py)  │
        └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
               │                 │                 │
               └─────────────────┼─────────────────┘
                                 │
                        ┌────────▼────────┐
                        │ Result Merger   │
                        │  (merger.py)    │
                        └────────┬────────┘
                                 │
                        ┌────────▼────────┐
                        │  Final Report   │
                        │   (output)      │
                        └─────────────────┘
```

## 3. Detailed Component Specifications

### 3.1 Chunker Module (`src/chunker.py`)

#### Purpose
Analyzes the filesystem and divides it into scannable chunks based on size and file count constraints.

#### Key Classes and Functions

```python
@dataclass
class ScanChunk:
    """Represents a chunk of files/directories to scan"""
    id: str                    # Unique identifier (UUID)
    paths: List[str]           # List of paths to scan
    estimated_size_bytes: int  # Total size in bytes
    file_count: int           # Number of files
    directory_count: int     # Number of directories
    created_at: datetime      # Timestamp of creation

@dataclass
class ChunkingConfig:
    """Configuration for chunking behavior"""
    target_size_gb: float = 15.0        # Target size per chunk in GB
    max_files_per_chunk: int = 30000    # Maximum files per chunk
    max_directories_per_chunk: int = 5000  # Maximum directories
    respect_directory_boundaries: bool = True  # Don't split directories
    isolate_large_files_gb: float = 1.0  # Files larger than this get own chunk

class FileSystemAnalyzer:
    """Analyzes filesystem structure for chunking"""

    def analyze_directory(self, path: str) -> DirectoryStats:
        """
        Walk directory tree and collect statistics.

        Returns:
            DirectoryStats with total size, file count, depth, large files list
        """
        pass

    def identify_problematic_files(self, path: str) -> List[ProblematicFile]:
        """
        Identify files likely to cause hangs or issues:
        - Files > 1GB
        - Archive files (*.zip, *.tar.gz, *.7z)
        - PDF files > 50MB
        - ISO/IMG files
        - Special files (FIFOs, sockets, device files)
        - Files on different filesystems (if cross_filesystems=False)

        Returns:
            List of ProblematicFile objects with path and reason
        """
        problematic = []

        for root, dirs, files in os.walk(path):
            # Check for mount points and skip if needed
            if not self.config.cross_filesystems:
                dirs[:] = [d for d in dirs if not os.path.ismount(os.path.join(root, d))]

            for file in files:
                filepath = os.path.join(root, file)

                try:
                    stat = os.stat(filepath, follow_symlinks=False)

                    # Skip special files
                    if stat.S_ISFIFO(stat.st_mode):
                        problematic.append(ProblematicFile(filepath, "FIFO"))
                        continue
                    if stat.S_ISSOCK(stat.st_mode):
                        problematic.append(ProblematicFile(filepath, "Socket"))
                        continue
                    if stat.S_ISBLK(stat.st_mode) or stat.S_ISCHR(stat.st_mode):
                        problematic.append(ProblematicFile(filepath, "Device"))
                        continue

                    # Check file size
                    if stat.st_size > 1024**3:  # 1GB
                        problematic.append(ProblematicFile(filepath, f"Large file: {stat.st_size / 1024**3:.1f}GB"))

                    # Check problematic extensions
                    ext = os.path.splitext(filepath)[1].lower()
                    if ext in ['.iso', '.img', '.vmdk', '.vdi']:
                        problematic.append(ProblematicFile(filepath, f"Disk image: {ext}"))

                except (OSError, PermissionError):
                    problematic.append(ProblematicFile(filepath, "Permission denied"))

        return problematic

class ChunkCreator:
    """Creates optimal chunks from filesystem analysis"""

    def create_chunks(self,
                     root_path: str,
                     config: ChunkingConfig) -> List[ScanChunk]:
        """
        Main chunking algorithm:

        1. Analyze filesystem structure
        2. Identify and isolate problematic files
        3. Group remaining files/directories into chunks
        4. Respect directory boundaries when possible
        5. Balance chunk sizes

        Algorithm:
        - Start with empty chunk
        - Walk directory tree depth-first
        - For each directory:
            - If directory fits in current chunk, add it
            - If not, close current chunk and start new one
            - If directory itself is too large, split by subdirectories
        - Handle edge cases:
            - Very deep nesting (>10 levels)
            - Directories with 100k+ files
            - Sparse directories (few files, deep nesting)
            - Single files larger than chunk size (isolate with extended timeout)

        Returns:
            List of ScanChunk objects ready for scanning
        """
        pass

    def rebalance_chunks(self, chunks: List[ScanChunk]) -> List[ScanChunk]:
        """
        Post-process chunks to ensure balanced distribution.
        Merge very small chunks, split very large ones.
        """
        pass
```

#### Implementation Notes
- Use `os.walk()` with `topdown=True` for controllable traversal
- Cache directory sizes to avoid repeated calculations
- Use `os.stat()` for accurate file sizes
- Handle permission errors gracefully (skip inaccessible directories)

### 3.2 Scanner Module (`src/scanner.py`)

#### Purpose
Manages the parallel execution of ClamAV scans on chunks with process monitoring.

#### Key Classes and Functions

```python
@dataclass
class ScanConfig:
    """Configuration for scanning behavior"""
    max_concurrent_processes: int = None  # Auto-calculated based on memory
    base_timeout_per_gb: int = 30  # seconds
    min_timeout_seconds: int = 300  # 5 minutes
    max_timeout_seconds: int = 3600  # 1 hour
    clamscan_path: str = "clamscan"
    clamscan_options: List[str] = field(default_factory=lambda: ["-r", "--no-summary"])
    memory_per_process_gb: float = 2.0  # Expected memory per clamscan
    min_free_memory_gb: float = 2.0  # Keep this much memory free

class ScanWorker:
    """Executes a single scan with monitoring"""

    async def scan_chunk(self, chunk: ScanChunk, config: ScanConfig) -> ScanResult:
        """
        Execute clamscan on a chunk with monitoring.

        Process:
        1. Calculate timeout based on chunk size
        2. Start clamscan subprocess
        3. Start monitoring tasks (timeout, CPU, output)
        4. Capture output
        5. Parse results
        6. Handle failures/timeouts

        Returns:
            ScanResult object with scan outcome
        """
        pass

    async def _execute_clamscan(self, paths: List[str], timeout: int) -> tuple[str, str, int]:
        """
        Run clamscan subprocess with asyncio.

        Command format:
            clamscan -r --no-summary [paths...]

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        pass

class ProcessMonitor:
    """Monitors running scan processes for hangs"""

    def __init__(self, process_pid: int):
        self.process = psutil.Process(process_pid)
        self.cpu_samples = deque(maxlen=10)
        self.last_output_time = time.time()

    async def monitor_cpu(self, threshold: float = 5.0) -> bool:
        """
        Monitor CPU usage. Returns True if process appears hung.

        Hang detection:
        - Sample CPU every 30 seconds
        - If CPU < threshold for 5 consecutive samples, likely hung
        """
        pass

    async def monitor_output(self, output_pipe: asyncio.StreamReader) -> bool:
        """
        Monitor output activity. Returns True if no output for 10 minutes.
        """
        pass

    def kill_process_tree(self):
        """
        Kill process and all children.
        Important: ClamAV may spawn child processes
        """
        pass

class ScanOrchestrator:
    """Coordinates parallel scanning of all chunks"""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.max_workers = self._calculate_max_workers()
        self.semaphore = asyncio.Semaphore(self.max_workers)
        self.results = []
        self.failed_chunks = []
        self.quarantined_files = []

    def _calculate_max_workers(self) -> int:
        """
        Calculate maximum workers based on available memory.

        Formula:
            available_memory = total_memory - used_memory - min_free_memory
            max_by_memory = available_memory / memory_per_process
            max_by_cpu = cpu_count() - 1
            return min(max_by_memory, max_by_cpu, configured_limit)
        """
        import psutil
        mem = psutil.virtual_memory()
        available_gb = (mem.available / (1024**3)) - self.config.min_free_memory_gb
        max_by_memory = int(available_gb / self.config.memory_per_process_gb)
        max_by_cpu = psutil.cpu_count() - 1

        if self.config.max_concurrent_processes:
            return min(max_by_memory, max_by_cpu, self.config.max_concurrent_processes)
        return max(1, min(max_by_memory, max_by_cpu))

    async def scan_all(
        self,
        chunks: List[ScanChunk],
        on_result: Optional[Callable[[ScanResult], Awaitable[None]]] = None,
    ) -> List[ScanResult]:
        """
        Scan all chunks in parallel with concurrency limit.

        Process:
        1. Create task for each chunk
        2. Use semaphore to limit concurrency
        3. Asynchronously yield results as soon as each chunk finishes
        4. Invoke `on_result` callback (sync or async) per chunk for streaming updates
        5. Track failed chunks and return all results when complete
        """
        pass

    async def _scan_with_retry(self, chunk: ScanChunk) -> ScanResult:
        """
        Scan a chunk with retry logic.
        Delegates to retry.py module.
        """
        pass
```

#### Implementation Notes
- Use `asyncio.create_subprocess_exec()` for subprocess management
- Set `stdout=PIPE, stderr=PIPE` to capture output
- Use `asyncio.wait_for()` for timeout enforcement
- Monitor process with `psutil.Process(pid).cpu_percent(interval=1)`
- Kill process tree to ensure all child processes are terminated

### 3.3 Parser Module (`src/parser.py`)

#### Purpose
Parses ClamAV output to extract scan results and statistics.

#### Key Classes and Functions

```python
@dataclass
class ScanResult:
    """Represents the result of a single scan"""
    chunk_id: str                    # ID of the scanned chunk
    status: str                      # "success", "failed", "timeout", "partial"
    infected_files: List[InfectedFile]  # List of infected files found
    scanned_files: int              # Number of files scanned
    scanned_directories: int        # Number of directories scanned
    total_errors: int               # Number of scan errors
    data_scanned_mb: float          # MB of data scanned
    data_read_mb: float             # MB of data read
    scan_time_seconds: float        # Time taken in seconds
    engine_version: str             # ClamAV engine version
    raw_output: str                 # Full raw output for debugging
    error_message: Optional[str]    # Error message if failed

@dataclass
class InfectedFile:
    """Represents an infected file detection"""
    file_path: str                  # Full path to infected file
    virus_name: str                 # Name of detected virus/malware
    action_taken: str               # Usually "FOUND"

class ClamAVOutputParser:
    """Parses ClamAV scan output"""

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ScanResult:
        """
        Parse ClamAV output to extract results.

        ClamAV output format:
        ```
        /path/to/file1: OK
        /path/to/file2: Virus.Name FOUND
        /path/to/file3: ERROR: Permission denied

        ----------- SCAN SUMMARY -----------
        Known viruses: 8708688
        Engine version: 1.4.3
        Scanned directories: 159931
        Scanned files: 1394942
        Infected files: 0
        Total errors: 3
        Data scanned: 92772.46 MB
        Data read: 159697.51 MB (ratio 0.58:1)
        Time: 24049.662 sec (400 m 49 s)
        Start Date: 2025:11:08 18:03:18
        End Date:   2025:11:09 00:44:08
        ```

        Returns:
            ScanResult object with parsed data
        """
        pass

    def _parse_infected_files(self, lines: List[str]) -> List[InfectedFile]:
        """
        Extract infected file entries from output lines.
        Pattern: "/path/to/file: VirusName FOUND"
        """
        pass

    def _parse_summary(self, summary_text: str) -> dict:
        """
        Parse the SCAN SUMMARY section.
        Uses regex to extract each field.
        """
        pass

    def _handle_parse_error(self, error: Exception, raw_output: str) -> ScanResult:
        """
        Create error result when parsing fails.
        Preserves raw output for debugging.
        """
        pass
```

#### Regular Expressions for Parsing

```python
# Patterns for parsing ClamAV output
PATTERNS = {
    'infected_file': re.compile(r'^(.+?):\s+(.+?)\s+FOUND$'),
    'error_line': re.compile(r'^(.+?):\s+ERROR:\s+(.+)$'),
    'summary_start': re.compile(r'-+\s*SCAN SUMMARY\s*-+'),
    'scanned_files': re.compile(r'Scanned files:\s+(\d+)'),
    'scanned_dirs': re.compile(r'Scanned directories:\s+(\d+)'),
    'infected_count': re.compile(r'Infected files:\s+(\d+)'),
    'total_errors': re.compile(r'Total errors:\s+(\d+)'),
    'data_scanned': re.compile(r'Data scanned:\s+([\d.]+)\s+MB'),
    'data_read': re.compile(r'Data read:\s+([\d.]+)\s+MB'),
    'scan_time': re.compile(r'Time:\s+([\d.]+)\s+sec'),
    'engine_version': re.compile(r'Engine version:\s+([\d.]+)'),
}
```

### 3.4 Retry Module (`src/retry.py`)

#### Purpose
Implements intelligent retry logic for failed scans with exponential backoff and chunk splitting.

#### Key Classes and Functions

```python
@dataclass
class RetryConfig:
    """Configuration for retry behavior"""
    max_attempts: int = 3
    max_attempts_per_file: int = 2  # Per-file retry limit
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 300.0  # 5 minutes
    exponential_base: float = 2.0
    jitter_factor: float = 0.1  # Add 0-10% random jitter
    split_on_retry: bool = True  # Split chunk into smaller pieces on retry
    quarantine_on_final_failure: bool = True  # Add to quarantine list

class RetryManager:
    """Manages retry logic for failed scans"""

    def __init__(self):
        self.file_retry_counts = defaultdict(int)  # Track per-file retries
        self.quarantine_list = []  # Files that consistently fail

    async def scan_with_retry(self,
                             chunk: ScanChunk,
                             scanner: ScanWorker,
                             config: RetryConfig) -> ScanResult:
        """
        Scan with exponential backoff retry and quarantine.

        Retry strategy:
        1. First attempt: scan normally
        2. Second attempt: wait 1-2 seconds, split chunk in half
        3. Third attempt: wait 4-8 seconds, split chunk into quarters
        4. Final: Add problematic files to quarantine, scan rest

        Returns:
            ScanResult (may be partial with quarantined files noted)
        """
        for attempt in range(config.max_attempts):
            try:
                # Check if any files in chunk exceed retry limit
                files_to_skip = self._get_files_to_skip(chunk, config)
                if files_to_skip:
                    chunk = self._exclude_files_from_chunk(chunk, files_to_skip)
                    self.quarantine_list.extend(files_to_skip)

                result = await scanner.scan_chunk(chunk, config)
                return result

            except (ScanTimeoutError, ScanHangError) as e:
                # Track which files might be problematic
                self._update_file_retry_counts(chunk)

                if attempt == config.max_attempts - 1:
                    # Final attempt failed - quarantine and report
                    return self._create_quarantine_result(chunk, e)

                # Calculate backoff delay
                delay = self.calculate_backoff(attempt, config)
                await asyncio.sleep(delay)

                # Split chunk for next attempt
                if config.split_on_retry:
                    chunk = self._split_problematic_chunk(chunk, 2 ** attempt)

        pass

    def calculate_backoff(self, attempt: int, config: RetryConfig) -> float:
        """
        Calculate exponential backoff with jitter.

        Formula:
            delay = min(base * (exponential_base ^ attempt), max_delay)
            jitter = random.uniform(0, delay * jitter_factor)
            return delay + jitter
        """
        pass

    def split_chunk(self, chunk: ScanChunk, factor: int) -> List[ScanChunk]:
        """
        Split a chunk into smaller pieces.

        Splitting strategy:
        - Divide paths evenly into 'factor' sub-chunks
        - Maintain directory boundaries where possible
        - Update size/count estimates proportionally
        """
        pass

    def create_skip_list(self, chunk: ScanChunk) -> List[str]:
        """
        Identify files to skip in final retry.

        Skip criteria:
        - Files > 1GB
        - Archive files
        - Files matching problematic patterns
        """
        pass

class CircuitBreaker:
    """Prevents repeated failures on problematic paths"""

    def __init__(self, failure_threshold: int = 3, reset_timeout: int = 300):
        self.failures = defaultdict(int)  # path -> failure count
        self.blocked_paths = set()
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout

    def record_failure(self, path: str):
        """Record a failure for a path"""
        pass

    def is_blocked(self, path: str) -> bool:
        """Check if path should be skipped"""
        pass

    def get_blocked_paths(self) -> List[str]:
        """Get list of all blocked paths"""
        pass
```

### 3.5 Monitor Module (`src/monitor.py`)

#### Purpose
Provides detailed process monitoring to detect hanging scans.

#### Key Classes and Functions

```python
@dataclass
class ProcessMetrics:
    """Metrics for a running process"""
    pid: int
    cpu_percent: float
    memory_mb: float
    num_threads: int
    io_counters: dict
    create_time: float
    status: str  # "running", "sleeping", "zombie"

class HangDetector:
    """Detects hanging scan processes"""

    def __init__(self,
                 cpu_threshold: float = 5.0,
                 cpu_sample_count: int = 5,
                 output_timeout: int = 600):  # 10 minutes
        self.cpu_threshold = cpu_threshold
        self.cpu_sample_count = cpu_sample_count
        self.output_timeout = output_timeout

    async def is_process_hung(self,
                              process: psutil.Process,
                              output_stream: Optional[asyncio.StreamReader]) -> bool:
        """
        Determine if process is hung using multiple signals.

        Hang indicators:
        1. CPU usage < threshold for N consecutive samples
        2. No output for timeout period
        3. Process in zombie state
        4. I/O counters not changing

        Returns:
            True if process appears hung
        """
        pass

    async def monitor_cpu_usage(self, process: psutil.Process) -> List[float]:
        """
        Collect CPU usage samples over time.
        Sample every 30 seconds.
        """
        pass

    async def monitor_output_activity(self,
                                     stream: asyncio.StreamReader,
                                     timeout: int) -> bool:
        """
        Monitor if output is being produced.
        Returns True if output detected within timeout.
        """
        pass

    def check_process_health(self, process: psutil.Process) -> str:
        """
        Check overall process health.
        Returns: "healthy", "suspicious", "hung", "zombie"
        """
        pass

class ResourceMonitor:
    """Monitors system resources during scanning"""

    def __init__(self):
        self.start_time = time.time()
        self.samples = []

    def collect_sample(self) -> ResourceSample:
        """
        Collect current resource usage.

        Metrics:
        - Total CPU usage
        - Available memory
        - Disk I/O rates
        - Number of scan processes
        """
        pass

    def should_reduce_concurrency(self) -> bool:
        """
        Determine if we should reduce parallel processes.

        Triggers:
        - Memory usage > 90%
        - CPU usage > 95% sustained
        - Disk I/O bottleneck detected
        """
        pass

    def get_recommended_concurrency(self) -> int:
        """
        Calculate optimal number of concurrent processes.
        Based on available resources.
        """
        pass
```

### 3.6 Merger Module (`src/merger.py`)

#### Purpose
Merges results from all chunks into a single unified report.

#### Key Classes and Functions

```python
@dataclass
class MergedReport:
    """Final merged scan report"""
    total_scanned_files: int
    total_scanned_directories: int
    total_infected_files: int
    infected_file_paths: List[str]
    total_errors: int
    total_data_scanned_mb: float
    total_data_read_mb: float
    total_time_seconds: float
    wall_clock_time_seconds: float
    engine_version: str
    chunks_successful: int
    chunks_failed: int
    chunks_partial: int
    skipped_paths: List[str]
    quarantined_files: List[QuarantineEntry]  # Files that couldn't be scanned
    scan_date: datetime
    scan_complete: bool  # False if any files were skipped/quarantined

@dataclass
class QuarantineEntry:
    """Record of a file that couldn't be scanned"""
    file_path: str
    reason: str  # "timeout", "hang", "permission", "special_file"
    file_size_bytes: Optional[int]
    retry_count: int
    last_attempt: datetime

class ResultMerger:
    """Merges multiple scan results into unified report"""

    def merge_results(self, results: List[ScanResult]) -> MergedReport:
        """
        Merge all scan results into single report.

        Merging logic:
        1. Deduplicate infected files (same file may appear in overlaps)
        2. Sum statistics (files, directories, errors, data)
        3. Calculate total time (max of individual times for wall clock)
        4. Track success/failure/partial counts
        5. Compile list of skipped paths

        Returns:
            MergedReport object
        """
        pass

    def _deduplicate_infected_files(self,
                                   results: List[ScanResult]) -> List[str]:
        """
        Remove duplicate infected file paths.
        Maintains order of first occurrence.
        """
        pass

    def _calculate_statistics(self, results: List[ScanResult]) -> dict:
        """
        Calculate aggregate statistics from all results.
        """
        pass

    def format_report(self, report: MergedReport) -> str:
        """
        Format report in required corporate format with quarantine info.

        Format:
        ```
        ----------- SCAN SUMMARY -----------
        Known viruses: {from first result}
        Engine version: {version}
        Scanned directories: {total}
        Scanned files: {total}
        Infected files: {count}
        Total errors: {total}
        Data scanned: {total} MB
        Data read: {total} MB (ratio {calculated}:1)
        Time: {seconds} sec ({minutes} m {seconds} s)
        Start Date: {timestamp}
        End Date:   {timestamp}

        ----------- QUARANTINE SUMMARY -----------
        Files that could not be scanned: {count}
        Reasons:
          - Timeout: {count}
          - Permission denied: {count}
          - Special files: {count}
          - Other: {count}

        IMPORTANT: {count} files were not scanned. Manual review required.
        Full quarantine list saved to: quarantine_report.json
        ```
        """
        pass

    def save_detailed_report(self, report: MergedReport, path: str):
        """
        Save detailed JSON report with all information.
        Includes per-chunk results, skipped files, errors.
        """
        pass
```

### 3.7 State Module (`src/state.py`)

#### Purpose
Manages persistent state for resumable scans and failure tracking.

#### Key Classes and Functions

```python
@dataclass
class ScanState:
    """Persistent state of a scan operation"""
    scan_id: str                    # Unique scan identifier
    root_path: str                  # Root path being scanned
    total_chunks: int               # Total number of chunks
    chunks: List[dict]              # Serialized chunk metadata (preserves IDs for resume)
    completed_chunks: List[str]     # IDs of completed chunks
    failed_chunks: List[str]        # IDs of failed chunks
    partial_results: List[ScanResult]  # Results collected so far
    start_time: datetime            # When scan started
    last_update: datetime           # Last state update
    configuration: dict             # Scan configuration used

class StateManager:
    """Manages persistent state storage"""

    def __init__(self, state_dir: str = "~/.clamscan-splitter/state"):
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
        """
        import json
        import tempfile

        state_file = self.state_dir / f"{state.scan_id}.json"
        temp_fd, temp_path = tempfile.mkstemp(
            dir=self.state_dir,
            prefix=f".{state.scan_id}.",
            suffix=".tmp"
        )

        try:
            # Write to temp file
            with os.fdopen(temp_fd, 'w') as f:
                json.dump(asdict(state), f, indent=2, default=str)
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
        Returns None if not found.
        """
        pass

    def list_incomplete_scans(self) -> List[ScanState]:
        """
        List all scans that haven't completed.
        """
        pass

    def cleanup_old_states(self, days: int = 30):
        """
        Remove state files older than specified days.
        """
        pass

class ProgressTracker:
    """Tracks and displays scan progress"""

    def __init__(self, total_chunks: int):
        self.total_chunks = total_chunks
        self.completed = 0
        self.failed = 0
        self.current_chunks = {}  # chunk_id -> status
        self.start_time = time.time()

    def update_chunk_status(self, chunk_id: str, status: str):
        """
        Update status of a chunk.
        Status: "scanning", "completed", "failed", "retrying"
        """
        pass

    def get_progress_percentage(self) -> float:
        """Calculate completion percentage"""
        pass

    def get_eta(self) -> Optional[timedelta]:
        """Estimate time to completion"""
        pass

    def format_progress_bar(self) -> str:
        """
        Format progress for display.
        Example: [████████████░░░░░░░░] 60% (12/20 chunks) ETA: 5m 30s
        """
        pass
```

### 3.8 CLI Module (`src/cli.py`)

#### Purpose
Provides command-line interface for the scanner.

#### Commands and Options

```python
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """ClamAV Scan Splitter - Parallel scanning for large directories"""
    pass

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--chunk-size', default=15.0, help='Target chunk size in GB')
@click.option('--max-files', default=30000, help='Max files per chunk')
@click.option('--workers', default=None, type=int, help='Number of parallel workers')
@click.option('--timeout-per-gb', default=30, help='Timeout seconds per GB')
@click.option('--output', '-o', type=click.Path(), help='Output report path')
@click.option('--json', is_flag=True, help='Output JSON format')
@click.option('--resume', type=str, help='Resume scan by ID')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--dry-run', is_flag=True, help='Show chunks without scanning')
def scan(path, chunk_size, max_files, workers, timeout_per_gb,
         output, json, resume, verbose, dry_run):
    """
    Scan directory with ClamAV using parallel chunked processing.

    Examples:
        # Basic scan
        clamscan-splitter scan ~/

        # Custom configuration
        clamscan-splitter scan ~/ --chunk-size 20 --workers 8

        # Dry run to see chunks
        clamscan-splitter scan ~/ --dry-run

        # Resume interrupted scan
        clamscan-splitter scan --resume abc123

        # Save report to file
        clamscan-splitter scan ~/ -o report.txt
    """
    pass

@cli.command()
def list():
    """List incomplete scans that can be resumed"""
    pass

@cli.command()
@click.argument('scan_id')
def status(scan_id):
    """Show status of a scan"""
    pass

@cli.command()
@click.option('--days', default=30, help='Delete states older than N days')
def cleanup(days):
    """Clean up old scan states"""
    pass

class ScanUI:
    """Rich terminal UI for scan progress"""

    def __init__(self):
        self.console = Console()
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        )
        self.task_id: Optional[int] = None
        self.chunk_status: Dict[str, str] = {}

    def display_scan_start(self, path: str, chunks: int):
        """Display scan start information"""
        pass

    def update_chunk_progress(
        self,
        chunk_id: str,
        status: str,
        completed: int,
        failed: int,
        total: int,
    ):
        """Update progress display for a chunk"""
        pass

    def display_infected_file(self, file_path: str, virus_name: str):
        """Display infected file detection in real-time"""
        pass

    def display_final_report(self, report: MergedReport):
        """Display formatted final report"""
        pass
```

## 4. Error Handling

### 4.1 Error Categories

```python
class ScanError(Exception):
    """Base exception for scan errors"""
    pass

class ChunkingError(ScanError):
    """Error during chunk creation"""
    pass

class ScanTimeoutError(ScanError):
    """Scan exceeded timeout"""
    pass

class ScanHangError(ScanError):
    """Scan process appears hung"""
    pass

class ParseError(ScanError):
    """Error parsing ClamAV output"""
    pass

class RetryExhaustedError(ScanError):
    """All retry attempts failed"""
    pass

class ResourceError(ScanError):
    """System resource issue (memory, disk)"""
    pass
```

### 4.2 Error Handling Strategy

1. **Permission Errors**: Skip inaccessible directories, log in report
2. **Timeout Errors**: Retry with smaller chunk size
3. **Parse Errors**: Save raw output, mark as partial result
4. **Resource Errors**: Reduce concurrency, wait, retry
5. **ClamAV Not Found**: Check PATH, provide installation instructions
6. **Keyboard Interrupt**: Save state, allow resume

## 5. Testing Strategy

### 5.1 Test Structure

```
tests/
├── unit/
│   ├── test_chunker.py
│   │   ├── test_analyze_directory
│   │   ├── test_create_chunks
│   │   ├── test_chunk_size_limits
│   │   └── test_problematic_file_detection
│   │
│   ├── test_parser.py
│   │   ├── test_parse_clean_output
│   │   ├── test_parse_infected_output
│   │   ├── test_parse_error_output
│   │   └── test_parse_malformed_output
│   │
│   ├── test_merger.py
│   │   ├── test_merge_results
│   │   ├── test_deduplicate_infections
│   │   └── test_format_report
│   │
│   └── test_retry.py
│       ├── test_exponential_backoff
│       ├── test_chunk_splitting
│       └── test_circuit_breaker
│
├── integration/
│   ├── test_scanner.py
│   │   ├── test_subprocess_execution
│   │   ├── test_timeout_handling
│   │   └── test_parallel_execution
│   │
│   └── test_monitor.py
│       ├── test_cpu_monitoring
│       ├── test_hang_detection
│       └── test_process_killing
│
├── e2e/
│   ├── test_full_scan.py
│   ├── test_resume_scan.py
│   └── test_error_recovery.py
│
└── fixtures/
    ├── mock_filesystem.py
    ├── sample_outputs/
    │   ├── clean_scan.txt
    │   ├── infected_scan.txt
    │   └── error_scan.txt
    └── test_files/
        ├── eicar.txt          # EICAR test virus
        ├── large_file.bin     # 2GB test file
        └── deep_nesting/      # Deeply nested directories
```

### 5.2 Key Test Cases

#### Unit Tests

```python
# test_chunker.py
def test_respects_size_limit(fs):
    """Test chunks don't exceed size limit"""
    fs.create_file('/test/big.bin', st_size=20*1024**3)  # 20GB
    chunks = create_chunks('/test', target_size_gb=15)
    assert len(chunks) == 2
    assert all(c.estimated_size_bytes <= 15*1024**3 for c in chunks)

def test_handles_deep_nesting(fs):
    """Test handling of deeply nested directories"""
    # Create 20-level deep directory
    path = '/test'
    for i in range(20):
        path = f'{path}/level{i}'
        fs.create_dir(path)
        fs.create_file(f'{path}/file.txt', st_size=1024)

    chunks = create_chunks('/test')
    assert len(chunks) > 0

# test_parser.py
def test_parse_infected_file_detection():
    """Test parsing of infected file entries"""
    output = """
    /home/user/virus.exe: Win.Trojan.Generic FOUND
    /home/user/malware.dll: Linux.Malware.Agent FOUND
    ----------- SCAN SUMMARY -----------
    Infected files: 2
    """
    result = parse_output(output)
    assert len(result.infected_files) == 2
    assert result.infected_files[0].virus_name == "Win.Trojan.Generic"

# test_retry.py
@pytest.mark.asyncio
async def test_exponential_backoff_timing():
    """Test retry delays follow exponential backoff"""
    delays = []
    for attempt in range(4):
        delay = calculate_backoff(attempt, RetryConfig())
        delays.append(delay)

    # Each delay should be roughly double the previous (minus jitter)
    assert delays[1] > delays[0] * 1.5
    assert delays[2] > delays[1] * 1.5
```

#### Integration Tests

```python
# test_scanner.py
@pytest.mark.asyncio
async def test_timeout_kills_process(fake_process):
    """Test that timeout properly kills hanging process"""
    # Mock a hanging clamscan
    fake_process.register_subprocess(
        ['clamscan', '-r', '/test'],
        stdout='Scanning...\n',
        wait=float('inf')
    )

    worker = ScanWorker()
    chunk = ScanChunk(id='test', paths=['/test'], ...)

    with pytest.raises(ScanTimeoutError):
        await asyncio.wait_for(
            worker.scan_chunk(chunk, ScanConfig(min_timeout_seconds=1)),
            timeout=2
        )

    # Verify process was killed
    assert fake_process.calls[0].was_terminated

# test_monitor.py
@pytest.mark.asyncio
async def test_detects_low_cpu_hang():
    """Test detection of hung process via low CPU"""
    monitor = HangDetector(cpu_threshold=5.0)

    # Mock process with low CPU
    mock_process = Mock(spec=psutil.Process)
    mock_process.cpu_percent.return_value = 2.0  # Below threshold

    # Collect samples
    is_hung = await monitor.is_process_hung(mock_process, None)
    assert is_hung == True
```

#### End-to-End Tests

```python
# test_full_scan.py
@pytest.mark.asyncio
async def test_complete_scan_with_infections(tmp_path):
    """Test full scan workflow with EICAR test virus"""
    # Create test structure
    (tmp_path / 'clean').mkdir()
    (tmp_path / 'clean' / 'file.txt').write_text('clean content')

    # Add EICAR test virus
    eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    (tmp_path / 'infected').mkdir()
    (tmp_path / 'infected' / 'virus.txt').write_text(eicar)

    # Run scan
    result = await scan_directory(str(tmp_path))

    assert result.total_infected_files == 1
    assert 'virus.txt' in result.infected_file_paths[0]
    assert result.total_scanned_files >= 2

# test_resume_scan.py
@pytest.mark.asyncio
async def test_resume_interrupted_scan(tmp_path, monkeypatch):
    """Test resuming an interrupted scan"""
    # Start scan
    scan_id = start_scan(str(tmp_path))

    # Simulate interruption after 2 chunks
    monkeypatch.setattr('scanner.INTERRUPT_AFTER_CHUNKS', 2)

    with pytest.raises(KeyboardInterrupt):
        await run_scan(scan_id)

    # Resume scan
    result = await resume_scan(scan_id)
    assert result.chunks_successful >= 2
```

### 5.3 Test Utilities

```python
# fixtures/mock_filesystem.py
class MockFileSystem:
    """Mock filesystem for testing"""

    def create_test_structure(self,
                             total_size_gb: float,
                             num_files: int,
                             max_depth: int) -> str:
        """Create a mock directory structure for testing"""
        pass

    def create_problematic_files(self) -> List[str]:
        """Create files that typically cause scan issues"""
        pass

# fixtures/sample_outputs.py
CLEAN_SCAN_OUTPUT = """
/home/user/file1.txt: OK
/home/user/file2.doc: OK
----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 2
Scanned files: 2
Infected files: 0
Total errors: 0
Data scanned: 0.50 MB
Data read: 0.50 MB (ratio 1.00:1)
Time: 1.234 sec (0 m 1 s)
"""

INFECTED_SCAN_OUTPUT = """
/home/user/virus.exe: Win.Trojan.Generic FOUND
/home/user/clean.txt: OK
----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 1
Scanned files: 2
Infected files: 1
Total errors: 0
Data scanned: 1.00 MB
Data read: 1.00 MB (ratio 1.00:1)
Time: 2.345 sec (0 m 2 s)
"""
```

## 6. Configuration

### 6.1 Configuration File Format (YAML)

```yaml
# ~/.clamscan-splitter/config.yml

scanning:
  # ClamAV executable path
  clamscan_path: /usr/local/bin/clamscan

  # Additional clamscan options
  clamscan_options:
    - "--max-filesize=2000M"
    - "--max-scansize=2000M"
    - "--max-recursion=16"

  # Chunking configuration
  chunking:
    target_size_gb: 15.0
    max_files_per_chunk: 30000
    max_directories_per_chunk: 5000
    respect_directory_boundaries: true
    isolate_large_files_gb: 1.0

  # Parallel execution
  concurrency:
    max_workers: 7  # null for auto-detect (cpu_count - 1)
    reduce_on_high_load: true
    min_workers: 2

  # Timeout settings
  timeouts:
    base_timeout_per_gb: 30  # seconds
    min_timeout: 300         # 5 minutes
    max_timeout: 3600        # 60 minutes
    output_timeout: 600      # 10 minutes

# Retry configuration
retry:
  max_attempts: 3
  base_delay: 1.0
  max_delay: 300.0
  exponential_base: 2.0
  jitter_factor: 0.1
  split_on_retry: true

# Monitoring settings
monitoring:
  cpu_threshold: 5.0         # percent
  cpu_sample_interval: 30    # seconds
  cpu_sample_count: 5        # consecutive samples
  check_process_health: true
  kill_zombies: true

# Output settings
output:
  format: "text"  # "text" or "json"
  verbose: false
  show_progress: true
  save_detailed_report: true
  report_directory: "~/.clamscan-splitter/reports"

# State management
state:
  enable_resume: true
  state_directory: "~/.clamscan-splitter/state"
  cleanup_days: 30

# File patterns to handle specially
patterns:
  skip_patterns:
    - "*.vmdk"
    - "*.vdi"
    - "*.iso"
    - "*.img"

  isolate_patterns:
    - "*.zip"
    - "*.tar.gz"
    - "*.7z"
    - "*.rar"

  problematic_extensions:
    - ".pdf"
    - ".docx"
    - ".xlsx"
```

### 6.2 Environment Variables

```bash
# Override configuration via environment variables
CLAMSCAN_SPLITTER_WORKERS=10
CLAMSCAN_SPLITTER_CHUNK_SIZE=20
CLAMSCAN_SPLITTER_TIMEOUT=45
CLAMSCAN_SPLITTER_CONFIG=/custom/path/config.yml
CLAMSCAN_SPLITTER_LOG_LEVEL=DEBUG
```

## 7. Performance Considerations

### 7.1 Optimization Strategies

1. **I/O Optimization**
   - Use `os.scandir()` instead of `os.listdir()` for better performance
   - Batch file operations when possible
   - Use memory-mapped files for large file checks

2. **Memory Management**
   - Stream parsing instead of loading entire output
   - Limit chunk metadata in memory
   - Use generators for file iteration

3. **CPU Utilization**
   - Balance CPU cores between scanners and monitors
   - Use process pools for CPU-intensive parsing
   - Implement adaptive concurrency based on system load

### 7.2 Benchmarks

Expected performance metrics:
- **Chunking**: ~100,000 files/second analysis
- **Scanning**: ~50-100 MB/second per process (ClamAV limited)
- **Parsing**: ~10,000 lines/second
- **Memory usage**: ~100MB base + 50MB per worker

## 8. Security Considerations

1. **Input Validation**
   - Validate all paths to prevent directory traversal
   - Sanitize file paths in reports
   - Limit chunk sizes to prevent memory exhaustion

2. **Process Isolation**
   - Run each scanner in separate process
   - Drop privileges if running as root
   - Use subprocess with shell=False

3. **Output Handling**
   - Sanitize virus names in reports
   - Limit output buffer sizes
   - Validate JSON before parsing

## 9. Installation and Setup

### 9.1 Requirements

```toml
# pyproject.toml
[project]
name = "clamscan-splitter"
version = "1.0.0"
description = "Parallel ClamAV scanner for large directories"
requires-python = ">=3.11"

dependencies = [
    "click>=8.1.0",
    "psutil>=5.9.0",
    "rich>=13.0.0",
    "pyyaml>=6.0",
    "aiofiles>=23.0.0",
]

[project.optional-dependencies]
test = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-subprocess>=1.5.0",
    "pyfakefs>=5.3.0",
    "pytest-cov>=4.1.0",
]

[project.scripts]
clamscan-splitter = "clamscan_splitter.cli:cli"
```

### 9.2 Installation Steps

```bash
# Using uv (recommended)
uv pip install -e .
uv pip install -e ".[test]"  # Include test dependencies

# Or using pip
pip install -e .
pip install -e ".[test]"
```

### 9.3 Quick Start

```bash
# Basic scan
clamscan-splitter scan ~/

# See what chunks would be created
clamscan-splitter scan ~/ --dry-run

# Custom configuration
clamscan-splitter scan ~/ --chunk-size 20 --workers 8

# Use configuration file
export CLAMSCAN_SPLITTER_CONFIG=~/.clamscan-splitter/config.yml
clamscan-splitter scan ~/

# Resume interrupted scan
clamscan-splitter list  # See incomplete scans
clamscan-splitter scan --resume abc123def456

# Run tests
pytest tests/ -v
pytest tests/unit/ --cov=clamscan_splitter
```

## 10. Troubleshooting Guide

### Common Issues and Solutions

1. **"clamscan not found"**
   - Install ClamAV: `sudo apt-get install clamav`
   - Verify path: `which clamscan`
   - Update config with correct path

2. **"Permission denied" errors**
   - Run with appropriate permissions
   - Or configure to skip inaccessible files

3. **Scans still hanging**
   - Reduce chunk size
   - Increase timeout values
   - Check system resources (RAM, disk space)

4. **High memory usage**
   - Reduce number of parallel workers
   - Decrease chunk size
   - Enable swap if needed

5. **Incomplete results**
   - Check for failed chunks in detailed report
   - Review skipped files list
   - Retry with --verbose flag

## 11. Future Enhancements

Potential improvements for future versions:

1. **Distributed Scanning**
   - Support for multiple machines
   - Network-based chunk distribution
   - Centralized result collection

2. **Database Integration**
   - Store results in PostgreSQL/SQLite
   - Historical scan comparisons
   - Trend analysis

3. **Real-time Monitoring**
   - Web dashboard for progress
   - Slack/email notifications
   - Grafana/Prometheus metrics

4. **Machine Learning**
   - Predict problematic files
   - Optimize chunk sizes automatically
   - Estimate scan times accurately

5. **Cloud Integration**
   - S3 bucket scanning
   - Azure Blob storage support
   - Google Cloud Storage scanning

## 12. License and Contributing

```
MIT License

Copyright (c) 2025 ClamScan Splitter Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
...
```

---

This specification provides a complete blueprint for implementing the ClamAV scan splitter. Each section includes detailed implementation notes, code structure, and examples that a junior engineer can follow to build the system successfully.