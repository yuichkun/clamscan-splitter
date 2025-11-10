# ClamAV Scan Splitter

A high-performance Python tool for scanning large directories (1M+ files) with ClamAV by intelligently splitting the workload into parallel chunks, handling timeouts, retries, and generating unified reports.

## Features

- **Parallel Processing**: Automatically splits large scans into manageable chunks and runs them concurrently
- **Hang Detection**: Monitors processes for hangs using CPU usage and output activity
- **Intelligent Retry**: Exponential backoff with chunk splitting for failed scans
- **Resumable Scans**: Atomic state persistence allows resuming interrupted scans
- **Memory-Aware**: Automatically calculates optimal worker count based on available memory
- **Comprehensive Reporting**: Merges results from all chunks into a single corporate-formatted report
- **Quarantine System**: Tracks files that couldn't be scanned for manual review

## Installation

### Prerequisites

- Python 3.11 or higher
- ClamAV installed and configured (`clamscan` command available)

### Global Installation (Recommended for CLI Usage)

Install the tool globally so you can use `clamscan-splitter` from anywhere:

```bash
# Clone the repository
git clone <repository-url>
cd clamscan-splitter

# Install globally (no venv needed)
uv pip install --system -e .

# Or using pip directly
pip install -e .

# Verify installation
clamscan-splitter --help
```

**Note**: Using `--system` flag with `uv` or regular `pip install` installs the CLI globally. You may need `sudo` on Linux/macOS if installing to system Python.

### Development Installation (For Contributors)

If you're developing or contributing to the project:

```bash
# Clone the repository
git clone <repository-url>
cd clamscan-splitter

# Create virtual environment for development
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in editable mode
uv pip install -e .

# Install test dependencies
uv pip install -e ".[test]"

# Verify installation
clamscan-splitter --help
```

### Alternative: Install from PyPI (When Available)

```bash
# Once published to PyPI
pip install clamscan-splitter

# Verify installation
clamscan-splitter --help
```

## Quick Start

### Basic Usage

```bash
# Scan a directory recursively (default behavior)
clamscan-splitter scan /path/to/directory

# Dry run to see how it will be chunked
clamscan-splitter scan /path/to/directory --dry-run

# Custom configuration
clamscan-splitter scan /path/to/directory \
    --chunk-size 20 \
    --max-files 50000 \
    --workers 8

# Save report to file
clamscan-splitter scan /path/to/directory -o report.txt

# JSON output
clamscan-splitter scan /path/to/directory --json
```

**Note**: The tool always scans directories recursively (equivalent to `clamscan -r`). It analyzes the entire directory tree and splits it into chunks for parallel processing.

### Resume Interrupted Scan

```bash
# List incomplete scans
clamscan-splitter list

# Resume a scan
clamscan-splitter scan --resume <scan-id>

# Check scan status
clamscan-splitter status <scan-id>
```

## Configuration

### Command-Line Options

```
Options:
  --chunk-size FLOAT      Target chunk size in GB (default: 15.0)
  --max-files INTEGER     Max files per chunk (default: 30000)
  --workers INTEGER       Number of parallel workers (auto-calculated if not specified)
  --timeout-per-gb INTEGER Timeout seconds per GB (default: 30)
  --output, -o PATH       Output report path
  --json                  Output JSON format
  --resume TEXT           Resume scan by ID
  --verbose, -v           Verbose output
  --dry-run               Show chunks without scanning
```

### Configuration File

Create a `config.yaml` file:

```yaml
chunking:
  target_size_gb: 15.0
  max_files_per_chunk: 30000
  isolate_large_files_gb: 1.0

scanning:
  max_concurrent_processes: null  # Auto-calculate
  base_timeout_per_gb: 30
  min_timeout_seconds: 300
  max_timeout_seconds: 3600
  memory_per_process_gb: 2.0
  min_free_memory_gb: 2.0

retry:
  max_attempts: 3
  max_attempts_per_file: 2
  base_delay_seconds: 1.0
  max_delay_seconds: 300.0
  exponential_base: 2.0
```

## Usage Examples

### Example 1: Basic Scan

```bash
clamscan-splitter scan ~/Documents
```

### Example 2: Large Directory with Custom Settings

```bash
clamscan-splitter scan /data \
    --chunk-size 20 \
    --max-files 50000 \
    --workers 16 \
    --timeout-per-gb 60 \
    -o scan_report.txt
```

### Example 3: Dry Run to Preview Chunking

```bash
clamscan-splitter scan /large/directory --dry-run
```

Output:
```
Starting scan: abc12345
Analyzing filesystem: /large/directory
Created 15 chunks

Chunk Summary:
  Chunk 1: 25000 paths, 14.50 GB, 25000 files
  Chunk 2: 25000 paths, 14.30 GB, 25000 files
  ...
```

### Example 4: Resume After Interruption

```bash
# List incomplete scans
clamscan-splitter list

# Output:
# Found 1 incomplete scan(s):
#
#   abc12345
#     Path: /large/directory
#     Progress: 5/15 chunks (33.3%)
#     Started: 2024-01-15 10:30:00

# Resume the scan
clamscan-splitter scan --resume abc12345
```

## How It Works

1. **Chunking**: Analyzes the filesystem and divides it into chunks (10-20GB or 30K files max)
2. **Parallel Scanning**: Runs multiple `clamscan` processes concurrently (memory-aware)
3. **Monitoring**: Detects hung processes using CPU usage and output activity
4. **Retry Logic**: Automatically retries failed chunks with exponential backoff
5. **State Persistence**: Saves scan state atomically for resumability
6. **Result Merging**: Combines all chunk results into a unified report

## Report Format

The tool generates reports in ClamAV-compatible format:

```
----------- SCAN SUMMARY -----------
Engine version: 1.4.3
Scanned directories: 1000
Scanned files: 1000000
Infected files: 5
Total errors: 2
Data scanned: 500.00 MB
Data read: 500.00 MB (ratio 1.00:1)
Time: 3600.000 sec (60 m 0 s)
Start Date: 2024:01:15 10:30:00
End Date:   2024:01:15 11:30:00

----------- QUARANTINE SUMMARY -----------
Files that could not be scanned: 10
Reasons:
  - timeout: 5
  - permission: 3
  - special_file: 2

IMPORTANT: 10 files were not scanned. Manual review required.
Full quarantine list saved to: quarantine_report.json
```

## Exit Codes

- `0`: Scan completed successfully with no infections
- `1`: Infections found (ClamAV convention)
- `2`: Scan incomplete (some files quarantined)
- `130`: Interrupted by user (Ctrl+C)

## Troubleshooting

### Issue: "No files found to scan"

**Solution**: Ensure the path exists and contains files. Check permissions.

### Issue: "Scan exceeded timeout"

**Solution**: Increase timeout settings:
```bash
clamscan-splitter scan /path --timeout-per-gb 60
```

### Issue: "Out of memory"

**Solution**: Reduce worker count or chunk size:
```bash
clamscan-splitter scan /path --workers 4 --chunk-size 10
```

### Issue: "Process appears hung"

**Solution**: The tool automatically detects and kills hung processes. Check logs for problematic files that may need to be excluded.

### Issue: "Permission denied"

**Solution**: Run with appropriate permissions or exclude problematic directories:
```bash
sudo clamscan-splitter scan /path
```

## Development

### Running Tests

```bash
# Run all tests
uv run pytest tests/ -v

# Run with coverage
uv run pytest --cov=src/clamscan_splitter --cov-report=html

# Run specific test file
uv run pytest tests/test_parser.py -v
```

### Project Structure

```
clamscan-splitter/
├── src/
│   └── clamscan_splitter/
│       ├── chunker.py      # Filesystem analysis and chunking
│       ├── scanner.py       # Parallel scan execution
│       ├── parser.py        # ClamAV output parsing
│       ├── merger.py        # Result merging and reporting
│       ├── retry.py         # Retry logic with backoff
│       ├── monitor.py       # Process monitoring
│       ├── state.py         # State persistence
│       ├── cli.py           # Command-line interface
│       └── config.py        # Configuration loading
└── tests/
    ├── test_*.py           # Unit tests
    ├── test_integration.py # Integration tests
    └── fixtures/           # Test fixtures and mocks
```

## Architecture

The tool is designed with modularity and testability in mind:

- **Chunker**: Analyzes filesystem and creates scan chunks
- **Scanner**: Executes scans in parallel with timeout handling
- **Parser**: Parses ClamAV output into structured data
- **Monitor**: Detects hung processes
- **Retry**: Handles failures with intelligent retry logic
- **State**: Persists scan state for resumability
- **Merger**: Combines results into unified reports
- **CLI**: User-friendly command-line interface

## Performance Considerations

- **Memory Usage**: Automatically calculates worker count based on available memory
- **Chunk Size**: Default 15GB chunks balance parallelism and overhead
- **File Limits**: 30K files per chunk prevents process overhead
- **Timeout Calculation**: Based on chunk size (30 seconds per GB)

## Limitations

- Requires ClamAV to be installed and configured
- Large files (>1GB) are isolated into separate chunks
- Special files (FIFOs, sockets) are skipped
- Mount points are not crossed by default

## Contributing

1. Follow TDD: Write tests first
2. Use `uv` for package management
3. Ensure all tests pass before submitting
4. Update documentation for new features

## License

MIT License

## Support

For issues and questions, please open an issue on the project repository.
