# ClamAV Scan Splitter - Implementation TODO

## Implementation Guidelines

**IMPORTANT**: Since you cannot run actual `clamscan` in your environment, follow strict TDD:
1. Write tests FIRST for every component
2. Use mocked clamscan outputs (provided in fixtures)
3. All subprocess calls must be mocked
4. Verify behavior through tests, not manual execution

## Phase 0: Project Setup

### 0.1 Initial Structure
- [x] Create project structure:
  ```
  clamscan-splitter/
  ├── pyproject.toml
  ├── src/
  │   └── clamscan_splitter/
  │       ├── __init__.py
  │       ├── chunker.py
  │       ├── scanner.py
  │       ├── parser.py
  │       ├── merger.py
  │       ├── retry.py
  │       ├── monitor.py
  │       ├── state.py
  │       └── cli.py
  └── tests/
      ├── __init__.py
      ├── conftest.py
      └── fixtures/
          └── mock_outputs.py
  ```

### 0.2 Dependencies
- [x] Create `pyproject.toml` with all dependencies:
  - Core: `click`, `psutil`, `rich`, `pyyaml`, `aiofiles`
  - Testing: `pytest`, `pytest-asyncio`, `pytest-subprocess`, `pyfakefs`, `pytest-cov`
- [x] Set up Python 3.11+ requirement
- [x] Configure pytest settings in pyproject.toml

## Phase 1: Test Infrastructure (CRITICAL - Do This First!)

### 1.1 Mock ClamAV Outputs
- [x] Create `tests/fixtures/mock_outputs.py` with:
  - [x] Clean scan output (no infections)
  - [x] Infected scan output (with virus detections)
  - [x] Partial scan output (interrupted)
  - [x] Error scan output (permission denied, etc.)
  - [x] Various SCAN SUMMARY formats

  **Guidance**: Use the exact format from SPECIFICATION.md section 3.4

### 1.2 Filesystem Mocking
- [x] Create `tests/fixtures/mock_filesystem.py`:
  - [x] Function to create fake directory structures
  - [x] Function to create files with specific sizes
  - [x] Function to create special files (FIFOs, sockets)
  - [x] Function to create deeply nested directories

  **Guidance**: Use `pyfakefs` for filesystem mocking

### 1.3 Subprocess Mocking
- [x] Create `tests/conftest.py` with pytest fixtures:
  - [x] `mock_clamscan` fixture that returns different outputs
  - [x] `mock_hanging_process` fixture that simulates hangs
  - [x] `mock_psutil` fixture for process monitoring

  **Guidance**: Use `pytest-subprocess` for subprocess mocking

## Phase 2: Core Modules (Test-First Implementation)

### 2.1 Parser Module (Start Here - Simplest)
- [x] Write `tests/test_parser.py`:
  - [x] Test parsing clean output
  - [x] Test parsing infected output
  - [x] Test parsing malformed output
  - [x] Test extracting statistics
  - [x] Test error handling

- [x] Implement `src/clamscan_splitter/parser.py`:
  - [x] `ScanResult` dataclass
  - [x] `InfectedFile` dataclass
  - [x] `ClamAVOutputParser.parse_output()` method
  - [x] Regex patterns for all fields

  **Acceptance**: All parser tests pass with 100% coverage

### 2.2 Chunker Module
- [x] Write `tests/test_chunker.py`:
  - [x] Test chunk size limits (10-20GB)
  - [x] Test file count limits (30K files)
  - [x] Test directory boundary respect
  - [x] Test large file isolation
  - [x] Test special file filtering
  - [x] Test mount point detection

- [x] Implement `src/clamscan_splitter/chunker.py`:
  - [x] `ScanChunk` dataclass
  - [x] `FileSystemAnalyzer.analyze_directory()`
  - [x] `FileSystemAnalyzer.identify_problematic_files()`
  - [x] `ChunkCreator.create_chunks()`

  **Acceptance**: Chunks never exceed limits, special files filtered

### 2.3 Monitor Module
- [x] Write `tests/test_monitor.py`:
  - [x] Test CPU monitoring (mock psutil)
  - [x] Test hang detection logic
  - [x] Test process killing (mock process tree)
  - [x] Test memory monitoring

- [x] Implement `src/clamscan_splitter/monitor.py`:
  - [x] `ProcessMonitor` class
  - [x] `HangDetector.is_process_hung()`
  - [x] Memory-aware worker calculation
  - [x] Process tree killing

  **Acceptance**: Correctly identifies hung processes without false positives

### 2.4 Retry Module
- [x] Write `tests/test_retry.py`:
  - [x] Test exponential backoff timing
  - [x] Test retry limit enforcement
  - [x] Test chunk splitting on retry
  - [x] Test quarantine list management
  - [x] Test per-file retry tracking

- [x] Implement `src/clamscan_splitter/retry.py`:
  - [x] `RetryManager` class
  - [x] `scan_with_retry()` with bounded attempts
  - [x] Quarantine list management
  - [x] Exponential backoff calculation

  **Acceptance**: No infinite loops, quarantine works correctly

### 2.5 State Module
- [x] Write `tests/test_state.py`:
  - [x] Test atomic write operations
  - [x] Test state loading/saving
  - [x] Test corruption recovery
  - [x] Test concurrent access (file locking)

- [x] Implement `src/clamscan_splitter/state.py`:
  - [x] `ScanState` dataclass
  - [x] `StateManager.save_state()` with atomic writes
  - [x] `StateManager.load_state()` with validation
  - [x] Progress tracking

  **Acceptance**: State survives process crashes, no corruption

### 2.6 Scanner Module
- [x] Write `tests/test_scanner.py`:
  - [x] Test subprocess execution (mocked)
  - [x] Test timeout enforcement
  - [x] Test parallel execution
  - [x] Test memory-based worker limits

- [x] Implement `src/clamscan_splitter/scanner.py`:
  - [x] `ScanWorker.scan_chunk()`
  - [x] `ScanOrchestrator` with memory-aware workers
  - [x] Subprocess management with asyncio
  - [x] Integration with monitor and retry

  **Acceptance**: Respects memory limits, handles timeouts correctly

### 2.7 Merger Module
- [x] Write `tests/test_merger.py`:
  - [x] Test result deduplication
  - [x] Test statistics aggregation
  - [x] Test quarantine reporting
  - [x] Test report formatting

- [x] Implement `src/clamscan_splitter/merger.py`:
  - [x] `MergedReport` dataclass with quarantine info
  - [x] `ResultMerger.merge_results()`
  - [x] Report formatting with quarantine summary
  - [x] JSON detailed report

  **Acceptance**: Accurate merging, clear quarantine reporting

## Phase 3: Integration

### 3.1 End-to-End Tests
- [x] Write `tests/test_integration.py`:
  - [x] Test complete scan workflow (mocked)
  - [x] Test resume after interruption
  - [x] Test handling of mixed success/failure
  - [x] Test quarantine workflow

  **Guidance**: Use all mocks together to simulate full scan

### 3.2 CLI Module
- [x] Write `tests/test_cli.py`:
  - [x] Test all CLI commands
  - [x] Test parameter validation
  - [x] Test output formatting

- [x] Implement `src/clamscan_splitter/cli.py`:
  - [x] `scan` command with all options
  - [x] `list` command for incomplete scans
  - [x] `status` command for scan progress
  - [x] Progress display with Rich

  **Acceptance**: CLI works with all options, clear output

## Phase 4: Configuration

### 4.1 Configuration Loading
- [x] Create default `config.yml` template
- [x] Add configuration loading to CLI
- [x] Add environment variable overrides
- [x] Test configuration validation

## Phase 5: Documentation

### 5.1 Code Documentation
- [x] Add docstrings to all classes and methods
- [x] Add type hints everywhere
- [x] Add inline comments for complex logic

### 5.2 User Documentation
- [x] Create README.md with:
  - [x] Installation instructions
  - [x] Basic usage examples
  - [x] Configuration guide
  - [x] Troubleshooting section

## Phase 6: Final Validation

### 6.1 Test Coverage
- [x] Achieve >90% test coverage
- [x] Add missing edge case tests
- [x] Verify all error paths tested

### 6.2 Mock Validation
- [x] Create test that simulates 1.4M files (using mocks)
- [x] Verify memory usage stays within limits
- [x] Verify quarantine system works at scale
- [x] Verify atomic writes prevent corruption

## Testing Commands to Run

```bash
# After each module implementation:
pytest tests/test_<module>.py -v --cov=src/clamscan_splitter/<module>

# For integration tests:
pytest tests/test_integration.py -v

# Final validation:
pytest --cov=src/clamscan_splitter --cov-report=html --cov-report=term

# Check type hints (if using mypy):
mypy src/clamscan_splitter
```

## Critical Success Criteria

1. **All tests pass** - No implementation without passing tests
2. **No actual clamscan calls** - Everything mocked
3. **Memory safety** - Worker calculation prevents OOM
4. **No infinite loops** - Retry limits enforced
5. **Atomic operations** - State corruption impossible
6. **Complete reporting** - No silent failures

## Notes for Implementation

- **Start with tests**: Write failing tests first, then implement
- **Use provided mocks**: Don't try to run actual clamscan
- **Check memory math**: Verify worker calculation logic
- **Test error paths**: Every exception should be tested
- **Validate atomicity**: State writes must be atomic

Remember: Since you can't run actual ClamAV, the tests ARE your validation. Make them comprehensive!

## Phase 7: Spec Compliance Fixes

### 7.1 Resume Flow Parity with Spec §3.7 / §3.8
- [x] When resuming, skip chunks whose IDs are already in `completed_chunks` instead of re-scanning everything.
- [x] Seed `ProgressTracker`/`ScanUI` with counts from `completed_chunks` and `failed_chunks` so the progress bar reflects true resume state.

### 7.2 Hang Detection Integration (Spec §1.3 Key Requirement & §3.5)
- [x] Wire `HangDetector`/`ResourceMonitor` into `ScanWorker` so long-running `clamscan` processes are monitored and terminated when CPU/output stalls.
- [x] Use `ResourceMonitor.should_reduce_concurrency()` to dynamically back off worker count when the system is overloaded, per configuration.

### 7.3 Configuration Loader Usage (Spec §6.1–§6.2)
- [x] Load defaults via `ConfigLoader` in the CLI, merge with `CLAMSCAN_SPLITTER_CONFIG` file (env override) and CLI flags.
- [x] Support documented environment overrides (`CLAMSCAN_SPLITTER_WORKERS`, `CLAMSCAN_SPLITTER_CHUNK_SIZE`, etc.) so users can control behavior without flags.

### 7.4 Quarantine Reporting (Spec §3.6 & §3.3 Summary Format)
- [x] Plumb `RetryManager.quarantine_list` into `ResultMerger` so quarantined paths populate `MergedReport.quarantined_files`.
- [x] Actually emit the `quarantine_report.json` file referenced in `format_report` whenever quarantined files exist.

### 7.5 Circuit Breaker Usage (Spec §3.4)
- [ ] Integrate the `CircuitBreaker` with the retry/orchestrator pipeline so paths that repeatedly fail are skipped/quarantined according to the spec.
