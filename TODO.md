# ClamAV Scan Splitter - Implementation TODO

## Implementation Guidelines

**IMPORTANT**: Since you cannot run actual `clamscan` in your environment, follow strict TDD:
1. Write tests FIRST for every component
2. Use mocked clamscan outputs (provided in fixtures)
3. All subprocess calls must be mocked
4. Verify behavior through tests, not manual execution

## Phase 0: Project Setup

### 0.1 Initial Structure
- [ ] Create project structure:
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
- [ ] Create `pyproject.toml` with all dependencies:
  - Core: `click`, `psutil`, `rich`, `pyyaml`, `aiofiles`
  - Testing: `pytest`, `pytest-asyncio`, `pytest-subprocess`, `pyfakefs`, `pytest-cov`
- [ ] Set up Python 3.11+ requirement
- [ ] Configure pytest settings in pyproject.toml

## Phase 1: Test Infrastructure (CRITICAL - Do This First!)

### 1.1 Mock ClamAV Outputs
- [ ] Create `tests/fixtures/mock_outputs.py` with:
  - [ ] Clean scan output (no infections)
  - [ ] Infected scan output (with virus detections)
  - [ ] Partial scan output (interrupted)
  - [ ] Error scan output (permission denied, etc.)
  - [ ] Various SCAN SUMMARY formats

  **Guidance**: Use the exact format from SPECIFICATION.md section 3.4

### 1.2 Filesystem Mocking
- [ ] Create `tests/fixtures/mock_filesystem.py`:
  - [ ] Function to create fake directory structures
  - [ ] Function to create files with specific sizes
  - [ ] Function to create special files (FIFOs, sockets)
  - [ ] Function to create deeply nested directories

  **Guidance**: Use `pyfakefs` for filesystem mocking

### 1.3 Subprocess Mocking
- [ ] Create `tests/conftest.py` with pytest fixtures:
  - [ ] `mock_clamscan` fixture that returns different outputs
  - [ ] `mock_hanging_process` fixture that simulates hangs
  - [ ] `mock_psutil` fixture for process monitoring

  **Guidance**: Use `pytest-subprocess` for subprocess mocking

## Phase 2: Core Modules (Test-First Implementation)

### 2.1 Parser Module (Start Here - Simplest)
- [ ] Write `tests/test_parser.py`:
  - [ ] Test parsing clean output
  - [ ] Test parsing infected output
  - [ ] Test parsing malformed output
  - [ ] Test extracting statistics
  - [ ] Test error handling

- [ ] Implement `src/clamscan_splitter/parser.py`:
  - [ ] `ScanResult` dataclass
  - [ ] `InfectedFile` dataclass
  - [ ] `ClamAVOutputParser.parse_output()` method
  - [ ] Regex patterns for all fields

  **Acceptance**: All parser tests pass with 100% coverage

### 2.2 Chunker Module
- [ ] Write `tests/test_chunker.py`:
  - [ ] Test chunk size limits (10-20GB)
  - [ ] Test file count limits (30K files)
  - [ ] Test directory boundary respect
  - [ ] Test large file isolation
  - [ ] Test special file filtering
  - [ ] Test mount point detection

- [ ] Implement `src/clamscan_splitter/chunker.py`:
  - [ ] `ScanChunk` dataclass
  - [ ] `FileSystemAnalyzer.analyze_directory()`
  - [ ] `FileSystemAnalyzer.identify_problematic_files()`
  - [ ] `ChunkCreator.create_chunks()`

  **Acceptance**: Chunks never exceed limits, special files filtered

### 2.3 Monitor Module
- [ ] Write `tests/test_monitor.py`:
  - [ ] Test CPU monitoring (mock psutil)
  - [ ] Test hang detection logic
  - [ ] Test process killing (mock process tree)
  - [ ] Test memory monitoring

- [ ] Implement `src/clamscan_splitter/monitor.py`:
  - [ ] `ProcessMonitor` class
  - [ ] `HangDetector.is_process_hung()`
  - [ ] Memory-aware worker calculation
  - [ ] Process tree killing

  **Acceptance**: Correctly identifies hung processes without false positives

### 2.4 Retry Module
- [ ] Write `tests/test_retry.py`:
  - [ ] Test exponential backoff timing
  - [ ] Test retry limit enforcement
  - [ ] Test chunk splitting on retry
  - [ ] Test quarantine list management
  - [ ] Test per-file retry tracking

- [ ] Implement `src/clamscan_splitter/retry.py`:
  - [ ] `RetryManager` class
  - [ ] `scan_with_retry()` with bounded attempts
  - [ ] Quarantine list management
  - [ ] Exponential backoff calculation

  **Acceptance**: No infinite loops, quarantine works correctly

### 2.5 State Module
- [ ] Write `tests/test_state.py`:
  - [ ] Test atomic write operations
  - [ ] Test state loading/saving
  - [ ] Test corruption recovery
  - [ ] Test concurrent access (file locking)

- [ ] Implement `src/clamscan_splitter/state.py`:
  - [ ] `ScanState` dataclass
  - [ ] `StateManager.save_state()` with atomic writes
  - [ ] `StateManager.load_state()` with validation
  - [ ] Progress tracking

  **Acceptance**: State survives process crashes, no corruption

### 2.6 Scanner Module
- [ ] Write `tests/test_scanner.py`:
  - [ ] Test subprocess execution (mocked)
  - [ ] Test timeout enforcement
  - [ ] Test parallel execution
  - [ ] Test memory-based worker limits

- [ ] Implement `src/clamscan_splitter/scanner.py`:
  - [ ] `ScanWorker.scan_chunk()`
  - [ ] `ScanOrchestrator` with memory-aware workers
  - [ ] Subprocess management with asyncio
  - [ ] Integration with monitor and retry

  **Acceptance**: Respects memory limits, handles timeouts correctly

### 2.7 Merger Module
- [ ] Write `tests/test_merger.py`:
  - [ ] Test result deduplication
  - [ ] Test statistics aggregation
  - [ ] Test quarantine reporting
  - [ ] Test report formatting

- [ ] Implement `src/clamscan_splitter/merger.py`:
  - [ ] `MergedReport` dataclass with quarantine info
  - [ ] `ResultMerger.merge_results()`
  - [ ] Report formatting with quarantine summary
  - [ ] JSON detailed report

  **Acceptance**: Accurate merging, clear quarantine reporting

## Phase 3: Integration

### 3.1 End-to-End Tests
- [ ] Write `tests/test_integration.py`:
  - [ ] Test complete scan workflow (mocked)
  - [ ] Test resume after interruption
  - [ ] Test handling of mixed success/failure
  - [ ] Test quarantine workflow

  **Guidance**: Use all mocks together to simulate full scan

### 3.2 CLI Module
- [ ] Write `tests/test_cli.py`:
  - [ ] Test all CLI commands
  - [ ] Test parameter validation
  - [ ] Test output formatting

- [ ] Implement `src/clamscan_splitter/cli.py`:
  - [ ] `scan` command with all options
  - [ ] `list` command for incomplete scans
  - [ ] `status` command for scan progress
  - [ ] Progress display with Rich

  **Acceptance**: CLI works with all options, clear output

## Phase 4: Configuration

### 4.1 Configuration Loading
- [ ] Create default `config.yml` template
- [ ] Add configuration loading to CLI
- [ ] Add environment variable overrides
- [ ] Test configuration validation

## Phase 5: Documentation

### 5.1 Code Documentation
- [ ] Add docstrings to all classes and methods
- [ ] Add type hints everywhere
- [ ] Add inline comments for complex logic

### 5.2 User Documentation
- [ ] Create README.md with:
  - [ ] Installation instructions
  - [ ] Basic usage examples
  - [ ] Configuration guide
  - [ ] Troubleshooting section

## Phase 6: Final Validation

### 6.1 Test Coverage
- [ ] Achieve >90% test coverage
- [ ] Add missing edge case tests
- [ ] Verify all error paths tested

### 6.2 Mock Validation
- [ ] Create test that simulates 1.4M files (using mocks)
- [ ] Verify memory usage stays within limits
- [ ] Verify quarantine system works at scale
- [ ] Verify atomic writes prevent corruption

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