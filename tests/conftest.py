"""Pytest configuration and shared fixtures."""

import asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from pytest_subprocess import FakeProcess

from tests.fixtures.mock_outputs import MOCK_OUTPUTS


@pytest.fixture
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def fake_process() -> FakeProcess:
    """Fixture for mocking subprocess calls."""
    return FakeProcess()


@pytest.fixture
def mock_clamscan_clean(fake_process: FakeProcess) -> FakeProcess:
    """Mock clamscan that returns clean scan output."""
    fake_process.register_subprocess(
        ["clamscan", "-r", "--no-summary"],
        stdout=MOCK_OUTPUTS["clean"],
        stderr="",
        returncode=0,
    )
    return fake_process


@pytest.fixture
def mock_clamscan_infected(fake_process: FakeProcess) -> FakeProcess:
    """Mock clamscan that returns infected scan output."""
    fake_process.register_subprocess(
        ["clamscan", "-r", "--no-summary"],
        stdout=MOCK_OUTPUTS["infected"],
        stderr="",
        returncode=1,  # ClamAV returns 1 when infections found
    )
    return fake_process


@pytest.fixture
def mock_clamscan_error(fake_process: FakeProcess) -> FakeProcess:
    """Mock clamscan that returns error output."""
    fake_process.register_subprocess(
        ["clamscan", "-r", "--no-summary"],
        stdout=MOCK_OUTPUTS["error"],
        stderr="Permission denied",
        returncode=2,
    )
    return fake_process


@pytest.fixture
def mock_clamscan_hanging(fake_process: FakeProcess) -> FakeProcess:
    """Mock clamscan that hangs indefinitely."""
    fake_process.register_subprocess(
        ["clamscan", "-r", "--no-summary"],
        stdout="Scanning...\n",
        wait=float("inf"),  # Never completes
    )
    return fake_process


@pytest.fixture
def mock_clamscan_timeout(fake_process: FakeProcess) -> FakeProcess:
    """Mock clamscan that takes too long (simulates timeout)."""
    fake_process.register_subprocess(
        ["clamscan", "-r", "--no-summary"],
        stdout="Scanning...\n",
        wait=3600,  # Takes 1 hour
    )
    return fake_process


@pytest.fixture
def mock_clamscan_partial(fake_process: FakeProcess) -> FakeProcess:
    """Mock clamscan that returns partial output (interrupted)."""
    fake_process.register_subprocess(
        ["clamscan", "-r", "--no-summary"],
        stdout=MOCK_OUTPUTS["partial"],
        stderr="",
        returncode=130,  # SIGINT
    )
    return fake_process


@pytest.fixture
def mock_psutil_process():
    """Mock psutil.Process for monitoring tests."""
    mock_process = Mock()
    mock_process.pid = 12345
    mock_process.cpu_percent.return_value = 10.0
    mock_process.memory_info.return_value = Mock(rss=100 * 1024 * 1024)  # 100MB
    mock_process.num_threads.return_value = 1
    mock_process.io_counters.return_value = Mock(
        read_count=1000,
        write_count=500,
        read_bytes=1024 * 1024,
        write_bytes=512 * 1024,
    )
    mock_process.create_time.return_value = 1000.0
    mock_process.status.return_value = "running"
    mock_process.children.return_value = []
    
    # Mock process tree killing
    def kill_side_effect():
        mock_process.status.return_value = "terminated"
    
    mock_process.kill.side_effect = kill_side_effect
    mock_process.terminate.side_effect = kill_side_effect
    
    return mock_process


@pytest.fixture
def mock_psutil_low_cpu():
    """Mock psutil.Process with low CPU (simulating hang)."""
    mock_process = Mock()
    mock_process.pid = 12345
    mock_process.cpu_percent.return_value = 2.0  # Low CPU
    mock_process.memory_info.return_value = Mock(rss=100 * 1024 * 1024)
    mock_process.num_threads.return_value = 1
    mock_process.io_counters.return_value = Mock(
        read_count=1000,
        write_count=500,
        read_bytes=1024 * 1024,
        write_bytes=512 * 1024,
    )
    mock_process.create_time.return_value = 1000.0
    mock_process.status.return_value = "sleeping"
    mock_process.children.return_value = []
    return mock_process


@pytest.fixture
def mock_psutil_zombie():
    """Mock psutil.Process in zombie state."""
    mock_process = Mock()
    mock_process.pid = 12345
    mock_process.cpu_percent.return_value = 0.0
    mock_process.memory_info.return_value = Mock(rss=0)
    mock_process.num_threads.return_value = 0
    mock_process.io_counters.return_value = None
    mock_process.create_time.return_value = 1000.0
    mock_process.status.return_value = "zombie"
    mock_process.children.return_value = []
    return mock_process


@pytest.fixture
def mock_virtual_memory():
    """Mock psutil.virtual_memory for resource monitoring."""
    mock_mem = Mock()
    mock_mem.total = 16 * 1024**3  # 16GB
    mock_mem.available = 8 * 1024**3  # 8GB available
    mock_mem.used = 8 * 1024**3  # 8GB used
    mock_mem.percent = 50.0
    return mock_mem


@pytest.fixture
def mock_cpu_count():
    """Mock psutil.cpu_count."""
    return 8


@pytest.fixture
def fs(fs):
    """Pyfakefs filesystem fixture."""
    return fs

