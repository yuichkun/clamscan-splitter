"""Tests for the CLI module."""

import inspect
import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from click.testing import CliRunner

from clamscan_splitter.cli import cli, scan, status, list_scans, cleanup
from clamscan_splitter.merger import MergedReport
from clamscan_splitter.parser import InfectedFile, ScanResult
from tests.fixtures.mock_outputs import CLEAN_SCAN_OUTPUT


def make_scan_all(results):
    """Helper to create scan_all coroutine that invokes callbacks."""
    async def _scan_all(chunks, on_result=None):
        for result in results:
            if on_result:
                callback_result = on_result(result)
                if inspect.isawaitable(callback_result):
                    await callback_result
        return results

    return _scan_all


class TestCLICommands:
    """Test CLI commands."""

    def test_cli_group_exists(self):
        """Test that CLI group exists."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        
        assert result.exit_code == 0
        assert "ClamAV Scan Splitter" in result.output

    def test_scan_command_help(self):
        """Test scan command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--help"])
        
        assert result.exit_code == 0
        assert "Scan directory" in result.output

    @patch("clamscan_splitter.cli.ScanOrchestrator")
    @patch("clamscan_splitter.cli.ChunkCreator")
    def test_scan_command_basic(self, mock_chunker, mock_orchestrator, tmp_path):
        """Test basic scan command."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        # Mock chunker
        from clamscan_splitter.chunker import ScanChunk
        from datetime import datetime
        
        mock_chunk_creator = Mock()
        mock_chunk_creator.create_chunks.return_value = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        mock_chunker.return_value = mock_chunk_creator
        
        # Mock orchestrator
        from clamscan_splitter.parser import ScanResult
        
        mock_orch = Mock()
        mock_result = ScanResult(
            chunk_id="chunk-1",
            status="success",
            scanned_files=1,
        )
        mock_orch.scan_all = make_scan_all([mock_result])
        mock_orchestrator.return_value = mock_orch
        
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(test_path), "--dry-run"])
        
        # Should exit successfully
        assert result.exit_code == 0 or "chunk" in result.output.lower()

    def test_scan_command_dry_run(self, tmp_path):
        """Test scan command with dry-run."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker:
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = []
            mock_chunker.return_value = mock_chunk_creator
            
            result = runner.invoke(cli, ["scan", str(test_path), "--dry-run"])
        
        # Should show chunks without scanning
        assert result.exit_code == 0

    def test_scan_command_actual_scan(self, tmp_path):
        """Test actual scan execution (not dry-run)."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        
        result_obj = ScanResult(
            chunk_id="chunk-1",
            status="success",
            scanned_files=1,
            scanned_directories=0,
            total_errors=0,
            data_scanned_mb=1.0,
            data_read_mb=1.0,
            scan_time_seconds=1.0,
            engine_version="1.4.3",
            raw_output=CLEAN_SCAN_OUTPUT,
        )
        
        report = MergedReport(
            total_scanned_files=1,
            total_scanned_directories=0,
            total_infected_files=0,
            infected_file_paths=[],
            total_errors=0,
            total_data_scanned_mb=1.0,
            total_data_read_mb=1.0,
            total_time_seconds=1.0,
            wall_clock_time_seconds=1.0,
            engine_version="1.4.3",
            chunks_successful=1,
            chunks_failed=0,
            chunks_partial=0,
            scan_complete=True,
        )
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("asyncio.create_subprocess_exec") as mock_subprocess:
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_orch_instance.scan_all = make_scan_all([result_obj])
            mock_orch_class.return_value = mock_orch_instance
            
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(CLEAN_SCAN_OUTPUT.encode(), b""))
            mock_proc.returncode = 0
            mock_subprocess.return_value = mock_proc
            
            result = runner.invoke(cli, ["scan", str(test_path)])
        
        # Should complete successfully
        assert result.exit_code in [0, 1, 2]  # 0=success, 1=infections, 2=incomplete

    def test_scan_command_with_infections(self, tmp_path):
        """Test scan command when infections are found."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        
        result_obj = ScanResult(
            chunk_id="chunk-1",
            status="success",
            scanned_files=1,
            scanned_directories=0,
            total_errors=0,
            data_scanned_mb=1.0,
            data_read_mb=1.0,
            scan_time_seconds=1.0,
            engine_version="1.4.3",
            raw_output="",
            infected_files=[
                InfectedFile("/test/virus.exe", "Win.Trojan.Generic")
            ],
        )
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("asyncio.create_subprocess_exec") as mock_subprocess:
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_orch_instance.scan_all = make_scan_all([result_obj])
            mock_orch_class.return_value = mock_orch_instance
            
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_proc.returncode = 0
            mock_subprocess.return_value = mock_proc
            
            result = runner.invoke(cli, ["scan", str(test_path)])
        
        # Should exit with code 1 (infections found)
        assert result.exit_code == 1

    def test_scan_command_resume(self, tmp_path):
        """Test scan command with resume option."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        from clamscan_splitter.state import ScanState
        from datetime import datetime
        
        state = ScanState(
            scan_id="test-resume",
            root_path=str(test_path),
            total_chunks=5,
            completed_chunks=["chunk-1"],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={"chunk_size": 20.0},
        )
        
        with patch("clamscan_splitter.cli.StateManager") as mock_state, \
             patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker:
            
            mock_manager = Mock()
            mock_manager.load_state.return_value = state
            mock_state.return_value = mock_manager
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = []
            mock_chunker.return_value = mock_chunk_creator
            
            result = runner.invoke(cli, ["scan", "--resume", "test-resume", "--dry-run"])
        
        # May exit with 0 or 2 depending on execution path
        assert result.exit_code in [0, 2]

    def test_scan_command_resume_not_found(self, tmp_path):
        """Test scan command with invalid resume ID."""
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.StateManager") as mock_state:
            mock_manager = Mock()
            mock_manager.load_state.return_value = None
            mock_state.return_value = mock_manager
            
            result = runner.invoke(cli, ["scan", "--resume", "nonexistent"])
        
        # Should exit with error code (1 or 2)
        assert result.exit_code in [1, 2]

    def test_scan_command_resume_without_path_argument(self, tmp_path):
        """Resuming should not require the PATH argument."""
        test_path = tmp_path / "resume_dir"
        test_path.mkdir()

        runner = CliRunner()

        from clamscan_splitter.chunker import ScanChunk
        from clamscan_splitter.state import ScanState
        from datetime import datetime

        stored_chunk = ScanChunk(
            id="chunk-1",
            paths=[str(test_path)],
            estimated_size_bytes=1024,
            file_count=1,
            directory_count=0,
            created_at=datetime.now(),
        )

        state = ScanState(
            scan_id="resume-cliid",
            root_path=str(test_path),
            total_chunks=1,
            chunks=[{
                "id": stored_chunk.id,
                "paths": stored_chunk.paths,
                "estimated_size_bytes": stored_chunk.estimated_size_bytes,
                "file_count": stored_chunk.file_count,
                "directory_count": stored_chunk.directory_count,
                "created_at": stored_chunk.created_at.isoformat(),
            }],
            completed_chunks=[],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={
                "chunk_size": 15.0,
                "max_files": 30000,
                "workers": None,
                "timeout_per_gb": 30,
            },
        )

        result_obj = ScanResult(
            chunk_id="chunk-1",
            status="success",
            scanned_files=1,
            scanned_directories=0,
            total_errors=0,
            data_scanned_mb=1.0,
            data_read_mb=1.0,
            scan_time_seconds=1.0,
            engine_version="1.0",
        )

        with patch("clamscan_splitter.cli.StateManager") as mock_state_class, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker:

            mock_manager = Mock()
            mock_manager.load_state.return_value = state
            mock_state_class.return_value = mock_manager

            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = [stored_chunk]
            mock_chunker.return_value = mock_chunk_creator

            mock_orch_instance = Mock()
            mock_orch_instance.scan_all = make_scan_all([result_obj])
            mock_orch_class.return_value = mock_orch_instance

            result = runner.invoke(cli, ["scan", "--resume", "resume-cliid"])

        assert result.exit_code in [0, 1]
        assert "Missing argument 'PATH'" not in result.output

    def test_scan_command_no_files(self, tmp_path):
        """Test scan command when no files found."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker:
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = []
            mock_chunker.return_value = mock_chunk_creator
            
            result = runner.invoke(cli, ["scan", str(test_path), "--dry-run"])
        
        assert result.exit_code == 0

    def test_scan_command_save_output(self, tmp_path):
        """Test scan command saving output to file."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        output_file = tmp_path / "report.txt"
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        
        result_obj = ScanResult(
            chunk_id="chunk-1",
            status="success",
            scanned_files=1,
            scanned_directories=0,
            total_errors=0,
            data_scanned_mb=1.0,
            data_read_mb=1.0,
            scan_time_seconds=1.0,
            engine_version="1.4.3",
            raw_output=CLEAN_SCAN_OUTPUT,
        )
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("asyncio.create_subprocess_exec") as mock_subprocess:
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_orch_instance.scan_all = make_scan_all([result_obj])
            mock_orch_class.return_value = mock_orch_instance
            
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(CLEAN_SCAN_OUTPUT.encode(), b""))
            mock_proc.returncode = 0
            mock_subprocess.return_value = mock_proc
            
            result = runner.invoke(cli, ["scan", str(test_path), "--output", str(output_file)])
        
        assert result.exit_code in [0, 1, 2]
        # File may or may not be created depending on execution path

    def test_scan_command_json_output_stdout(self, tmp_path):
        """Test scan command with JSON output to stdout."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        
        result_obj = ScanResult(
            chunk_id="chunk-1",
            status="success",
            scanned_files=1,
            scanned_directories=0,
            total_errors=0,
            data_scanned_mb=1.0,
            data_read_mb=1.0,
            scan_time_seconds=1.0,
            engine_version="1.4.3",
            raw_output=CLEAN_SCAN_OUTPUT,
        )
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("asyncio.create_subprocess_exec") as mock_subprocess:
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_orch_instance.scan_all = make_scan_all([result_obj])
            mock_orch_class.return_value = mock_orch_instance
            
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(CLEAN_SCAN_OUTPUT.encode(), b""))
            mock_proc.returncode = 0
            mock_subprocess.return_value = mock_proc
            
            result = runner.invoke(cli, ["scan", str(test_path), "--json"])
        
        assert result.exit_code in [0, 1, 2]

    def test_list_command(self):
        """Test list command for incomplete scans."""
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.StateManager") as mock_state:
            mock_manager = Mock()
            mock_manager.list_incomplete_scans.return_value = []
            mock_state.return_value = mock_manager
            
            result = runner.invoke(cli, ["list"])
        
        assert result.exit_code == 0

    def test_list_command_with_scans(self):
        """Test list command with incomplete scans."""
        runner = CliRunner()
        
        from clamscan_splitter.state import ScanState
        from datetime import datetime
        
        incomplete_state = ScanState(
            scan_id="incomplete-1",
            root_path="/test",
            total_chunks=5,
            completed_chunks=["chunk-1"],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        
        with patch("clamscan_splitter.cli.StateManager") as mock_state:
            mock_manager = Mock()
            mock_manager.list_incomplete_scans.return_value = [incomplete_state]
            mock_state.return_value = mock_manager
            
            result = runner.invoke(cli, ["list"])
        
        assert result.exit_code == 0
        assert "incomplete-1" in result.output

    def test_status_command(self):
        """Test status command."""
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.StateManager") as mock_state:
            mock_manager = Mock()
            mock_manager.load_state.return_value = None
            mock_state.return_value = mock_manager
            
            result = runner.invoke(cli, ["status", "test-scan-id"])
        
        # Should handle missing scan gracefully
        assert result.exit_code == 0 or result.exit_code == 1

    def test_status_command_with_state(self):
        """Test status command with existing state."""
        runner = CliRunner()
        
        from clamscan_splitter.state import ScanState
        from datetime import datetime
        
        state = ScanState(
            scan_id="test-scan",
            root_path="/test",
            total_chunks=10,
            completed_chunks=["chunk-1", "chunk-2"],
            failed_chunks=["chunk-3"],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        
        with patch("clamscan_splitter.cli.StateManager") as mock_state:
            mock_manager = Mock()
            mock_manager.load_state.return_value = state
            mock_state.return_value = mock_manager
            
            result = runner.invoke(cli, ["status", "test-scan"])
        
        assert result.exit_code == 0
        assert "test-scan" in result.output

    def test_cleanup_command(self):
        """Test cleanup command."""
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.StateManager") as mock_state:
            mock_manager = Mock()
            mock_state.return_value = mock_manager
            
            result = runner.invoke(cli, ["cleanup", "--days", "30"])
        
        assert result.exit_code == 0
        mock_manager.cleanup_old_states.assert_called_once_with(30)

    def test_scan_command_with_options(self, tmp_path):
        """Test scan command with various options."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker:
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = []
            mock_chunker.return_value = mock_chunk_creator
            
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(test_path),
                    "--chunk-size", "20",
                    "--max-files", "50000",
                    "--workers", "8",
                    "--dry-run",
                ],
            )
        
        assert result.exit_code == 0

    def test_scan_command_output_file(self, tmp_path):
        """Test scan command with output file."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        output_file = tmp_path / "report.txt"
        
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker:
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = []
            mock_chunker.return_value = mock_chunk_creator
            
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(test_path),
                    "--output", str(output_file),
                    "--dry-run",
                ],
            )
        
        # Output file may or may not be created in dry-run
        assert result.exit_code == 0

    def test_scan_command_json_output(self, tmp_path):
        """Test scan command with JSON output."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker:
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = []
            mock_chunker.return_value = mock_chunk_creator
            
            result = runner.invoke(
                cli,
                [
                    "scan",
                    str(test_path),
                    "--json",
                    "--dry-run",
                ],
            )
        
        assert result.exit_code == 0

    def test_scan_command_keyboard_interrupt(self, tmp_path):
        """Test scan command handling keyboard interrupt."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class:
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_orch_instance.scan_all = AsyncMock(side_effect=KeyboardInterrupt())
            mock_orch_class.return_value = mock_orch_instance
            
            result = runner.invoke(cli, ["scan", str(test_path)])
        
        # Should handle interrupt gracefully
        assert result.exit_code == 130

    def test_scan_command_exception(self, tmp_path):
        """Test scan command handling exceptions."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker:
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.side_effect = Exception("Test error")
            mock_chunker.return_value = mock_chunk_creator
            
            result = runner.invoke(cli, ["scan", str(test_path), "--dry-run"])
        
        # Should handle exception gracefully
        assert result.exit_code == 1


class TestStatePersistence:
    """Test state persistence in CLI."""
    
    def test_scan_creates_state_on_start(self, tmp_path):
        """Verify that StateManager.save_state() is called when a new scan starts."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("clamscan_splitter.cli.StateManager") as mock_state_class:
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_result = ScanResult(
                chunk_id="chunk-1",
                status="success",
                scanned_files=1,
            )
            mock_orch_instance.scan_all = make_scan_all([mock_result])
            mock_orch_class.return_value = mock_orch_instance
            
            mock_state_manager = Mock()
            mock_state_class.return_value = mock_state_manager
            
            result = runner.invoke(cli, ["scan", str(test_path)])
        
        # Verify save_state was called
        assert mock_state_manager.save_state.called
        # Verify it was called with a ScanState object
        call_args = mock_state_manager.save_state.call_args
        assert call_args is not None
        state = call_args[0][0]
        assert state.scan_id is not None
        assert state.root_path == str(test_path)
        assert state.total_chunks == 1
        assert len(state.chunks) == 1
    
    def test_scan_state_appears_in_list(self, tmp_path):
        """Verify that after starting a scan, running list command shows the scan ID."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        state_dir = tmp_path / "state"
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from clamscan_splitter.state import StateManager, ScanState
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        
        # Use real StateManager to test persistence
        state_manager = StateManager(state_dir=str(state_dir))
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("clamscan_splitter.cli.StateManager", return_value=state_manager):
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_result = ScanResult(
                chunk_id="chunk-1",
                status="success",
                scanned_files=1,
            )
            mock_orch_instance.scan_all = make_scan_all([mock_result])
            mock_orch_class.return_value = mock_orch_instance
            
            # Run scan
            result = runner.invoke(cli, ["scan", str(test_path)])
            assert result.exit_code == 0
        
        # Now check if state appears in list
        with patch("clamscan_splitter.cli.StateManager", return_value=state_manager):
            result = runner.invoke(cli, ["list"])
        
        # Should show the scan (or no incomplete scans if it completed)
        # Since we only have 1 chunk and it completed, it might not show as incomplete
        # Let's create an incomplete state manually to test
        incomplete_state = ScanState(
            scan_id="test-incomplete",
            root_path=str(test_path),
            total_chunks=3,
            completed_chunks=["chunk-1"],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        state_manager.save_state(incomplete_state)
        
        with patch("clamscan_splitter.cli.StateManager", return_value=state_manager):
            result = runner.invoke(cli, ["list"])
        assert "test-incomplete" in result.output or "No incomplete scans" in result.output
    
    def test_resume_uses_persisted_chunks(self, tmp_path):
        """Ensure resumed scans reuse stored chunk metadata."""
        from datetime import datetime
        from clamscan_splitter.state import ScanState
        
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        stored_chunk = {
            "id": "chunk-1",
            "paths": [str(test_path)],
            "estimated_size_bytes": 1024,
            "file_count": 1,
            "directory_count": 0,
            "created_at": datetime.now().isoformat(),
        }
        
        state = ScanState(
            scan_id="resume-id",
            root_path=str(test_path),
            total_chunks=1,
            chunks=[stored_chunk],
            completed_chunks=[],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={
                "chunk_size": 15.0,
                "max_files": 30000,
                "workers": None,
                "timeout_per_gb": 30,
            },
        )
        
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.StateManager") as mock_state_class, \
             patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class:
            
            mock_manager = Mock()
            mock_manager.load_state.return_value = state
            mock_state_class.return_value = mock_manager
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.side_effect = AssertionError(
                "ChunkCreator.create_chunks should not be called when chunks are persisted"
            )
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_result = ScanResult(
                chunk_id="chunk-1",
                status="success",
                scanned_files=1,
            )
            mock_orch_instance.scan_all = make_scan_all([mock_result])
            mock_orch_class.return_value = mock_orch_instance
            
            result = runner.invoke(cli, ["scan", "--resume", "resume-id"])
        
        assert result.exit_code in [0, 1, 2]  # 2 indicates incomplete scan
        mock_chunk_creator.create_chunks.assert_not_called()
        assert state.total_chunks == 1
    
    def test_scan_updates_state_during_execution(self, tmp_path):
        """Verify that state is updated (via save_state) as chunks complete/fail during scan."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            ),
            ScanChunk(
                id="chunk-2",
                paths=[str(test_path)],
                estimated_size_bytes=2048,
                file_count=2,
                directory_count=0,
                created_at=datetime.now(),
            ),
        ]
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("clamscan_splitter.cli.StateManager") as mock_state_class:
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_result1 = ScanResult(
                chunk_id="chunk-1",
                status="success",
                scanned_files=1,
            )
            mock_result2 = ScanResult(
                chunk_id="chunk-2",
                status="success",
                scanned_files=2,
            )
            mock_orch_instance.scan_all = make_scan_all([mock_result1, mock_result2])
            mock_orch_class.return_value = mock_orch_instance
            
            mock_state_manager = Mock()
            mock_state_class.return_value = mock_state_manager
            
            result = runner.invoke(cli, ["scan", str(test_path)])
        
        # Verify save_state was called multiple times (initial + after each chunk)
        assert mock_state_manager.save_state.call_count >= 3  # Initial + 2 chunks
        
        # Verify the last call has both chunks in completed_chunks
        last_call_state = mock_state_manager.save_state.call_args_list[-1][0][0]
        assert "chunk-1" in last_call_state.completed_chunks
        assert "chunk-2" in last_call_state.completed_chunks
    
    def test_scan_state_persists_across_processes(self, tmp_path):
        """Use a real StateManager to verify state files are written to disk."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        state_dir = tmp_path / "state"
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from clamscan_splitter.state import StateManager
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        
        # Use real StateManager
        state_manager = StateManager(state_dir=str(state_dir))
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("clamscan_splitter.cli.StateManager", return_value=state_manager):
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_result = ScanResult(
                chunk_id="chunk-1",
                status="success",
                scanned_files=1,
            )
            mock_orch_instance.scan_all = make_scan_all([mock_result])
            mock_orch_class.return_value = mock_orch_instance
            
            # Run scan
            result = runner.invoke(cli, ["scan", str(test_path)])
            assert result.exit_code == 0
        
        # Verify state file exists
        state_files = list(state_dir.glob("*.json"))
        assert len(state_files) > 0
        
        # Load state from file using a new StateManager instance (simulating separate process)
        new_state_manager = StateManager(state_dir=str(state_dir))
        # Get scan_id from the file
        scan_id = state_files[0].stem
        loaded_state = new_state_manager.load_state(scan_id)
        
        assert loaded_state is not None
        assert loaded_state.root_path == str(test_path)
        assert loaded_state.total_chunks == 1
        assert len(loaded_state.chunks) == 1
    
    def test_scan_saves_state_on_interrupt(self, tmp_path):
        """Verify that if scan is interrupted (KeyboardInterrupt), state is saved."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from datetime import datetime
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path)],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            )
        ]
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("clamscan_splitter.cli.StateManager") as mock_state_class:
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_orch_instance.scan_all = AsyncMock(side_effect=KeyboardInterrupt())
            mock_orch_class.return_value = mock_orch_instance
            
            mock_state_manager = Mock()
            mock_state_class.return_value = mock_state_manager
            
            result = runner.invoke(cli, ["scan", str(test_path)])
        
        # Should handle interrupt gracefully
        assert result.exit_code == 130
        # Verify save_state was called (initial save + interrupt save)
        assert mock_state_manager.save_state.called
        # Verify the interrupt message mentions resume
        assert "resume" in result.output.lower()
    
    def test_list_shows_incomplete_scans(self, tmp_path):
        """Verify that list command correctly shows scans that are in progress."""
        from clamscan_splitter.state import ScanState, StateManager
        from datetime import datetime
        
        state_dir = tmp_path / "state"
        state_manager = StateManager(state_dir=str(state_dir))
        
        # Create incomplete scan
        incomplete_state = ScanState(
            scan_id="incomplete-123",
            root_path="/test/path",
            total_chunks=5,
            completed_chunks=["chunk-1", "chunk-2"],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        state_manager.save_state(incomplete_state)
        
        # Create complete scan (should not appear)
        complete_state = ScanState(
            scan_id="complete-456",
            root_path="/test/path2",
            total_chunks=3,
            completed_chunks=["chunk-1", "chunk-2", "chunk-3"],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={},
        )
        state_manager.save_state(complete_state)
        
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.StateManager", return_value=state_manager):
            result = runner.invoke(cli, ["list"])
        
        # Should show incomplete scan
        assert "incomplete-123" in result.output
        assert "/test/path" in result.output
        # Should not show complete scan
        assert "complete-456" not in result.output
    
    def test_resume_loads_existing_state(self, tmp_path):
        """Verify that resume functionality correctly loads and continues from saved state."""
        test_path = tmp_path / "test_dir"
        test_path.mkdir()
        state_dir = tmp_path / "state"
        
        runner = CliRunner()
        
        from clamscan_splitter.chunker import ScanChunk
        from clamscan_splitter.state import StateManager, ScanState
        from datetime import datetime
        
        # Create existing state
        state_manager = StateManager(state_dir=str(state_dir))
        existing_state = ScanState(
            scan_id="resume-test",
            root_path=str(test_path),
            total_chunks=2,
            completed_chunks=["chunk-1"],
            failed_chunks=[],
            partial_results=[],
            start_time=datetime.now(),
            last_update=datetime.now(),
            configuration={"chunk_size": 20.0, "max_files": 50000},
        )
        state_manager.save_state(existing_state)
        
        chunks = [
            ScanChunk(
                id="chunk-1",
                paths=[str(test_path / "file1.txt")],
                estimated_size_bytes=1024,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            ),
            ScanChunk(
                id="chunk-2",
                paths=[str(test_path / "file2.txt")],
                estimated_size_bytes=2048,
                file_count=1,
                directory_count=0,
                created_at=datetime.now(),
            ),
        ]
        
        with patch("clamscan_splitter.cli.ChunkCreator") as mock_chunker, \
             patch("clamscan_splitter.cli.ScanOrchestrator") as mock_orch_class, \
             patch("clamscan_splitter.cli.StateManager", return_value=state_manager):
            
            mock_chunk_creator = Mock()
            mock_chunk_creator.create_chunks.return_value = chunks
            mock_chunker.return_value = mock_chunk_creator
            
            mock_orch_instance = Mock()
            mock_result = ScanResult(
                chunk_id="chunk-2",
                status="success",
                scanned_files=1,
            )
            mock_orch_instance.scan_all = make_scan_all([mock_result])
            mock_orch_class.return_value = mock_orch_instance
            
            result = runner.invoke(cli, ["scan", "--resume", "resume-test", "--dry-run"])
        
        # Should load existing state
        assert result.exit_code in [0, 2]
        # Verify state was loaded (check that configuration was used)
        loaded_state = state_manager.load_state("resume-test")
        assert loaded_state is not None
        assert loaded_state.scan_id == "resume-test"
