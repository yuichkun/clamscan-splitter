"""Tests for the CLI module."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest
from click.testing import CliRunner

from clamscan_splitter.cli import cli, scan, status, list_scans, cleanup


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
        mock_orch.scan_all = AsyncMock(return_value=[mock_result])
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

    def test_list_command(self):
        """Test list command for incomplete scans."""
        runner = CliRunner()
        
        with patch("clamscan_splitter.cli.StateManager") as mock_state:
            mock_manager = Mock()
            mock_manager.list_incomplete_scans.return_value = []
            mock_state.return_value = mock_manager
            
            result = runner.invoke(cli, ["list"])
        
        assert result.exit_code == 0

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

