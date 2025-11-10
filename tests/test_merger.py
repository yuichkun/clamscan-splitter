"""Tests for the merger module."""

from datetime import datetime

import pytest

from clamscan_splitter.merger import MergedReport, QuarantineEntry, ResultMerger
from clamscan_splitter.parser import InfectedFile, ScanResult


class TestMergedReport:
    """Test MergedReport dataclass."""

    def test_merged_report_creation(self):
        """Test creating a MergedReport."""
        report = MergedReport(
            total_scanned_files=1000,
            total_scanned_directories=100,
            total_infected_files=5,
            infected_file_paths=["/path1", "/path2"],
            total_errors=2,
            total_data_scanned_mb=500.0,
            total_data_read_mb=500.0,
            total_time_seconds=100.0,
            wall_clock_time_seconds=50.0,
            engine_version="1.4.3",
            chunks_successful=10,
            chunks_failed=1,
            chunks_partial=0,
            skipped_paths=[],
            quarantined_files=[],
            scan_date=datetime.now(),
            scan_complete=True,
        )
        
        assert report.total_scanned_files == 1000
        assert report.total_infected_files == 5
        assert report.scan_complete is True


class TestQuarantineEntry:
    """Test QuarantineEntry dataclass."""

    def test_quarantine_entry_creation(self):
        """Test creating a QuarantineEntry."""
        entry = QuarantineEntry(
            file_path="/test/file.txt",
            reason="timeout",
            file_size_bytes=1024,
            retry_count=3,
            last_attempt=datetime.now(),
        )
        
        assert entry.file_path == "/test/file.txt"
        assert entry.reason == "timeout"
        assert entry.retry_count == 3


class TestResultMerger:
    """Test ResultMerger class."""

    def test_merge_results_simple(self):
        """Test merging simple results."""
        merger = ResultMerger()
        
        results = [
            ScanResult(
                chunk_id="chunk-1",
                status="success",
                infected_files=[],
                scanned_files=100,
                scanned_directories=10,
                total_errors=0,
                data_scanned_mb=50.0,
                data_read_mb=50.0,
                scan_time_seconds=10.0,
                engine_version="1.4.3",
                raw_output="",
            ),
            ScanResult(
                chunk_id="chunk-2",
                status="success",
                infected_files=[],
                scanned_files=200,
                scanned_directories=20,
                total_errors=0,
                data_scanned_mb=100.0,
                data_read_mb=100.0,
                scan_time_seconds=20.0,
                engine_version="1.4.3",
                raw_output="",
            ),
        ]
        
        report = merger.merge_results(results)
        
        assert report.total_scanned_files == 300
        assert report.total_scanned_directories == 30
        assert report.total_data_scanned_mb == 150.0
        assert report.chunks_successful == 2

    def test_merge_results_with_infections(self):
        """Test merging results with infected files."""
        merger = ResultMerger()
        
        results = [
            ScanResult(
                chunk_id="chunk-1",
                status="success",
                infected_files=[
                    InfectedFile("/path/virus1.exe", "Win.Trojan.Generic"),
                    InfectedFile("/path/virus2.exe", "Linux.Malware.Agent"),
                ],
                scanned_files=100,
                scanned_directories=10,
                total_errors=0,
                data_scanned_mb=50.0,
                data_read_mb=50.0,
                scan_time_seconds=10.0,
                engine_version="1.4.3",
                raw_output="",
            ),
            ScanResult(
                chunk_id="chunk-2",
                status="success",
                infected_files=[
                    InfectedFile("/path/virus1.exe", "Win.Trojan.Generic"),  # Duplicate
                    InfectedFile("/path/virus3.exe", "Mac.Trojan.Generic"),
                ],
                scanned_files=200,
                scanned_directories=20,
                total_errors=0,
                data_scanned_mb=100.0,
                data_read_mb=100.0,
                scan_time_seconds=20.0,
                engine_version="1.4.3",
                raw_output="",
            ),
        ]
        
        report = merger.merge_results(results)
        
        assert report.total_infected_files == 3  # Should deduplicate
        assert len(report.infected_file_paths) == 3
        assert "/path/virus1.exe" in report.infected_file_paths
        assert "/path/virus2.exe" in report.infected_file_paths
        assert "/path/virus3.exe" in report.infected_file_paths

    def test_merge_results_with_errors(self):
        """Test merging results with errors."""
        merger = ResultMerger()
        
        results = [
            ScanResult(
                chunk_id="chunk-1",
                status="success",
                infected_files=[],
                scanned_files=100,
                scanned_directories=10,
                total_errors=2,
                data_scanned_mb=50.0,
                data_read_mb=50.0,
                scan_time_seconds=10.0,
                engine_version="1.4.3",
                raw_output="",
            ),
            ScanResult(
                chunk_id="chunk-2",
                status="failed",
                infected_files=[],
                scanned_files=0,
                scanned_directories=0,
                total_errors=1,
                data_scanned_mb=0.0,
                data_read_mb=0.0,
                scan_time_seconds=0.0,
                engine_version="",
                raw_output="",
                error_message="Timeout",
            ),
        ]
        
        report = merger.merge_results(results)
        
        assert report.total_errors == 3
        assert report.chunks_successful == 1
        assert report.chunks_failed == 1

    def test_merge_results_with_quarantine(self):
        """Test merging results with quarantined files."""
        merger = ResultMerger()
        
        results = [
            ScanResult(
                chunk_id="chunk-1",
                status="success",
                infected_files=[],
                scanned_files=100,
                scanned_directories=10,
                total_errors=0,
                data_scanned_mb=50.0,
                data_read_mb=50.0,
                scan_time_seconds=10.0,
                engine_version="1.4.3",
                raw_output="",
            ),
            ScanResult(
                chunk_id="chunk-2",
                status="partial",
                infected_files=[],
                scanned_files=50,
                scanned_directories=5,
                total_errors=5,
                data_scanned_mb=25.0,
                data_read_mb=25.0,
                scan_time_seconds=5.0,
                engine_version="1.4.3",
                raw_output="",
            ),
        ]
        
        report = merger.merge_results(results)
        
        assert report.chunks_partial == 1
        assert report.scan_complete is False  # Has partial results

    def test_deduplicate_infected_files(self):
        """Test deduplication of infected files."""
        merger = ResultMerger()
        
        results = [
            ScanResult(
                chunk_id="chunk-1",
                status="success",
                infected_files=[
                    InfectedFile("/path/file1.exe", "Virus1"),
                    InfectedFile("/path/file2.exe", "Virus2"),
                ],
                scanned_files=2,
                scanned_directories=0,
                total_errors=0,
                data_scanned_mb=1.0,
                data_read_mb=1.0,
                scan_time_seconds=1.0,
                engine_version="1.4.3",
                raw_output="",
            ),
            ScanResult(
                chunk_id="chunk-2",
                status="success",
                infected_files=[
                    InfectedFile("/path/file1.exe", "Virus1"),  # Duplicate
                    InfectedFile("/path/file3.exe", "Virus3"),
                ],
                scanned_files=2,
                scanned_directories=0,
                total_errors=0,
                data_scanned_mb=1.0,
                data_read_mb=1.0,
                scan_time_seconds=1.0,
                engine_version="1.4.3",
                raw_output="",
            ),
        ]
        
        deduplicated = merger._deduplicate_infected_files(results)
        
        assert len(deduplicated) == 3
        assert "/path/file1.exe" in deduplicated
        assert "/path/file2.exe" in deduplicated
        assert "/path/file3.exe" in deduplicated

    def test_format_report(self):
        """Test report formatting."""
        merger = ResultMerger()
        
        report = MergedReport(
            total_scanned_files=1000,
            total_scanned_directories=100,
            total_infected_files=5,
            infected_file_paths=["/path1", "/path2"],
            total_errors=2,
            total_data_scanned_mb=500.0,
            total_data_read_mb=500.0,
            total_time_seconds=100.0,
            wall_clock_time_seconds=50.0,
            engine_version="1.4.3",
            chunks_successful=10,
            chunks_failed=1,
            chunks_partial=0,
            skipped_paths=[],
            quarantined_files=[],
            scan_date=datetime.now(),
            scan_complete=True,
        )
        
        formatted = merger.format_report(report)
        
        assert "SCAN SUMMARY" in formatted
        assert "1000" in formatted  # Total files
        assert "1.4.3" in formatted  # Engine version

    def test_format_report_with_quarantine(self):
        """Test report formatting with quarantine info."""
        merger = ResultMerger()
        
        quarantine_entries = [
            QuarantineEntry(
                file_path="/test/file1.txt",
                reason="timeout",
                file_size_bytes=1024,
                retry_count=3,
                last_attempt=datetime.now(),
            ),
            QuarantineEntry(
                file_path="/test/file2.txt",
                reason="permission",
                file_size_bytes=None,
                retry_count=1,
                last_attempt=datetime.now(),
            ),
        ]
        
        report = MergedReport(
            total_scanned_files=1000,
            total_scanned_directories=100,
            total_infected_files=0,
            infected_file_paths=[],
            total_errors=0,
            total_data_scanned_mb=500.0,
            total_data_read_mb=500.0,
            total_time_seconds=100.0,
            wall_clock_time_seconds=50.0,
            engine_version="1.4.3",
            chunks_successful=10,
            chunks_failed=0,
            chunks_partial=0,
            skipped_paths=[],
            quarantined_files=quarantine_entries,
            scan_date=datetime.now(),
            scan_complete=False,
        )
        
        formatted = merger.format_report(report)
        
        assert "QUARANTINE SUMMARY" in formatted
        assert "2" in formatted  # Quarantine count

    def test_save_detailed_report(self, tmp_path):
        """Test saving detailed JSON report."""
        merger = ResultMerger()
        
        report = MergedReport(
            total_scanned_files=1000,
            total_scanned_directories=100,
            total_infected_files=0,
            infected_file_paths=[],
            total_errors=0,
            total_data_scanned_mb=500.0,
            total_data_read_mb=500.0,
            total_time_seconds=100.0,
            wall_clock_time_seconds=50.0,
            engine_version="1.4.3",
            chunks_successful=10,
            chunks_failed=0,
            chunks_partial=0,
            skipped_paths=[],
            quarantined_files=[],
            scan_date=datetime.now(),
            scan_complete=True,
        )
        
        report_path = tmp_path / "report.json"
        merger.save_detailed_report(report, str(report_path))
        
        assert report_path.exists()
        
        # Verify JSON is valid
        import json
        with open(report_path) as f:
            data = json.load(f)
            assert data["total_scanned_files"] == 1000

