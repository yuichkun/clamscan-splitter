"""Tests for the parser module."""

import pytest

from clamscan_splitter.parser import (
    ClamAVOutputParser,
    InfectedFile,
    ParseError,
    ScanResult,
)
from tests.fixtures.mock_outputs import (
    CLEAN_SCAN_OUTPUT,
    ERROR_SCAN_OUTPUT,
    INFECTED_SCAN_OUTPUT,
    LARGE_SCAN_OUTPUT,
    MALFORMED_SCAN_OUTPUT,
    MIXED_SCAN_OUTPUT,
    NO_SUMMARY_OUTPUT,
    PARTIAL_SCAN_OUTPUT,
)


class TestClamAVOutputParser:
    """Test ClamAVOutputParser class."""

    def test_parse_clean_output(self):
        """Test parsing clean scan output (no infections)."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(CLEAN_SCAN_OUTPUT, "", 0)
        
        assert result.status == "success"
        assert len(result.infected_files) == 0
        assert result.scanned_files == 2
        assert result.scanned_directories == 2
        assert result.total_errors == 0
        assert result.infected_files == []
        assert result.engine_version == "1.4.3"
        assert result.data_scanned_mb == 0.50
        assert result.data_read_mb == 0.50

    def test_parse_infected_output(self):
        """Test parsing infected scan output."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(INFECTED_SCAN_OUTPUT, "", 1)
        
        assert result.status == "success"
        assert len(result.infected_files) == 2
        assert result.scanned_files == 3
        assert result.total_infected_files == 2
        
        # Check first infected file
        assert result.infected_files[0].file_path == "/home/user/virus.exe"
        assert result.infected_files[0].virus_name == "Win.Trojan.Generic"
        assert result.infected_files[0].action_taken == "FOUND"
        
        # Check second infected file
        assert result.infected_files[1].file_path == "/home/user/malware.dll"
        assert result.infected_files[1].virus_name == "Linux.Malware.Agent"
        assert result.infected_files[1].action_taken == "FOUND"

    def test_parse_error_output(self):
        """Test parsing error scan output."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(ERROR_SCAN_OUTPUT, "Permission denied", 2)
        
        assert result.status == "success"  # Still success, but with errors
        assert result.total_errors == 2
        assert result.scanned_files == 2
        assert len(result.infected_files) == 0

    def test_parse_mixed_output(self):
        """Test parsing mixed output (infections + errors)."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(MIXED_SCAN_OUTPUT, "", 1)
        
        assert result.status == "success"
        assert len(result.infected_files) == 2
        assert result.total_errors == 1
        assert result.scanned_files == 3

    def test_parse_large_output(self):
        """Test parsing large scan output (1.4M files)."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(LARGE_SCAN_OUTPUT, "", 0)
        
        assert result.status == "success"
        assert result.scanned_files == 1394942
        assert result.scanned_directories == 159931
        assert result.total_errors == 3
        assert result.data_scanned_mb == 92772.46
        assert result.data_read_mb == 159697.51

    def test_parse_partial_output(self):
        """Test parsing partial output (no summary)."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(PARTIAL_SCAN_OUTPUT, "", 130)
        
        # Partial output should still parse, but with limited info
        assert result.status == "partial"
        assert result.scanned_files == 3
        assert result.raw_output == PARTIAL_SCAN_OUTPUT

    def test_parse_no_summary_output(self):
        """Test parsing output with no summary section."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(NO_SUMMARY_OUTPUT, "", 0)
        
        assert result.status == "success"
        assert result.scanned_files == 4
        assert result.raw_output == NO_SUMMARY_OUTPUT

    def test_parse_malformed_output(self):
        """Test parsing malformed output."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(MALFORMED_SCAN_OUTPUT, "", 0)
        
        # Should handle gracefully
        assert result.status in ["partial", "success"]
        assert result.raw_output == MALFORMED_SCAN_OUTPUT

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        parser = ClamAVOutputParser()
        result = parser.parse_output("", "", 0)
        
        assert result.status == "partial"
        assert result.scanned_files == 0
        assert result.raw_output == ""

    def test_parse_with_stderr(self):
        """Test parsing with stderr output."""
        parser = ClamAVOutputParser()
        stderr = "WARNING: Some warning message"
        result = parser.parse_output(CLEAN_SCAN_OUTPUT, stderr, 0)
        
        assert result.status == "success"
        assert stderr in result.raw_output or result.error_message is None

    def test_parse_scan_time(self):
        """Test parsing scan time correctly."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(CLEAN_SCAN_OUTPUT, "", 0)
        
        assert result.scan_time_seconds == 1.234

    def test_parse_engine_version(self):
        """Test parsing engine version."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(CLEAN_SCAN_OUTPUT, "", 0)
        
        assert result.engine_version == "1.4.3"

    def test_parse_data_ratio(self):
        """Test parsing data read/scanned ratio."""
        parser = ClamAVOutputParser()
        result = parser.parse_output(LARGE_SCAN_OUTPUT, "", 0)
        
        # Ratio should be approximately 0.58:1
        assert result.data_read_mb > result.data_scanned_mb
        assert result.data_read_mb == 159697.51
        assert result.data_scanned_mb == 92772.46

    def test_infected_file_dataclass(self):
        """Test InfectedFile dataclass."""
        infected = InfectedFile(
            file_path="/path/to/virus.exe",
            virus_name="Test.Virus",
            action_taken="FOUND"
        )
        
        assert infected.file_path == "/path/to/virus.exe"
        assert infected.virus_name == "Test.Virus"
        assert infected.action_taken == "FOUND"

    def test_scan_result_dataclass(self):
        """Test ScanResult dataclass."""
        result = ScanResult(
            chunk_id="test-chunk-1",
            status="success",
            infected_files=[],
            scanned_files=100,
            scanned_directories=10,
            total_errors=0,
            data_scanned_mb=50.0,
            data_read_mb=50.0,
            scan_time_seconds=10.5,
            engine_version="1.4.3",
            raw_output="test output",
            error_message=None,
        )
        
        assert result.chunk_id == "test-chunk-1"
        assert result.status == "success"
        assert result.scanned_files == 100
        assert result.total_infected_files == 0

    def test_parse_infected_files_with_colons_in_path(self):
        """Test parsing infected files when path contains colons."""
        output = """/path:with:colons/file.txt: Win.Virus FOUND
----------- SCAN SUMMARY -----------
Scanned files: 1
Infected files: 1
"""
        parser = ClamAVOutputParser()
        result = parser.parse_output(output, "", 1)
        
        assert len(result.infected_files) == 1
        # Should handle paths with colons correctly
        assert ":" in result.infected_files[0].file_path or result.infected_files[0].file_path == "/path:with:colons/file.txt"

    def test_parse_summary_with_variations(self):
        """Test parsing summary with format variations."""
        output = """----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 5
Scanned files: 10
Infected files: 0
Total errors: 0
Data scanned: 5.25 MB
Data read: 5.25 MB (ratio 1.00:1)
Time: 10.5 sec (0 m 10 s)
"""
        parser = ClamAVOutputParser()
        result = parser.parse_output(output, "", 0)
        
        assert result.scanned_files == 10
        assert result.scanned_directories == 5
        assert result.data_scanned_mb == 5.25
        assert result.scan_time_seconds == 10.5

    def test_parse_with_whitespace(self):
        """Test parsing output with extra whitespace."""
        output = """
/home/user/file1.txt: OK

/home/user/file2.txt: OK

----------- SCAN SUMMARY -----------
Scanned files: 2
Infected files: 0
"""
        parser = ClamAVOutputParser()
        result = parser.parse_output(output, "", 0)
        
        assert result.scanned_files == 2
        assert len(result.infected_files) == 0

