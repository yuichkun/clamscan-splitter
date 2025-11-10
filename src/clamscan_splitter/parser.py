"""Parser module for parsing ClamAV scan output."""

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class InfectedFile:
    """Represents an infected file detection."""
    file_path: str  # Full path to infected file
    virus_name: str  # Name of detected virus/malware
    action_taken: str = "FOUND"  # Usually "FOUND"


@dataclass
class ScanResult:
    """Represents the result of a single scan."""
    chunk_id: str = ""  # ID of the scanned chunk
    status: str = "success"  # "success", "failed", "timeout", "partial"
    infected_files: List[InfectedFile] = field(default_factory=list)
    scanned_files: int = 0
    scanned_directories: int = 0
    total_errors: int = 0
    data_scanned_mb: float = 0.0
    data_read_mb: float = 0.0
    scan_time_seconds: float = 0.0
    engine_version: str = ""
    raw_output: str = ""
    error_message: Optional[str] = None
    
    @property
    def total_infected_files(self) -> int:
        """Return the total number of infected files."""
        return len(self.infected_files)


class ParseError(Exception):
    """Error parsing ClamAV output."""
    pass


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


class ClamAVOutputParser:
    """Parses ClamAV scan output."""

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ScanResult:
        """
        Parse ClamAV output to extract results.

        Args:
            stdout: Standard output from clamscan
            stderr: Standard error from clamscan
            return_code: Process return code

        Returns:
            ScanResult object with parsed data
        """
        raw_output = stdout + ("\n" + stderr if stderr else "")
        lines = stdout.splitlines()
        
        # Determine status based on return code and output
        status = self._determine_status(return_code, stdout)
        
        # Parse infected files from output lines
        infected_files = self._parse_infected_files(lines)
        
        # Parse summary section
        summary_data = self._parse_summary(stdout)
        
        # Create result object
        result = ScanResult(
            status=status,
            infected_files=infected_files,
            scanned_files=summary_data.get('scanned_files', 0),
            scanned_directories=summary_data.get('scanned_directories', 0),
            total_errors=summary_data.get('total_errors', 0),
            data_scanned_mb=summary_data.get('data_scanned_mb', 0.0),
            data_read_mb=summary_data.get('data_read_mb', 0.0),
            scan_time_seconds=summary_data.get('scan_time_seconds', 0.0),
            engine_version=summary_data.get('engine_version', ''),
            raw_output=raw_output,
            error_message=stderr if stderr else None,
        )
        
        return result

    def _determine_status(self, return_code: int, stdout: str) -> str:
        """Determine scan status from return code and output."""
        has_summary = PATTERNS['summary_start'].search(stdout) is not None
        
        if return_code == 0:
            return "success" if has_summary else "partial"
        elif return_code == 1:
            # ClamAV returns 1 when infections are found
            return "success" if has_summary else "partial"
        elif return_code == 130:
            # SIGINT (interrupted)
            return "partial"
        elif return_code == 2:
            # Error
            return "failed" if not has_summary else "success"
        else:
            return "failed" if not has_summary else "partial"

    def _parse_infected_files(self, lines: List[str]) -> List[InfectedFile]:
        """
        Extract infected file entries from output lines.
        Pattern: "/path/to/file: VirusName FOUND"
        """
        infected_files = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            match = PATTERNS['infected_file'].match(line)
            if match:
                file_path = match.group(1).strip()
                virus_name = match.group(2).strip()
                infected_files.append(
                    InfectedFile(
                        file_path=file_path,
                        virus_name=virus_name,
                        action_taken="FOUND"
                    )
                )
        
        return infected_files

    def _parse_summary(self, summary_text: str) -> dict:
        """
        Parse the SCAN SUMMARY section.
        Uses regex to extract each field.
        
        Args:
            summary_text: Full output text containing summary
            
        Returns:
            Dictionary with parsed summary fields
        """
        summary_data = {}
        
        # Check if summary section exists
        summary_match = PATTERNS['summary_start'].search(summary_text)
        if not summary_match:
            return summary_data
        
        # Extract summary section
        summary_start = summary_match.start()
        summary_section = summary_text[summary_start:]
        
        # Parse each field
        scanned_files_match = PATTERNS['scanned_files'].search(summary_section)
        if scanned_files_match:
            summary_data['scanned_files'] = int(scanned_files_match.group(1))
        
        scanned_dirs_match = PATTERNS['scanned_dirs'].search(summary_section)
        if scanned_dirs_match:
            summary_data['scanned_directories'] = int(scanned_dirs_match.group(1))
        
        infected_count_match = PATTERNS['infected_count'].search(summary_section)
        if infected_count_match:
            summary_data['infected_count'] = int(infected_count_match.group(1))
        
        total_errors_match = PATTERNS['total_errors'].search(summary_section)
        if total_errors_match:
            summary_data['total_errors'] = int(total_errors_match.group(1))
        
        data_scanned_match = PATTERNS['data_scanned'].search(summary_section)
        if data_scanned_match:
            summary_data['data_scanned_mb'] = float(data_scanned_match.group(1))
        
        data_read_match = PATTERNS['data_read'].search(summary_section)
        if data_read_match:
            summary_data['data_read_mb'] = float(data_read_match.group(1))
        
        scan_time_match = PATTERNS['scan_time'].search(summary_section)
        if scan_time_match:
            summary_data['scan_time_seconds'] = float(scan_time_match.group(1))
        
        engine_version_match = PATTERNS['engine_version'].search(summary_section)
        if engine_version_match:
            summary_data['engine_version'] = engine_version_match.group(1)
        
        return summary_data

    def _handle_parse_error(self, error: Exception, raw_output: str) -> ScanResult:
        """
        Create error result when parsing fails.
        Preserves raw output for debugging.
        
        Args:
            error: The exception that occurred
            raw_output: Raw output that failed to parse
            
        Returns:
            ScanResult with error status
        """
        return ScanResult(
            status="failed",
            error_message=str(error),
            raw_output=raw_output,
        )
