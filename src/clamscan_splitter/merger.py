"""Merger module for combining scan results into unified reports."""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import List, Optional

from clamscan_splitter.parser import ScanResult


@dataclass
class QuarantineEntry:
    """Record of a file that couldn't be scanned."""
    file_path: str
    reason: str  # "timeout", "hang", "permission", "special_file"
    file_size_bytes: Optional[int] = None
    retry_count: int = 0
    last_attempt: datetime = field(default_factory=datetime.now)


@dataclass
class MergedReport:
    """Final merged scan report."""
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
    skipped_paths: List[str] = field(default_factory=list)
    quarantined_files: List[QuarantineEntry] = field(default_factory=list)
    scan_date: datetime = field(default_factory=datetime.now)
    scan_complete: bool = True  # False if any files were skipped/quarantined


class ResultMerger:
    """Merges multiple scan results into unified report."""

    def merge_results(
        self,
        results: List[ScanResult],
        quarantined_entries: Optional[List[QuarantineEntry]] = None,
    ) -> MergedReport:
        """
        Merge all scan results into single report.

        Args:
            results: List of ScanResult objects to merge

        Returns:
            MergedReport object
        """
        if not results:
            return MergedReport(
                total_scanned_files=0,
                total_scanned_directories=0,
                total_infected_files=0,
                infected_file_paths=[],
                total_errors=0,
                total_data_scanned_mb=0.0,
                total_data_read_mb=0.0,
                total_time_seconds=0.0,
                wall_clock_time_seconds=0.0,
                engine_version="",
                chunks_successful=0,
                chunks_failed=0,
                chunks_partial=0,
                scan_complete=True,
            )
        
        # Deduplicate infected files
        infected_file_paths = self._deduplicate_infected_files(results)
        
        # Calculate statistics
        stats = self._calculate_statistics(results)
        
        # Determine scan completeness
        scan_complete = (
            stats["chunks_failed"] == 0
            and stats["chunks_partial"] == 0
            and len(stats["skipped_paths"]) == 0
        )
        
        # Get engine version from first successful result
        engine_version = ""
        for result in results:
            if result.engine_version:
                engine_version = result.engine_version
                break
        
        quarantine_list = list(quarantined_entries or [])
        
        return MergedReport(
            total_scanned_files=stats["total_files"],
            total_scanned_directories=stats["total_directories"],
            total_infected_files=len(infected_file_paths),
            infected_file_paths=infected_file_paths,
            total_errors=stats["total_errors"],
            total_data_scanned_mb=stats["total_data_scanned"],
            total_data_read_mb=stats["total_data_read"],
            total_time_seconds=stats["total_time"],
            wall_clock_time_seconds=stats["wall_clock_time"],
            engine_version=engine_version,
            chunks_successful=stats["chunks_successful"],
            chunks_failed=stats["chunks_failed"],
            chunks_partial=stats["chunks_partial"],
            skipped_paths=stats["skipped_paths"],
            quarantined_files=quarantine_list,
            scan_date=datetime.now(),
            scan_complete=scan_complete,
        )

    def _deduplicate_infected_files(
        self, results: List[ScanResult]
    ) -> List[str]:
        """
        Remove duplicate infected file paths.
        Maintains order of first occurrence.

        Args:
            results: List of scan results

        Returns:
            List of unique infected file paths
        """
        seen = set()
        unique_paths = []
        
        for result in results:
            for infected_file in result.infected_files:
                if infected_file.file_path not in seen:
                    seen.add(infected_file.file_path)
                    unique_paths.append(infected_file.file_path)
        
        return unique_paths

    def _calculate_statistics(self, results: List[ScanResult]) -> dict:
        """
        Calculate aggregate statistics from all results.

        Args:
            results: List of scan results

        Returns:
            Dictionary with aggregated statistics
        """
        stats = {
            "total_files": 0,
            "total_directories": 0,
            "total_errors": 0,
            "total_data_scanned": 0.0,
            "total_data_read": 0.0,
            "total_time": 0.0,
            "wall_clock_time": 0.0,
            "chunks_successful": 0,
            "chunks_failed": 0,
            "chunks_partial": 0,
            "skipped_paths": [],
            "quarantined_files": [],
        }
        
        for result in results:
            stats["total_files"] += result.scanned_files
            stats["total_directories"] += result.scanned_directories
            stats["total_errors"] += result.total_errors
            stats["total_data_scanned"] += result.data_scanned_mb
            stats["total_data_read"] += result.data_read_mb
            stats["total_time"] += result.scan_time_seconds
            stats["wall_clock_time"] = max(
                stats["wall_clock_time"], result.scan_time_seconds
            )
            
            # Count chunk statuses
            if result.status == "success":
                stats["chunks_successful"] += 1
            elif result.status == "failed":
                stats["chunks_failed"] += 1
            elif result.status == "partial":
                stats["chunks_partial"] += 1
            
            # Collect skipped paths from error messages
            if result.error_message and "skip" in result.error_message.lower():
                # Extract paths from error message if possible
                pass  # Would need parsing logic
        
        return stats

    def format_report(self, report: MergedReport) -> str:
        """
        Format report in required corporate format with quarantine info.

        Args:
            report: MergedReport to format

        Returns:
            Formatted report string
        """
        lines = []
        lines.append("----------- SCAN SUMMARY -----------")
        lines.append(f"Engine version: {report.engine_version}")
        lines.append(f"Scanned directories: {report.total_scanned_directories}")
        lines.append(f"Scanned files: {report.total_scanned_files}")
        lines.append(f"Infected files: {report.total_infected_files}")
        lines.append(f"Total errors: {report.total_errors}")
        lines.append(f"Data scanned: {report.total_data_scanned_mb:.2f} MB")
        
        # Calculate ratio
        ratio = (
            report.total_data_read_mb / report.total_data_scanned_mb
            if report.total_data_scanned_mb > 0
            else 1.0
        )
        lines.append(
            f"Data read: {report.total_data_read_mb:.2f} MB (ratio {ratio:.2f}:1)"
        )
        
        # Format time
        total_minutes = int(report.total_time_seconds // 60)
        total_seconds = int(report.total_time_seconds % 60)
        lines.append(
            f"Time: {report.total_time_seconds:.3f} sec ({total_minutes} m {total_seconds} s)"
        )
        
        # Format dates
        start_date = report.scan_date.strftime("%Y:%m:%d %H:%M:%S")
        end_date = datetime.now().strftime("%Y:%m:%d %H:%M:%S")
        lines.append(f"Start Date: {start_date}")
        lines.append(f"End Date:   {end_date}")
        
        # Add quarantine summary if needed
        if report.quarantined_files:
            lines.append("")
            lines.append("----------- QUARANTINE SUMMARY -----------")
            lines.append(
                f"Files that could not be scanned: {len(report.quarantined_files)}"
            )
            lines.append("Reasons:")
            
            # Count by reason
            reason_counts = {}
            for entry in report.quarantined_files:
                reason_counts[entry.reason] = reason_counts.get(entry.reason, 0) + 1
            
            for reason, count in reason_counts.items():
                lines.append(f"  - {reason}: {count}")
            
            lines.append("")
            lines.append(
                f"IMPORTANT: {len(report.quarantined_files)} files were not scanned. Manual review required."
            )
            lines.append("Full quarantine list saved to: quarantine_report.json")
        
        return "\n".join(lines)

    def save_quarantine_report(
        self,
        report: MergedReport,
        path: str = "quarantine_report.json",
    ):
        """
        Save detailed quarantine metadata.

        Args:
            report: MergedReport containing quarantined files
            path: Destination JSON path
        """
        data = [
            {
                "file_path": entry.file_path,
                "reason": entry.reason,
                "file_size_bytes": entry.file_size_bytes,
                "retry_count": entry.retry_count,
                "last_attempt": entry.last_attempt.isoformat(),
            }
            for entry in report.quarantined_files
        ]
        
        with open(path, 'w') as fh:
            json.dump(data, fh, indent=2)

    def save_detailed_report(self, report: MergedReport, path: str):
        """
        Save detailed JSON report with all information.

        Args:
            report: MergedReport to save
            path: Path to save JSON file
        """
        # Convert to dict, handling datetime serialization
        report_dict = asdict(report)
        report_dict["scan_date"] = report.scan_date.isoformat()
        report_dict["quarantined_files"] = [
            {
                "file_path": q.file_path,
                "reason": q.reason,
                "file_size_bytes": q.file_size_bytes,
                "retry_count": q.retry_count,
                "last_attempt": q.last_attempt.isoformat(),
            }
            for q in report.quarantined_files
        ]
        
        with open(path, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)
