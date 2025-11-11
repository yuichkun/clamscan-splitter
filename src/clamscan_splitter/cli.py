"""CLI module for command-line interface."""

import asyncio
import os
import sys
import uuid
from dataclasses import asdict
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from clamscan_splitter.chunker import ChunkCreator, ChunkingConfig
from clamscan_splitter.merger import MergedReport, ResultMerger
from clamscan_splitter.scanner import ScanConfig, ScanOrchestrator
from clamscan_splitter.state import ProgressTracker, ScanState, StateManager


console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """ClamAV Scan Splitter - Parallel scanning for large directories"""
    pass


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--chunk-size', default=15.0, help='Target chunk size in GB')
@click.option('--max-files', default=30000, help='Max files per chunk')
@click.option('--workers', default=None, type=int, help='Number of parallel workers')
@click.option('--timeout-per-gb', default=30, help='Timeout seconds per GB')
@click.option('--output', '-o', type=click.Path(), help='Output report path')
@click.option('--json', is_flag=True, help='Output JSON format')
@click.option('--resume', type=str, help='Resume scan by ID')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--dry-run', is_flag=True, help='Show chunks without scanning')
def scan(path, chunk_size, max_files, workers, timeout_per_gb,
         output, json, resume, verbose, dry_run):
    """
    Scan directory with ClamAV using parallel chunked processing.

    Examples:
        # Basic scan
        clamscan-splitter scan ~/

        # Custom configuration
        clamscan-splitter scan ~/ --chunk-size 20 --workers 8

        # Dry run to see chunks
        clamscan-splitter scan ~/ --dry-run

        # Resume interrupted scan
        clamscan-splitter scan --resume abc123

        # Save report to file
        clamscan-splitter scan ~/ -o report.txt
    """
    state_manager = StateManager()
    state = None
    
    try:
        if resume:
            # Resume existing scan
            state = state_manager.load_state(resume)
            if not state:
                console.print(f"[red]Error: Scan ID '{resume}' not found[/red]")
                sys.exit(1)
            
            console.print(f"[green]Resuming scan: {resume}[/green]")
            path = state.root_path
            scan_id = state.scan_id
            # Use state configuration
            chunk_size = state.configuration.get('chunk_size', chunk_size)
            max_files = state.configuration.get('max_files', max_files)
            workers = state.configuration.get('workers', workers)
            timeout_per_gb = state.configuration.get('timeout_per_gb', timeout_per_gb)
        else:
            # Create new scan - scan_id will be set after chunks are created
            scan_id = None
        
        # Create chunking configuration
        chunk_config = ChunkingConfig(
            target_size_gb=chunk_size,
            max_files_per_chunk=max_files,
        )
        
        # Create chunks
        chunker = ChunkCreator()
        console.print(f"[cyan]Analyzing filesystem: {path}[/cyan]")
        chunks = chunker.create_chunks(path, chunk_config)
        
        if not chunks:
            console.print("[yellow]No files found to scan[/yellow]")
            return
        
        console.print(f"[green]Created {len(chunks)} chunks[/green]")
        
        # Create or update state with chunk information
        if not resume:
            # Create new scan state
            scan_id = str(uuid.uuid4())[:8]
            console.print(f"[green]Starting scan: {scan_id}[/green]")
            
            state = ScanState(
                scan_id=scan_id,
                root_path=str(path),
                total_chunks=len(chunks),
                completed_chunks=[],
                failed_chunks=[],
                partial_results=[],
                configuration={
                    'chunk_size': chunk_size,
                    'max_files': max_files,
                    'workers': workers,
                    'timeout_per_gb': timeout_per_gb,
                }
            )
            # Save initial state
            state_manager.save_state(state)
        else:
            # Update existing state if chunk count changed
            if state.total_chunks != len(chunks):
                state.total_chunks = len(chunks)
                state_manager.save_state(state)
        
        if dry_run:
            # Show chunk information
            console.print("\n[bold]Chunk Summary:[/bold]")
            for i, chunk in enumerate(chunks, 1):
                size_gb = chunk.estimated_size_bytes / (1024**3)
                console.print(
                    f"  Chunk {i}: {len(chunk.paths)} paths, "
                    f"{size_gb:.2f} GB, {chunk.file_count} files"
                )
            return
        
        # Create scan configuration
        scan_config = ScanConfig(
            max_concurrent_processes=workers,
            base_timeout_per_gb=timeout_per_gb,
        )
        
        # Run scan
        ui = ScanUI()
        ui.display_scan_start(path, len(chunks))
        
        orchestrator = ScanOrchestrator(scan_config)
        tracker = ProgressTracker(len(chunks))
        
        async def run_scan():
            results = await orchestrator.scan_all(chunks)
            
            # Update progress and state
            for result in results:
                if result:
                    tracker.update_chunk_status(result.chunk_id, result.status)
                    
                    # Update state
                    if result.status == "success":
                        if result.chunk_id not in state.completed_chunks:
                            state.completed_chunks.append(result.chunk_id)
                        # Remove from failed if it was there
                        if result.chunk_id in state.failed_chunks:
                            state.failed_chunks.remove(result.chunk_id)
                    elif result.status in ("failed", "timeout"):
                        if result.chunk_id not in state.failed_chunks:
                            state.failed_chunks.append(result.chunk_id)
                        # Remove from completed if it was there
                        if result.chunk_id in state.completed_chunks:
                            state.completed_chunks.remove(result.chunk_id)
                    
                    # Store result as dict
                    result_dict = asdict(result)
                    # Update or append to partial_results
                    existing_idx = None
                    for idx, pr in enumerate(state.partial_results):
                        if pr.get('chunk_id') == result.chunk_id:
                            existing_idx = idx
                            break
                    if existing_idx is not None:
                        state.partial_results[existing_idx] = result_dict
                    else:
                        state.partial_results.append(result_dict)
                    
                    # Save state after each chunk
                    state_manager.save_state(state)
                    
                    if result.infected_files:
                        for infected in result.infected_files:
                            ui.display_infected_file(
                                infected.file_path,
                                infected.virus_name
                            )
            
            # Merge results
            merger = ResultMerger()
            report = merger.merge_results(results)
            
            return report
        
        # Execute scan
        report = asyncio.run(run_scan())
        
        # Display final report
        ui.display_final_report(report)
        
        # Save report if requested
        if output:
            if json:
                merger = ResultMerger()
                merger.save_detailed_report(report, output)
            else:
                formatted = merger.format_report(report)
                with open(output, 'w') as f:
                    f.write(formatted)
            console.print(f"[green]Report saved to: {output}[/green]")
        elif json:
            # Output JSON to stdout
            import json as json_module
            merger = ResultMerger()
            report_dict = {
                "total_scanned_files": report.total_scanned_files,
                "total_infected_files": report.total_infected_files,
                "infected_file_paths": report.infected_file_paths,
                "total_errors": report.total_errors,
                "chunks_successful": report.chunks_successful,
                "chunks_failed": report.chunks_failed,
            }
            console.print(json_module.dumps(report_dict, indent=2))
        
        # Exit with appropriate code
        if report.total_infected_files > 0:
            sys.exit(1)  # ClamAV convention: exit 1 if infections found
        elif not report.scan_complete:
            sys.exit(2)  # Exit 2 if scan incomplete
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        # Save state before exiting so scan can be resumed
        if state:
            try:
                state_manager.save_state(state)
                console.print(f"[cyan]State saved. Resume with: clamscan-splitter scan --resume {state.scan_id}[/cyan]")
            except Exception as e:
                console.print(f"[red]Warning: Failed to save state: {e}[/red]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


@cli.command(name="list")
def list_scans():
    """List incomplete scans that can be resumed"""
    state_manager = StateManager()
    incomplete = state_manager.list_incomplete_scans()
    
    if not incomplete:
        console.print("[green]No incomplete scans found[/green]")
        return
    
    console.print(f"[bold]Found {len(incomplete)} incomplete scan(s):[/bold]\n")
    
    for state in incomplete:
        completed = len(state.completed_chunks)
        total = state.total_chunks
        percentage = (completed / total * 100) if total > 0 else 0
        
        console.print(f"  [cyan]{state.scan_id}[/cyan]")
        console.print(f"    Path: {state.root_path}")
        console.print(f"    Progress: {completed}/{total} chunks ({percentage:.1f}%)")
        console.print(f"    Started: {state.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        console.print("")


@cli.command()
@click.argument('scan_id')
def status(scan_id):
    """Show status of a scan"""
    state_manager = StateManager()
    state = state_manager.load_state(scan_id)
    
    if not state:
        console.print(f"[red]Scan ID '{scan_id}' not found[/red]")
        sys.exit(1)
    
    completed = len(state.completed_chunks)
    failed = len(state.failed_chunks)
    total = state.total_chunks
    percentage = (completed / total * 100) if total > 0 else 0
    
    console.print(f"[bold]Scan Status: {scan_id}[/bold]\n")
    console.print(f"Path: {state.root_path}")
    console.print(f"Total chunks: {total}")
    console.print(f"Completed: {completed}")
    console.print(f"Failed: {failed}")
    console.print(f"Progress: {percentage:.1f}%")
    console.print(f"Started: {state.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"Last update: {state.last_update.strftime('%Y-%m-%d %H:%M:%S')}")


@cli.command()
@click.option('--days', default=30, help='Delete states older than N days')
def cleanup(days):
    """Clean up old scan states"""
    state_manager = StateManager()
    state_manager.cleanup_old_states(days)
    console.print(f"[green]Cleaned up scan states older than {days} days[/green]")


class ScanUI:
    """Rich terminal UI for scan progress."""

    def __init__(self):
        """Initialize scan UI."""
        self.console = Console()
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=self.console,
        )

    def display_scan_start(self, path: str, chunks: int):
        """Display scan start information."""
        self.console.print(f"[bold green]Starting scan of: {path}[/bold green]")
        self.console.print(f"[cyan]Total chunks: {chunks}[/cyan]\n")
        self.progress.start()

    def update_chunk_progress(self, chunk_id: str, status: str):
        """Update progress display for a chunk."""
        # Implementation would update progress bar
        pass

    def display_infected_file(self, file_path: str, virus_name: str):
        """Display infected file detection in real-time."""
        self.console.print(
            f"[red]⚠ INFECTED: {file_path} - {virus_name}[/red]"
        )

    def display_final_report(self, report: MergedReport):
        """Display formatted final report."""
        self.progress.stop()
        self.console.print("\n[bold]Scan Complete![/bold]\n")
        
        merger = ResultMerger()
        formatted = merger.format_report(report)
        self.console.print(formatted)
        
        if report.total_infected_files > 0:
            self.console.print(
                f"\n[bold red]⚠ WARNING: {report.total_infected_files} infected file(s) found![/bold red]"
            )
        elif not report.scan_complete:
            self.console.print(
                f"\n[yellow]⚠ WARNING: Scan incomplete. {len(report.quarantined_files)} file(s) quarantined.[/yellow]"
            )
        else:
            self.console.print("\n[bold green]✓ Scan completed successfully with no infections[/bold green]")
