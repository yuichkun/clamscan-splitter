# ClamAV Scan Splitter

![screenshot](./screenshot.gif)

Supervise monster ClamAV scans without babysitting. This CLI chops huge directory trees into safe chunks, runs multiple `clamscan` workers, retries stubborn files, and gives you one clean report (plus a quarantine list) at the end.

---

## Install It (60 Seconds)

```bash
git clone https://github.com/yuichkun/clamscan-splitter.git
cd clamscan-splitter

# System-wide install (recommended)
uv pip install --system -e .
# or, inside a venv:
# uv venv && source .venv/bin/activate && uv pip install -e .

clamscan-splitter --help
```

Requirements: Python 3.11+, ClamAV (`clamscan` on PATH). No PyPI package—install from this repo.

---

## Everyday Commands

```bash
# Basic scan (recursive)
clamscan-splitter scan /path/to/dir

# Preview chunk plan only
clamscan-splitter scan /path/to/dir --dry-run

# Tweak limits
clamscan-splitter scan /big/data --chunk-size 20 --max-files 50000 --workers 8

# Save report
clamscan-splitter scan /path -o report.txt

# JSON summary
clamscan-splitter scan /path --json
```

### Resume / Monitor

```bash
clamscan-splitter list                 # show in-progress scans
clamscan-splitter scan --resume <id>   # restart from last saved chunk
clamscan-splitter status <id>          # show progress + last report summary
```

---

## Configuration Options

- CLI flags override everything.
- Environment overrides (optional):  
  `CLAMSCAN_SPLITTER_CHUNK_SIZE`, `CLAMSCAN_SPLITTER_WORKERS`, `CLAMSCAN_SPLITTER_TIMEOUT`.
- Config file (`~/.clamscan-splitter/config.yml` by default):

```yaml
chunking:
  target_size_gb: 15
  max_files_per_chunk: 30000

scanning:
  max_concurrent_processes: null   # auto
  base_timeout_per_gb: 30
```

Set `CLAMSCAN_SPLITTER_CONFIG=/path/to/config.yml` to load a custom file.

---

## What You Get

1. Auto chunking (~15 GB / 30k files each).  
2. Parallel `clamscan` workers sized to your RAM.  
3. Hang detection + retries with chunk splitting.  
4. Continuous state saves → resume anytime.  
5. Final text summary + `quarantine_report.json` for manual review.

---

## Troubleshooting Cheatsheet

| Problem | Fix |
| --- | --- |
| “No files found” | Check the path + permissions. |
| “Scan exceeded timeout” | Increase `--timeout-per-gb` (e.g. `--timeout-per-gb 60`). |
| “Out of memory” | Lower `--workers` or `--chunk-size`. |
| Hung process | Tool auto-kills + quarantines; inspect `quarantine_report.json`. |
| Permission denied | Run with sufficient privileges or exclude that path. |

Exit codes: `0` = clean, `1` = infections found, `2` = incomplete/quarantined, `130` = interrupted (Ctrl+C).

---

## Need Help?

File an issue on GitHub with the command you ran plus the last few lines of output.

## License

MIT
