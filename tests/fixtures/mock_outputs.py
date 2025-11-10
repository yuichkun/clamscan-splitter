"""Mock ClamAV scan outputs for testing.

This module provides various ClamAV output formats for testing the parser
and other components without requiring actual ClamAV execution.
"""

# Clean scan output (no infections)
CLEAN_SCAN_OUTPUT = """/home/user/file1.txt: OK
/home/user/file2.doc: OK
----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 2
Scanned files: 2
Infected files: 0
Total errors: 0
Data scanned: 0.50 MB
Data read: 0.50 MB (ratio 1.00:1)
Time: 1.234 sec (0 m 1 s)
Start Date: 2025:01:15 10:00:00
End Date:   2025:01:15 10:00:01
"""

# Infected scan output (with virus detections)
INFECTED_SCAN_OUTPUT = """/home/user/virus.exe: Win.Trojan.Generic FOUND
/home/user/clean.txt: OK
/home/user/malware.dll: Linux.Malware.Agent FOUND
----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 1
Scanned files: 3
Infected files: 2
Total errors: 0
Data scanned: 1.00 MB
Data read: 1.00 MB (ratio 1.00:1)
Time: 2.345 sec (0 m 2 s)
Start Date: 2025:01:15 10:00:00
End Date:   2025:01:15 10:00:02
"""

# Partial scan output (interrupted)
PARTIAL_SCAN_OUTPUT = """/home/user/file1.txt: OK
/home/user/file2.txt: OK
/home/user/file3.txt: OK
"""

# Error scan output (permission denied, etc.)
ERROR_SCAN_OUTPUT = """/home/user/file1.txt: OK
/home/user/restricted.txt: ERROR: Permission denied
/home/user/file2.txt: OK
/home/user/missing.txt: ERROR: No such file or directory
----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 1
Scanned files: 2
Infected files: 0
Total errors: 2
Data scanned: 0.50 MB
Data read: 0.50 MB (ratio 1.00:1)
Time: 1.234 sec (0 m 1 s)
Start Date: 2025:01:15 10:00:00
End Date:   2025:01:15 10:00:01
"""

# Large scan output (simulating 1.4M files)
LARGE_SCAN_OUTPUT = """----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 159931
Scanned files: 1394942
Infected files: 0
Total errors: 3
Data scanned: 92772.46 MB
Data read: 159697.51 MB (ratio 0.58:1)
Time: 24049.662 sec (400 m 49 s)
Start Date: 2025:11:08 18:03:18
End Date:   2025:11:09 00:44:08
"""

# Mixed output (infections + errors)
MIXED_SCAN_OUTPUT = """/home/user/file1.txt: OK
/home/user/virus.exe: Win.Trojan.Generic FOUND
/home/user/restricted.txt: ERROR: Permission denied
/home/user/malware.dll: Linux.Malware.Agent FOUND
/home/user/file2.txt: OK
----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 1
Scanned files: 3
Infected files: 2
Total errors: 1
Data scanned: 2.50 MB
Data read: 2.50 MB (ratio 1.00:1)
Time: 3.456 sec (0 m 3 s)
Start Date: 2025:01:15 10:00:00
End Date:   2025:01:15 10:00:03
"""

# Malformed output (missing summary)
MALFORMED_SCAN_OUTPUT = """/home/user/file1.txt: OK
/home/user/file2.txt: OK
"""

# Output with no summary section (timeout/interrupted)
NO_SUMMARY_OUTPUT = """/home/user/file1.txt: OK
/home/user/file2.txt: OK
/home/user/file3.txt: OK
/home/user/file4.txt: OK
"""

# Output with different summary format variations
SUMMARY_VARIATION_1 = """----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 5
Scanned files: 10
Infected files: 0
Total errors: 0
Data scanned: 5.25 MB
Data read: 5.25 MB (ratio 1.00:1)
Time: 10.5 sec (0 m 10 s)
Start Date: 2025:01:15 10:00:00
End Date:   2025:01:15 10:00:10
"""

# Output with empty lines and whitespace
CLEAN_SCAN_WITH_WHITESPACE = """
/home/user/file1.txt: OK

/home/user/file2.doc: OK

----------- SCAN SUMMARY -----------
Known viruses: 8708688
Engine version: 1.4.3
Scanned directories: 2
Scanned files: 2
Infected files: 0
Total errors: 0
Data scanned: 0.50 MB
Data read: 0.50 MB (ratio 1.00:1)
Time: 1.234 sec (0 m 1 s)
Start Date: 2025:01:15 10:00:00
End Date:   2025:01:15 10:00:01

"""

# All mock outputs as a dictionary for easy access
MOCK_OUTPUTS = {
    "clean": CLEAN_SCAN_OUTPUT,
    "infected": INFECTED_SCAN_OUTPUT,
    "partial": PARTIAL_SCAN_OUTPUT,
    "error": ERROR_SCAN_OUTPUT,
    "large": LARGE_SCAN_OUTPUT,
    "mixed": MIXED_SCAN_OUTPUT,
    "malformed": MALFORMED_SCAN_OUTPUT,
    "no_summary": NO_SUMMARY_OUTPUT,
    "summary_variation": SUMMARY_VARIATION_1,
    "clean_with_whitespace": CLEAN_SCAN_WITH_WHITESPACE,
}

