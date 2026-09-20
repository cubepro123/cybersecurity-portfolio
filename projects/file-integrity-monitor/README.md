# File Integrity Monitor

## Overview
An educational Python CLI that builds a SHA-256 baseline and compares later scans to detect file changes.

## Objectives
- Understand file hashing for integrity monitoring.
- Detect added, modified, and deleted files.
- Practice safe handling of file-system permissions.

## Features
- Baseline creation to JSON.
- Change detection for added/modified/deleted files.
- Excludes baseline file from scans.
- Avoids following symlinks by default.
- Text and JSON reporting.

## Technologies
- Python standard library (`hashlib`, `pathlib`, `argparse`, `json`)
- Pytest

## Setup
```bash
cd projects/file-integrity-monitor
python -m pip install pytest
```

## Usage
```bash
python fim.py create-baseline --directory ./demo --baseline ./baseline.json
python fim.py scan --directory ./demo --baseline ./baseline.json --format text
```

## Example Output
```text
File Integrity Monitor Report
Added: 1
Modified: 1
Deleted: 0
```

## Security Considerations
- Designed for defensive monitoring and education.
- Permission errors are handled safely (no forced access).
- Does not attempt stealth or persistence behavior.

## Lessons Learned
- Strong baselines are required before detection is meaningful.
- Clear reporting accelerates incident triage.

## Future Improvements
- Add optional hash algorithm selection.
- Add timestamped scan history output.
