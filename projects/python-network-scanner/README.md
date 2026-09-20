# Python Network Scanner

## Overview
A safe educational TCP scanner built with the Python standard library for authorized local-lab practice.

## Objectives
- Practice Python networking and CLI argument parsing.
- Detect open/closed ports in controlled environments.
- Produce readable and JSON reports.

## Features
- Explicit `--target` requirement.
- Private/localhost target restriction by default.
- `--allow-public-targets` override with legal warning.
- Configurable port list/range and timeout.
- Readable terminal output plus optional JSON export.

## Technologies
- Python standard library (`socket`, `argparse`, `json`, `ipaddress`)
- Pytest

## Setup
```bash
cd projects/python-network-scanner
python -m pip install pytest
```

## Usage
```bash
python scanner.py --target 127.0.0.1 --ports 22,80,443
python scanner.py --target localhost --ports 8000-8005 --timeout 0.3 --json-output result.json
```

## Example Output
```text
Target: 127.0.0.1

Port    Status
----    ------
22      closed
80      closed
443     closed
```

## Security Considerations
- Default behavior blocks public targets.
- Use `--allow-public-targets` only with explicit written authorization.
- This project does not include stealth, exploitation, credential attacks, or mass scanning.

## Status
- **Current Status:** Completed

## Evidence to Add
- [ ] Screenshot of a safe localhost/private-target scan command and result.
- [ ] Sanitized JSON report output from a lab run.
- [ ] Short note on one input-validation improvement you practiced.

## Lessons Learned
- Safe defaults reduce misuse risk.
- Input validation is essential for reliable security tooling.

## Future Improvements
- Add optional service banner hints for localhost labs.
- Add CSV export for reporting.
