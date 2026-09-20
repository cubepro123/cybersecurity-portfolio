# Linux Log Analyzer

## Overview
A Python CLI that parses Linux `auth.log` / `secure` style SSH authentication lines and highlights suspicious patterns from sample data.

## Objectives
- Parse common authentication log formats.
- Identify failed and successful login events.
- Detect repeated failures by IP and targeted usernames.

## Features
- Failed login detection.
- Successful login detection.
- Repeated failures by configurable threshold.
- Targeted username counting.
- Text and JSON report formats.

## Technologies
- Python standard library (`re`, `argparse`, `collections`, `json`)
- Pytest

## Setup
```bash
cd projects/linux-log-analyzer
python -m pip install pytest
```

## Usage
```bash
python analyzer.py --log-file sample_logs/auth.log.example --threshold 3 --format text
python analyzer.py --log-file sample_logs/auth.log.example --threshold 2 --format json
```

## Example Output
```text
Linux Auth Log Analysis Report
Failed logins: 4
Successful logins: 1
Repeated failure threshold: 3

Repeated Failures by IP:
- 192.168.56.10: 3
```

## Security Considerations
- Use only sanitized sample logs.
- Do not upload production auth logs.
- Treat usernames and source addresses as sensitive metadata.

## Status
- **Current Status:** Completed

## Evidence to Add
- [ ] Sanitized auth.log example snippet used during practice.
- [ ] Screenshot or text output of threshold-based detections.
- [ ] Brief explanation of one false-positive reduction decision.

## Lessons Learned
- Reliable regex parsing supports fast triage.
- Thresholds reduce noisy alerting.

## Future Improvements
- Add time-window based detections.
- Add CSV exports for SOC tooling.
