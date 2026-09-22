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
- Explainable risk assessment (`LOW`, `MEDIUM`, `HIGH`) based on threshold-triggered activity.
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
Risk level: MEDIUM
Risk explanation: At least one IP met the repeated-failure threshold of 3.

Repeated Failures by IP:
- 192.168.56.10: 3
```

```json
{
  "failed_logins": 4,
  "successful_logins": 1,
  "repeated_failures_by_ip": {
    "192.168.56.10": 3
  },
  "targeted_usernames": {
    "root": 3,
    "student": 1
  },
  "risk_level": "MEDIUM",
  "risk_explanation": "At least one IP met the repeated-failure threshold of 3."
}
```

## Risk Scoring Rules
- **LOW**: No IP address reaches the repeated-failure threshold.
- **MEDIUM**: Exactly one suspicious IP reaches the threshold, but does not exceed `2x` threshold.
- **HIGH**: Two or more suspicious IPs reach threshold, or one suspicious IP reaches at least `2x` threshold.
- These rules are deterministic and use only `repeated_failures_by_ip` and `--threshold`.

## Security Considerations
- Use only sanitized sample logs.
- Do not upload production auth logs.
- Treat usernames and source addresses as sensitive metadata.
- This analyzer is defensive and educational; it does not include exploitation, brute-force automation, or offensive scanning behavior.

## Status
- **Current Status:** Completed

## Evidence to Add
- [ ] Sanitized auth.log example snippet used during practice.
- [ ] Screenshot or text output of threshold-based detections.
- [ ] Screenshot or JSON snippet showing LOW, MEDIUM, and HIGH risk classifications.
- [ ] Brief explanation of one false-positive reduction decision.

## Lessons Learned
- Reliable regex parsing supports fast triage.
- Thresholds reduce noisy alerting.
- Simple, transparent scoring rules make alert severity easier to explain during review.

## Future Improvements
- Add time-window based detections.
- Add CSV exports for SOC tooling.
