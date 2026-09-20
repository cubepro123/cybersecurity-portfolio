# Secure Login Demo

## Overview
A small local-only Flask application demonstrating safer authentication implementation patterns.

## Objectives
- Demonstrate secure password storage and verification.
- Apply input validation and defensive authentication responses.
- Show basic lockout and audit logging behavior.

## Features
- User registration and login.
- Werkzeug password hashing.
- Parameterized SQLite queries.
- Generic authentication error messages.
- Basic lockout after repeated failures.
- Audit logging without password logging.

## Technologies
- Flask
- SQLite
- Werkzeug security utilities
- Pytest

## Setup
```bash
cd projects/secure-login-demo
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
python app.py
```
Open `http://127.0.0.1:5000` in your browser.

## Example Output
```text
2026-01-01 10:00:00 INFO audit_event=login_success username=student_1 ip=127.0.0.1
```

## Security Considerations
- Local educational demo only; not hardened for internet deployment.
- Includes baseline controls, not full production defenses.
- See [SECURITY_NOTES.md](SECURITY_NOTES.md) for risk mapping.

## Lessons Learned
- Secure defaults and consistent error handling improve safety.
- Authentication controls need both prevention and monitoring.

## Future Improvements
- Add CSRF protections and stronger password policy checks.
- Add MFA simulation for learning.
