# Security Notes

This project is educational and **not production-ready**.

## Implemented Protections
- Password hashing with Werkzeug (`generate_password_hash`, `check_password_hash`) to reduce credential exposure risk.
- Parameterized SQLite queries (`?` placeholders) to mitigate SQL injection.
- Basic input validation for username format and password length.
- Generic authentication failures (`Invalid username or password.`) to reduce account enumeration.
- Login rate limiting/lockout after repeated failed attempts.
- Session cookie hardening (`HttpOnly`, `SameSite=Lax`).
- Audit logging of auth events without logging plaintext passwords.

## Risk Mapping (Educational)
- **Injection:** parameterized queries.
- **Identification and Authentication Failures:** hashing + lockout + generic errors.
- **Security Misconfiguration:** local-only defaults and conservative session settings.
- **Insufficient Logging and Monitoring:** simple auth event logging for triage practice.
