# Example Findings (Sanitized)

- DNS showed repeated lookups to a simulated training domain with several NXDOMAIN responses, suggesting misconfiguration.
- TCP analysis showed multiple failed handshakes to an unopened lab service port, consistent with a controlled scan exercise.
- HTTP traffic existed in one internal demo app; recommendation is to enforce HTTPS even in staging labs.
- TLS observations indicated modern protocol usage with no deprecated SSL versions in the sample traffic.
