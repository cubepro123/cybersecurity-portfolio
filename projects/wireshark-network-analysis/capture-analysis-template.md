# Capture Analysis Template

## Scope
- Capture source:
- Lab environment:
- Time window:

## Filters Used
- DNS: `dns`
- TCP handshake: `tcp.flags.syn == 1 and tcp.flags.ack == 0`
- HTTP: `http`
- TLS: `tls`

## Observations
### DNS
- Query volume:
- NXDOMAIN ratio:

### TCP Handshakes
- Successful vs failed:
- Repeated SYN retries:

### HTTP/TLS
- Cleartext HTTP found:
- TLS versions observed:

## Findings
- Key anomaly:
- Impact:
- Confidence:

## Recommendations
- Short-term:
- Long-term:
