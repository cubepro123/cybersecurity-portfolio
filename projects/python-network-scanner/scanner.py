from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
from dataclasses import dataclass, asdict
from typing import Iterable, List

MAX_PORTS = 128


@dataclass
class PortResult:
    port: int
    status: str


def parse_ports(value: str) -> List[int]:
    ports: set[int] = set()
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise ValueError(f"Invalid range '{item}': start must be <= end")
            for port in range(start, end + 1):
                validate_port(port)
                ports.add(port)
        else:
            port = int(item)
            validate_port(port)
            ports.add(port)

    result = sorted(ports)
    if not result:
        raise ValueError("At least one port must be provided")
    if len(result) > MAX_PORTS:
        raise ValueError(f"Too many ports requested ({len(result)}). Maximum is {MAX_PORTS}")
    return result


def validate_port(port: int) -> None:
    if not 1 <= port <= 65535:
        raise ValueError(f"Port out of range: {port}")


def resolve_target(target: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        resolved = socket.gethostbyname(target)
        return ipaddress.ip_address(resolved)


def is_lab_target(address: ipaddress._BaseAddress) -> bool:
    return address.is_private or address.is_loopback


def scan_ports(target: str, ports: Iterable[int], timeout: float) -> list[PortResult]:
    results: list[PortResult] = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((target, port))
            status = "open" if code == 0 else "closed"
            results.append(PortResult(port=port, status=status))
    return results


def format_results(target: str, results: list[PortResult]) -> str:
    lines = [f"Target: {target}", "", "Port    Status", "----    ------"]
    for result in results:
        lines.append(f"{result.port:<7} {result.status}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe educational TCP port scanner")
    parser.add_argument("--target", required=True, help="Target hostname or IP")
    parser.add_argument("--ports", default="22,80,443", help="Port list or range (e.g. 22,80,8000-8005)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout in seconds")
    parser.add_argument("--json-output", help="Optional path to write JSON results")
    parser.add_argument(
        "--allow-public-targets",
        action="store_true",
        help="Override lab-target restriction for explicitly authorized assessments",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.timeout <= 0:
            raise ValueError("Timeout must be positive")

        target_ip = resolve_target(args.target)
        ports = parse_ports(args.ports)

        if not args.allow_public_targets and not is_lab_target(target_ip):
            raise ValueError(
                "Public targets are blocked by default. Use localhost/private lab targets, "
                "or pass --allow-public-targets with explicit authorization."
            )

        if args.allow_public_targets and not is_lab_target(target_ip):
            print(
                "WARNING: You enabled --allow-public-targets. Only scan systems with explicit authorization.",
                file=sys.stderr,
            )

        results = scan_ports(str(target_ip), ports, args.timeout)
        print(format_results(str(target_ip), results))

        if args.json_output:
            payload = {
                "target": str(target_ip),
                "ports": ports,
                "results": [asdict(result) for result in results],
            }
            with open(args.json_output, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)

        return 0
    except (ValueError, OSError, socket.gaierror) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
