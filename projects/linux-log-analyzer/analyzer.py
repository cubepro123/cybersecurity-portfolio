from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>\S+)",
)
SUCCESS_RE = re.compile(r"Accepted password for (?P<username>\S+) from (?P<ip>\S+)")


@dataclass
class LogReport:
    failed_logins: int
    successful_logins: int
    repeated_failures_by_ip: dict[str, int]
    targeted_usernames: dict[str, int]
    risk_level: str
    risk_explanation: str


def assess_risk(repeated_failures_by_ip: dict[str, int], threshold: int) -> tuple[str, str]:
    suspicious_ips = len(repeated_failures_by_ip)
    if suspicious_ips == 0:
        return "LOW", "No IP met the repeated-failure threshold."

    peak_failures = max(repeated_failures_by_ip.values())
    if suspicious_ips >= 2:
        return "HIGH", f"{suspicious_ips} IPs met or exceeded the threshold of {threshold}."
    if peak_failures >= threshold * 2:
        return "HIGH", f"An IP reached {peak_failures} failed logins (2x threshold {threshold})."
    return "MEDIUM", f"At least one IP met the repeated-failure threshold of {threshold}."


def analyze_log(path: Path, threshold: int) -> LogReport:
    failed = 0
    successful = 0
    failures_by_ip: Counter[str] = Counter()
    targeted_usernames: Counter[str] = Counter()

    for line in path.read_text(encoding="utf-8").splitlines():
        failed_match = FAILED_RE.search(line)
        if failed_match:
            failed += 1
            failures_by_ip[failed_match.group("ip")] += 1
            targeted_usernames[failed_match.group("username")] += 1
            continue

        success_match = SUCCESS_RE.search(line)
        if success_match:
            successful += 1

    repeated = {ip: count for ip, count in failures_by_ip.items() if count >= threshold}
    risk_level, risk_explanation = assess_risk(repeated, threshold)
    return LogReport(
        failed_logins=failed,
        successful_logins=successful,
        repeated_failures_by_ip=dict(sorted(repeated.items())),
        targeted_usernames=dict(sorted(targeted_usernames.items())),
        risk_level=risk_level,
        risk_explanation=risk_explanation,
    )


def text_report(report: LogReport, threshold: int) -> str:
    lines = [
        "Linux Auth Log Analysis Report",
        f"Failed logins: {report.failed_logins}",
        f"Successful logins: {report.successful_logins}",
        f"Repeated failure threshold: {threshold}",
        f"Risk level: {report.risk_level}",
        f"Risk explanation: {report.risk_explanation}",
        "",
        "Repeated Failures by IP:",
    ]

    if report.repeated_failures_by_ip:
        for ip, count in report.repeated_failures_by_ip.items():
            lines.append(f"- {ip}: {count}")
    else:
        lines.append("- none")

    lines.append("")
    lines.append("Targeted Usernames (failed attempts):")
    if report.targeted_usernames:
        for username, count in report.targeted_usernames.items():
            lines.append(f"- {username}: {count}")
    else:
        lines.append("- none")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze Linux auth.log/secure-style events")
    parser.add_argument("--log-file", required=True, help="Path to auth log sample")
    parser.add_argument("--threshold", type=int, default=3, help="Threshold for repeated failures")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Report format")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.threshold <= 0:
        print("Error: threshold must be > 0")
        return 1

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Error: file not found: {log_path}")
        return 1

    report = analyze_log(log_path, args.threshold)
    if args.format == "json":
        print(json.dumps(asdict(report), indent=2))
    else:
        print(text_report(report, args.threshold))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
