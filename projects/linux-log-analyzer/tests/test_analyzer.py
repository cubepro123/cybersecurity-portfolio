from __future__ import annotations

from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))
from analyzer import analyze_log, main


def test_analyze_log_counts_events(tmp_path: Path) -> None:
    sample = tmp_path / "auth.log"
    sample.write_text(
        "\n".join(
            [
                "Jan 1 10:00:00 host sshd[1]: Failed password for root from 10.0.0.2 port 22 ssh2",
                "Jan 1 10:00:01 host sshd[2]: Failed password for invalid user admin from 10.0.0.2 port 23 ssh2",
                "Jan 1 10:00:02 host sshd[3]: Accepted password for student from 10.0.0.3 port 24 ssh2",
            ]
        ),
        encoding="utf-8",
    )

    report = analyze_log(sample, threshold=2)
    assert report.failed_logins == 2
    assert report.successful_logins == 1
    assert report.repeated_failures_by_ip == {"10.0.0.2": 2}
    assert report.targeted_usernames["root"] == 1
    assert report.targeted_usernames["admin"] == 1


def test_main_json_output(capsys) -> None:
    sample_path = Path(__file__).resolve().parents[1] / "sample_logs" / "auth.log.example"
    rc = main([
        "--log-file",
        str(sample_path),
        "--format",
        "json",
        "--threshold",
        "2",
    ])
    assert rc == 0
    output = capsys.readouterr().out
    assert '"failed_logins"' in output
