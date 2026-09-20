from __future__ import annotations

import json
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))
from fim import build_baseline, compare_baseline, main


def test_baseline_compare_detects_changes(tmp_path: Path) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "a.txt").write_text("hello", encoding="utf-8")
    (monitored / "b.txt").write_text("world", encoding="utf-8")

    baseline_file = tmp_path / "baseline.json"
    baseline = build_baseline(monitored, baseline_file)

    (monitored / "a.txt").write_text("changed", encoding="utf-8")
    (monitored / "c.txt").write_text("new", encoding="utf-8")
    (monitored / "b.txt").unlink()

    report = compare_baseline(monitored, baseline, baseline_file)
    assert report.added == ["c.txt"]
    assert report.modified == ["a.txt"]
    assert report.deleted == ["b.txt"]


def test_create_and_scan_cli_json(tmp_path: Path, capsys) -> None:
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "a.txt").write_text("hello", encoding="utf-8")

    baseline_file = tmp_path / "baseline.json"
    assert main(["create-baseline", "--directory", str(monitored), "--baseline", str(baseline_file)]) == 0
    capsys.readouterr()

    (monitored / "a.txt").write_text("hello2", encoding="utf-8")
    assert main(["scan", "--directory", str(monitored), "--baseline", str(baseline_file), "--format", "json"]) == 0
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["modified"] == ["a.txt"]
