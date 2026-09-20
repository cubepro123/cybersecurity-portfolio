from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class ScanReport:
    added: list[str]
    modified: list[str]
    deleted: list[str]
    inaccessible: list[str]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_baseline(directory: Path, baseline_file: Path, include_symlinks: bool = False) -> dict[str, str]:
    baseline: dict[str, str] = {}
    baseline_resolved = baseline_file.resolve()

    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.resolve() == baseline_resolved:
            continue
        if file_path.is_symlink() and not include_symlinks:
            continue

        rel = file_path.relative_to(directory).as_posix()
        try:
            baseline[rel] = sha256_file(file_path)
        except (OSError, PermissionError):
            continue

    return dict(sorted(baseline.items()))


def compare_baseline(
    directory: Path, baseline: dict[str, str], baseline_file: Path, include_symlinks: bool = False
) -> ScanReport:
    current = build_baseline(directory, baseline_file=baseline_file, include_symlinks=include_symlinks)

    baseline_paths = set(baseline)
    current_paths = set(current)

    added = sorted(current_paths - baseline_paths)
    deleted = sorted(baseline_paths - current_paths)
    modified = sorted(path for path in (current_paths & baseline_paths) if baseline[path] != current[path])

    return ScanReport(added=added, modified=modified, deleted=deleted, inaccessible=[])


def write_baseline(path: Path, baseline: dict[str, str]) -> None:
    path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def read_baseline(path: Path) -> dict[str, str]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Educational file integrity monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create-baseline", help="Create baseline file")
    create.add_argument("--directory", required=True)
    create.add_argument("--baseline", required=True)

    scan = subparsers.add_parser("scan", help="Compare baseline with current state")
    scan.add_argument("--directory", required=True)
    scan.add_argument("--baseline", required=True)
    scan.add_argument("--format", choices=["text", "json"], default="text")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    directory = Path(args.directory)
    baseline_path = Path(args.baseline)

    if not directory.exists() or not directory.is_dir():
        print("Error: directory does not exist")
        return 1

    if args.command == "create-baseline":
        baseline = build_baseline(directory, baseline_path)
        write_baseline(baseline_path, baseline)
        print(f"Baseline created with {len(baseline)} file(s): {baseline_path}")
        return 0

    if not baseline_path.exists():
        print("Error: baseline file does not exist")
        return 1

    baseline = read_baseline(baseline_path)
    report = compare_baseline(directory, baseline, baseline_path)
    if args.format == "json":
        print(json.dumps(asdict(report), indent=2))
    else:
        print("File Integrity Monitor Report")
        print(f"Added: {len(report.added)}")
        print(f"Modified: {len(report.modified)}")
        print(f"Deleted: {len(report.deleted)}")
        if report.added:
            print("- Added:")
            for item in report.added:
                print(f"  - {item}")
        if report.modified:
            print("- Modified:")
            for item in report.modified:
                print(f"  - {item}")
        if report.deleted:
            print("- Deleted:")
            for item in report.deleted:
                print(f"  - {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
