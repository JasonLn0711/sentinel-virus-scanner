#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import subprocess


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUST_ROOT = PROJECT_ROOT / "rust"


COMMANDS = [
    ["cargo", "fmt", "--check"],
    ["cargo", "test"],
    ["cargo", "clippy", "--all-targets", "--", "-D", "warnings"],
    ["cargo", "run", "--", "validate-signatures", "--signatures", "../signatures/malware-signatures.json"],
    ["cargo", "run", "--", "prepare-eicar-demo", "--target", "../demo/demo-tree"],
    ["cargo", "run", "--", "verify-demo", "--target", "../demo/demo-tree", "--signatures", "../signatures/malware-signatures.json"],
    [
        "cargo",
        "run",
        "--",
        "scan",
        "--target",
        "../demo/demo-tree",
        "--signatures",
        "../signatures/malware-signatures.json",
        "--json",
        "../reports/demo-report.json",
        "--markdown",
        "../reports/demo-report.md",
    ],
    [
        "cargo",
        "run",
        "--",
        "write-evidence",
        "--target",
        "../demo/demo-tree",
        "--signatures",
        "../signatures/malware-signatures.json",
        "--report",
        "../reports/demo-report.json",
        "--report",
        "../reports/demo-report.md",
        "--output",
        "../reports/demo-evidence-manifest.json",
    ],
]


def main() -> int:
    for command in COMMANDS:
        print()
        print("$ " + " ".join(command), flush=True)
        completed = subprocess.run(command, cwd=RUST_ROOT, check=False)
        if _allowed_detection_exit(command, completed.returncode):
            print("note: scan returned 1 because the generated EICAR safe test file was detected.")
            continue
        if completed.returncode != 0:
            return completed.returncode

    print()
    print("Demo artifacts regenerated:")
    print("- reports/demo-report.json")
    print("- reports/demo-report.md")
    print("- reports/demo-evidence-manifest.json")
    return 0


def _allowed_detection_exit(command: list[str], returncode: int) -> bool:
    return "scan" in command and returncode == 1


if __name__ == "__main__":
    raise SystemExit(main())
