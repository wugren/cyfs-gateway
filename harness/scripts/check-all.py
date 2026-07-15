#!/usr/bin/env python3
"""Run scaffold-level repository checks without replaying task lifecycle gates.

Task-owned schema, admission, stage-scope, pipeline-plan, test, and acceptance
checks run when their relevant inputs change. A repository-wide audit is not an
invalidation event and must not execute those checkers again.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> bool:
    print(f"check-all: running {' '.join(cmd)}")
    return subprocess.run(cmd).returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    root = Path(args.root)
    scripts = root / "harness" / "scripts"
    checks = (
        scripts / "harness-self-check.py",
        scripts / "architecture-doc-check.py",
    )
    failed = 0

    for checker in checks:
        if not checker.exists():
            print(f"check-all: missing {checker}", file=sys.stderr)
            failed += 1
            continue
        if not run([sys.executable, str(checker), "--root", str(root)]):
            failed += 1

    if failed:
        print(f"check-all: FAILED ({failed} check(s) failed)", file=sys.stderr)
        return 1
    print("check-all: passed (task lifecycle checks not replayed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
