#!/usr/bin/env python3
"""Lightweight sanity check for docs/architecture.

The default harness treats `docs/architecture/` as a project-wide architecture
documentation area. It does not require mirrored implementation directories,
proposal/design documents, source hash bindings, or a fixed document set.

Repo-local project rules may define stricter requirements. Keep those rules in
versioned project-owned policy, such as `harness/custom-rules/`, and add custom
checks there when needed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


DEFAULT_DOC_ROOT = "docs/architecture"
ALLOWED_SUFFIXES = {".md", ".markdown", ".txt", ".yaml", ".yml", ".json", ".toml"}


def fail(message: str) -> None:
    print(f"architecture-doc-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--doc-root", default=DEFAULT_DOC_ROOT)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    doc_root = root / args.doc_root
    if not doc_root.exists():
        fail(f"missing architecture docs directory: {doc_root}")
    if not doc_root.is_dir():
        fail(f"architecture docs path is not a directory: {doc_root}")

    unsupported = [
        path.relative_to(root).as_posix()
        for path in doc_root.rglob("*")
        if path.is_file() and path.suffix.lower() and path.suffix.lower() not in ALLOWED_SUFFIXES
    ]
    if unsupported:
        fail(
            "unsupported file extension under docs/architecture; "
            "add a project rule/check if this format is intentional: "
            + ", ".join(unsupported[:20])
        )

    file_count = sum(1 for path in doc_root.rglob("*") if path.is_file())
    print(
        "architecture-doc-check: passed "
        f"({file_count} file(s); content requirements are project-rule-defined)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
