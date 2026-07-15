#!/usr/bin/env python3
"""Capture task-start file baselines under the project-local .harness directory.

The snapshot is intentionally filesystem-backed. It never creates a temporary
Git index, tree, or commit, so capturing a baseline does not write Git metadata
or trigger repository-control approval prompts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path, PurePosixPath


TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def fail(message: str) -> None:
    print(f"baseline-snapshot: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalize(path: str) -> str:
    normalized = path.replace("\\", "/").lstrip("\ufeff")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    candidate = PurePosixPath(normalized)
    if not normalized or candidate.is_absolute() or ".." in candidate.parts:
        fail(f"path must stay inside the repository: {path}")
    return candidate.as_posix()


def canonical_source(root: Path, path: str) -> tuple[str, Path]:
    normalized = normalize(path)
    root_resolved = root.resolve()
    source = (root_resolved / normalized).resolve(strict=False)
    try:
        source.relative_to(root_resolved)
    except ValueError:
        fail(f"path resolves outside the repository: {path}")
    if not source.is_file():
        fail(f"baseline source is not a file: {normalized}")
    return normalized, source


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def capture(root: Path, task_id: str, paths: list[str]) -> Path:
    if not TASK_ID_RE.fullmatch(task_id):
        fail(f"invalid task id: {task_id}")
    if not paths:
        fail("at least one --path is required")

    sources: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for raw in paths:
        normalized, source = canonical_source(root, raw)
        if normalized not in seen:
            sources.append((normalized, source))
            seen.add(normalized)

    task_dir = root.resolve() / ".harness" / "baselines" / task_id
    if task_dir.exists():
        fail(f"baseline already exists and will not be overwritten: {task_dir}")

    records: list[dict[str, str]] = []
    for path, source in sources:
        snapshot_relative = PurePosixPath("files") / PurePosixPath(path)
        destination = task_dir / Path(*snapshot_relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        records.append(
            {
                "path": path,
                "snapshot": snapshot_relative.as_posix(),
                "sha256": sha256_bytes(destination.read_bytes()),
            }
        )

    manifest = task_dir / "manifest.json"
    manifest.write_text(
        json.dumps(
            {"schema": 1, "task_id": task_id, "files": records},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--path", action="append", dest="paths", required=True)
    args = parser.parse_args()

    manifest = capture(Path(args.root), args.task_id, args.paths)
    print(f"baseline-snapshot: wrote {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

