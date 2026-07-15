#!/usr/bin/env python3
"""Allocate and validate version-local Harness task sequence names.

Task packet names use <task-seq>-<task-slug>, for example 001-login-flow.
The sequence is allocated per docs/versions/<version>/ across every project
module and globals. This tool scans both existing packet directories and the
unfinished-task index so agents do not hand-pick sequence numbers.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


TASK_NAME_RE = re.compile(r"^(?P<seq>\d{3,})-(?P<slug>[a-z0-9][a-z0-9_.-]*)$")
TASK_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_.-])(?P<name>\d{3,}-[a-z0-9][a-z0-9_.-]*)(?![A-Za-z0-9_.-])")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
EXCLUDED_MODULE_DIRS = {"_template"}


def fail(message: str) -> None:
    print(f"task-seq: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalize_slug(slug: str) -> str:
    value = slug.strip().lower().replace("_", "-").replace(" ", "-")
    value = re.sub(r"[^a-z0-9.-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-.")
    if not value or not SLUG_RE.fullmatch(value):
        fail(f"invalid task slug after normalization: {slug!r}")
    return value


def task_seq(task_name: str) -> int | None:
    match = TASK_NAME_RE.fullmatch(task_name)
    if not match:
        return None
    return int(match.group("seq"))


def collect_from_tasks_md(path: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    if not path.is_file():
        return found
    text = path.read_text(encoding="utf-8")
    for match in TASK_TOKEN_RE.finditer(text):
        name = match.group("name")
        found.setdefault(name, path.as_posix())
    return found


def collect_from_directories(modules_dir: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    if not modules_dir.is_dir():
        return found

    for module_dir in sorted(path for path in modules_dir.iterdir() if path.is_dir()):
        if module_dir.name in EXCLUDED_MODULE_DIRS:
            continue
        if module_dir.name == "globals":
            search_roots = [module_dir]
        else:
            search_roots = [module_dir]
        for root in search_roots:
            for task_dir in sorted(path for path in root.iterdir() if path.is_dir()):
                if TASK_NAME_RE.fullmatch(task_dir.name):
                    found.setdefault(task_dir.name, task_dir.as_posix())
    return found


def collect_task_names(root: Path, version: str) -> dict[str, str]:
    modules_dir = root / "docs" / "versions" / version / "modules"
    found = collect_from_directories(modules_dir)
    for name, source in collect_from_tasks_md(modules_dir / "tasks.md").items():
        found.setdefault(name, source)
    return found


def next_sequence(root: Path, version: str, width: int) -> tuple[int, dict[str, str]]:
    names = collect_task_names(root, version)
    sequences = [seq for name in names for seq in [task_seq(name)] if seq is not None]
    next_seq = max(sequences, default=0) + 1
    if next_seq >= 10**width:
        width = len(str(next_seq))
    return next_seq, names


def format_task_name(sequence: int, width: int, slug: str) -> str:
    return f"{sequence:0{width}d}-{slug}"


def command_next(args: argparse.Namespace) -> int:
    root = Path(args.root)
    slug = normalize_slug(args.slug) if args.slug else None
    sequence, names = next_sequence(root, args.version, args.width)
    task_name = format_task_name(sequence, args.width, slug) if slug else f"{sequence:0{args.width}d}"
    if args.json:
        print(json.dumps({"version": args.version, "sequence": sequence, "task_name": task_name, "existing": sorted(names)}, indent=2))
    else:
        print(task_name)
    return 0


def command_check(args: argparse.Namespace) -> int:
    root = Path(args.root)
    match = TASK_NAME_RE.fullmatch(args.task_name)
    if not match:
        fail(f"task name must match <task-seq>-<task-slug>: {args.task_name}")
    if len(match.group("seq")) < args.width:
        fail(f"task sequence must be at least {args.width} digits: {args.task_name}")

    names = collect_task_names(root, args.version)
    if args.task_name in names and not args.allow_existing:
        fail(f"task name already exists in {names[args.task_name]}: {args.task_name}")

    sequence = int(match.group("seq"))
    next_seq, _ = next_sequence(root, args.version, args.width)
    if args.require_next and sequence != next_seq:
        fail(f"task sequence must be the next unused value {next_seq:0{args.width}d}, got {match.group('seq')}")

    print("task-seq: passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    subparsers = parser.add_subparsers(dest="command", required=True)

    next_parser = subparsers.add_parser("next", help="print the next sequence or sequence-prefixed task name")
    next_parser.add_argument("--version", required=True)
    next_parser.add_argument("--slug", help="task slug; when provided, output <seq>-<slug>")
    next_parser.add_argument("--width", type=int, default=3)
    next_parser.add_argument("--json", action="store_true")
    next_parser.set_defaults(func=command_next)

    check_parser = subparsers.add_parser("check", help="validate a sequence-prefixed task name")
    check_parser.add_argument("--version", required=True)
    check_parser.add_argument("--task-name", required=True)
    check_parser.add_argument("--width", type=int, default=3)
    check_parser.add_argument("--allow-existing", action="store_true")
    check_parser.add_argument("--require-next", action="store_true")
    check_parser.set_defaults(func=command_check)

    args = parser.parse_args()
    if args.width < 1:
        fail("--width must be positive")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
