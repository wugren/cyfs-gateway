#!/usr/bin/env python3
"""Fail on unallowlisted repository references to removed public symbols."""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path


TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
EXCLUDED_PARTS = {".git", ".venv", "target", "test-results", "__pycache__"}


def fail(message: str) -> None:
    print(f"consumer-closure-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalize_column(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def split_row(line: str) -> list[str]:
    values = [value.strip() for value in line.strip().split("|")]
    if values and not values[0]:
        values.pop(0)
    if values and not values[-1]:
        values.pop()
    return values


def table_rows(text: str, heading: str, path: Path) -> list[dict[str, str]]:
    match = re.search(rf"(?m)^##\s+{re.escape(heading)}\s*$", text)
    if not match:
        fail(f"{path} missing required section: ## {heading}")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    lines = text[match.end() : end].splitlines()
    start = None
    for index, line in enumerate(lines):
        if "|" in line and index + 1 < len(lines) and TABLE_SEPARATOR_RE.match(lines[index + 1]):
            start = index
            break
    if start is None:
        fail(f"{path} ## {heading} missing table")
    headers = [normalize_column(value) for value in split_row(lines[start])]
    rows: list[dict[str, str]] = []
    for line in lines[start + 2 :]:
        if not line.lstrip().startswith("|"):
            break
        values = split_row(line)
        rows.append({header: values[index] if index < len(values) else "" for index, header in enumerate(headers)})
    if not rows:
        fail(f"{path} ## {heading} has no rows")
    return rows


def inline_list(text: str, key: str, path: Path) -> list[str]:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(\[[^\n]*\])\s*$", text)
    if not match:
        fail(f"{path} missing inline {key} list")
    try:
        value = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError) as error:
        fail(f"{path} invalid {key}: {error}")
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        fail(f"{path} {key} must be a non-empty string list")
    return value


def safe_path(root: Path, value: str, label: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or any(part == ".." for part in relative.parts):
        fail(f"{label} must stay inside the repository: {value}")
    configured = root / relative
    if configured.is_symlink():
        fail(f"{label} must not be a symlink: {value}")
    resolved = configured.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        fail(f"{label} resolves outside the repository: {value}")
    if not resolved.exists():
        fail(f"{label} does not exist: {value}")
    return resolved


def text_files(root: Path, inputs: list[str]) -> list[Path]:
    files: set[Path] = set()
    for value in inputs:
        path = safe_path(root, value, "evidence input")
        candidates = path.rglob("*") if path.is_dir() else [path]
        for candidate in candidates:
            if candidate.is_symlink():
                fail(f"evidence input tree contains a symlink: {candidate}")
            if candidate.is_file() and not any(
                part in EXCLUDED_PARTS for part in candidate.relative_to(root.resolve()).parts
            ):
                files.add(candidate.resolve())
    return sorted(files)


def readable_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > 5 * 1024 * 1024:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--version", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--task-name", required=True)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    packet = root / "docs" / "versions" / args.version / "modules" / args.module / args.task_name
    plan = packet / "pipeline" / "plan.md"
    design = plan if plan.is_file() else packet / "design.md"
    testplan = packet / "testplan.yaml"
    if not design.is_file() or not testplan.is_file():
        fail(f"missing design/pipeline or testplan for task packet: {packet}")

    rows = table_rows(design.read_text(encoding="utf-8"), "Consumer Migration Closure", design)
    inputs = inline_list(testplan.read_text(encoding="utf-8"), "evidence_inputs", testplan)
    files = text_files(root, inputs)
    allowed: dict[str, set[Path]] = {}
    symbols: set[str] = set()
    for index, row in enumerate(rows, start=1):
        symbol = row.get("old_symbol", "").strip().strip("`")
        status = row.get("migration_status", "").strip().lower()
        consumer = row.get("consumer_path", "").strip().strip("`")
        if not symbol or symbol.lower() in {"not-applicable", "none"}:
            continue
        symbols.add(symbol)
        if status in {"allowed-negative-fixture", "allowed-compatibility-shim"}:
            allowed.setdefault(symbol, set()).add(safe_path(root, consumer, "negative fixture"))
        elif status == "migrated":
            migrated = safe_path(root, consumer, "migrated consumer")
            content = readable_text(migrated)
            if content is None:
                fail(f"migrated consumer is not readable UTF-8 text: {consumer}")
            if symbol in content:
                fail(f"migrated consumer still references removed symbol {symbol}: {consumer}")
        elif status != "verified-none":
            fail(f"consumer row {index} has unsupported migration status: {status}")

    if not symbols:
        fail("consumer closure contains no concrete removed symbols")
    findings: list[str] = []
    for path in files:
        content = readable_text(path)
        if content is None:
            continue
        for symbol in symbols:
            if symbol in content and path not in allowed.get(symbol, set()):
                findings.append(f"{path.relative_to(root)}: {symbol}")
    if findings:
        fail("unallowlisted removed-symbol references remain:\n  " + "\n  ".join(findings))
    print("consumer-closure-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

