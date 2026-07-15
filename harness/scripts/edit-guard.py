#!/usr/bin/env python3
"""Claude Code PreToolUse hook: block production-code edits before admission.

Wire this in `.claude/settings.json` (see harness/claude-settings-hooks.example.json):
the hook receives the pending tool call as JSON on stdin and exits 2 to block it.
It turns the implementation-admission gate from a prose rule into a mechanical
one: editing production code is rejected until a valid admission stamp exists
under docs/versions/<version>/evidence/admission/.

A stamp is valid only when admission-check.py wrote it for a today-dated
evidence file and the recorded proposal.md/design.md hashes still match the
current documents, so a stamp goes stale the moment a bound document changes.
When valid stamps exist, the edited production path must additionally fall
inside the union of their admitted design Scope Paths.

The guard is a coarse backstop, not the full gate: admission-check.py remains
the authority on whether the evidence itself is valid, and
stage-scope-check.py remains the authority on the final recorded implementation task paths.
"""

from __future__ import annotations

import datetime
import fnmatch
import hashlib
import json
import sys
from pathlib import Path

GUARDED_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
EXEMPT_PREFIXES = ("docs/", ".claude/", ".git/")
EXEMPT_SUFFIXES = (".md", ".markdown", ".txt")
STAMP_SCHEMA = 1


def is_test_artifact(path: str) -> bool:
    parts = path.split("/")
    leaf = parts[-1].lower()
    return (
        "tests" in parts
        or "test" in parts
        or "__tests__" in parts
        or leaf.startswith("test_")
        or leaf.endswith("_test.py")
        or ".test." in leaf
        or ".spec." in leaf
        or leaf.endswith("_test.rs")
        or leaf.endswith("_tests.rs")
        or leaf in {"test.rs", "tests.rs"}
    )


def normalize(raw: str, project_dir: Path) -> str:
    path = Path(raw)
    if path.is_absolute():
        try:
            path = path.relative_to(project_dir)
        except ValueError:
            return ""
    return path.as_posix()


def lf_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stamp_scope_paths(stamp_path: Path, project_dir: Path) -> list[str] | None:
    """Return the stamp's scope paths when the stamp is still valid, else None."""
    try:
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None
    if not isinstance(stamp, dict) or stamp.get("schema") != STAMP_SCHEMA:
        return None

    evidence_file = stamp.get("evidence_file")
    if not isinstance(evidence_file, str) or not (project_dir / evidence_file).is_file():
        return None

    doc_hashes = stamp.get("doc_hashes")
    if not isinstance(doc_hashes, dict) or not doc_hashes:
        return None
    for rel_path, recorded in doc_hashes.items():
        doc = project_dir / rel_path
        try:
            if not doc.is_file() or lf_sha256(doc) != recorded:
                return None
        except (OSError, UnicodeDecodeError):
            return None

    scope_paths = stamp.get("scope_paths")
    if not isinstance(scope_paths, list) or not scope_paths:
        return None
    return [entry for entry in scope_paths if isinstance(entry, str) and entry]


def todays_admitted_scope(project_dir: Path) -> list[str]:
    versions_dir = project_dir / "docs" / "versions"
    if not versions_dir.is_dir():
        return []
    today = datetime.date.today().strftime("%Y%m%d")
    scope: list[str] = []
    for evidence_dir in sorted(versions_dir.glob("*/evidence/admission")):
        if not evidence_dir.is_dir():
            continue
        for stamp_path in evidence_dir.glob(f"{today}-*.stamp.json"):
            entries = stamp_scope_paths(stamp_path, project_dir)
            if not entries:
                continue
            for entry in entries:
                if entry not in scope:
                    scope.append(entry)
    return scope

def in_scope_paths(path: str, scope_paths: list[str]) -> bool:
    for entry in scope_paths:
        cleaned = entry.replace("\\", "/").strip("/")
        if path == cleaned or path.startswith(cleaned + "/"):
            return True
        if fnmatch.fnmatch(path, cleaned):
            return True
    return False


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return 0

    if event.get("tool_name") not in GUARDED_TOOLS:
        return 0
    raw_path = (event.get("tool_input") or {}).get("file_path") or (
        event.get("tool_input") or {}
    ).get("notebook_path")
    if not raw_path:
        return 0

    project_dir = Path(event.get("cwd") or ".").resolve()
    path = normalize(str(raw_path), project_dir)
    if not path:
        return 0
    if path.startswith(EXEMPT_PREFIXES) or path.endswith(EXEMPT_SUFFIXES):
        return 0
    if is_test_artifact(path):
        return 0

    scope = todays_admitted_scope(project_dir)
    if not scope:
        print(
            f"edit-guard: blocked edit to production file '{path}': no valid admission "
            "stamp dated today exists under docs/versions/<version>/evidence/admission/. "
            "Complete implementation admission first: read the approved proposal.md "
            "and design.md, create docs/versions/<version>/evidence/admission/<YYYYMMDD>-<task-slug>.md, "
            "and pass schema-check.py and admission-check.py (which writes the stamp). "
            "A stale stamp means a bound document changed after admission; rerun "
            "admission-check.py to regenerate it. "
            "See harness/rules/task-entry-gate-rules.md.",
            file=sys.stderr,
        )
        return 2

    if not in_scope_paths(path, scope):
        print(
            f"edit-guard: blocked edit to production file '{path}': the path is outside "
            f"the admitted design Scope Paths ({', '.join(scope)}). "
            "Extend the design Scope Paths coverage (via the owning design stage) and "
            "rerun admission-check.py, or split this edit into its own admitted task. "
            "See harness/rules/task-entry-gate-rules.md.",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
