#!/usr/bin/env python3
"""Check implementation admission for explicit module/change ids.

The checker verifies mandatory proposal/design structure, approval state,
direct change traceability, and task-level admission evidence that records
the required document-reading and coverage judgment before code edits.

Evidence files are bound to the exact approved document content: they must
record LF-normalized sha256 hashes of proposal.md/design.md and verbatim
coverage quotes that the checker re-verifies against the current documents,
so stale or fabricated evidence fails closed.

On success the checker writes a machine-readable admission stamp
(`docs/versions/<version>/evidence/admission/<evidence-id>.<module>[.<submodule>][.<target-module>].stamp.json`)
recording the bound document hashes and the admitted design Scope Paths.
Later stages reuse the stamp while its bound inputs remain unchanged.
`--verify-only` is reserved for explicit audits or relevant-input changes.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path


FORBIDDEN_BROAD_IDS = {"all", "any", "bugfix", "change", "cleanup", "misc", "module", "refactor", "task"}
REQUIRED_DOCS = ("proposal.md", "design.md")
APPROVAL_DOCS = ("proposal.md", "design.md")
TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
REQUIRED_EVIDENCE_ITEMS = (
    "proposal_read",
    "design_read",
    "change_scope_matches_request",
    "active_module_resolved",
    "same_module_task_selection",
    "no_chat_only_evidence",
)
EMPTY_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo", "pending", '""', "''"}
PIPELINE_APPROVER = "auto-pipeline"
FORBIDDEN_APPROVERS = {
    "agent", "assistant", "ai", "bot", "llm", "model", "self", "auto",
    "claude", "codex", "copilot", "cursor", "gemini", "gpt",
}
APPROVAL_RECORD_FIELDS = ("approver", "approval_date", "user_statement")
APPROVAL_HASH_EXCLUDED_FIELDS = {
    "status",
    "approved_by",
    "approved_at",
    "approved_content_sha256",
}
EVIDENCE_FILENAME_RE = re.compile(r"^(\d{4})(\d{2})(\d{2})-[A-Za-z0-9][A-Za-z0-9_.-]*\.md$")
MIN_QUOTE_CHARS = 20
STAMP_SCHEMA = 1
TASK_NAME_RE = re.compile(r"^\d{3,}-[a-z0-9][a-z0-9_.-]*$")
MODULE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
def fail(message: str) -> None:
    print(f"admission-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path) -> str:
    if not path.exists():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def front_matter(text: str, path: Path) -> dict[str, str]:
    if not text.startswith("---\n"):
        fail(f"missing front matter: {path}")
    end = text.find("\n---", 4)
    if end == -1:
        fail(f"unterminated front matter: {path}")
    data: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def approval_hash_content(text: str, path: Path) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.startswith("---\n"):
        fail(f"missing front matter: {path}")
    front_end = normalized.find("\n---", 4)
    if front_end == -1:
        fail(f"unterminated front matter: {path}")
    kept_front_matter: list[str] = []
    for line in normalized[4:front_end].splitlines():
        key = line.split(":", 1)[0].strip() if ":" in line else ""
        if key not in APPROVAL_HASH_EXCLUDED_FIELDS:
            kept_front_matter.append(line)
    body = normalized[front_end + 4 :]
    approval = re.search(r"(?m)^##\s+Approval Record\s*$", body)
    if approval:
        next_heading = re.search(r"(?m)^##\s+", body[approval.end() :])
        section_end = approval.end() + next_heading.start() if next_heading else len(body)
        body = body[: approval.start()] + body[section_end:]
    return "---\n" + "\n".join(kept_front_matter) + "\n---" + body


def approval_hash(text: str, path: Path) -> str:
    return hashlib.sha256(approval_hash_content(text, path).encode("utf-8")).hexdigest()


def validate_change_id(change_id: str) -> None:
    if change_id.lower() in FORBIDDEN_BROAD_IDS:
        fail(f"change_id is too broad: {change_id}")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{2,63}", change_id):
        fail(f"change_id must be a stable 3-64 character id: {change_id}")


def validate_task_name(value: str, label: str) -> None:
    if not TASK_NAME_RE.fullmatch(value):
        fail(
            f"{label} must match <task-seq>-<task-slug> with a 3+ digit version-local "
            f"sequence prefix, for example 001-example-task: {value}"
        )

def approval_record_fields(text: str, path: Path) -> dict[str, str]:
    match = re.search(r"(?m)^##\s+Approval Record\s*$", text)
    if not match:
        fail(f"{path} is approved but missing required section: ## Approval Record")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    fields: dict[str, str] = {}
    for line in text[match.end() : end].splitlines():
        item = re.match(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
        if item:
            fields[item.group(1).strip()] = item.group(2).strip()
    return fields


def require_approval_provenance(root: Path, path: Path, text: str, data: dict[str, str]) -> None:
    approved_by = data.get("approved_by", "").strip()

    if approved_by == PIPELINE_APPROVER:
        if not pipeline_no_stage_docs(
            root, data.get("version", ""), data.get("module", ""), data.get("task_name")
        ):
            fail(
                f"{path} is approved by {PIPELINE_APPROVER} but the pipeline plan is not "
                "explicitly bound to this version/packet/task"
            )
        return

    if approved_by.lower() in FORBIDDEN_APPROVERS:
        fail(
            f"{path} approved_by '{approved_by}' looks like an agent self-approval; "
            "only the user or auto-pipeline (after explicit launch) may approve"
        )

    record = approval_record_fields(text, path)
    missing = [field for field in APPROVAL_RECORD_FIELDS if not has_value(record.get(field, ""))]
    if missing:
        fail(f"{path} ## Approval Record has missing or placeholder fields: {', '.join(missing)}")
    if record["approver"].strip() != approved_by:
        fail(
            f"{path} ## Approval Record approver '{record['approver'].strip()}' "
            f"does not match front matter approved_by '{approved_by}'"
        )


def require_approved(root: Path, path: Path, module: str, version: str, submodule: str | None = None) -> None:
    text = read_text(path)
    data = front_matter(text, path)
    if data.get("module") != module:
        fail(f"{path} module mismatch: expected {module}, got {data.get('module', '<missing>')}")
    if data.get("version") != version:
        fail(f"{path} version mismatch: expected {version}, got {data.get('version', '<missing>')}")
    if submodule:
        validate_task_name(submodule, "--submodule")
        if data.get("task_name") != submodule:
            fail(f"{path} task_name mismatch: expected {submodule}, got {data.get('task_name', '<missing>')}")
    if submodule and data.get("submodule") not in {None, "", submodule}:
        fail(f"{path} submodule mismatch: expected {submodule}, got {data.get('submodule')}")
    if data.get("status") != "approved":
        fail(f"{path} is not approved")
    if not has_value(data.get("approved_by", "")) or not has_value(data.get("approved_at", "")):
        fail(f"{path} approval metadata is incomplete")
    recorded_hash = data.get("approved_content_sha256", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", recorded_hash):
        fail(f"{path} approved_content_sha256 is missing or invalid")
    if recorded_hash != approval_hash(text, path):
        fail(
            f"{path} approved_content_sha256 does not match approved content; "
            "approved documents are immutable and require a sibling amendment/fix task"
        )
    require_approval_provenance(root, path, text, data)


def normalize_column(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def split_table_row(line: str) -> list[str]:
    parts = [part.strip() for part in line.strip().split("|")]
    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return parts


def table_rows_after_heading(text: str, heading: str, path: Path) -> list[dict[str, str]]:
    heading_pattern = re.compile(rf"(?m)^##\s+{re.escape(heading)}\s*$")
    match = heading_pattern.search(text)
    if not match:
        fail(f"{path} missing required section: ## {heading}")

    lines = text[match.end() :].splitlines()
    table_start = None
    for index, line in enumerate(lines):
        if re.match(r"^##\s+", line):
            break
        if "|" in line and index + 1 < len(lines) and TABLE_SEPARATOR_RE.match(lines[index + 1]):
            table_start = index
            break
    if table_start is None:
        fail(f"{path} section ## {heading} missing required table")

    headers = [normalize_column(cell) for cell in split_table_row(lines[table_start])]
    rows: list[dict[str, str]] = []
    for line in lines[table_start + 2 :]:
        if not line.strip() or not line.lstrip().startswith("|"):
            break
        values = split_table_row(line)
        row = {header: values[pos].strip() if pos < len(values) else "" for pos, header in enumerate(headers)}
        rows.append(row)
    if not rows:
        fail(f"{path} section ## {heading} has no data rows")
    return rows


def require_table_change(
    path: Path,
    text: str,
    heading: str,
    change_id: str,
    required_columns: tuple[str, ...],
    required_values: tuple[str, ...],
    target_module: str | None = None,
) -> dict[str, str]:
    rows = table_rows_after_heading(text, heading, path)
    available_columns = set(rows[0])
    missing_columns = [column for column in required_columns if column not in available_columns]
    if missing_columns:
        fail(f"{path} ## {heading} missing columns: {', '.join(missing_columns)}")

    matches = [row for row in rows if row.get("change_id") == change_id]
    if target_module is not None:
        matches = [row for row in matches if row.get("target_module") == target_module]
    if not matches:
        suffix = f" for target_module {target_module}" if target_module else ""
        fail(f"change_id {change_id}{suffix} missing from {path} ## {heading}")
    if len(matches) > 1:
        fail(f"change_id {change_id} appears multiple times in {path} ## {heading}")

    row = matches[0]
    empty_values = [column for column in required_values if not row.get(column)]
    if empty_values:
        fail(f"change_id {change_id} in {path} ## {heading} has empty fields: {', '.join(empty_values)}")
    return row


def section_body(text: str, heading: str, path: Path) -> str:
    match = re.search(rf"(?m)^##\s+{re.escape(heading)}\s*$", text)
    if not match:
        fail(f"{path} missing required section: ## {heading}")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    return text[match.end() : end]


def table_rows_in_section(text: str, heading: str, path: Path) -> list[dict[str, str]]:
    body = section_body(text, heading, path)
    lines = body.splitlines()
    table_start = None
    for index, line in enumerate(lines):
        if "|" in line and index + 1 < len(lines) and TABLE_SEPARATOR_RE.match(lines[index + 1]):
            table_start = index
            break
    if table_start is None:
        fail(f"{path} section ## {heading} missing required table")
    headers = [normalize_column(cell) for cell in split_table_row(lines[table_start])]
    rows: list[dict[str, str]] = []
    for line in lines[table_start + 2 :]:
        if not line.strip() or not line.lstrip().startswith("|"):
            break
        values = split_table_row(line)
        rows.append({header: values[pos].strip() if pos < len(values) else "" for pos, header in enumerate(headers)})
    if not rows:
        fail(f"{path} section ## {heading} has no data rows")
    return rows


def has_value(value: str) -> bool:
    return value.strip().lower() not in EMPTY_VALUES


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def lf_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def pipeline_trigger_value(text: str, label: str) -> str | None:
    match = re.search(rf"(?mi)^\s*-\s*{re.escape(label)}:\s*(.+)$", text)
    return match.group(1).strip() if match else None


def pipeline_no_stage_docs(
    root: Path, version: str, module: str, task_name: str | None
) -> bool:
    if not task_name:
        return False
    plan = root / "docs" / "versions" / version / "modules" / module / task_name / "pipeline" / "plan.md"
    if not plan.exists():
        return False
    text = plan.read_text(encoding="utf-8")
    launch = (pipeline_trigger_value(text, "User launch confirmed") or "").lower()
    launch_statement = pipeline_trigger_value(text, "User launch statement") or ""
    policy = (pipeline_trigger_value(text, "Auto-pipeline document policy") or "").lower()
    return (
        launch in {"yes", "true", "confirmed"}
        and len(launch_statement.strip()) >= 8
        and pipeline_trigger_value(text, "Version") == version
        and pipeline_trigger_value(text, "Packet module") == module
        and pipeline_trigger_value(text, "Task name") == task_name
        and (pipeline_trigger_value(text, "Proposal") or "").strip("`")
        == f"docs/versions/{version}/modules/{module}/{task_name}/proposal.md"
        and "no design/testing markdown docs" in policy
        and "testplan.yaml required" in policy
    )


def validate_evidence_filename(path: Path) -> None:
    match = EVIDENCE_FILENAME_RE.match(path.name)
    if not match:
        fail(
            f"evidence file name must match <YYYYMMDD>-<task-slug>.md: {path.name}"
        )
    try:
        stamp = datetime.date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        fail(f"evidence file name has an invalid date: {path.name}")
    if stamp > datetime.date.today():
        fail(f"evidence file name is dated in the future: {path.name}")


def validate_document_binding(text: str, path: Path, expected_docs: dict[str, Path]) -> None:
    rows = table_rows_in_section(text, "Document Binding", path)
    available = set(rows[0])
    if not {"doc", "sha256"} <= available:
        fail(f"{path} ## Document Binding must have doc and sha256 columns")
    recorded = {row.get("doc", "").strip(): row.get("sha256", "").strip().lower() for row in rows}
    for rel_path, doc_path in expected_docs.items():
        if rel_path not in recorded:
            fail(f"{path} ## Document Binding missing row for {rel_path}")
        actual = lf_sha256(doc_path)
        if recorded[rel_path] != actual:
            fail(
                f"{path} ## Document Binding hash mismatch for {rel_path}: "
                f"evidence was created against different document content; "
                f"re-read the document and regenerate the evidence "
                f"(current sha256 {actual})"
            )


def quote_block(text: str, leaf: str, change_id: str, path: Path) -> str:
    heading = re.search(
        rf"(?m)^###\s+Quote:\s+{re.escape(leaf)}\s+{re.escape(change_id)}\s*$", text
    )
    if not heading:
        fail(f"{path} missing section: ### Quote: {leaf} {change_id}")
    lines: list[str] = []
    for line in text[heading.end() :].splitlines():
        stripped = line.strip()
        if not stripped:
            if lines:
                break
            continue
        if stripped.startswith(">"):
            lines.append(stripped.lstrip(">").strip())
            continue
        break
    return "\n".join(lines)


def validate_coverage_quotes(
    text: str, path: Path, change_ids: list[str], doc_texts: dict[str, str]
) -> None:
    for change_id in change_ids:
        for leaf, doc_text in doc_texts.items():
            quote = normalize_ws(quote_block(text, leaf, change_id, path))
            if len(quote) < MIN_QUOTE_CHARS:
                fail(
                    f"{path} quote for {leaf} {change_id} is too short; "
                    f"quote the verbatim coverage row or sentence (>= {MIN_QUOTE_CHARS} chars)"
                )
            if change_id not in quote:
                fail(f"{path} quote for {leaf} {change_id} does not contain the change_id")
            if quote not in normalize_ws(doc_text):
                fail(
                    f"{path} quote for {leaf} {change_id} does not appear verbatim in {leaf}; "
                    "quotes must be copied from the current approved document"
                )


def validate_admission_evidence(path: Path, change_ids: list[str]) -> None:
    text = read_text(path)
    rows = table_rows_in_section(text, "Implementation Admission Evidence", path)
    available = set(rows[0])
    required_columns = {"evidence_item", "source", "status", "notes"}
    missing_columns = sorted(required_columns - available)
    if missing_columns:
        fail(f"{path} ## Implementation Admission Evidence missing columns: {', '.join(missing_columns)}")

    by_item = {row.get("evidence_item", "").strip(): row for row in rows if row.get("evidence_item", "").strip()}
    missing_items = [item for item in REQUIRED_EVIDENCE_ITEMS if item not in by_item]
    if missing_items:
        fail(f"{path} missing admission evidence items: {', '.join(missing_items)}")

    for item in REQUIRED_EVIDENCE_ITEMS:
        row = by_item[item]
        if row.get("status", "").strip().lower() != "pass":
            fail(f"{path} admission evidence item {item} must have status pass")
        if not has_value(row.get("source", "")):
            fail(f"{path} admission evidence item {item} must name a source")
        if not has_value(row.get("notes", "")):
            fail(f"{path} admission evidence item {item} must include notes")

    text_lower = text.lower()
    for change_id in change_ids:
        if change_id.lower() not in text_lower:
            fail(f"{path} must cite admitted change_id: {change_id}")


def parse_scope_paths(cell: str) -> list[str]:
    """Parse a design Scope Paths cell into repo-relative path entries.

    Entries are the backtick-wrapped tokens in the cell; without backticks the
    cell is split on commas. Each entry is a path prefix or fnmatch glob
    relative to the repository root.
    """
    entries = [match.group(1) for match in re.finditer(r"`([^`]+)`", cell)]
    if not entries:
        entries = cell.split(",")
    normalized: list[str] = []
    for entry in entries:
        cleaned = entry.strip().replace("\\", "/").strip("/")
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)
    return normalized


def admission_stamp_path(evidence_path: Path, args: argparse.Namespace) -> Path:
    stamp_name = evidence_path.stem + "." + args.module
    if args.submodule:
        stamp_name += "." + args.submodule
    if args.module == "globals":
        stamp_name += "." + args.target_module
    return evidence_path.parent / (stamp_name + ".stamp.json")


def admission_stamp_payload(
    root: Path,
    evidence_path: Path,
    args: argparse.Namespace,
    scope_paths: list[str],
    doc_paths: dict[str, Path],
) -> dict[str, object]:
    try:
        evidence_rel = evidence_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        evidence_rel = evidence_path.as_posix()
    return {
        "schema": STAMP_SCHEMA,
        "evidence_file": evidence_rel,
        "version": args.version,
        "module": args.module,
        "target_module": args.target_module,
        "submodule": args.submodule,
        "change_ids": list(args.change_ids),
        "doc_hashes": {rel_path: lf_sha256(path) for rel_path, path in doc_paths.items()},
        "scope_paths": scope_paths,
    }


def write_admission_stamp(
    root: Path,
    evidence_path: Path,
    args: argparse.Namespace,
    scope_paths: list[str],
    doc_paths: dict[str, Path],
) -> Path:
    stamp_path = admission_stamp_path(evidence_path, args)
    stamp = admission_stamp_payload(root, evidence_path, args, scope_paths, doc_paths)
    stamp["created_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    stamp_path.write_text(json.dumps(stamp, indent=2) + "\n", encoding="utf-8")
    return stamp_path


def verify_admission_stamp(
    root: Path,
    evidence_path: Path,
    args: argparse.Namespace,
    scope_paths: list[str],
    doc_paths: dict[str, Path],
) -> Path:
    stamp_path = admission_stamp_path(evidence_path, args)
    if not stamp_path.is_file():
        fail(f"missing machine-written admission stamp: {stamp_path}")
    try:
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as error:
        fail(f"invalid admission stamp {stamp_path}: {error}")
    if not isinstance(stamp, dict):
        fail(f"admission stamp must be a JSON object: {stamp_path}")
    expected = admission_stamp_payload(root, evidence_path, args, scope_paths, doc_paths)
    for key, value in expected.items():
        if stamp.get(key) != value:
            fail(f"admission stamp mismatch for {key}: {stamp_path}; rerun admission-check.py")
    if not has_value(str(stamp.get("created_at", ""))):
        fail(f"admission stamp missing created_at: {stamp_path}")
    return stamp_path


def yaml_list_contains(block: str, key: str, value: str) -> bool:
    inline = re.search(rf"(?m)^\s*{re.escape(key)}:\s*\[([^\]]*)\]\s*$", block)
    if inline:
        values = [item.strip().strip("\"'") for item in inline.group(1).split(",")]
        return value in values

    multiline = re.search(rf"(?ms)^\s*{re.escape(key)}:\s*\n((?:\s+-\s*[^\n]+\n?)+)", block)
    if multiline:
        values = [line.split("-", 1)[1].strip().strip("\"'") for line in multiline.group(1).splitlines()]
        return value in values
    return False


def extract_level_block(text: str, level: str) -> str:
    match = re.search(rf"(?m)^  {re.escape(level)}:\s*$", text)
    if not match:
        return ""
    next_level = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", text[match.end() :])
    end = match.end() + next_level.start() if next_level else len(text)
    return text[match.end() : end]


def extract_step_block(level_block: str, step_id: str) -> str:
    match = re.search(rf"(?m)^      - id:\s*{re.escape(step_id)}\s*$", level_block)
    if not match:
        return ""
    next_step = re.search(r"(?m)^      - id:\s*[A-Za-z0-9_.-]+\s*$", level_block[match.end() :])
    end = match.end() + next_step.start() if next_step else len(level_block)
    return level_block[match.start() : end]


def require_testplan_mapping(path: Path, text: str, change_id: str, testing_row: dict[str, str]) -> None:
    level = testing_row.get("testplan_level", "").strip()
    step_id = testing_row.get("testplan_step_id", "").strip()
    gap = testing_row.get("gap", "").strip().lower()
    gap_reason = testing_row.get("gap_manual_reason", "").strip()

    if not level:
        fail(f"change_id {change_id} in testing.md must declare testplan_level")
    level_block = extract_level_block(text, level)
    if not level_block:
        fail(f"change_id {change_id} references missing testplan level: {level}")

    if level in {"manual", "disabled"} or gap in {"yes", "manual", "disabled"}:
        if not gap_reason:
            fail(f"change_id {change_id} declares a gap/manual path without a reason in testing.md")
        if not yaml_list_contains(level_block, "change_ids", change_id):
            fail(f"change_id {change_id} must appear in testplan.yaml level {level} change_ids")
        return

    if not step_id:
        fail(f"change_id {change_id} in testing.md must declare testplan_step_id")
    step_block = extract_step_block(level_block, step_id)
    if not step_block:
        fail(f"change_id {change_id} references missing testplan step: {level}/{step_id}")
    if not yaml_list_contains(step_block, "change_ids", change_id):
        fail(f"change_id {change_id} must appear in testplan.yaml step {level}/{step_id} change_ids")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--version", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--submodule")
    parser.add_argument("--target-module")
    parser.add_argument("--change-id", action="append", dest="change_ids")
    parser.add_argument(
        "--evidence-file",
        help="task evidence file containing ## Implementation Admission Evidence",
    )
    parser.add_argument(
        "--print-doc-hashes",
        action="store_true",
        help="print the LF-normalized sha256 hashes needed for ## Document Binding and exit",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="validate existing admission evidence without rewriting its stamp",
    )
    args = parser.parse_args()

    root = Path(args.root)
    if args.submodule:
        validate_task_name(args.submodule, "--submodule")
    if args.module == "globals":
        if not args.target_module or args.target_module == "globals":
            fail("--module globals requires a concrete --target-module for independent project admission")
    else:
        if args.target_module and args.target_module != args.module:
            fail("--target-module may differ from --module only when --module globals")
        args.target_module = args.module
    if not MODULE_NAME_RE.fullmatch(args.target_module):
        fail(f"invalid --target-module: {args.target_module}")
    task_index = root / "docs" / "versions" / args.version / "modules" / "tasks.md"
    if not task_index.exists():
        fail(f"missing hard-gate unfinished-task index: docs/versions/{args.version}/modules/tasks.md")
    packet = root / "docs" / "versions" / args.version / "modules" / args.module
    packet_rel = f"docs/versions/{args.version}/modules/{args.module}"
    if args.submodule:
        packet = packet / args.submodule
        packet_rel = f"{packet_rel}/{args.submodule}"
    no_stage_docs = pipeline_no_stage_docs(root, args.version, args.module, args.submodule)
    required_docs = ["proposal.md"] if no_stage_docs else list(REQUIRED_DOCS)
    for name in required_docs:
        if not (packet / name).exists():
            fail(f"missing required file: {packet / name}")
    if no_stage_docs:
        forbidden = ["design.md", "testing.md"]
        present = [name for name in forbidden if (packet / name).exists()]
        if present:
            fail(
                "auto-pipeline document policy forbids generated stage docs in this packet: "
                + ", ".join(str(packet / name) for name in present)
            )
        if (packet / "design").exists() or (packet / "testing").exists():
            fail("auto-pipeline document policy forbids task-local design/ or testing/ directories")
    doc_paths = {f"{packet_rel}/{name}": packet / name for name in required_docs}
    if no_stage_docs:
        plan = packet / "pipeline" / "plan.md"
        if not plan.exists():
            fail(f"auto-pipeline no-doc admission requires task-local plan: {plan}")
        doc_paths[f"{packet_rel}/pipeline/plan.md"] = plan

    if args.print_doc_hashes:
        for rel_path, doc_path in doc_paths.items():
            print(f"| {rel_path} | {lf_sha256(doc_path)} |")
        return 0

    if not args.change_ids:
        fail("--change-id is required")
    if not args.evidence_file:
        fail("--evidence-file is required")
    approval_docs = [] if no_stage_docs else list(APPROVAL_DOCS)
    for name in approval_docs:
        require_approved(root, packet / name, args.module, args.version, args.submodule)

    docs = {name: read_text(packet / name) for name in required_docs}
    if no_stage_docs:
        docs["pipeline-plan.md"] = read_text(packet / "pipeline" / "plan.md")
    scope_paths: list[str] = []
    for change_id in args.change_ids:
        validate_change_id(change_id)
        require_table_change(
            packet / "proposal.md",
            docs["proposal.md"],
            "Proposal Items",
            change_id,
            ("proposal_id", "change_id", "requirement", "success_evidence"),
            ("proposal_id", "requirement", "success_evidence"),
        )
        if no_stage_docs:
            design_row = require_table_change(
                packet / "pipeline" / "plan.md",
                docs["pipeline-plan.md"],
                "Implementation Scope Bindings",
                change_id,
                ("change_id", "target_module", "proposal_id", "design_coverage", "scope_paths"),
                ("target_module", "proposal_id", "design_coverage", "scope_paths"),
                args.target_module,
            )
        else:
            design_row = require_table_change(
                packet / "design.md",
                docs["design.md"],
                "Directly Mapped Change Items",
                change_id,
                ("change_id", "target_module", "proposal_id", "design_coverage", "scope_paths"),
                ("target_module", "proposal_id", "design_coverage", "scope_paths"),
                args.target_module,
            )
        entries = parse_scope_paths(design_row.get("scope_paths", ""))
        if not entries:
            fail(
                f"change_id {change_id} has no parsable Scope Paths entries in "
                + (f"{packet_rel}/pipeline/plan.md" if no_stage_docs else "design.md")
                + "; record concrete repo-relative paths or globs (backtick-wrapped) so the "
                "implementation task paths can be scoped mechanically"
            )
        for entry in entries:
            if entry not in scope_paths:
                scope_paths.append(entry)

    evidence_path = Path(args.evidence_file)
    if not evidence_path.is_absolute():
        evidence_path = Path(args.root) / evidence_path
    expected_evidence_dir = root / "docs" / "versions" / args.version / "evidence" / "admission"
    try:
        if evidence_path.parent.resolve() != expected_evidence_dir.resolve():
            fail(
                "--evidence-file must be under "
                f"docs/versions/{args.version}/evidence/admission/ for this version"
            )
    except OSError as error:
        fail(f"cannot resolve evidence directory for {evidence_path}: {error}")
    validate_evidence_filename(evidence_path)
    validate_admission_evidence(evidence_path, args.change_ids)
    evidence_text = read_text(evidence_path)
    validate_document_binding(
        evidence_text,
        evidence_path,
        doc_paths,
    )
    validate_coverage_quotes(evidence_text, evidence_path, args.change_ids, docs)
    if args.verify_only:
        stamp_path = verify_admission_stamp(root, evidence_path, args, scope_paths, doc_paths)
    else:
        stamp_path = write_admission_stamp(root, evidence_path, args, scope_paths, doc_paths)
    print("admission-check: passed")
    print("implementation admission evidence: passed")
    if not args.verify_only:
        print(f"admission stamp written: {stamp_path}")
    else:
        print(f"admission stamp verified without rewrite: {stamp_path}")
    print(f"admitted scope paths: {', '.join(scope_paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
