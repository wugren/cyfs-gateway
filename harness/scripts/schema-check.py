#!/usr/bin/env python3
"""Validate the generated Harness Engineering module packet shape.

This template intentionally uses only the Python standard library. Adapt paths
or stricter YAML parsing after the target repository chooses its dependencies.
Only proposal.md and design.md are mandatory implementation-admission inputs.
testplan.yaml is validated when present; testing-coverage-check.py enforces it
for completed testing work.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from pathlib import Path


REQUIRED_FRONT_MATTER = (
    "module",
    "version",
    "status",
    "approved_by",
    "approved_at",
    "approved_content_sha256",
)
ALLOWED_LEVELS = {"unit", "dv", "integration"}
ALLOWED_MODES = {"enabled", "manual", "disabled"}
CONTRACT_KINDS = {
    "external-positive",
    "external-negative",
    "removed-symbol-scan",
    "repository-compile-closure",
    "documentation-examples",
}
CONTRACT_ASSERTIONS = {
    "external-positive": "new-path-compiles",
    "external-negative": "old-path-rejected-for-removed-symbol",
    "removed-symbol-scan": "no-unallowlisted-old-symbol-references",
    "repository-compile-closure": "repository-consumers-compile",
    "documentation-examples": "documentation-examples-compile",
}
PUBLIC_API_IMPACTS = {"none", "backward-compatible", "migration-required", "breaking"}
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
PLACEHOLDER_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo", "pending", '""', "''"}
TASK_NAME_RE = re.compile(r"^\d{3,}-[a-z0-9][a-z0-9_.-]*$")


def fail(message: str) -> None:
    print(f"schema-check: {message}", file=sys.stderr)
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
    """Return canonical document content excluding mutable approval metadata."""
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


def has_value(value: str) -> bool:
    return value.strip().strip('"').strip("'").lower() not in PLACEHOLDER_VALUES


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
    body = text[match.end() : end]
    fields: dict[str, str] = {}
    for line in body.splitlines():
        item = re.match(r"^\s*-\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$", line)
        if item:
            fields[item.group(1).strip()] = item.group(2).strip()
    return fields


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


def validate_pipeline_launch_evidence(
    root: Path, path: Path, module: str, version: str, task_name: str | None
) -> None:
    if not task_name:
        fail(f"{path} auto-pipeline approval requires a task-bound packet")
    plan = root / "docs" / "versions" / version / "modules" / module / task_name / "pipeline" / "plan.md"
    if not plan.exists():
        fail(
            f"{path} is approved by {PIPELINE_APPROVER} but {plan} is missing; "
            "auto-pipeline approval requires recorded launch evidence"
        )
    if not pipeline_no_stage_docs(root, version, module, task_name):
        fail(
            f"{path} is approved by {PIPELINE_APPROVER} but {plan} is not explicitly "
            f"bound to version={version}, packet_module={module}, task_name={task_name}"
        )


def validate_pipeline_state_link(packet: Path) -> None:
    plan = packet / "pipeline" / "plan.md"
    state_path = packet / "pipeline" / "state.json"
    if not state_path.is_file():
        fail(f"auto-pipeline requires sibling execution state: {state_path}")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid pipeline state {state_path}: {error}")
    if not isinstance(state, dict) or state.get("schema_version") != 1:
        fail(f"{state_path} schema_version must be 1")
    expected_hash = hashlib.sha256(
        plan.read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8")
    ).hexdigest()
    if state.get("plan_sha256") != expected_hash:
        fail(f"{state_path} plan_sha256 does not match sibling plan.md")


def validate_approval_provenance(root: Path, path: Path, text: str, data: dict[str, str]) -> None:
    if data.get("status") != "approved":
        return
    approved_by = data.get("approved_by", "").strip()
    approved_at = data.get("approved_at", "").strip()
    if not has_value(approved_by) or not has_value(approved_at):
        fail(f"{path} is approved but approved_by/approved_at are empty")
    recorded_hash = data.get("approved_content_sha256", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", recorded_hash):
        fail(f"{path} is approved but approved_content_sha256 is missing or invalid")
    expected_hash = approval_hash(text, path)
    if recorded_hash != expected_hash:
        fail(
            f"{path} approved_content_sha256 does not match approved content; "
            "approved documents are immutable and require a sibling amendment/fix task"
        )

    if approved_by == PIPELINE_APPROVER:
        validate_pipeline_launch_evidence(
            root, path, data.get("module", ""), data.get("version", ""), data.get("task_name")
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


def validate_doc(root: Path, path: Path, module: str, version: str, submodule: str | None = None) -> None:
    text = read_text(path)
    data = front_matter(text, path)
    missing = [field for field in REQUIRED_FRONT_MATTER if field not in data]
    if missing:
        fail(f"{path} missing front matter fields: {', '.join(missing)}")
    if data["module"] != module:
        fail(f"{path} module mismatch: expected {module}, got {data['module']}")
    if data["version"] != version:
        fail(f"{path} version mismatch: expected {version}, got {data['version']}")
    if submodule:
        validate_task_name(submodule, "--submodule")
        if data.get("task_name") != submodule:
            fail(f"{path} task_name mismatch: expected {submodule}, got {data.get('task_name', '<missing>')}")
    if submodule and data.get("submodule") not in {None, "", submodule}:
        fail(f"{path} submodule mismatch: expected {submodule}, got {data['submodule']}")
    validate_approval_provenance(root, path, text, data)


def extract_level_blocks(text: str) -> dict[str, str]:
    match = re.search(r"(?m)^levels:\s*$", text)
    if not match:
        fail("testplan.yaml missing levels")
    levels_text = text[match.end() :]
    starts = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", levels_text))
    blocks: dict[str, str] = {}
    for index, start in enumerate(starts):
        level = start.group(1)
        end = starts[index + 1].start() if index + 1 < len(starts) else len(levels_text)
        blocks[level] = levels_text[start.end() : end]
    return blocks


def validate_testplan(path: Path, module: str, version: str, submodule: str | None = None) -> None:
    text = read_text(path)
    step_ids: set[str] = set()
    for key, value in (("schema_version", "1"), ("version", version), ("module", module)):
        if not re.search(rf"(?m)^{re.escape(key)}:\s*{re.escape(value)}\s*$", text):
            fail(f"{path} missing or mismatched {key}: {value}")
    task_name_match = re.search(r"(?m)^task_name:\s*(\S+)\s*$", text)
    if not task_name_match:
        fail(f"{path} missing task_name")
    task_name = task_name_match.group(1)
    validate_task_name(task_name, f"{path} task_name")
    if submodule:
        validate_task_name(submodule, "--submodule")
        if task_name != submodule:
            fail(f"{path} task_name mismatch: expected {submodule}, got {task_name}")
    if submodule and re.search(r"(?m)^submodule:\s*\S+", text):
        if not re.search(rf"(?m)^submodule:\s*{re.escape(submodule)}\s*$", text):
            fail(f"{path} submodule mismatch: expected {submodule}")

    impact = re.search(r"(?ms)^api_impact:\s*$\n(.*?)(?=^[A-Za-z0-9_-]+:\s*|\Z)", text)
    if not impact:
        fail(f"{path} missing api_impact")
    impact_body = impact.group(1)
    public_api = re.search(r"(?m)^  public_api:\s*([A-Za-z0-9_-]+)\s*$", impact_body)
    if not public_api or public_api.group(1) not in PUBLIC_API_IMPACTS:
        fail(f"{path} api_impact.public_api must be one of: {', '.join(sorted(PUBLIC_API_IMPACTS))}")
    for key in ("crate_root_export_change", "build_surface_change", "documentation_examples_affected"):
        if not re.search(rf"(?m)^  {re.escape(key)}:\s*(true|false)\s*$", impact_body):
            fail(f"{path} api_impact.{key} must be true or false")

    evidence_inputs = re.search(r"(?m)^evidence_inputs:\s*(\[[^\n]*\])\s*$", text)
    if not evidence_inputs:
        fail(f"{path} missing inline evidence_inputs list")
    try:
        parsed_inputs = ast.literal_eval(evidence_inputs.group(1))
    except (SyntaxError, ValueError) as error:
        fail(f"{path} evidence_inputs is invalid: {error}")
    if not isinstance(parsed_inputs, list) or not parsed_inputs or not all(
        isinstance(item, str) and item not in {"", "."} for item in parsed_inputs
    ):
        fail(f"{path} evidence_inputs must be a non-empty list of repository-relative paths")
    if any(Path(item).is_absolute() or any(part == ".." for part in Path(item).parts) for item in parsed_inputs):
        fail(f"{path} evidence_inputs must stay inside the repository")

    contract = re.search(r"(?ms)^contract_checks:\s*$\n(.*?)(?=^[A-Za-z0-9_-]+:\s*|\Z)", text)
    if not contract:
        fail(f"{path} missing contract_checks")
    contract_body = contract.group(1)
    contract_mode = re.search(r"(?m)^  mode:\s*(enabled|disabled)\s*$", contract_body)
    if not contract_mode:
        fail(f"{path} contract_checks.mode must be enabled or disabled")
    contract_ids = re.findall(r"(?m)^    - id:\s*([A-Za-z0-9_.-]+)\s*$", contract_body)
    if contract_mode.group(1) == "disabled":
        if not re.search(r"(?m)^  reason:\s*\S.+$", contract_body):
            fail(f"{path} disabled contract_checks require a concrete reason")
        if contract_ids:
            fail(f"{path} disabled contract_checks must not declare steps")
    elif not contract_ids:
        fail(f"{path} enabled contract_checks require steps")
    for step_id in contract_ids:
        if step_id in step_ids:
            fail(f"{path} duplicate step id: {step_id}")
        step_ids.add(step_id)
        start = re.search(rf"(?m)^    - id:\s*{re.escape(step_id)}\s*$", contract_body)
        assert start is not None
        following = re.search(r"(?m)^    - id:\s*", contract_body[start.end() :])
        end = start.end() + following.start() if following else len(contract_body)
        block = contract_body[start.end() : end]
        kind = re.search(r"(?m)^      kind:\s*([A-Za-z0-9_-]+)\s*$", block)
        if not kind or kind.group(1) not in CONTRACT_KINDS:
            fail(f"{path} contract step {step_id} has missing or unsupported kind")
        assertion = re.search(r"(?m)^      assertion:\s*([A-Za-z0-9_-]+)\s*$", block)
        if not assertion or assertion.group(1) != CONTRACT_ASSERTIONS[kind.group(1)]:
            fail(f"{path} contract step {step_id} assertion does not match kind {kind.group(1)}")
        for key in ("name", "change_ids", "run"):
            pattern = rf"(?m)^      {key}:\s*\S.+$" if key == "name" else rf"(?m)^      {key}:\s*\[.+\]\s*$"
            if not re.search(pattern, block):
                fail(f"{path} contract step {step_id} must define {key}")

    blocks = extract_level_blocks(text)
    unknown = set(blocks) - ALLOWED_LEVELS
    if unknown:
        fail(f"{path} has unknown test levels: {', '.join(sorted(unknown))}")

    for level in sorted(ALLOWED_LEVELS):
        if level not in blocks:
            fail(f"{path} missing test level: {level}")
        block = blocks[level]
        mode_match = re.search(r"(?m)^    mode:\s*([A-Za-z0-9_-]+)\s*$", block)
        if not mode_match:
            fail(f"{path} level {level} missing mode")
        mode = mode_match.group(1)
        if mode not in ALLOWED_MODES:
            fail(f"{path} level {level} has invalid mode: {mode}")

        ids = re.findall(r"(?m)^      - id:\s*([A-Za-z0-9_.-]+)\s*$", block)
        if mode == "enabled" and not ids:
            fail(f"{path} enabled level {level} has no steps")
        if mode in {"manual", "disabled"} and not re.search(r"(?mi)reason:\s*\S+", block):
            fail(f"{path} {mode} level {level} missing reason")
        for step_id in ids:
            if step_id in step_ids:
                fail(f"{path} duplicate step id: {step_id}")
            step_ids.add(step_id)
            step_pattern = (
                rf"(?ms)^      - id:\s*{re.escape(step_id)}\s*$"
                rf".*?^        name:\s*\S+"
                rf".*?^        change_ids:\s*\[.+\]\s*$"
                rf".*?^        run:\s*\[.+\]\s*$"
            )
            if not re.search(step_pattern, block):
                fail(f"{path} step {step_id} must define name, change_ids, and run")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--version")
    parser.add_argument("--module")
    parser.add_argument("--submodule")
    parser.add_argument(
        "--print-approval-hash",
        metavar="DOCUMENT",
        help="print the approval hash for a stage document and exit",
    )
    args = parser.parse_args()

    root = Path(args.root)
    if args.print_approval_hash:
        path = Path(args.print_approval_hash)
        if not path.is_absolute():
            path = root / path
        text = read_text(path)
        print(approval_hash(text, path))
        return 0

    if not (args.version and args.module):
        fail("--version and --module are required")
    if args.submodule:
        validate_task_name(args.submodule, "--submodule")

    task_index = root / "docs" / "versions" / args.version / "modules" / "tasks.md"
    if not task_index.exists():
        fail(f"missing hard-gate unfinished-task index: docs/versions/{args.version}/modules/tasks.md")
    packet = root / "docs" / "versions" / args.version / "modules" / args.module
    if args.submodule:
        packet = packet / args.submodule
    no_stage_docs = pipeline_no_stage_docs(root, args.version, args.module, args.submodule)
    required_docs = ["proposal.md"] if no_stage_docs else ["proposal.md", "design.md"]
    for name in required_docs:
        validate_doc(root, packet / name, args.module, args.version, args.submodule)
    if no_stage_docs:
        validate_pipeline_state_link(packet)
        forbidden = ["design.md", "testing.md"]
        present = [name for name in forbidden if (packet / name).exists()]
        if present:
            fail(
                "auto-pipeline document policy forbids generated stage docs in this packet: "
                + ", ".join(str(packet / name) for name in present)
            )
        if (packet / "design").exists() or (packet / "testing").exists():
            fail("auto-pipeline document policy forbids task-local design/ or testing/ directories")
        optional_testplan = packet / "testplan.yaml"
        if optional_testplan.exists():
            validate_testplan(optional_testplan, args.module, args.version, args.submodule)
    else:
        optional_testing = packet / "testing.md"
        if optional_testing.exists():
            validate_doc(root, optional_testing, args.module, args.version, args.submodule)
        optional_testplan = packet / "testplan.yaml"
        if optional_testplan.exists():
            validate_testplan(optional_testplan, args.module, args.version, args.submodule)
    print("schema-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
