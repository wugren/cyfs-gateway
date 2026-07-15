#!/usr/bin/env python3
"""Validate that an acceptance report contains enforceable review evidence.

Beyond report structure, this checker re-verifies execution evidence. Accepted
reports must either reference task-relevant machine-written test artifacts
(test-run.py writes test-results/test-runs/*.json) with non-empty successful
executed steps, or record a structured automated-test exception with reason,
owner, risk, acceptance impact, and alternative evidence. Pasted command
output alone is not acceptance evidence. Single-task acceptance uses only the
active task's test artifact; package/module, whole-project, and quality-gate
runs are not automatic task evidence. Risk-triggered API/build-surface tasks
also require their contract kinds/assertions and a current scoped
evidence_input_sha256 binding.

The checker also requires a category-by-category implementation correctness
audit. Passing tests cannot replace explicit review of logic, progress,
concurrency, resource lifetime, state integrity, recovery, boundaries, and
security/capacity safety.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
EMPTY_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo", "pending"}
BLOCKING_EVIDENCE_STATUSES = {"missing", "inconsistent", "logically invalid"}
BLOCKING_TEST_STATUSES = {"gap", "stale", "not runnable"}
BLOCKING_RULE_STATUSES = {"fail", "gap"}
ALLOWED_CORRECTNESS_STATUSES = {"pass", "fail", "not applicable"}
ALLOWED_CORRECTNESS_STAGES = {"none", "proposal", "design", "implementation", "testing"}
REQUIRED_CORRECTNESS_CATEGORIES = {
    "logic and control flow",
    "termination and progress",
    "concurrency and synchronization",
    "resource lifetime and cleanup",
    "state and data integrity",
    "error handling and recovery",
    "interface boundary and compatibility",
    "security and capacity safety",
}
HIGH_SEVERITIES = {"critical", "high"}
ALLOWED_SEVERITIES = {"none", "low", "medium", "high", "critical"}
REQUIRED_VALIDATION_LABELS = (
    "Existing schema result",
    "Existing admission stamp",
    "Existing stage-scope result",
    "Task-relevant test run artifact",
    "Commands rerun because checker-owned inputs changed",
)
RUN_ARTIFACT_RE = re.compile(
    r"test-results/(test-runs|quality-runs)/[A-Za-z0-9+_.-]+\.json"
)
RUN_ARTIFACT_SCHEMA = 1
CONTRACT_ASSERTIONS = {
    "external-positive": "new-path-compiles",
    "external-negative": "old-path-rejected-for-removed-symbol",
    "removed-symbol-scan": "no-unallowlisted-old-symbol-references",
    "repository-compile-closure": "repository-consumers-compile",
    "documentation-examples": "documentation-examples-compile",
}
QUALITY_GATES_CONFIG = "harness/quality-gates.yaml"
NOT_APPLICABLE_RE = re.compile(
    r"\b(not applicable|not required|not relevant|out of scope|no automated tests?|no runnable tests?)\b",
    re.IGNORECASE,
)
AUTOMATED_TEST_EXCEPTION_FIELDS = (
    "Reason",
    "Owner",
    "Risk",
    "Acceptance impact",
    "Alternative evidence",
)


def fail(message: str) -> None:
    print(f"acceptance-report-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: Path) -> str:
    if not path.exists():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def normalize_column(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def split_table_row(line: str) -> list[str]:
    parts = [part.strip() for part in line.strip().split("|")]
    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return parts


def non_empty(value: str) -> bool:
    return value.strip().lower() not in EMPTY_VALUES


def section_body(text: str, heading: str, path: Path) -> str:
    match = re.search(rf"(?m)^##\s+{re.escape(heading)}\s*$", text)
    if not match:
        fail(f"{path} missing required section: ## {heading}")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    return text[match.end() : end]


def table_rows(text: str, heading: str, path: Path) -> list[dict[str, str]]:
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


def require_columns(path: Path, heading: str, rows: list[dict[str, str]], columns: tuple[str, ...]) -> None:
    missing = sorted(set(columns) - set(rows[0]))
    if missing:
        fail(f"{path} ## {heading} missing columns: {', '.join(missing)}")


def conclusion(text: str, path: Path) -> str:
    body = section_body(text, "Conclusion", path).lower()
    if re.search(r"accepted\s*/\s*rejected\s*/\s*needs changes:\s*accepted\b", body):
        return "accepted"
    if re.search(r"accepted\s*/\s*rejected\s*/\s*needs changes:\s*rejected\b", body):
        return "rejected"
    if re.search(r"accepted\s*/\s*rejected\s*/\s*needs changes:\s*needs changes\b", body):
        return "needs changes"
    fail(f"{path} Conclusion must explicitly select accepted, rejected, or needs changes")


def check_nonempty_rows(path: Path, heading: str, rows: list[dict[str, str]], skip: set[str] | None = None) -> None:
    skip = skip or set()
    for index, row in enumerate(rows, start=1):
        for column, value in row.items():
            if column in skip:
                continue
            if not non_empty(value):
                fail(f"{path} ## {heading} row {index} column {column} is empty placeholder content")


def check_implementation_correctness_audit(path: Path, text: str, result: str) -> None:
    heading = "Implementation Correctness Audit"
    rows = table_rows(text, heading, path)
    require_columns(
        path,
        heading,
        rows,
        (
            "category",
            "applicable_scope",
            "evidence_reviewed",
            "finding_reason_not_applicable",
            "owning_stage",
            "status",
        ),
    )
    check_nonempty_rows(path, heading, rows, skip={"owning_stage"})

    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        category = re.sub(r"\s+", " ", row.get("category", "").strip().lower())
        if category in seen:
            fail(f"{path} ## {heading} repeats category: {category}")
        seen.add(category)

        status = re.sub(r"\s+", " ", row.get("status", "").strip().lower())
        if status not in ALLOWED_CORRECTNESS_STATUSES:
            fail(f"{path} ## {heading} row {index} has invalid status: {row.get('status')}")

        stage = row.get("owning_stage", "").strip().lower()
        if stage not in ALLOWED_CORRECTNESS_STAGES:
            fail(f"{path} ## {heading} row {index} has invalid owning stage: {row.get('owning_stage')}")
        if status == "fail" and stage not in {"proposal", "design", "implementation", "testing"}:
            fail(f"{path} ## {heading} failing row {index} must name its owning upstream stage")
        if status != "fail" and stage != "none":
            fail(f"{path} ## {heading} non-failing row {index} must use owning stage: none")
        if result == "accepted" and status == "fail":
            fail(f"{path} accepted conclusion has failing implementation correctness category: {category}")
        if status == "not applicable":
            reason = row.get("finding_reason_not_applicable", "").strip()
            if len(reason) < 12:
                fail(f"{path} ## {heading} row {index} needs a concrete not-applicable reason")

    missing = sorted(REQUIRED_CORRECTNESS_CATEGORIES - seen)
    if missing:
        fail(f"{path} ## {heading} missing required categories: {', '.join(missing)}")


def load_run_artifact(root: Path, rel_path: str) -> dict[str, object]:
    artifact_path = root / rel_path
    if not artifact_path.is_file():
        fail(f"referenced run artifact does not exist: {rel_path}")
    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        fail(f"referenced run artifact is not valid JSON: {rel_path}: {error}")
    if not isinstance(artifact, dict) or artifact.get("schema") != RUN_ARTIFACT_SCHEMA:
        fail(f"referenced run artifact has an unsupported schema: {rel_path}")
    return artifact


def required_contract_kinds(root: Path, scope: dict[str, object]) -> set[str]:
    packet = (
        root
        / "docs"
        / "versions"
        / str(scope["version"])
        / "modules"
        / str(scope["module"])
        / str(scope["task_name"])
    )
    plan = packet / "pipeline" / "plan.md"
    design = plan if plan.is_file() else packet / "design.md"
    if not design.is_file():
        return set()
    text = design.read_text(encoding="utf-8")
    section = re.search(r"(?ms)^##\s+API and Build Surface Impact\s*$\n(.*?)(?=^##\s+|\Z)", text)
    if not section:
        return set()
    body = section.group(1)
    public = re.search(r"(?im)^\s*-\s*Public API impact:\s*([A-Za-z0-9_-]+)\s*$", body)
    public_api = public.group(1).lower() if public else ""
    required: set[str] = set()
    if public_api == "breaking" or re.search(r"(?im)^\s*-\s*Compatibility:\s*breaking\s*$", text):
        required.update({"external-positive", "external-negative", "removed-symbol-scan", "repository-compile-closure"})
    elif public_api == "migration-required" or re.search(r"(?im)^\s*-\s*Compatibility:\s*migration-required\s*$", text):
        required.update({"external-positive", "removed-symbol-scan", "repository-compile-closure"})
    if re.search(r"(?im)^\s*-\s*Crate-root export change:\s*yes\s*$", body):
        required.update({"external-positive", "repository-compile-closure"})
    if re.search(r"(?im)^\s*-\s*Build-surface change:\s*yes\s*$", body):
        required.add("repository-compile-closure")
    if re.search(r"(?im)^\s*-\s*Documentation examples affected:\s*yes\s*$", body):
        required.add("documentation-examples")
    if plan.is_file():
        compatibilities = re.findall(
            r"(?im)^\|[^\n]*\|\s*(new|backward-compatible|migration-required|breaking)\s*\|[^\n]*$",
            text,
        )
        if "breaking" in {value.lower() for value in compatibilities}:
            required.update({"external-positive", "external-negative", "removed-symbol-scan", "repository-compile-closure"})
        elif "migration-required" in {value.lower() for value in compatibilities}:
            required.update({"external-positive", "removed-symbol-scan", "repository-compile-closure"})
    return required


def required_risk_evidence_paths(root: Path, scope: dict[str, object]) -> set[str]:
    packet = (
        root / "docs" / "versions" / str(scope["version"]) / "modules"
        / str(scope["module"]) / str(scope["task_name"])
    )
    plan = packet / "pipeline" / "plan.md"
    design = plan if plan.is_file() else packet / "design.md"
    text = design.read_text(encoding="utf-8")
    paths: set[str] = set()
    for row in table_rows(text, "Consumer Migration Closure", design):
        if row.get("migration_status", "").strip().lower() == "verified-none":
            continue
        value = row.get("consumer_path", "").strip().strip("`")
        if value:
            paths.add(value)
    heading = "Implementation Scope Bindings" if plan.is_file() else "Directly Mapped Change Items"
    for row in table_rows(text, heading, design):
        if row.get("change_id", "").strip() not in scope["change_ids"]:
            continue
        for value in re.split(r"\s*(?:,|<br\s*/?>)\s*", row.get("scope_paths", "")):
            cleaned = re.split(r"[*?\[]", value.strip().strip("`"), maxsplit=1)[0].rstrip("/")
            if cleaned:
                paths.add(cleaned)
    return paths


def roots_cover_path(roots: list[str], path: str) -> bool:
    target = Path(path)
    return any(target == Path(root) or Path(root) in target.parents for root in roots)


def current_evidence_input_binding(
    root: Path, roots: list[str], expected_testplan: str
) -> tuple[list[str], str]:
    root_resolved = root.resolve()
    paths: set[Path] = {(root / expected_testplan).resolve()}
    for relative_root in roots:
        if relative_root in {"", "."} or Path(relative_root).is_absolute() or any(
            part == ".." for part in Path(relative_root).parts
        ):
            fail(f"artifact has invalid evidence input root: {relative_root}")
        configured = root / relative_root
        if configured.is_symlink():
            fail(f"artifact evidence input root is a symlink: {relative_root}")
        candidate = configured.resolve()
        try:
            candidate.relative_to(root_resolved)
        except ValueError:
            fail(f"artifact evidence input resolves outside repository: {relative_root}")
        if not candidate.exists():
            fail(f"artifact evidence input root is missing: {relative_root}")
        if candidate.is_dir():
            for child in candidate.rglob("*"):
                if child.is_symlink():
                    fail(f"artifact evidence input tree contains a symlink: {child}")
                if child.is_file() and not any(
                    part in {".git", ".venv", "target", "test-results", "__pycache__"}
                    for part in child.relative_to(root_resolved).parts
                ):
                    paths.add(child.resolve())
        elif candidate.is_file():
            paths.add(candidate)
    hasher = hashlib.sha256(b"harness-task-evidence-input-v1\0")
    relative_paths = sorted(path.relative_to(root_resolved).as_posix() for path in paths)
    for relative in relative_paths:
        path = root / relative
        hasher.update(relative.encode("utf-8") + b"\0" + path.read_bytes() + b"\0")
    return relative_paths, hasher.hexdigest()


def configured_quality_gate_ids(root: Path) -> set[str] | None:
    """Return configured gate ids, an empty set, or None for missing/malformed config."""
    config = root / QUALITY_GATES_CONFIG
    if not config.is_file():
        return None
    text = config.read_text(encoding="utf-8")
    if re.search(r"(?m)^gates:\s*\[\s*\]\s*$", text):
        return set()
    gates_line = re.search(r"(?m)^gates:\s*$", text)
    if not gates_line:
        return None
    gate_ids = set(re.findall(r"(?m)^\s*-\s*id:\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*$", text[gates_line.end() :]))
    return gate_ids or None


def command_value(command_body: str, label: str) -> str | None:
    pattern = rf"(?im)^\s*-\s+.*{re.escape(label)}.*:\s*(.+)$"
    match = re.search(pattern, command_body)
    return match.group(1).strip() if match else None


def check_automated_test_exception(text: str, path: Path) -> None:
    body = section_body(text, "Automated Test Exception", path)
    applies = re.search(r"(?im)^\s*-\s+Applies:\s*(yes|true)\s*$", body)
    if not applies:
        fail(f"{path} Automated Test Exception must explicitly set Applies: yes")
    for label in AUTOMATED_TEST_EXCEPTION_FIELDS:
        match = re.search(rf"(?im)^\s*-\s+{re.escape(label)}:\s*(.+)$", body)
        value = match.group(1).strip().strip('"').strip("'") if match else ""
        if not match or not non_empty(value):
            fail(f"{path} Automated Test Exception missing concrete {label}")
    reason = re.search(r"(?im)^\s*-\s+Reason:\s*(.+)$", body)
    if reason and len(reason.group(1).strip()) < 12:
        fail(f"{path} Automated Test Exception reason is too short to be actionable")


def object_scope(text: str, path: Path) -> dict[str, object]:
    body = section_body(text, "Object and Scope", path)
    values: dict[str, str] = {}
    for label in ("Module", "Version", "Task name", "change_id values reviewed"):
        match = re.search(rf"(?im)^\s*-\s+{re.escape(label)}:\s*(.+)$", body)
        if not match or not non_empty(match.group(1)):
            fail(f"{path} Object and Scope missing concrete value for {label}")
        values[label] = match.group(1).strip()
    task_name = values["Task name"]
    if not re.fullmatch(r"\d{3,}-[a-z0-9][a-z0-9_.-]*", task_name):
        fail(f"{path} Object and Scope has invalid Task name: {task_name}")
    change_ids = {
        item.strip().strip("`")
        for item in values["change_id values reviewed"].split(",")
        if item.strip()
    }
    if not change_ids:
        fail(f"{path} Object and Scope must list reviewed change_id values")
    return {
        "module": values["Module"],
        "version": values["Version"],
        "task_name": task_name,
        "change_ids": change_ids,
        "task_scope": f"{values['Module']}/{task_name}",
    }


def check_run_artifacts(
    path: Path,
    text: str,
    root: Path,
    result: str,
    scope: dict[str, object],
) -> None:
    referenced_paths = sorted(set(match.group(0) for match in RUN_ARTIFACT_RE.finditer(text)))
    artifacts = {rel: load_run_artifact(root, rel) for rel in referenced_paths}

    if result != "accepted":
        return

    for rel, artifact in artifacts.items():
        if artifact.get("exit_code") != 0:
            fail(
                f"{path} referenced run artifact must be passing for an accepted "
                f"report: {rel}"
            )

    task_artifacts: list[str] = []
    required_contracts = required_contract_kinds(root, scope)
    expected_testplan = (
        f"docs/versions/{scope['version']}/modules/{scope['module']}/"
        f"{scope['task_name']}/testplan.yaml"
    )
    for rel, artifact in artifacts.items():
        if "/test-runs/" not in rel:
            continue
        if artifact.get("requested_module") != scope["task_scope"]:
            continue
        if artifact.get("requested_level") != "all":
            continue
        testplans = artifact.get("testplans")
        if not isinstance(testplans, list) or expected_testplan not in testplans:
            continue
        artifact_change_ids = artifact.get("change_ids")
        if not isinstance(artifact_change_ids, list) or not all(
            isinstance(item, str) for item in artifact_change_ids
        ):
            continue
        if not scope["change_ids"] <= set(artifact_change_ids):
            continue
        steps = artifact.get("steps")
        if not isinstance(steps, list) or not steps:
            continue
        if any(
            not isinstance(step, dict)
            or step.get("exit_code") != 0
            or not isinstance(step.get("command"), list)
            or not step.get("command")
            or not isinstance(step.get("sources"), list)
            or not step.get("sources")
            for step in steps
        ):
            continue
        if required_contracts:
            seen_contracts: dict[str, str] = {}
            for step in steps:
                if not isinstance(step, dict):
                    continue
                for source in step.get("sources", []):
                    if not isinstance(source, dict):
                        continue
                    kind = source.get("contract_kind")
                    assertion = source.get("assertion")
                    if isinstance(kind, str) and isinstance(assertion, str):
                        seen_contracts[kind] = assertion
            missing_contracts = required_contracts - set(seen_contracts)
            if missing_contracts or any(
                seen_contracts.get(kind) != CONTRACT_ASSERTIONS[kind]
                for kind in required_contracts
            ):
                continue
            evidence_inputs = artifact.get("evidence_inputs")
            evidence_roots = artifact.get("evidence_input_roots")
            recorded_hash = artifact.get("evidence_input_sha256")
            current_inputs, current_hash = current_evidence_input_binding(
                root,
                evidence_roots if isinstance(evidence_roots, list) and all(isinstance(item, str) for item in evidence_roots) else [],
                expected_testplan,
            )
            if (
                not isinstance(evidence_inputs, list)
                or not evidence_inputs
                or not all(isinstance(item, str) for item in evidence_inputs)
                or not isinstance(evidence_roots, list)
                or not evidence_roots
                or any(
                    not roots_cover_path(evidence_roots, required_path)
                    for required_path in required_risk_evidence_paths(root, scope)
                )
                or not isinstance(recorded_hash, str)
                or current_inputs != sorted(evidence_inputs)
                or current_hash != recorded_hash
            ):
                continue
        task_artifacts.append(rel)
    test_run_ok = bool(task_artifacts)
    command_body = section_body(text, "Validation Evidence", path)
    test_artifact_value = command_value(command_body, "Task-relevant test run artifact") or ""
    if not test_run_ok:
        if not NOT_APPLICABLE_RE.search(test_artifact_value):
            fail(
                f"{path} accepted conclusion requires a referenced passing task run for "
                f"{scope['task_scope']} all covering change_ids "
                f"{', '.join(sorted(scope['change_ids']))} from {expected_testplan}, or a structured "
                "Automated Test Exception"
            )
        check_automated_test_exception(text, path)

    quality_value = command_value(command_body, "Quality gates") or ""
    quality_claims_run = non_empty(quality_value) and not NOT_APPLICABLE_RE.search(quality_value)
    if quality_claims_run:
        configured_gate_ids = configured_quality_gate_ids(root)
        if configured_gate_ids is None:
            fail(f"{path} cannot determine configured quality gates from {QUALITY_GATES_CONFIG}")
        quality_artifact_ok = any(
            "/quality-runs/" in rel
            and isinstance(artifact.get("gates"), list)
            and bool(artifact.get("gates"))
            and {str(gate.get("id", "")) for gate in artifact["gates"] if isinstance(gate, dict)}
            == configured_gate_ids
            and all(
                isinstance(gate, dict)
                and non_empty(str(gate.get("id", "")))
                and isinstance(gate.get("command"), list)
                and bool(gate.get("command"))
                and gate.get("exit_code") == 0
                for gate in artifact["gates"]
            )
            for rel, artifact in artifacts.items()
        )
        if not quality_artifact_ok:
            fail(
                f"{path} reports explicitly requested quality gates without citing a passing "
                "test-results/quality-runs/*.json artifact"
            )


def check_report(path: Path, text: str, root: Path) -> None:
    result = conclusion(text, path)
    scope = object_scope(text, path)
    expected_report = (
        root
        / "docs"
        / "versions"
        / str(scope["version"])
        / "modules"
        / str(scope["module"])
        / str(scope["task_name"])
        / "acceptance-report.md"
    )
    try:
        if path.resolve() != expected_report.resolve():
            fail(f"{path} Object and Scope does not match report task packet path: {expected_report}")
    except OSError as error:
        fail(f"cannot resolve acceptance report task binding: {error}")

    findings = table_rows(text, "Findings", path)
    require_columns(path, "Findings", findings, ("id", "severity", "stage", "evidence", "problem", "fail_condition_hit"))
    # severity legitimately uses the value "none" for no-finding rows; its
    # validity is checked against ALLOWED_SEVERITIES below instead.
    check_nonempty_rows(path, "Findings", findings, skip={"fail_condition_hit", "severity"})
    for index, row in enumerate(findings, start=1):
        severity = row.get("severity", "").strip().lower()
        if severity not in ALLOWED_SEVERITIES:
            fail(f"{path} Findings row {index} has invalid severity: {row.get('severity')}")
        if result == "accepted" and severity in HIGH_SEVERITIES:
            fail(f"{path} accepted conclusion cannot contain {severity} findings")
        if result == "accepted" and non_empty(row.get("fail_condition_hit", "")):
            fail(f"{path} accepted conclusion cannot cite a fail condition in Findings row {index}")

    result_summary = section_body(text, "Result Summary", path)
    summary_values: dict[str, str] = {}
    for label in (
        "Overall result",
        "Plain-language outcome",
        "What was verified",
        "Evidence used",
        "Blocking issues",
        "Next action",
    ):
        pattern = rf"(?im)^\s*-\s+{re.escape(label)}:\s*(.+)$"
        match = re.search(pattern, result_summary)
        if not match or not non_empty(match.group(1)):
            fail(f"{path} Result Summary missing readable content for {label}")
        summary_values[label] = match.group(1).strip().lower()
    if result not in summary_values["Overall result"]:
        fail(f"{path} Result Summary overall result must match the Conclusion result: {result}")

    coverage = table_rows(text, "Evidence Coverage", path)
    require_columns(
        path,
        "Evidence Coverage",
        coverage,
        ("documented_item", "source_document", "implementation_evidence", "test_result_evidence", "status"),
    )
    check_nonempty_rows(path, "Evidence Coverage", coverage)
    if result == "accepted":
        for row in coverage:
            if row.get("status", "").strip().lower() in BLOCKING_EVIDENCE_STATUSES:
                fail(f"{path} accepted conclusion has blocking evidence status: {row.get('status')}")

    adequacy = table_rows(text, "Test Design Adequacy", path)
    require_columns(
        path,
        "Test Design Adequacy",
        adequacy,
        ("behavior_risk_change_id", "required_case_types", "test_design_evidence", "runnable_test_evidence", "status"),
    )
    check_nonempty_rows(path, "Test Design Adequacy", adequacy)
    if result == "accepted":
        for row in adequacy:
            if row.get("status", "").strip().lower() in BLOCKING_TEST_STATUSES:
                fail(f"{path} accepted conclusion has blocking test design status: {row.get('status')}")

    check_implementation_correctness_audit(path, text, result)

    rules = table_rows(text, "Generated Acceptance Rules", path)
    require_columns(path, "Generated Acceptance Rules", rules, ("rule_id", "source", "expected_result", "evidence_required", "status"))
    check_nonempty_rows(path, "Generated Acceptance Rules", rules)
    if result == "accepted":
        for row in rules:
            if row.get("status", "").strip().lower() in BLOCKING_RULE_STATUSES:
                fail(f"{path} accepted conclusion has failing acceptance rule: {row.get('rule_id')}")

    command_body = section_body(text, "Validation Evidence", path)
    for label in REQUIRED_VALIDATION_LABELS:
        pattern = rf"(?im)^\s*-\s+.*{re.escape(label)}.*:\s*(.+)$"
        match = re.search(pattern, command_body)
        if not match or not non_empty(match.group(1)):
            fail(f"{path} Validation Evidence missing result for {label}")

    summary_body = section_body(text, "Consistency Summary", path)
    for label in (
        "Proposal authority check",
        "Proposal vs design",
        "Design vs implementation",
        "Test design adequacy",
        "change_id traceability",
        "Document logic review",
        "Implementation logic review",
        "Implementation correctness audit completeness and routing",
    ):
        pattern = rf"(?im)^\s*-\s+{re.escape(label)}:\s*(.+)$"
        match = re.search(pattern, summary_body)
        if not match or not non_empty(match.group(1)):
            fail(f"{path} Consistency Summary missing evidence for {label}")

    follow_up = section_body(text, "Follow-Up Tasks", path)
    iteration = re.search(r"(?im)^\s*-\s+Iteration count:\s*(\d+)\s*$", follow_up)
    if not iteration:
        fail(f"{path} Follow-Up Tasks must include numeric Iteration count")
    if int(iteration.group(1)) > 5 and result == "accepted":
        fail(f"{path} accepted conclusion cannot exceed 5 unresolved iterations")

    check_run_artifacts(path, text, root, result, scope)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    root = Path(args.root)
    path = Path(args.report)
    if not path.is_absolute():
        path = root / path
    check_report(path, read_text(path), root)
    print("acceptance-report-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
