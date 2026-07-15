#!/usr/bin/env python3
"""Validate post-implementation testing coverage metadata for change_ids."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
GAP_VALUES = {"yes", "manual", "disabled", "deferred", "gap"}
NO_GAP_VALUES = {"", "no", "none", "n/a", "na"}
CASE_TYPES = {"normal", "boundary", "negative", "error", "compatibility", "lifecycle", "cross-module"}
TEST_LEVELS = {"unit", "dv", "integration"}
EMPTY_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo", "pending"}
PUBLIC_API_IMPACTS = {"none", "backward-compatible", "migration-required", "breaking"}
CONTRACT_ASSERTIONS = {
    "external-positive": "new-path-compiles",
    "external-negative": "old-path-rejected-for-removed-symbol",
    "removed-symbol-scan": "no-unallowlisted-old-symbol-references",
    "repository-compile-closure": "repository-consumers-compile",
    "documentation-examples": "documentation-examples-compile",
}
MIGRATION_STATUSES = {"migrated", "allowed-negative-fixture", "allowed-compatibility-shim", "verified-none"}


def fail(message: str) -> None:
    print(f"testing-coverage-check: {message}", file=sys.stderr)
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


def table_rows_after_heading(text: str, heading: str, path: Path) -> list[dict[str, str]]:
    match = re.search(rf"(?m)^##\s+{re.escape(heading)}\s*$", text)
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
        rows.append({header: values[pos].strip() if pos < len(values) else "" for pos, header in enumerate(headers)})
    if not rows:
        fail(f"{path} section ## {heading} has no data rows")
    return rows


def require_columns(path: Path, heading: str, rows: list[dict[str, str]], columns: tuple[str, ...]) -> None:
    available = set(rows[0])
    missing = [column for column in columns if column not in available]
    if missing:
        fail(f"{path} ## {heading} missing columns: {', '.join(missing)}")


def packet_path(root: Path, version: str, module: str, submodule: str | None) -> Path:
    packet = root / "docs" / "versions" / version / "modules" / module
    if submodule:
        packet = packet / submodule
    return packet


def has_value(value: str) -> bool:
    return value.strip().strip('"').strip("'").lower() not in EMPTY_VALUES


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


def pipeline_plan_path(root: Path, version: str, module: str, task_name: str) -> Path:
    plan = root / "docs" / "versions" / version / "modules" / module / task_name / "pipeline" / "plan.md"
    if not plan.exists():
        fail(f"auto-pipeline no-doc testing coverage requires task-local plan: {plan}")
    return plan


def change_ids_from_docs(packet: Path, plan: Path | None = None) -> set[str]:
    proposal = packet / "proposal.md"
    proposal_rows = table_rows_after_heading(read_text(proposal), "Proposal Items", proposal)
    require_columns(proposal, "Proposal Items", proposal_rows, ("proposal_id", "change_id", "requirement", "success_evidence"))
    proposal_ids = {row["change_id"] for row in proposal_rows if row.get("change_id")}
    if plan is not None:
        design_rows = table_rows_after_heading(read_text(plan), "Implementation Scope Bindings", plan)
        require_columns(plan, "Implementation Scope Bindings", design_rows, ("change_id", "target_module", "proposal_id", "design_coverage", "scope_paths"))
        design_ids = {row["change_id"] for row in design_rows if row.get("change_id")}
    else:
        design = packet / "design.md"
        design_rows = table_rows_after_heading(read_text(design), "Directly Mapped Change Items", design)
        require_columns(design, "Directly Mapped Change Items", design_rows, ("change_id", "target_module", "proposal_id", "design_coverage", "scope_paths"))
        design_ids = {row["change_id"] for row in design_rows if row.get("change_id")}
    missing_design = proposal_ids - design_ids
    if missing_design:
        fail(f"change_ids missing from design mapping: {', '.join(sorted(missing_design))}")
    return proposal_ids & design_ids


def pipeline_state_rows(state_path: Path, key: str) -> list[dict[str, str]]:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid pipeline state {state_path}: {error}")
    plan = state_path.with_name("plan.md")
    expected_hash = hashlib.sha256(
        plan.read_text(encoding="utf-8").replace("\r\n", "\n").encode("utf-8")
    ).hexdigest()
    if not isinstance(state, dict) or state.get("schema_version") != 1:
        fail(f"{state_path} schema_version must be 1")
    if state.get("plan_sha256") != expected_hash:
        fail(f"{state_path} plan_sha256 does not match sibling plan.md")
    raw_rows = state.get(key) if isinstance(state, dict) else None
    if not isinstance(raw_rows, list) or any(not isinstance(row, dict) for row in raw_rows):
        fail(f"{state_path} {key} must be an array of objects")
    return [{str(column): str(value) for column, value in row.items()} for row in raw_rows]


def direct_coverage_rows(packet: Path, state_path: Path | None = None) -> dict[str, dict[str, str]]:
    testing = state_path or (packet / "testing.md")
    if state_path is not None:
        rows = pipeline_state_rows(state_path, "testing_evidence")
        columns = ("change_id", "validation_id", "testplan_level", "testplan_step_id", "evidence", "gap", "gap_manual_reason")
        missing = sorted(set(columns) - (set(rows[0]) if rows else set()))
        if missing:
            fail(f"{state_path} testing_evidence missing fields: {', '.join(missing)}")
    else:
        rows = table_rows_after_heading(read_text(testing), "Direct Change Coverage", testing)
        require_columns(
            testing,
            "Direct Change Coverage",
            rows,
            ("change_id", "design_source", "validation_id", "testplan_level", "testplan_step_id", "gap", "gap_manual_reason"),
        )
    coverage: dict[str, dict[str, str]] = {}
    for row in rows:
        change_id = row.get("change_id", "")
        if not change_id:
            continue
        if change_id in coverage:
            fail(f"{testing} duplicates Direct Change Coverage row for {change_id}")
        coverage[change_id] = row
    return coverage


def parse_inline_list(value: str) -> list[str]:
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, str)]


def impact_value(text: str, label: str, path: Path) -> str:
    section = re.search(r"(?ms)^##\s+API and Build Surface Impact\s*$\n(.*?)(?=^##\s+|\Z)", text)
    if not section:
        fail(f"{path} missing required section: ## API and Build Surface Impact")
    match = re.search(rf"(?mi)^\s*-\s*{re.escape(label)}:\s*(.+)$", section.group(1))
    value = match.group(1).strip().lower() if match else ""
    if not value:
        fail(f"{path} API/build impact missing concrete {label}")
    return value


def design_api_contract(packet: Path, plan: Path | None) -> tuple[dict[str, object], list[dict[str, str]]]:
    source = plan or (packet / "design.md")
    text = read_text(source)
    public_api = impact_value(text, "Public API impact", source)
    if public_api not in PUBLIC_API_IMPACTS:
        fail(f"{source} has invalid Public API impact: {public_api}")
    flags: dict[str, bool] = {}
    for label, key in (
        ("Crate-root export change", "crate_root_export_change"),
        ("Build-surface change", "build_surface_change"),
        ("Documentation examples affected", "documentation_examples_affected"),
    ):
        value = impact_value(text, label, source)
        if value not in {"yes", "no"}:
            fail(f"{source} {label} must be yes or no")
        flags[key] = value == "yes"
    if plan is not None:
        interfaces = table_rows_after_heading(text, "Exported Interfaces", source)
        compatibilities = {row.get("compatibility", "").strip().lower() for row in interfaces}
    else:
        compatibilities = {
            value.strip().lower()
            for value in re.findall(r"(?im)^\s*-\s*Compatibility:\s*([^\n]+)$", text)
        }
    breaking = public_api == "breaking" or "breaking" in compatibilities
    migration = public_api == "migration-required" or "migration-required" in compatibilities
    risky = breaking or migration or any(flags.values())
    rows = table_rows_after_heading(text, "Consumer Migration Closure", source) if risky else []
    if risky:
        require_columns(
            source,
            "Consumer Migration Closure",
            rows,
            ("old_symbol", "new_path", "change_id", "consumer_path", "consumer_kind", "migration_status"),
        )
    required: set[str] = set()
    if breaking:
        required.update({"external-positive", "external-negative", "removed-symbol-scan", "repository-compile-closure"})
    elif migration:
        required.update({"external-positive", "removed-symbol-scan", "repository-compile-closure"})
    if flags["crate_root_export_change"]:
        required.update({"external-positive", "repository-compile-closure"})
    if flags["build_surface_change"]:
        required.add("repository-compile-closure")
    if flags["documentation_examples_affected"]:
        required.add("documentation-examples")
    return ({"public_api": public_api, "breaking": breaking, "migration": migration, "required": required, **flags}, rows)


def testplan_api_impact(text: str, path: Path) -> dict[str, object]:
    block = re.search(r"(?ms)^api_impact:\s*$\n(.*?)(?=^[A-Za-z0-9_-]+:\s*|\Z)", text)
    if not block:
        fail(f"{path} missing api_impact")
    public_match = re.search(r"(?m)^  public_api:\s*([A-Za-z0-9_-]+)\s*$", block.group(1))
    result: dict[str, object] = {"public_api": public_match.group(1) if public_match else ""}
    for key in ("crate_root_export_change", "build_surface_change", "documentation_examples_affected"):
        match = re.search(rf"(?m)^  {key}:\s*(true|false)\s*$", block.group(1))
        if not match:
            fail(f"{path} api_impact.{key} must be true or false")
        result[key] = match.group(1) == "true"
    return result


def contract_steps(text: str, path: Path) -> list[dict[str, object]]:
    block = re.search(r"(?ms)^contract_checks:\s*$\n(.*?)(?=^[A-Za-z0-9_-]+:\s*|\Z)", text)
    if not block:
        fail(f"{path} missing contract_checks")
    starts = list(re.finditer(r"(?m)^    - id:\s*([A-Za-z0-9_.-]+)\s*$", block.group(1)))
    rows: list[dict[str, object]] = []
    for index, start in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(block.group(1))
        body = block.group(1)[start.end() : end]
        kind = re.search(r"(?m)^      kind:\s*([A-Za-z0-9_-]+)\s*$", body)
        assertion = re.search(r"(?m)^      assertion:\s*([A-Za-z0-9_-]+)\s*$", body)
        changes = re.search(r"(?m)^      change_ids:\s*(\[[^\n]*\])\s*$", body)
        run = re.search(r"(?m)^      run:\s*(\[[^\n]*\])\s*$", body)
        rows.append(
            {
                "id": start.group(1),
                "kind": kind.group(1) if kind else "",
                "assertion": assertion.group(1) if assertion else "",
                "change_ids": parse_inline_list(changes.group(1)) if changes else [],
                "run": parse_inline_list(run.group(1)) if run else [],
            }
        )
    return rows


def path_covered_by_inputs(path: str, inputs: list[str]) -> bool:
    path = re.split(r"[*?\[]", path, maxsplit=1)[0].rstrip("/")
    target = Path(path)
    return any(target == Path(item) or Path(item) in target.parents for item in inputs)


def design_scope_paths(packet: Path, plan: Path | None, requested: set[str]) -> set[str]:
    source = plan or (packet / "design.md")
    heading = "Implementation Scope Bindings" if plan is not None else "Directly Mapped Change Items"
    rows = table_rows_after_heading(read_text(source), heading, source)
    result: set[str] = set()
    for row in rows:
        if row.get("change_id", "").strip() not in requested:
            continue
        raw = row.get("scope_paths", "")
        for value in re.split(r"\s*(?:,|<br\s*/?>)\s*", raw):
            cleaned = value.strip().strip("`")
            if cleaned:
                result.add(cleaned)
    return result


def check_api_contract_closure(root: Path, packet: Path, plan: Path | None, requested: set[str]) -> None:
    impact, consumers = design_api_contract(packet, plan)
    testplan = packet / "testplan.yaml"
    text = read_text(testplan)
    recorded = testplan_api_impact(text, testplan)
    for key in ("public_api", "crate_root_export_change", "build_surface_change", "documentation_examples_affected"):
        if recorded.get(key) != impact.get(key):
            fail(f"{testplan} api_impact.{key} does not match design/pipeline evidence")
    required = set(impact["required"])
    if not required:
        return
    inputs_match = re.search(r"(?m)^evidence_inputs:\s*(\[[^\n]*\])\s*$", text)
    inputs = parse_inline_list(inputs_match.group(1)) if inputs_match else []
    if not inputs:
        fail(f"{testplan} risk-triggered contract checks require evidence_inputs")
    for scope_path in sorted(design_scope_paths(packet, plan, requested)):
        if not path_covered_by_inputs(scope_path, inputs):
            fail(f"design Scope Paths entry is not bound by testplan evidence_inputs: {scope_path}")
    for index, row in enumerate(consumers, start=1):
        status = row.get("migration_status", "").strip().lower()
        if status not in MIGRATION_STATUSES:
            fail(f"consumer migration row {index} has invalid or incomplete status: {status}")
        if impact["breaking"] and status == "allowed-compatibility-shim":
            fail("breaking API consumer closure cannot retain an allowed-compatibility-shim")
        consumer = row.get("consumer_path", "").strip().strip("`")
        if status != "verified-none" and not path_covered_by_inputs(consumer, inputs):
            fail(f"consumer migration path is not bound by testplan evidence_inputs: {consumer}")
        change_id = row.get("change_id", "").strip()
        if change_id not in requested:
            fail(f"consumer migration row uses change_id outside requested coverage: {change_id}")
    steps = contract_steps(text, testplan)
    by_kind = {str(row["kind"]): row for row in steps}
    missing = required - set(by_kind)
    if missing:
        fail(f"{testplan} missing required contract check kinds: {', '.join(sorted(missing))}")
    for kind in sorted(required):
        row = by_kind[kind]
        if row["assertion"] != CONTRACT_ASSERTIONS[kind]:
            fail(f"{testplan} contract check {kind} has mismatched assertion")
        if not requested <= set(row["change_ids"]):
            fail(f"{testplan} contract check {kind} does not cover every requested change_id")
        command = row["run"]
        if not isinstance(command, list) or not command or command[0] in {"true", "echo", "rg"}:
            fail(f"{testplan} contract check {kind} must use a real verifying wrapper/command")
        if kind == "removed-symbol-scan" and not any(
            str(item).replace("\\", "/").endswith("harness/scripts/consumer-closure-check.py")
            for item in command
        ):
            fail("removed-symbol-scan must invoke harness/scripts/consumer-closure-check.py")
        if kind == "repository-compile-closure" and (root / "Cargo.toml").exists():
            if command[:2] != ["cargo", "test"] or "--no-run" not in command or "--all-targets" not in command:
                fail("Rust repository compile closure must use cargo test --no-run --all-targets")
        if kind == "documentation-examples" and (root / "Cargo.toml").exists():
            if command[:2] != ["cargo", "test"] or "--doc" not in command:
                fail("Rust documentation example closure must use cargo test --doc or a repo-local wrapper")


def extract_level_blocks(text: str) -> dict[str, str]:
    match = re.search(r"(?m)^levels:\s*$", text)
    if not match:
        return {}
    levels_text = text[match.end() :]
    starts = list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$", levels_text))
    blocks: dict[str, str] = {}
    for index, start in enumerate(starts):
        level = start.group(1)
        end = starts[index + 1].start() if index + 1 < len(starts) else len(levels_text)
        blocks[level] = levels_text[start.end() : end]
    return blocks


def extract_steps(level_block: str) -> dict[str, str]:
    starts = list(re.finditer(r"(?m)^      - id:\s*([A-Za-z0-9_.-]+)\s*$", level_block))
    steps: dict[str, str] = {}
    for index, start in enumerate(starts):
        step_id = start.group(1)
        end = starts[index + 1].start() if index + 1 < len(starts) else len(level_block)
        steps[step_id] = level_block[start.start() : end]
    return steps


def yaml_list_contains(block: str, key: str, value: str) -> bool:
    inline = re.search(rf"(?m)^\s*{re.escape(key)}:\s*(\[[^\]]*\])\s*$", block)
    if inline:
        return value in parse_inline_list(inline.group(1))
    multiline = re.search(rf"(?ms)^\s*{re.escape(key)}:\s*\n((?:\s+-\s*[^\n]+\n?)+)", block)
    if multiline:
        values = [line.split("-", 1)[1].strip().strip("\"'") for line in multiline.group(1).splitlines()]
        return value in values
    return False


def check_testplan_mapping(packet: Path, change_id: str, row: dict[str, str]) -> None:
    testplan = packet / "testplan.yaml"
    if not testplan.exists():
        fail(f"missing required post-implementation test metadata: {testplan}")
    text = read_text(testplan)
    levels = extract_level_blocks(text)
    level = row.get("testplan_level", "").strip()
    step_id = row.get("testplan_step_id", "").strip()
    gap = row.get("gap", "").strip().lower()
    reason = row.get("gap_manual_reason", "").strip()
    if level not in levels:
        fail(f"{change_id} references missing testplan level: {level}")
    level_block = levels[level]
    mode_match = re.search(r"(?m)^    mode:\s*([A-Za-z0-9_-]+)\s*$", level_block)
    mode = mode_match.group(1).lower() if mode_match else ""
    if mode in {"manual", "disabled"} or gap in GAP_VALUES:
        if not reason:
            fail(f"{change_id} has manual/disabled/gap coverage without a reason")
        if not yaml_list_contains(level_block, "change_ids", change_id):
            fail(f"{change_id} missing from testplan level {level} change_ids")
        return
    if gap not in NO_GAP_VALUES:
        fail(f"{change_id} uses unknown Gap? value: {gap}")
    if not step_id:
        fail(f"{change_id} automated coverage must declare testplan_step_id")
    step_block = extract_steps(level_block).get(step_id)
    if not step_block:
        fail(f"{change_id} references missing testplan step: {level}/{step_id}")
    if not yaml_list_contains(step_block, "change_ids", change_id):
        fail(f"{change_id} missing from testplan step {level}/{step_id} change_ids")
    if not re.search(r"(?m)^        run:\s*\[.+\]\s*$", step_block):
        fail(f"{change_id} testplan step {level}/{step_id} missing run command")


def check_case_type_coverage(packet: Path, requested: set[str], state_path: Path | None = None) -> None:
    testing = state_path or (packet / "testing.md")
    if state_path is not None:
        rows = pipeline_state_rows(state_path, "testing_case_type_coverage")
        columns = ("change_id", "case_type", "required", "validation_id", "level", "status", "gap_manual_reason")
        missing = sorted(set(columns) - (set(rows[0]) if rows else set()))
        if missing:
            fail(f"{state_path} testing_case_type_coverage missing fields: {', '.join(missing)}")
    else:
        rows = table_rows_after_heading(read_text(testing), "Case-Type Coverage", testing)
        require_columns(
            testing,
            "Case-Type Coverage",
            rows,
            ("change_id", "case_type", "required", "validation_id", "level", "status", "gap_manual_reason"),
        )
    coverage: dict[str, set[str]] = {change_id: set() for change_id in requested}
    for index, row in enumerate(rows, start=1):
        change_id = row.get("change_id", "").strip()
        if change_id not in requested:
            continue
        case_type = row.get("case_type", "").strip().lower()
        required = row.get("required", "").strip().lower()
        status = row.get("status", "").strip().lower()
        reason = row.get("gap_manual_reason", "").strip()
        if case_type not in CASE_TYPES:
            fail(f"{testing} Case-Type Coverage row {index} has unknown case_type: {case_type}")
        if required not in {"yes", "no"}:
            fail(f"{testing} Case-Type Coverage row {index} Required must be yes or no")
        if status not in {"covered", "gap", "manual", "disabled", "not-applicable"}:
            fail(f"{testing} Case-Type Coverage row {index} has invalid status: {status}")
        if required == "yes" and status == "not-applicable":
            fail(f"{testing} Case-Type Coverage row {index} cannot mark required coverage not-applicable")
        if status in {"gap", "manual", "disabled", "not-applicable"} and not reason:
            fail(f"{testing} Case-Type Coverage row {index} requires Gap / Manual Reason")
        level = row.get("level", "").strip().lower()
        if status == "covered" and level not in TEST_LEVELS:
            fail(
                f"{testing} Case-Type Coverage row {index} covered cases must declare the implementing "
                f"level (unit/dv/integration): {level or '<empty>'}"
            )
        coverage[change_id].add(case_type)
    for change_id, seen in coverage.items():
        missing = CASE_TYPES - seen
        if missing:
            fail(f"{testing} change_id {change_id} missing Case-Type Coverage rows: {', '.join(sorted(missing))}")


def check_row(change_id: str, row: dict[str, str]) -> None:
    level_column = "testplan_level"
    for column in ("validation_id", level_column):
        if not row.get(column, "").strip():
            fail(f"{change_id} coverage row missing {column}")
    gap = row.get("gap", "").strip().lower()
    reason = row.get("gap_manual_reason", "").strip()
    if gap in GAP_VALUES and not reason:
        fail(f"{change_id} declares {gap} coverage without Gap / Manual Reason")
    if gap not in GAP_VALUES and gap not in NO_GAP_VALUES:
        fail(f"{change_id} uses unknown Gap? value: {gap}")


def run_test_runner_dry_run(root: Path, module_key: str) -> None:
    test_runner = root / "harness" / "scripts" / "test-run.py"
    if not test_runner.exists():
        fail(f"missing unified test runner: {test_runner}")
    completed = subprocess.run(
        [sys.executable, str(test_runner), module_key, "all", "--root", str(root), "--dry-run"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        fail(f"unified test runner cannot reach {module_key} all: {detail}")


def task_scope_from_testplan(packet: Path, module: str) -> str:
    testplan = packet / "testplan.yaml"
    if not testplan.exists():
        return module
    match = re.search(r"(?m)^task_name:\s*(\S+)\s*$", read_text(testplan))
    if not match:
        fail(f"testplan missing task_name: {testplan}")
    return f"{module}/{match.group(1)}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--version", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--submodule")
    parser.add_argument("--change-id", action="append", dest="change_ids")
    parser.add_argument(
        "--allow-missing-testplan",
        action="store_true",
        help="allow repositories with an explicit local rule to complete testing without testplan.yaml",
    )
    parser.add_argument("--skip-test-run-check", action="store_true")
    args = parser.parse_args()

    root = Path(args.root)
    packet = packet_path(root, args.version, args.module, args.submodule)
    no_stage_docs = pipeline_no_stage_docs(root, args.version, args.module, args.submodule)
    plan = pipeline_plan_path(root, args.version, args.module, args.submodule) if no_stage_docs else None
    state_path = plan.with_name("state.json") if plan is not None else None
    if no_stage_docs:
        forbidden = ["testing.md"]
        present = [name for name in forbidden if (packet / name).exists()]
        if present or (packet / "testing").exists():
            fail("auto-pipeline document policy forbids generated testing Markdown docs in this packet")
        if not (packet / "testplan.yaml").exists():
            fail(f"missing required auto-pipeline test metadata: {packet / 'testplan.yaml'}")
    elif args.allow_missing_testplan and not (packet / "testplan.yaml").exists():
        print("testing-coverage-check: warning: testplan.yaml missing by explicit local exception", file=sys.stderr)
    doc_change_ids = change_ids_from_docs(packet, plan)
    requested = set(args.change_ids or doc_change_ids)
    unknown = requested - doc_change_ids
    if unknown:
        fail(f"requested change_ids are not directly mapped by proposal/design: {', '.join(sorted(unknown))}")

    coverage = direct_coverage_rows(packet, state_path)
    missing = requested - set(coverage)
    if missing:
        fail(f"change_ids missing from testing coverage evidence: {', '.join(sorted(missing))}")

    for change_id in sorted(requested):
        row = coverage[change_id]
        check_row(change_id, row)
        if no_stage_docs or (packet / "testplan.yaml").exists() or not args.allow_missing_testplan:
            check_testplan_mapping(packet, change_id, row)
    check_case_type_coverage(packet, requested, state_path)
    check_api_contract_closure(root, packet, plan, requested)

    if not args.skip_test_run_check:
        module_key = (
            f"{args.module}/{args.submodule}"
            if args.submodule
            else task_scope_from_testplan(packet, args.module)
        )
        run_test_runner_dry_run(root, module_key)

    print("testing-coverage-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
