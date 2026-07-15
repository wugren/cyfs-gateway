#!/usr/bin/env python3
"""Validate task-bound auto-pipeline plans and their executable dependency graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath


TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
EMPTY_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo", "pending"}
ALLOWED_STATUSES = {"pending", "running", "confirmed", "complete", "blocked", "returned"}
ALLOWED_STAGES = {"design", "implementation", "testing", "acceptance"}
FINISHED_STATUSES = {"confirmed", "complete"}
TASK_NAME_RE = re.compile(r"^\d{3,}-[a-z0-9][a-z0-9_.-]*$")
MODULE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
CONFIRMED_LAUNCH_VALUES = {"yes", "true", "confirmed"}
BROAD_SCOPE_PATHS = {".", "*", "**", "src", "source", "lib", "app", "packages", "crates"}
COMPATIBILITY_VALUES = {"new", "backward-compatible", "migration-required", "breaking"}
PUBLIC_API_IMPACTS = {"none", "backward-compatible", "migration-required", "breaking"}
MIGRATION_STATUSES = {"migrated", "allowed-negative-fixture", "allowed-compatibility-shim", "verified-none"}
DECISION_TYPES = {"boundary", "technical", "collaboration"}


def fail(message: str) -> None:
    print(f"pipeline-plan-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalize_column(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def non_empty(value: str) -> bool:
    normalized = value.strip().strip('"').strip("'")
    return (
        normalized.lower() not in EMPTY_VALUES
        and not re.search(r"<[^>]+>", normalized)
    )


def split_table_row(line: str) -> list[str]:
    parts = [part.strip() for part in line.strip().split("|")]
    if parts and parts[0] == "":
        parts = parts[1:]
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return parts


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
        rows.append(
            {header: values[pos].strip() if pos < len(values) else "" for pos, header in enumerate(headers)}
        )
    if not rows:
        fail(f"{path} ## {heading} has no data rows")
    return rows


def require_columns(
    path: Path, heading: str, rows: list[dict[str, str]], columns: tuple[str, ...]
) -> None:
    missing = sorted(set(columns) - set(rows[0]))
    if missing:
        fail(f"{path} ## {heading} missing columns: {', '.join(missing)}")


def bullet_value(body: str, label: str, path: Path) -> str:
    match = re.search(rf"(?im)^\s*-\s+{re.escape(label)}:\s*(.+)$", body)
    if not match or not non_empty(match.group(1)):
        fail(f"{path} Trigger missing concrete value for {label}")
    return match.group(1).strip()


def csv_values(value: str) -> list[str]:
    return [item.strip().strip("`") for item in value.split(",") if item.strip()]


def front_matter_value(text: str, key: str) -> str | None:
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    if end == -1:
        return None
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+)$", text[4:end])
    return match.group(1).strip() if match else None


def check_trigger(text: str, path: Path, root: Path) -> dict[str, object]:
    body = section_body(text, "Trigger", path)
    values = {
        label: bullet_value(body, label, path)
        for label in (
            "Proposal",
            "User launch confirmed",
            "User launch statement",
            "Per-stage user confirmation",
            "Auto-confirm completed document stages",
            "Auto-pipeline document policy",
            "Version",
            "Packet module",
            "Task name",
            "Target module(s)",
            "change_id values",
        )
    }
    if values["User launch confirmed"].lower() not in CONFIRMED_LAUNCH_VALUES:
        fail(f"{path} auto-pipeline plan requires explicit user launch confirmation")
    if len(values["User launch statement"].strip()) < 8:
        fail(f"{path} User launch statement must record the user's explicit launch instruction verbatim")
    policy = values["Auto-pipeline document policy"].lower()
    if "no design/testing markdown docs" not in policy or "testplan.yaml required" not in policy:
        fail(
            f"{path} Auto-pipeline document policy must include: "
            "no design/testing markdown docs; testplan.yaml required"
        )
    task_name = values["Task name"]
    if not TASK_NAME_RE.fullmatch(task_name):
        fail(f"{path} Task name must match <task-seq>-<task-slug>: {task_name}")
    packet_module = values["Packet module"]
    target_modules = csv_values(values["Target module(s)"])
    if not target_modules or any(
        not non_empty(item) or not MODULE_NAME_RE.fullmatch(item) for item in target_modules
    ):
        fail(f"{path} Target module(s) must list concrete project modules")
    if packet_module == "globals":
        if len(set(target_modules)) < 2 or "globals" in target_modules:
            fail(f"{path} globals packet requires at least two concrete target modules")
    elif set(target_modules) != {packet_module}:
        fail(f"{path} non-globals packet Target module(s) must equal Packet module")

    expected_proposal = (
        f"docs/versions/{values['Version']}/modules/{packet_module}/{task_name}/proposal.md"
    )
    proposal = values["Proposal"].strip("`")
    if proposal != expected_proposal:
        fail(f"{path} Proposal must be the bound task packet path: {expected_proposal}")
    proposal_path = root / proposal
    if not proposal_path.is_file():
        fail(f"{path} bound proposal does not exist: {proposal}")
    proposal_text = proposal_path.read_text(encoding="utf-8")
    expected_front_matter = {
        "version": values["Version"],
        "module": packet_module,
        "task_name": task_name,
    }
    for key, expected in expected_front_matter.items():
        if front_matter_value(proposal_text, key) != expected:
            fail(f"{path} bound proposal front matter {key} must be {expected}")

    change_ids = csv_values(values["change_id values"])
    if not change_ids or any(not non_empty(item) for item in change_ids):
        fail(f"{path} change_id values must list concrete ids")
    if len(change_ids) != len(set(change_ids)):
        fail(f"{path} change_id values contains duplicates")
    return {
        "version": values["Version"],
        "packet_module": packet_module,
        "task_name": task_name,
        "target_modules": set(target_modules),
        "change_ids": set(change_ids),
    }


def parse_dependencies(value: str) -> list[str]:
    if value.strip().lower() in {"none", "root"}:
        return []
    return csv_values(value)


def check_task_graph(
    text: str, path: Path
) -> tuple[dict[str, dict[str, str]], dict[str, list[str]]]:
    stage_rows = table_rows(text, "Stage Graph", path)
    require_columns(
        path,
        "Stage Graph",
        stage_rows,
        ("task_id", "stage", "responsibility", "scope", "parent_task", "depends_on", "output", "done_condition"),
    )
    child_rows = table_rows(text, "Submodule Tasks", path)
    require_columns(
        path,
        "Submodule Tasks",
        child_rows,
        ("task_id", "stage", "responsibility", "submodule", "parent_task", "depends_on", "output", "done_condition"),
    )

    tasks: dict[str, dict[str, str]] = {}
    dependencies: dict[str, list[str]] = {}
    for heading, rows, scope_column in (
        ("Stage Graph", stage_rows, "scope"),
        ("Submodule Tasks", child_rows, "submodule"),
    ):
        for index, row in enumerate(rows, start=1):
            task_id = row.get("task_id", "").strip()
            for column in ("task_id", "stage", "responsibility", scope_column, "parent_task", "output", "done_condition"):
                if not non_empty(row.get(column, "")):
                    fail(f"{path} ## {heading} row {index} column {column} is empty or placeholder")
            if task_id in tasks:
                fail(f"{path} duplicate task_id across pipeline graph: {task_id}")
            stage = row.get("stage", "").strip().lower()
            if stage not in ALLOWED_STAGES:
                fail(f"{path} task {task_id} has invalid stage: {stage}")
            row["stage"] = stage
            tasks[task_id] = row
            dependencies[task_id] = parse_dependencies(row.get("depends_on", ""))

    missing = ALLOWED_STAGES - {row["stage"] for row in stage_rows}
    if missing:
        fail(f"{path} ## Stage Graph missing stages: {', '.join(sorted(missing))}")

    stage_rank = {"design": 0, "implementation": 1, "testing": 2, "acceptance": 3}
    for task_id, row in tasks.items():
        parent = row.get("parent_task", "").strip()
        if parent.lower() != "root" and parent not in tasks:
            fail(f"{path} task {task_id} references unknown parent_task: {parent}")
        for dependency in dependencies[task_id]:
            if dependency not in tasks:
                fail(f"{path} task {task_id} references unknown dependency: {dependency}")
            if dependency == task_id:
                fail(f"{path} task {task_id} cannot depend on itself")
            if stage_rank[tasks[dependency]["stage"]] > stage_rank[row["stage"]]:
                fail(f"{path} task {task_id} depends on later-stage task {dependency}")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str, stack: list[str]) -> None:
        if task_id in visited:
            return
        if task_id in visiting:
            fail(f"{path} task dependency cycle: {' -> '.join([*stack, task_id])}")
        visiting.add(task_id)
        for dependency in dependencies[task_id]:
            visit(dependency, [*stack, task_id])
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in tasks:
        visit(task_id, [])
    return tasks, dependencies


def check_parallel_policy(text: str, path: Path) -> None:
    body = section_body(text, "Parallel Scheduling", path)
    required = (
        "Strategy: dependency-ready-set",
        "runtime-available child-agent slots",
        "Shared artifact owner: parent-orchestrator",
        ".harness/locks/",
        "maximum dependency-ready set",
        "immediately backfill free slots",
        "explicit dependency, overlapping write scope, or exhausted concurrency capacity only",
        "pipeline/state.json",
    )
    missing = [value for value in required if value not in body]
    if missing:
        fail(f"{path} ## Parallel Scheduling missing required policy: {', '.join(missing)}")


def check_dependency_graphs(text: str, path: Path) -> None:
    body = section_body(text, "Dependency Graphs", path)
    mermaid = re.search(r"(?ms)```mermaid\s+(.+?)```", body)
    if not mermaid:
        fail(f"{path} ## Dependency Graphs must include a concrete Mermaid graph")
    rows = table_rows(text, "Dependency Graphs", path)
    require_columns(path, "Dependency Graphs", rows, ("level", "parent", "node", "depends_on"))

    groups: dict[tuple[str, str], dict[str, list[str]]] = {}
    for index, row in enumerate(rows, start=1):
        for column in ("level", "parent", "node"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## Dependency Graphs row {index} column {column} is empty or placeholder")
        key = (row["level"], row["parent"])
        nodes = groups.setdefault(key, {})
        node = row["node"]
        if node in nodes:
            fail(f"{path} ## Dependency Graphs duplicates node {node} at {key[0]}/{key[1]}")
        nodes[node] = parse_dependencies(row.get("depends_on", ""))

    table_edges: set[tuple[str, str]] = set()
    for (level, parent), nodes in groups.items():
        for node, dependencies in nodes.items():
            table_edges.update((node, dependency) for dependency in dependencies)
            unknown = [dependency for dependency in dependencies if dependency not in nodes]
            if unknown:
                fail(
                    f"{path} dependency graph {level}/{parent} node {node} depends on "
                    f"unknown or different-parent node(s): {', '.join(unknown)}"
                )
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node: str, stack: list[str]) -> None:
            if node in visited:
                return
            if node in visiting:
                fail(
                    f"{path} dependency graph cycle at {level}/{parent}: "
                    f"{' -> '.join([*stack, node])}"
                )
            visiting.add(node)
            for dependency in nodes[node]:
                visit(dependency, [*stack, node])
            visiting.remove(node)
            visited.add(node)

        for node in nodes:
            visit(node, [])

    mermaid_edges = set(
        re.findall(
            r"(?m)^\s*([A-Za-z0-9_.-]+)\s*-->\s*([A-Za-z0-9_.-]+)",
            mermaid.group(1),
        )
    )
    if mermaid_edges != table_edges:
        fail(
            f"{path} Mermaid dependency edges must exactly match the machine-checkable "
            "Dependency Graphs table"
        )


def check_exported_interfaces(text: str, path: Path) -> None:
    rows = table_rows(text, "Exported Interfaces", path)
    require_columns(
        path,
        "Exported Interfaces",
        rows,
        ("interface", "owner", "consumer", "compatibility", "affected_callers", "migration_path"),
    )
    for index, row in enumerate(rows, start=1):
        for column in ("interface", "owner", "consumer", "compatibility"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## Exported Interfaces row {index} column {column} is empty or placeholder")
        compatibility = row["compatibility"].strip().lower()
        if compatibility not in COMPATIBILITY_VALUES:
            fail(f"{path} ## Exported Interfaces row {index} has invalid compatibility: {compatibility}")
        if compatibility in {"migration-required", "breaking"}:
            for column in ("affected_callers", "migration_path"):
                if not non_empty(row.get(column, "")):
                    fail(
                        f"{path} ## Exported Interfaces row {index} {compatibility} interface "
                        f"requires concrete {column}"
                    )


def impact_value(text: str, label: str, path: Path) -> str:
    body = section_body(text, "API and Build Surface Impact", path)
    match = re.search(rf"(?mi)^\s*-\s*{re.escape(label)}:\s*(.+)$", body)
    value = match.group(1).strip().lower() if match else ""
    if not value:
        fail(f"{path} ## API and Build Surface Impact missing concrete {label}")
    return value


def check_consumer_migration_closure(text: str, path: Path) -> None:
    public_api = impact_value(text, "Public API impact", path)
    if public_api not in PUBLIC_API_IMPACTS:
        fail(f"{path} has invalid Public API impact: {public_api}")
    flags: dict[str, bool] = {}
    for label in ("Crate-root export change", "Build-surface change", "Documentation examples affected"):
        value = impact_value(text, label, path)
        if value not in {"yes", "no"}:
            fail(f"{path} {label} must be yes or no")
        flags[label] = value == "yes"
    interface_rows = table_rows(text, "Exported Interfaces", path)
    interface_risk = any(
        row.get("compatibility", "").strip().lower() in {"breaking", "migration-required"}
        for row in interface_rows
    )
    interface_breaking = any(
        row.get("compatibility", "").strip().lower() == "breaking" for row in interface_rows
    )
    risky = public_api in {"breaking", "migration-required"} or interface_risk or any(flags.values())
    if not risky:
        return
    rows = table_rows(text, "Consumer Migration Closure", path)
    require_columns(
        path,
        "Consumer Migration Closure",
        rows,
        ("old_symbol", "new_path", "change_id", "consumer_path", "consumer_kind", "migration_status"),
    )
    for index, row in enumerate(rows, start=1):
        for column in ("old_symbol", "new_path", "change_id", "consumer_kind", "migration_status"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## Consumer Migration Closure row {index} column {column} is empty or placeholder")
        status = row["migration_status"].strip().lower()
        if status not in MIGRATION_STATUSES:
            fail(f"{path} ## Consumer Migration Closure row {index} has invalid migration_status: {status}")
        if (public_api == "breaking" or interface_breaking) and status == "allowed-compatibility-shim":
            fail(f"{path} breaking interfaces cannot retain an allowed-compatibility-shim")
        consumer = row.get("consumer_path", "").strip().strip("`")
        if status == "verified-none":
            if consumer.lower() not in {"none-found", "verified-none"}:
                fail(f"{path} verified-none consumer rows must use consumer_path none-found")
        elif (
            not non_empty(consumer)
            or consumer.endswith("/")
            or any(token in consumer for token in ("*", "?", "["))
            or consumer.lower() in {"all callers", "all consumers"}
        ):
            fail(f"{path} ## Consumer Migration Closure row {index} must name one concrete consumer file")


def check_state_ownership(text: str, path: Path) -> None:
    rows = table_rows(text, "State Ownership", path)
    require_columns(
        path,
        "State Ownership",
        rows,
        ("state", "owner", "access_interface", "lifecycle", "failure_transitions"),
    )
    owners: dict[str, str] = {}
    for index, row in enumerate(rows, start=1):
        for column in ("state", "owner", "access_interface", "lifecycle", "failure_transitions"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## State Ownership row {index} column {column} is empty or placeholder")
        state = row["state"]
        if state in owners and owners[state] != row["owner"]:
            fail(f"{path} state {state} has multiple owners: {owners[state]}, {row['owner']}")
        owners[state] = row["owner"]


def check_failure_flows(text: str, path: Path) -> None:
    rows = table_rows(text, "Failure Flows", path)
    require_columns(path, "Failure Flows", rows, ("flow", "boundary", "failure", "handling"))
    for index, row in enumerate(rows, start=1):
        for column in ("flow", "boundary", "failure", "handling"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## Failure Flows row {index} column {column} is empty or placeholder")


def check_rejected_alternatives(text: str, path: Path) -> None:
    rows = table_rows(text, "Rejected Alternatives", path)
    require_columns(
        path,
        "Rejected Alternatives",
        rows,
        ("decision_type", "selected", "rejected", "reason"),
    )
    found: set[str] = set()
    for index, row in enumerate(rows, start=1):
        for column in ("decision_type", "selected", "rejected", "reason"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## Rejected Alternatives row {index} column {column} is empty or placeholder")
        decision_type = row["decision_type"].strip().lower()
        if decision_type not in DECISION_TYPES:
            fail(f"{path} ## Rejected Alternatives row {index} has invalid decision_type: {decision_type}")
        found.add(decision_type)
    missing = DECISION_TYPES - found
    if missing:
        fail(f"{path} ## Rejected Alternatives missing decision types: {', '.join(sorted(missing))}")


def check_design_evidence(text: str, path: Path) -> None:
    check_dependency_graphs(text, path)
    check_exported_interfaces(text, path)
    check_consumer_migration_closure(text, path)
    check_state_ownership(text, path)
    check_failure_flows(text, path)
    check_rejected_alternatives(text, path)


def normalize_repo_path(value: str) -> str:
    normalized = value.strip().strip("`").replace("\\", "/")
    if any(token in normalized for token in ("*", "?", "[", "]")):
        fail(f"Scope Paths must name concrete repository paths, not globs: {value}")
    candidate = PurePosixPath(normalized)
    if candidate.is_absolute() or ".." in candidate.parts:
        fail(f"Scope Paths must stay inside the repository: {value}")
    return candidate.as_posix().strip("/")


def parse_scope_paths(cell: str) -> list[str]:
    entries = [match.group(1) for match in re.finditer(r"`([^`]+)`", cell)] or cell.split(",")
    return [normalize_repo_path(entry) for entry in entries if entry.strip()]


def check_implementation_scope_bindings(
    text: str, path: Path, trigger: dict[str, object]
) -> dict[tuple[str, str], list[str]]:
    rows = table_rows(text, "Implementation Scope Bindings", path)
    require_columns(
        path,
        "Implementation Scope Bindings",
        rows,
        ("change_id", "target_module", "proposal_id", "design_coverage", "scope_paths", "design_rules_applied"),
    )
    bindings: dict[tuple[str, str], list[str]] = {}
    for index, row in enumerate(rows, start=1):
        for column in ("change_id", "target_module", "proposal_id", "design_coverage", "scope_paths", "design_rules_applied"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## Implementation Scope Bindings row {index} column {column} is empty or placeholder")
        key = (row["change_id"], row["target_module"])
        if key in bindings:
            fail(f"{path} duplicates implementation scope binding {key[0]}/{key[1]}")
        if row["change_id"] not in trigger["change_ids"]:
            fail(f"{path} binding uses change_id not declared in Trigger: {row['change_id']}")
        if row["target_module"] not in trigger["target_modules"]:
            fail(f"{path} binding uses target module not declared in Trigger: {row['target_module']}")
        scope_paths = parse_scope_paths(row["scope_paths"])
        if not scope_paths or any(scope.lower() in BROAD_SCOPE_PATHS for scope in scope_paths):
            fail(f"{path} binding {key[0]}/{key[1]} has missing or over-broad Scope Paths")
        bindings[key] = scope_paths
    bound_changes = {change_id for change_id, _ in bindings}
    if bound_changes != trigger["change_ids"]:
        missing = sorted(trigger["change_ids"] - bound_changes)
        fail(f"{path} Trigger change_ids missing scope bindings: {', '.join(missing)}")
    bound_targets = {target for _, target in bindings}
    if bound_targets != trigger["target_modules"]:
        missing = sorted(trigger["target_modules"] - bound_targets)
        fail(f"{path} Trigger target modules missing scope bindings: {', '.join(missing)}")
    return bindings


def path_matches_scope(path: str, scopes: list[str]) -> bool:
    normalized = normalize_repo_path(path)
    return any(
        normalized == scope
        or normalized.startswith(scope + "/")
        for scope in scopes
    )


def check_file_sequence(
    text: str,
    path: Path,
    tasks: dict[str, dict[str, str]],
    bindings: dict[tuple[str, str], list[str]],
) -> None:
    rows = table_rows(text, "File-Level Implementation Sequence", path)
    require_columns(
        path,
        "File-Level Implementation Sequence",
        rows,
        ("sequence", "task_id", "file_level_module", "action", "depends_on", "change_id", "target_module", "scope_paths", "context_sources"),
    )
    sequences: list[int] = []
    seen_tasks: set[str] = set()
    for index, row in enumerate(rows, start=1):
        for column in ("sequence", "task_id", "file_level_module", "action", "change_id", "target_module", "scope_paths", "context_sources"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## File-Level Implementation Sequence row {index} column {column} is empty or placeholder")
        try:
            sequence = int(row["sequence"])
        except ValueError:
            fail(f"{path} file sequence must be an integer: {row['sequence']}")
        sequences.append(sequence)
        task_id = row["task_id"]
        if task_id in seen_tasks:
            fail(f"{path} file sequence duplicates task_id: {task_id}")
        seen_tasks.add(task_id)
        if task_id not in tasks or tasks[task_id]["stage"] != "implementation":
            fail(f"{path} file sequence task_id must reference an implementation task: {task_id}")
        key = (row["change_id"], row["target_module"])
        if key not in bindings:
            fail(f"{path} file sequence has no matching scope binding: {key[0]}/{key[1]}")
        row_scopes = parse_scope_paths(row["scope_paths"])
        if not row_scopes or any(scope.lower() in BROAD_SCOPE_PATHS for scope in row_scopes):
            fail(f"{path} file sequence task {task_id} has missing or over-broad Scope Paths")
        if any(not path_matches_scope(scope, bindings[key]) for scope in row_scopes):
            fail(f"{path} file sequence task {task_id} widens its bound Scope Paths")
        if not path_matches_scope(row["file_level_module"], row_scopes):
            fail(f"{path} file {row['file_level_module']} is outside its file-sequence Scope Paths")
        if not path_matches_scope(row["file_level_module"], bindings[key]):
            fail(f"{path} file {row['file_level_module']} is outside binding Scope Paths for {key[0]}/{key[1]}")
        for dependency in parse_dependencies(row.get("depends_on", "")):
            if dependency not in seen_tasks:
                fail(f"{path} file sequence task {task_id} depends on a missing or later task: {dependency}")
    if sequences != list(range(1, len(rows) + 1)):
        fail(f"{path} file implementation sequence must be contiguous and ordered from 1")


def lf_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_pipeline_state(plan_path: Path) -> tuple[Path, dict[str, object]]:
    state_path = plan_path.with_name("state.json")
    if not state_path.is_file():
        fail(f"missing task-local pipeline state: {state_path}")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"invalid pipeline state {state_path}: {error}")
    if not isinstance(state, dict) or state.get("schema_version") != 1:
        fail(f"{state_path} schema_version must be 1")
    if state.get("plan_sha256") != lf_sha256(plan_path):
        fail(f"{state_path} plan_sha256 does not match sibling plan.md")
    return state_path, state


def check_task_state(
    state: dict[str, object], state_path: Path, tasks: dict[str, dict[str, str]],
    dependencies: dict[str, list[str]], require_complete: bool,
) -> None:
    task_state = state.get("tasks")
    if not isinstance(task_state, dict) or set(task_state) != set(tasks):
        fail(f"{state_path} tasks must exactly match task ids declared by plan.md")
    statuses: dict[str, str] = {}
    for task_id, entry in task_state.items():
        if not isinstance(entry, dict):
            fail(f"{state_path} task {task_id} must be an object")
        status = entry.get("status")
        if status not in ALLOWED_STATUSES:
            fail(f"{state_path} task {task_id} has invalid status: {status}")
        statuses[task_id] = str(status)
    for task_id, status in statuses.items():
        if status in {"running", "confirmed", "complete"}:
            unfinished = [dep for dep in dependencies[task_id] if statuses[dep] not in FINISHED_STATUSES]
            if unfinished:
                fail(f"{state_path} task {task_id} is {status} before dependencies finish: {', '.join(unfinished)}")
        if require_complete and status not in FINISHED_STATUSES:
            fail(f"{state_path} task {task_id} must be confirmed or complete before pipeline completion")


def check_scheduler_state(
    state: dict[str, object],
    state_path: Path,
    tasks: dict[str, dict[str, str]],
    dependencies: dict[str, list[str]],
    require_complete: bool,
) -> None:
    scheduler = state.get("scheduler")
    if not isinstance(scheduler, dict):
        fail(f"{state_path} scheduler must be an object")
    expected = {
        "strategy": "dependency-ready-set",
        "max_concurrency": "runtime-available-slots",
        "shared_artifact_owner": "parent-orchestrator",
        "lock_directory": ".harness/locks",
    }
    for key, value in expected.items():
        if scheduler.get(key) != value:
            fail(f"{state_path} scheduler.{key} must be {value}")
    waves = scheduler.get("waves")
    if not isinstance(waves, list):
        fail(f"{state_path} scheduler.waves must be an array")

    previously_launched: set[str] = set()
    for index, wave in enumerate(waves, start=1):
        if not isinstance(wave, dict):
            fail(f"{state_path} scheduler wave {index} must be an object")
        task_ids = wave.get("tasks")
        reasons = wave.get("serialization_reasons")
        if (
            not isinstance(task_ids, list)
            or not task_ids
            or any(not isinstance(task_id, str) for task_id in task_ids)
            or len(task_ids) != len(set(task_ids))
        ):
            fail(f"{state_path} scheduler wave {index} tasks must be a non-empty unique string array")
        if not isinstance(reasons, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in reasons.items()):
            fail(f"{state_path} scheduler wave {index} serialization_reasons must be a string map")
        unknown = set(task_ids) - set(tasks)
        if unknown:
            fail(f"{state_path} scheduler wave {index} has unknown tasks: {', '.join(sorted(unknown))}")
        for task_id in task_ids:
            unfinished = [dependency for dependency in dependencies[task_id] if dependency not in previously_launched]
            if unfinished:
                fail(
                    f"{state_path} scheduler wave {index} launches {task_id} before dependencies: "
                    + ", ".join(unfinished)
                )
        previously_launched.update(task_ids)

    if require_complete:
        missing = set(tasks) - previously_launched
        if missing:
            fail(f"{state_path} completed pipeline scheduler never launched: {', '.join(sorted(missing))}")


def check_testing_evidence(
    state: dict[str, object], state_path: Path, trigger: dict[str, object], require_complete: bool
) -> None:
    rows = state.get("testing_evidence")
    if not isinstance(rows, list):
        fail(f"{state_path} testing_evidence must be an array")
    if require_complete and not rows:
        fail(f"{state_path} testing_evidence must not be empty before completion")
    if any(not isinstance(row, dict) for row in rows):
        fail(f"{state_path} testing_evidence entries must be objects")
    row_changes = {str(row.get("change_id", "")) for row in rows if non_empty(str(row.get("change_id", "")))}
    if (rows or require_complete) and row_changes != trigger["change_ids"]:
        fail(f"{state_path} testing_evidence change_ids must exactly match Trigger change_id values")
    if require_complete:
        for index, row in enumerate(rows, start=1):
            for column in ("change_id", "validation_id", "testplan_level", "testplan_step_id", "evidence"):
                if not non_empty(str(row.get(column, ""))):
                    fail(f"{state_path} testing_evidence row {index} field {column} is incomplete")

    case_rows = state.get("testing_case_type_coverage")
    if not isinstance(case_rows, list):
        fail(f"{state_path} testing_case_type_coverage must be an array")
    if any(not isinstance(row, dict) for row in case_rows):
        fail(f"{state_path} testing_case_type_coverage entries must be objects")
    unknown = {str(row.get("change_id", "")) for row in case_rows} - trigger["change_ids"]
    if unknown:
        fail(f"{state_path} testing_case_type_coverage has undeclared change_ids: {', '.join(sorted(unknown))}")


def check_exit_condition(state: dict[str, object], state_path: Path, require_complete: bool) -> None:
    conditions = state.get("exit_conditions")
    if not isinstance(conditions, dict) or not conditions:
        fail(f"{state_path} exit_conditions must be a non-empty object")
    if any(not isinstance(value, bool) for value in conditions.values()):
        fail(f"{state_path} exit_conditions values must be booleans")
    acceptance = state.get("acceptance")
    if not isinstance(acceptance, dict) or acceptance.get("status") not in {"pending", "accepted", "rejected", "needs-changes"}:
        fail(f"{state_path} acceptance status is invalid")
    if require_complete:
        unchecked = [name for name, value in conditions.items() if not value]
        if unchecked:
            fail(f"{state_path} has incomplete exit conditions: {', '.join(unchecked)}")
        if acceptance.get("status") != "accepted" or not non_empty(str(acceptance.get("report", ""))):
            fail(f"{state_path} completion requires accepted status and a report path")


def check_state_metadata(
    state: dict[str, object], state_path: Path, trigger: dict[str, object]
) -> None:
    evidence = state.get("evidence")
    if not isinstance(evidence, dict):
        fail(f"{state_path} evidence must be an object")
    for key in ("test_runs", "quality_runs"):
        values = evidence.get(key)
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            fail(f"{state_path} evidence.{key} must be an array of paths")
    returns = state.get("return_records")
    if not isinstance(returns, list) or any(not isinstance(item, dict) for item in returns):
        fail(f"{state_path} return_records must be an array of objects")
    for index, item in enumerate(returns, start=1):
        issue_id = item.get("issue_id")
        owning_stage = item.get("owning_stage")
        count = item.get("count")
        if not non_empty(str(issue_id or "")):
            fail(f"{state_path} return_records row {index} requires issue_id")
        if owning_stage not in ALLOWED_STAGES:
            fail(f"{state_path} return_records row {index} has invalid owning_stage")
        if not isinstance(count, int) or count < 1:
            fail(f"{state_path} return_records row {index} count must be a positive integer")
    acceptance = state.get("acceptance")
    if isinstance(acceptance, dict) and acceptance.get("status") == "accepted":
        expected = (
            f"docs/versions/{trigger['version']}/modules/{trigger['packet_module']}/"
            f"{trigger['task_name']}/acceptance-report.md"
        )
        if acceptance.get("report") != expected:
            fail(f"{state_path} accepted report must be the task-packet report: {expected}")


def is_successful_task_run(
    artifact: object,
    task_scope: str,
    expected_testplan: str,
    change_ids: set[str],
) -> bool:
    if not isinstance(artifact, dict) or artifact.get("schema") != 1:
        return False
    if artifact.get("requested_module") != task_scope or artifact.get("requested_level") != "all":
        return False
    if artifact.get("exit_code") != 0:
        return False
    testplans = artifact.get("testplans")
    artifact_change_ids = artifact.get("change_ids")
    steps = artifact.get("steps")
    if not isinstance(testplans, list) or expected_testplan not in testplans:
        return False
    if (
        not isinstance(artifact_change_ids, list)
        or not all(isinstance(item, str) for item in artifact_change_ids)
        or not change_ids <= set(artifact_change_ids)
    ):
        return False
    if not isinstance(steps, list) or not steps:
        return False
    return all(
        isinstance(step, dict)
        and step.get("exit_code") == 0
        and isinstance(step.get("command"), list)
        and bool(step.get("command"))
        and isinstance(step.get("sources"), list)
        and bool(step.get("sources"))
        for step in steps
    )


def check_completion_artifacts(root: Path, trigger: dict[str, object]) -> None:
    version = str(trigger["version"])
    module = str(trigger["packet_module"])
    task_name = str(trigger["task_name"])
    packet = root / "docs" / "versions" / version / "modules" / module / task_name
    testplan = packet / "testplan.yaml"
    if not testplan.is_file():
        fail(f"pipeline completion requires testplan.yaml: {testplan}")

    expected_testplan = testplan.relative_to(root).as_posix()
    task_scope = f"{module}/{task_name}"
    change_ids = set(trigger["change_ids"])
    matching_artifacts: list[Path] = []
    for artifact_path in sorted((root / "test-results" / "test-runs").glob("*.json")):
        try:
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if is_successful_task_run(
            artifact, task_scope, expected_testplan, change_ids
        ):
            matching_artifacts.append(artifact_path)
    if not matching_artifacts:
        fail(
            "pipeline completion requires a successful task test-run artifact for "
            f"{task_scope} all covering {', '.join(sorted(change_ids))}"
        )

    report = packet / "acceptance-report.md"
    if not report.is_file():
        fail(f"pipeline completion requires acceptance report: {report}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan")
    parser.add_argument("--root", default=".")
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--print-plan-hash", action="store_true")
    args = parser.parse_args()

    root = Path(args.root)
    path = Path(args.plan)
    if not path.is_absolute():
        path = root / path
    if not path.exists():
        fail(f"missing required file: {path}")
    if args.print_plan_hash:
        print(lf_sha256(path))
        return 0
    text = path.read_text(encoding="utf-8")
    trigger = check_trigger(text, path, root)
    expected_plan = root / "docs" / "versions" / str(trigger["version"]) / "modules" / str(trigger["packet_module"]) / str(trigger["task_name"]) / "pipeline" / "plan.md"
    if path.resolve() != expected_plan.resolve():
        fail(f"pipeline plan must be task-local: {expected_plan}")
    state_path, state = load_pipeline_state(path)
    check_state_metadata(state, state_path, trigger)
    tasks, dependencies = check_task_graph(text, path)
    check_parallel_policy(text, path)
    check_task_state(state, state_path, tasks, dependencies, args.require_complete)
    check_scheduler_state(state, state_path, tasks, dependencies, args.require_complete)
    check_design_evidence(text, path)
    bindings = check_implementation_scope_bindings(text, path, trigger)
    check_file_sequence(text, path, tasks, bindings)
    check_testing_evidence(state, state_path, trigger, args.require_complete)
    check_exit_condition(state, state_path, args.require_complete)
    if args.require_complete:
        check_completion_artifacts(root, trigger)
    print("pipeline-plan-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
