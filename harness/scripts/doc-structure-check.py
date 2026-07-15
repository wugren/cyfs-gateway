#!/usr/bin/env python3
"""Validate Harness Engineering module packet document structure."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


MAX_HUMAN_DOC_LINES = 1000
TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
EMPTY_VALUES = {"", "-", "n/a", "na", "none", "tbd", "todo"}

REQUIRED_SECTIONS = {
    "proposal.md": (
        "Background and Goal",
        "Scope",
        "Requirement Review",
        "Proposal Items",
        "Success Criteria",
        "Risks",
        "Approval Record",
    ),
    "design.md": (
        "Design Scope",
        "Useful Context",
        "Overall Approach",
        "Layered Design Document Index",
        "Module Relationship UML",
        "File-Level Interfaces",
        "Key Flows",
        "State and Ownership",
        "Directly Mapped Change Items",
        "Implementation Order",
        "File-Level Implementation Sequence",
        "Design Notes",
        "Risks and Rollback",
    ),
    "testing.md": (
        "Test Document Index",
        "Unified Test Entry",
        "Submodule Tests",
        "Module-Level Tests",
        "External Interface Tests",
        "Direct Change Coverage",
        "Case-Type Coverage",
        "Design Element Coverage",
        "Validation Rationale",
        "Unit Tests",
        "DV Tests",
        "Integration Tests",
        "Definition of Done",
    ),
}

REQUIRED_TABLE_COLUMNS = {
    ("proposal.md", "Proposal Items"): (
        "proposal_id",
        "change_id",
        "requirement",
        "boundary",
        "tradeoff",
        "success_evidence",
        "non_goal",
    ),
    ("design.md", "Directly Mapped Change Items"): (
        "change_id",
        "target_module",
        "proposal_id",
        "design_coverage",
        "scope_paths",
    ),
    ("design.md", "Implementation Order"): ("phase", "goal", "depends_on", "output"),
    ("design.md", "Layered Design Document Index"): (
        "level",
        "parent_document",
        "unit",
        "design_document",
        "responsibility",
    ),
    ("design.md", "File-Level Implementation Sequence"): (
        "sequence",
        "file_level_module",
        "action",
        "depends_on",
        "change_id",
        "scope_path",
        "implementation_task",
    ),
    ("testing.md", "Direct Change Coverage"): (
        "change_id",
        "design_source",
        "validation_id",
        "testplan_level",
        "testplan_step_id",
        "gap",
        "gap_manual_reason",
    ),
    ("testing.md", "Case-Type Coverage"): (
        "change_id",
        "case_type",
        "required",
        "validation_id",
        "level",
        "status",
        "gap_manual_reason",
    ),
    ("testing.md", "Design Element Coverage"): (
        "element_type",
        "design_source",
        "derived_cases",
        "level",
        "status",
        "gap_manual_reason",
    ),
    ("testing.md", "Unit Tests"): (
        "function_or_unit",
        "branch_or_condition",
        "covered_behavior",
        "test_file",
        "status",
        "gap_manual_reason",
    ),
    ("testing.md", "DV Tests"): (
        "workflow",
        "kind",
        "entry",
        "expected_result",
        "test_file_or_script",
        "status",
        "gap_manual_reason",
    ),
    ("testing.md", "Integration Tests"): (
        "contract_or_flow",
        "modules_involved",
        "success_case",
        "failure_case",
        "test_file",
        "status",
        "gap_manual_reason",
    ),
}

CASE_TYPES = {"normal", "boundary", "negative", "error", "compatibility", "lifecycle", "cross-module"}
TEST_LEVELS = {"unit", "dv", "integration"}
DESIGN_ELEMENT_TYPES = {
    "parameter-domain",
    "state-transition",
    "failure-path",
    "error-handling",
    "invariant",
    "concurrency",
}
COVERAGE_STATUSES = {"covered", "gap", "manual", "disabled", "not-applicable"}
DV_KINDS = {"lifecycle", "main", "failure", "config", "persistence"}
LEVEL_TABLE_HEADINGS = ("Unit Tests", "DV Tests", "Integration Tests")
SUBMODULE_TYPES = {"business", "shared", "technical", "assembly"}
GRAB_BAG_SHARED_NAMES = {"common", "utils", "util", "misc", "helpers", "helper"}
COMPATIBILITY_VALUES = {"new", "backward-compatible", "migration-required", "breaking"}
PUBLIC_API_IMPACTS = {"none", "backward-compatible", "migration-required", "breaking"}
MIGRATION_STATUSES = {"migrated", "allowed-negative-fixture", "allowed-compatibility-shim", "verified-none"}
NOT_APPLICABLE_RE = re.compile(r"(?i)^not-applicable\s*:\s*\S.*$")
MERMAID_BLOCK_RE = re.compile(r"```mermaid\s+([\s\S]*?)```", re.IGNORECASE)
CODE_BLOCK_RE = re.compile(r"```([A-Za-z0-9_+-]+)\s+([\s\S]*?)```", re.IGNORECASE)
UML_EDGE_RE = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s+[-.o*<|]+[-.]+[>.o*|]*\s+([A-Za-z_][A-Za-z0-9_.-]*)")
HTML_COMMENT_RE = re.compile(r"<!--[\s\S]*?-->")

def fail(message: str) -> None:
    print(f"doc-structure-check: {message}", file=sys.stderr)
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


def section_body(text: str, heading: str, path: Path) -> str:
    pattern = re.compile(rf"(?m)^##\s+{re.escape(heading)}\s*$")
    match = pattern.search(text)
    if not match:
        fail(f"{path} missing required section: ## {heading}")
    next_heading = re.search(r"(?m)^##\s+", text[match.end() :])
    end = match.end() + next_heading.start() if next_heading else len(text)
    return text[match.end() : end]



def visible_section_body(text: str, heading: str, path: Path) -> str:
    return HTML_COMMENT_RE.sub("", section_body(text, heading, path))


def section_declares_not_applicable(body: str) -> bool:
    return re.search(r"(?im)^\s*(?:[-*]\s*)?not-applicable\s*:\s*\S", body) is not None


def table_after_heading(text: str, heading: str, path: Path) -> list[dict[str, str]]:
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
        row = {header: values[pos].strip() if pos < len(values) else "" for pos, header in enumerate(headers)}
        rows.append(row)
    if not rows:
        fail(f"{path} section ## {heading} has no data rows")
    return rows


def non_empty(value: str) -> bool:
    return value.strip().lower() not in EMPTY_VALUES


def check_line_count(path: Path, max_lines: int) -> None:
    line_count = len(read_text(path).splitlines())
    if line_count > max_lines:
        fail(f"{path} has {line_count} lines; split docs above {max_lines} lines")


def check_sections(path: Path, text: str) -> None:
    for heading in REQUIRED_SECTIONS[path.name]:
        section_body(text, heading, path)


def check_tables(path: Path, text: str) -> None:
    for (name, heading), columns in REQUIRED_TABLE_COLUMNS.items():
        if name != path.name:
            continue
        rows = table_after_heading(text, heading, path)
        available = set(rows[0])
        missing = [column for column in columns if column not in available]
        if missing:
            fail(f"{path} ## {heading} missing columns: {', '.join(missing)}")
        for index, row in enumerate(rows, start=1):
            if all(not non_empty(value) for value in row.values()):
                fail(f"{path} ## {heading} row {index} is empty placeholder content")
            first_value = row.get(columns[0], "").strip()
            if is_not_applicable(first_value):
                require_not_applicable_reason(path, f"## {heading} row {index}", first_value)
                continue
            for column in columns:
                if column in {
                    "depends_on",
                    "gap_manual_reason",
                    "deferred_checks_and_reason",
                    "required_checks",
                    "testplan_step_id",
                    "type",
                    "test_file",
                    "test_file_or_script",
                    "derived_cases",
                    "design_source",
                    "level",
                }:
                    continue
                if not non_empty(row.get(column, "")):
                    fail(f"{path} ## {heading} row {index} column {column} is empty placeholder content")


def mermaid_blocks_for_section(text: str, heading: str, path: Path) -> list[str]:
    body = section_body(text, heading, path)
    return MERMAID_BLOCK_RE.findall(body)


FORBIDDEN_DESIGN_TEST_HEADINGS = {
    "test cases",
    "test plan",
    "testing strategy",
    "validation rationale",
    "unit tests",
    "dv tests",
    "integration tests",
    "test implementation",
}
FORBIDDEN_DESIGN_TEST_TERMS_RE = re.compile(r"(?i)\\b(testability seams?|validation ids?|test fixtures?|expected test results?)\\b")


def check_design_has_no_test_design(path: Path, text: str) -> None:
    for heading in re.findall(r"(?m)^##+\\s+(.+?)\\s*$", text):
        normalized = heading.strip().lower()
        if normalized in FORBIDDEN_DESIGN_TEST_HEADINGS:
            fail(f"{path} design-stage documents must not define testing section: {heading}")
    match = FORBIDDEN_DESIGN_TEST_TERMS_RE.search(HTML_COMMENT_RE.sub("", text))
    if match:
        fail(f"{path} design-stage documents must not define testing details: {match.group(1)}")


def check_design_uml(path: Path, text: str) -> None:
    body = visible_section_body(text, "Module Relationship UML", path)
    if section_declares_not_applicable(body):
        return
    blocks = MERMAID_BLOCK_RE.findall(body)
    if not blocks:
        fail(f"{path} ## Module Relationship UML must include a Mermaid UML diagram or not-applicable reason")
    if not any(re.search(r"(?m)^\s*classDiagram\b", block) for block in blocks):
        fail(f"{path} ## Module Relationship UML must use a Mermaid classDiagram for module relationships")
    check_uml_dependency_cycles(path, blocks)


def check_key_flow_diagrams(path: Path, text: str) -> None:
    body = visible_section_body(text, "Key Flows", path)
    if section_declares_not_applicable(body):
        return
    blocks = MERMAID_BLOCK_RE.findall(body)
    if not blocks:
        fail(f"{path} ## Key Flows must include a sequenceDiagram for cross-boundary flows or not-applicable reason")
    if not any(re.search(r"(?m)^\s*sequenceDiagram\b", block) for block in blocks):
        fail(f"{path} ## Key Flows must use Mermaid sequenceDiagram when flows are described")


def check_state_ownership(path: Path, text: str) -> None:
    body = visible_section_body(text, "State and Ownership", path)
    if section_declares_not_applicable(body):
        return
    if not re.search(r"(?im)^\s*-\s*Owner\s*:\s*\S", body):
        fail(f"{path} ## State and Ownership must name the single owner or record not-applicable")
    if re.search(r"(?i)state|lifecycle|transition", body):
        blocks = MERMAID_BLOCK_RE.findall(body)
        if blocks and not any(re.search(r"(?m)^\s*stateDiagram(?:-v2)?\b", block) for block in blocks):
            fail(f"{path} ## State and Ownership lifecycle diagrams must use Mermaid stateDiagram-v2")


def check_uml_dependency_cycles(path: Path, blocks: list[str]) -> None:
    graph: dict[str, set[str]] = {}
    for block in blocks:
        if not re.search(r"(?m)^\s*classDiagram\b", block):
            continue
        for source, target in UML_EDGE_RE.findall(block):
            graph.setdefault(source, set()).add(target)
            graph.setdefault(target, set())

    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            cycle = " -> ".join([*stack, node])
            fail(f"{path} ## Module Relationship UML contains a dependency cycle: {cycle}")
        visiting.add(node)
        stack.append(node)
        for dependency in sorted(graph.get(node, ())):
            visit(dependency)
        stack.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(graph):
        visit(node)


def check_file_level_interfaces(path: Path, text: str) -> None:
    body = visible_section_body(text, "File-Level Interfaces", path)
    values: set[str] = set()
    if not section_declares_not_applicable(body):
        blocks = CODE_BLOCK_RE.findall(body)
        source_blocks = [lang.lower() for lang, code in blocks if lang.lower() not in {"mermaid", "text", "txt", "plain", "markdown", "md"} and non_empty(code)]
        if not source_blocks:
            fail(f"{path} ## File-Level Interfaces must use fenced code blocks with the project language, or record not-applicable")
        if not re.search(r"(?im)^\s*-\s*Consumer\s*:\s*\S", body):
            fail(f"{path} ## File-Level Interfaces must name the consumer module or change_id")
        compatibility = re.search(r"(?im)^\s*-\s*Compatibility\s*:\s*([^\n]+)", body)
        if not compatibility:
            fail(f"{path} ## File-Level Interfaces must record compatibility")
        values = {part.strip().lower() for part in re.split(r"[/,]", compatibility.group(1))}
        if not values & COMPATIBILITY_VALUES:
            fail(f"{path} ## File-Level Interfaces compatibility must include one of: {', '.join(sorted(COMPATIBILITY_VALUES))}")
    impact_body = visible_section_body(text, "API and Build Surface Impact", path)
    impact_match = re.search(r"(?im)^\s*-\s*Public API impact\s*:\s*([^\n]+)", impact_body)
    public_api = impact_match.group(1).strip().lower() if impact_match else ""
    if public_api not in PUBLIC_API_IMPACTS:
        fail(f"{path} ## API and Build Surface Impact has invalid Public API impact: {public_api or '<missing>'}")
    flags: list[bool] = []
    for label in ("Crate-root export change", "Build-surface change", "Documentation examples affected"):
        match = re.search(rf"(?im)^\s*-\s*{re.escape(label)}\s*:\s*(yes|no)\s*$", impact_body)
        if not match:
            fail(f"{path} ## API and Build Surface Impact missing yes/no value for {label}")
        flags.append(match.group(1).lower() == "yes")
    risky = (
        public_api in {"breaking", "migration-required"}
        or bool(values & {"breaking", "migration-required"})
        or any(flags)
    )
    if not risky:
        return
    rows = table_after_heading(text, "Consumer Migration Closure", path)
    for index, row in enumerate(rows, start=1):
        for column in ("old_symbol", "new_path", "change_id", "consumer_kind", "migration_status"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## Consumer Migration Closure row {index} missing concrete {column}")
        status = row["migration_status"].strip().lower()
        if status not in MIGRATION_STATUSES:
            fail(f"{path} ## Consumer Migration Closure row {index} has invalid migration_status: {status}")
        if (public_api == "breaking" or "breaking" in values) and status == "allowed-compatibility-shim":
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


def is_not_applicable(value: str) -> bool:
    return value.strip().lower().startswith("not-applicable")


def require_not_applicable_reason(path: Path, context: str, value: str) -> None:
    if not NOT_APPLICABLE_RE.match(value.strip()):
        fail(f"{path} {context}: not-applicable entries need a concrete reason: `not-applicable: <reason>`")


def check_layered_design_index(path: Path, text: str) -> None:
    rows = table_after_heading(text, "Layered Design Document Index", path)
    for index, row in enumerate(rows, start=1):
        document = row.get("design_document", "").strip().strip("`")
        level = row.get("level", "").strip()
        if is_not_applicable(level):
            require_not_applicable_reason(path, f"## Layered Design Document Index row {index}", level)
            continue
        unit = row.get("unit", "").strip()
        if is_not_applicable(document):
            require_not_applicable_reason(path, f"## Layered Design Document Index row {index}", document)
            continue
        if document == "design.md":
            continue
        if not document.startswith("design/") or not document.endswith(".md"):
            fail(f"{path} ## Layered Design Document Index row {index} must use design/<submodule>.md style path")
        if not unit or unit.lower() in EMPTY_VALUES:
            fail(f"{path} ## Layered Design Document Index row {index} must name the submodule or nested submodule")
        child = path.parent / document
        if not child.exists():
            fail(f"{path} indexed child design document does not exist: {child}")


def check_file_level_implementation_sequence(path: Path, text: str) -> None:
    rows = table_after_heading(text, "File-Level Implementation Sequence", path)
    for index, row in enumerate(rows, start=1):
        module = row.get("file_level_module", "").strip()
        sequence = row.get("sequence", "").strip()
        if is_not_applicable(sequence):
            require_not_applicable_reason(path, f"## File-Level Implementation Sequence row {index}", sequence)
            continue
        if is_not_applicable(module):
            require_not_applicable_reason(path, f"## File-Level Implementation Sequence row {index}", module)
            continue
        for column in ("sequence", "file_level_module", "action", "change_id", "scope_path", "implementation_task"):
            if not non_empty(row.get(column, "")):
                fail(f"{path} ## File-Level Implementation Sequence row {index} column {column} is empty placeholder content")


def check_case_type_coverage(path: Path, text: str) -> None:
    if path.name != "testing.md":
        return
    rows = table_after_heading(text, "Case-Type Coverage", path)
    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        case_type = row.get("case_type", "").strip().lower()
        required = row.get("required", "").strip().lower()
        status = row.get("status", "").strip().lower()
        seen.add(case_type)
        if case_type not in CASE_TYPES:
            fail(f"{path} ## Case-Type Coverage row {index} has unknown case_type: {case_type}")
        if required not in {"yes", "no"}:
            fail(f"{path} ## Case-Type Coverage row {index} Required must be yes or no")
        if status not in {"covered", "gap", "manual", "disabled", "not-applicable"}:
            fail(f"{path} ## Case-Type Coverage row {index} has invalid status: {status}")
        if required == "yes" and status == "not-applicable":
            fail(f"{path} ## Case-Type Coverage row {index} cannot mark required coverage not-applicable")
        if status in {"gap", "manual", "disabled", "not-applicable"} and not non_empty(row.get("gap_manual_reason", "")):
            fail(f"{path} ## Case-Type Coverage row {index} requires Gap / Manual Reason")
        level = row.get("level", "").strip().lower()
        if status == "covered" and level not in TEST_LEVELS:
            fail(
                f"{path} ## Case-Type Coverage row {index} covered cases must declare the implementing "
                f"level (unit/dv/integration): {level or '<empty>'}"
            )
    missing = sorted(CASE_TYPES - seen)
    if missing:
        fail(f"{path} ## Case-Type Coverage missing case types: {', '.join(missing)}")


def check_design_element_coverage(path: Path, text: str) -> None:
    if path.name != "testing.md":
        return
    rows = table_after_heading(text, "Design Element Coverage", path)
    seen: set[str] = set()
    for index, row in enumerate(rows, start=1):
        element_type = row.get("element_type", "").strip().lower()
        status = row.get("status", "").strip().lower()
        reason = row.get("gap_manual_reason", "")
        seen.add(element_type)
        if element_type not in DESIGN_ELEMENT_TYPES:
            fail(f"{path} ## Design Element Coverage row {index} has unknown element_type: {element_type}")
        if status not in COVERAGE_STATUSES:
            fail(f"{path} ## Design Element Coverage row {index} has invalid status: {status}")
        if status == "covered":
            if not non_empty(row.get("design_source", "")):
                fail(f"{path} ## Design Element Coverage row {index} covered rows must name the design source")
            if not non_empty(row.get("derived_cases", "")):
                fail(f"{path} ## Design Element Coverage row {index} covered rows must list derived cases")
            level = row.get("level", "").strip().lower()
            if level not in TEST_LEVELS:
                fail(
                    f"{path} ## Design Element Coverage row {index} covered rows must declare the "
                    f"implementing level (unit/dv/integration): {level or '<empty>'}"
                )
        elif not non_empty(reason):
            fail(f"{path} ## Design Element Coverage row {index} requires Gap / Manual Reason")
    missing = sorted(DESIGN_ELEMENT_TYPES - seen)
    if missing:
        fail(f"{path} ## Design Element Coverage missing element types: {', '.join(missing)}")


def check_level_tables(path: Path, text: str) -> None:
    if path.name != "testing.md":
        return
    for heading in LEVEL_TABLE_HEADINGS:
        rows = table_after_heading(text, heading, path)
        first_column = REQUIRED_TABLE_COLUMNS[(path.name, heading)][0]
        seen_kinds: set[str] = set()
        escaped_rows = 0
        for index, row in enumerate(rows, start=1):
            if is_not_applicable(row.get(first_column, "").strip()):
                escaped_rows += 1
                continue
            status = row.get("status", "").strip().lower()
            if status not in COVERAGE_STATUSES:
                fail(f"{path} ## {heading} row {index} has invalid status: {status}")
            if status != "covered" and not non_empty(row.get("gap_manual_reason", "")):
                fail(f"{path} ## {heading} row {index} requires Gap / Manual Reason")
            if status == "covered" and "test_file" in row and not non_empty(row.get("test_file", "")):
                fail(f"{path} ## {heading} row {index} covered rows must name the test file")
            if heading == "DV Tests":
                kind = row.get("kind", "").strip().lower()
                if kind not in DV_KINDS:
                    fail(
                        f"{path} ## DV Tests row {index} kind must be one of "
                        f"{'/'.join(sorted(DV_KINDS))}: {kind or '<empty>'}"
                    )
                seen_kinds.add(kind)
        if heading == "DV Tests" and escaped_rows < len(rows):
            missing_kinds = sorted({"lifecycle", "main", "failure"} - seen_kinds)
            if missing_kinds:
                fail(
                    f"{path} ## DV Tests must include lifecycle, main, and failure workflow rows "
                    f"(covered or with recorded gaps); missing kinds: {', '.join(missing_kinds)}"
                )


def check_submodule_doc_placement(packet: Path) -> None:
    for folder_name in ("design", "testing"):
        folder = packet / folder_name
        if not folder.exists():
            continue
        for name in ("proposal.md", "design.md", "testing.md", "testplan.yaml"):
            matches = sorted(folder.rglob(name))
            if matches:
                rendered = ", ".join(str(path) for path in matches[:5])
                fail(f"submodule packet docs belong directly under the submodule packet, not {folder_name}/: {rendered}")


def check_doc(path: Path, max_lines: int) -> None:
    text = read_text(path)
    check_line_count(path, max_lines)
    check_sections(path, text)
    check_tables(path, text)
    if path.name == "design.md":
        check_design_uml(path, text)
        check_file_level_interfaces(path, text)
        check_key_flow_diagrams(path, text)
        check_state_ownership(path, text)
        check_design_has_no_test_design(path, text)
        check_layered_design_index(path, text)
        check_file_level_implementation_sequence(path, text)
    check_case_type_coverage(path, text)
    check_design_element_coverage(path, text)
    check_level_tables(path, text)
    if path.name == "testing.md" and "harness/scripts/test-run.py" not in text:
        fail(f"{path} must reference the unified test entrypoint")


def packet_path(root: Path, version: str, module: str, submodule: str | None) -> Path:
    packet = root / "docs" / "versions" / version / "modules" / module
    if submodule:
        packet = packet / submodule
    return packet


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--version", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--submodule")
    parser.add_argument("--max-lines", type=int, default=MAX_HUMAN_DOC_LINES)
    parser.add_argument(
        "--docs",
        choices=("all", "mandatory", "proposal", "design", "testing"),
        default="all",
    )
    args = parser.parse_args()

    packet = packet_path(Path(args.root), args.version, args.module, args.submodule)
    if args.docs in {"all", "mandatory", "proposal"}:
        check_doc(packet / "proposal.md", args.max_lines)
    if args.docs in {"all", "mandatory", "design"}:
        check_doc(packet / "design.md", args.max_lines)
    if args.docs in {"all", "testing"}:
        testing = packet / "testing.md"
        if testing.exists():
            check_doc(testing, args.max_lines)
        elif args.docs == "testing":
            fail(f"missing required file: {testing}")

    check_submodule_doc_placement(packet)
    print("doc-structure-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
