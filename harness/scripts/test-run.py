#!/usr/bin/env python3
"""Unified test entrypoint for Harness Engineering repositories.

Adapt this template to the target repository's test commands. The contract is
stable: all test implementation must be reachable through this entrypoint.

Every real run (not --list / --dry-run) writes a machine-readable run artifact
to test-results/test-runs/<timestamp>-<module>-<level>.json recording the exact
task scope, commands, registration sources, and exit codes. test-results/ is
generated output and must be listed in .gitignore. Acceptance cites these
artifacts instead of pasted command output.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path


LEVELS = ("unit", "dv", "integration")
TASK_NAME_RE = re.compile(r"^\d{3,}-[a-z0-9][a-z0-9_.-]*$")
RUN_ARTIFACT_SCHEMA = 1
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

# Canonical module-level regression suites. Task testplan.yaml files are
# discovered separately and are registered only as <module>/<task-name>.
# `module all` and `all all` use only each module's explicit `all` suite.
MODULE_SUITES: dict[str, dict[str, list[list[str]]]] = {
    "gateway-runtime": {
        "unit": [["bash", "-lc", "cd src && cargo test -p cyfs-gateway-lib --lib -- --test-threads=1"]],
        "dv": [["bash", "-lc", "cd src && cargo test -p cyfs_gateway --test test_control_server -- --test-threads=1"]],
        "integration": [["bash", "-lc", "cd src && cargo test -p cyfs_gateway --test test_cyfs_gateway -- --test-threads=1"]],
        "all": [["bash", "-lc", "cd src && cargo test -p cyfs_gateway -p cyfs-gateway-lib -- --test-threads=1"]],
    },
    "cert-manager": {
        "unit": [
            ["bash", "-lc", "cd src && cargo test -p cyfs-acme --lib -- --test-threads=1"],
            ["bash", "-lc", "cd src && cargo test -p cyfs-gateway-lib cert --lib -- --test-threads=1"],
        ],
        "dv": [["bash", "-lc", "cd src && cargo test -p cyfs-gateway-lib self_cert --lib -- --test-threads=1"]],
        "integration": [["bash", "-lc", "cd src && cargo test -p cyfs_gateway client_cert -- --test-threads=1"]],
        "all": [
            ["bash", "-lc", "cd src && cargo test -p cyfs-acme -- --test-threads=1"],
            ["bash", "-lc", "cd src && cargo test -p cyfs-gateway-lib cert -- --test-threads=1"],
            ["bash", "-lc", "cd src && cargo test -p cyfs_gateway cert -- --test-threads=1"],
        ],
    },
    "cyfs-tun": {
        "unit": [["bash", "-lc", "cd src && cargo test -p cyfs-tun --lib -- --test-threads=1"]],
        "dv": [],
        "integration": [],
        "all": [["bash", "-lc", "cd src && cargo test -p cyfs-tun -- --test-threads=1"]],
    },
    "process-chain-engine": {
        "unit": [["bash", "-lc", "cd src && cargo test -p cyfs-process-chain -p cyfs-process-chain-lint --lib -- --test-threads=1"]],
        "dv": [],
        "integration": [],
        "all": [["bash", "-lc", "cd src && cargo test -p cyfs-process-chain -p cyfs-process-chain-lint -- --test-threads=1"]],
    },
    "runtime-configs": {
        "unit": [["bash", "-lc", "cd src && cargo test -p cyfs_gateway config --lib -- --test-threads=1"]],
        "dv": [["bash", "-lc", "cd src && cargo test -p cyfs_gateway --test test_control_server -- --test-threads=1"]],
        "integration": [["bash", "-lc", "cd src && cargo test -p cyfs_gateway --test test_cyfs_gateway -- --test-threads=1"]],
        "all": [["bash", "-lc", "cd src && cargo test -p cyfs_gateway -- --test-threads=1"]],
    },
    "web-dashboard": {
        "unit": [],
        "dv": [],
        "integration": [],
        "all": [["bash", "-lc", "cd src/apps/cyfs_gateway/web && npm run build"]],
    },
}


def fail(message: str) -> None:
    print(f"test-run: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_inline_list(value: str) -> list[str]:
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError) as error:
        fail(f"invalid run command list {value!r}: {error}")
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        fail(f"run command must be a list of strings: {value!r}")
    return parsed


def steps_from_testplan(path: Path, level: str) -> list[tuple[list[str], str, list[str]]]:
    text = path.read_text(encoding="utf-8")
    start = re.search(rf"(?m)^  {re.escape(level)}:\s*$", text)
    if not start:
        return []
    next_level = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", text[start.end() :])
    end = start.end() + next_level.start() if next_level else len(text)
    body = text[start.end() : end]
    starts = list(re.finditer(r"(?m)^      - id:\s*(\S+)\s*$", body))
    steps: list[tuple[list[str], str, list[str]]] = []
    for index, match in enumerate(starts):
        block_end = starts[index + 1].start() if index + 1 < len(starts) else len(body)
        block = body[match.end() : block_end]
        change_ids = re.search(r"(?m)^        change_ids:\s*(\[[^\n]*\])\s*$", block)
        run = re.search(r"(?m)^        run:\s*(\[[^\n]*\])\s*$", block)
        if not change_ids or not run:
            fail(f"testplan step {level}/{match.group(1)} must define inline change_ids and run lists")
        steps.append(
            (
                parse_inline_list(run.group(1)),
                match.group(1),
                parse_inline_list(change_ids.group(1)),
            )
        )
    return steps


def contract_steps_from_testplan(path: Path) -> list[tuple[list[str], str, list[str], str, str]]:
    text = path.read_text(encoding="utf-8")
    start = re.search(r"(?m)^contract_checks:\s*$", text)
    if not start:
        return []
    next_top = re.search(r"(?m)^[A-Za-z0-9_-]+:\s*", text[start.end() :])
    end = start.end() + next_top.start() if next_top else len(text)
    body = text[start.end() : end]
    if re.search(r"(?m)^  mode:\s*disabled\s*$", body):
        return []
    starts = list(re.finditer(r"(?m)^    - id:\s*([A-Za-z0-9_.-]+)\s*$", body))
    steps: list[tuple[list[str], str, list[str], str]] = []
    for index, match in enumerate(starts):
        block_end = starts[index + 1].start() if index + 1 < len(starts) else len(body)
        block = body[match.end() : block_end]
        kind_match = re.search(r"(?m)^      kind:\s*([A-Za-z0-9_-]+)\s*$", block)
        assertion_match = re.search(r"(?m)^      assertion:\s*([A-Za-z0-9_-]+)\s*$", block)
        change_ids = re.search(r"(?m)^      change_ids:\s*(\[[^\n]*\])\s*$", block)
        run = re.search(r"(?m)^      run:\s*(\[[^\n]*\])\s*$", block)
        if (
            not kind_match
            or kind_match.group(1) not in CONTRACT_KINDS
            or not assertion_match
            or assertion_match.group(1) != CONTRACT_ASSERTIONS.get(kind_match.group(1))
            or not change_ids
            or not run
        ):
            fail(
                f"testplan contract step {match.group(1)} must define a supported kind "
                "plus inline change_ids and run lists"
            )
        steps.append(
            (
                parse_inline_list(run.group(1)),
                match.group(1),
                parse_inline_list(change_ids.group(1)),
                kind_match.group(1),
                assertion_match.group(1),
            )
        )
    return steps


def evidence_input_paths(root: Path, testplan: Path) -> list[Path]:
    text = testplan.read_text(encoding="utf-8")
    match = re.search(r"(?m)^evidence_inputs:\s*(\[[^\n]*\])\s*$", text)
    configured = parse_inline_list(match.group(1)) if match else []
    candidates = [testplan.resolve()]
    root_resolved = root.resolve()
    for value in configured:
        if value in {"", "."} or any(part == ".." for part in Path(value).parts):
            fail(f"invalid evidence input path in {testplan}: {value!r}")
        configured_path = root / value
        if configured_path.is_symlink():
            fail(f"evidence input must not be a symlink in {testplan}: {value}")
        candidate = configured_path.resolve()
        try:
            candidate.relative_to(root_resolved)
        except ValueError:
            fail(f"evidence input resolves outside repository in {testplan}: {value}")
        if not candidate.exists():
            fail(f"evidence input does not exist in {testplan}: {value}")
        if candidate.is_dir():
            for child in sorted(candidate.rglob("*")):
                if child.is_symlink():
                    fail(f"evidence input tree contains a symlink in {testplan}: {child}")
                if child.is_file() and not any(
                    part in {".git", ".venv", "target", "test-results", "__pycache__"}
                    for part in child.relative_to(root_resolved).parts
                ):
                    candidates.append(child.resolve())
        elif candidate.is_file():
            candidates.append(candidate)
    return sorted(set(candidates), key=lambda item: item.relative_to(root_resolved).as_posix())


def evidence_input_roots(root: Path, testplans: list[str]) -> list[str]:
    roots: set[str] = set()
    for relative in testplans:
        text = (root / relative).read_text(encoding="utf-8")
        match = re.search(r"(?m)^evidence_inputs:\s*(\[[^\n]*\])\s*$", text)
        if match:
            roots.update(parse_inline_list(match.group(1)))
    return sorted(roots)


def evidence_input_binding(root: Path, testplans: list[str]) -> tuple[list[str], str | None]:
    if not testplans:
        return [], None
    root_resolved = root.resolve()
    paths: set[Path] = set()
    for relative in testplans:
        paths.update(evidence_input_paths(root, root / relative))
    hasher = hashlib.sha256(b"harness-task-evidence-input-v1\0")
    relative_paths: list[str] = []
    for path in sorted(paths, key=lambda item: item.relative_to(root_resolved).as_posix()):
        relative = path.relative_to(root_resolved).as_posix()
        relative_paths.append(relative)
        hasher.update(relative.encode("utf-8") + b"\0" + path.read_bytes() + b"\0")
    return relative_paths, hasher.hexdigest()


def non_executed_levels_from_testplan(path: Path, requested_level: str) -> list[dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    levels = list(LEVELS) if requested_level == "all" else [requested_level]
    records: list[dict[str, str]] = []
    for level in levels:
        start = re.search(rf"(?m)^  {re.escape(level)}:\s*$", text)
        if not start:
            return []
        next_level = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", text[start.end() :])
        end = start.end() + next_level.start() if next_level else len(text)
        body = text[start.end() : end]
        mode_match = re.search(r"(?m)^    mode:\s*(manual|disabled)\s*$", body)
        reason_match = re.search(r"(?m)^    reason:\s*(.+)\s*$", body)
        if not mode_match or not reason_match or not reason_match.group(1).strip():
            return []
        records.append(
            {
                "level": level,
                "mode": mode_match.group(1),
                "reason": reason_match.group(1).strip(),
            }
        )
    return records


def discover_testplans(root: Path) -> dict[str, Path]:
    plans: dict[str, Path] = {}
    for path in root.glob("docs/versions/*/modules/**/testplan.yaml"):
        relative = path.relative_to(root / "docs" / "versions")
        if any(part.startswith("_") for part in relative.parts):
            continue
        modules_index = relative.parts.index("modules")
        packet_parts = relative.parts[modules_index + 1 : -1]
        if len(packet_parts) != 2 or not TASK_NAME_RE.fullmatch(packet_parts[1]):
            # Pre-refresh module-level and unsequenced packet plans remain
            # historical metadata. Canonical module suites replace the former,
            # and only sequence-prefixed task packets register task plans.
            continue
        text = path.read_text(encoding="utf-8")
        module = None
        task_name = None
        for line in text.splitlines():
            if line.startswith("module:"):
                module = line.split(":", 1)[1].strip()
            elif line.startswith("task_name:"):
                task_name = line.split(":", 1)[1].strip()
        if module:
            if not task_name:
                fail(f"task testplan must declare task_name and cannot register as a top-level module: {path}")
            if task_name != packet_parts[1]:
                fail(f"task_name must match task packet directory {packet_parts[1]}: {path}")
            key = f"{module}/{task_name}"
            if key in plans:
                fail(f"duplicate task testplan registration for {key}: {plans[key]} and {path}")
            plans[key] = path
    return plans


def validate_module_suites() -> None:
    allowed_levels = {*LEVELS, "all"}
    for module, suite in MODULE_SUITES.items():
        if not module or "/" in module:
            fail(f"invalid canonical module name: {module!r}")
        unknown = set(suite) - allowed_levels
        if unknown:
            fail(f"module {module} has unknown canonical levels: {', '.join(sorted(unknown))}")
        missing = allowed_levels - set(suite)
        if missing:
            fail(f"module {module} is missing canonical levels: {', '.join(sorted(missing))}")
        if not suite.get("all"):
            fail(f"module {module} must define a non-empty canonical all suite")
        for level, commands in suite.items():
            if not isinstance(commands, list):
                fail(f"module {module} canonical level {level} must be a list of argv lists")
            for command in commands:
                if not command or not isinstance(command, list) or not all(
                    isinstance(item, str) and item for item in command
                ):
                    fail(f"module {module} canonical level {level} has invalid argv: {command!r}")


def command_sources_for(
    root: Path,
    scope: str,
    requested_level: str,
    task_plans: dict[str, Path],
) -> list[tuple[list[str], dict[str, object]]]:
    entries: list[tuple[list[str], dict[str, object]]] = []
    if scope in MODULE_SUITES:
        suite = MODULE_SUITES[scope]
        if requested_level == "all":
            if "all" not in suite or not suite["all"]:
                fail(f"module {scope} must define a non-empty canonical all suite")
            levels = ["all"]
        else:
            levels = [requested_level]
        for level in levels:
            for command_index, command in enumerate(suite.get(level, [])):
                entries.append(
                    (
                        command,
                        {
                            "scope": scope,
                            "kind": "module-suite",
                            "level": level,
                            "registration_index": str(command_index),
                        },
                    )
                )
        return entries

    plan = task_plans.get(scope)
    if plan is None:
        fail(f"unknown module or task scope: {scope}")
    levels = list(LEVELS) if requested_level == "all" else [requested_level]
    try:
        plan_rel = plan.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        plan_rel = plan.as_posix()
    for level in levels:
        for command_index, (command, step_id, change_ids) in enumerate(steps_from_testplan(plan, level)):
            entries.append(
                (
                    command,
                    {
                        "scope": scope,
                        "kind": "task-testplan",
                        "level": level,
                        "testplan": plan_rel,
                        "step_id": step_id,
                        "change_ids": change_ids,
                        "registration_index": str(command_index),
                    },
                )
            )
    if requested_level == "all":
        contract_entries: list[tuple[list[str], dict[str, object]]] = []
        for command_index, (command, step_id, change_ids, contract_kind, assertion) in enumerate(
            contract_steps_from_testplan(plan)
        ):
            contract_entries.append(
                (
                    command,
                    {
                        "scope": scope,
                        "kind": "task-testplan-contract",
                        "level": "contract",
                        "contract_kind": contract_kind,
                        "assertion": assertion,
                        "testplan": plan_rel,
                        "step_id": step_id,
                        "change_ids": change_ids,
                        "registration_index": str(command_index),
                    },
                )
            )
        entries = contract_entries + entries
    return entries


def selected_scopes(requested_module: str, task_plans: dict[str, Path]) -> list[str]:
    if requested_module == "all":
        modules = sorted(MODULE_SUITES)
        if not modules:
            fail(
                "no canonical module suites registered in MODULE_SUITES; "
                "adapt harness/scripts/test-run.py to register each project module's "
                "explicit all suite before using 'all all'"
            )
        return modules
    if requested_module in MODULE_SUITES or requested_module in task_plans:
        return [requested_module]
    fail(f"unknown module or task scope: {requested_module}")


def deduplicated_execution_plan(
    root: Path,
    scopes: list[str],
    requested_level: str,
    task_plans: dict[str, Path],
) -> list[dict[str, object]]:
    by_argv: dict[tuple[str, ...], dict[str, object]] = {}
    for scope in scopes:
        for command, source in command_sources_for(root, scope, requested_level, task_plans):
            key = tuple(command)
            entry = by_argv.setdefault(key, {"command": command, "sources": []})
            sources = entry["sources"]
            if isinstance(sources, list) and source not in sources:
                sources.append(source)
    return list(by_argv.values())


def run_command(command: list[str], root: Path, dry_run: bool) -> int:
    print("+ " + " ".join(command))
    if dry_run:
        return 0
    completed = subprocess.run(command, cwd=root)
    return completed.returncode


def git_state(root: Path) -> tuple[str | None, bool | None]:
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True
        )
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True
        )
    except OSError:
        return None, None
    if head.returncode != 0 or status.returncode != 0:
        return None, None
    return head.stdout.strip(), bool(status.stdout.strip())


def write_run_artifact(
    root: Path,
    requested_module: str,
    requested_level: str,
    started_at: str,
    steps: list[dict[str, object]],
    exit_code: int,
    non_executed_levels: list[dict[str, str]] | None = None,
) -> None:
    artifact_dir = root / "test-results" / "test-runs"
    try:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        slug_module = requested_module.replace("/", "+")
        artifact_path = artifact_dir / f"{timestamp}-{slug_module}-{requested_level}.json"
        head, dirty = git_state(root)
        artifact = {
            "schema": RUN_ARTIFACT_SCHEMA,
            "requested_module": requested_module,
            "requested_level": requested_level,
            "started_at": started_at,
            "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "git_head": head,
            "worktree_dirty": dirty,
            "testplans": sorted(
                {
                    source["testplan"]
                    for step in steps
                    for source in step.get("sources", [])
                    if isinstance(source, dict) and isinstance(source.get("testplan"), str)
                }
            ),
            "change_ids": sorted(
                {
                    change_id
                    for step in steps
                    for source in step.get("sources", [])
                    if isinstance(source, dict)
                    for change_id in source.get("change_ids", [])
                    if isinstance(change_id, str)
                }
            ),
            "evidence_inputs": [],
            "evidence_input_roots": [],
            "evidence_input_sha256": None,
            "steps": steps,
            "non_executed_levels": non_executed_levels or [],
            "exit_code": exit_code,
        }
        artifact["evidence_inputs"], artifact["evidence_input_sha256"] = evidence_input_binding(
            root, artifact["testplans"]
        )
        artifact["evidence_input_roots"] = evidence_input_roots(root, artifact["testplans"])
        artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        print(f"test-run: run artifact written: {artifact_path}")
    except OSError as error:
        print(f"test-run: warning: failed to write run artifact: {error}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("module", help="module name, module/task-name, or all")
    parser.add_argument("level", choices=[*LEVELS, "all"], help="test level or all")
    parser.add_argument("--root", default=".")
    parser.add_argument("--list", action="store_true", help="list known modules and exit")
    parser.add_argument("--dry-run", action="store_true", help="print commands without running them")
    args = parser.parse_args()

    root = Path(args.root)
    validate_module_suites()
    task_plans = discover_testplans(root)
    modules = sorted({*MODULE_SUITES, *task_plans})
    if args.list:
        for module in modules:
            print(module)
        return 0

    scopes = selected_scopes(args.module, task_plans)
    plan = deduplicated_execution_plan(root, scopes, args.level, task_plans)
    if not plan:
        non_executed_levels = (
            non_executed_levels_from_testplan(task_plans[args.module], args.level)
            if len(scopes) == 1 and args.module in task_plans
            else []
        )
        if not non_executed_levels:
            fail("no test commands matched the requested module/task scope and level")
        started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        print(
            "test-run: passed without automated commands; selected levels are manual/disabled: "
            + ", ".join(
                f"{item['level']}={item['mode']} ({item['reason']})"
                for item in non_executed_levels
            )
        )
        if not args.dry_run:
            write_run_artifact(
                root,
                args.module,
                args.level,
                started_at,
                [],
                0,
                non_executed_levels,
            )
        return 0
    source_count = sum(len(entry["sources"]) for entry in plan if isinstance(entry.get("sources"), list))
    if source_count > len(plan):
        print(
            f"test-run: exact argv deduplication merged {source_count} registrations "
            f"into {len(plan)} commands"
        )

    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    steps: list[dict[str, object]] = []
    exit_code = 0
    for entry in plan:
        command = entry["command"]
        sources = entry["sources"]
        if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
            fail(f"invalid registered command: {command!r}")
        if not isinstance(sources, list) or not sources:
            fail(f"registered command has no sources: {command!r}")
        first_source = sources[0]
        step_start = time.monotonic()
        code = run_command(command, root, args.dry_run)
        steps.append(
            {
                "module": first_source.get("scope") if isinstance(first_source, dict) else None,
                "level": first_source.get("level") if isinstance(first_source, dict) else None,
                "command": command,
                "sources": sources,
                "exit_code": code,
                "duration_s": round(time.monotonic() - step_start, 3),
            }
        )
        if code != 0:
            exit_code = code
            break

    if not args.dry_run:
        write_run_artifact(root, args.module, args.level, started_at, steps, exit_code)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
