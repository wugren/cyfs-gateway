#!/usr/bin/env python3
"""Run the repository's declared mechanical quality gates (build, lint, ...).

Gates are declared in harness/quality-gates.yaml. This checker fails closed:
- a missing config file fails
- `gates: []` fails unless `empty_reason` records a concrete versioned decision
- any failing gate command fails the run

Every explicitly requested real run writes a machine-readable artifact to
test-results/quality-runs/<timestamp>.json recording each gate's command and
exit code. test-results/ is generated output and must be listed in .gitignore.
Task execution and acceptance do not invoke this checker automatically.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import json
import re
import subprocess
import sys
import time
from pathlib import Path


CONFIG_RELATIVE_PATH = "harness/quality-gates.yaml"
RUN_ARTIFACT_SCHEMA = 1


def fail(message: str) -> None:
    print(f"quality-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_run_list(value: str, gate_id: str) -> list[str]:
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError) as error:
        fail(f"gate {gate_id} has an invalid run command list {value!r}: {error}")
    if not isinstance(parsed, list) or not parsed or not all(isinstance(item, str) for item in parsed):
        fail(f"gate {gate_id} run command must be a non-empty list of strings: {value!r}")
    return parsed


def parse_gates(path: Path) -> list[dict[str, object]]:
    text = path.read_text(encoding="utf-8")
    if not re.search(r"(?m)^schema_version:\s*1\s*$", text):
        fail(f"{path} missing or unsupported schema_version (expected 1)")
    gates_line = re.search(r"(?m)^gates:\s*(\[\s*\])?\s*$", text)
    if not gates_line:
        fail(f"{path} missing required top-level key: gates")
    if gates_line.group(1):
        reason_match = re.search(r"(?m)^empty_reason:\s*(.+)\s*$", text)
        reason = reason_match.group(1).strip().strip('"').strip("'") if reason_match else ""
        if (
            not reason
            or len(reason) < 12
            or re.search(r"<[^>]+>|\b(tbd|todo|pending|n/a|none)\b", reason, re.IGNORECASE)
        ):
            fail(
                f"{path} declares gates: [] but empty_reason is missing, placeholder-only, "
                "or too short; record the concrete reason no mechanical quality gate applies"
            )
        return []

    gates: list[dict[str, object]] = []
    current_id: str | None = None
    for line in text[gates_line.end() :].splitlines():
        if re.match(r"^\S", line) and not line.startswith("#"):
            break
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        id_match = re.match(r"^-\s*id:\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*$", stripped)
        if id_match:
            current_id = id_match.group(1)
            gates.append({"id": current_id, "run": None})
            continue
        run_match = re.match(r"^run:\s*(\[.*\])\s*$", stripped)
        if run_match:
            if current_id is None or gates[-1]["run"] is not None:
                fail(f"{path} run entry without a preceding gate id")
            gates[-1]["run"] = parse_run_list(run_match.group(1), current_id)
            continue
        fail(f"{path} unrecognized gates entry: {stripped!r}")

    ids = [gate["id"] for gate in gates]
    if len(ids) != len(set(ids)):
        fail(f"{path} duplicate gate ids")
    for gate in gates:
        if gate["run"] is None:
            fail(f"{path} gate {gate['id']} missing run command")
    return gates


def write_run_artifact(root: Path, steps: list[dict[str, object]], exit_code: int, started_at: str) -> None:
    artifact_dir = root / "test-results" / "quality-runs"
    try:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        artifact_path = artifact_dir / f"{timestamp}-quality.json"
        artifact = {
            "schema": RUN_ARTIFACT_SCHEMA,
            "started_at": started_at,
            "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "gates": steps,
            "exit_code": exit_code,
        }
        artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        print(f"quality-check: run artifact written: {artifact_path}")
    except OSError as error:
        print(f"quality-check: warning: failed to write run artifact: {error}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--list", action="store_true", help="list configured gates and exit")
    args = parser.parse_args()

    root = Path(args.root)
    config = root / CONFIG_RELATIVE_PATH
    if not config.exists():
        fail(
            f"missing {config}: declare the repository's quality gates (build, lint, "
            "typecheck, ...) there, or declare `gates: []` with a concrete "
            "empty_reason as a versioned decision"
        )

    gates = parse_gates(config)
    if args.list:
        for gate in gates:
            print(f"{gate['id']}: {' '.join(gate['run'])}")
        return 0

    if not gates:
        print(
            "quality-check: passed (no quality gates configured; "
            f"{CONFIG_RELATIVE_PATH} declares an explicitly empty gates list)"
        )
        return 0

    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    steps: list[dict[str, object]] = []
    exit_code = 0
    for gate in gates:
        command = gate["run"]
        print(f"quality-check: running gate {gate['id']}: {' '.join(command)}")
        step_start = time.monotonic()
        try:
            completed = subprocess.run(command, cwd=root)
            code = completed.returncode
        except OSError as error:
            print(f"quality-check: gate {gate['id']} failed to start: {error}", file=sys.stderr)
            code = 1
        steps.append(
            {
                "id": gate["id"],
                "command": command,
                "exit_code": code,
                "duration_s": round(time.monotonic() - step_start, 3),
            }
        )
        if code != 0:
            exit_code = code

    write_run_artifact(root, steps, exit_code, started_at)
    if exit_code != 0:
        failed = [step["id"] for step in steps if step["exit_code"] != 0]
        print(f"quality-check: FAILED gates: {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"quality-check: passed ({len(steps)} gate(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
