#!/usr/bin/env python3
"""Validate that a generated Harness Engineering scaffold is complete.

This checker is intentionally dependency-free. It verifies the default files
that the bootstrap kit expects every generated repository to contain.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path


REQUIRED_RULES = (
    "task-entry-gate-rules.md",
    "proposal-doc-rules.md",
    "design-doc-rules.md",
    "testing-doc-rules.md",
    "test-design-rules.md",
    "implementation-admission-rules.md",
    "schema-validation-rules.md",
    "unified-test-entry-rules.md",
    "acceptance-task-rules.md",
    "acceptance-review-rules.md",
    "quality-gate-rules.md",
    "auto-pipeline-rules.md",
)

REQUIRED_SCRIPTS = (
    "test-run.py",
    "schema-check.py",
    "task-seq.py",
    "admission-check.py",
    "baseline-snapshot.py",
    "stage-scope-check.py",
    "harness-self-check.py",
    "doc-structure-check.py",
    "architecture-doc-check.py",
    "testing-coverage-check.py",
    "consumer-closure-check.py",
    "acceptance-report-check.py",
    "pipeline-plan-check.py",
    "check-all.py",
    "quality-check.py",
)

REQUIRED_TASK_TEMPLATES = (
    "pipeline-stage-task.md",
    "pipeline-submodule-task.md",
    "acceptance-return-task.md",
)


def fail(message: str) -> None:
    print(f"harness-self-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def warn(message: str) -> None:
    print(f"harness-self-check: warning: {message}", file=sys.stderr)


def require_path(path: Path, *, directory: bool | None = None) -> None:
    if not path.exists():
        fail(f"missing required path: {path}")
    if directory is True and not path.is_dir():
        fail(f"expected directory: {path}")
    if directory is False and not path.is_file():
        fail(f"expected file: {path}")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        fail(f"{path} is not valid utf-8: {error}")


def require_contains(path: Path, patterns: tuple[str, ...]) -> None:
    text = read_text(path)
    missing = [pattern for pattern in patterns if pattern not in text]
    if missing:
        fail(f"{path} missing required references: {', '.join(missing)}")


def require_any(path: Path, patterns: tuple[str, ...], description: str) -> None:
    text = read_text(path)
    if not any(pattern in text for pattern in patterns):
        fail(f"{path} missing required reference: {description}")


def configured_module_suites(path: Path) -> dict[object, object]:
    """Read the literal MODULE_SUITES registration without executing the runner."""
    try:
        tree = ast.parse(read_text(path), filename=str(path))
    except SyntaxError as error:
        fail(f"{path} is not valid Python: {error}")
    for node in tree.body:
        target = node.target if isinstance(node, ast.AnnAssign) else None
        if isinstance(target, ast.Name) and target.id == "MODULE_SUITES":
            try:
                suites = ast.literal_eval(node.value)
            except (ValueError, TypeError) as error:
                fail(f"{path} MODULE_SUITES must be a literal mapping: {error}")
            if not isinstance(suites, dict):
                fail(f"{path} MODULE_SUITES must be a mapping")
            return suites
    fail(f"{path} does not define MODULE_SUITES")


def require_configured_module_suites(path: Path) -> None:
    suites = configured_module_suites(path)
    if not suites:
        fail(
            f"{path} has no canonical MODULE_SUITES; adapt the template to "
            "register each project module's explicit all suite"
        )
    for module, suite in suites.items():
        if not isinstance(module, str) or not module:
            fail(f"{path} has an invalid canonical module name: {module!r}")
        if not isinstance(suite, dict):
            fail(f"{path} module {module} suite must be a mapping")
        all_commands = suite.get("all")
        if not isinstance(all_commands, list) or not all_commands:
            fail(f"{path} module {module} must define a non-empty canonical all suite")


def check_root(root: Path) -> None:
    require_path(root / "AGENTS.md", directory=False)
    require_path(root / "test-run.bat", directory=False)
    require_path(root / "test-run.sh", directory=False)
    require_path(root / "docs", directory=True)
    require_path(root / "docs" / "architecture", directory=True)
    require_path(root / "docs" / "modules", directory=True)
    require_path(root / "docs" / "versions", directory=True)
    require_path(root / "harness", directory=True)
    require_path(root / "harness" / "rules", directory=True)
    require_path(root / "harness" / "custom-rules", directory=True)
    require_path(root / "harness" / "scripts", directory=True)
    require_path(root / "harness" / "process_rules", directory=True)
    require_path(root / "harness" / "quality-gates.yaml", directory=False)
    require_path(root / ".harness", directory=True)
    check_version_evidence_dirs(root)
    check_generated_output_ignored(root)


def check_version_evidence_dirs(root: Path) -> None:
    versions_dir = root / "docs" / "versions"
    version_dirs = [path for path in versions_dir.iterdir() if path.is_dir()]
    if not version_dirs:
        fail("docs/versions must contain at least one version directory")
    for version_dir in version_dirs:
        require_path(version_dir / "modules" / "tasks.md", directory=False)
        require_path(version_dir / "evidence" / "admission", directory=True)
        require_path(version_dir / "evidence" / "stage-scope", directory=True)
        require_path(
            version_dir / "evidence" / "stage-scope-manifest-meta.template.json",
            directory=False,
        )

def check_generated_output_ignored(root: Path) -> None:
    """Generated run artifacts and local Harness state must stay untracked."""
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        fail("missing .gitignore: test-results/ and .harness/ must be git-ignored")
    entries = {
        line.strip().lstrip("/").rstrip("/")
        for line in read_text(gitignore).splitlines()
    }
    missing = [entry for entry in ("test-results", ".harness") if entry not in entries]
    if missing:
        fail(
            ".gitignore must ignore generated Harness output: "
            + ", ".join(f"{entry}/" for entry in missing)
        )


def check_rules(root: Path) -> None:
    rules_dir = root / "harness" / "rules"
    for name in REQUIRED_RULES:
        require_path(rules_dir / name, directory=False)

    custom_dir = root / "harness" / "custom-rules"
    for path in custom_dir.glob("*.md"):
        if path.name in REQUIRED_RULES:
            fail(f"skill-managed rule appears under harness/custom-rules: {path}")


def check_scripts(root: Path) -> None:
    scripts_dir = root / "harness" / "scripts"
    for name in REQUIRED_SCRIPTS:
        path = scripts_dir / name
        require_path(path, directory=False)
        text = read_text(path)
        if "raise SystemExit(main())" not in text:
            warn(f"{path} does not expose the standard main() exit pattern")

    require_contains(
        root / "test-run.bat",
        ("uv", ".venv", "uv run", "--active", "python", "UV_CACHE_DIR", ".harness\\uv-cache"),
    )
    require_any(
        root / "test-run.bat",
        ("harness/scripts/test-run.py", "harness\\scripts\\test-run.py"),
        "harness/scripts/test-run.py",
    )
    require_contains(
        root / "test-run.sh",
        (
            "uv",
            ".venv",
            "uv run",
            "--active",
            "python",
            "harness/scripts/test-run.py",
            "UV_CACHE_DIR",
            ".harness/uv-cache",
            "mkdir -p",
        ),
    )
    require_configured_module_suites(scripts_dir / "test-run.py")
    require_contains(
        scripts_dir / "test-run.py",
        ("contract_steps_from_testplan", "contract_kind", "evidence_input_sha256"),
    )


def check_process_templates(root: Path) -> None:
    require_path(root / "harness" / "process_rules" / "task-template.md", directory=False)
    template_dir = root / "harness" / "process_rules" / "task_templates"
    require_path(template_dir, directory=True)
    for name in REQUIRED_TASK_TEMPLATES:
        require_path(template_dir / name, directory=False)


def check_agents_references(root: Path) -> None:
    agents = root / "AGENTS.md"
    require_contains(
        agents,
        (
            "harness/rules/task-entry-gate-rules.md",
            "harness/scripts/schema-check.py",
            "harness/scripts/admission-check.py",
            "harness/scripts/stage-scope-check.py",
        ),
    )


def check_markdown_path_references(root: Path) -> None:
    """Catch obvious stale generated path references in default harness files."""

    checked_roots = [root / "AGENTS.md", root / "harness" / "rules", root / "harness" / "process_rules"]
    pattern = re.compile(r"`((?:harness|docs|test-run)[^`]+?)`")
    missing: list[tuple[Path, str]] = []
    for base in checked_roots:
        paths = [base] if base.is_file() else sorted(base.rglob("*.md"))
        for path in paths:
            text = read_text(path)
            for match in pattern.finditer(text):
                raw = match.group(1).strip()
                if any(token in raw for token in ("<", ">", "|", "*", " ", "\n")):
                    continue
                candidate = root / raw.replace("\\", "/")
                if not candidate.exists() and raw.startswith(("harness/", "docs/")):
                    missing.append((path, raw))
    if missing:
        for path, raw in missing[:20]:
            print(f"  - {path}: {raw}", file=sys.stderr)
        fail("generated docs reference missing concrete paths")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--skip-reference-check",
        action="store_true",
        help="skip best-effort markdown path reference validation",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    check_root(root)
    check_rules(root)
    check_scripts(root)
    check_process_templates(root)
    check_agents_references(root)
    if not args.skip_reference_check:
        check_markdown_path_references(root)

    print("harness-self-check: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
