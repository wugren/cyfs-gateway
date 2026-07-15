# Unified Test Entry Rules

## Goal
- Define the canonical runnable test interface for all project validation.
- Ensure every generated or hand-written test can be run through one stable command surface.

## Scope
- project-root test shortcuts: `test-run.bat` on Windows and `test-run.sh` on Unix-like systems
- `harness/scripts/test-run.py`
- generated test implementation
- optional `testing.md`
- `testplan.yaml` for completed testing work, unless a repo-local versioned exception explicitly allows missing machine-readable test metadata

## Canonical Commands
- Project-root shortcut:
  - Windows: `test-run.bat [<module> <level>]`
  - Unix: `./test-run.sh [<module> <level>]`
- `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/test-run.py <module> unit`
- `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/test-run.py <module> dv`
- `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/test-run.py <module> integration`
- `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/test-run.py <module> all`
- `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/test-run.py <module>/<task-name> all`
- `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/test-run.py all all`

## Consistency Rule
- `harness/scripts/test-run.py` is mandatory in generated repositories.
- What each level (`unit` / `dv` / `integration`) must verify and how deep is defined by `harness/rules/test-design-rules.md`; this rule governs how those tests are invoked.
- A generated repository MUST include both project-root one-click test shortcuts: `test-run.bat` for Windows and `test-run.sh` for Unix-like systems.
- The root shortcut MUST check whether `uv` is installed and print an installation hint when it is missing.
- The root shortcuts MUST create a local `.venv` when it is missing, use `uv` to sync or install dependencies when project metadata exists, activate the project virtual environment, and then invoke `harness/scripts/test-run.py` through `UV_CACHE_DIR=.harness/uv-cache uv run --active python`.
- The root shortcut MUST NOT bypass the unified test entrypoint.
- The unified test interface MUST be able to run every project test that is part of the harness evidence chain.
- Bootstrap and harness refresh work MUST replace the empty example `MODULE_SUITES` mapping with explicit registrations for the target repository. Each registered module MUST define a non-empty canonical `all` suite; scaffold self-check MUST fail when no canonical module suite is registered.
- A testing task is not complete until every new or changed test implementation is registered with, or otherwise reachable through, the unified test interface.
- Every task-local `testplan.yaml` MUST declare `task_name` and register only as `<module>/<task-name>`; it MUST NOT be attached to the bare `<module>` scope.
- Package/module suites are mandatory maintenance commands independent of task plans; they MUST never be selected by single-task execution.
- Risk-triggered task-local contract steps are not module-suite selection. `<module>/<task-name> all` MAY execute a design-required package/workspace compile-only closure while remaining a task-scoped artifact; it MUST NOT execute the broad runtime suite.
- Generated tests, `testing.md`, and `testplan.yaml` must reference the same validation surfaces for completed testing work.
- Test scripts MUST be non-interactive and return meaningful exit codes.
- New test execution paths MUST be added to the canonical entrypoint instead of creating unrelated ad hoc commands.
- Test implementation may use local framework-specific commands internally, but acceptance and pipeline tasks must call them through `harness/scripts/test-run.py`.

## Execution Contract
- Unknown modules or test levels MUST exit non-zero.
- Every real run (not `--list` / `--dry-run`) MUST write a machine-readable run artifact to `test-results/test-runs/` recording requested task scope, requested level, covered `change_ids`, each executed command, its registration sources, exit code, duration, and optional informational git state. It MUST NOT calculate or record a repository/package state hash. `test-results/` is generated output, lives outside `harness/`, and MUST be listed in `.gitignore`.
- `<module>/<task-name> all` MUST run only the task's `unit`, `dv`, and `integration` testplan commands.
- `<module>/<task-name> all` MUST run enabled task-local `contract_checks` before the task's unit/DV/integration commands. Contract sources record `contract_kind` and its exact assertion in the run artifact.
- Single-task testing, acceptance, and auto-pipeline completion MUST invoke only `<module>/<task-name> <level-or-all>` and MUST NOT invoke `<module> <level-or-all>`, `all all`, or a root shortcut defaulting to those broader scopes.
- Package/module and `all all` commands MUST exist only for explicit user-directed maintenance outside a task flow.
- Exact argv duplicates MUST execute once and the run artifact MUST preserve all contributing registration sources.
- The runner MUST NOT infer semantic containment between different argv values. Broad and filtered framework commands remain distinct unless scope isolation prevents them from being selected together.
- Enabled steps MUST execute in declared order.
- "success without executing steps" MUST be reserved for task scopes whose every selected level is `manual` or `disabled` with a concrete reason; the run artifact records those non-executed levels and is not automated acceptance evidence by itself.
- Each enabled step MUST declare stable machine-readable fields `id`, `name`, `change_ids`, and `run`.
- Each contract step MUST additionally declare `kind` and the matching fixed `assertion`; arbitrary prose assertions do not satisfy acceptance.
- Task runs with API/build-surface contract checks MUST record expanded `evidence_inputs` plus `evidence_input_sha256`; acceptance recomputes the scoped hash instead of relying on a whole-repository hash.
- Each enabled step MUST declare the `change_ids` it validates when it is used as acceptance evidence.
- `harness/scripts/schema-check.py` MUST reject unknown levels, duplicate step ids, enabled levels without steps, enabled steps without `change_ids`, and manual or disabled levels without reasons when `testplan.yaml` exists.
