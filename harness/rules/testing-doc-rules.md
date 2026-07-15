# Testing Document Rules

## Goal
- Define optional persistent testing artifacts and post-implementation testing responsibilities.

## Scope
- `docs/versions/<version>/modules/<project>/<task-seq>-<task-slug>/testing.md`, `testing/`, and `testplan.yaml`.
- Cross-project testing artifacts under `docs/versions/<version>/modules/globals/<task-seq>-<task-slug>/`.

## Metadata For Optional Testing Documents
- `module`
- `version`
- `status`
- `approved_by`
- `approved_at`

## Required Content
- Test cases designed after implementation from proposal, design, and delivered code.
- Submodule, module, external interface, and direct `change_id` coverage.
- Validation rationale tied to concrete behaviors, risks, and success criteria.
- Case-type coverage for normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases, including the implementing test level.
- Per-level tables: `## Unit Tests`, `## DV Tests`, `## Integration Tests`, following `harness/rules/test-design-rules.md`.
- `## Design Element Coverage` mapping parameter domains, state transitions, failure paths, error categories, invariants, and concurrency declarations to cases or gaps.
- Stable test entrypoints aligned with `testplan.yaml` for completed testing work.
- For breaking/migration-required public APIs, crate-root export changes, or build-surface changes: a file-level repository consumer closure and risk-triggered contract checks derived from design.
- Explicit gap records for missing direct validation.
- Large-module submodule test documentation when design uses direct submodules.

## Guardrails
- Testing operationalizes approved proposal/design intent against delivered implementation.
- Optional testing docs with approval metadata follow the common approval authority rule; agents MUST NOT approve their own testing docs.
- Testing runs after implementation and MUST inspect proposal, design, and delivered code before designing cases.
- Test design MUST follow `harness/rules/test-design-rules.md`: unit covers changed-code branches, DV covers lifecycle/workflows/failure workflow, and integration covers consumed exported-interface success and failure semantics.
- Test cases MUST derive from design elements and record concrete evidence in `## Design Element Coverage`; `not-applicable` rows need a concrete design source.
- Verify each behavior at the lowest test level that can expose its failure; duplicate cross-level verification records a reason.
- Failure paths, error categories, or state transitions found in code but missing from design return to design.
- Testing tasks are single-stage by default and MUST NOT edit proposal, design, acceptance, production code, `docs/architecture/`, or another task packet unless explicitly requested.
- Testing may modify test code, fixtures, runners, optional testing artifacts, and unified test entrypoint wiring needed to register tests.
- Code inside an existing Rust `#[cfg(test)]` item is test code. Every newly created unit test MUST live in a dedicated test file, test directory, or test-only crate/package; testing MUST NOT add new inline test bodies to production source files.
- A production-path Rust file passes testing-stage scope only when `stage-scope-check.py --baseline-manifest .harness/baselines/<task-id>/manifest.json` compares it with a pre-edit snapshot captured by `baseline-snapshot.py` and proves that every change is inside a pre-existing exact `#[cfg(test)]` item. Missing/tampered baselines, new inline items, and mixed production/test changes fail closed.
- Baseline capture is project-local generated state. `.harness/` MUST be git-ignored, and testing tasks MUST NOT use `GIT_INDEX_FILE`, `git read-tree`, `git write-tree`, or `git commit-tree` to create synthetic Git baseline objects.
- Task-local testing artifacts stay in the same task packet, not older `testing/<task-seq>-<task-slug>/` directories.
- Human-authored testing docs MUST stay under 1000 lines, splitting by submodule, responsibility, validation layer, or interface boundary when needed.
- Every implemented change MUST have direct validation coverage or an explicit gap.
- Completed testing MUST generate/update `testplan.yaml` unless a repo-local versioned exception records reason, owner, risk, and acceptance impact.
- Every implemented `change_id` MUST map to validation ids and generated tests or `testplan.yaml` steps unless the validation path is `manual` or `disabled`.
- Every implemented `change_id` MUST have case-type rows; non-covered, manual, disabled, or not-applicable rows need concrete reasons.
- Every generated or changed automated test MUST be reachable through `harness/scripts/test-run.py`.
- The task's `testplan.yaml` MUST declare `task_name`, register only as `<module>/<task-name>`, and be reachable through `<module>/<task-name> all` without being aggregated into the top-level module.
- Single-task testing runs only `<module>/<task-name> <level-or-all>` from the active task plan. It MUST NOT trigger package/module suites, `all all`, root shortcuts, or quality gates; broader suites are explicit user-directed maintenance only.
- Narrow exception: when design marks `public-api: breaking` / `migration-required`, a crate-root export change, or a build-surface change, the task-local plan MUST contain the required repository consumer contract checks. The invocation remains `<module>/<task-name> all`, but its task-local `repository-compile-closure` step MAY run a package/workspace compile-only command such as `cargo test -p <package> --no-run --all-targets` for the affected consumer closure. This exception does not authorize executing the package's runtime test suite.
- Rust `--all-targets` excludes doctests. When documentation examples are affected, add a separate `documentation-examples` step such as `cargo test -p <package> --doc`, or a repository-defined README/example compile wrapper.
- Breaking APIs MUST provide `external-positive`, `external-negative`, `removed-symbol-scan`, and `repository-compile-closure` contract checks. The negative wrapper must succeed only when compilation fails for the expected removed symbol; raw failing compiler commands are not valid evidence.
- `removed-symbol-scan` MUST invoke the canonical `harness/scripts/consumer-closure-check.py`, which scans declared evidence-input roots, permits only explicitly recorded negative fixtures, and fails on remaining old-symbol references.
- Migration-required APIs MUST provide `external-positive`, `removed-symbol-scan`, and `repository-compile-closure`. Crate-root export changes require external-positive plus compile closure; build-surface-only changes require compile closure. Documentation-example impact requires `documentation-examples`.
- Risk-triggered tasks MUST declare `evidence_inputs` covering production scope, repository consumer files, external fixtures, test code, and affected documentation. Run artifacts bind their current content with `evidence_input_sha256` so acceptance rejects stale evidence.
- Test execution evidence is the machine-written artifact under `test-results/test-runs/`; pasted command output is not evidence.
- Bugfix testing MUST show red-green regression evidence for the bugfix `change_id`, or record why pre-fix reproduction is not feasible.
- Validation paths MUST prove named behavior or risk, not unrelated checks.
- Acceptance-returned testing gaps MUST supplement test design, test implementation, metadata when used, and unified-entrypoint runnable evidence before retry.
- Manual or disabled layers require reasons in generated evidence and optional metadata when present.
- Upstream design or implementation problems route to the owning stage instead of silently widening testing scope.
- Downstream acceptance follow-up is recorded unless cross-stage synchronization is explicitly requested.
- Before completion, run:
  - manual flow: `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/doc-structure-check.py --version <version> --module <module> --docs testing` only when optional `testing.md` exists
  - auto-pipeline: do not run `doc-structure-check.py --docs testing`, because `testing.md` / `testing/` are forbidden; validate pipeline testing evidence and `testplan.yaml` through `testing-coverage-check.py`
  - `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/testing-coverage-check.py --version <version> --module <module>`
- Use `testing-coverage-check.py --allow-missing-testplan` only with a recorded repo-local versioned exception.
