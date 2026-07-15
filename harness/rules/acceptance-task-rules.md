# Acceptance Task Rules

## Goal
- Define how acceptance evaluates evidence and records outcomes.

## Scope
- Optional `acceptance.md`.
- Acceptance result reports under the active task packet, by default `docs/versions/<version>/modules/<module>/<task-seq>-<task-slug>/acceptance-report.md` or `docs/versions/<version>/modules/globals/<task-seq>-<task-slug>/acceptance-report.md` for cross-project work.

## Required Inputs
- Active task packet proposal/design, optional testing/acceptance artifacts, implementation, tests, and test results relevant to the reviewed `change_id` values and affected paths.
- Long-lived module docs and relevant project-wide docs under `docs/architecture/` only when repo-local project rules or task evidence make them applicable.
- Optional git diff/status evidence when useful for locating changed files.
- `harness/rules/acceptance-review-rules.md`.

## Acceptance Rule
- Acceptance first defines the task-relevant acceptance scope: reviewed `change_id` values, active task packet, affected module paths, and evidence-bearing modules.
- Acceptance evaluates only the evidence chain relevant to that scope and MUST apply `harness/rules/acceptance-review-rules.md`.
- Acceptance MUST execute only task-scoped automated tests. Direct package/module runtime suites, whole-project suites, root shortcuts, and quality-gate commands are forbidden in single-task acceptance; changes under `harness/**` or `docs/**` never trigger them.
- Risk-triggered API/build-surface tasks remain task-scoped: acceptance invokes only `<module>/<task-name> all`, whose task-local plan may contain the required package/workspace compile-only consumer closure. The exception never authorizes broad runtime test execution.
- Git diff/status output is discovery evidence only, not the acceptance standard.
- Acceptance MUST check consistency between proposal, design, relevant project-rule-governed `docs/architecture/` docs when applicable, implementation, testing implementation, generated acceptance rules, and expected results.
- Approved `proposal.md` is authoritative when downstream artifacts conflict.
- Subject to the proposal, non-requirement fixes route design -> implementation/code -> testing implementation.
- Acceptance writes a standalone review report and MUST NOT edit stage docs, code, or tests unless the user explicitly requested a separate cross-stage update task.
- Auto-pipeline acceptance MUST NOT create `acceptance.md` by default; it records final acceptance in task-local `pipeline/state.json` and the task-packet `acceptance-report.md`.
- Each blocking mismatch MUST identify its owning stage.
- Reviewed behavior MUST map to direct proposal/design items and stable `change_id` values, not only module overviews.
- Every evidence-bearing module or task packet MUST have approved directly mapped proposal/design coverage, project-rule-governed `docs/architecture/` evidence where applicable, and post-implementation testing evidence.
- Completed testing work MUST include `testplan.yaml` unless a versioned exception records reason, owner, risk, and acceptance impact.
- Acceptance MUST judge post-implementation test design adequacy for proposal/design/code behavior, including relevant normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases.
- Acceptance MUST perform and record an implementation correctness audit beyond test pass/fail. It MUST cover logic/control flow, termination/progress, concurrency/synchronization, resource lifetime/cleanup, state/data integrity, error handling/recovery, interface boundaries/compatibility, and security/capacity safety; every category needs inspected evidence and either pass, a concrete finding, or a concrete not-applicable reason.
- Automated test evidence MUST be reachable through `harness/scripts/test-run.py`; reuse the existing `<module>/<task-name> all` artifact while implementation, tests, testplan, and registration are unchanged, and rerun only after one of those inputs changes.
- Execution evidence MUST cite a machine-written `test-results/test-runs/*.json` artifact matching `<module>/<task-name> all` and the reviewed `change_id` values. Artifacts MUST NOT carry or be validated by a repository/package state hash.
- Risk-triggered API/build-surface artifacts instead carry explicit evidence-input roots, their expanded files, and `evidence_input_sha256`; acceptance re-expands and rehashes that scoped closure so new or modified consumer inputs invalidate stale evidence.
- When no automated task run can apply, acceptance MUST replace the run artifact with a structured `## Automated Test Exception` containing `Applies: yes`, a concrete reason, owner, risk, acceptance impact, and alternative evidence; `not applicable` alone is not sufficient.
- Quality gates are independent, explicitly user-invoked checks and are not acceptance-blocking single-task evidence.
- Bugfix acceptance MUST verify red-green regression evidence or a concrete infeasibility reason.
- Implementation task paths MUST be bound to admitted design `Scope Paths` through `stage-scope-check.py --stage implementation --change-id ... --changed-paths-file ...`.
- Acceptance MUST cite the pre-existing admission stamp and MUST NOT replay implementation admission while its bound inputs are unchanged. A missing result returns to the owning stage; acceptance does not create or refresh admission evidence.
- Missing active module, active task packet, `change_id`, or required evidence is blocking.
- Passing tests alone never imply acceptance.
- Before final judgment, reuse existing task-relevant validation. Run a gate again only after its owned inputs changed; run `acceptance-report-check.py` after the report itself is created or modified.

## Failure Handling
- Proposal ambiguity, contradiction, incorrect requirement, or incorrect acceptance boundary: stop acceptance and any auto-pipeline, report the issue, and ask the user to decide. Do not infer the requirement or open an automatic proposal return task.
- Proposal-to-design mismatch or a missing/incorrect architecture, algorithm, state model, concurrency model, resource-lifetime model, interface contract, or failure strategy: return to design.
- Design-to-code or document-to-code mismatch: return to implementation/code, or design when docs need synchronization.
- Missing, invalid, stale, non-runnable, ambiguous, incomplete, or unreasonable test design / test implementation coverage: return to testing.
- Project-rule-governed architecture-doc-to-code mismatch: return to design for doc sync or implementation when code violates approved design.
- Implementation defect against an adequate design, including incorrect logic, non-termination, deadlock/race, resource leak, state corruption, error-path defect, or compatibility/security/capacity defect: return to implementation.
- Logic or consistency finding: return to the owning stage named by the finding.
- Non-requirement findings repeat design -> implementation -> testing implementation, then rerun acceptance.
- More than 5 unsuccessful iterations for the same unresolved issue: stop and report the issue to the user.
