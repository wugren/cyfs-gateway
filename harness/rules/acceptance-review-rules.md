# Acceptance Review Gate

## Goal
- Define acceptance as an evidence-chain and consistency review.
- Acceptance confirms that approved behavior is implemented, documents agree with code/tests, and no logic defect invalidates the result.
- Git diff output is optional scoping evidence, not the acceptance standard.
- Acceptance defines a task-relevant scope before running checks and must not execute unrelated audits or commands.

## Required Audits
Acceptance MUST audit:
- Task-relevant scope: reviewed `change_id` values, active task packet, affected module paths, and evidence-bearing modules.
- Document coverage for every approved behavior, non-goal, constraint, and acceptance boundary.
- Consistency across task packet docs, generated acceptance rules, expected results, long-lived module docs, and relevant project-rule-governed `docs/architecture/` docs when applicable.
- Implementation and test evidence against proposal, design, and relevant project architecture docs when applicable.
- Test design adequacy for relevant normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases.
- Design quality: dependency direction, shared-submodule justification, interface minimality, compatibility decisions, data/state ownership, failure paths, alternatives, testability seams, and invariants.
- Implementation correctness beyond test pass/fail: logic/control flow, termination/progress, concurrency/synchronization, resource lifetime/cleanup, state/data integrity, error handling/recovery, interface boundaries/compatibility, and security/capacity safety.
- Logic defects: contradictions, impossible states, missing cases, invalid assumptions, or correctness risks.

## Evidence Discovery
Optional changed-file discovery commands:
- `git status --short`
- `git diff --stat`
- `git diff --name-status`
- `git diff --check`

These commands do not pass or fail acceptance by themselves. For public symbol, API, codec, or wire-format migrations, ad hoc `rg` is discovery only; accepted evidence must come from the task's machine-recorded removed-symbol-scan contract step.

## Validation Evidence Reuse
Acceptance MUST cite the existing passing schema result, admission stamp, stage-scope result, pipeline-plan result when applicable, and task-test artifact. It MUST NOT rerun those checkers or tests while their owned inputs are unchanged.

Rerun only the checker whose owned input changed after its latest pass:
- schema: a schema-bearing packet document or metadata file changed
- admission: a bound proposal/design/plan, admission evidence, target module, `change_id`, or admitted Scope Path changed
- stage scope: the manifest, sidecar, baseline, governed task path, or admitted Scope Path changed
- pipeline plan: task-local plan, state, or completion evidence changed
- task tests: affected implementation, test code, testplan, or registered command changed

A stage transition, acceptance start, commit, CI run, or need to fill the report is not an input change. A missing prior result fails acceptance and returns to the owning stage; acceptance MUST NOT manufacture it by replaying the checker. Run `acceptance-report-check.py` only after creating or modifying the acceptance report itself.

Task-relevant execution evidence MUST be a machine-written task artifact under `test-results/test-runs/`. Reuse it when its implementation, tests, testplan, and registered command inputs are unchanged. The acceptance checker MUST compare report `Version`, `Module`, `Task name`, and reviewed `change_id` values to artifact `testplans`, `requested_module`, `requested_level`, `change_ids`, and non-empty successful executed steps; exit code alone is insufficient. It MUST NOT require or validate a repository/package state hash. An accepted report without an automated task run MUST include a structured `## Automated Test Exception` with `Applies: yes`, concrete reason, owner, risk, acceptance impact, and alternative evidence. A bare `not applicable` statement is invalid.

Quality gates are not part of automatic single-task acceptance. Changes under `harness/**` or `docs/**` never trigger them. They may be run and cited only after an explicit user request.

## Evidence Scope
Acceptance MUST identify the documents, code paths, tests, and results used for each approved behavior. Unrelated worktree churn and unrelated validations are not blocking and must not be executed as acceptance requirements. Reject only when reviewed evidence shows missing approved behavior, document inconsistency, project-rule-governed architecture doc inconsistency, document/code mismatch, logical contradiction, unsupported assumption, or relevant correctness defect.

## Cross-Module Admission
- Every evidence-bearing module or task packet MUST have approved manual-flow proposal/design coverage or launch-confirmed auto-pipeline proposal/design mappings, direct `change_id` mapping, and post-implementation test evidence or explicit gaps.
- Every automated test used as evidence MUST be reachable through the unified test entrypoint.
- Project-root shortcuts, package/module suites, and whole-project commands are explicit maintenance interfaces outside single-task acceptance.
- Exception: acceptance still invokes only `<module>/<task-name> all`, but a risk-triggered task artifact MUST include its task-local repository compile-only closure and other required API contract steps. This is not permission to run a broad runtime suite.
- Multi-project behavior MUST use a `globals/<task-seq>-<task-slug>/` packet and pass checks for each affected implementation scope.
- New task evidence MUST come from the current task packet, not older packets; approved packets MUST NOT be treated as editable containers for new or expanded work.
- Draft, missing, ambiguous, or non-covering docs fail acceptance even when workspace tests pass.

## Design Quality
Acceptance checks the approved design against delivered implementation:
- Dependency direction: shared/technical do not depend on business, and nothing depends on assembly.
- Shared submodules: at least 2 real consumers and one clear responsibility.
- Interfaces: every export has a real consumer or mapped `change_id`; interface changes carry compatibility and migration detail.
- Data/state: each persistent datum or shared state is written only by its recorded owner.
- Failure paths: code matches recorded timeout, retry, idempotency, and partial-completion behavior.
- Alternatives: recorded alternatives are genuine, not template filler.
- Testability seams: promised seams exist and were usable by tests or justified gaps.
- Invariants: preserved-invariant regressions block acceptance.

Structural findings return to design; implementation deviations from adequate design return to implementation.

## Test Design Adequacy
Acceptance MUST review post-implementation test design before accepting:
- Approved behaviors, constraints, non-goals, acceptance boundaries, and implemented `change_id` values map to tests or explicit gaps.
- Relevant normal, boundary, negative, error, compatibility, lifecycle, concurrency/retry, and cross-module cases are covered.
- Per-level contracts from `harness/rules/test-design-rules.md` are satisfied.
- `## Design Element Coverage` rows trace to real design elements, not template-like evidence.
- Each behavior is verified at the lowest effective level.
- Completed testing includes `testplan.yaml` unless a versioned exception records reason, owner, risk, and acceptance impact.
- Bugfix work shows red-green regression evidence or a concrete infeasibility reason.
- Testing docs, metadata, implementation, and command evidence agree.
- Broad smoke-only or unregistered tests do not count unless a concrete rationale explains why deeper validation is not applicable.

Incomplete, unreasonable, ambiguous, stale, or non-runnable test coverage returns to testing.

## Implementation Correctness Audit
Acceptance MUST inspect delivered code and relevant runtime evidence rather than infer correctness from passing tests. The report MUST contain one row for every category below; `not applicable` is allowed only with a concrete task-specific reason.

- Logic and control flow: incorrect algorithms or conditions, off-by-one behavior, wrong branch selection, unintended fallthrough, unreachable required behavior, numeric overflow/underflow, and invalid assumptions.
- Termination and progress: infinite loops or recursion, hot spinning, permanently blocking waits, livelock, starvation, and retry loops without a bounded or externally controlled exit.
- Concurrency and synchronization: data races, deadlocks and lock-order cycles, lost wakeups, non-atomic compound operations, ordering/visibility defects, unsafe shared state, cancellation races, and check-then-act races.
- Resource lifetime and cleanup: memory, file, socket, transaction, thread, task, timer, subscription, lock, and device-handle leaks; double release, use-after-release, and missing cleanup on success, failure, timeout, or cancellation.
- State and data integrity: illegal transitions, partial initialization or commit, multi-writer violations, corruption, stale cache/state, broken transaction boundaries, duplicate side effects, and retry/idempotency defects.
- Error handling and recovery: swallowed or misclassified errors, incorrect fallback, missing rollback, retry storms, timeout/backpressure defects, partial-failure handling, and failure paths that leave the system unusable.
- Interface boundary and compatibility: invalid input handling, null/empty/extreme values, serialization/encoding errors, API/wire/runtime semantic regressions, caller migration gaps, and trust-boundary mistakes.
- Security and capacity safety: authorization/authentication bypass, injection, secret exposure, unsafe deserialization, path traversal, denial-of-service amplification, unbounded queues/memory/tasks, and algorithmic resource blowups where applicable.

Every defect MUST identify the earliest owning stage. If the proposal is ambiguous, contradictory, or incorrect, stop and ask the user. If the design's architecture, algorithm, state/concurrency/resource/interface/failure model is absent or wrong, return to design. If an adequate design exists but code is defective, return to implementation. If the defect is only missing or defective validation, return to testing. Acceptance MUST NOT repair the defect in place.

## Document Timing Consistency
- Approved documents need a current `approved_content_sha256`; stale hashes show an invalid post-approval edit and do not authorize refreshing metadata on the old document. Use a sibling amendment/fix task for approved-document corrections.
- Downstream design approval MUST NOT predate proposal coverage it claims to implement.
- Testing artifacts created before final implementation MUST be regenerated or explicitly revalidated.
- Acceptance fails when approval exists but approved content does not directly cover reviewed evidence.

## Acceptance Must Fail If
- Approved behavior, constraint, non-goal, or acceptance boundary is missing or unverifiable.
- Required evidence lacks approved manual-flow proposal/design coverage or launch-confirmed auto-pipeline proposal/design mappings, post-implementation test evidence, or required project-rule-governed architecture docs when applicable.
- Stage scope checks are missing or failing.
- Public API, codec, wire format, or runtime semantics changed without design coverage and test evidence or explicit gap.
- Breaking/migration-required API, crate-root export, build-surface, or documentation-example impact lacks its mechanically required contract kinds, consumer closure, or current scoped evidence hash.
- A breaking API is accepted only from one task artifact containing successful new-path external compilation, expected old-path rejection, removed-symbol scan, repository compile closure, and documentation example closure when applicable.
- Test design/implementation does not reasonably cover proposal/design/code behavior and required per-level contracts.
- Task-relevant test execution evidence lacks either a passing machine-written artifact with executed steps or a complete structured automated-test exception.
- Quality gates are missing, unrun, or failing when the task scope or repo-local custom rules make them relevant.
- Reviewed bugfix work lacks red-green regression evidence and no concrete infeasibility reason is recorded.
- Implementation paths were not bound to admitted design `Scope Paths`.
- Completed testing lacks `testplan.yaml` without a versioned exception.
- Design quality audit finds dependency-direction violations, multi-writer state, exports without consumers, unrecorded breaking changes, or invariant regressions.
- The implementation correctness audit is missing, omits a required category without a concrete not-applicable reason, or finds incorrect logic, non-termination, concurrency/synchronization defects, resource-lifetime defects, state/data corruption risks, error-recovery defects, boundary/compatibility defects, or security/capacity hazards.
- Stage docs, relevant project-rule-governed architecture docs, implementation, or tests contradict each other or silently narrow/expand proposal intent.
- Any document or implementation contains a plausible correctness, compatibility, governance, or logic defect.
- The same non-requirement issue remains unresolved after more than 5 design -> implementation -> testing iterations.

## Report Format
- Findings come first, sorted by severity.
- A human-readable result summary follows findings and explains the outcome, what was verified, the evidence used, and the next action in plain language.
- Test success is supporting evidence only.
- Any High finding produces `rejected` or `needs changes`.
- The report MUST include acceptance rules, expected results, coverage/consistency findings, implementation evidence, the category-by-category implementation correctness audit, test design adequacy, harness command results, test evidence, optional diff summaries, iteration count, and unresolved risks.
- Iteration count is derived from task-local `pipeline/state.json` return records or prior acceptance reports naming the same blocking issue id, plus the current run.
- `acceptance-report-check.py` fails missing, placeholder-only, or conclusion-incompatible required fields.
