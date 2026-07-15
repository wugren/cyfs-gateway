# [Module Name] Acceptance Report

## Findings
| ID | Severity | Stage | Evidence | Problem | Fail Condition Hit |
|----|----------|-------|----------|---------|--------------------|
| F-000 | none | acceptance | completed review evidence | no blocking finding recorded | none |

## Result Summary
- Overall result:
- Plain-language outcome:
- What was verified:
- Evidence used:
- Blocking issues:
- Next action:

## Object and Scope
- Module:
- Version:
- Task name:
- change_id values reviewed:
- Review date:
- In scope:
- Out of scope:
- Task-relevant acceptance scope:
- Out-of-scope checks not run:

## Optional Diff / Status Evidence
- `git status --short` summary:
- `git diff --stat` summary:
- `git diff --name-status` summary:
- `git diff --check` result:
- Note: diff/status output is a discovery aid only, not the acceptance standard.

## Evidence Coverage
| Documented Item | Source Document | Implementation Evidence | Test / Result Evidence | Status |
|-----------------|-----------------|-------------------------|------------------------|--------|
| | | | | implemented / missing / inconsistent / logically invalid |

## Test Design Adequacy
| Behavior / Risk / change_id | Required Case Types | Test Design Evidence | Runnable Test Evidence | Status |
|-----------------------------|---------------------|----------------------|------------------------|--------|
| | normal / boundary / negative / error / compatibility / lifecycle / cross-module | | | adequate / gap / stale / not runnable |

## Implementation Correctness Audit
| Category | Applicable Scope | Evidence Reviewed | Finding / Reason Not Applicable | Owning Stage | Status |
|----------|------------------|-------------------|---------------------------------|--------------|--------|
| logic and control flow | | | | none | pass / fail / not applicable |
| termination and progress | | | | none | pass / fail / not applicable |
| concurrency and synchronization | | | | none | pass / fail / not applicable |
| resource lifetime and cleanup | | | | none | pass / fail / not applicable |
| state and data integrity | | | | none | pass / fail / not applicable |
| error handling and recovery | | | | none | pass / fail / not applicable |
| interface boundary and compatibility | | | | none | pass / fail / not applicable |
| security and capacity safety | | | | none | pass / fail / not applicable |

## Generated Acceptance Rules
| Rule ID | Source | Expected Result | Evidence Required | Status |
|---------|--------|-----------------|-------------------|--------|
| | proposal/design/code/tests | | | pass / fail / gap |

## Inputs
- `proposal.md`
- `design.md`
- test implementation and optional `testing.md`
- `testplan.yaml` for completed testing work, or a versioned local exception with reason, owner, risk, and acceptance impact
- optional `acceptance.md`
- long-lived module doc
- implementation
- test code
- test results
- optional git diff/status evidence
- `harness/rules/acceptance-review-rules.md`

## Review Order
1. Review approved requirements and acceptance boundaries
2. Review design against proposal
3. Generate or finalize acceptance rules and expected results from proposal, design, implementation, and test implementation
4. Define the task-relevant acceptance scope, then review implementation against proposal and design only within that scope
5. Review whether test design reasonably covers proposal/design/code behavior, including normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases where applicable
6. Review tests and results against generated test evidence, optional `testing.md`, and required completed-testing `testplan.yaml` or its versioned exception
7. Complete every implementation correctness audit category, actively checking logic errors, non-termination, deadlocks/races, resource leaks, state corruption, error/recovery defects, boundary/compatibility defects, and security/capacity hazards
8. Route proposal defects to user decision, design defects to design, implementation defects to implementation, and validation defects to testing; do not repair findings in acceptance
9. Review document and implementation logic for contradictions, invalid assumptions, impossible states, and correctness defects
10. Use diff/status output only when helpful to locate task-relevant evidence; do not run unrelated checks
11. Produce conclusion

## Consistency Summary
- Proposal authority check:
- Proposal vs design:
- Design vs testing implementation:
- Design vs long-lived boundary doc:
- Design vs implementation:
- Test implementation vs test code vs results:
- Test design adequacy:
- change_id traceability:
- Acceptance criteria traceability:
- Cross-module admission:
- Public API / codec / runtime semantics review:
- Document logic review:
- Implementation logic review:
- Implementation correctness audit completeness and routing:
- Document approval timing (approved_content_sha256 verified by schema-check):
- Implementation task paths bound to design Scope Paths (`stage-scope-check.py --stage implementation --change-id ... --changed-paths-file ...`):
- Bugfix red-green regression evidence, when the reviewed work contains a bugfix:

## Validation Evidence
- Existing schema result (cite the owning-stage result; do not rerun unchanged input):
- Existing admission stamp (cite the stamp; do not run `--verify-only` during acceptance unless an admission-owned input changed):
- Existing stage-scope result (cite the owning-stage result; do not rerun an unchanged manifest/scope):
- Existing pipeline-plan result, when applicable (cite the latest result for current plan/state inputs):
- Task-relevant test run artifact(s) (reuse when implementation/tests/testplan/registration are unchanged):
- Commands rerun because checker-owned inputs changed after their previous pass (or `none` with evidence):
- Direct package/module runtime suites, whole-project suites, and root shortcuts: not run; risk-triggered compile-only consumer closure appears only inside the task artifact
- Risk-triggered task-local contract kinds and assertions, when applicable:
- Scoped evidence input hash current, when risk-triggered:
- Quality gates: not run automatically; cite only when explicitly requested by the user
- Explicitly requested quality run artifact, if any:
- Architecture doc check, only when `docs/architecture/` evidence is relevant:
- Acceptance report check after this report was created or modified:
- Targeted migration search, only when applicable to the reviewed task:

## Automated Test Exception
<!-- Complete this section only when no automated task run can apply. For an accepted report without a task run artifact, every field below is mandatory; a bare "not applicable" is invalid. -->
- Applies: no
- Reason:
- Owner:
- Risk:
- Acceptance impact:
- Alternative evidence:

## Conclusion
- Accepted / rejected / needs changes: accepted / rejected / needs changes
- Reason:
- Supporting task-relevant test evidence:
- Residual risk:

## Follow-Up Tasks
- Requirement task:
- User decision required for proposal issue:
- Design task:
- Implementation task:
- Testing task:
- Testing return reason if coverage is incomplete:
- Iteration count:
- Stop reason if more than 5 unsuccessful iterations:

