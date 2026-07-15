---
module: example-module
task_name: 001-example-task
version: v0.6
status: draft
approved_by:
approved_at:
---

# [Module Name] Acceptance

> This optional file records acceptance guidance. Final acceptance rules and expected results are generated or finalized after implementation and test implementation; run results belong in review reports.

## Acceptance Baseline
- Primary baseline: `proposal.md`
- Supporting evidence:
  - `design.md` and `design/`
  - test implementation, optional `testing.md`, and completed-testing `testplan.yaml` or its versioned exception
  - long-lived module docs
  - implementation
  - test code
  - test results
  - optional git diff/status evidence when useful for locating implementation evidence

## Required Outcomes
| Outcome | Proposal Source | Acceptance Evidence | Pass Condition |
|---------|-----------------|---------------------|----------------|
| | proposal section / table row | doc, code, test, or result reference | |

## Consistency Checks
- [ ] Proposal, design, generated acceptance criteria, implementation, and test implementation describe the same intended result
- [ ] Any document or code inconsistency is resolved against approved `proposal.md`
- [ ] If proposal is satisfied, fixes route through design first, implementation/code second, and testing implementation third as needed
- [ ] Optional testing documents conform to design documents
- [ ] Code conforms to design
- [ ] Test implementation verifies proposal/design/code behavior
- [ ] Design, long-lived module docs, and any relevant project-rule-governed `docs/architecture/` docs agree on stable boundaries and contracts
- [ ] `harness/scripts/architecture-doc-check.py` passed against the latest implementation
- [ ] Implementation matches approved design items
- [ ] Test code and test results match generated test evidence, optional `testing.md`, and completed-testing `testplan.yaml` or its versioned exception
- [ ] Every implemented change maps back to direct proposal/design items and generated test evidence, or to an explicit documented gap
- [ ] No downstream document contradicts, narrows, or silently expands approved proposal intent
- [ ] Every document-described behavior, constraint, non-goal, and acceptance boundary has implementation or explicit non-implementation evidence
- [ ] Every evidence-bearing module has approved direct `change_id` coverage in proposal/design and post-implementation test evidence
- [ ] Document and implementation logic contains no blocking contradiction, invalid assumption, impossible state, or correctness defect
- [ ] Implementation correctness was explicitly audited for logic/control flow, termination/progress, concurrency/synchronization, resource lifetime/cleanup, state/data integrity, error handling/recovery, interface boundaries/compatibility, and security/capacity safety
- [ ] Every correctness-audit category cites inspected evidence and records pass, a concrete finding, or a concrete reason it is not applicable

## Required Evidence
| Evidence | Source | Required? | Notes |
|----------|--------|-----------|-------|
| Requirement coverage | `proposal.md` | yes | |
| Design coverage | `design.md` / `design/` | yes | |
| Test implementation coverage | test code, fixtures, runners, optional `testing.md`, completed-testing `testplan.yaml` or exception | yes | |
| Implementation evidence | production code | yes | |
| Test results | latest accepted run output | yes / manual / disabled | |
| Diff/status evidence | `git status --short`, `git diff --stat`, `git diff --name-status`, `git diff --check` | optional | Discovery aid only; not a pass/fail standard |

## Failure Conditions
- Proposal ambiguity, contradiction, incorrect requirement, or incorrect acceptance boundary requiring user decision
- Design mismatch
- Testing gap or missing required evidence
- Acceptance criteria not traceable to proposal intent
- Implementation defect or unimplemented approved behavior
- Documentation and implementation describe different behavior
- Testing implementation contradicts design or implementation while proposal intent is satisfied
- Code contradicts design while proposal intent is satisfied
- Document contains a contradiction, unsupported assumption, or impossible requirement
- Implementation contains a logical correctness, compatibility, lifecycle, state, or error-handling defect
- Implementation may deadlock, livelock, starve, race, loop/recurse forever, leak or misuse resources, corrupt or partially commit state, mishandle cancellation/retry/timeout/backpressure, violate interface boundaries, regress compatibility, bypass security controls, or grow resources without bound
- Public API, codec, wire format, or runtime semantics changed without direct design coverage and generated test coverage or an explicit gap

## Return Routing
| Failure Type | Owning Stage | Notes |
|--------------|--------------|-------|
| proposal ambiguity, contradiction, or incorrect requirement/boundary | user decision | stop acceptance/pipeline and ask the user; do not infer or auto-return |
| missing or incorrect architecture/algorithm/state/concurrency/resource/interface/failure model | design | |
| proposal-to-design mismatch | design | proposal is authoritative unless ambiguous or contradictory |
| design-to-testing mismatch | testing | tests must verify proposal/design/code behavior |
| testing gap or invalid test metadata | testing | |
| document-to-code mismatch | implementation | code must follow design |
| implementation defect against adequate design | implementation | includes logic, progress, concurrency, resource, state, recovery, boundary, compatibility, security, and capacity defects |
| document logic defect | owning document stage | route by the document that contains the contradiction or invalid assumption |
| implementation logic defect | implementation | route by whether docs or code are defective |

## Acceptance Guardrails
- Do not record run-specific conclusions in this file.
- Do not use acceptance to repair proposal, design, testing, or implementation artifacts.
- A separate acceptance report must put findings first and state scope, coverage evidence, consistency evidence, optional diff/status evidence, conclusion, and follow-up tasks.
- Passing tests are supporting evidence only; they do not automatically satisfy acceptance.
- Non-requirement failures return through design -> implementation -> testing; stop and report to the user after more than 5 unsuccessful iterations.

