# Pipeline Stage Task

## Task Identity
- Task ID:
- Stage: design / implementation / testing / acceptance
- Responsibility:
- Scope:
- Version:
- Module:
- Task Packet: `docs/versions/<version>/modules/<project-or-globals>/<task-seq>-<task-slug>/`
- Packet Module: `<project-or-globals>`
- Target Module: `<project>`
- Submodule:
- change_id:
- Parent Task:
- Depends On:
- Owner:
- Exclusive Write Scope:
- Parallel-Eligible Ready Tasks:
- Serialization Reason: none / dependency / overlapping-write-scope / concurrency-capacity

## Goal
- Describe the single stage outcome this task must complete.

## Inputs
- Proposal inputs:
- Upstream task outputs:
- Relevant docs:
- Relevant code:
- Constraints:

## Admission Checks
- [ ] For implementation-like scopes: `harness/rules/task-entry-gate-rules.md` was applied before any code, test, build, or resource edit
- [ ] Required upstream artifacts exist
- [ ] Required upstream approvals exist
- [ ] If per-stage user confirmation is skipped, the pipeline plan records explicit user auto-pipeline authorization
- [ ] Task-local `pipeline/state.json` status was updated to `confirmed` or `complete` before dependent tasks continue
- [ ] The parent orchestrator, not this child agent, owns shared `pipeline/plan.md`, `pipeline/state.json`, task indexes, shared `testplan.yaml`, and shared runner registration
- [ ] Every dependency-ready task with a disjoint write scope was launched concurrently up to available child-agent capacity before the parent waited
- [ ] Auto-pipeline design/testing tasks did not generate `design.md`, task-local `design/`, `testing.md`, or `testing/`, and testing generated `testplan.yaml`
- [ ] If a repository-local extension produces a stage document and auto-confirmation is enabled, the document front matter was updated to `status: approved`, `approved_by: auto-pipeline`, `approved_at`, and `approved_content_sha256`
- [ ] Scope does not cross into another stage
- [ ] If scope crosses into another stage, the user explicitly requested those stages or cross-stage synchronization
- [ ] For design: the design decomposes top-down from the whole affected module to child submodules, nested submodules, and file-level modules where applicable
- [ ] For design: every child submodule or nested submodule is recorded in `pipeline/plan.md` design mappings instead of generated design documents
- [ ] For design: `pipeline/plan.md` `## File-Level Implementation Sequence` lists concrete source files to create or modify in dependency order
- [ ] For single-stage tasks, a current stage-scope result exists for this task's recorded changed paths; unchanged inputs were not replayed
- [ ] For implementation: task-local `pipeline/plan.md` `User launch statement` copies the user's explicit current instruction verbatim, and validated dependency/interface/state/failure/alternative evidence plus scope bindings cover admitted `change_id` values
- [ ] For implementation: active `version`, packet `module`, `target_module`, and `change_id` are explicit
- [ ] For implementation in a direct submodule packet: active `submodule` is explicit
- [ ] For implementation: a current schema result exists for the active packet; unchanged inputs were not rechecked
- [ ] For implementation: `docs/versions/<version>/evidence/admission/<evidence-id>.md` contains required admission evidence
- [ ] For implementation: a current admission stamp exists for every admitted `change_id`; unchanged inputs were not replayed
- [ ] For implementation in a direct submodule packet: both checks passed with `--submodule <submodule>`
- [ ] For implementation: approved-doc inspection and task coverage judgment are recorded in the admission evidence file
- [ ] For implementation: this child task corresponds to the next ready item in the pipeline-plan file-level implementation sequence
- [ ] For implementation: task context is limited to the relevant proposal excerpt, pipeline-plan design mapping, `change_id`, `Scope Paths`, interfaces, and source files for this file-level module
- [ ] For a `globals` packet: each affected project passed independently with `--module globals --submodule <task-name> --target-module <project>`
- [ ] For cross-submodule implementation: each affected submodule packet passed admission independently
- [ ] For implementation: code edits started only after `admission-check.py` passed with the admission evidence file

## Allowed Changes
- Can modify:
- Must not modify:

## Implementation Admission Evidence
| evidence_item | source | status | notes |
|---------------|--------|--------|-------|
| proposal_read | `proposal.md` section/table | pass/fail | cite admitted `change_id` and relevant proposal coverage |
| design_read | `design.md` section/table or `pipeline/plan.md` `## Implementation Scope Bindings` | pass/fail | cite admitted `change_id` and relevant design coverage |
| change_scope_matches_request | user request + proposal/design mapping or pipeline-plan design mapping | pass/fail | explain why the admitted scope covers this task |
| active_module_resolved | module packet path | pass/fail | version/module/submodule if applicable |
| same_module_task_selection | `docs/versions/<version>/modules/tasks.md` and module Current/Active Task | pass/fail | reused tasks are same-module only, or different-module unfinished tasks were excluded and a new packet was created |
| no_chat_only_evidence | versioned docs and inspected code | pass/fail | confirm no oral/chat-only requirement is used as admission evidence |

Stage-task defaults (shared-artifact entries are proposed by the child and applied only by the parent orchestrator):
- Proposal can modify: `proposal.md` in the active task packet only
- Design can return: proposed `pipeline/plan.md` design mappings; direct writes are limited to its reserved long-lived boundary or project-rule-required `docs/architecture/` scope; no `design.md` or task-local `design/` is generated in auto-pipeline mode
- Implementation can modify: production code, required non-test runtime/build resources, and task admission evidence under `docs/versions/<version>/evidence/admission/` only
- Testing can return: proposed shared `testplan.yaml`, shared runner registration, and `pipeline/state.json` evidence/status; direct writes are limited to reserved test code, fixtures, runner files, and run artifacts; no `testing.md` or `testing/` is generated in auto-pipeline mode
- Acceptance can return: proposed task-local `pipeline/state.json` acceptance/return status; direct writes are limited to its reserved task-packet acceptance report
- Acceptance can modify: review reports and generated acceptance rules/expected-result evidence only
- Downstream follow-up from an upstream change is recorded as a return route unless cross-stage synchronization was explicitly requested

## Required Outputs
- Output 1:
- Output 2:

## Done Condition
- [ ] Required output exists
- [ ] For testing: every generated or changed automated test is reachable through `harness/scripts/test-run.py`
- [ ] For acceptance: `architecture-doc-check.py` passed against latest implementation docs
- [ ] For acceptance: test design adequacy was reviewed, including relevant normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases
- [ ] For acceptance: incomplete, ambiguous, unreasonable, stale, or non-runnable test coverage was routed back to testing
- [ ] Scope boundary respected
- [ ] Stage scope check passed when applicable
- [ ] Dependencies satisfied
- [ ] Evidence attached

## Failure Handling
- If blocked by an upstream issue, do not patch outside scope.
- Record:
  - blocking issue
  - suspected owning stage
  - return target
  - evidence
