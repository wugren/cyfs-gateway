# Pipeline Submodule Task

## Task Identity
- Task ID:
- Stage:
- Responsibility:
- Version:
- Module:
- Submodule / Task Directory:
- Packet Module:
- Target Module:
- change_id:
- Parent Task:
- Depends On:
- Owner:
- Exclusive Write Scope:
- Parallel-Eligible Ready Tasks:
- Serialization Reason: none / dependency / overlapping-write-scope / concurrency-capacity

## Goal
- Complete the named stage for this task packet or direct submodule only.

## Scope Boundary
- In scope:
- Out of scope:
- Shared topics handled elsewhere:

## Inputs
- Proposal excerpts:
- Design references:
- Testing references or generated test evidence:
- Upstream outputs:

## Admission Checks
- [ ] Required upstream artifacts exist
- [ ] The launch-confirmed proposal and required upstream pipeline-plan mappings exist; auto-pipeline does not require approved `design.md` or `testing.md`
- [ ] If per-stage user confirmation is skipped, the pipeline plan records explicit user auto-pipeline authorization
- [ ] Task-local `pipeline/state.json` status was updated to `confirmed` or `complete` before dependent tasks continue
- [ ] The parent orchestrator owns shared pipeline/state/testplan/runner artifacts; this child writes only its exclusive scope and task-specific evidence
- [ ] All ready sibling tasks with disjoint write scopes were launched concurrently up to available child-agent capacity before waiting
- [ ] If a repository-local extension produces a stage document, its auto-confirmation metadata is complete; normal auto-pipeline design/testing tasks produce no stage Markdown document
- [ ] Scope stays inside this task packet or direct submodule
- [ ] Scope stays inside the named stage unless the user explicitly requested cross-stage synchronization
- [ ] For design: this submodule's same-level structure and child mappings are recorded in `pipeline/plan.md`, without generating `design.md` or task-local `design/`
- [ ] For design: file-level modules owned by this submodule are recorded in the pipeline-plan implementation sequence in dependency order before implementation starts
- [ ] For single-stage tasks, a current stage-scope result exists for this task's recorded changed paths; unchanged inputs were not replayed
- [ ] For implementation: the proposal is confirmed by an explicit current user launch recorded verbatim as `User launch statement`, and dependency/interface/state/failure/alternative design inputs for this submodule are validated
- [ ] For implementation: active `version`, packet `module`, `target_module`, submodule, and `change_id` are explicit
- [ ] For implementation: a current schema result exists for the submodule packet; unchanged inputs were not rechecked
- [ ] For implementation: `docs/versions/<version>/evidence/admission/<evidence-id>.md` contains required admission evidence
- [ ] For implementation: a current admission stamp exists for every admitted `change_id`; unchanged inputs were not replayed
- [ ] For implementation: inspection of the launch-confirmed proposal and task-relevant pipeline-plan mapping is recorded in the admission evidence file
- [ ] For implementation: this child task implements the next ready file-level module in the validated pipeline-plan dependency sequence
- [ ] For implementation: context is limited to the task-relevant pipeline-plan mapping, `change_id`, `Scope Paths`, interfaces, and source files for this file-level module

## Implementation Admission Evidence
| evidence_item | source | status | notes |
|---------------|--------|--------|-------|
| proposal_read | bound task packet `proposal.md` section/table | pass/fail | cite admitted `change_id` and relevant proposal coverage |
| design_read | `pipeline/plan.md` dependency/interface/scope mappings | pass/fail | cite admitted `change_id`, `target_module`, and relevant design coverage |
| change_scope_matches_request | user request + launch-confirmed proposal + pipeline-plan mapping | pass/fail | explain why the admitted scope covers this submodule task |
| active_module_resolved | submodule packet path | pass/fail | version/module/submodule |
| same_module_task_selection | `docs/versions/<version>/modules/tasks.md` and module Current/Active Task | pass/fail | reused tasks are same-module only, or different-module unfinished tasks were excluded and a new packet was created |
| no_chat_only_evidence | versioned docs and inspected code | pass/fail | confirm no oral/chat-only requirement is used as admission evidence |

## Required Outputs
- Output file(s):
- Evidence:

## Allowed Changes
- Can modify:
- Must not modify:

Stage-task defaults (shared-artifact entries are proposed by the child and applied only by the parent orchestrator):
- Design can return: this submodule's proposed mappings and implementation sequence for `pipeline/plan.md`; direct writes are limited to its reserved long-lived boundary scope; it MUST NOT generate `design.md` or task-local `design/`
- Implementation can modify: production code, required non-test runtime/build resources, and task admission evidence under `docs/versions/<version>/evidence/admission/` only
- Testing can return: proposed shared `testplan.yaml`, shared runner registration, and pipeline testing evidence; direct writes are limited to reserved test code, fixtures, runner files, and run artifacts; it MUST NOT generate `testing.md` or task-local `testing/`
- Acceptance can modify: review reports and generated acceptance rules/expected-result evidence only
- Cross-stage edits require explicit user instruction naming the extra stage(s) or asking for cross-stage synchronization

## Done Condition
- [ ] Submodule output is complete
- [ ] For testing: submodule tests are reachable through `harness/scripts/test-run.py <module>/<submodule> all` or the repository's documented submodule equivalent
- [ ] For acceptance: submodule test design adequacy was reviewed, including relevant normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases
- [ ] For acceptance: incomplete, ambiguous, unreasonable, stale, or non-runnable submodule test coverage was routed back to testing
- [ ] No out-of-scope files were changed
- [ ] Stage scope check passed when applicable
- [ ] Handover data for the next dependent task exists

## Failure Handling
- If the issue is shared or upstream, return it instead of solving it inside this submodule task.
- Record:
  - issue id
  - return stage
  - return target task
  - expected upstream fix
