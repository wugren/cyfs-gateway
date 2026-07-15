# [Task Name]

## Feature / Stage
- Feature:
- Stage:
- Stage Responsibility:
- Version:
- Packet Module:
- Target Module:
- Task Packet: `docs/versions/<version>/modules/<project-or-globals>/<task-seq>-<task-slug>/`
- Submodule:
- change_id:
- Owner:
- Parent Task:
- Depends On:

## Goal
- What this task must finish.

## Assumptions And Ambiguities
- Assumptions:
- Ambiguities:
- Decision or return route:

## Success Criteria
- Criterion 1:
- Criterion 2:
- Verification signal:

## Inputs
- Upstream artifacts:
- Relevant docs:
- Relevant code:
- Constraints:

## Admission Checks
- [ ] If this task may affect code, tests, runtime behavior, UI behavior, build behavior, bugfixes, optimization, or refactoring, `harness/rules/task-entry-gate-rules.md` was applied first
- [ ] Required upstream documents exist
- [ ] Required upstream approvals exist
- [ ] This task is operating inside its stage boundary
- [ ] If this task modifies multiple stage artifact groups, the user explicitly requested those stages or cross-stage synchronization
- [ ] For single-stage tasks, a current `stage-scope-check.py` result exists for this task's recorded changed paths; unchanged inputs were not replayed
- [ ] If this is an implementation or bugfix task, active `version`, packet `module`, `target_module`, and `change_id` are explicit
- [ ] If packet module is `globals`, admission and implementation scope checks use `--target-module <project>` independently for each affected project
- [ ] If this targets a direct submodule packet, active `submodule` is explicit
- [ ] If this is an implementation or bugfix task, a current schema result exists for the active packet; unchanged schema inputs were not rechecked
- [ ] If this is an implementation or bugfix task, `docs/versions/<version>/evidence/admission/<evidence-id>.md` contains required admission evidence
- [ ] If this is an implementation or bugfix task, a current admission stamp exists for every admitted `change_id`; unchanged admission inputs were not replayed
- [ ] If this is an implementation or bugfix task in a direct submodule packet, both checks passed with `--submodule <submodule>`
- [ ] If this is an implementation or bugfix task, the approved-doc inspection and task coverage judgment are recorded in the admission evidence file
- [ ] If this is a cross-module implementation or bugfix task, every affected module passed admission independently
- [ ] If this is a cross-submodule implementation or bugfix task, every affected submodule packet passed admission independently
- [ ] If this is an implementation or bugfix task, code edits started only after `admission-check.py` passed with the admission evidence file

## Implementation Admission Evidence
| evidence_item | source | status | notes |
|---------------|--------|--------|-------|
| proposal_read | `proposal.md` section/table | pass/fail | cite admitted `change_id` and relevant proposal coverage |
| design_read | `design.md` section/table | pass/fail | cite admitted `change_id` and relevant design coverage |
| change_scope_matches_request | user request + proposal/design mapping | pass/fail | explain why the admitted scope covers this task |
| active_module_resolved | module packet path | pass/fail | version/module/submodule if applicable |
| same_module_task_selection | `docs/versions/<version>/modules/tasks.md` and module Current/Active Task | pass/fail | reused tasks are same-module only, or different-module unfinished tasks were excluded and a new packet was created |
| no_chat_only_evidence | versioned docs and inspected code | pass/fail | confirm no oral/chat-only requirement is used as admission evidence |

## Work
- What should be produced.
- What must be validated.
- What should be left for the next task.

## Steps
### Step 1
- Action:
- Skill or tool:
- Output:
- Verify:

### Step 2
- Action:
- Skill or tool:
- Output:
- Verify:

### Step 3
- Action:
- Skill or tool:
- Output:
- Verify:

## Deliverables
- Deliverable 1:
- Deliverable 2:

## Done Criteria
- [ ] Goal is met
- [ ] If this is a testing task, generated or changed tests are reachable through `harness/scripts/test-run.py`
- [ ] Required validation has a current passing result; unchanged inputs were not rerun
- [ ] Stage scope check passed when applicable
- [ ] Residual risks are recorded

## Next-Stage Gate
- [ ] Preconditions for the next stage are satisfied
- [ ] If the next stage is implementation, manual flow has approved proposal/design; auto-pipeline has a launch-confirmed proposal plus validated pipeline-plan mappings and `Scope Paths`
- [ ] If the next stage is implementation, those approved docs already contain the next task's required content

## Return Routing On Failure
- Return to stage:
- Reason:
- Blocking or non-blocking:

## Allowed Changes
- Can modify:
- Must not modify:

Stage-task defaults:
- Proposal can modify: `proposal.md` in the active task packet only
- Design can modify: active task packet `design.md`, task-local `design/`, required long-lived boundary sync, and project-rule-required `docs/architecture/` updates only
- Testing can modify: test code, test fixtures, test runners, unified test entrypoint wiring, and optional testing artifacts only
- Acceptance can modify: review reports and generated acceptance rules/expected-result evidence only; it must run `architecture-doc-check.py` as documentation validation
- Cross-stage edits require explicit user instruction naming the extra stage(s) or asking for cross-stage synchronization

Implementation-task defaults:
- Can modify: production code, required non-test runtime/build resources, and task admission evidence under `docs/versions/<version>/evidence/admission/` only
- Must not modify: stage documents such as `proposal.md`, `design.md`, `design/`, `testing.md`, `testing/`, `testplan.yaml`, `acceptance.md`, including the same files inside direct submodule packets
