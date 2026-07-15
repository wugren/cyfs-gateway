# Auto Pipeline Rules

## Goal
- Define the repository's fully automatic downstream workflow after explicit user launch.
- Make stage planning, child-task execution, return-routing, and exit conditions explicit.

## Trigger
- This rule is inactive unless the user explicitly asks to enter it.
- Entry signal: user explicitly asks to enable, launch, run, or enter the automatic pipeline
- Agents MUST NOT infer, synthesize, or self-issue this entry signal. `pipeline/plan.md` MUST copy the user's explicit launch instruction verbatim into `User launch statement`; without that current user instruction, `User launch confirmed` remains unset and the normal manual workflow applies.
- Required prerequisite: the bound `proposal.md` exists
- Explicit user launch confirms the bound proposal for this pipeline; separate proposal approval metadata is not required
- The plan MUST bind exactly one task packet by `Version`, `Packet module`, and `Task name` under `## Trigger`; it MUST NOT change document policy for unrelated packets.
- `Packet module: globals` is the specialized cross-project packet keyword. Its `Target module(s)` list contains concrete projects, and each project is admitted independently with `--target-module`.
- Optional launch command or workflow entry:

## Priority Override
- After explicit user launch, this rule has higher priority than the normal task-entry and implementation-admission rules only for the no-`design.md` / no-`testing.md` document policy and replacement of `design.md` evidence with validated pipeline-plan mappings.
- The override removes auto-pipeline requirements for proposal approval metadata, `design.md`, `testing.md`, and their approval state. It does not waive proposal binding, change-level mapping, concrete `Scope Paths`, admission evidence, stage scope, validation, or acceptance.

## User Authorization Precedence
- Explicit user instructions have highest priority for entering auto-pipeline mode, requested pipeline scope, and whether per-stage user confirmation is required.
- If the user explicitly asks auto-pipeline mode to handle all subsequent stages or the whole downstream workflow, the pipeline MUST NOT stop after each stage to ask for separate user confirmation before continuing.
- That launch instruction authorizes downstream design, implementation, post-implementation testing, and acceptance execution according to the pipeline plan.
- Auto-pipeline design and testing stages MUST NOT generate or update persistent `design.md`, task-local `design/`, `testing.md`, or `testing/` artifacts. Testing MUST generate `testplan.yaml`.
- Auto-pipeline tasks MUST NOT run `doc-structure-check.py`; their document/mapping structure gates are `schema-check.py`, `pipeline-plan-check.py`, and `testing-coverage-check.py`. Proposal document structure is completed before pipeline launch.
- Auto-pipeline design-stage outputs MUST be recorded in task-local `pipeline/plan.md` as dependency graphs plus their machine-checkable node/dependency table, exported interfaces with concrete consumers and compatibility decisions, structured API/build impact plus consumer migration closure, single-owner state models with failure transitions, cross-boundary failure flows and handling, rejected boundary/technical/collaboration alternatives, implementation order, and concrete `Scope Paths`; testing-stage outputs MUST include `testplan.yaml`, task-local `pipeline/state.json` coverage/evidence references, test code, test runner wiring, and machine-written test run artifacts.
- When creating or intentionally revising `pipeline/plan.md`, record its LF-normalized sha256 as sibling `pipeline/state.json` `plan_sha256` before the plan's validation run. A design revision intentionally invalidates earlier admission stamps; ordinary state updates never alter plan or its admission binding.
- When a repository-local extension adds a document-producing stage, the pipeline MUST auto-confirm that stage by updating the produced stage document front matter to:
  - `status: approved`
  - `approved_by: auto-pipeline`
  - `approved_at: <current timestamp>`
  - `approved_content_sha256: <hash from schema-check.py --print-approval-hash>`
- Auto-confirmation happens only after that stage's declared done criteria and required checks pass.
- `approved_by: auto-pipeline` is valid only while `pipeline/plan.md` records confirmed launch evidence and the same `Version`, `Packet module`, and `Task name` as that document; `schema-check.py` and `admission-check.py` fail unbound approval claims.
- Outside an explicitly launched pipeline, the normal approval authority rule applies: agents MUST NOT set `status: approved` themselves, and user approvals require a filled `## Approval Record`.
- The parent orchestrator is the sole writer for shared coordination artifacts including `pipeline/plan.md`, `pipeline/state.json`, unfinished-task indexes, shared `testplan.yaml`, and shared test-runner registration. Child agents return scoped results; the parent merges them and updates statuses/evidence.
- After each child task completes, the parent orchestrator MUST update the task-local `pipeline/state.json` task status to `confirmed` or `complete` before continuing to dependent tasks.
- The pipeline MUST run `pipeline-plan-check.py` after creating or modifying `pipeline/plan.md` or sibling `state.json`; that latest passing result satisfies downstream entry while those inputs remain unchanged. It MUST run `--require-complete` only after completion state or completion evidence changes. Reaching the next stage or final completion without an input change MUST NOT trigger another run. Complete mode verifies the bound task's `testplan.yaml`, successful matching `<module>/<task-name> all` artifact, and acceptance-report reference without rerunning their owning checkers. It MUST NOT trigger package/module tests, `all all`, root shortcuts, or quality gates.
- Implementation completion MUST be recorded in task-local `pipeline/state.json` and implementation evidence, and final acceptance MUST be recorded in task-local `pipeline/state.json` and the acceptance report.
- This authorization confirms the bound proposal and does not waive proposal authority, design-stage rules, testing-stage rules, stage write scopes, `stage-scope-check.py`, implementation admission, schema checks, admission checks, required validation, or final acceptance; it only changes proposal approval metadata requirements and where auto-pipeline records design and testing outputs.

## Acceptance Baseline
- Final acceptance baseline: the user-launch-confirmed `proposal.md`
- Downstream artifacts (pipeline-plan design mappings, pipeline-plan testing evidence, optional acceptance artifacts, implementation, and tests) may refine execution detail but MUST NOT contradict, narrow, or silently expand the proposal.
- When downstream artifacts or code disagree, fixes MUST preserve the launch-confirmed proposal and route non-requirement defects through design -> implementation/code -> testing implementation.
- Code MUST conform to design, and tests MUST verify proposal/design/code behavior.

## Stage Responsibilities
- Proposal responsibility:
  - define the user-confirmed baseline of goals, scope, non-goals, and constraints
- Pipeline planning responsibility:
  - plan stage tasks, dependencies, outputs, and done conditions before execution starts
- Design responsibility:
  - convert the launch-confirmed proposal into submodules, dependencies, key call flows, exported interfaces, external dependencies, and implementation order
  - decompose design top-down from the whole affected module to submodules, nested submodules, and file-level modules
  - record every child submodule or nested submodule design mapping in `pipeline/plan.md` instead of saving independent `design/` documents
  - exclude test cases, test plans, test strategy, validation IDs, fixtures, testability seams, and test implementation from design-stage outputs
  - produce no persistent `design.md` or task-local `design/` documents in auto-pipeline mode
  - keep module and submodule dependencies acyclic
  - make every dependency row belong to one level and parent, and reject unknown cross-parent dependencies
  - name a concrete consumer and compatibility decision for every exported interface; breaking or migration-required interfaces also name affected callers and a migration path
  - record old symbol -> new path -> concrete repository consumer file -> migration status rows for breaking/migration-required APIs and crate-root/build-surface changes
  - assign every persistent/shared state to exactly one owner and record lifecycle plus failure transitions
  - record handling for every key cross-boundary failure flow
  - record rejected boundary, technical, and collaboration alternatives with concrete reasons
  - split submodules by business logic first, extract shared implementation logic into shared submodules, and isolate clear technical areas such as HTTP interfaces or persistence/database access
- Testing responsibility:
  - after implementation completes, design test cases from proposal, pipeline-plan design mappings, and delivered code, then generate test implementation and runnable evidence
  - produce no persistent `testing.md` or `testing/` documents in auto-pipeline mode; generate `testplan.yaml` and record coverage and gaps in the pipeline plan
  - generate risk-triggered task-local contract checks and scoped evidence inputs; affected package/workspace compile-only closure is allowed without broad runtime test execution
- Implementation responsibility:
  - deliver the smallest production code changes that satisfy the launch-confirmed proposal and design inputs
  - execute file-level implementation child tasks in the pipeline-plan design mapping dependency order
- Acceptance responsibility:
  - generate or finalize acceptance rules and expected results, independently evaluate evidence consistency and logic, then return non-requirement failures through design -> implementation -> testing

## Pipeline Planning Rule
- Before execution starts, the pipeline MUST create a plan for:
  - design tasks that update pipeline-plan design mappings instead of design documents
  - implementation tasks
  - testing tasks that generate `testplan.yaml` and update pipeline-plan testing evidence instead of testing Markdown documents
  - acceptance tasks
- The planner MUST declare:
  - task ids
  - stage
  - responsibility
  - scope
  - dependencies
  - outputs
  - done conditions
- Implementation tasks MUST be generated from the pipeline-plan `## File-Level Implementation Sequence`; dependency-related file-level child tasks follow dependency order, while ready tasks with disjoint Scope Paths execute concurrently.
- Each implementation child task MUST limit its context to the relevant proposal excerpt, pipeline-plan design mapping, `change_id`, `Scope Paths`, interfaces, and source files for that file-level module.

## Implementation Admission Rule
- The task entry gate still applies inside the pipeline: implementation tasks MUST classify scope and run admission before editing production code, build files, or resources.
- No implementation task may start unless:
  - the user-launch-bound `proposal.md` exists
- `pipeline/plan.md` records design coverage, concrete `target_module`, and concrete `Scope Paths` for every admitted `change_id`
- Implementation tasks MUST read the launch-confirmed proposal and pipeline-plan design mapping, then confirm they cover the current task before coding.
- Implementation tasks MUST record that confirmation in `docs/versions/<version>/evidence/admission/<evidence-id>.md`, and `admission-check.py` MUST validate it with `--evidence-file`.
- Implementation tasks MUST identify explicit `version`, packet `module`, `target_module`, and `change_id` values before coding. `--module globals` always requires a concrete `--target-module`.
- If the requested task module is clearly different from unfinished task records, the pipeline MUST create a new task packet immediately and MUST NOT consider continuing a different-module unfinished task.
- Implementation tasks for direct submodule packets MUST also identify explicit `submodule`.
- Implementation tasks MUST pass `schema-check.py` and `admission-check.py` for each affected module packet.
- Implementation tasks MUST pass `admission-check.py --evidence-file docs/versions/<version>/evidence/admission/<evidence-id>.md` for each affected module packet.
- Implementation tasks for direct submodule packets MUST pass those checks with `--submodule <submodule>`.
- Cross-module implementation tasks MUST pass admission independently for every affected module.
- Cross-submodule implementation tasks MUST pass admission independently for every affected submodule packet.
- If the launch-confirmed proposal is incomplete, the pipeline MUST stop and require a corrected proposal plus a new explicit user launch; incomplete pipeline-plan design mapping returns to the design task.
- Bugfix tasks follow the same rule unless the repository publishes a narrower exception path.
- If any prerequisite is missing or unconfirmed, the task MUST return to the owning upstream stage.

## Stage Execution Rule
- Each stage MUST execute as an independent child task.
- At every scheduling point, compute the dependency-ready set of pending child tasks whose declared dependencies are `confirmed` or `complete`. Reserve exclusive write scopes under `.harness/locks/`, launch the maximum non-conflicting dependency-ready set concurrently up to the runtime's available child-agent slots, and immediately backfill a free slot when another ready task exists.
- The orchestrator MUST NOT enter agent waiting while a ready non-conflicting child task and a free agent slot both exist. Serialization is allowed only for an explicit dependency, overlapping write scope, or exhausted runtime concurrency capacity; record the concrete reason in scheduler state.
- Child agents MUST NOT write shared coordination artifacts directly. They write only exclusive task Scope Paths and task-specific evidence, then return results to the parent for shared-file merging and batched `pipeline/state.json` updates.
- Each stage child task MUST keep direct writes inside its reserved exclusive stage scope unless the user explicitly requested cross-stage synchronization for that task. A child may return proposed shared-artifact mutations, but only the parent orchestrator applies them to `pipeline/plan.md`, `pipeline/state.json`, shared `testplan.yaml`, unfinished-task indexes, or shared test-runner registration. Testing children may write exclusively owned test code, fixtures, runner files, and `test-results/test-runs/*.json` evidence. Auto-pipeline design/testing child tasks MUST NOT create `design.md`, task-local `design/`, `testing.md`, or `testing/`; testing children return testplan content for the parent to create or merge.
- Each single-stage child task MUST record its changed paths in `docs/versions/<version>/evidence/stage-scope/<task-id>.paths`, then run `stage-scope-check.py --stage <stage> --version <version> --module <module> --changed-paths-file docs/versions/<version>/evidence/stage-scope/<task-id>.paths` (plus `--submodule <submodule>` for submodule packets) before completion and fail on out-of-stage task paths.
- A testing child task that edits an existing Rust inline test captures the file before editing with `baseline-snapshot.py` under git-ignored `.harness/baselines/<task-id>/` and passes `--baseline-manifest` to `stage-scope-check.py`; it never synthesizes a Git index, tree, or commit.
- Upstream-stage changes MUST NOT automatically edit downstream-stage artifacts. If a downstream artifact becomes stale, the pipeline MUST create or reopen the downstream stage task instead of silently bundling the edit into the upstream task.
- If a stage contains direct submodules, the pipeline MUST create independent child tasks for those submodules or record a concrete merged-task reason in the pipeline plan.
- `pipeline/state.json` MUST record scheduler strategy, shared-artifact ownership, and scheduling waves. Each wave lists child tasks launched together; tasks in one wave MUST have no dependency relationship, and completed pipelines require every declared task to appear in at least one wave.
- Each child task MUST have:
  - one owner
  - one clear output
  - explicit file or scope boundary
  - explicit dependencies
  - observable done criteria
- `pipeline-plan-check.py` MUST fail a plan with unresolved placeholders; an unbound version/packet/task; duplicate or unknown task ids; missing, cyclic, later-stage, or unfinished dependencies; invalid parent tasks or statuses; missing design/implementation/testing/acceptance stages; incomplete target-module scope bindings; over-broad `Scope Paths`; an invalid file-level implementation sequence; Trigger/binding/testing `change_id` drift; missing launch/document policy evidence; or incomplete exit conditions.

## Recommended Stage Order
1. Design planning and design tasks that write pipeline-plan mappings
2. Implementation tasks
3. Testing planning and testing implementation tasks that generate `testplan.yaml`, write pipeline-plan coverage, and produce runnable evidence
4. Acceptance task

## Recursive Submodule Rule
- If `proposal.md` and the pipeline-plan design mappings define direct submodules for the same task, the pipeline MUST create independently addressable child tasks in the bound pipeline plan and mirror them in:
  - design child tasks
  - testing child tasks
  - implementation child tasks where ownership can be separated safely
- Layered design artifacts for the same task MUST live in `pipeline/plan.md` design mapping sections; implementation and testing child tasks reference those sections instead of copying their contents or creating `design/<submodule>.md` files.
- Same-task child tasks do not create nested task packets. Independent submodule proposal/design artifacts for a separate new requirement require their own sibling task packet, such as `docs/versions/<version>/modules/<module>/<task-seq>-<task-slug>/proposal.md`; do not hide new requirements in an older packet or nest a sequence-prefixed packet inside it.
- Shared cross-cutting topics may be separate child tasks if they have clear boundaries.

## Acceptance Task Rule
- Final acceptance MUST compare delivered results back to the launch-confirmed `proposal.md`.
- Final acceptance MUST generate or finalize acceptance rules and expected results from proposal, pipeline-plan design mappings, implementation, and testing implementation.
- Final acceptance MUST check consistency between proposal, pipeline-plan design mappings, implementation, testing implementation, and results.
- Final acceptance MUST audit whether test design is reasonable and covers normal, boundary, negative, error, compatibility, lifecycle, and cross-module cases where applicable.
- Final acceptance MUST apply `harness/rules/acceptance-review-rules.md`.
- Git diff/status output may be used to locate evidence, but it is not the final acceptance standard.
- Final acceptance MUST audit admission for every module needed as evidence for the accepted behavior.
- If consistency problems exist, final acceptance MUST use the launch-confirmed `proposal.md` as the authority and route non-requirement fixes through design -> implementation/code -> testing implementation.
- Acceptance MUST inspect supporting evidence from:
  - pipeline-plan design mappings and implementation scope bindings
  - test implementation, fixtures, runners, `testplan.yaml`, pipeline-plan testing evidence, and machine-written run artifacts
  - direct submodule packets when the accepted work is split by submodule
  - implementation
  - test code
  - test results
- Acceptance MUST output:
  - findings first, sorted by severity
  - accepted, rejected, or needs changes conclusion
  - evidence summary
  - mismatch list
  - document and implementation logic findings
  - category-by-category implementation correctness audit covering logic/control flow, termination/progress, concurrency/synchronization, resource lifetime/cleanup, state/data integrity, error handling/recovery, interface boundaries/compatibility, and security/capacity safety
  - return-routing decision

## Return Routing Rule
- If acceptance fails, the pipeline MUST return work to the correct earlier stage instead of exiting.
- If acceptance finds a proposal ambiguity, contradiction, incorrect requirement, or incorrect acceptance boundary, the pipeline MUST stop and ask the user to decide; it MUST NOT infer the intended proposal or create an automatic proposal return task.
- If acceptance finds a missing or defective architecture, algorithm, state/concurrency/resource model, interface contract, or failure strategy, return to design. If the design is adequate but code is defective, return to implementation.
- If acceptance finds incomplete, ambiguous, unreasonable, stale, or non-runnable test design / test implementation coverage, the pipeline MUST return to the testing stage to supplement tests and evidence before rerunning acceptance.
- Non-requirement acceptance failures MUST repeat design -> implementation -> testing, then rerun acceptance.
- If the same unresolved issue remains after more than 5 unsuccessful iterations, the pipeline MUST stop and report the issue to the user.
- The iteration counter lives in the pipeline plan: every failed acceptance run MUST append a return record (blocking issue id, owning stage, target task, reason, expected fix output), and the iteration count for an issue is the number of return records with the same blocking issue id. Do not track the count from memory or chat context.
- `pipeline-plan-check.py --require-complete` MUST fail if final exit-condition checkboxes are not complete.

Minimum return categories:
- proposal issue requiring user decision and pipeline stop
- design issue
- testing implementation issue
- implementation issue

For each failed acceptance run, record:
- blocking issue id
- owning stage
- target task to reopen or recreate
- reason for return
- expected fix output

## Exit Condition
- The pipeline MUST continue until:
  - proposal-defined outcomes are satisfied
  - blocking issues are closed
  - required tests and evidence exist
  - final acceptance passes

## Guardrails
- The pipeline MUST NOT skip planning and jump straight into implementation.
- The pipeline MUST NOT treat missing pipeline-plan design mappings as implementation-ready.
- The pipeline MUST NOT treat missing post-implementation test evidence as acceptance-ready.
- The pipeline MUST NOT generate design or testing Markdown documents to satisfy auto-pipeline stage outputs; testing still MUST generate `testplan.yaml`, and other outputs belong in the pipeline plan and executable evidence.
- The pipeline MUST NOT treat one failed acceptance as terminal completion.
- The pipeline MUST NOT let downstream documents override proposal intent.
- The pipeline MUST record the ownership or validation boundary for every child task in the pipeline plan; unnecessary task depth is rejected by acceptance when it creates unclear ownership or evidence.

## Suggested Companion Files
- `pipeline/plan.md` or equivalent generated plan artifact
- child task template
- acceptance report template
