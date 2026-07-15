# Task Entry Gate Rules

## Goal
- Prevent implementation, bugfix, optimization, and refactor requests from bypassing versioned document admission.

## Priority
- This is the highest-priority rule for task classification and implementation admission.
- Apply it before task-type process rules or repository edits.
- Narrow exception: after an explicit current user launch whose verbatim instruction is recorded as task-local `pipeline/plan.md` `User launch statement`, `auto-pipeline-rules.md` has higher priority only for its no-`design.md` / no-`testing.md` policy and use of validated pipeline-plan design mappings. Agents never infer or synthesize launch. The exception does not relax any other entry, approval, scope, or validation gate.

## Harness Rule Activation
- All harness rules apply by default.
- An explicit current user instruction to skip all harness rules disables every harness rule for the scope named by the user. If the user names no scope, apply the skip only to the current task.
- Evaluate this explicit all-rules opt-out before this task entry gate and every other harness rule. Do not infer the opt-out from urgency, a request to proceed, or user silence.
- The opt-out does not override system or developer instructions, safety requirements, remaining user scope constraints, or repository requirements outside the harness.

## Scope
- Code, test, runtime, UI, build, bugfix, optimization, refactor, and implementation-shaped requests.

## Task Packet Rule
- Every new manual-flow task MUST use a packet with its own `proposal.md`, `design.md`, optional `testing.md`, and optional `acceptance.md`.
- Every explicitly launched auto-pipeline task MUST use a packet with `proposal.md`, `pipeline/plan.md`, `pipeline/state.json`, and later `testplan.yaml`; generated `design.md`, task-local `design/`, `testing.md`, and `testing/` are forbidden. Admission-relevant design mappings are recorded in plan; mutable testing coverage and execution status are recorded in state.
- Every new task name MUST use `<task-seq>-<task-slug>`; `<task-seq>` is a version-local sequence number, defaults to 3 digits, starts at `001` for each version, and increments by 1 across all project modules and `globals` in that version.
- When creating a task packet, run `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/task-seq.py next --version <version> --slug <task-slug>` and use the returned `<task-seq>-<task-slug>` for the directory, front matter `task_name`, checker `--submodule`, and unfinished-task index `task_id`.
- Sequence numbers identify creation order only; do not use the largest number to decide the current/latest task.
- Single-project task packet: `docs/versions/<version>/modules/<project>/<task-seq>-<task-slug>/`.
- Cross-project task packet: `docs/versions/<version>/modules/globals/<task-seq>-<task-slug>/`.
- Do not modify an existing task packet to describe new work.
- A task packet document with `status: approved` is frozen by default. New requirements, new APIs, new `change_id` values, scope expansion, success-criteria changes, or downstream supplements MUST create a sibling task packet instead of editing the approved packet.
- Corrections to an approved task MUST create a sibling amendment/fix task packet that names the original packet and explains the correction reason; do not directly edit the original approved document.
- Project-level module packets may contain long-lived overviews, but new implementation admission MUST bind to the current task packet.
- Maintain `docs/versions/<version>/modules/tasks.md` as the unfinished-task index: add new task packets when created, remove task records when completed, and keep only unfinished tasks in the file.
- "Latest task" MUST NOT be decided by directory order, timestamps, or agent guessing. It must come from the current user request or a `docs/modules/<module>.md` Current/Active Task field.
- If the new task clearly belongs to a different module than every relevant unfinished task record, create a new task packet immediately and do not consider continuing any unfinished task from another module.
- If `docs/versions/<version>/modules/tasks.md` lists multiple same-module unfinished tasks and the user request does not identify one, stop and confirm whether to use an existing task or create a new sibling task packet.
- Only the explicitly pointed latest task packet whose current-stage document is not `status: approved` may receive further current-stage edits.

## Stage Write Scope
- When the user explicitly enters one stage, that stage is the only write scope by default.
- Proposal: active packet `proposal.md`, plus the unfinished-task index `docs/versions/<version>/modules/tasks.md` when creating or closing task records.
- Design: only `design.md`, task-local `design/`, required long-lived boundary sync, project-rule-required `docs/architecture/` updates, and task-local `pipeline/plan.md` plus `pipeline/state.json` during an explicitly launched auto-pipeline.
- Testing: only test code, fixtures, runners, unified entrypoint wiring (`harness/scripts/test-run.py`), generated run evidence under `test-results/test-runs/*.json`, optional `testing.md`, `testing/`, `testplan.yaml`, and task-local `pipeline/state.json` coverage/status during an explicitly launched auto-pipeline.
- Testing treats code inside an existing Rust `#[cfg(test)]` item as test code, but new unit tests MUST use dedicated test files, test directories, or test-only crates/packages rather than new inline test bodies in production source files.
- Implementation: only production code, required non-test runtime/build resources, task admission evidence after admission passes, and task-local `pipeline/state.json` status during an explicitly launched auto-pipeline.
- Acceptance: review report, optional manual-flow `acceptance.md`, and task-local `pipeline/state.json` final/return status during an explicitly launched auto-pipeline.
- Acceptance: only evidence audit, architecture-doc validation, generated/final acceptance rules and expected results, and review reports.
- A task MUST NOT edit multiple stage artifact groups unless the user explicitly names the stages or asks for cross-stage synchronization.
- Multi-stage authorization MUST be recorded from the user's own words in the evidence file or produced report; otherwise the task is single-stage.
- Every single-stage task MUST maintain `docs/versions/<version>/evidence/stage-scope/<task-id>.paths`, one repo-relative path per line, plus `<task-id>.paths.meta.json` recording schema `1`, stage, version, module, optional submodule, optional `.harness/baselines/<task-id>/manifest.json`, and implementation `change_ids`.
- Bootstrap and Harness refresh create project-root `.harness/` and ensure `.gitignore` contains `.harness/` without removing existing entries. Runtime files under `.harness/` are omitted from task path manifests.
- Every direct `uv` invocation uses `UV_CACHE_DIR=.harness/uv-cache`; root shortcuts set the equivalent absolute project-local cache path before any `uv` command. Do not allocate per-task `UV_CACHE_DIR` paths under `/tmp`.
- A testing task that edits an existing Rust inline test MUST capture the target before editing with `harness/scripts/baseline-snapshot.py`. Never synthesize a baseline through `GIT_INDEX_FILE`, `git read-tree`, `git write-tree`, or `git commit-tree`.
- Changing an upstream document does not authorize downstream edits. Record the return route or follow-up unless the user explicitly requested those edits.
- Before finishing a single-stage task, run `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/stage-scope-check.py --stage <stage> --version <version> --module <module> --changed-paths-file docs/versions/<version>/evidence/stage-scope/<task-id>.paths` plus `--submodule <task-seq>-<task-slug>` for task packets.
- Do not rerun a passing stage-scope check unless the manifest, sidecar metadata, baseline, a governed task path, or the admitted design Scope Paths changed after that pass. Acceptance and `check-all.py` reuse the existing result.
- Implementation-stage scope checks also pass concrete `--target-module <project>` and repeatable `--change-id <change_id>` so recorded paths are bound to the correct project's admitted design `Scope Paths`.
- Whole-worktree git status or diff is diagnostic only; task completion evidence MUST use the explicit path manifest.

## Approval Authority
- Agents MUST NOT set `status: approved` or fill `approved_by` / `approved_at` on stage documents on their own initiative.
- Document-stage tasks deliver `status: draft` by default.
- Approval is allowed only from an explicit user approval instruction, recorded in `## Approval Record` with `approver`, `approval_date`, and verbatim `user_statement`, or from auto-pipeline auto-confirm backed by `pipeline/plan.md` launch evidence.
- Approval metadata may be updated only as part of explicit approval for that document.
- `schema-check.py` and `admission-check.py` fail closed on missing, placeholder, inconsistent, agent-like, or unverifiable approval provenance.

## Requirement And Scope Classification
- Requests that add, remove, narrow, widen, or reclassify goals, scope, non-goals, obligations, supported/unsupported behavior, acceptance boundaries, or success evidence default to proposal stage.
- Requirement language such as "does not need", "no longer needs", "should not provide", "must provide", "support", or "do not support" defaults to proposal stage unless the user explicitly requests downstream synchronization.
- Proposal-stage work updates `proposal.md`, fills `## Requirement Review` and `## Proposal Items`, and keeps the document focused on requirements, boundaries, tradeoffs, success criteria, `change_id` values, and approval.
- Before proposal completion, run `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/doc-structure-check.py --version <version> --module <module> --docs proposal`.

## Implementation Entry Gate
- Implementation-shaped requests MUST NOT edit code immediately.
- First locate or create the active task packet from the current user request, `docs/modules/<module>.md` Current/Active Task, or a confirmed `docs/versions/<version>/modules/tasks.md` unfinished-task record; then identify `version`, `module`, and concrete `change_id` values.
- Task packets under a project-level module or `globals` MUST identify `submodule=<task-seq>-<task-slug>` for generated checkers.
- `globals` is a specialized packet-module keyword, not an implementation target. Cross-project work uses `globals/<task-seq>-<task-slug>/` for shared intent and binds each affected project independently with `--module globals --submodule <task-seq>-<task-slug> --target-module <project>`.
- Do not reuse older task packets for new work, and do not edit approved packets to absorb new work.
- Before implementation starts, read approved `proposal.md` plus approved `design.md` in manual flow, or the user-launch-confirmed `proposal.md` plus validated `pipeline/plan.md` design mappings and `Scope Paths` in auto-pipeline.
- Create `docs/versions/<version>/evidence/admission/<evidence-id>.md`, where `<evidence-id>` is `<YYYYMMDD>-<task-slug>` using today's date. The dated evidence id MUST NOT be used as the task packet name or unfinished-index `task_id`; those remain `<task-seq>-<task-slug>`.
- Admission evidence MUST include `proposal_read`, `design_read`, `change_scope_matches_request`, `active_module_resolved`, `same_module_task_selection`, and `no_chat_only_evidence`, each `pass` with concrete source and notes.
- Evidence MUST include `## Document Binding` hashes from `admission-check.py --print-doc-hashes` and `## Coverage Quotes` for each admitted `change_id` from proposal plus the active design source (`design.md` or `pipeline/plan.md`).
- `admission-check.py` re-verifies hashes and quotes against current documents and writes the only valid admission stamp. Do not hand-write stamp files.
- Before code edits, run:
  - `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/schema-check.py --version <version> --module <module>`
  - `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/admission-check.py --version <version> --module <module> --change-id <change_id> --evidence-file docs/versions/<version>/evidence/admission/<evidence-id>.md`
- Add `--submodule <task-seq>-<task-slug>` to both checks for task packets.
- Code modification may begin only after admission passes with the task evidence file.
- If schema and admission already passed for the exact current packet documents, evidence, target module, `change_id` values, and Scope Paths, reuse those results. A later stage, acceptance, commit, CI, or report is not a reason to rerun them.

## Default Stage Classification
- If the user does not explicitly name proposal, design, testing, or acceptance, classify by likely artifact changes.
- Requirement or acceptance-boundary changes classify as proposal first.
- Code-changing requests run implementation admission first.
- Failed admission routes to the earliest missing or non-covering document stage.
- Missing active module, submodule, or concrete mapped `change_id` routes to proposal or design.
- `change_id` maps only from the required proposal and design mapping-table columns.
- Oral requirements, chat context, old implementation, module overviews, and historical notes are not admission evidence.
- Ambiguity affecting scope, behavior, risk, or validation routes upstream instead of being guessed.
- "Read code first" permits inspection only. If inspection reveals a document gap, stop the code path and return upstream.

## Return Routing
- Missing task packet or unapproved `proposal.md`: proposal stage.
- Missing direct proposal coverage: proposal stage.
- Manual flow missing or unapproved `design.md`: design stage.
- Auto-pipeline missing pipeline-plan design mapping or concrete `Scope Paths`: auto-pipeline design task.
- Missing direct design, boundary, or interface coverage in the active design source: design stage.

## Examples
- "Fix a 500" is implementation-shaped: run entry gate and admission before code edits.
- "No longer needs X" is proposal-stage requirement language.
- "Update design.md" is design write scope only.
- "Look at why this is slow" allows inspection only until a fix is requested.
