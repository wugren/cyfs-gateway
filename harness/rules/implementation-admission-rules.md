# Implementation Admission Rules

## Goal
- Define the hard prerequisites for implementation and bugfix work.
- This rule applies after `task-entry-gate-rules.md` classifies a request as implementation-shaped.

## Scope
- Implementation tasks, bugfix tasks, and production code changes for versioned task packets.

## Required Inputs
- Active task packet selected by the current user request, `docs/modules/<module>.md` Current/Active Task, or a confirmed unfinished-task record. Manual flow requires `proposal.md` and `design.md`; explicitly launched auto-pipeline requires `proposal.md` plus `pipeline/plan.md` design mappings and MUST NOT require `design.md`. Packet locations:
  - `docs/versions/<version>/modules/<project>/<task-seq>-<task-slug>/`
  - `docs/versions/<version>/modules/globals/<task-seq>-<task-slug>/`
- `docs/versions/<version>/evidence/admission/<evidence-id>.md`.

## Admission Rule
- Admission MUST pass before editing production code, build files, or resources.
- Manual-flow packet docs MUST exist, be `status: approved`, and have valid approval provenance. Auto-pipeline requires an explicit current user launch whose verbatim instruction is recorded as task-local `pipeline/plan.md` `User launch statement`, plus valid dependency/interface/state/failure/alternative design evidence and concrete `Scope Paths`; agents never infer or synthesize launch, and proposal approval metadata is not required.
- Approved status alone is not enough: the task MUST read the proposal plus active design source (`design.md` or pipeline-plan mappings) and confirm direct coverage.
- Admission evidence MUST record `proposal_read`, `design_read`, `change_scope_matches_request`, `active_module_resolved`, `same_module_task_selection`, and `no_chat_only_evidence`, each `pass` with concrete source and notes.
- Evidence file names MUST be `docs/versions/<version>/evidence/admission/<YYYYMMDD>-<task-slug>.md` using today's date.
- Evidence MUST bind to current approved document content with `## Document Binding` hashes and `## Coverage Quotes` for each admitted `change_id`; `admission-check.py` re-verifies both and fails closed on mismatch.
- A passing `admission-check.py` run writes `docs/versions/<version>/evidence/admission/<evidence-id>.<module>[.<submodule>][.<target-module>].stamp.json`. Reuse that stamp while its bound documents, evidence, target module, `change_id` values, and Scope Paths remain unchanged. Never hand-write stamp files.
- Bugfix tasks follow the same rule unless a versioned repo rule defines a narrower exception.
- Bugfix testing MUST produce red-green regression evidence for the bugfix `change_id`, or a concrete reason pre-fix reproduction is not feasible.
- The active `version`, `module`, and concrete `change_id` values MUST be known; task packets also require `--submodule <task-seq>-<task-slug>`.
- If the requested task module is clearly different from every relevant unfinished task record, implementation admission MUST use a new task packet for the requested module and MUST NOT reuse an unfinished task from another module.
- Each admitted `change_id` MUST appear in `proposal.md` `## Proposal Items` and either manual `design.md` `## Directly Mapped Change Items` or auto-pipeline `pipeline/plan.md` `## Implementation Scope Bindings`.
- `globals` is a specialized packet-module keyword, not a production target. Cross-project requests use a `globals/<task-seq>-<task-slug>/` packet for shared intent and admit each affected project independently with `--module globals --submodule <task-seq>-<task-slug> --target-module <project>`.
- Older packets, broad module overviews, historical notes, oral context, or chat claims do not satisfy admission for new work.
- If direct coverage is missing from approved docs, create or route to a sibling task packet or amendment/fix task instead of editing the approved packet or implementing first and documenting later.

## Required Commands
- Run the following only when no passing result exists for the current inputs or when their owned inputs changed. Do not replay them in acceptance or `check-all.py`.
- `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/schema-check.py --version <version> --module <module>`
- `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/admission-check.py --version <version> --module <module> --change-id <change_id> --evidence-file docs/versions/<version>/evidence/admission/<evidence-id>.md`
- Add `--submodule <task-seq>-<task-slug>` to both commands for task packets.
- For a `globals` packet, also add `--target-module <project>` and repeat admission independently for every affected project.

## Allowed Changes
- Production code.
- Required non-test runtime/build resources.
- Task admission evidence under `docs/versions/<version>/evidence/admission/`.

## Execution Guardrails
- Implement the minimum production change needed to satisfy the governing proposal/design and current request.
- Keep changed production paths inside admitted design `Scope Paths`.
- When the approved design lists multiple file-level modules, implementation MUST follow `## File-Level Implementation Sequence` in dependency order and create child tasks in that order.
- Each file-level implementation child task MUST limit its context to the relevant proposal/design excerpts, child design document, `change_id`, `Scope Paths`, interfaces, and source files for that file-level module.
- Record task paths in `docs/versions/<version>/evidence/stage-scope/<task-id>.paths`, then run `stage-scope-check.py --stage implementation --version <version> --module <module> --change-id <change_id> --changed-paths-file ...` before completion.
- If extra paths are legitimately needed, return to design to extend `Scope Paths` or split the work into a separate admitted task.
- Leave test implementation for post-implementation testing unless the user explicitly requested combined implementation/testing.
- Match surrounding style, naming, and structure.
- Do not refactor, reformat, rename, rewrite comments, add features/options, or clean adjacent code unless admitted by the task.
- Remove only artifacts made unused by the current change.
- Record unrelated defects as residual risk or follow-up instead of fixing them inside the implementation task.
- Acceptance evidence MUST trace every changed line to the approved docs, requested behavior, and at least one admitted `change_id`.

## Forbidden Changes
- Proposal, design, testing, acceptance, and test artifacts unless the user explicitly requested the relevant stage in the same task.

## Verification Default
- Repositories may choose a strict default where implementation does not proactively run validation commands.
- In that mode, tests run only when the user asks, debugging needs evidence, or task docs/repo-local rules require validation.

## Rust Formatting Default
- Rust agents MUST NOT automatically run `cargo fmt`; run it only on explicit user request or repo-local rule.

## Return Routing
- Missing/draft proposal or missing direct proposal mapping: proposal task.
- Manual flow missing/draft design, or either flow missing direct design mapping, changed boundaries/interfaces, or out-of-scope task paths: design task. Auto-pipeline writes the correction to pipeline-plan mappings rather than `design.md`.
- Missing active module, task packet, `change_id`, or failing admission evidence: admission setup before code edits.
- Failed schema/admission checker: owning document stage named by checker output.
- Approved docs that do not cover the current task: new sibling proposal/design task or amendment/fix task; do not edit the approved packet.
- Upstream contradiction discovered during implementation: owning upstream stage.
