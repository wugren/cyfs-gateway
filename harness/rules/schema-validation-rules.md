# Schema Validation Rules

## Goal
- Define machine-checkable task packet, rule, and validation metadata structure.
- Make implementation admission fail closed on missing fields, approval state, or change-level traceability.

## Scope
- Task packet proposal/design/testing/testplan files under `docs/versions/<version>/modules/<project>/<task-seq>-<task-slug>/`.
- Cross-project task packets under `docs/versions/<version>/modules/globals/<task-seq>-<task-slug>/`.
- Harness checkers: `schema-check.py`, `admission-check.py`, `stage-scope-check.py`, `doc-structure-check.py`, `testing-coverage-check.py`, `acceptance-report-check.py`, and `pipeline-plan-check.py`.

## Required Front Matter
Manual-flow `proposal.md` and `design.md` MUST contain YAML-style front matter. Auto-pipeline requires only packet `proposal.md`; optional `testing.md` uses the same metadata when generated:

```yaml
module: <project-or-globals>
task_name: <task-seq>-<task-slug>
version: <version>
status: draft | approved | rejected | superseded
approved_by: <person-or-process>
approved_at: <iso-8601-date-or-datetime>
approved_content_sha256: <64-hex-content-hash>
```


Task packet docs MAY also include:

```yaml
submodule: <task-seq>-<task-slug>
```

Manual-flow implementation admission accepts only `status: approved`. Explicitly user-launched auto-pipeline admission treats launch as confirmation of the bound proposal and does not require proposal approval metadata.

## Approval Provenance Schema
- Agents MUST NOT set `status: approved` or fill approval fields on their own initiative.
- Approved documents MUST use one of two provenance forms:
  - User approval: `approved_by` names the user, and `## Approval Record` contains non-placeholder `approver`, `approval_date`, and verbatim `user_statement`; `approver` matches `approved_by`.
  - Auto-pipeline approval: `approved_by: auto-pipeline`, valid only while `pipeline/plan.md` records confirmed `User launch confirmed:` plus the user's verbatim explicit instruction in `User launch statement:` under `## Trigger`; agents never infer or synthesize those fields.
- Agent-like `approved_by` values such as `agent`, `assistant`, `claude`, `ai`, `self`, `auto`, or `bot` fail validation.
- Approval metadata may be changed only as part of explicit approval for that document.
- The approving edit MUST record `approved_content_sha256` from `schema-check.py --print-approval-hash <document>`; the hash excludes `status`, `approved_by`, `approved_at`, `approved_content_sha256`, and the entire `## Approval Record` section.
- `schema-check.py` and `admission-check.py` MUST recompute this hash and fail approved documents whose hash is missing, malformed, or stale.
- `schema-check.py` and `admission-check.py` fail closed on missing, placeholder, inconsistent, agent-like, or unverifiable approval provenance.

## Task Name Sequence Schema
- Task packet directory names and front matter `task_name` values MUST match `<task-seq>-<task-slug>`.
- `<task-seq>` is a version-local decimal sequence with default width 3 digits. New versions start at `001`; subsequent tasks increment by 1 across all project modules and `globals` in that version.
- `<task-slug>` is the stable human-readable task slug. Use lowercase ASCII words separated by hyphens unless a repo custom rule defines a stricter slug format.
- `docs/versions/<version>/modules/tasks.md` MUST record the same sequence-prefixed `task_id` and packet path.
- The sequence identifies creation order only; active/current task resolution still comes from the user request, module Current/Active Task field, or confirmed unfinished-task index row.
- New task sequence allocation MUST use `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/task-seq.py next --version <version> --slug <task-slug>`; hand-picked sequence numbers are invalid unless the script output is recorded or reproduced by `task-seq.py check --require-next`.

## Approved Task Immutability
- `status: approved` task packet documents are immutable by default.
- New requirements, new APIs, new `change_id` values, scope expansion, success-criteria changes, or downstream supplements MUST use a sibling task packet.
- Corrections to approved task content MUST use a sibling amendment/fix task packet that records the original packet path and correction reason.
- Only a user-requested current/latest task packet with `status != approved` in the relevant stage document may be edited for that stage.
- A task is current/latest only when the current user request explicitly points to it or `docs/modules/<module>.md` Current/Active Task points to it; directory order and timestamps do not count.
- `docs/versions/<version>/modules/tasks.md` is the unfinished-task index. It contains only unfinished task records; new tasks are added when created and removed when completed.

## Change Traceability Schema
- Every implementation-ready change has one stable, specific `change_id`; broad IDs such as `misc`, `cleanup`, `all`, `module`, or `bugfix` are invalid.
- The same `change_id` MUST appear in:
  - `proposal.md` `## Proposal Items`, `change_id` column, with non-empty `proposal_id`, `requirement`, and `success_evidence`.
  - `design.md` `## Directly Mapped Change Items`, keyed by `change_id` plus `target_module`, with non-empty `proposal_id`, `Design Coverage`, and `Scope Paths`.
- Post-implementation testing evidence also references the same `change_id`, but testing files are not implementation-admission prerequisites.
- Mentions in comments, prose, unrelated tables, historical notes, module overviews, or oral explanations do not satisfy admission.

## Active Module Resolution
- Admission requires explicit `version`, `module`, and one or more `change_id` values.
- Task directories under a project-level module or `globals` also require `submodule=<task-seq>-<task-slug>` for checker compatibility.
- `globals` is a specialized packet-module keyword, never an implementation target. Multi-project requests use `globals/<task-seq>-<task-slug>/` for shared intent, then run admission and implementation scope checks with `--module globals --submodule <task-seq>-<task-slug> --target-module <project>` independently for every affected project.
- A new task MUST NOT be admitted from an older or approved task packet.
- If a new task clearly belongs to a different module than unfinished records in `docs/versions/<version>/modules/tasks.md`, those records are ineligible and the task MUST create a new task packet for the requested module.
- If an active same-module task cannot be determined from the current request, `docs/modules/<module>.md` Current/Active Task, or a confirmed `docs/versions/<version>/modules/tasks.md` record, create a new task packet or stop for confirmation.
- If the active module cannot be determined from paths, module docs, or the user's explicit request, route to proposal or design.

## Testplan Schema
Completed testing MUST include `testplan.yaml` unless a repo-local versioned rule permits missing machine-readable metadata and records reason, owner, risk, and acceptance impact. `schema-check.py` validates `testplan.yaml` when present; `testing-coverage-check.py` enforces mapping unless explicitly allowed.

```yaml
schema_version: 1
version: <version>
module: <module>
task_name: <task-seq>-<task-slug> # required for task packets
submodule: <task-seq>-<task-slug> # optional; required only when explicit submodule metadata is used
api_impact:
  public_api: none | backward-compatible | migration-required | breaking
  crate_root_export_change: false
  build_surface_change: false
  documentation_examples_affected: false
evidence_inputs: ["<production-or-consumer-path>"]
contract_checks:
  mode: enabled | disabled
  reason: <required when disabled>
  steps: [] # enabled risk-triggered checks add id/kind/assertion/name/change_ids/run
levels:
  unit|dv|integration:
    mode: enabled | manual | disabled
    summary: <text>
    test_targets: []
    preconditions:
      tools: []
      env: []
      services: []
      notes: []
    steps:
      - id: <stable-id>
        name: <text>
        change_ids: [<change-id>]
        run: [<command>, <arg>]
```

Rules:
- Every testplan declares structured `api_impact`, a non-empty repository-relative `evidence_inputs` list, and `contract_checks` with `enabled` or reasoned `disabled` mode.
- Contract steps define `kind` plus its fixed matching `assertion`; mismatched or arbitrary assertions fail validation.
- Enabled levels need at least one step.
- Enabled steps define `id`, `name`, `change_ids`, and `run`.
- Step ids are unique within the task packet.
- Manual/disabled levels include `change_ids` and a reason in evidence and optional testing metadata.
- Unknown levels fail validation.

## Checker Contract
- `schema-check.py` validates packet structure, approval provenance, and optional testplan shape, with `--submodule <task-seq>-<task-slug>` for task directories.
- `admission-check.py` validates explicit `version`, packet `module`, optional `submodule`, concrete `target_module`, `change_id` values, mandatory proposal/design traceability, and approval provenance. `--module globals` requires `--target-module`.
- `admission-check.py --evidence-file ...` also validates proposal/design reading evidence, direct coverage judgment, active module resolution, same-module task selection or cross-module task exclusion, no chat-only evidence, file name date, document hashes, and verbatim coverage quotes.
- `admission-check.py --verify-only` is reserved for an explicit user-requested audit or an admission-owned input change; acceptance and `check-all.py` MUST NOT invoke it for unchanged evidence.
- On success, `admission-check.py` writes an admission stamp with bound document hashes and admitted design `Scope Paths`; later stages reuse it while those inputs remain unchanged. `stage-scope-check.py` only evaluates the current task manifest against the selected stage and `change_id` Scope Paths.
- `stage-scope-check.py` validates per-task changed path manifests using canonical paths resolved beneath the real repository root. Absolute paths, `..`, symlink escapes, and glob Scope Paths fail closed. After matching `--submodule`, it strips that task-directory prefix before classifying task-local `design/` and `testing/` paths. It allows only narrow stage companion paths required by the workflow: proposal task-index updates; auto-pipeline task-local `pipeline/plan.md` only for design; task-local `pipeline/state.json` for design/implementation/testing/acceptance bookkeeping; testing-stage `harness/scripts/test-run.py` entrypoint wiring; testing-stage `test-results/test-runs/*.json` run evidence; and stage-scope/admission evidence. During testing, a production-path Rust file is allowed only when a verified `.harness/baselines/<task-id>/manifest.json` snapshot proves all changes are inside pre-existing exact `#[cfg(test)]` items; new inline items, mixed production/test changes, missing/tampered baselines, and extension-only allowances fail closed. Implementation runs require `--version`, packet `--module`, concrete `--target-module`, repeatable `--change-id`, and `--changed-paths-file`, then fail paths outside the selected target's admitted `Scope Paths` except task evidence and allowed state bookkeeping; implementation also rejects stage artifacts in every task packet, not only the active packet.
- Every `.paths` manifest MUST have a sibling `.paths.meta.json` with schema `1`, stage, version, packet module, optional task submodule, concrete `target_module`, optional `baseline_manifest`, and implementation `change_ids`; testing tasks that change existing inline Rust tests record `.harness/baselines/<task-id>/manifest.json`. Run `stage-scope-check.py` after this metadata, the manifest, governed paths, baseline, or design Scope Paths change; do not replay it otherwise.
- `baseline-snapshot.py` writes only under git-ignored `.harness/baselines/` and refuses overwrite. Harness rules forbid synthetic Git baselines created with `GIT_INDEX_FILE`, `git read-tree`, `git write-tree`, or `git commit-tree`.
- `doc-structure-check.py` validates proposal core sections, design UML diagrams, source-language file-level interface blocks, acyclic relationships, useful design sections, testing case coverage, and mandatory tables needed by admission/testing.
- `testing-coverage-check.py` validates direct `change_id` coverage, gap reasons, testplan mapping, case-type coverage, and unified test entrypoint reachability.
- `test-run.py` writes machine-readable task run artifacts under `test-results/test-runs/`; artifacts record exact task scope, testplan, `change_id` values, commands, sources, and exit codes without a repository/package state hash.
- Changes under `harness/**` or `docs/**` do not invalidate task evidence and MUST NOT trigger package/module tests, whole-project tests, or quality gates.
- `quality-check.py` runs `harness/quality-gates.yaml` only on explicit user request and writes artifacts under `test-results/quality-runs/`; `check-all.py`, task execution, and acceptance do not invoke it automatically.
- `acceptance-report-check.py` validates reports when created, including blocking findings, command evidence, consistency evidence, acceptance rules, test design evidence, and referenced passing task artifacts; historical reports are not replayed by `check-all.py`.
- `pipeline-plan-check.py` validates task-local immutable `pipeline/plan.md`, its sibling `pipeline/state.json`, launch evidence, stage graph dependencies, task statuses, testing evidence, and exit-condition evidence. Run it only after one of those inputs changes; later stages reuse the latest passing result.
- All checkers MUST exit non-zero on missing mandatory files, invalid approvals, missing traceability, ambiguous active module, malformed optional metadata, or out-of-stage paths.
- Stage scope checks fail proposal, design, testing, acceptance, or implementation task manifests that contain paths outside their stage and the explicit companion paths above. In auto-pipeline mode, child manifests contain only reserved direct-write paths and task-specific evidence; parent-orchestrator merges of `pipeline/plan.md`, `pipeline/state.json`, shared `testplan.yaml`, indexes, or shared runner registration are recorded and checked as parent-owned coordination updates, never attributed to a parallel child.
- Passing checkers are necessary but not sufficient: agents must still read approved docs and keep edits inside admitted scope.
