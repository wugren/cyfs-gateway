# Design Document Rules

## Goal
- Define the minimum useful structure and approval requirements for `design.md` and task-local `design/`.
- Keep design documents readable by using UML diagrams for module relationships and source-language signatures for file-level interfaces.

## Scope
- Single-project design: `docs/versions/<version>/modules/<project>/<task-seq>-<task-slug>/design.md` and optional task-local `design/`.
- Cross-project design: `docs/versions/<version>/modules/globals/<task-seq>-<task-slug>/design.md`.
- Required long-lived boundary sync in `docs/modules/<module>.md`.
- Project-rule-required updates to global architecture docs under `docs/architecture/`.

## Required Metadata
- `module`
- `version`
- `status`
- `approved_by`
- `approved_at`

## Required Content
- Design scope, useful context, and the smallest sufficient overall approach.
- A top-down layered design decomposition from the whole affected module to submodules, nested submodules, and file-level modules.
- A design document index that names each level's independent design document; child level documents live under the parent module document directory's `design/` directory and are named after the child submodule.
- UML-style Mermaid diagrams for module relationships at every affected level with multiple units.
- Source-language fenced code blocks for file-level module interfaces when the design reaches implementation files.
- Key boundary-crossing flows as sequence diagrams when runtime interaction matters.
- State/data ownership only for persistent data or shared state affected by the task.
- Direct change mapping with stable `change_id` values, a concrete `target_module`, and concrete `Scope Paths`.
- File-level modules to create or modify, ordered by same-level dependency for implementation.
- Implementation ordering constraints, material design notes, risks, rollback notes, and `## Approval Record`.

## Guardrails
- Design implements approved proposal intent without changing scope.
- Design tasks deliver `status: draft`; agents MUST NOT approve their own documents.
- Approval requires explicit user approval plus `## Approval Record`, or auto-pipeline approval backed by launch evidence, and MUST record `approved_content_sha256`.
- After `status: approved`, this design is frozen for new requirements, new `change_id` values, scope expansion, success-criteria changes, downstream supplements, and implementation-scope widening; create a sibling task packet or amendment/fix packet instead of editing it.
- Approval metadata may be updated only as part of explicit approval for this document; do not refresh the hash to make old edited approved content pass.
- Design tasks are single-stage by default and MUST NOT edit proposal, testing, acceptance, code, tests, or another task packet unless explicitly requested.
- Design stays at module shape level: relationships, ownership, interfaces, external dependencies, key flows, state transitions, and implementation order. Avoid low-level implementation detail unless it affects a contract, dependency, state, or control flow.
- Design docs MUST contain only useful content. Delete filler tables, placeholder sections, repeated proposal text, speculative extension points, idealized architecture, test planning, and facts that do not affect implementation, admission, or acceptance.
- Design MUST proceed top-down: whole affected project/module first, then direct submodules, nested submodules, and finally file-level modules. A lower level is not implementation-ready unless every parent level has a same-level design description and indexed child design document.
- Each submodule or nested submodule level MUST have an independent design document under the parent module document directory's `design/` directory, with the file name based on the child submodule name, for example `design/<submodule>.md`. The parent design document MUST list the child document in `## Layered Design Document Index`.
- Layered design documents belong to the active task's design artifact group. They describe the same task's decomposition and MUST NOT be used as a substitute for creating a sibling task packet for a new requirement or independent task.
- Design-stage artifacts MUST NOT define test cases, test plans, test strategy, validation IDs, test fixtures, testability seams, test implementation, or expected test results. Testing-stage artifacts own test-case design and test implementation after implementation completes.
- Module relationships MUST be represented with UML-style Mermaid diagrams instead of prose tables. Use `classDiagram` for static dependencies/ownership, `sequenceDiagram` for boundary-crossing flows, and `stateDiagram-v2` for lifecycle/state transitions when relevant.
- UML diagrams describe same-level relationships only. Do not draw dependencies between submodules with different parent modules; represent that relationship at the nearest common parent level.
- Module and submodule dependency graphs MUST be acyclic. Circular dependencies return to design.
- Split by business responsibility first. Shared implementation logic used by multiple business submodules belongs in a shared submodule; single-consumer logic stays with its consumer.
- Technical areas such as HTTP interfaces, persistence, adapters, codecs, schedulers, or storage become technical submodules only when they have clear responsibility boundaries; otherwise keep them inside the owning business submodule and record the reason in `## Design Notes`.
- Dependency direction is business -> shared/technical. Shared and technical submodules MUST NOT depend on business submodules, and nothing may depend on an assembly submodule.
- A shared submodule needs at least 2 visible consumers and one nameable responsibility. Grab-bag `common`, `utils`, `misc`, or `helpers` designs are defects.
- File-level modules are one source file each. When file-level design is needed, the interface MUST be described with the current project's implementation language in fenced code blocks, for example Rust traits/struct impl signatures, TypeScript interfaces/classes, Python classes/protocols, Go interfaces, or comparable language-native signatures.
- File-level interface descriptions MUST name the concrete consumer or mapped `change_id` and compatibility decision (`new` / `backward-compatible` / `migration-required` / `breaking`). Breaking or migration-required changes MUST list affected callers and migration path.
- Designs that touch exported interfaces MUST include `## API and Build Surface Impact` with concrete `Public API impact`, `Crate-root export change`, `Build-surface change`, and `Documentation examples affected` values.
- A `breaking` or `migration-required` public API, crate-root export change, or build-surface change MUST include `## Consumer Migration Closure` rows mapping old symbol -> new path -> `change_id` -> concrete repository-relative consumer file -> consumer kind -> migration status.
- Consumer paths MUST be file-level paths. Directory-only paths, glob-only paths, `all callers`, and prose summaries do not count as consumer discovery evidence.
- Allowed migration statuses are `migrated`, `allowed-negative-fixture`, `allowed-compatibility-shim`, and `verified-none`. `allowed-compatibility-shim` is valid only for migration-required, never breaking, changes. `verified-none` requires a later machine-run removed-symbol scan.
- Unowned global functions as the primary file-level design are defects unless a repo custom rule or language constraint records an explicit exception in `## Design Notes`.
- Every persistent datum or shared state has exactly one owning submodule; other submodules access it through the owner's interface.
- Lifecycles and cross-boundary call flows include failure, timeout, retry, idempotency, and partial-completion behavior only where those behaviors affect this change.
- Boundary, technical-choice, and cross-module collaboration decisions record a serious rejected alternative only when a real alternative was considered; otherwise omit the filler and record no fake decision.
- Do not record testability seams in design documents. If a replaceable dependency or boundary hook is required for production behavior, describe it as an implementation interface with its real consumer and compatibility decision, not as a testing aid.
- Changes to existing modules list externally observable behavior and invariants to preserve when those invariants constrain the implementation; greenfield modules can record `not-applicable: new module`.
- Small submodules may map to one file. Larger submodules with internal responsibilities should be directories; keep detailed internal layout out of `design.md` unless required for the change.
- The final design MUST identify every file-level module that will be created or modified. `## File-Level Implementation Sequence` MUST order those files by dependency so implementation child tasks can be created and executed in that order.
- Existing-code designs describe current structure only where it constrains the change.
- Large module roots with 3 or more distinct externally visible directories/files MUST model new independent features as direct submodules unless `## Design Notes` explains otherwise.
- New task details belong in a new sibling task packet, not in older task `design/<task-seq>-<task-slug>/` directories or approved packets.
- Human-authored design docs SHOULD stay well below 1000 lines; any doc above 1000 lines MUST be split by submodule, responsibility, validation layer, or interface boundary and the relevant document index must be updated.
- Do not add idealized architecture, speculative features, extension points, configuration, or abstractions beyond the approved proposal.
- New abstractions MUST match local patterns or remove real duplicated complexity, with the reason recorded in `## Design Notes`.
- Cross-module work MUST identify every affected module.
- Broad change buckets are not implementation admission evidence.
- Every `## Directly Mapped Change Items` row MUST name `target_module`. Single-project packets use their project module; `globals` packets use one row per affected project-level target and never use `globals` as the target.
- `Scope Paths` in `## Directly Mapped Change Items` MUST be concrete repo-relative path prefixes or globs that cover exactly the allowed implementation area. Over-broad entries such as `src` are design findings.
- Design MUST update `docs/architecture/` only when repo-local project rules require global architecture documentation changes. Default generated rules do not require mirrored implementation directories, proposal/design docs, or source hash bindings under `docs/architecture/`.
- Proposal ambiguity routes back to proposal.
- Downstream testing or acceptance follow-up is recorded unless cross-stage synchronization is explicitly requested.
- Before completion, run `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/doc-structure-check.py --version <version> --module <module> --docs design`.
