# Test Design Rules

## Goal
- Define how post-implementation test cases are designed and recorded.
- Make completeness derivable from approved design documents and delivered code.

## Scope
- Post-implementation test case design at `unit`, `dv`, and `integration` levels.
- `testing.md` sections `## Unit Tests`, `## DV Tests`, `## Integration Tests`, `## Design Element Coverage`, and `## Case-Type Coverage`.
- Acceptance audits that cite this rule.

## Level Contracts

### Unit
- Object: changed functions, methods, and branches; external dependencies are stubbed or mocked.
- Placement: code inside an existing Rust `#[cfg(test)]` item is test code, but every newly created unit test MUST be implemented in a dedicated test file, test directory, or test-only crate/package rather than as a new inline test body in a production source file.
- Mechanical scope: when testing changes an existing inline Rust test item, `baseline-snapshot.py` first captures the file under `.harness/baselines/<task-id>/`, and `stage-scope-check.py --baseline-manifest ...` passes it only if all changes are confined to pre-existing exact `#[cfg(test)]` items. It fails closed for a missing/tampered baseline, a newly added inline item, or any production-content change.
- MUST cover every public function touched by implemented `change_id` values and every conditional branch in changed code: if/else arms, match/switch arms, early returns, error returns, loop zero/one/many iterations, and boundary comparisons.
- Uncovered branches MUST be recorded per branch with a concrete reason in `## Unit Tests`.
- Not responsible for cross-module behavior, real external I/O, or full workflows.
- Done when every changed-code branch is covered or has a recorded per-branch gap reason.

### DV (single-module runnable verification)
- Object: the module as a whole inside its boundary, with real internal wiring between submodules.
- MUST cover lifecycle where applicable, each main workflow, at least one failure workflow, behavior-changing configuration variants, and persisted-state recovery when the module persists state.
- Not responsible for branch-level internal coverage or neighbor-module contracts.
- Done when each main workflow and at least one failure workflow have runnable DV steps or recorded gaps.

### Integration
- Object: contracts between this module and neighbor modules.
- MUST cover every consumed exported interface with at least one success case and one failure-semantics case, plus cross-module data flow and side-effect ordering for boundary-crossing key call flows.
- Not responsible for re-proving logic already covered at unit or DV level.
- Done when every consumed exported interface has success and failure coverage or recorded gaps.

### API and Repository Consumer Contracts
- These contract checks complement, and do not replace, unit/DV/integration levels.
- Breaking public APIs require: new-path external compilation succeeds; old-path external compilation is rejected for the expected removed symbol; the repository scan has no unallowlisted old-symbol references; and all affected repository consumers compile.
- Repository consumers include production references, tests, examples, benches, doctests, README/documentation compile fixtures, and downstream workspace packages identified by design.
- A text scan is discovery/absence evidence, not a substitute for compiler closure. Aliases, re-exports, macros, feature combinations, and generated targets require compiler-backed checks where applicable.
- The canonical removed-symbol absence check is `harness/scripts/consumer-closure-check.py`; ad hoc `rg`, shell-negated searches, or pasted search output are not acceptance evidence.

## Lowest-Level Placement
- Verify behavior at the lowest level that can expose its failure: pure logic at `unit`, single-module runtime behavior at `dv`, cross-module contracts at `integration`.
- Higher-level tests MUST NOT compensate for missing lower-level coverage.
- Duplicate verification across levels MUST record a reason.

## Case Derivation
Test cases MUST derive from design artifacts. Each derivation source below gets concrete cases or an explicit `## Design Element Coverage` row:

| element_type | Derivation source | Required cases |
|--------------|-------------------|----------------|
| parameter-domain | changed interface input domains | equivalence classes plus min, max, empty, just-outside-range, malformed input |
| state-transition | `## State and Ownership` transitions | one case per legal transition plus illegal-transition rejection cases |
| failure-path | `## Key Call Flows` failure handling | one fault-injection case per recorded failure path |
| error-handling | changed-code error categories | at least one case triggering each category |
| invariant | `## Invariants to Preserve` | one case verifying each invariant |
| concurrency | concurrency, reentrancy, or ordering declarations | race, reentry, ordering cases, or a manual reason |

- Every `element_type` MUST appear at least once; no matching design content uses `status: not-applicable` with concrete design evidence.
- Each derived case MUST name its design source so acceptance can audit authenticity.
- New failure paths, error categories, or state transitions found in code but missing from design return to design.

## Required Recording
- `## Unit Tests`: function/branch, covered behavior, test file, status, and per-branch gaps.
- `## DV Tests`: one row per lifecycle, main, failure, config, or persistence workflow.
- `## Integration Tests`: one row per cross-module contract or flow with success and failure cases.
- `## Design Element Coverage`: one row per derivation source with derived cases and level.
- `## Case-Type Coverage`: records which level implements each covered case.
- Status vocabulary: `covered`, `gap`, `manual`, `disabled`, `not-applicable`; non-covered statuses need concrete reasons.

## Guardrails
- In manual flow, `doc-structure-check.py --docs testing` validates level tables, design element coverage, case-type `level`, and placeholder-only rows when optional `testing.md` exists. Auto-pipeline does not run that document check and validates pipeline-plan testing tables plus `testplan.yaml` through `testing-coverage-check.py`.
- Acceptance MUST audit per-level depth, not only case-type row presence.
- Execution evidence and unified-entrypoint registration are governed by `testing-doc-rules.md` and `unified-test-entry-rules.md`.

