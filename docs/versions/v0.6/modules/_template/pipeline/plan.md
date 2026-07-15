# Pipeline Plan

## Trigger
- Proposal: docs/versions/<version>/modules/<packet-module>/<task-name>/proposal.md
- User launch confirmed: <yes-after-explicit-user-launch>
- User launch statement: <verbatim-user-instruction-that-explicitly-launches-auto-pipeline>
- Per-stage user confirmation: skipped by explicit user auto-pipeline authorization
- Auto-confirm completed document stages: no design/testing Markdown documents generated; repository-local document extensions only
- Auto-pipeline document policy: no design/testing markdown docs; testplan.yaml required
- Version: <version>
- Packet module: <project-or-globals>
- Task name: <task-seq>-<task-slug>
- Target module(s): <project-module>[, <project-module>]
- change_id values: <change-id>[, <change-id>]

## Acceptance Baseline
- Final acceptance is judged against:
  - `proposal.md`

## Stage Graph
| Task ID | Stage | Responsibility | Scope | Parent Task | Depends On | Output | Done Condition |
|---------|-------|----------------|-------|-------------|------------|--------|----------------|
| D-1 | design | convert user-confirmed intent into executable structure | bound task packet | root | none | pipeline plan design mappings and scope bindings | design rules satisfied without generating design docs |
| I-1 | implementation | deliver production code inside approved boundaries | bound task packet | root | D-1 | production code | implementation complete |
| T-1 | testing | design test cases from proposal/plan/code, generate test implementation, and wire tests into unified entrypoint | bound task packet | root | I-1 | tests + testplan.yaml + test-run wiring + state testing evidence | testing implementation reachable through test-run |
| A-1 | acceptance | generate acceptance rules and expected results, audit the evidence chain, and judge proposal satisfaction | bound task packet | root | T-1 | acceptance report | acceptance passed |

## Submodule Tasks
| Task ID | Stage | Responsibility | Submodule | Parent Task | Depends On | Output | Done Condition |
|---------|-------|----------------|-----------|-------------|------------|--------|----------------|
| I-file-1 | implementation | implement one file-level module | <file-level-module> | I-1 | D-1 | production file | file implementation complete |

## Parallel Scheduling
- Strategy: dependency-ready-set
- Concurrency: use all runtime-available child-agent slots
- Shared artifact owner: parent-orchestrator
- Lock directory: `.harness/locks/`
- Dispatch rule: launch the maximum dependency-ready set with disjoint exclusive write scopes before waiting; immediately backfill free slots
- Serialization reasons: explicit dependency, overlapping write scope, or exhausted concurrency capacity only
- Evidence: record launched task ids and serialization reasons in sibling `pipeline/state.json` scheduler waves

## Dependency Graphs
```mermaid
graph TD
    api --> domain
    domain --> storage
```

| Level | Parent | Node | Depends On |
|-------|--------|------|------------|
| submodule | <project-module> | api | domain |
| submodule | <project-module> | domain | storage |
| submodule | <project-module> | storage | none |

## Exported Interfaces
| Interface | Owner | Consumer | Compatibility | Affected Callers | Migration Path |
|-----------|-------|----------|---------------|------------------|----------------|
| <interface-name> | <owning-submodule> | <existing-module-or-change-id> | new | none | none |

## API and Build Surface Impact
- Public API impact: none
- Crate-root export change: no
- Build-surface change: no
- Documentation examples affected: no

## Consumer Migration Closure
| Old Symbol | New Path | change_id | Consumer Path | Consumer Kind | Migration Status |
|------------|----------|-----------|---------------|---------------|------------------|
| not-applicable | not-applicable | <change-id> | not-applicable | not-applicable | verified-none |

## State Ownership
| State | Owner | Access Interface | Lifecycle | Failure Transitions |
|-------|-------|------------------|-----------|---------------------|
| <persistent-or-shared-state> | <single-owner-submodule> | <exported-interface> | <states-and-legal-transitions> | <failed-state-and-recovery-transitions> |

## Failure Flows
| Flow | Boundary | Failure | Handling |
|------|----------|---------|----------|
| <key-call-flow> | <cross-module-boundary> | <concrete-failure> | <propagation-retry-rollback-or-compensation> |

## Rejected Alternatives
| Decision Type | Selected | Rejected | Reason |
|---------------|----------|----------|--------|
| boundary | <selected-boundary> | <rejected-boundary> | <why-rejected> |
| technical | <selected-technology> | <rejected-technology> | <why-rejected> |
| collaboration | <selected-collaboration> | <rejected-collaboration> | <why-rejected> |

## Implementation Scope Bindings
| change_id | target_module | proposal_id | design_coverage | scope_paths | design_rules_applied |
|-----------|---------------|-------------|-----------------|-------------|----------------------|
| <change-id> | <project-module> | <proposal-id> | <concrete pipeline-plan design mapping> | `<repo-relative/path>` | module decomposition, dependencies, interfaces, state, risks |

## File-Level Implementation Sequence
| Sequence | Task ID | File-Level Module | Action | Depends On | change_id | target_module | Scope Paths | Context Sources |
|----------|---------|-------------------|--------|------------|-----------|---------------|-------------|-----------------|
| 1 | I-file-1 | `<repo-relative/path>` | create / modify | none | <change-id> | <project-module> | `<repo-relative/path>` | proposal excerpt, pipeline plan design mapping, relevant source only |

## Return Rules
- If acceptance finds proposal ambiguity:
  - stop the pipeline and ask the user to decide; do not infer the requirement or create an automatic proposal return task
- If acceptance finds design mismatch:
  - return to design when the architecture, algorithm, state/concurrency/resource model, interface contract, or failure strategy is absent or wrong
- If acceptance finds implementation defect:
  - return to implementation when adequate design exists but delivered code is defective
- If acceptance finds testing implementation gap:
  - return to testing task
- For non-requirement findings:
  - repeat design -> implementation -> testing, then rerun acceptance
- If the same unresolved issue remains after more than 5 unsuccessful iterations:
  - stop and report the issue to the user

Execution status, testing evidence, return records, and final acceptance are stored in sibling `state.json`. They are deliberately excluded from this admission-bound plan.

