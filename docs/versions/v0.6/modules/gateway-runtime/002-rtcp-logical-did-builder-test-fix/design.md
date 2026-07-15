---
module: gateway-runtime
task_name: 002-rtcp-logical-did-builder-test-fix
submodule: 002-rtcp-logical-did-builder-test-fix
version: v0.6
status: approved
approved_by: user
approved_at: 2026-07-15T14:44:03+08:00
approved_content_sha256: b59d6714c3b19f042b6c2b34c78eb17bc75be94edf12fa4bfc22598ed11f8c1d
---

# RTCP Logical-DID Builder Test Fix Design

## Design Scope

### Goals
- Keep the production `RtcpStack` builder and its validation order unchanged.
- Align the stale in-file logical-DID test consumer with the builder's existing mandatory runtime dependency.
- Reuse the RTCP test module's established builder helper rather than introducing another runtime-construction path.

### Non-goals
- No production RTCP behavior, identity validation, builder API, configuration, or dependency change.
- No new abstraction or module boundary.

## Useful Context
`RtcpStack::create` rejects a builder without `server_runtime` before it evaluates logical-DID identity material. The same test module already owns `test_server_runtime()` and `rtcp_stack_builder()`, and the latter constructs an `RtcpStackBuilder` with that mandatory runtime populated. The affected test bypasses this established helper.

## Overall Approach
Keep the runtime builder contract intact and make the existing test-only consumer enter through `rtcp_stack_builder()`. All remaining explicit inputs continue to be supplied by the consumer, so the logical-DID validation remains the first intentionally unsatisfied contract in that construction path.

## Layered Design Document Index

| level | parent_document | unit | design_document | responsibility |
|-------|-----------------|------|-----------------|----------------|
| root | `design.md` | RTCP logical-DID builder test correction | `design.md` | Records the unchanged production boundary and the single-file testing-stage scope. |

No child design document is needed because the change has one existing file-level consumer and introduces no submodule or nested-module relationship.

## Module Relationship UML
not-applicable: the task changes no relationship between modules, submodules, or file-level production modules.

## File-Level Interfaces

The existing test-only helper remains the sole runtime-populated builder entry used by the affected consumer:

```rust
#[cfg(test)]
fn rtcp_stack_builder() -> RtcpStackBuilder;
```

- Consumer: the existing logical-DID builder regression consumer mapped by `P-rtcp-logical-did-builder-test-fix-1`.
- Compatibility: backward-compatible
- Scope note: test-only; no exported or production signature changes.

## API and Build Surface Impact
- Public API impact: none
- Crate-root export change: no
- Build-surface change: no
- Documentation examples affected: no

## Consumer Migration Closure
not-applicable: there is no breaking or migration-required API, crate-root export, or build-surface change.

## Key Flows
not-applicable: no production runtime or cross-boundary flow changes.

## State and Ownership
not-applicable: no persistent data or shared state changes.

## Directly Mapped Change Items

| change_id | target_module | proposal_id | Design Coverage | Scope Paths | Interface / Boundary Impact | Notes |
|-----------|---------------|-------------|-----------------|-------------|-----------------------------|-------|
| P-rtcp-logical-did-builder-test-fix-1 | gateway-runtime | RTCP-TEST-FIX-1 | `Overall Approach` and `File-Level Interfaces` preserve the builder contract while aligning its existing test consumer. | `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs` | None; existing `#[cfg(test)]` consumer only. | Production portions of the file remain out of scope. |

## Implementation Order

| Phase | Goal | Depends On | Output |
|-------|------|------------|--------|
| 1 | Hand the single-file, test-only scope to the testing stage; no production implementation is required. | Approved proposal and design | Testing-stage task scoped to the pre-existing inline test consumer. |

## File-Level Implementation Sequence

| sequence | file_level_module | action | depends_on | change_id | scope_path | implementation_task |
|----------|-------------------|--------|------------|-----------|------------|---------------------|
| 1 | `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs` | Modify only the pre-existing inline test consumer during the testing stage. | none | P-rtcp-logical-did-builder-test-fix-1 | `src/components/cyfs-gateway-lib/src/stack/rtcp_stack.rs` | T-rtcp-logical-did-builder-test-fix |

## Design Notes
- Rejected alternative: reordering production builder validation would change which invalid prerequisite is reported and would make runtime behavior serve an incomplete test fixture.
- No new abstraction is justified because `rtcp_stack_builder()` already owns the needed test-only construction pattern.
- Testing-stage details are intentionally omitted; testing owns case metadata, baseline capture, source modification, and execution evidence.

## Risks and Rollback
- Risk: editing a mixed production/test Rust file could accidentally widen the change. The testing-stage baseline gate must prove the edit stays inside the pre-existing `#[cfg(test)]` module.
- Rollback: restore the single test consumer call; no production or data migration rollback is needed.

## Approval Record
- approver: user
- approval_date: 2026-07-15T14:44:03+08:00
- user_statement: "确认，自动处理后续步骤"
