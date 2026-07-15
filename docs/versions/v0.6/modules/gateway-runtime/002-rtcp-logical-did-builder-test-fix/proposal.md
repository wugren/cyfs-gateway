---
module: gateway-runtime
task_name: 002-rtcp-logical-did-builder-test-fix
submodule: 002-rtcp-logical-did-builder-test-fix
version: v0.6
status: approved
approved_by: user
approved_at: 2026-07-15T14:19:15+08:00
approved_content_sha256: 208f6fde20601eaae360bca2ff9a11b0cd8e7fd2a8695413e11e5fcf8fa87f6c
---

# RTCP Logical-DID Builder Test Fix Proposal

## Background and Goal
`test_rtcp_stack_builder_requires_device_doc_jwt_for_logical_did` is intended to verify that an RTCP stack using a logical DID is rejected when `device_doc_jwt` is absent. The builder now validates the mandatory `server_runtime` dependency first, while this test fixture does not provide one, so the test fails on an unrelated prerequisite and never reaches the logical-DID assertion. Restore the focused regression test without changing production validation semantics.

## Scope

### In scope
- Update the existing RTCP builder test fixture to provide the mandatory server runtime dependency.
- Preserve the assertion that a logical DID without `device_doc_jwt` is rejected specifically for the missing device document JWT.
- Run the task-scoped gateway-runtime test entry required by the Harness testing stage.

### Out of scope
- Reordering or relaxing production `RtcpStack` builder validation.
- Changing RTCP identity, logical-DID, JWT verification, network, or runtime behavior.
- Adding new configuration fields, fixtures, APIs, or unrelated RTCP tests.

### Boundary with neighboring modules
The change is confined to the existing inline RTCP unit test in `gateway-runtime`. Production RTCP behavior and neighboring configuration, process-chain, certificate, and transport modules remain unchanged.

## Requirement Review
The requested fix is reasonable because the failing test fixture is stale relative to a mandatory builder dependency. Supplying that dependency keeps the test focused on its named logical-DID contract. Reordering production validation merely to satisfy the test would make error precedence depend on an incomplete fixture and would change runtime behavior unnecessarily. The selected direction is therefore a test-only fixture correction, with the production builder left intact.

## Proposal Items
| proposal_id | change_id | requirement | boundary | tradeoff | success_evidence | non_goal |
|-------------|-----------|-------------|----------|----------|------------------|----------|
| RTCP-TEST-FIX-1 | P-rtcp-logical-did-builder-test-fix-1 | The logical-DID builder regression test supplies all unrelated mandatory prerequisites and reaches the existing `device_doc_jwt` validation. | Existing inline unit test in `gateway-runtime` only. | The test depends on the production runtime-construction helper, but this accurately models the builder's required inputs. | The focused assertion reports a missing `device_doc_jwt`, and the task-scoped unified test run passes. | No production validation-order, RTCP identity, JWT, configuration, or API change. |

## Success Criteria
- The named failing test reaches the logical-DID validation instead of failing with `server_runtime is required`.
- The test continues to assert that the returned error identifies `device_doc_jwt`.
- Required task-scoped test and Harness scope evidence pass.
- Explicit non-goals: no production code, runtime behavior, configuration contract, or unrelated test changes.

## Risks
- A poorly constructed runtime fixture could start background work or bind a fixed port; use the existing lightweight test runtime pattern and keep the builder bind address ephemeral.
- Test-only scope must not be widened into a production validation-order change.

## Approval Record
- approver: user
- approval_date: 2026-07-15T14:19:15+08:00
- user_statement: "确认，自从处理后续步骤"
