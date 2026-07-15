# HTTP Upstreams Merge Acceptance Report

## Findings
| ID | Severity | Stage | Evidence | Problem | Fail Condition Hit |
|----|----------|-------|----------|---------|--------------------|
| F-000 | none | acceptance | proposal, pipeline plan, admitted implementation, task-local test artifact, and correctness audit | No blocking finding remains after the Host compatibility return and Testing-only fixture repair. | |

## Result Summary
- Overall result: accepted
- Plain-language outcome: The merge conflicts are semantically resolved; named HTTP upstream pooling is retained together with the performance branch's timeout, body, trusted-source, cancellation, and dynamic-router behavior.
- What was verified: Dependency selection, named token parsing, path normalization, Host policy, direct/pool parity, acquisition and lease lifecycle, error mapping, generated-router compatibility, RTCP/build exclusions, and task-scoped runnable evidence.
- Evidence used: Launch-confirmed proposal, task-local pipeline plan/state, admission stamp, four stage-scope manifests, relevant code and tests, and `test-results/test-runs/20260715T043629Z-gateway-runtime+001-http-upstreams-merge-all.json`.
- Blocking issues: No unresolved blocking issue; HOST-1 was corrected and its regression now passes.
- Next action: Stage the resolved merge and task evidence; no additional implementation or testing return is required.

## Object and Scope
- Module: gateway-runtime
- Version: v0.6
- Task name: 001-http-upstreams-merge
- change_id values reviewed: P-http-upstreams-1
- Review date: 2026-07-15
- In scope: Six admitted production paths, named HTTP upstream configuration and execution, fixed-client HTTP/1 pooling, TLS/URI/Host/header semantics, timeout/cancellation/error behavior, generated-router Host compatibility, and task test evidence.
- Out of scope: RTCP protocol/cache changes, HTTP/2 pooling, active-connection limiting, persisted schema, UI behavior, and unrelated Harness/worktree changes.
- Task-relevant acceptance scope: `docs/versions/v0.6/modules/gateway-runtime/001-http-upstreams-merge/`, admitted production paths, `tests/integration/cyfs_gateway_app/run.py`, and the bound task artifact.
- Out-of-scope checks not run: No extra quality gates, unrelated module suites, migration scans, or architecture audits were selected by this single-task acceptance.

## Optional Diff / Status Evidence
- `git status --short` summary: The workspace contains this merge plus unrelated pre-existing Harness edits; task scope is established by the packet, admission stamp, and stage manifests.
- `git diff --stat` summary: Used only to locate the six admitted implementation paths and the Testing-only fixture repair.
- `git diff --name-status` summary: Confirmed task files are distinguishable from unrelated worktree churn.
- `git diff --check` result: Passed with no whitespace errors.
- Note: Diff/status output was used only as discovery evidence.

## Evidence Coverage
| Documented Item | Source Document | Implementation Evidence | Test / Result Evidence | Status |
|-----------------|-----------------|-------------------------|------------------------|--------|
| Named upstream configuration, named tokens, and optional fixed-client reuse | `proposal.md` HTTP-UPSTREAMS-1; plan exported interfaces and scope binding | `Cargo.toml`, `cmds/forward.rs`, `server/http_server.rs` | compile closure, `http-upstreams-unit`, and `named-forward-token` in the task artifact | implemented |
| Preserve current body, timeout, cancellation, trusted-source, compression, post-chain, and error behavior | proposal scope/success criteria; plan failure flows and state ownership | shared normalization and timeout/abort wrappers in `server/http_server.rs` | 101 HTTP server regressions in `http-upstreams-unit` | implemented |
| Proxy TLS, URI, Host precedence, and hop-by-hop filtering parity | proposal success criteria; plan request-normalization interface | `server/mod.rs`, `server/server.rs`, `server/http_server.rs` | positive, boundary, negative, error, TLS, URI, Host, and filtering cases in the task artifact | implemented |
| Preserve dynamic virtual-host routes under the new proxy Host default | proposal scope; plan `control_router_compat` mapping and HOST-1 return | explicit `REQ.host` self-assignment in `src/apps/cyfs_gateway/src/gateway.rs` | `dynamic-router-host` and `gateway-routing-integration` both pass | implemented |
| Keep current dependency and exclude unrelated RTCP/build drift | proposal non-goals; plan boundary decision and exact Scope Paths | `sfo-io 0.1.18`, `sfo-http-pool 0.1.1`, and no admitted RTCP/build-script path | repository compile closure and scope manifests pass | implemented |

## Test Design Adequacy
| Behavior / Risk / change_id | Required Case Types | Test Design Evidence | Runnable Test Evidence | Status |
|-----------------------------|---------------------|----------------------|------------------------|--------|
| `P-http-upstreams-1`: config/token domains, direct/pool control flow, TLS/URI/Host boundaries, connector/send/body errors, pool lifecycle, current compatibility, and cross-module routing | normal, boundary, negative, error, compatibility, lifecycle, cross-module | `pipeline/state.json` case-type coverage; task `testplan.yaml` unit/integration steps and build-surface contract check | six successful task steps in `test-results/test-runs/20260715T043629Z-gateway-runtime+001-http-upstreams-merge-all.json` | adequate |

## Implementation Correctness Audit
| Category | Applicable Scope | Evidence Reviewed | Finding / Reason Not Applicable | Owning Stage | Status |
|----------|------------------|-------------------|---------------------------------|--------------|--------|
| logic and control flow | name resolution, target selection, URI/Host normalization, direct/pool dispatch, and generated rules | admitted code, plan flows, 101 unit cases, router unit and integration | Acquisition precedes body commitment, explicit Host policy wins, and no incorrect branch or fallback selection remains. | none | pass |
| termination and progress | DNS candidate iteration, connection acquisition, request/response timeouts, and application test polling | bounded loops and configured timeout wrappers in code plus task execution | Candidate loops are finite; waits are timeout/cancellation bounded; no hot spin, unbounded retry, or progress defect was found. | none | pass |
| concurrency and synchronization | shared pool clients, local-task bodies, connection tasks, cancellation, and request-local streams | `Arc<PooledHttpClient>` ownership, `UnsyncBoxBody` boundary, pool tests, cancellation tests | Pool synchronization remains library-owned; no gateway lock crosses network awaits, and local non-Send task semantics are preserved. | none | pass |
| resource lifetime and cleanup | pooled leases, direct abort handles, response bodies, server replacement, sockets, and process fixtures | body lease/drop paths, abort-on-drop code, early-drop/EOS tests, process cleanup | Leases survive to EOS, errors/early drops evict, direct tasks retain abort ownership, and test services/processes clean up on success/failure. | none | pass |
| state and data integrity | immutable upstream map, connection reuse state, Host marker, tunnel history, and reload ownership | plan state table, builder/runtime code, reuse/history tests | State has one recorded owner; pooled code does not duplicate tunnel history or persist new schema, and reload drops old pool owners. | none | pass |
| error handling and recovery | invalid config, connect/TLS/handshake/acquire/send/body failures, timeouts, and stale connections | plan failure flows, canonical error-source mapping, negative/error tests | Pre-commit failures remain eligible for existing fallback; committed bodies are not silently replayed; stale/error connections are evicted. | none | pass |
| interface boundary and compatibility | config fields, named forward tokens, Host/URI/TLS contract, TunnelManager boundary, and generated routers | proposal/plan interfaces, exact Scope Paths, task compile/unit/integration evidence | New fields/tokens are backward-compatible, RTCP stays behind TunnelManager, and HOST-1 compatibility is explicitly restored. | none | pass |
| security and capacity safety | TLS trust/name/depth, forwarded Host, hop-by-hop headers, idle cache and active concurrency | TLS/filter tests, Host marker logic, fixed-client builder limits and plan decisions | TLS identity uses upstream host, trust failures reject config/requests, hop-by-hop headers are stripped, and idle capacity is not misused as an active limit. | none | pass |

## Generated Acceptance Rules
| Rule ID | Source | Expected Result | Evidence Required | Status |
|---------|--------|-----------------|-------------------|--------|
| AR-1 | proposal HTTP-UPSTREAMS-1 | Named tokens resolve to configured upstreams and optional HTTP/1 pool clients. | admitted code, compile closure, named-token and HTTP unit steps | pass |
| AR-2 | proposal preservation criteria; plan failure/state mappings | Pooling does not bypass current body, timeout, cancellation, trusted-source, post-chain, or error semantics. | 101 branch/error/lifecycle regressions plus code audit | pass |
| AR-3 | proposal TLS/URI/Host criteria | Direct and pooled requests share NGINX-like URI, proxy Host, TLS, and hop-by-hop filtering policy. | boundary/negative/TLS/Host/filter cases in task artifact | pass |
| AR-4 | HOST-1 return and plan compatibility interface | Generated dynamic routes retain inbound virtual Host while ordinary forwards use upstream authority. | router unit and gateway integration task steps | pass |
| AR-5 | proposal exclusions and dependency constraint | Current I/O dependency remains, pool dependency is added, and RTCP/build drift is absent. | implementation scope binding, stage-scope result, compile closure | pass |

## Inputs
- `proposal.md` in the active task packet
- task-local `pipeline/plan.md` and `pipeline/state.json`
- `testplan.yaml`
- admission evidence and stamp
- admitted implementation and test fixture
- task-local machine-written test result
- `docs/modules/gateway-runtime.md` and repository architecture boundary docs used during task entry
- `harness/rules/acceptance-review-rules.md`

## Review Order
1. Bound the task to `P-http-upstreams-1` and the launch-confirmed proposal.
2. Compared pipeline design mappings to proposal boundaries and non-goals.
3. Compared all six admitted implementation paths to the scope binding and failure/state/interface model.
4. Audited unit/integration/contract coverage and the task artifact.
5. Completed all eight implementation correctness categories.
6. Generated acceptance rules and reached the accepted conclusion.

## Consistency Summary
- Proposal authority check: The launch-confirmed proposal remains the authority; the plan, implementation, and tests preserve its scope, exclusions, and success criteria.
- Proposal vs design: Pipeline mappings cover named config, normalization, pool transport, generated-router compatibility, dependency direction, state ownership, failure flows, alternatives, and all exact paths without widening RTCP/build scope.
- Design vs testing implementation: The task plan exercises the mapped parameter, failure, lifecycle, compatibility, cross-module, and build-surface risks; the unrelated SN/BNS fixture repair only restores runner reachability.
- Design vs long-lived boundary doc: `gateway-runtime` continues to own HTTP server/runtime assembly while TunnelManager remains the non-HTTP transport boundary.
- Design vs implementation: All six code paths match the plan binding; pool ownership, acquire-before-consume, Host marker, timeout/error, and router compatibility decisions are present.
- Test implementation vs test code vs results: Testplan step ids map to executed commands and all six artifact steps succeeded with non-empty sources.
- Test design adequacy: Normal, boundary, negative, error, compatibility, lifecycle, and cross-module coverage is concrete and placed at unit/integration levels; DV is explicitly inapplicable because no intermediate executable boundary exists.
- change_id traceability: `P-http-upstreams-1` appears in proposal, plan scope binding, admission stamp, state coverage, every task test step, run artifact, and this report.
- Acceptance criteria traceability: AR-1 through AR-5 map every proposal success criterion and exclusion to implementation and runnable evidence.
- Cross-module admission: One concrete target module is admitted; gateway application integration consumes the same `gateway-runtime` behavior and introduces no second implementation module.
- Public API / codec / runtime semantics review: The config/token additions are backward-compatible; build-surface impact has a successful repository compile closure; no codec or wire-format change exists.
- Document logic review: No contradiction, impossible requirement, hidden scope expansion, or stale approval claim remains in the new auto-pipeline packet.
- Implementation logic review: Manual control-flow and failure-path review found no remaining correctness, retry, timeout, lease, Host, or tunnel-history defect.
- Implementation correctness audit completeness and routing: All eight required categories are present and pass; HOST-1 was routed through design/implementation/testing before this second acceptance run.
- Document approval timing (approved_content_sha256 verified by schema-check): Auto-pipeline uses a launch-confirmed draft proposal plus plan binding under the new no-design/testing-doc policy; schema passed for current packet inputs.
- Implementation task paths bound to design Scope Paths (`stage-scope-check.py --stage implementation --change-id ... --changed-paths-file ...`): Passed for the six production paths and version-local admission/stage evidence.
- Bugfix red-green regression evidence, when the reviewed work contains a bugfix: The pre-fix whole-project run returned HTTP 500 because the generated router lost the inbound virtual Host; that run used the superseded repository-wide evidence location and is intentionally not retained as final task evidence. The scoped task artifact supplies the green half by passing both the router Host unit assertion and gateway integration step after the preservation fix.

## Validation Evidence
- Existing schema result: `schema-check.py --version v0.6 --module gateway-runtime --submodule 001-http-upstreams-merge` passed after task-packet migration.
- Existing admission stamp: `docs/versions/v0.6/evidence/admission/20260714-http-upstreams-merge.gateway-runtime.001-http-upstreams-merge.stamp.json` is current and passed for target `gateway-runtime` and `P-http-upstreams-1`.
- Existing stage-scope result: Proposal, Design, Implementation, and Testing manifests under `docs/versions/v0.6/evidence/stage-scope/` passed; Testing passed again after adding the task artifact.
- Existing pipeline-plan result, when applicable: task-local plan/state check passed for the current hash and execution state.
- Task-relevant test run artifact: `test-results/test-runs/20260715T043629Z-gateway-runtime+001-http-upstreams-merge-all.json` passed all six executed steps for `gateway-runtime/001-http-upstreams-merge all`.
- Commands rerun because checker-owned inputs changed: Schema, plan, admission, stage-scope, testing coverage, and task tests were rerun only after the Harness migration or their owned packet/state/manifest/test inputs changed.
- Direct package/module runtime suites, whole-project suites, and root shortcuts: Not used as final single-task acceptance evidence; earlier user-authorized maintenance runs are supplementary only.
- Risk-triggered task-local contract kinds and assertions, when applicable: `repository-compile-closure` / `repository-consumers-compile` passed inside the task artifact.
- Scoped evidence input hash current, when risk-triggered: `b262b1b4a4c38a33451012d5ffccf433a31a735cb6bd92873e55de3fe36ae6b0` matches the current testplan and seven evidence-input roots.
- Quality gates: Not required; the current single-task rules do not select them and the user did not explicitly request a quality run.
- Explicitly requested quality run artifact, if any: No explicit quality run was requested under the current task packet.
- Architecture doc check, only when `docs/architecture/` evidence is relevant: Not required because no architecture document is changed and the existing gateway/TunnelManager boundary is preserved.
- Acceptance report check after this report was created or modified: Passed with `acceptance-report-check.py` after the final report update.
- Targeted migration search, only when applicable to the reviewed task: Not required because no symbol is removed and public compatibility is backward-compatible.

## Automated Test Exception
- Applies: no
- Reason: A passing automated task artifact exists and includes all required contract, unit, and integration steps.
- Owner: gateway-runtime task pipeline
- Risk: No automated-test exception risk is accepted.
- Acceptance impact: Automated evidence fully supports acceptance.
- Alternative evidence: The admission, scope, and manual correctness audits supplement the task artifact.

## Conclusion
- Accepted / rejected / needs changes: accepted
- Reason: The launch-confirmed proposal is fully implemented within admitted scope, task-level build/test evidence passes, and the document, design, test, and eight-category correctness audits found no blocking mismatch or defect.
- Supporting task-relevant test evidence: `test-results/test-runs/20260715T043629Z-gateway-runtime+001-http-upstreams-merge-all.json`
- Residual risk: External production networks may expose upstream-specific latency or certificate-chain behavior beyond loopback fixtures, but configured timeout, verification, eviction, and error paths are directly covered and no acceptance blocker is inferred.

## Follow-Up Tasks
- Requirement task: No new requirement task is required.
- User decision required for proposal issue: No proposal issue requires a user decision.
- Design task: No design return remains.
- Implementation task: No implementation return remains.
- Testing task: No testing return remains.
- Testing return reason if coverage is incomplete: Coverage is complete for the accepted task boundary.
- Iteration count: 2
- Stop reason if more than 5 unsuccessful iterations: The limit was not reached.
