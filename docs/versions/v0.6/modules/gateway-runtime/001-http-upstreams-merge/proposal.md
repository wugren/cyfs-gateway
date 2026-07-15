---
module: gateway-runtime
task_name: 001-http-upstreams-merge
submodule: 001-http-upstreams-merge
version: v0.6
status: draft
approved_by:
approved_at:
approved_content_sha256:
---

# HTTP Named Upstreams Merge Proposal

## Background and Goal
The `origin/http_reuse` branch adds named HTTP upstreams and reusable upstream HTTP/1 connections, but conflicts with the performance branch's newer request-body, timeout, trusted-forwarding, and dependency behavior. Resolve the merge semantically so named pooling is added without discarding the current branch's runtime guarantees.

## Scope

### In scope
- Add named upstream configuration and allow `forward` to resolve configured names.
- Use `sfo-http-pool` fixed clients for optional HTTP/1 reuse over HTTP, HTTPS, and existing tunnel streams.
- Preserve current timeout, cancellation, trusted-source, compression, request-body, post-chain, URI, Host, TLS, and error-classification behavior where compatible.
- Preserve existing control-plane `add_router` virtual-host routing while ordinary proxy forwarding defaults Host to the upstream authority.
- Keep current RTCP protocol/cache code and current dependency versions when incoming changes are unrelated branch drift.

### Out of scope
- RTCP protocol, identity, DID cache, or wire-format redesign.
- HTTP/2 upstream pooling or a new active-connection limit.
- Formatting-only build-script changes.
- Changes to existing forward timeout defaults, trusted-upstream semantics, or persisted data.

### Boundary with neighboring modules
`gateway-runtime` owns named-upstream parsing, request normalization, pool construction, forwarding, and response lifecycle. `TunnelManager` remains the transport opener for non-HTTP URLs. RTCP stays behind that transport boundary, and common server configuration normalization owns trusted-certificate path resolution.

## Requirement Review
Taking either side's complete `http_server.rs` would lose behavior from the other branch. The selected direction integrates the incoming pool feature into the current implementation, keeps pool acquisition before request-body commitment, prevents hidden pool retries, holds response leases to EOS/drop, and treats `keepalive` as idle-cache capacity rather than active concurrency. The tradeoff is a larger semantic merge, mitigated by direct/pool parity tests and gateway integration evidence.

## Proposal Items
| proposal_id | change_id | requirement | boundary | tradeoff | success_evidence | non_goal |
|-------------|-----------|-------------|----------|----------|------------------|----------|
| HTTP-UPSTREAMS-1 | P-http-upstreams-1 | Named upstreams provide optional reusable HTTP/1 connections across HTTP, HTTPS, and tunnel transports while preserving current-branch forwarding and dynamic-router compatibility. | HTTP forwarding and generated router policy inside `gateway-runtime`; RTCP remains an unchanged transport dependency. | Semantic integration is more complex than choosing one side, but avoids runtime regressions. | Conflict-free admitted code, task-local compile closure, focused unit/integration tests, and acceptance audit of both behavior sets. | No RTCP redesign, HTTP/2 pooling, active-connection limit, persisted schema, or UI change. |

## Success Criteria
- Named upstream configuration and named `forward` tokens work with optional keepalive pooling.
- Direct and pooled paths share URI, Host, TLS, hop-by-hop filtering, timeout, cancellation, and error semantics.
- Generated `add_router` HTTP rules retain inbound virtual Host routing.
- `sfo-io = "0.1.18"` remains and `sfo-http-pool = "0.1.1"` is added without unrelated RTCP/build drift.
- All conflict markers are removed and task-local compile/test evidence passes.
- Explicit non-goals: no RTCP protocol/cache change, no HTTP/2 pool, no persisted-data or UI change.

## Risks
- Body adaptation could accidentally impose `Send + Sync` on local-task bodies.
- Acquisition/send ordering could consume an unbuffered body before retry eligibility is known.
- Pool leases could be reused after errors or dropped too early.
- TLS identity, proxy Host defaults, or generated-router Host policy could create compatibility or trust-boundary regressions.

## Approval Record
- approver:
- approval_date:
- user_statement: ""
