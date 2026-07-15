---
module: example-module
task_name: 001-example-task
submodule: 001-example-task
version: v0.6
status: draft
approved_by:
approved_at:
approved_content_sha256:
---

# [Module Name] Proposal

## Background and Goal
<!-- What problem is being solved and why now -->

## Scope
### In scope
### Out of scope
### Boundary with neighboring modules

## Requirement Review
<!-- Evaluate whether the requested outcome is reasonable, identify material tradeoffs, and record the chosen direction. -->

## Proposal Items
| proposal_id | change_id | requirement | boundary | tradeoff | success_evidence | non_goal |
|-------------|-----------|-------------|----------|----------|------------------|----------|
| P-001 | CHG-example | | | | | |

## Success Criteria
- Concrete user-visible or system-visible result:
- Required evidence:
- Explicit non-goals:

## Risks
<!-- High-risk changes, shared contracts, security or migration impact -->

## Approval Record
<!-- Fill only when the user explicitly approves this document. Agents MUST NOT fill this section or set `status: approved` on their own initiative. `approver` must match front matter `approved_by`; `user_statement` must quote the user's approval instruction verbatim. The same edit must record front matter `approved_content_sha256` from `schema-check.py --print-approval-hash <this-file>`; later content edits invalidate approval and require a sibling amendment/fix task. -->
- approver:
- approval_date:
- user_statement: ""
