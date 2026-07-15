# Acceptance Return Task

> Do not instantiate this task for a proposal ambiguity, contradiction, or incorrect requirement/acceptance boundary. Stop acceptance and ask the user to decide instead.

## Task Identity
- Task ID:
- Triggered By Acceptance Report:
- Return Stage:
- Return Stage Responsibility:
- Return Target Task:
- Owner:

## Reason For Return
- Blocking issue id:
- Why acceptance failed:
- If returning because project-rule-governed architecture docs are inconsistent, list the code path and `docs/architecture/` path that disagree:
- Why this stage owns the fix:
- Correctness category: logic/control flow / termination/progress / concurrency/synchronization / resource lifetime/cleanup / state/data integrity / error handling/recovery / interface boundary/compatibility / security/capacity safety / test evidence
- If returning to testing, list the missing or unreasonable case types: normal / boundary / negative / error / compatibility / lifecycle / cross-module

## Required Fix Output
- Output 1:
- Output 2:
- For testing returns: supplemented test design, test implementation, metadata if used, and unified-entrypoint runnable evidence

## Evidence To Re-Attach
- Updated docs or code:
- Updated tests or results:
- Iteration count for this issue:
- Notes for re-running acceptance:

## Done Condition
- [ ] The acceptance-blocking issue is addressed inside this stage boundary
- [ ] Evidence is attached for the next acceptance run
- [ ] No unrelated stage work was bundled into this return task
- [ ] If this issue has already survived more than 5 unsuccessful iterations, stop and report it to the user instead of opening another return task
