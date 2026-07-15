# Manual Module Stage Task

## Task Identity

- Task ID: `<task-seq>-<task-slug>`
- Version:
- Project module:
- Packet path:
- Stage: proposal / design / implementation / testing / acceptance
- Stage responsibility:
- Owner:
- Depends on:
- change_id values:
- Exclusive write scope:

## Goal

- 描述本阶段必须交付的唯一结果与可观察完成信号。

## Inputs

- Task proposal:
- Active design source:
- Existing stage artifacts:
- Long-lived module / architecture docs:
- Matching custom rules:

## Entry Checks

- [ ] 当前 task 由用户、module Current/Active Task 或唯一 confirmed unfinished record 明确指向
- [ ] Packet 名称与目录是 `<task-seq>-<task-slug>`
- [ ] 当前阶段写入范围明确，未把其他阶段默认并入
- [ ] Approved packet 没有被当作新需求或修正的可编辑容器
- [ ] Implementation：version、packet module、target module 与 `change_id` 明确
- [ ] Implementation：proposal 与 design 已读且直接覆盖请求
- [ ] Implementation：current schema result 与 admission stamp 存在
- [ ] Testing：production implementation 已完成；测试现在才从 proposal/design/code 推导
- [ ] Acceptance：task test evidence 或 structured automated-test exception 已存在

## Scope

- Can modify:
- Must not modify:
- Current-task `.paths` manifest:
- `.paths.meta.json` sidecar:
- Optional Rust baseline manifest:

Stage defaults:

- Proposal：只写 task `proposal.md` 与 unfinished index bookkeeping。
- Design：只写 task `design.md` / `design/` 与规则要求的长期边界同步；不设计测试。
- Implementation：只写生产代码、必要非测试资源与 admission evidence。
- Testing：只写测试、fixtures、runner、task `testplan.yaml`、可选 testing docs 与 run artifacts；不改生产行为。
- Acceptance：只审计并写 task `acceptance-report.md` / 可选 guidance，不原地修复上游。

## Required Outputs

- Output:
- Evidence:
- Follow-up / return route:

## Done Conditions

- [ ] Required output exists
- [ ] Current-stage structure/coverage checker passed when applicable
- [ ] Task manifest stage-scope check passed
- [ ] Testing：所有新/改测试通过 `harness/scripts/test-run.py <module>/<task-name> all` 可达
- [ ] Acceptance：test design adequacy 与 implementation correctness categories 已审计
- [ ] Checker results were reused unless their owned inputs changed
- [ ] No unrelated user worktree changes were modified

## Failure Routing

- Proposal ambiguity/incorrect boundary：stop and ask user
- Missing proposal mapping：return proposal
- Missing design/interface/state/Scope Path：return design
- Code defect against adequate design：return implementation
- Missing/unreasonable/non-runnable validation：return testing
- Acceptance finding：record issue id, owning stage, expected fix output, and iteration count
