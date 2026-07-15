# 模块交付循环

## 目标

- 在 task packet 与阶段门禁齐备后，为模块级工作提供稳定、可复用的交付回路。
- Manual flow 与 explicitly launched auto-pipeline 使用不同 active design source，但共享 admission、scope、validation 与 acceptance 约束。

## 执行前置检查

1. 读取 `harness/rules/task-entry-gate-rules.md`。
2. 读取 `docs/versions/<version>/modules/tasks.md` 并定位用户或 module Current/Active Task 明确指向的序号化 packet。
3. 读取 task proposal；manual flow 读取 task `design.md`，auto-pipeline 读取 task-local `pipeline/plan.md`。
4. 读取 `docs/modules/<module>.md`、相关 `docs/architecture/` 与匹配的 custom rules。
5. 确认当前阶段、唯一写入范围、`change_id` 与完成信号。
6. 只有用户显式要求 enable / launch / run / enter auto-pipeline 时才进入自动模式。

## 循环步骤

1. 根据当前阶段确认输入、owner、exclusive scope 与 done condition。
2. Proposal/design 文档任务默认交付 draft，agent 不自批。
3. Implementation 开始前复用或取得当前 schema/admission pass；未覆盖时返回 proposal/design。
4. 只修改当前阶段允许的工件：
   - proposal：当前 task `proposal.md` 与 unfinished index bookkeeping
   - design：manual design artifacts，或 auto-pipeline parent-owned plan/state mappings
   - implementation：生产代码与必要非测试资源
   - testing：implementation 后的测试、fixtures、runner、task testplan 与 run artifact
   - acceptance：task packet review report 与允许的状态记录
5. 当前任务用显式 `.paths` manifest 与 sidecar 运行 stage scope；无关 working-tree 变更不进入该清单。
6. checker-owned inputs 未变化时复用已有结果，不因阶段切换、commit、CI 或 report 重跑。
7. 当前阶段内的问题继续修复；上游问题按 owning stage 返回，不跨阶段顺手修改。
8. Testing 完成后只通过 `<module>/<task-name> all` 产生 task evidence。
9. Acceptance 独立审计 proposal/design/code/tests/results 与实现正确性，失败时返回对应 stage。
10. 完成 task 后从 `docs/versions/<version>/modules/tasks.md` 移除记录。

## 仓库特定说明

- Rust 测试默认单线程；端口敏感场景优先动态端口。
- 配置契约变化同时应用 `harness/custom-rules/config-template-sync-rules.md`。
- agent 不运行全局 `cargo fmt`。
- Module suites、`all all`、root shortcuts 与 quality gates 仅在用户明确发起 maintenance 时运行。
- 现有未序号化 packet 是 legacy input，不作为新 task admission 入口。
