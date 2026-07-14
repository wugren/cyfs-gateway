# Agent Guide (cyfs-gateway)

当前 Beta2.2 是 breaking-change 版本。

本仓库采用分层 Harness Engineering 结构。`AGENTS.md` 只做导航，不承载完整规则细节。

## 规则优先级
当规则冲突时按以下顺序解释，数字越小优先级越高：
1. 当前任务中的明确用户指令。用户指令可选择阶段、模式和范围，但不能绕过 approval provenance、implementation admission、stage scope、validation 和 acceptance review 等机械门禁。
2. `harness/rules/task-entry-gate-rules.md`：任务分类、准入和批准权限。
3. 当前阶段对应的 `harness/rules/*.md`。
4. `harness/custom-rules/` 下的项目自定义规则；custom rules 只能加严，不能放宽或绕过 generated gates。
5. 模块包文档和长期架构文档。

若按上述顺序仍存在真实矛盾，停止并向用户报告，不静默选择一边。

## 首次读取顺序
1. `harness/rules/task-entry-gate-rules.md`
2. `docs/architecture/repository-baseline.md`
3. `docs/architecture/module-map.md`
4. `docs/modules/<module>.md`
5. `docs/versions/v0.6/modules/<module>/proposal.md`
6. `docs/versions/v0.6/modules/<module>/design.md`
7. `docs/versions/v0.6/modules/<module>/testing.md`
8. `docs/versions/v0.6/modules/<module>/testplan.yaml`
9. `docs/versions/v0.6/modules/<module>/acceptance.md`
10. `harness/rules/*.md`
11. `harness/process_rules/*.md`

## 任务决策流
1. 用户是否明确指定 proposal / design / testing / implementation / acceptance 阶段？若是，只进入该阶段写入范围。
2. 请求是否增删、收窄、放宽或重分类需求、范围、非目标、支持/不支持行为或验收边界？若是，默认进入 proposal 阶段。
3. 请求是否会修改生产代码、构建、运行时资源或行为？若是，先定位 module packet，读取已批准的 `proposal.md` 和 `design.md`，创建 admission evidence，并通过 `schema-check.py` 与 `admission-check.py` 后再改代码。
4. 任何门禁失败时，返回最早缺失或未覆盖的文档阶段，不从聊天上下文直接实现。
5. 单阶段任务结束前运行 `stage-scope-check.py`，确认 diff 未越界。

| 阶段 | 写入范围 | 完成前检查 |
|------|----------|------------|
| Proposal | 当前 packet 的 `proposal.md` | `doc-structure-check.py --docs proposal`；`stage-scope-check.py --stage proposal --version <v> --module <m>` |
| Design | `design.md`、`design/`、必要的长期边界同步 | `doc-structure-check.py --docs design`；`stage-scope-check.py --stage design --version <v> --module <m>` |
| Implementation | 生产代码、必要非测试运行时/构建资源、当前任务 admission evidence | 修改前通过 `harness/scripts/schema-check.py` 与 `harness/scripts/admission-check.py --evidence-file ...`；修改后 `stage-scope-check.py --stage implementation --change-id <id>` |
| Testing | 测试代码、fixtures、runner、统一入口 wiring、testing artifacts | `doc-structure-check.py --docs testing`；`testing-coverage-check.py`；`test-run.py <module> all`；`stage-scope-check.py --stage testing` |
| Acceptance | review report 与验收证据 | 按 `acceptance-review-rules.md` 运行检查，引用 test/quality run artifacts，并用 `acceptance-report-check.py` 校验报告 |

## 仓库地图
- Rust 工作区：`src/`
- 主服务：`src/apps/cyfs_gateway/`
- 核心库：`src/components/cyfs-gateway-lib/`
- Web 控制台：`src/apps/cyfs_gateway/web/`
- 运行时配置：`src/rootfs/etc/`
- 历史资料：`doc/`
- 项目级基线：`docs/architecture/`
- 长期模块边界：`docs/modules/`
- 版本化模块包：`docs/versions/v0.6/modules/`
- 验收报告：`docs/versions/v0.6/reviews/`
- Durable harness 规则：`harness/rules/`
- 项目自定义规则：`harness/custom-rules/`
- 执行流程与任务模板：`harness/process_rules/`
- 人审与分级：`harness/human-rules/`、`harness/checklists/`

## 阶段职责
- Proposal：定义目标、范围、非目标和约束，输出 `proposal.md`
- Design：定义实现形态、子模块、接口和路径归属，输出 `design.md`
- Testing：在 implementation 后定义验证覆盖、补充测试实现、证据路径和 `testplan.yaml`
- Implementation：只修改生产代码与必要的非测试运行时/构建资源
- Acceptance：审计证据链并输出独立验收报告

## 阶段边界
- Implementation 开始前，`proposal.md`、`design.md` 必须存在且处于批准态。
- 批准态不是充分条件；implementation 必须确认已批准文档直接覆盖当前变更。
- 若当前变更无法映射到 proposal / design 的具体条目，必须回退到对应文档阶段补充；测试覆盖不足在 implementation 后回到 testing 阶段补充。
- 单阶段任务收尾前运行 `python3 ./harness/scripts/stage-scope-check.py --stage <stage>`，确认 diff 没有越过阶段边界。
- Acceptance 只写报告，不在原任务里修代码或补上游文档。

## 关键规则入口
- 任务入口规则：`harness/rules/task-entry-gate-rules.md`
- Proposal 规则：`harness/rules/proposal-doc-rules.md`
- Design 规则：`harness/rules/design-doc-rules.md`
- Rust Design 附加规则：`harness/rules/rust-design-doc-rules.md`
- Testing 规则：`harness/rules/testing-doc-rules.md`
- 模块包约束：`harness/rules/module-packet-rules.md`
- Implementation 准入：`harness/rules/implementation-admission-rules.md`
- Schema 校验：`harness/rules/schema-validation-rules.md`
- 验收规则：`harness/rules/acceptance-task-rules.md`
- 验收 Review Gate：`harness/rules/acceptance-review-rules.md`
- 触发式加严：`harness/rules/trigger-rules.md`
- 质量门规则：`harness/rules/quality-gate-rules.md`
- 配置模板同步：`harness/custom-rules/config-template-sync-rules.md`
- 禁止全局 Rust 格式化：`harness/custom-rules/no-global-cargo-fmt-rules.md`
- 任务后聚焦测试：`harness/custom-rules/focused-post-task-test-rules.md`
- 统一测试入口：`harness/rules/unified-test-entry-rules.md`
- Auto-pipeline：`harness/rules/auto-pipeline-rules.md`
- 模块交付循环：`harness/process_rules/module-delivery-loop.md`
- 全仓 harness 检查：`harness/scripts/check-all.py`

## 标准命令
- Rust 构建：`cd src && cargo build --verbose`
- Rust 全量测试：`cd src && cargo test -- --test-threads=1`
- Web 构建：`cd src/apps/cyfs_gateway/web && npm run build`
- 统一测试入口：
  - `python3 ./harness/scripts/test-run.py <module> unit`
  - `python3 ./harness/scripts/test-run.py <module> dv`
  - `python3 ./harness/scripts/test-run.py <module> integration`
  - `python3 ./harness/scripts/test-run.py <module> all`
  - `python3 ./harness/scripts/test-run.py all all`
  - `./test-run.sh all all`
  - `test-run.bat all all`
- 质量门：`python3 ./harness/scripts/quality-check.py`
- 全仓 Harness 检查：`python3 ./harness/scripts/check-all.py`

## 仓库约束
- 优先做小而局部的改动，不把 bugfix 和重构混在一起。
- Rust 测试默认使用单线程，尤其是涉及端口、共享状态或运行时启动时。
- agent 不执行全局 `cargo fmt`；详见 `harness/custom-rules/no-global-cargo-fmt-rules.md`。
- 任务完成后的验证默认只运行与本次修改直接相关的聚焦测试或检查；不要把全量测试作为普通任务收尾动作，详见 `harness/custom-rules/focused-post-task-test-rules.md`。
- 配置、控制平面、运行时组装、process-chain、SN/DNS/RTCP 和 UI 契约改动，先看 `trigger-rules.md` 再决定附加验证。
- `doc/` 是历史资料和参考资料层；harness 事实来源是 `docs/` 和 `harness/`。历史资料可作为输入引用，但不能单独作为 implementation admission 证据。
- `harness/rules/` 是 skill-managed generated rules；项目自定义规则只放在 `harness/custom-rules/`，刷新 harness 时不得修改 custom rules，除非用户明确要求。
- Auto-pipeline 规则默认存在但不自动启用；只有用户明确要求启用、启动、运行或进入 automatic pipeline 时才读取并执行。
