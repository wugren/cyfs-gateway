# Agent Guide (cyfs-gateway)

当前 Beta2.2 是 breaking-change 版本。本仓库采用分层 Harness Engineering；本文件只做导航，详细约束位于 `harness/` 与 `docs/`。

## Harness 规则启用

- `harness/` 下的规则默认全部生效。
- 当前用户可以明确要求对其点名的范围跳过全部 Harness 规则；若未点名范围，只对当前任务生效。
- 该 opt-out 必须在其他 Harness 规则前判断，不能从“尽快处理”、一般性继续请求、沉默或紧急程度推断。
- 跳过 Harness 规则不覆盖 system/developer 指令、安全要求、用户仍保留的范围约束或非 Harness 仓库约束。

## 规则优先级

发生冲突时按以下顺序解释，数字越小优先级越高：

1. 当前任务中的明确用户指令；除非用户明确启用上述全规则 opt-out，否则用户指令只选择阶段、模式与范围，不能绕过机械门禁。
2. 仅在用户明确启动 auto-pipeline 时，`harness/rules/auto-pipeline-rules.md` 对“不生成 `design.md` / `testing.md`、改用 task-local pipeline plan/state”具有窄范围优先级；其他门禁不放宽。
3. `harness/rules/task-entry-gate-rules.md`：任务分类、准入、批准权限与 task packet 选择。
4. 当前阶段对应的 `harness/rules/*.md`。
5. `harness/custom-rules/` 下的项目自定义规则；custom rules 只能加严，不能放宽 generated gates。
6. 当前 task packet、长期模块文档与架构文档。

若仍存在真实矛盾，停止并报告，不静默选择一边。

## 首次读取顺序

1. `AGENTS.md`
2. `harness/rules/task-entry-gate-rules.md`
3. `docs/versions/<version>/modules/tasks.md`
4. 当前 task packet：
   - 单项目：`docs/versions/<version>/modules/<project>/<task-seq>-<task-slug>/`
   - 跨项目：`docs/versions/<version>/modules/globals/<task-seq>-<task-slug>/`
5. `docs/modules/<module>.md`
6. 与任务相关的 `docs/architecture/` 文档
7. 当前阶段的 `harness/rules/*.md`
8. 匹配任务的 `harness/custom-rules/*.md` 与 `harness/process_rules/*.md`

不要因为规则文件存在就进入 auto-pipeline；只有用户明确要求 enable / launch / run / enter automatic pipeline 时才读取并执行其模式规则。

## 任务决策流

1. 用户是否明确指定 proposal / design / testing / acceptance 阶段？若是，只进入该阶段写入范围。
2. 请求是否增删、收窄、放宽或重分类需求、范围、非目标、支持/不支持行为或验收边界？若是，默认进入 proposal。
3. 新需求、新 API、新 `change_id`、范围扩展或已批准内容修正是否针对 approved packet？若是，新建序号化 sibling task；修正使用 amendment/fix task，不能改写 approved packet。
4. 请求是否会改生产代码、构建或运行时资源？若是，先定位 packet，读取 proposal 与 active design source，创建 admission evidence，并通过 schema/admission gate。
5. 任何门禁失败时，返回最早缺失或未覆盖的文档阶段，不从聊天、旧实现或模块概览直接实现。
6. 单阶段任务用当前任务专属的 `.paths` 清单与 sidecar 运行 stage-scope；无关 dirty-worktree 路径不属于该任务清单。
7. checker 的输入未变化时复用最近通过结果；阶段切换、acceptance、commit、CI 或报告生成本身不触发重跑。

| 阶段 | 职责与写入范围 | 完成前检查 |
|------|----------------|------------|
| Proposal | 把用户意图变成可批准的目标、范围、非目标、约束与成功标准；只写当前 packet 的 `proposal.md` 和 unfinished-task 索引 | `doc-structure-check.py --docs proposal`；task-manifest `stage-scope-check.py --stage proposal` |
| Design | 把 proposal 变成可实现的模块关系、接口、状态所有权、流程、Scope Paths 与文件级顺序；manual flow 写 `design.md` / `design/` | manual flow 运行 `doc-structure-check.py --docs design`；task-manifest stage scope |
| Implementation | 交付满足批准输入的最小生产代码与必要非测试运行时/构建资源 | 修改前通过 `schema-check.py`、`admission-check.py --evidence-file ...`；修改后按 `change_id` 与 Scope Paths 运行 stage scope |
| Testing | implementation 后从 proposal、design 与代码设计用例并实现测试；写测试、fixtures、runner、task `testplan.yaml` 与 task run artifact | 可选 `testing.md` 存在时运行 doc structure；运行 `testing-coverage-check.py`、`test-run.py <module>/<task-name> all`、task-manifest stage scope |
| Acceptance | 定义当前验收范围，审计文档、代码、测试设计、结果与实现正确性；只写 task packet 的 review report/必要状态 | 复用已有 task evidence；运行 `acceptance-report-check.py <report>` |

## Task Packet 与证据

- 新 task 名称必须是版本内序号化的 `<task-seq>-<task-slug>`；创建前运行：
  `UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/task-seq.py next --version <version> --slug <task-slug>`
- `docs/versions/<version>/modules/tasks.md` 只记录未完成 task；序号仅表示创建顺序，不表示 current/latest。
- current/latest 只能来自当前用户明确指向，或 `docs/modules/<module>.md` 的 Current/Active Task。
- task packet checker 使用 `--submodule <task-seq>-<task-slug>`。
- implementation admission evidence 位于 `docs/versions/<version>/evidence/admission/<YYYYMMDD>-<task-slug>.md`。
- stage scope 清单位于 `docs/versions/<version>/evidence/stage-scope/<task-id>.paths`，并带 `.paths.meta.json` sidecar。
- Rust testing 若改已有 `#[cfg(test)]` item，修改前用 `baseline-snapshot.py` 将文件保存到 git-ignored `.harness/baselines/<task-id>/`；禁止用临时 Git index/tree/commit 伪造 baseline。
- agent 不得自行把阶段文档设为 approved。用户批准必须记录 `## Approval Record` 与内容哈希；auto-pipeline 批准必须绑定用户逐字 launch 证据。

## 仓库地图

- Rust 工作区：`src/`
- 主服务：`src/apps/cyfs_gateway/`
- 核心库：`src/components/cyfs-gateway-lib/`
- Web 控制台：`src/apps/cyfs_gateway/web/`
- 运行时配置：`src/rootfs/etc/`
- 历史资料：`doc/`
- 项目级架构：`docs/architecture/`
- 长期模块边界：`docs/modules/`
- 版本化 task packets：`docs/versions/v0.6/modules/`
- Durable generated rules：`harness/rules/`
- 用户自定义规则：`harness/custom-rules/`
- 流程与任务模板：`harness/process_rules/`
- 统一检查器：`harness/scripts/`
- 本地 Harness 状态：`.harness/`（git ignored）
- 测试与质量 run artifacts：`test-results/`（git ignored）

## 关键入口

- 任务入口：`harness/rules/task-entry-gate-rules.md`
- Proposal：`harness/rules/proposal-doc-rules.md`
- Design：`harness/rules/design-doc-rules.md`
- Testing：`harness/rules/testing-doc-rules.md`、`harness/rules/test-design-rules.md`
- Implementation admission：`harness/rules/implementation-admission-rules.md`
- Schema：`harness/rules/schema-validation-rules.md`
- Acceptance：`harness/rules/acceptance-task-rules.md`、`harness/rules/acceptance-review-rules.md`
- 统一测试：`harness/rules/unified-test-entry-rules.md`
- 触发式加严：`harness/rules/trigger-rules.md`
- 质量门：`harness/rules/quality-gate-rules.md`
- Schema checker：`harness/scripts/schema-check.py`
- Admission checker：`harness/scripts/admission-check.py`
- Stage-scope checker：`harness/scripts/stage-scope-check.py`
- 全仓 scaffold 审计：`UV_CACHE_DIR=.harness/uv-cache uv run --active python ./harness/scripts/check-all.py`

## 仓库约束

- 优先小而局部的改动，不把 bugfix 与重构混在一起。
- Rust 测试默认单线程，尤其涉及端口、共享状态或运行时启动时。
- agent 不自动运行全局 `cargo fmt`；遵循 `harness/custom-rules/no-global-cargo-fmt-rules.md`。
- 配置契约变更遵循 `harness/custom-rules/config-template-sync-rules.md`。
- `harness/rules/` 是 skill-managed generated rules；刷新不得修改、删除、重命名或重排 `harness/custom-rules/`。
- `doc/` 只作历史参考；Harness 事实来源是 `docs/` 与 `harness/`。
- 单 task 测试、acceptance 与 auto-pipeline 只调用 `<module>/<task-name> all`；module suites、`all all`、root shortcuts 与 quality gates 仅供用户明确发起的 maintenance。
