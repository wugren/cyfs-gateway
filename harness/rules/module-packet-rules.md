# Task Packet Rules

## 目标

- 让 `docs/versions/<version>/modules/<project>/<task-seq>-<task-slug>/` 成为版本化任务的固定入口。
- 为 implementation admission、post-implementation testing、acceptance 与统一测试入口提供稳定路径。

## 标准结构

单项目 task packet：

```text
docs/versions/<version>/modules/<project>/<task-seq>-<task-slug>/
```

跨项目 task packet：

```text
docs/versions/<version>/modules/globals/<task-seq>-<task-slug>/
```

Manual flow 包含：

- `proposal.md`
- `design.md`
- 可选 `design/`
- implementation 后可选 `testing.md` / `testing/`
- completed testing 的 `testplan.yaml`，除非版本化例外明确记录 reason、owner、risk 与 acceptance impact
- 可选 `acceptance.md`
- 实际验收报告 `acceptance-report.md`

Explicitly launched auto-pipeline 包含：

- `proposal.md`
- `pipeline/plan.md`
- `pipeline/state.json`
- implementation 后的 `testplan.yaml`
- `acceptance-report.md`

Auto-pipeline 不生成 `design.md`、task-local `design/`、`testing.md` 或 `testing/`。

## Task 标识与索引

- 新 task 名称必须是 `<task-seq>-<task-slug>`，序号由 `harness/scripts/task-seq.py` 分配。
- `docs/versions/<version>/modules/tasks.md` 只记录未完成 task。
- 序号只表示创建顺序；current/latest 必须由当前用户请求或 `docs/modules/<module>.md` 的 Current/Active Task 指定。
- Approved packet 对新需求和修正默认不可变；新工作创建 sibling packet，修正创建 amendment/fix packet。
- 旧的模块根级或未序号化 packet 只能作为历史/迁移输入，不能作为新 implementation admission 的 task packet。

## 读取顺序

1. `docs/versions/<version>/modules/tasks.md`
2. 当前 task packet 的 `proposal.md`
3. Manual flow 的 `design.md` / `design/`，或 auto-pipeline 的 `pipeline/plan.md`
4. 已存在的 task-local testing artifacts
5. 已存在的 `acceptance-report.md` / 可选 `acceptance.md`
6. `docs/modules/<module>.md`
7. 与任务相关的 `docs/architecture/`
8. 当前阶段规则与项目 custom rules

## 一致性与准入

- Manual flow 的 proposal/design front matter 必须与目录中的 version、project、task name 一致。
- Auto-pipeline 的 plan/state 必须绑定同一个 version、packet module 与 task name。
- Implementation 只接受当前 task 的 proposal 与 active design source，并要求稳定 `change_id`、concrete `target_module` 与 `Scope Paths`。
- 模块概览、旧 packet、历史资料或聊天说明不能单独作为 implementation admission evidence。
- Testing 在 implementation 后设计并实现测试；testing artifact 不是 implementation 前置批准件。
- Acceptance 报告保存在当前 task packet，不写入版本级共享 reviews 目录。

## 阶段职责

- Proposal：批准需求基线，只定义 why/what、边界、权衡与成功标准。
- Design：定义 how、依赖、接口、状态所有权、流程、Scope Paths 与文件级顺序，不设计测试。
- Implementation：只交付满足 active design source 的最小生产代码与必要非测试资源。
- Testing：implementation 后设计并实现测试，生成 task `testplan.yaml` 与 runnable evidence。
- Acceptance：独立审计证据链与实现正确性，只写 report 和允许的状态记录。

## 缺失时回退

- 缺 task packet 或 proposal 覆盖：回 proposal。
- Manual flow 缺 design 或直接映射；auto-pipeline 缺 plan mapping / Scope Paths：回 design。
- Implementation 后缺测试设计、实现、task testplan 或 runner 注册：回 testing。
- 缺验收报告：进入 acceptance；acceptance 不在同一任务内修上游工件。
