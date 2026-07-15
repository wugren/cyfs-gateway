# Rust Design Document Rules

## 目标

- 在通用 design 规则之上，明确 Rust 文件级接口、异步边界与资源所有权。
- 保持 design 只包含会影响 implementation、admission 或 acceptance 的事实，不混入测试设计。

## 适用范围

- 当前 task packet 的 `design.md` / `design/` 涉及 Rust crate、module、trait、struct、enum、async task、runtime assembly 或 FFI/配置边界时。
- Auto-pipeline 将相同信息写入 task-local `pipeline/plan.md` mappings，不生成 design Markdown。

## 必需输入

- 当前 task packet 的 approved proposal，或显式启动 auto-pipeline 时的 launch-confirmed proposal。
- `harness/rules/design-doc-rules.md`。
- 相关 `docs/modules/<module>.md` 与实际 Rust source paths。

## Rust 文件级接口

- 每个受影响文件级 module 使用 `rust` fenced code block 给出实现所需的具体 signatures、types、traits、functions 与 error types。
- 每个 exported interface 必须命名 concrete consumer 或当前版本 `change_id`，并记录 compatibility：`new`、`backward-compatible`、`migration-required` 或 `breaking`。
- Breaking / migration-required 变更必须列出 concrete caller files 与 migration path，并进入 consumer migration closure。
- 不以无所有者的 global function 作为主要文件级形态；若语言或现有 crate 结构确实要求例外，在 `## Design Notes` 记录原因。

示例：

```rust
pub trait CertProvider {
    async fn resolve(&self, request: CertRequest) -> Result<CertMaterial, CertError>;
}
```

## 异步、并发与资源所有权

仅在当前变更受影响时记录：

- `Arc`、锁、channel、watch/broadcast 等共享机制的 owner 与 dependency direction。
- spawn 点、取消条件、shutdown/join/abort 顺序与 termination guarantee。
- lock ordering、atomicity、visibility、backpressure 与 retry/idempotency 约束。
- socket、file、certificate、timer、task、device handle 等资源的唯一 owner 与成功/失败/取消清理路径。
- persistent/shared state 的 single writer、合法状态转换、failure transition 与 recovery。

## 错误与边界流程

- 对跨 module/submodule 的关键流程使用 `sequenceDiagram`；生命周期有实质变化时使用 `stateDiagram-v2`。
- 只记录会改变实现形态或 acceptance boundary 的 timeout、retry、fallback、partial completion 与 error conversion。
- 配置进入 Rust 类型时，记录 concrete config path、validation/default/compatibility 语义与 consumer。
- Module/submodule 关系遵循通用规则：same-parent、acyclic、business -> shared/technical、nothing -> assembly。

## 文件级实现顺序

- 最终 design 必须列出每个 create/modify 的 Rust 文件。
- `## File-Level Implementation Sequence` 按 same-level dependency 排序，并为每行绑定 `change_id` 与 concrete Scope Path。
- Crate-root export、Cargo feature、dependency 或 build-surface 变化必须在 API/build impact 与 consumer closure 中显式记录。

## 禁止内容

- Design 阶段不得定义 test cases、test plans、validation ids、fixtures、test strategy、testability seams、test implementation 或 expected test results。
- 不为未来可能性添加 speculative traits、generic parameters、feature flags 或 extension points。
- 不重复 proposal，不把现有代码逐行抄入设计。
- 不自动运行 `cargo fmt`；格式化遵循项目 custom rule。

## 完成检查

- 通用 `doc-structure-check.py --docs design` 必须通过。
- Rust interface code blocks、owners、consumers、compatibility、Scope Paths 与 file-level sequence 足以让 implementation 在不依赖聊天上下文的情况下执行。
