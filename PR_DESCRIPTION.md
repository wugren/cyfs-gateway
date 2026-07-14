# PR: 新增 Web3 Gateway 应用和共享 Gateway App 库

## 概要

本 PR 只包含提交 `3afd899bc8cf14defa08f7c49581d6c0f990d057`。

该提交新增 `web3_gateway` 应用 crate，并将 `cyfs_gateway` 中可复用的 Gateway 应用层代码抽取到新的共享 crate：`cyfs-gateway-app-lib`。现有 `cyfs_gateway` 应用改为依赖共享库，不再直接维护这些通用模块。

## 范围

- 提交：`3afd899bc8cf14defa08f7c49581d6c0f990d057`
- 提交标题：`Add web3 gateway app and shared gateway app library`
- 变更文件数：27
- Diff 规模：新增 12870 行，删除 1518 行

## 主要变更

### 新增 `web3_gateway` 应用

- 新增 workspace 成员 `apps/web3_gateway`。
- 新增 `web3_gateway` 二进制入口和包元数据。
- 新增 Web3 Gateway 实现，包括配置加载、ACME/SN provider 接入和 Gateway 运行时代码。
- 新增 Web3 Gateway 测试和测试配置：
  - `tests/test_control_server.rs`
  - `tests/test_cyfs_gateway.rs`
  - `tests/test_sn_bns_integration.rs`
  - `tests/test_cyfs_gateway.yaml`
  - `tests/local_dns.toml`

### 新增共享库 `cyfs-gateway-app-lib`

- 新增 workspace 成员 `components/cyfs-gateway-app-lib`。
- 从 `apps/cyfs_gateway` 中迁移可复用的应用层模块：
  - `config_merger`
  - `debug`
  - `gateway_control_server`
  - `gateway_control_server.yaml`
  - `process_chain_doc`
- 新增共享 `config_parser` 模块。
- 在 `cyfs-gateway-app-lib/src/lib.rs` 中统一 re-export Gateway 应用层公共 API。

### 更新现有 `cyfs_gateway`

- 新增对 `cyfs-gateway-app-lib` 的依赖。
- 移除已迁移模块在 `cyfs_gateway` 内的本地模块声明。
- 调整 `cyfs_gateway` 的导出和导入，使其从 `cyfs-gateway-app-lib` 使用共享配置解析、控制服务、debug 命令和 process-chain 文档类型。
- 保持现有 Gateway 运行流程，同时减少与新 Web3 Gateway 应用之间的重复代码。

### 打包和 workspace 更新

- 在 `src/Cargo.toml` 中加入 `components/cyfs-gateway-app-lib` 和 `apps/web3_gateway`。
- 更新 `src/bucky_project.yaml`，让 `web3-gateway` 应用打包时使用新的 `web3_gateway` 模块。

## 验证

该提交包含新增 `web3_gateway` crate 的测试文件。

生成本文档时未执行以下命令：

- `cd src && cargo build --verbose`
- `cd src && cargo test -- --test-threads=1`
- `cd src && cargo test -p web3_gateway`
- `cd src && cargo test -p cyfs_gateway`

## Review 重点

- 确认迁移到共享库后的模块仍保持 `cyfs_gateway` 原有行为。
- 对照 `cyfs_gateway` 检查 `web3_gateway` 的配置加载和运行时 wiring。
- 检查 `bucky_project.yaml` 的打包配置，尤其是 `web3_gateway` 模块映射。
- Review 新增的控制服务、Gateway 运行时和 SN/BNS 集成测试覆盖。
