# BNS 改造 TODO（一步到位：私链 + 真合约 + 真索引器）

> **方向**：不再用 Rust 状态机 + SQLite 模拟 BNS 逻辑。第一天就上 **本地私链 + 第一版 BNS 合约（Solidity）**，
> 合约是状态的**唯一权威源**；`bns-indexer` 从第一天起就是一个**真正的事件索引器**（只读、不持有业务逻辑）。
> 目标是**在真实业务中尽早把 BNS ABI 跑稳**——selector / 参数 packing / revert / event topic 这些只有真 EVM 才暴露的问题，越早撞到越好。

---

## 实现现状

第一阶段（私链环境 + 合约）已落地，代码在 **`src/apps/bns`**（Foundry 工程，非原计划的 `contracts/`）。
EVM 客户端基础层与索引器事件投影已落地；BNS Server 已切到 raw TX + 投影读模型，SN 写路径已**强制**走 EVM Controller（`sn_server.rs` 中 `bns_write_enabled` 必须配 `bns_evm`，否则启动报错；SN 写控制器只有 `new_evm` 构造路径）。剩余未完成的是几项明确标注为"后续/可选/上公链前"的非阻塞项（revm 内嵌、EIP-170 拆分、ABI 移除 `CallAuthority` 入参、部分文档同步）。

| 模块 | 状态 | 说明 |
| --- | --- | --- |
| 私链环境（Anvil 脚本） | ✅ 已完成 | [scripts/anvil.sh](../src/apps/bns/scripts/anvil.sh) / [scripts/deploy.sh](../src/apps/bns/scripts/deploy.sh) |
| BNS 合约 `Bns.sol` | ✅ 已完成（**超出原计划范围**） | 一次性实现了**完整闭环接口**，而非计划中的"先 5 个核心写操作"，见 [src/Bns.sol](../src/apps/bns/src/Bns.sol) |
| `forge test` 合约单测 | ✅ 已完成 | 6 个用例，覆盖鉴权 / guard / 文档 / 事件，见 [test/Bns.t.sol](../src/apps/bns/test/Bns.t.sol) |
| 链上 smoke 流程 | ✅ 已完成 | [script/Smoke.s.sol](../src/apps/bns/script/Smoke.s.sol)：部署 → registerName → publishDocument → resolveDocument |
| `bns-evm` crate（alloy 绑定 + TX 构造/签名） | ✅ 基础已完成 | 新增 [src/components/bns-evm](../src/components/bns-evm)：`sol!` ABI 绑定、calldata/event 解码、EIP-1559 TX 构造/签名、JSON-RPC helper、round-trip 测试 |
| Standard / Controller 客户端 | ✅ 已完成 | `src/components/bns-client` 新增 EVM Standard/Controller client、raw TX 提交、unsigned TX helper、托管私钥签名；`sn_bns_controller.rs` 写路径**仅有** `EvmSnBnsWriteBackend` 一种实现（[sn_bns_controller.rs:466](../src/components/bns-client/src/sn_bns_controller.rs:466)），通过 Controller Client 自动签名提交，旧 RPC/CallAuthority 写 backend 已删除 |
| `bns-indexer` → 事件索引器 | ✅ 已完成 | [sync.rs](../src/components/bns-indexer/src/sync.rs)：轮询 `eth_getLogs` 同步器、常驻 polling driver、last-synced-block+block-hash 游标、reorg 检测后重放、完整读投影重建（names/documents/authority/controller/alias/checkpoint）、`EventLogRecord` 写入；`CentralizedBnsRegistry::new` 默认只读，旧状态机写路径仅保留隐藏 legacy 测试入口 |
| BNS Server 读/写路径改造 | ✅ 已完成 | 新增 `BnsContractServerHandler` / `SqliteBnsServerHttpServer`：写路径 `tx.submit_raw` 转发 `eth_sendRawTransaction`，读路径查 SQLite 投影；旧 `CallAuthority` 写 RPC 在新 handler 中返回 unsupported |
| SN EVM 配置 | ✅ 已完成 | `SNServerConfig` 新增 `bns_evm` RPC/chainId/合约地址/gas/私钥来源字段；配置存在时 SN 写路径构造 `BnsEvmControllerClient` 并走 EVM Controller 提交 |

### 与原计划的两处关键偏差（需注意）

1. **合约范围一次到顶，而非渐进式**：合约不是"先跑通 5 个写操作"，而是把**整套闭环接口**（注册 / 续期 / 转移 / owner / 释放 / 命名空间策略 / 授权密钥 / controller 策略 / 文档发布撤销 / 别名 / 支付目标 / 日志检查点 + 全部读 API）放进**单个 `Bns.sol`**。
   - 代价：字节码**超过公链 EIP-170 大小上限**，私链脚本用 `--disable-code-size-limit` 绕过；上公链前需拆分 facet/module（README 已注明）。

2. **`CallAuthority` 被保留在 ABI 中，但不被信任**：原计划是"删掉 `CallAuthority`，纯靠 `msg.sender`"。实际实现是：函数签名**仍接收 `CallAuthority` 入参**（用于区分 role=Owner/Controller 与选择 `kid`），但合约**只信任 `msg.sender`**——
   `_authenticateExpectedPrincipal`（[Bns.sol:1541](../src/apps/bns/src/Bns.sol:1541)）要求 `CallAuthority.actor` 解析出的地址 / 授权密钥地址 **必须等于 `msg.sender`**。即"签名边界"已经做到合约只认节点恢复出的 sender，但 ABI 形状暂未清理。

---

## 0. 目标架构

### 0.1 分层与交互顺序（重要）

整条链路是一个**线性分层**结构，每一层只与相邻层对话：

```
BNS(合约) <-> BNS-Indexer <-> BNS-Server <-> BNS-Client <-> BNS-Controller
```

各层职责，以及"签名 / control 逻辑放在哪一层"是本文档的核心约定：

| 层 | 角色 | 职责 | 不做什么 |
| --- | --- | --- | --- |
| **BNS(合约)** `Bns.sol` | 权威状态机 | 唯一权威源；访问控制（只认 `msg.sender`）；`emit` 事件 | — |
| **BNS-Indexer** | 事件索引器（只读） | 监听合约 event → 解码 → 建只读查询索引投影；派生 EventLog/Checkpoint | 不持有业务逻辑、不做 mutation/鉴权 |
| **BNS-Server** | **标准智能合约处理器**（BNS Index 的 Server 端） | 暴露**直接连接**的合约接口，**只处理两类请求：TX（写交易）和读（查询）**。写=接收**已签名的 raw TX** 并 `eth_sendRawTransaction`；读=查 Indexer 投影 | **不做自动签名、不持私钥、不含 control 逻辑** |
| **BNS-Client** | 薄封装 | 对 BNS-Server 两类接口的薄封装：构造 calldata / unsigned TX、提交 raw TX、转发读请求。**自动签名与 control 这类"前置逻辑"在这一层之上完成** | 默认形态（Standard）不持私钥 |
| **BNS-Controller** | Client 的前置逻辑（持 control 私钥时启用） | 当 Client **认为自己持有某些资产的 control 公钥**时，由 Controller 承担"自动签名 + control 决策"：构造 op → 查 nonce → 填 chainId/gas → ABI 编码 → **签名** → 经 Client/Server 提交 | — |

**关键边界约定**：

- **BNS-Server 是一个标准的智能合约处理器**——它能处理的接口"一定是直接连接的"，只对应合约本身能做的两件事：**提交交易（TX）** 和 **读状态**。它**不**承担任何自动签名或我们的 control 逻辑。
- **凡是"自动签名 / control"这类前置处理，都在 BNS-Client 的前置逻辑里做**，具体由 **BNS-Controller** 实现。Client 只有在判断"自己持有该资产的 control 公钥"时，才走 Controller 路径用私钥自动签名；否则走 Standard 路径，入参就是外部已签好的 raw TX。

### 0.2 写/读数据流

```
写：[ BNS-Controller ] 构造 op + 托管私钥签名 ──┐
    [ BNS-Client(Standard) ] 入参=外部已签 raw TX ─┤─> [ BNS-Server ] eth_sendRawTransaction ─> [ BNS(合约) ]
                                                                                                     │ emit event
                                                                                                     ▼
读：[ BNS-Client ] ──> [ BNS-Server ] 查询 API ──> [ BNS-Indexer ] 只读投影 <── 监听/解码合约 event
```

- 合约 `emit` 事件 → BNS-Indexer 监听、解码、建只读索引投影；EventLog/Checkpoint 由链上日志派生。
- BNS-Server 读接口（kRPC/HTTP）后端查 Indexer 投影；写接口仅做 raw TX 转发，不解释、不签名。

**本质变化**：
- 权威源：`Rust 状态机` → **`Bns.sol` 合约**。✅ 合约侧已成立（链上 `_names`/`_documents`/`_authoritySets` 等即权威状态）。
- `bns-indexer`：`状态机+存储` → **事件索引器**。✅ 轮询 `eth_getLogs` 同步器 + 常驻 polling driver + 完整读投影重建 + block-hash reorg 检测/重放已落地；默认构造已是只读投影 facade，旧状态机写路径下线。
- `bns-server`：`状态机 HTTP 包装` → **标准智能合约处理器**：只处理 TX（转发已签 raw TX）和读（查索引器投影），不签名、不含 control 逻辑。✅ 新 handler 已落地。
- 鉴权：不再由 server 端 `ecrecover` 或信任传入的 `CallAuthority`；**节点恢复 sender，合约用 `msg.sender` 做 `require` 访问控制**——✅ 合约侧已成立（`CallAuthority` 仅作 role/kid 提示，地址必须 == `msg.sender`）。Rust 客户端侧已能构造/签名 EVM TX；SN 写路径已强制经 EVM Controller 提交（见上）。BNS Server 写路径仅做 raw TX 转发。

## 1. 私链环境（Anvil）✅ 已完成

- [x] 引入 **Foundry**：`forge`（写/编译/测合约）+ `anvil`（私链）。README 含安装指引。
- [x] 起链脚本 [scripts/anvil.sh](../src/apps/bns/scripts/anvil.sh)：`--state var/anvil-state.json`（持久化）、`--block-time 1`、固定助记词 `test test ... junk`（确定性账户）、`--chain-id 31337`、`--disable-code-size-limit`。
- [x] 部署脚本 [scripts/deploy.sh](../src/apps/bns/scripts/deploy.sh)：`forge build` + `forge create src/Bns.sol:Bns`，输出到 `deployments/anvil.local.json`。
- [x] "随时可改"工作流：改 `Bns.sol` → `forge build` → 重新部署。**中心化测试环境，零迁移负担**。
- [x] 集成测试从 Rust 里自动拉起 anvil + 部署合约 + 跑端到端：[tests/e2e_anvil.rs](../src/components/bns-client/tests/e2e_anvil.rs)（7 个 `#[ignore]` 用例，缺 Foundry 时优雅跳过）。**实现差异**：用 `std::process::Command` 直接拉起 `anvil` + `forge create`，未使用 `alloy-node-bindings` 库。
- [x] 配置项进 Rust 侧：链 RPC endpoint、chainId、合约地址、controller 私钥来源字段已进入 `SNServerConfig.bns_evm`。
- [x] 把 SN 写请求真正切到 EVM Controller Client：`sn_server.rs` 写控制器仅 `new_evm` 构造，`bns_write_enabled` 强制要求 `bns_evm`。
- [ ] 删掉旧的裸 `CallAuthority` 字段/路径：当前 `CallAuthority` 仍作为 role/kid 数据载体保留在请求结构与 ABI 入参中（合约只信 `msg.sender`），尚未从线协议/ABI 中移除。见 §10 与开放问题 8。

## 2. BNS 合约（Solidity）✅ 已完成（范围超出原计划）

> 实际实现没有停在"第一版 5 个核心操作"，而是把完整闭环接口一次性写进 [src/Bns.sol](../src/apps/bns/src/Bns.sol)（约 1976 行）。
> foundry 配置：solc `0.8.24`、`optimizer`、`via_ir`、`evm_version = paris`（[foundry.toml](../src/apps/bns/foundry.toml)）。

- [x] 写操作（**远超**原计划的 5 个）：
  - [x] `registerName`（[Bns.sol:625](../src/apps/bns/src/Bns.sol:625)）
  - [x] `renewName`（[Bns.sol:694](../src/apps/bns/src/Bns.sol:694)）
  - [x] `transferName`（[Bns.sol:725](../src/apps/bns/src/Bns.sol:725)）
  - [x] `setNameOwner`（[Bns.sol:788](../src/apps/bns/src/Bns.sol:788)）
  - [x] `releaseName`（[Bns.sol:834](../src/apps/bns/src/Bns.sol:834)）
  - [x] `setNamespacePolicy`（[Bns.sol:856](../src/apps/bns/src/Bns.sol:856)）
  - [x] `updateAuthorityKeys`（[Bns.sol:891](../src/apps/bns/src/Bns.sol:891)）
  - [x] `applyMutations`（[Bns.sol:906](../src/apps/bns/src/Bns.sol:906)）— 批量 authority key + document 变更（原计划的 `rotateAuthorityAndOwnerDocument` 已合并进此批量入口）
  - [x] `publishDocument`（[Bns.sol:953](../src/apps/bns/src/Bns.sol:953)）
  - [x] `revokeDocument`（[Bns.sol:1002](../src/apps/bns/src/Bns.sol:1002)）
  - [x] `setControllerPolicy`（[Bns.sol:1052](../src/apps/bns/src/Bns.sol:1052)）
  - [x] `setDidAlias`（[Bns.sol:1067](../src/apps/bns/src/Bns.sol:1067)）
  - [x] `setPaymentTarget`（[Bns.sol:1102](../src/apps/bns/src/Bns.sol:1102)）
  - [x] `publishLogCheckpoint`（[Bns.sol:1162](../src/apps/bns/src/Bns.sol:1162)）
  - ⚠️ **与文档历史版本的差异**：原列出的 `bootstrapName` / `rotateAuthorityAndOwnerDocument` 两个独立函数在当前合约中**已不存在**——bootstrap 语义并入 `registerName`，authority+owner 文档轮换并入批量 `applyMutations`。功能未丢失，仅入口收敛。
- [x] 读 API：`queryNameState` / `resolveOwner` / `isStandardTransferEnabled` / `getAuthoritySet` / `getAuthorityKey` / `resolveDocument` / `getDocumentVersion` / `getAlias` / `getPurchaseContext` / `resolvePaymentTarget` / `latestCheckpoint` / `chainAccountPrincipal` / `bnsNamePrincipal`。
- [x] 访问控制基于 `msg.sender`：`_authorizeOwner`（[Bns.sol:1550](../src/apps/bns/src/Bns.sol:1550)）解析 effectiveOwner 后经 `_authenticateExpectedPrincipal`（[Bns.sol:1565](../src/apps/bns/src/Bns.sol:1565)）要求其地址 == `msg.sender`；controller 操作在 `_authorizeUpdate`（[Bns.sol:1499](../src/apps/bns/src/Bns.sol:1499)）中按 controller policy 的 `permissions` 位掩码 + docType 匹配 + 有效期校验，并要求登记的 controller 地址 == `msg.sender`。
- [x] **合约级 controller 策略**：`ControllerRule[]`（`permissions` 含 `PUBLISH_DOCUMENT` / `REVOKE_DOCUMENT` / `SET_PAYMENT` / `SET_ALIAS` / `SET_NAMESPACE`），含 docType scope 与有效期窗口。映射现有 `ControllerRule`/controller policy 概念。
- [x] 每个写操作 `emit` 专用事件 **＋** 统一的 `ProtocolEvent(seq, eventType, actor, previousLogRoot, logRoot)`（[Bns.sol:327](../src/apps/bns/src/Bns.sol:327)）；字段含 name/docType/version/actor/contentHash 等，可直接供索引器消费。
- [x] 大对象走 `DocumentRef`：inline 上限 `MAX_INLINE_DOCUMENT = 4KB`（[Bns.sol:258](../src/apps/bns/src/Bns.sol:258)），inline 必须 `sha256(inlineDocument) == contentHash`；非 inline 走 `uri` + hash 引用。
- [x] `MutationGuard`（`expectedNameSeq` + `expectedParentNameSeq`）作为参数进合约，`_checkGuard`（[Bns.sol:1663](../src/apps/bns/src/Bns.sol:1663)）`require(nameSeq == expected)`；`_hashDocumentState`（[Bns.sol:1945](../src/apps/bns/src/Bns.sol:1945)）/ `_commitEvent` 均混入 `block.chainid` + `address(this)` 防跨部署重放。
- [x] `forge test` 写 Solidity 单测，覆盖鉴权 / guard / 文档 / 事件（见 §9）。
- [ ] **上公链前的拆分**：当前单合约字节码超过 EIP-170 上限，仅私链 `--disable-code-size-limit` 可部署。上公链需拆 facet/module 或把读 helper 移出写合约。（README 已注明，留作后续。）

## 3. `bns-evm` crate（ABI 绑定 + TX 构造/签名）✅ 基础已完成

> 所有 EVM/密码学依赖收敛到这一层。`sol!` 一份定义同时充当合约接口与客户端编码器，ABI 漂移编译期即报错。
> **现状**：已新增 `src/components/bns-evm`。该 crate 从 Foundry 产物生成类型安全绑定，并提供 EIP-1559 TX 构造、签名、raw TX 解码、JSON-RPC 与事件解码基础能力。

- [x] 新建 crate `bns-evm`，引入 alloy：`alloy-primitives`、`alloy-sol-types`、`alloy-consensus`、`alloy-rlp`、`alloy-signer-local`；JSON-RPC helper 先用 `reqwest` 直连节点。
- [x] 用 `sol!(Bns, "out/Bns.sol/Bns.json")` 生成类型安全绑定（calldata 编码 + event 解码一份搞定）。
- [x] 封装：`build_tx(call, nonce, chainId, to, gas) -> TxEip1559`、`sign(tx, key) -> RawTx`、`decode_bns_event` / `decode_bns_call` helper。
- [x] round-trip 测试：calldata 编/解码一致；独立解码自己签的 TX，恢复出的 signer 地址一致。
- [x] 自动部署合约的端到端测试已补：[tests/e2e_anvil.rs](../src/components/bns-client/tests/e2e_anvil.rs)（用 `std::process::Command` 拉起 anvil + `forge create`，未用 `alloy-node-bindings` 库）。

## 4. BNS-Client（薄封装）与 BNS-Controller（前置签名逻辑）✅ 已完成

> **定位**（见 §0.1）：这两者都在 BNS-Server 之上。**Standard Client = BNS-Client 的默认薄封装形态（不持私钥）**；**Controller Client = BNS-Controller**，即 Client 在"自己持有该资产 control 公钥"时启用的前置签名逻辑。所有自动签名/control 决策都收敛在 Controller，Server 层完全不感知。
> **现状**：`src/components/bns-client` 已新增 EVM Standard/Controller client（见 [evm.rs](../src/components/bns-client/src/evm.rs)）。`sn_bns_controller.rs` 已通过 `SnBnsWriteBackend` 接入 EVM Controller Client；配置 `bns_evm` 时 SN 写路径构造 op → Controller 自动查 nonce / 填 TX / 签名 / 提交。`SnBnsWriteBackend` 仅有 `EvmSnBnsWriteBackend` 一种实现，旧 RPC backend 已删除。

- [x] **Standard Client**（= BNS-Client 薄封装，无私钥）：入参为**已签名 raw TX 字节**，`eth_sendRawTransaction` 提交；另提供 `build_calldata`/`build_unsigned_tx` helper 给外部签名方。读走索引器。
- [x] **Controller Client**（= BNS-Controller，托管私钥，自动签名）：持 secp256k1 私钥，自动查 nonce → 填 chainId/to/gas → ABI 编码 → 签名 → 提交。仅在 Client 判断持有对应 control 公钥时走此路径。
  - [x] 迁移 `sn_bns_controller.rs`：通过 EVM write backend 构造合约 op → Controller Client 自动签名提交；旧 `CallAuthority` RPC 写 backend 已删除（仅剩 `EvmSnBnsWriteBackend`）。
  - [x] 幂等元数据：`SnBnsWriteRequestStore` 增加 `evm_chain_id` / `evm_nonce` / `evm_tx_hash` / `evm_raw_tx` 字段，避免后续迁移时重复提交信息丢失。
  - [x] nonce 管理基础：Controller Client 本地缓存 pending nonce。
  - [x] nonce 管理增强：签名/提交失败回退重查、Controller Client 内串行化提交避免并发 nonce 冲突、可选等待 `eth_getTransactionReceipt` 确认上链与确认数。

## 5. `bns-indexer` = 真正的事件索引器 ✅ 已完成

> 状态权威在合约；indexer 只**读链、建索引、供查询**，不再有任何 mutation/validate 逻辑。
> **现状**：[sync.rs](../src/components/bns-indexer/src/sync.rs) 的 `BnsContractEventIndexer` 已完成链→投影同步与常驻 polling driver。`sync_once()` 完成一轮：
> 校验链 `chain_id` → 取最新块并按 `confirmations` 回退 → 校验游标 block hash/reorg → 读游标定起始块 → 按 `max_block_span` 分片 `eth_getLogs` → 逐日志投影 → 写入带 block hash 的游标。
> `CentralizedBnsRegistry::new` 默认只读；旧状态机写路径仅通过隐藏 `new_legacy_state_machine` 给历史测试使用。

- [x] **删除/下线**现有状态机写路径：`registry.rs` 的 mutation / `validate_actor_key` / `authorize_owner_*` 不再是默认可达权威路径；`CentralizedBnsRegistry::new` 对所有写入口返回 `UNSUPPORTED_OPERATION`，读方法只查投影。历史状态机仅保留隐藏 legacy 构造函数供旧测试覆盖。
- [x] 同步器（**轮询版**）：`BnsContractEventIndexer::sync_once` 按合约地址过滤、按 `max_block_span` 分片轮询 `eth_getLogs`，用 `bns-evm` event 绑定解码；`run_polling_loop` 提供 crate 内常驻 driver，`bns-dv serve` 已改为使用该 driver。`eth_subscribe(logs)` 推送版不作为本阶段必要路径。
- [x] 合约事件解码/投影基础：用 `bns-evm` event 绑定解码日志，将 `ProtocolEvent` 与专用事件投影为现有 `RegistryEvent` / `EventLogRecord`。
- [x] 重建完整索引投影：复用现有 SQLite schema 作为**只读投影表**（names / documents / authority set+keys / controller policy / alias / checkpoint），由 `projection_for_record`（[sync.rs:280](../src/components/bns-indexer/src/sync.rs:280)）写入；事件 + projection 在同一 `store.transact` 内原子落库，不再是权威存储。
  - ⚠️ **设计要点（非纯事件回放）**：投影采用**混合**策略——事件只用来定位"哪个 name/doc 变了"，随后通过 `eth_call`（`queryNameState` / `getDocumentVersion` / `getAuthoritySet` / `getAlias` / `latestCheckpoint`）拉取**当前权威状态**，并对 authority key / controller rule 解码原始 calldata（`decode_bns_call`，按 tx hash 缓存）补全事件未携带的入参。即"投影=最新状态快照"，而非按事件流逐条回放历史。
- [x] 同步进度游标：`bns_indexer_cursors` 表与 `IndexerCursor`（按 `source_id = evm:{network}:{chainId}:{contract}` 作用域隔离）记录 last-synced-block + block hash；合约重部署后换 contract 地址即换 source，可从 `start_block` 重放。
- [x] reorg 处理：同步前通过 `eth_getBlockByNumber` 校验游标块 hash；发现 hash 不匹配或游标块高于链头时清空当前投影和该 source 游标，从 `start_block` 按 canonical chain 重放。当前 SQLite 投影表未按 source 分区，因此 reset 会清空全局读投影，避免 fork 状态残留。
- [x] `EventLogRecord` 基础写入：由链上 `ProtocolEvent` 的 `seq` / `previousLogRoot` / `logRoot` 派生并经 `put_event_record` 写入 `bns_events`。
- [x] `LogCheckpoint` 对齐：监听 `LogCheckpointPublished` 后 `eth_call` `latestCheckpoint` 读取并 upsert（`put_checkpoint` 已支持 `ON CONFLICT(last_seq)` 覆盖）。
- [x] BNS Server 保留现有**读 API**（query_name_state / resolve_owner / resolve_document / get_authority_* / list_events / latest_checkpoint），新 `BnsContractServerHandler` 已改为查索引投影；旧 `CallAuthority` 写 RPC 返回 unsupported，默认 `CentralizedBnsRegistry` 不再接受本地写。

## 6. BNS Server = 标准智能合约处理器（TX + 读）✅ 已完成

> **定位**（见 §0.1）：BNS-Server 是 BNS Index 的 Server 端，是一个**标准的智能合约处理器**。它暴露的接口"一定是直接连接的"，**只处理两类请求**：
> - **TX（写交易）**：接收**已签名的 raw TX**，转发 `eth_sendRawTransaction`。**不签名、不持私钥、不含 control 逻辑**——自动签名/control 属于 BNS-Client 的前置逻辑（BNS-Controller）。
> - **读（查询）**：kRPC/HTTP 读接口，后端查 BNS-Indexer 的只读投影。

- [x] 写路径：新增 `tx.submit_raw`，仅做 raw TX hex 解码与 `eth_sendRawTransaction` 转发，不解释 payload、不做鉴权（鉴权在合约 `msg.sender`）。
- [x] 读路径：保留 kRPC/HTTP 读接口，后端改为查索引器 SQLite 投影。
- [x] 删除旧的"传入 CallAuthority"写 RPC 方法在新 Server handler 中的执行能力：`name.register` / `document.publish` / `controller.set_policy` 等旧写方法统一返回 `UNSUPPORTED_OPERATION`。

## 7. 身份与授权（合约侧 ✅ / Rust 侧 🟡）

- [x] 身份 = 以太坊地址（合约见 `msg.sender`）。合约 `_authenticateExpectedPrincipal` 已要求恢复出的地址 == `msg.sender`。
- [x] `AuthorityKey` 承载 secp256k1 公钥/地址（合约 `keyData` 解析为 20/32 字节地址），授权集投影由 `updateAuthorityKeys` 事件维护（`authoritySeq` / `authorityRoot` / `activeKeyCount`）。
- [x] owner / controller 校验全部在合约 `require` 里完成。
- [x] Rust 客户端侧已能构造并签名 EIP-1559 TX；节点负责恢复 signer 并作为合约 `msg.sender`。
- [x] SN 写路径已在 `bns_evm` 配置存在时从旧 `CallAuthority` RPC 切到 EVM TX 提交。

## 8. 下一步：内嵌 revm（中心化生产形态，可选/后置）

- [ ] 把 revm 当库嵌进 BNS Server，进程内执行 `Bns.sol` 字节码，`Database` trait 背后接持久化（可仍用 SQLite 存 EVM state）。去掉独立节点 / JSON-RPC 跳数，确定性更强、可快照回滚。
- [ ] 与外挂 anvil 共享同一份合约与 `bns-evm` 绑定，切换成本低。

## 9. 测试与验证

- [x] `forge test`：[test/Bns.t.sol](../src/apps/bns/test/Bns.t.sol) 6 个用例：
  - `testRegisterAndPublishInlineDocument`（注册 + inline 文档发布）
  - `testStaleNameSeqRejectsPublish`（guard / nameSeq 冲突拒绝）
  - `testControllerCanOnlyPublishAllowedDocType`（controller scope 限制）
  - `testBnsAuthorityKeyTakesOverFromAssetOwner`（BNS 授权密钥接管 assetOwner）
  - `testRevokeCurrentVersionKeepsCurrentPointerRevoked`（撤销当前版本）
- [x] 链上 smoke：[script/Smoke.s.sol](../src/apps/bns/script/Smoke.s.sol) 部署 → registerName → publishDocument → resolveDocument。
- [x] `bns-evm` calldata/TX round-trip + 独立 signer 恢复交叉验证。
- [x] `bns-client` EVM call 转换与 unsigned TX 构造测试。
- [x] `bns-indexer` 合约事件投影与 SQLite event 写入测试。
- [x] `bns-indexer` 同步配置测试（[tests/sync_config.rs](../src/components/bns-indexer/tests/sync_config.rs)）：`source_id` 由 network/chainId/contract 组合且按链隔离；`IndexerCursor` 按 source 作用域存取互不串扰。
- [x] `bns-server` 标准合约处理器测试：投影读、旧 `CallAuthority` 写 RPC 禁用、raw TX 转发到 `eth_sendRawTransaction`。
- [x] 端到端集成：[tests/e2e_anvil.rs](../src/components/bns-client/tests/e2e_anvil.rs) 拉起 anvil → `forge create` 部署 `Bns.sol` → Controller Client 提交 → `sync_once` 同步 → 读 API 命中，全闭环已覆盖：
  - `e2e_write_read_closed_loop_matches_onchain_truth`（写注册/发布 → 同步 → 读投影 == 链上真值）
  - `e2e_signing_boundary_actor_mismatch_reverts_onchain`（签名边界：actor 不匹配链上 revert）
  - `e2e_nonce_replay_and_chain_id_rejection`（nonce 重放 / chainId 不匹配拒绝）
  - `e2e_confirmations_gate_and_cursor_advance`（确认数门控 + 游标推进）
  - `e2e_redeploy_uses_isolated_source_and_replays_from_zero`（重部署 source 隔离 + 从 0 重放）
  - `e2e_controller_policy_scopes_doc_types_on_chain`（controller policy docType scope 链上生效）
  - **实现差异**：用 `std::process::Command` 拉起节点，未用 `alloy-node-bindings` 库。
- [x] 防重放/隔离：合约侧已含 `block.chainid`+`address(this)` 隔离与 guard；nonce 重放 / chainId 不匹配的 TX 级测试已由 `e2e_nonce_replay_and_chain_id_rejection`（[tests/e2e_anvil.rs:437](../src/components/bns-client/tests/e2e_anvil.rs:437)）覆盖。
- [x] 合约重部署 → 索引器从 0 重放一致性：`bns-indexer` mock RPC 测试已覆盖换 contract 地址即换 source、旧游标不串扰、新 source 从 `start_block` 重放。

## 10. 收尾

- [x] 移除 `bns-indexer` 的状态机写逻辑与 `CentralizedBnsRegistry` 权威语义：默认构造降级为只读投影 facade，所有写入口返回 `UNSUPPORTED_OPERATION`；旧状态机仅保留隐藏 legacy 测试入口。
- [ ] 更新 `BNS 智能合约接口设计.md`、SN 文档：权威源=合约、indexer=事件索引器、两客户端模型。
- [x] `SNServerConfig` 新增链 RPC / chainId / 合约地址 / controller 私钥来源 / gas 配置字段。
- [x] 接入 Controller Client：SN 写路径已强制走 EVM Controller（`sn_server.rs`，仅 `new_evm`）。
- [ ] 去掉裸 `CallAuthority` 配置/写路径：仍作 role/kid 提示保留，未从线协议/ABI 移除（与开放问题 8 合并处理）。
- [ ] （新增）清理合约 ABI：评估是否从写函数签名中**移除 `CallAuthority` 入参**（目前保留作 role/kid 提示，但身份只认 `msg.sender`），统一签名边界语义。
- [ ] （新增）公链化：拆分单合约以满足 EIP-170。

---

### 待用户拍板的开放问题（部分已由实现确定）

1. TX 类型 **EIP-1559** 还是 legacy？— **已按 EIP-1559 基础实现**（`bns-evm`）。
2. 写路径：客户端**直连链 RPC** 还是经 **BNS Server 代理**？— **已澄清定位**（见 §0.1/§6）：无论直连还是经 BNS-Server，Server 层都只是**标准合约处理器**，仅做 raw TX 转发 + 读，不签名、不含 control 逻辑；自动签名/control 一律在 BNS-Client/BNS-Controller 完成。具体物理拓扑（直连 vs 经 Server）仍可后定。
3. chainId 与合约地址如何分配/配置？— 私链已**默认 chainId = 31337**（`anvil.sh`，可经 `ANVIL_CHAIN_ID` 覆盖），合约地址由 `deploy.sh` 写入 `deployments/anvil.local.json`；Rust 侧已有 `SNServerConfig.bns_evm` 配置结构，生产分发方式仍待定。
4. controller 托管私钥存放方式（配置 / KMS / 环境变量）？— Rust 配置结构已预留环境变量 / 文件 / inline 字段；实际加载与 SN 写路径接入仍待完成。
5. gas 字段：接受并忽略，还是强制 0？— `bns-evm`/`SNServerConfig.bns_evm` 已按 EIP-1559 gas 字段处理；具体生产策略仍需按部署环境确定。
6. 第一批合约函数范围 — **已确定并超额完成**：实现直接覆盖了**全部闭环写操作 + 读 API**（见 §2），而非"先 register + publish"。
7. （新增）单合约字节码超过 EIP-170：公链部署前的拆分策略（facet/module）？
8. （新增）是否最终从 ABI 移除 `CallAuthority` 入参，纯靠 `msg.sender`？
