# 新 SN 测试计划

> 本计划按当前仓库的实际实现整理，描述重点是测试目的和风险边界；具体用例名称、内部函数和行号以测试代码为准。
>
> 相关设计文档：[SN-Auth.md](SN-Auth.md)、[SN-DeviceInfo-DB.md](SN-DeviceInfo-DB.md)、[SN-BNS-Contoller.md](../BNS/SN-BNS-Contoller.md)、[SN-Resolver.md](SN-Resolver.md)、[SN-Relay.md](SN-Relay.md)、[新SN核心流程整理.md](新SN核心流程整理.md)。

## 0. 总体目标

SN 当前由两条主线组成：

- **BNS 写入与读取链路**：BNS 合约、EVM 编码/签名、索引器投影、BNS Server、BNS Client / SN BNS Controller。
- **SN 业务链路**：账号认证、用户域名与 PKX、zone/device/DID/DNS/relay 数据、SN Resolver、HTTP/DNS 对外查询。

测试按“无外部依赖的快速回归优先，真 EVM/DV 集成单独运行”的原则组织。单元和组件测试只验证本层契约；端到端测试只验证跨层拼接、真实 EVM 行为和配置集成，不重复低层分支覆盖。

## 1. 当前测试入口

| 层级 | 测试目的 | 当前入口 |
| --- | --- | --- |
| BNS 合约 | 验证链上授权边界、权限策略、guard、防重放、文档生命周期、事件契约和关键不变量 | `cd src/apps/bns && forge test` |
| BNS Rust 组件 | 验证 ABI/TX 边界、索引投影、同步游标、BNS Server 读写职责、Client/Controller 写入策略 | `cd src && cargo test -p bns-evm -p bns-indexer -p bns-server -p bns-client -- --test-threads=1` |
| SN 组件 | 验证账号认证、DeviceInfo、Resolver、S2S DB 适配、SN HTTP/kRPC API 的业务语义 | `cd src && cargo test -p cyfs-sn -- --test-threads=1` |
| Gateway + SN/BNS 读取集成 | 验证 gateway 中 SN 服务能通过 BNS indexer 读取 BNS 文档并对外解析 | `cd src && cargo test -p cyfs_gateway --test test_sn_bns_integration -- --test-threads=1` |
| 真 EVM 集成 | 验证 anvil + 合约部署 + Controller 写入 + indexer 同步 + server/client 读取闭环 | `cd src && cargo test -p bns-client --test e2e_anvil -- --ignored --test-threads=1` |
| DV 冒烟 | 验证本地开发环境 fresh/resume、BNS Server、indexer 轮询和最小写读链路 | `cd src/apps/bns && scripts/dv-up.sh --fresh && scripts/dv-smoke.sh` |
| SN seed 集成 | 验证 make_sn_config seed-v2 产物经 bns_dv `--seed-config` 上链、cyfs-sn `sn_seed.yaml` 幂等导入后，账号/DNS/链上/域名种子全部生效（T1-T6，含幂等重放与产物确定性） | `cd src && cargo test -p cyfs_gateway --test e2e_sn_seed -- --ignored --test-threads=1`；手工环境：`cd src/web3-gateway && scripts/sn-dev-up.sh --fresh && scripts/sn-dev-smoke.sh` |

说明：

- `cargo test` 默认会跳过 `#[ignore]` 的真 EVM 集成测试；需要显式加 `--ignored`。
- Foundry 相关测试需要本机安装 `forge`/`anvil`。缺 Foundry 时，Rust 的 ignored e2e 用例应跳过而不是阻断普通回归。
- CI 基线仍以 `cd src && cargo test -- --test-threads=1` 为准；涉及 SN/BNS 改动时建议额外跑对应 Foundry 或 DV 测试。

## 2. BNS 合约测试目的

BNS 合约测试用于钉住链上规则，而不是验证 Rust 侧实现细节。重点覆盖：

- **授权边界**：合约写入必须由真实 `msg.sender` 决定，外部传入的 authority 信息只能作为角色和 key 提示。
- **Controller 策略**：不同权限位、docType scope、有效期窗口、owner-scoped 文档限制都应有正反路径。
- **MutationGuard / 防重放**：name sequence、parent sequence、事件链、chain id、合约地址等防重放条件必须稳定。
- **文档语义**：inline 文档哈希、大小边界、DocumentRef、撤销、历史版本和当前指针行为必须一致。
- **生命周期**：注册、续期、释放、tombstone、owner/authority 切换、namespace/payment/alias/checkpoint 等状态变化要符合设计。
- **原子批量写**：批量 mutation 要么整体成功，要么整体拒绝，且 name sequence 推进规则明确。
- **事件契约**：每类写操作都要发出索引器可消费的事件，事件字段必须能支撑链下投影。
- **fuzz / invariant**：对权限、guard、authority key、事件序列等高风险组合做周期性增强。

通过标准：`forge test` 通过；新增链上写函数或新事件时，同步补授权、guard、事件和至少一个成功路径。

## 3. BNS Rust 组件测试目的

### 3.1 `bns-evm`

目标是保证 Rust 与合约 ABI 的边界稳定：

- calldata 编码/解码、结构体 packing、selector、event decode 与合约一致。
- EIP-1559 交易构造、签名、sender 恢复、chain id 语义正确。
- 截断 calldata、未知 selector、错误 raw tx 等坏输入返回明确错误，不能 panic。

### 3.2 `bns-indexer`

目标是保证链上事实能稳定投影成可读状态：

- source id、chain id、合约地址、游标和 block hash 能隔离不同网络/合约部署。
- confirmations、max block span、幂等追平、polling loop、reorg 检测和重放符合预期。
- 事件记录和状态投影在同一事务内落库，失败时不留下半状态。
- 对需要 `eth_call` 或交易 calldata 补全的事件，投影结果必须以链上权威状态为准。
- SQLite 存储、旧 centralized registry 语义和当前只读投影保持兼容。

### 3.3 `bns-server`

目标是固定 BNS Server 的职责边界：

- 写路径只接受已签名 raw EVM tx 并原样转发链 RPC。
- 读路径只从 indexer 投影读取并按 RPC envelope 返回。
- 旧的 CallAuthority 写 RPC 不应继续作为可用写入口。

### 3.4 `bns-client` / `SnBnsController`

目标是保证 SN 侧发起 BNS 写入时不会绕过链上授权：

- Standard client 能构造 unsigned tx / calldata，并能提交外部已签 raw tx。
- Controller client 使用托管私钥签名，正确处理 nonce、并发写、提交失败后的 nonce 恢复和可选回执确认。
- SN BNS Controller 对注册、zone/boot 文档、DID 文档、DNS TXT、relay assignment 等写入提供幂等 request_id 语义。
- Controller policy、docType scope、owner-scoped 文档限制和 stale guard 错误需要透传到调用方。
- 写请求存储要记录 EVM 元数据，重复 request_id 只能复用同一语义请求。

## 4. SN 业务组件测试目的

### 4.1 SN-Auth / SN V2 API

目标是保证账号和权限模型可恢复、可撤销、可审计：

- 激活码、注册、密码哈希、登录、refresh、logout、session 查询与撤销语义正确。
- TODO（本版本）：注册必须拒绝缺失/格式非法的邮箱；邮箱按统一规范化结果存储，并通过数据库唯一约束保证大小写或首尾空白变体以及并发请求都不能绑定到多个账号。
- TODO（本版本）：密码找回应覆盖不存在邮箱不泄露账号、重置凭证过期与单次消费、成功重置后撤销已有 sessions，以及不改变 BNS owner/controller 权限；注册邮箱验证码不在本轮测试范围内。
- 用户状态变化能立即影响已有 session。
- 用户域名绑定必须经过 PKX 校验；域名冲突、最长匹配、解绑和历史保留要稳定。
- zone 信息 patch、relay_sn 更新、self_cert 权限检查要符合账号/设备权限。
- namespaced RPC 的认证上下文能区分 owner、controller、device、SN user，并拒绝跨用户访问。
- 当 BNS 写入启用时，注册、zone bind、DID 写入等路径应通过 SN BNS Controller，而不是直接改本地兼容缓存。

### 4.2 SN-DeviceInfo

目标是保证设备在线态和查询视图可信：

- device index 的创建、重绑、删除和唯一约束正确。
- runtime 上报能处理 report_seq、TTL、from_ip、reported_ip、endpoint、NAT 类型等字段。
- stale、offline、blocked、unblock、expire 等状态迁移要可预测。
- endpoint 的 active/disabled/stale/failed 过滤、排序和公网/内网分类要稳定。
- 按 DID、按 zone/device_name、分页列表等查询视图不能泄漏过期或被禁用 endpoint。
- local DB 与 remote S2S wrapper 应暴露一致语义，尤其是 `Ok(None)` / `result:null` 的 envelope 行为。

### 4.3 SN Resolver

目标是保证 SN 查询结果来自正确数据源并兼容旧数据：

- BNS name、zone 文档、boot 文档、device_mini_doc、dns_txt、DID 文档能被解析。
- BNS 文档优先级、embedded/standalone device map、legacy local cache fallback 行为明确。
- gateway address、OOD、DNS A/AAAA/TXT、DID/web DID 等对外视图保持一致。
- 离线设备、无 runtime 状态设备、relay assignment 等边界能返回可解释结果。

### 4.4 Gateway 集成

目标是验证 gateway 配置下 SN 服务对外可用：

- SN HTTP/kRPC 和 SN DNS server 能在 gateway stack 中启动。
- 配置了 BNS indexer URL 时，SN resolver 可以只通过 BNS 文档完成解析。
- 测试端口和临时数据库必须隔离，避免和本机服务或并发测试冲突。

## 5. 真 EVM / DV 集成测试目的

真 EVM 集成只验证单元测试无法覆盖的跨层风险：

- Rust 编码的 calldata 能被真实合约接受并产出可索引事件。
- `msg.sender` 授权、controller policy、revert、receipt status 与链上行为一致。
- raw tx 提交、nonce、重放拒绝、chain id 拒绝和回执确认语义正确。
- indexer 的 confirmations、游标推进、source 隔离和合约重部署重放在真实链环境中成立。
- `dv-up.sh --fresh` 能初始化完整开发环境；`--resume` 能复用 anvil state、合约地址和 indexer 游标。
- `dv-smoke.sh` 能通过 BNS Server 完成最小注册、发布、同步、读取闭环。
- `sn-dev-up.sh --fresh` 能在本机（非 VM）拉起 anvil + bns_dv（带 `--seed-config`）+
  web3_gateway 全栈，seed 产物真实生效；`--resume` 是"不动 seed 重启"，验证
  bns_dv 链上幂等重放与 cyfs-sn ensure-exists 重放的零写入契约（属"真集成，
  默认跳过"层，入口 `e2e_sn_seed`，见 §1）。

真 EVM 测试不要求覆盖所有业务分支；业务分支应优先留在 §2-§4 的快速测试中。

## 6. 推荐执行策略

### 快速回归

每次改动优先运行：

```bash
cd src && cargo test -- --test-threads=1
```

涉及 BNS 合约或 ABI 时额外运行：

```bash
cd src/apps/bns && forge test
```

### 定向回归

只改某一层时可先跑更窄命令：

```bash
cd src && cargo test -p bns-evm -p bns-indexer -p bns-server -p bns-client -- --test-threads=1
cd src && cargo test -p cyfs-sn sn_auth -- --test-threads=1
cd src && cargo test -p cyfs-sn sn_device_info -- --test-threads=1
cd src && cargo test -p cyfs_gateway --test test_sn_bns_integration -- --test-threads=1
```

### 集成回归

涉及 EVM 写入、indexer 同步或 DV 脚本时运行：

```bash
cd src && cargo test -p bns-client --test e2e_anvil -- --ignored --test-threads=1
cd src/apps/bns && scripts/dv-up.sh --fresh && scripts/dv-smoke.sh && scripts/dv-down.sh
```

需要验证恢复路径时追加：

```bash
cd src/apps/bns && scripts/dv-up.sh --resume && scripts/dv-smoke.sh && scripts/dv-down.sh
```

涉及 SN seed（make_sn_config seed-v2 / sn_seed.rs / bns_dv seed）时运行：

```bash
cd src && cargo test -p cyfs-sn sn_seed -- --test-threads=1
cd src && cargo test -p cyfs_gateway --test e2e_sn_seed -- --ignored --test-threads=1
```

手工调试 SN 本机环境（三件套，仿 bns dv）：

```bash
cd src/web3-gateway && scripts/sn-dev-up.sh --fresh && scripts/sn-dev-smoke.sh
cd src/web3-gateway && scripts/sn-dev-down.sh --purge
```

## 7. 当前缺口

- TODO（本版本）：SN Auth 尚无注册邮箱字段、邮箱唯一绑定、存量账号迁移和密码找回测试；实现时需要同时补 DB、RPC、并发和端到端覆盖。
- SN 服务层尚缺一个“`bns_write_enabled=true` + 真 BNS EVM/indexer/server”的完整业务端到端测试，用来覆盖 `auth.register`、`zone.bind_config`、`did.set_document` 通过 BNS Controller 写链后，再由 SN Resolver 读回的闭环。
- 真链 reorg 场景目前主要由 mock RPC 覆盖；如果未来要支持生产级 reorg 回滚策略，需要增加更接近真实节点行为的集成验证。
- SN Auth DB 的 remote S2S 适配已有接口，但缺少像 DeviceInfo 一样的 local/remote 同批用例一致性测试。
- 新增 BNS docType、写操作、RPC 方法或 resolver 数据源时，需要同时更新快速测试和至少一个跨层验证点，避免只测本地缓存或只测链上单边行为。
