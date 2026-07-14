# SN 运行态 lazy-init 改造 TODO

## 背景与目标

参见 [新SN核心流程整理.md](./新SN核心流程整理.md)。

当前实现把 SN 本地运行态（zone_info、device 在线态、relay 分配、self_cert）**作为 SN 自身发起 BNS 写入的副作用**建立，数据直接来自进入 SN 的请求 payload，而不是回读 `bns-indexer` 的最终状态。这导致 SN 隐式依赖"BNS 的写入是我发起的"——Web3 用户用钱包/CLI 直接写 BNS 时，SN 的运行态建立逻辑不会被触发，运行态与 BNS 最终状态脱节。

**目标**：把运行态从"写时副作用"改为"读时 lazy 派生"。

核心原则：

> 运行态读访问器在状态缺失时返回**默认值**（而非"未注册/报错"），随后由真实数据（indexer 解析结果、设备上报、ACME 结果）刷新。

这样无论 BNS 写入由钱包发起还是由 `sn_bns_controller` 代发，对 SN 运行态没有区别——即文档要求的"以 BNS 最终状态为输入"。

---

## 运行态分类与 lazy 策略

### A. BNS 派生缓存 —— lazy 从 indexer 读，默认=空

zone / boot / device_mini_doc 内容是 BNS 权威态的本地缓存。第一次需要时按 `name` 去 `bns-indexer` 读；读不到 = 该 name 尚未发布。

### B. 纯 SN 运行态 —— lazy 默认值，之后被真实事件覆盖

与 BNS 无关，缺失时给语义安全默认，随后被真实事件刷新。

### C. SN 账号/登录态 —— 不能 lazy default（不在本次改造范围）

`sn_user` 用户名/密码/token 是真正必须显式创建的 SN-local 态，无合理默认。改造时**只需保证解析路径不把"存在 sn_user"当前提**（Web3 用户没有 sn_user 行也能解析）。

---

## 改造点（按 seam / crate）

### 1. 解耦写路径：写只发起 BNS 写，不建运行态

- [ ] `api/zone.rs` `bind_config`（[zone.rs:60-148](../../src/components/cyfs-sn/src/api/zone.rs:60)）
  - 移除写成功后用请求 payload 落运行态的 `update_user_zone_config`（第 126-130 行）与 `update_user_domain`（第 131-137 行）。
  - 保留 `controller.bind_zone_documents(...)` 仅作为 Web2 兼容代写；Web3 路径下该分支不触发。
- [ ] `api/auth.rs` `register`（[auth.rs:116-153](../../src/components/cyfs-sn/src/api/auth.rs:116)）
  - `bootstrap_name` 后不再把 BNS 派生态当真值落库；只落 sn_user 账号本体（C 类）。
- [ ] `api/device.rs` 设备注册（[device.rs:72-107](../../src/components/cyfs-sn/src/api/device.rs:72)）
  - `publish_device_mini_doc` 后不建设备权威态；设备在线态改由 `update_ood_info` 上报触发（B 类）。
- [ ] `api/did.rs` `publish_document`（[did.rs:42-57](../../src/components/cyfs-sn/src/api/did.rs:42)）
  - 仅返回 receipt，不缓存为本地权威态。

### 2. 读路径：`get_*` → `ensure_*`（None 时物化默认 / lazy 解析）

- [ ] `sn_resolver.rs` `get_zone_info`（[sn_resolver.rs:466/497](../../src/components/cyfs-sn/src/sn_resolver.rs:466)）
  - 命中空时 lazy 调用 `BnsIndexerDocumentReader` 按 `name` 解析 zone/boot（A 类），合成 ZoneInfo；运行态字段走默认（B 类）。
- [ ] `sn_auth.rs` `get_zone_info`（[sn_auth.rs:436](../../src/components/cyfs-sn/src/sn_auth.rs:436)）
  - `None → 默认 ZoneInfo`（self_cert=false、relay_sn=unassigned）。
- [ ] `relay_mgr.rs` `get_zone_relay`（[relay_mgr.rs:1252](../../src/components/cyfs-sn/src/relay_mgr.rs:1252)）
  - `None → unassigned`；首次 `keep_tunnel`/from_ip 触发 `assign_zone_relay`（[relay_mgr.rs:1192](../../src/components/cyfs-sn/src/relay_mgr.rs:1192)）。
- [ ] `sn_device_info.rs` `get_device_state` / `get_device_state_by_name`（[sn_device_info.rs:1713](../../src/components/cyfs-sn/src/sn_device_info.rs:1713)）
  - `None → offline/空 view`；由 `update_device_state`（[sn_device_info.rs:1459](../../src/components/cyfs-sn/src/sn_device_info.rs:1459)）刷新。

### 3. indexer 读路径转为必需（去掉 Empty 退化的依赖）

- [ ] `sn_server.rs` 初始化（[sn_server.rs:701](../../src/components/cyfs-sn/src/sn_server.rs:701)）
  - 当前 `bns_indexer_url` 缺失时退化成 `EmptyBnsDocumentReader`（恒 None）。lazy 模型下 A 类依赖 indexer，需要：要么把 indexer_url 设为必需配置，要么明确"无 indexer = 仅 Web2 缓存模式"并在日志/启动校验中告警。

### 4. 默认值的落库策略

- [ ] 决定默认 view 是**纯内存返回**（读不落库，写时才落库）还是**读时落库**。
  - 推荐纯内存默认 + 真实数据到达时落库，避免空行污染与并发竞争。

---

## 默认值表

| 运行态 | 类型 | 默认值 | 被什么刷新 | seam |
|---|---|---|---|---|
| zone/boot 内容 | A | 空（未发布） | indexer lazy 解析 | `sn_resolver.get_zone_info` |
| device_mini_doc | A | 空（未发布） | indexer lazy 解析 | resolver device 解析 |
| `self_cert` | B | `false`（HTTP/80 兜底） | ACME 成功 → `update_user_self_cert` | `sn_auth.get_zone_info` |
| `relay_sn` 分配 | B | `unassigned` | 首次 keep_tunnel/from_ip → `assign_zone_relay` | `relay_mgr.get_zone_relay` |
| device 在线态/IP | B | `offline`/空 | `update_ood_info` → `update_device_state` | `sn_device_info.get_device_state` |
| user_domain 绑定 | B | 无绑定 | bind/domain proof 流程 | `sn_auth` |
| sn_user 账号 | C | **无默认**（显式创建） | register | `auth_db.get_user_info` |

---

## 风险点

- [ ] **默认值必须选幂等安全的一端**：`self_cert` 默认 `false`，生产路径绝不能隐式默认 true 覆盖真实证书状态（呼应文档"区分本轮签发失败 vs 当前证书不可用"——lazy 模型下天然满足）。离线 devtest 已预置测试证书时，允许可信 seed 显式声明 `self_cert=true`。
- [ ] **indexer 延迟**：写后立即读 indexer 可能尚未同步到新版本。lazy 模型下表现为"短暂返回旧/空态、随 indexer 追上自愈"，可接受；但需确认 resolver 缓存失效跟随 indexer 的 `name_seq`/document version（当前仅 [sn_bns_reader.rs:151](../../src/components/cyfs-sn/src/sn_bns_reader.rs:151)、[sn_resolver.rs:197](../../src/components/cyfs-sn/src/sn_resolver.rs:197) 读到 name_seq，未用于失效）。
- [ ] **解析路径解除 sn_user 前提**：确认 `resolve_hostname`/`resolve_name_by_username` 等在没有 sn_user 行时也能只凭 BNS name + indexer 完成（C 类要求）。
- [ ] **首次 relay 分配的触发点收敛**：原先在 bind_zone 时 `maybe_assign_zone_relay`（[zone.rs:138](../../src/components/cyfs-sn/src/api/zone.rs:138)），改造后需明确改到首次 keep_tunnel/上报，避免分配逻辑悬空。
- [ ] **idempotency 语义**：`sn_bns_controller` 幂等仍以 SN `request_id` 为 key（[sn_bns_controller.rs:954](../../src/components/bns-client/src/sn_bns_controller.rs:954)），仅约束 Web2 代写路径，不影响 lazy 读；保持现状即可，但勿让运行态依赖它。
- [ ] **缓存一致性**：纯内存默认 + 落库混用时注意并发，避免默认 view 与刚到达的真实数据竞争。

---

## 建议实施顺序

1. 读路径 `get_* → ensure_*`（B 类默认值），不动写路径——先让运行态缺失时不报错。
2. 接通 A 类 indexer lazy 解析（resolver 命中空时按 name 读 indexer）。
3. 摘除写路径里的运行态副作用（zone/auth/device/did）。
4. indexer_url 必需化 / 启动校验。
5. 解析路径解除 sn_user 前提，跑通纯 Web3 路径（钱包直接写 BNS，SN 不经手）端到端。
