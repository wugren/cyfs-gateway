# ACME 使用设备身份无人值守更新 SN DNS TODO

## 1. 目标

修复 `cyfs_gateway` 的 SN ACME DNS provider，使 gateway 在没有 SN 用户密码、
没有预置 SN access token、没有人工登录的情况下，可以使用本机设备
authentication 私钥完成以下闭环：

1. 生成 SN 可验证的短期 device token；
2. 通过 `user.add_dns_record` 添加 ACME DNS-01 TXT record；
3. SN 把设备身份可靠映射到所属 zone，并只允许写入该 zone 的 ACME challenge；
4. SN DNS server 能立即查询到刚写入的 TXT；
5. ACME 完成后能安全删除本次 challenge，不误删同名的其他 TXT value。

本 TODO 是后续 CodeAgent 的实施说明。修改涉及两个 checkout：

- `cyfs-gateway`：ACME provider、SN 鉴权/DNS API、存储语义和 smoke test；
- `buckyos`：scheduler 生成 gateway ACME 配置的回归验证；仅在 provider 无法从
  `did.json` 稳定推导 scoped device DID 时才增加配置字段。

## 2. 当前已确认的问题

### P1：ACME provider 生成了错误类型的 token

文件：`src/apps/cyfs_gateway/src/acme_sn_provider.rs`

当前无 `access_token` 时调用：

```rust
RPCSessionToken::generate_jwt_token(
    self.user_name.as_str(),
    "cyfs_gateway",
    None,
    &self.private_key,
)
```

该 token 使用设备私钥签名，但形状是旧的普通 RPC token：

- `sub` 是设备短名（例如 `ood1`）；
- `aud` 是 `cyfs_gateway`；
- 没有短期 `exp`；
- 签名 key 是设备 key。

当前 SN 用户 access token 必须由 SN token key 签名且 `aud=sn`，所以这个 token
无法通过 `verify_access_session`。代码中可选的静态 `access_token` 只能临时绕过
问题：scheduler 没有提供它，而且 SN access token 默认一小时过期，不适合无人值守
续证。

### P1：SN DNS mutation 只接受 SnUser，不接受 Device

文件：`src/components/cyfs-sn/src/api/dns.rs`

`user.add_dns_record` 和 `user.remove_dns_record` 当前调用
`require_account_username`。仓库已经实现 `require_sn_user_or_device` 及完整的
`sn-device` 验证链，但 DNS API 尚未接入。

### P1：请求中的 device DID 可能不是 SN 在线表使用的 DID

Provider 当前把 `device_config.id` 放入 `device_did`。它可能是 scoped DID，例如
`did:web:ood1.example.com`；node daemon 在线上报通常使用
`did:dev:<authentication-public-key-x>`。DNS handler 不应在已经验证 Device token
后继续相信客户端传入的任意 `device_did`。

### P1：同名 TXT 目前只能保存一个 value

`user_dns_records` 当前唯一键为 `(owner, domain, record_type)`，add 是 upsert，remove
按整个 record type 删除。根域与 wildcard 的独立 ACME order 都使用
`_acme-challenge.<zone>`，可能互相覆盖或互删。

### P2：设备 token 是 bearer token，不绑定 RPC body

现有 `sn-device` JWT 能证明设备私钥持有者，但不签名具体 RPC method/params。
本轮至少要维持默认十分钟有效期、严格限制 Device DNS 权限，并依赖 HTTPS。不要把
token 缓存成长期凭证。逐请求 nonce/body hash 可作为后续增强，不阻塞本次修复。

## 3. 目标认证协议

必须复用：

```rust
cyfs_gateway_api::generate_sn_device_token
```

目标 claims：

```text
sub = did:dev:<authentication-public-key-x>
iss = 设备的 zone-scoped DID，例如 did:web:ood1.example.com
aud = sn-device
exp = now + 600 seconds（默认值）
signature = EdDSA(authentication.private.pem)
```

SN 端必须继续执行现有 `require_sn_device` 信任链：

1. 从 `sub` 提取 Ed25519 公钥并验证 JWT；
2. 检查 `aud` 和 `exp`；
3. 从 `iss` 解析 `(zone, device_name)`；
4. 检查 zone 用户存在且 active；
5. 从 zone 权威设备文档解析登记公钥；
6. 登记公钥必须与 `sub` 公钥相同。

不得把“第一个拿私钥来请求的设备”自动登记为可信设备，不得降级为 TOFU。

## 4. 实施任务

### A. 修复 AcmeSnProvider 的凭证生成

文件：`src/apps/cyfs_gateway/src/acme_sn_provider.rs`

- [ ] 保留当前“私钥公钥必须匹配 `did.json` authentication key”的启动检查。
- [ ] 从 authentication 公钥构造 `device_key_did = did:dev:<x>`，不要再把设备短名
  当作 token subject。
- [ ] 推导 `device_scoped_did`：
  - `device_config.id.method` 是 `web` 或 `bns` 时优先使用 `device_config.id`；
  - `id` 是 `did:dev` 时，使用 `device_config.zone_did + device_config.name` 构造；
  - 其他 DID method 或上述信息不足时启动失败并给出明确错误，禁止生成无法锚定
    zone 的 token。
- [ ] 每次 add/remove RPC 前调用 `generate_sn_device_token` 生成新的短期 token。
- [ ] 删除设备私钥走通用 `generate_jwt_token(..., "cyfs_gateway", ...)` 的 fallback。
- [ ] `access_token` 如需兼容保留，必须明确标为人工/调试兼容路径；默认生产路径必须
  是 device token，并补测试证明未配置 access token 可以工作。
- [ ] RPC 参数中的设备 DID 使用 `device_key_did`；不要发送语义不确定的
  `device_config.id`。
- [ ] 修正 remove 失败时仍写成 `add_dns_record failed` 的错误文案。

尽量不要在 scheduler 配置中新增重复身份字段。只有当 `DeviceDocument` 无法覆盖旧身份
布局时，才向 `AcmdSnProviderConfig` 增加可选 `device_scoped_did`，并由 scheduler 明确
生成；新增字段必须保持旧配置可解析。

### B. 让 SN DNS API 接受受限 Device context

文件：

- `src/components/cyfs-sn/src/api/dns.rs`
- `src/components/cyfs-sn/src/sn_authority.rs`（仅在需要公共 helper 时修改）

- [ ] 为 add/remove 增加统一的 DNS mutation identity 解析：支持 `SnUser` 与
  `Device`，内部输出可信的 `username/zone` 和设备身份。
- [ ] `SnUser` 保持现有行为和兼容性。
- [ ] `Device` 必须以验证结果中的 `zone/device_name/did` 为准；请求参数不能覆盖
  这些值。
- [ ] Device context 只允许：
  - `record_type == TXT`；
  - domain 是 `_acme-challenge.<name>`；
  - `<name>` 位于该 zone 的 active `user_domain`，或当前用户自己的
    `<username>.web3.<server_host>` bridge 范围；
  - add/remove 自己的 challenge value。
- [ ] Device context 必须拒绝 A/AAAA、普通 TXT、其他用户域名和未绑定的传统域名。
- [ ] 不要因为客户端传入 `has_cert=true` 就直接设置 `self_cert`。证书成功状态应通过
  受信任 ACME 完成路径更新，至少要由已验证 Device context 且与本机证书状态检查
  绑定；若本轮不能安全收敛，先停止在 DNS mutation 中更新 `self_cert`，另列任务。
- [ ] `/kapi/sn/auth` 路径可以保留；鉴权能力由 method handler 决定，不需要仅因使用
  device token 新增 HTTP path。

### C. 支持同名 TXT 多值和精确删除

文件：

- `src/components/cyfs-sn/src/sn_compat_store.rs`
- `src/components/cyfs-sn/src/api/common.rs`
- `src/components/cyfs-sn/src/api/dns.rs`
- 相关 migration/schema 与 resolver 代码

- [ ] 把唯一性调整为至少 `(owner, domain, record_type, record)`，或采用等价 RRset
  多值模型。
- [ ] 重复 add 相同 value 必须幂等。
- [ ] add 不得覆盖同名 TXT 的其他 value。
- [ ] remove 请求携带 `record`，只删除本次 challenge value；保留兼容的整组删除能力
  时，只允许 SnUser 管理路径使用，Device ACME 路径禁止整组删除。
- [ ] DNS TXT query 返回该 name 下的全部有效 value。
- [ ] cache invalidation 必须覆盖 add/remove，写入完成后 SN 权威 DNS 查询应立即可见。

如果改为“根域 + wildcard 单个 SAN order”来避免冲突，也仍建议让 TXT API 支持标准
RRset 多值；ACME 重试、并发续期或多 gateway 节点仍可能同时持有 challenge。

### D. 对齐 buckyos scheduler 配置

文件：`/Users/liuzhicong/project/buckyos/src/kernel/scheduler/src/system_config_agent.rs`

- [ ] 保持 `key_path` 指向设备 authentication 私钥。
- [ ] 保持 `device_config_path` 指向与该私钥匹配的 `did.json`。
- [ ] 如果 A 中新增 `device_scoped_did`，由 `zone_config.id + node_id` 使用公共 DID helper
  构造，禁止手写不一致的字符串规则。
- [ ] 更新 scheduler 测试：验证每个节点使用自己的身份路径，SN URL 正规化输入正确，
  ACME 配置不依赖 access token。
- [ ] scheduler 测试不能只检查 JSON 外形；至少增加一个跨 repo smoke 的执行说明或
  CI job，证明生成配置能被真实 provider 消费。

## 5. 必须实现的无人值守 smoke test

### 5.1 测试名称与入口

建议在 `src/apps/cyfs_gateway/src/acme_sn_provider.rs` 的 `#[cfg(test)]` 模块中实现：

```text
smoke_acme_sn_device_add_txt_unattended
```

并提供稳定命令：

```bash
cd src
cargo test -p cyfs_gateway smoke_acme_sn_device_add_txt_unattended \
  -- --nocapture --test-threads=1
```

测试应完全使用临时目录和 `127.0.0.1:0`，不依赖公网 ACME、真实域名、人工输入、
已登录 shell 或开发机已有身份。若启动完整 SN/DNS 的耗时使其不适合默认测试，可以
标记 `#[ignore]`，但必须同时提供可复制的 `--ignored` 命令，并在相关 CI 或发布前
smoke 中执行。

### 5.2 强制覆盖的调用路径

Smoke **不得**直接调用 `SnClient::add_dns_record`、不得直接调用 SN DB/store、不得把
SN access token 注入 provider。它必须模拟 ACME client 的真实 provider 调用：

```rust
let factory = AcmeSnProviderFactory::new(provider_data_dir);
let provider = DnsProviderFactory::create(
    &*factory,
    Weak::<AcmeCertManager>::new(),
    json!({
    "sn": sn_url,
    "key_path": device_private_key_path,
    "device_config_path": did_json_path
    // 故意没有 access_token
    }),
).await?;

provider.call(
    "add_challenge".to_string(),
    "_acme-challenge.<test-zone>".to_string(),
    unique_txt_value.clone(),
).await?;
```

这就是 `cyfs-acme` 在 `ChallengeType::Dns01` 下使用的接口边界。测试不要求请求真实
Let's Encrypt 证书，避免公网和速率限制；但必须经过与真实 ACME 完全相同的
`AcmeSnProvider -> kRPC -> SN authority -> DNS API -> store -> DNS server` 写入链路。

### 5.3 Smoke 环境准备

- [ ] 生成临时 Ed25519 authentication key 和匹配的 `DeviceDocument`。
- [ ] 创建 zone 用户，例如 `alice`，状态为 active。
- [ ] 建立 active `user_domain`，例如 `alice.test`，或使用明确的本地 bridge test
  domain；优先覆盖 active `user_domain`，另用单测覆盖 bridge。
- [ ] 把 `ood1` 的公钥通过测试 fixture 登记到 zone 权威设备身份来源，确保
  `require_sn_device` 走真实 trust anchor，而不是测试旁路。
- [ ] 启动真实 `SNServer` HTTP/kRPC 与 DNS server，端口使用 ephemeral port。
- [ ] provider 配置中只给 SN URL、设备私钥路径和 `did.json` 路径。
- [ ] challenge value 使用每次测试唯一值，便于发现旧缓存或残留数据。

环境准备阶段可以直接使用测试 fixture/DB API 建立账号和权威文档；“无人值守”的硬
要求针对 ACME mutation 阶段：从创建 provider 开始，不得再使用账号密码、用户
access token、owner key 或管理员接口。

### 5.4 Smoke 断言

- [ ] provider 的一次 `add_challenge` 返回成功。
- [ ] 通过真实 DNS UDP/TCP 查询（推荐复用仓库 DNS client）轮询
  `_acme-challenge.<test-zone>` 的 TXT，最终得到精确的 `unique_txt_value`。
- [ ] 测试不能以查询 SN DB 或 `user.list_dns_records` 代替 DNS 查询。
- [ ] SN 记录的 owner 是 token 映射出的 zone 用户，不是设备短名 `ood1`。
- [ ] provider 未读取或使用 SN access token。
- [ ] 测试日志不得输出设备私钥、完整 JWT 或账号凭证。
- [ ] 测试结束后用同一 provider 的 `del_challenge` 做 best-effort 清理，并验证目标
  value 消失；清理失败不能掩盖 add/query 的原始失败。

通过标准：全新临时环境中，一条命令可重复运行，无人工步骤，且至少一次真实
`AcmeSnProvider::call("add_challenge", ...)` 写入能从 SN 权威 DNS TXT 查询读回。

## 6. 其他必须补充的自动化测试

### Provider 单元测试

- [ ] token claims 为 `sub=did:dev:<x>`、`iss=scoped DID`、`aud=sn-device`，且存在短期
  `exp`。
- [ ] token 能由 authentication 公钥验证。
- [ ] 私钥与 `did.json` 不匹配时 provider 创建失败。
- [ ] 缺少 scoped DID 信息时明确失败。
- [ ] 每次 mutation 生成短期 token，不复用过期 token。

### SN authority/DNS API 测试

- [ ] 已登记且 active zone 的 Device token 可以添加自己的 ACME TXT。
- [ ] forged key、未登记设备、过期 token、错误 `aud` 全部拒绝。
- [ ] Device token 写其他用户域名、普通 TXT、A/AAAA 全部拒绝。
- [ ] SnUser 原有 DNS 管理能力不回归。
- [ ] 请求中的伪造 `device_did` 不能越权。
- [ ] 同名不同 TXT value 可并存，删除一个不影响另一个。
- [ ] add 相同 value 两次幂等。

### ACME 并发语义测试

- [ ] 模拟根域与 wildcard 对同一 `_acme-challenge.<zone>` 写两个 value。
- [ ] DNS query 同时返回两个 value。
- [ ] 任一 order 删除自己的 value 后，另一个仍可查询。

## 7. 验收命令

至少执行：

```bash
cd /Users/liuzhicong/project/cyfs-gateway/src
cargo test -p cyfs-sn -- --test-threads=1
cargo test -p cyfs_gateway smoke_acme_sn_device_add_txt_unattended \
  -- --nocapture --test-threads=1
cargo test -p cyfs_gateway -- --test-threads=1
```

如果 smoke 被标记为 ignored：

```bash
cd /Users/liuzhicong/project/cyfs-gateway/src
cargo test -p cyfs_gateway smoke_acme_sn_device_add_txt_unattended \
  -- --ignored --nocapture --test-threads=1
```

Scheduler 回归：

```bash
cd /Users/liuzhicong/project/buckyos/src
cargo test -p scheduler test_update_node_gateway_config_keeps_acme_and_zone_tls_hosts \
  -- --nocapture
```

实际 crate 名或 test filter 若有差异，CodeAgent 应先用 `cargo metadata` / `cargo test
-- --list` 确认并更新本文，不能留下不可执行的验收命令。

## 8. 完成定义

以下条件全部满足才可以关闭本 TODO：

- [ ] 生产 ACME provider 默认使用设备私钥签发短期 `sn-device` token。
- [ ] SN 对 token 完成签名、时效、zone/device 和权威公钥锚定校验。
- [ ] Device DNS 权限严格限制到所属 zone 的 ACME TXT challenge。
- [ ] 无用户 access token、无密码、无人工登录时 add TXT 成功。
- [ ] TXT 可从真实 SN DNS query 读回。
- [ ] 同名多值不会覆盖或误删。
- [ ] smoke test 和定向回归通过。
- [ ] 没有在日志、配置或测试产物中泄漏设备私钥/JWT。
- [ ] `SN-Auth.md`、`SN-API.md` 和相关配置说明与最终行为一致。
