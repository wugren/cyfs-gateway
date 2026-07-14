# SN-Auth

`sn_auth` 是 SN 的账号与低频用户状态模块。它负责 SN 本地账号体系、登录态、`sn_user <-> user_domain` 绑定关系，以及不适合放入 BNS 权威文档的 `zone_info` 运行态。

当本文和当前实现冲突时，以 `新SN核心流程整理.md` 中的设计意图为准；BNS 写路径与签名边界以 `../BNS/BNS-签名边界改造-EVM-TX-TODO.md` 为准。当前实现只作为差距对照，不作为兼容约束。本版本是 breaking change，不要求兼容旧 RPC alias、旧 token 语义或旧 `user_domain` 绑定方式。

## 设计定位

`sn_auth` 负责：

- 用户名、唯一绑定的电子邮箱、密码凭证、激活码和登录 token。
- `sn_user` 的本地状态，例如 active、suspended、deleted、banned。
- `sn_user <-> user_domain` 的绑定关系、历史冲突检查和 PKX proof 状态。
- `zone_info` 中的本地运行态，例如 `self_cert`、当前 `relay_sn` 分配结果、历史实现中的 `sn_ips`。
- 为 `sn_authority` 提供 SN 登录 token 的签发和校验基础。
- 为 `sn_resolver` 提供非 BNS 域名到 `sn_user` 的映射。
- 为 SN Admin 提供激活码管理、传统账号冻结、密码恢复等本地账号能力。

`sn_auth` 不负责：

- BNS name、owner key、controller key、controller policy 的权威状态。
- 发布 BNS `zone`、`boot`、`device_mini_doc`、`dns_txt` 文档。
- 设备在线态、device IP、NAT 状态和 keep-alive 状态。
- relay 节点健康状态和 zone -> relay 调度决策。
- 把 SN 登录 token 提升为 BNS owner 权限。

这些能力分别属于 `bns-indexer`、`sn_bns_controller`、`sn_device_info`、`sn_relay_manager` 和 `sn_authority`。

## 权限原则

SN Auth 的核心权限边界是：

- SN 登录 token 只代表 `SnUser(username)`。
- `SnUser(username)` 可用于 UI 管理、账号资料、低风险本地状态查询和发起需要二次授权的流程。
- `SnUser(username)` 不天然等价于 BNS owner。
- 涉及 BNS owner 权限的操作，必须由 owner ETH 私钥、BNS authority key，或 BNS controller policy 授权的 SN controller key 完成。
- device 私钥签名 token 只能得到 `Device(zone, device_name, did)` 权限，默认不能写 BNS owner 级状态。
- 账号恢复、密码找回、激活码清理只能恢复 SN 登录能力，不能绕过 BNS owner key。

`sn_authority` 应统一验证 token 和签名，并输出权限上下文。业务模块不应散落解析 token。`sn_auth` 只负责签发/存储 SN 用户会话和提供账号资料。

## 设备级凭证（device token）

设备在线态上报接口（`device.register` / `device.update`）接受两种凭证：SN 账号
access token（激活/管理面，可上报该账号名下任意设备）与设备级 device token
（node_daemon 周期上报，只能上报凭证锚定的那台设备）。device token 由设备私钥
签名，`sn_authority::require_sn_device` 校验后输出
`AuthContext::Device { zone, device_name, did }`（2026-07 落地）。

token 形状（签发方 `cyfs_gateway_api::generate_sn_device_token`，BuckyOS 侧
node_daemon 经该 helper 生成）：

- `sub`: 设备 key DID（`did:dev:<ed25519-x>`），公钥内嵌，签名自证持有设备私钥。
- `iss`: 设备的 zone 域名层级 DID（如 `did:bns:ood1.alice`、`did:web:ood1.charlie.me`）。
- `aud`: `sn-device`。与账号 token 的 `sn` 域隔离：`verify_access_session` 拒绝
  `sn-device`，`require_sn_device` 拒绝非 `sn-device`，两类 token 互不通用。
- `exp`: 短期有效（客户端默认 10 分钟，服务端硬上限 24h）。

校验链（sn_authority.rs `require_sn_device`）：

1. `aud` 必须是 `sn-device`；`sub` 必须是合法 `did:dev`（x 可解码为 32 字节
   ed25519 公钥），用 `sub` 内嵌公钥验 EdDSA 签名与 `exp`。
2. `iss` 经 `registered_device_key_from_did` 解析为 (zone, device_name)：
   `did:bns:<dev>.<短名>` → username；`did:bns:<dev>.<带点域名>` / `did:web:*`
   → `user_domain` 反查。
3. zone 用户存在且 state=active。
4. 信任锚定：`SnResolver::resolve_zone_device_did(zone, device_name)` 读取 zone
   权威侧登记的设备身份（BNS `<dev>.<zone>` 单文档 → zone 级 `device_mini_doc`
   聚合 → zone doc devices → 兼容 devices 表/在线索引），其公钥必须与 `sub`
   一致。锚定不上即拒绝：不做 TOFU，"第一个来报的 key"不能自动成为设备身份。

权限边界：Device 上下文只能上报凭证锚定的那台设备（`api/device.rs`
`ReportIdentity::enforce_reported_device` 强制 device_name/DID 一致），不能访问
账号面接口（`device.get` / `device.list` 等仍要求 SnUser）。设备的首次登记仍由
激活流程的账号 token 或 BNS 文档发布完成，device token 不承担登记职责。
e2e 覆盖见 sn_server.rs `test_sn_device_token_report_paths`。

## 核心对象

### sn_user

`sn_user` 是 SN 本地账号。`username` 同时通常映射到 BNS name，但 BNS name 的权威所有权仍在 BNS。

目标字段：

- `username`: 规范化后的唯一用户名。
- `email`: 规范化后的必填电子邮箱；一个邮箱地址只能绑定一个 `sn_user`，用于账号识别和密码找回。
- `state`: `active | suspended | deleted | banned`。
- `bns_name`: 绑定的 BNS name，默认等于 `username`。
- `activation_code`: 注册或测试清理使用的许可码。
- `owner_key_ref`: 本地缓存的 owner public key 或 key id，仅用于 UI 状态和签名校验辅助。
- `created_at` / `updated_at` / `last_login_at`。

当前实现映射：

- `src/components/cyfs-sn/src/sn_auth.rs` 的 `users` 表已含 `email` 及现有目标字段：`username`、`state`、`bns_name`、`public_key`、`activation_code`、`owner_key_ref`、`zone_config`、`self_cert`、`user_domain`、`sn_ips`、`created_at`、`updated_at`、`last_login_at`。
- `state` 枚举（active/suspended/deleted/banned）已建模（sn_auth.rs:21-53）。
- `public_key` 当前存 JWK 字符串，未来应视为本地缓存，不作为 BNS authority 的最终来源。
- 已完成：`SNUserInfo` 和 `users` 表已增加 `email`，新注册统一 trim + ASCII lowercase 并校验基本格式，数据库部分唯一索引保证规范化邮箱与账号一对一绑定。迁移时存量账号暂保留 `NULL`，等待后续可信邮箱补录流程；不允许通过公开注册接口创建无邮箱账号。
- 待实现（阶段二）：`owner_key_ref` 列虽已建，但所有 insert 路径都置 NULL，从不写入（sn_auth.rs:1041、1206）；`public_key` 仍是事实上的 owner key 来源。

### password_credential

密码凭证属于 SN 本地账号体系。

目标字段：

- `username`
- `password_hash`
- `password_salt`
- `password_algo`
- `created_at`
- `updated_at`
- `last_login_at`

当前实现（阶段一已完成）：

- `user_auth` 表保存上述全部字段（sn_auth.rs:316-324）。
- V2 使用 `pbkdf2-sha256-100000`，salt 为 16 字节随机值，hash 为 32 字节结果的 hex（sn_auth_manager.rs:16-17、97-101、195-210）。

服务端不得存储明文密码。RPC 参数名里历史上使用 `pwd_hash`，但当前 V2 实际会把该值再次 PBKDF2 后保存（register/login 直接把 `pwd_hash` 喂给 `hash_password`/`verify_password`，auth.rs:71、116）；后续接口命名应澄清为 `password` 或明确客户端预哈希语义，避免“双 hash”语义不清。

### account_session

SN 登录态是 `SnUser(username)` 的证明。

目标字段和约束：

- `sub`: username。
- `aud`: access token 使用 `sn`，refresh token 使用 `sn-refresh`。
- `exp`: access token 短期有效，refresh token 较长有效。
- `kid`: token signing key id，便于后续 key rotation。
- `session_id` 或 `jti`: 便于 logout、撤销和审计。

当前实现（session 撤销已接线，2026-07 完成）：

- `SnAuthManager` 使用 Ed25519 key 签发 JWT，`sub`=username、`aud`=`sn`/`sn-refresh`、`exp`、`jti`=16 字节随机 hex（即 session_id；sn_auth_manager.rs:13-16、75-99、151-204）。
- access token 默认 1 小时，refresh token 默认 24 小时。
- token key 存在 `sn_token_key/private_key.pem` 和 `public_key.json`。
- 签发即入库：`build_auth_success_response`（register/login 共用）为 access/refresh token 各写一条 `account_sessions` 记录（auth.rs:14-53）；`auth.refresh` 为新签发的 access token 同样入库（auth.rs:233-266）。
- 校验路径检查撤销：V2 鉴权统一走 `require_account_username` → `sn_authority::require_sn_user` → `validate_account_session`（common.rs:177-186；sn_authority.rs:25-43、57-91）。session_id 优先取 `jti`，无 `jti` 的历史 token 回落 SHA-256(token)（`sn_authority::session_id`，sn_authority.rs:45-55）。库中有记录时强校验 state=active、未过期、subject 一致；库中无记录的合法签名 token 放行（黑名单语义，兼容库外历史 token）。`auth.refresh` 经 `validate_refresh_session` 受同样检查（auth.rs:238-243），refresh session 被撤销后无法再换发 access token。
- `auth.logout` 撤销 access session（req.token）与可选传入的 refresh session（params.refresh_token），无效 token 忽略、best-effort 返回成功（auth.rs:267-297）。
- DB 层：`account_sessions` 表（sn_auth.rs:741-760），`create_account_session`/`revoke_account_session`/`revoke_user_sessions`/`get_account_session`（sn_auth.rs:2125-2218）；`set_user_state` 置非 active 时自动撤销该用户全部 session（sn_auth.rs:1662-1675），配合校验路径即账号冻结即时生效。
- 待实现（阶段二）：token 不含 `kid`（`generate_jwt` 的 kid 参数恒为 None，sn_auth_manager.rs:172），key rotation 未实现，仍是单一静态 Ed25519 key pair。

### user_domain

`user_domain` 是传统 DNS 域名到 `sn_user` 的绑定关系，暂归 `sn_auth` 管理。

目标字段：

- `domain`: 规范化域名，去掉尾部 `.`，统一小写。
- `owner`: 绑定的 `sn_user`。
- `state`: `active | revoked | superseded`。
- `pkx`: 期望在传统 DNS 中看到的 `PKX(sn_user.pkx)`。
- `pkx_record_name`: 按 PKX 规范计算出的 DNS TXT name。
- `verified_at`
- `created_at` / `updated_at`

PKX 是 `user_domain` 唯一的证明方法。它不是一次性随机挑战，也不需要 nonce 或过期时间。用户在传统 DNS 中写入稳定的 PKX 记录；SN 后续接管该域名 DNS 基础设施后，也继续写入同一个 PKX，因此绑定证明不会因为挑战记录切换带来解析抖动。Beta2.2 是 breaking change，目标流程不保留“先占 pending 再验证”的历史包袱：谁当前能控制 DNS TXT，谁就能完成绑定或接管。

当前实现映射（阶段二一站式绑定已完成）：

- `user_domain_bindings` 是权威来源：`id` 主键 + 「同一 domain 至多一行 active」的部分唯一索引，state 取值 `active | revoked | superseded`（sn_auth.rs:675-724、14-16）；旧 `domain` 主键 / `pending_pkx` schema 在启动时自动迁移重建，`pending_pkx` 行直接丢弃（sn_auth.rs:855-919）。
- `users.user_domain` 只作兼容/主域名缓存；supersede 接管时事务内同步清空旧 owner 的同名缓存（sn_auth.rs:1013-1119），后续可考虑移除该缓存字段。
- `user_domain_history` 改为追加式审计事件表（每次绑定获得记一行），不参与任何冲突判定（sn_auth.rs:644-672）。
- 统一 helper：`canonical_user_domain`（去 `*.` 前缀、小写、去尾点）、`pkx_record_name`、`pkx_source_of`（JWK JSON / `PKX=<x>` / 裸值 → `sn_user.pkx`）、`pkx_value`、`txt_matches_pkx`（sn_auth.rs:24-100），全部为模块级 pub 函数，DB 层 / RPC 层 / DNS proof 层共用。
- 一站式 `domain.bind` RPC：服务端主动查外部 DNS TXT，命中后调用 `activate_user_domain_binding` 在同一事务内激活（api/domain.rs:62-153；sn_auth.rs:1876-1927）。两阶段的 `domain.begin_verify` / `domain.verify` 已删除。
- 外部 DNS proof path：`sn_dns_proof.rs` 的 `DnsTxtResolver` trait + `DohDnsTxtResolver`（默认 `https://dns.google/dns-query`，RFC 8484；`pkx_doh_url` 配置可替换，path 以 `/resolve` 结尾时走 dns.google JSON API）。
- 期望 `PKX(sn_user.pkx)` 来源：`did:bns:<username>` 链上 owner document / authority key 优先（owner_config key → effective_owner key），链已配置但暂不可达时返回可重试错误而不静默回落；名字不在链上时回落本地 `users.public_key`，无 owner key 的账号回落确定性 `sn-user:<username>` 标签（sn_server.rs:707-770，`expected_user_domain_pkx`）。

### zone_info

`zone_info` 是 SN 本地运行态缓存，不是 BNS 权威文档。

目标字段：

- `username` / `bns_name`
- `zone`: zone name 或 DID。
- `relay_sn`: 当前分配的 relay SN。
- `self_cert`: 当前是否有可用自签/ACME 证书。
- `cert_checked_at` / `cert_expires_at`
- `sn_ips`: 历史实现中的 SN IP 列表，迁移期可作为数据来源。
- `source_version`: 从 BNS `zone`/`boot` 更新缓存时使用的版本信息。
- `updated_at`

当前实现映射（阶段一已完成）：

- 已新增独立 `zone_info` 表，含全部目标字段 `username`、`bns_name`、`zone`、`relay_sn`、`self_cert`、`cert_checked_at`、`cert_expires_at`、`sn_ips`、`source_version`、`updated_at`（sn_auth.rs:365-380）。
- `get_zone_info`/`update_zone_info`（patch 语义）与从 `users` 回填的 backfill 已实现（sn_auth.rs:1883-2014、548-600）。
- 兼容期 `update_zone_info` 仍会把 `zone`/`self_cert`/`sn_ips` 双写回 `users` 表（sn_auth.rs:1993-2008）。
- `users.zone_config` 当前仍保存旧 `zone_config`/boot JWT。目标架构中，`zone` 和 `boot` 应进入 BNS 文档，`sn_auth` 只保存必要运行态缓存。

## 数据归属

属于 `sn_auth` 的数据：

- 激活码及使用状态。
- SN 用户、唯一邮箱绑定、密码凭证、密码找回状态和登录态元数据。
- 用户状态、传统账号恢复状态、冻结/解冻状态。
- `user_domain` 绑定、历史冲突记录和 PKX proof 状态。
- `zone_info` 本地运行态，例如 `self_cert`、`relay_sn`、`sn_ips`。

不属于 `sn_auth` 的数据：

- BNS owner/controller authority key。
- BNS controller policy。
- BNS `zone`、`boot`、`device_mini_doc`、`dns_txt` 文档。
- 设备在线态和可达 IP。
- relay 健康状态和调度策略。

## 注册流程

### 注册 SN 用户和 BNS owner

目标输入：

- `username`
- `email`，必填；规范化后必须全局唯一。
- owner public keys，至少包含 BNS/ETH owner key 和后续文档签名所需 key。
- `owner_config`
- `password` 或明确约定的 password credential。
- `active_code`
- `request_id`，作为注册幂等 key。

目标流程：

1. `sn_auth` 规范化并校验 `username`。
2. `sn_auth` trim、规范化并校验 `email` 基本格式。
3. `sn_auth` 检查 `active_code` 未使用。
4. `sn_auth` 检查本地账号和规范化邮箱都不存在。
5. `sn_bns_controller` 构造并用托管 owner/controller 私钥签名 BNS 合约注册 TX，经 BNS-Server 提交 raw TX 创建 BNS name。
6. BNS 创建阶段同步发布 owner_config，并设置 SN controller key 和受限 controller policy。
7. BNS 注册成功后，`sn_auth.register` 在一个本地事务中写入 `sn_user`、唯一邮箱绑定和 `password_credential`，并标记激活码已使用。
8. 返回 access token、refresh token 和 BNS name 状态。

一致性要求：

- BNS 注册请求必须有幂等 key。
- `sn_auth` 本地写入必须是事务性的。
- 邮箱唯一性必须由数据库唯一约束兜底；两个并发注册不能把同一个规范化邮箱绑定给不同账号。
- 如果 BNS name 已存在但 `sn_auth` 未完成，应进入明确恢复流程：继续补齐本地账号，或由 admin 标记人工处理。
- 不能出现本地账号注册成功但 BNS name 未创建、且系统误认为用户拥有 BNS owner 权限的状态。

当前实现：

- 阶段一已完成：`register_user` 在命名锁下用事务完成 `users`、`user_auth`、`zone_info`、`activation_codes.used` 的一致写入（sn_auth.rs:989-1091），返回 access+refresh token 并提示 `need_bind_owner_key=true`（auth.rs:89）。
- 已完成：`auth.register`/`register_user` 接收并保存规范化 `email`，服务端和客户端 DTO、schema 迁移、数据库唯一索引、稳定冲突错误和并发测试均已落地。注册邮箱暂不做验证码或所有权验证。
- 待实现（阶段二）：V2 `auth.register` 只写本地 DB，没有调用 `sn_bns_controller` 提交 BNS 合约注册 TX（`bns_indexer_url` 只接入了 resolver 读路径，sn_server.rs:688-693），没有 `request_id` 幂等 key，也没有“BNS name 已存在但本地未完成”的恢复流程。

### public key 注册

当前实现中的 `user.register_by_public_key` / `register_user` 支持：

- `user_name`
- `public_key`
- `active_code`
- 可选 `zone_config`
- 可选 `user_domain`

该路径不作为新版本目标接口保留。新架构中，注册 BNS owner 必须走完整的 BNS 注册流程；`public_key` 本地写入不能替代 BNS authority key。

## 登录流程

目标输入：

- `username`
- `password`

目标流程：

1. 规范化 `username`。
2. 查询 `password_credential`。
3. 校验用户存在且状态为 `active`。
4. 校验密码。
5. 更新 `last_login_at`。
6. 签发 access token 和 refresh token。
7. 返回 `need_bind_owner_key`、profile 摘要和必要的 BNS name 状态。

当前实现：

- 阶段一已完成：V2 `auth.login` 不再依赖 `active_code`。`LoginReq.active_code` 已改为可选且 login 分支从不读取它，只做用户 active 校验 + 密码校验 + 更新 `last_login_at`（auth.rs:91-133，common.rs:39-45）。`need_bind_owner_key` 由 `public_key` 是否为空推导。
- 阶段二已完成（2026-07）：`auth.logout` 基于 `jti` 撤销 access 与 refresh session，签发/刷新/校验路径均已接 `account_sessions`（见 account_session 小节）。

## 密码找回流程

本版本要求支持密码找回。注册时保存的唯一规范化邮箱是账号定位与找回通知地址，但邮箱地址本身不是授权凭证。

目标要求：

1. 按规范化邮箱查询唯一 SN 账号；对外响应不得泄露该邮箱是否已注册。
2. 生成短时、一次性的密码重置凭证，并通过受控邮件通道交付。
3. 消费重置凭证时更新 `password_credential`，使该凭证立即失效，并撤销该账号现有 access/refresh sessions。
4. 密码找回只能恢复 SN 登录能力，不能修改或轮换 BNS owner key、controller key 或 controller policy。

TODO（本版本）：定义密码找回 RPC、重置凭证 schema/过期与单次消费规则、邮件投递接口、限流与审计，并完成端到端测试。本版本注册流程不要求邮箱验证码或注册时邮箱所有权验证；在重置凭证交付机制完成前，禁止仅凭 `username + email` 直接重置密码。

## owner key 绑定

`user.bind_owner_key` 当前把 JWK public key 写入 `users.public_key`。

目标语义：

- 首次绑定 owner key 可以作为注册后补齐资料流程的一部分。
- 绑定后的 key 用于客户端签名校验和 UI 状态展示。
- BNS authority key 的权威来源必须是 BNS，不是 `users.public_key`。
- owner key rotation 必须走 BNS authority/controller 机制，不能只更新 `users.public_key`。

当前接口可继续保留，但涉及 BNS 文档写入时必须通过 `sn_authority` 得到 `Owner(name)` 或 `Controller(name, doc_type_scope)`。

## bind zone

目标输入：

- `zone_config`
- `zone_boot_config`
- owner 签名，或可由 `sn_authority` 映射为 owner authority 的 token。

目标流程：

1. `sn_authority` 校验 owner 权限。
2. `sn_bns_controller` 校验 `zone_config` 和 `zone_boot_config` 的签名与内容一致性。
3. 发布 BNS `zone` document。
4. 发布 BNS `boot` document。
5. 根据 zone/boot 内容更新 `sn_auth.zone_info` 中的运行态缓存。

`sn_auth` 在该流程中只负责最后一步的本地运行态缓存更新，不负责判断 BNS owner 权限，也不直接发布 BNS 文档。

当前实现差异（待实现项归阶段二）：

- V2 `zone.bind_config` 要求 SN access token 和本地 `public_key` 已绑定，然后直接更新 zone_info/`users.zone_config`（zone.rs:31-53）。这里的“owner”只是本地 `public_key`，不是 BNS authority。
- 旧 `bind_zone_config` 使用 owner public key 验证 RPCSessionToken（sn_server.rs:1114-1132 等），但校验仍偏简化。
- 绕过风险（阶段二待修）：`zone.bind_config` 仍可同时写 `user_domain` 且不强制 PKX proof，`update_user_domain` 直接把 binding 置 `active`（zone.rs:46-52，sn_auth.rs:1418-1519）；`register_user_with_owner_key` 同样无证明就插入 `active` binding（sn_auth.rs:1240-1263）。
- 当前没有发布 BNS `zone` / `boot` 文档。
- 当前 `zone_config` 字段应视为历史 boot JWT 字段，目标上应由 BNS 权威文档替代。

## user_domain 绑定和 PKX proof

`user_domain` 用于把非 BNS 的传统 DNS 域名绑定到 `sn_user`。该绑定属于 `sn_auth`，但必须证明传统 DNS owner 同意绑定。

### 绑定输入

- `username`
- `domain`
- 当前登录态 `SnUser(username)`

### 目标流程

1. 用户先在传统 DNS 中配置 `pkx_record_name = _pkx.<canonical-domain>` 的 TXT。
2. 用户调用 `domain.bind(domain)`，SN 规范化 `domain`：去尾点、小写、去掉可选 `*.` 前缀得到 canonical domain。
3. SN 检查当前登录 `sn_user` 存在且状态为 `active`。
4. SN 从 `did:bns:<username>` 对应的链上 owner document / authority key 中读取期望的 `PKX(sn_user.pkx)`；绑定流程不提供修改 PKX 的入口，也不从待绑定的 `user_domain` 反查权威身份。
5. SN 通过服务端侧外部 DNS 查询能力读取 `pkx_record_name` 的 TXT 并校验：
   - TXT 出现在 PKX 规范要求的 DNS name。
   - TXT 值等于当前 `sn_user` 的 `PKX(sn_user.pkx)`。
6. 校验失败时返回明确错误，包含待配置的 `pkx_record_name` 和期望 `pkx`；不写入或修改 active binding。
7. 校验成功后，在同一事务内把同一 canonical domain 的旧 active binding 标记为 `superseded`，再写入当前用户的 active binding；如果旧 owner 的 `users.user_domain` 正好等于该 domain，同步清空该兼容缓存。
8. 写入 `user_domain_history` 作为审计记录，不把历史记录作为拒绝后续合法 DNS owner 接管的硬冲突。
9. 父子域名不再用历史互斥规则一刀切拒绝。SN-DNS 解析按最长 active binding 匹配：父域绑定可覆盖未单独绑定的子域；子域完成自己的 DNS proof 后可形成更具体 active binding，并优先响应。

### PKX 记录格式

PKX 记录格式只由一个统一 helper 生成和解析。`sn_auth` 不支持额外证明类型，不支持用户自定义证明载荷，不支持 nonce/exp 变种。

```text
<PKX(sn_user.pkx)>
```

`PKX(sn_user.pkx)` 的具体编码由统一 helper（`pkx_source_of` + `pkx_value`，sn_auth.rs:52-91）生成，不能由不同模块重复实现。`sn_user.pkx` 是 owner key 的公开身份：JWK 输入归一为 `x` 分量、`PKX=<x>[:...];` 形式取 `<x>`；权威来源优先 BNS owner_config / authority key（`expected_user_domain_pkx`），链上无该名字时回落本地 `users.public_key`。

PKX 记录是稳定状态，不是临时验证状态。SN 接管 DNS 基础设施后，仍应继续发布同一条 PKX 记录；这样从用户自管 DNS 迁移到 SN 托管 DNS 时，不需要替换 proof，也不会引入解析行为抖动。

### 解绑语义

解绑只取消当前 `users.user_domain` 或 `user_domain.active` 状态，不应默认删除 `user_domain_history`。历史记录仅用于审计，不用于阻止后续能通过当前 DNS TXT proof 的合法 owner 接管。

域名转让不需要旧 owner 先手工 unbind。新 owner 只要能控制传统 DNS 并发布自己的 PKX TXT，就可以调用 `domain.bind` 接管同一 canonical domain；SN 在事务内把旧 active binding 标记为 `superseded`。

active 绑定默认持续有效，不做周期性 DNS TXT 复验。用户可手工 `unbind`；解绑后 SN-DNS 不再响应该 `user_domain` 及其子域名的解析请求，除非后续重新完成绑定和验证流程。

### 当前实现差异

阶段二 user_domain TODO 已全部落地（对应实现见「当前实现映射」小节），实现上的明确取舍：

- 无 owner key 的账号（V2 密码注册、未接链）期望 PKX 回落为确定性 `sn-user:<username>` 标签：TXT 值仍能证明「DNS owner 同意绑定到该 SN 账号」的意图，保住 VM 无链部署的 user_domain 能力；账号补齐 owner key / 接入 BNS 后重新 `domain.bind` 即可升级为 key 锚定的 PKX。
- Beta2.2 不保留两阶段验证兼容入口：`domain.begin_verify` / `domain.verify` / `create_pkx_binding` / `verify_pkx_binding` 的 RPC 名已删除，统一使用 `domain.bind`。

TODO（阶段二，2026-07-06 完成）：

- [x] 将 `domain.bind` 改为一站式服务端主动验证入口：规范化域名、检查用户状态、从 `did:bns:<username>` 链上 owner document / authority key 计算 `PKX(sn_user.pkx)`，然后由 SN 自己查询 DNS TXT。→ api/domain.rs:62-153 `handle_bind` + sn_server.rs `expected_user_domain_pkx`。
- [x] 移除 `pending_pkx` 目标语义与 `domain.begin_verify` / `domain.verify` / `create_pkx_binding` / `verify_pkx_binding` RPC。→ 对应 S2S/DB 方法和兼容 alias 均已删除；旧库中的 `pending_pkx` 行随 schema 迁移丢弃。
- [x] 移除外部客户端传入 `txt_records` 作为 proof 的信任边界。→ `DomainReq` 只接受 `domain`，携带 `txt_records` 的旧请求被忽略；e2e 断言伪造 `txt_records` 不能激活绑定。
- [x] 修改冲突规则：`user_domain_history` 仅审计；同一 canonical domain 的旧 active binding 可被当前 DNS proof 成功的新 owner supersede；父子域名按最长 active binding 匹配，不因历史记录互斥。→ `check_domain_conflicts_tx` 已删除，`activate_binding_tx` 实现 supersede（sn_auth.rs:1013-1119）。
- [x] DNS 查询必须走外部 DNS proof path，不能复用 SN 自己的权威/合成解析路径，不能读取 `user_dns_records`、BNS fallback 或本地 name cache。→ 独立 `sn_dns_proof.rs` 模块，仅出站 DoH。
- [x] 默认可配置使用 Google Public DNS DoH：优先 RFC 8484 `https://dns.google/dns-query`，只做 TXT 查询时也可用 JSON API `https://dns.google/resolve?name=<pkx_record_name>&type=TXT`；实现上必须允许配置替换 resolver。→ `SNServerConfig.pkx_doh_url`（默认 RFC 8484；`/resolve` 结尾自动走 JSON API）。
- [x] DNS 查询应读取 `_pkx.<canonical-domain>` 的 TXT，支持多条 TXT、多段 TXT 拼接、引号/首尾空白归一化。→ wire 路径按 rdata 段无分隔拼接、JSON 路径 `unquote_txt_data`，比对经 `txt_matches_pkx` 归一。
- [x] 验证成功后在同一事务内 supersede 同一 canonical domain 的旧 active binding、写入当前 active binding、更新 `users.user_domain`、写入 `user_domain_history` 审计记录。→ `activate_user_domain_binding`（sn_auth.rs:1876-1927 → activate_binding_tx）。
- [x] 明确 `user_domain_bindings` 是权威来源；`users.user_domain` 只作为兼容/主域名缓存，接管时要清理旧 owner 的同名缓存，后续可考虑移除该缓存字段。
- [x] 验证失败时返回可重试错误和待配置的 `pkx_record_name` / `pkx`，不写入或修改 active binding。→ 错误码 `[SN:1016:domain_proof_failed]`，message 为含 `pkx_record_name`/`pkx`/`retryable`/`reason` 的 JSON（api/errors.rs、api/domain.rs:40-59）。
- [x] active 绑定持续有效直到用户手工 `unbind`；解绑后 SN-DNS 停止响应该 `user_domain` 及其子域名。→ unbind 只撤销 active 行；`get_user_by_domain` 只命中 active binding。
- [x] 收窄 `update_user_domain` / `register_user_with_owner_key` 的直接 active 写入语义，只允许 seed/import 等明确 trusted 路径使用。→ trait 上标注 trusted-only（sn_auth.rs:252-282），两者均不在对外 RPC 路由暴露（仅 seed 导入与 SN 内部 S2S auth-db API 使用）。
- [x] 增加测试：DNS TXT 命中后一站式 bind 成功、TXT 不匹配失败且不写 binding、同一 canonical domain 可被新 DNS owner supersede、history 不阻止接管、父子域名最长 active binding 匹配、客户端伪造 `txt_records` 不能激活绑定、unbind 后 SN-DNS 不再响应相关域名。→ DB 层 sn_auth.rs:2281-3050（supersede/audit-only/最长匹配/迁移），e2e sn_server.rs `test_sn_refactored_api_paths`（mock DoH 上的完整一站式流程），DoH 单测 sn_dns_proof.rs。

## user DNS records

当前实现有 `user_dns_records`，用于保存用户域名下的 DNS 记录：

- `(owner, domain, record_type, record)` 唯一，同名 TXT 可组成多值 RRset。
- `add_user_domain` 对同一个 value 幂等，不覆盖同名的其他 value。
- `remove_user_domain` 支持精确删除 value；整组删除仅保留给账号管理路径。
- `dns.add_record` / `dns.remove_record` 会检查 domain 是否属于当前用户可管理范围。

目标边界：

- `user_domain` 绑定关系仍属于 `sn_auth`。
- DNS 查询合成属于 `sn_resolver`。
- 对 BNS 域名的 `dns_txt` 发布应由 `sn_bns_controller` 使用 SN controller key 写 BNS 文档。
- 对传统 `user_domain` 的本地辅助记录可以继续放在 SN 本地 DB，但必须基于 active PKX 绑定授权。

域名授权规则：

- 如果用户已完成 active PKX 绑定，只能管理该 domain 或其子域名。
- 如果没有 active `user_domain`，不能通过 `user_domain` 路径管理传统 DNS 域名；但可以管理当前账号自己的 `<username>.web3.<server_host>` 及其子域。
- 不能管理其他账号的 web3 bridge 域名。除上述 bridge 兼容范围外，BNS DNS 内容仍应走 BNS `dns_txt` 或其他 BNS 文档流程。
- ACME challenge 记录应只允许写入符合该用户域名边界的 `_acme-challenge.*`，不能借设备 token 写入任意域名。
- 已通过 `sn-device` 信任链验证的设备只能增删所属 zone 边界内的 `_acme-challenge.*` TXT；请求中的 `device_did` 不参与授权，删除必须携带精确 `record` value。

`<username>.web3.<server_host>` 允许写入 SN 本地 `user_dns_records` 是过渡设计，主要避免 ACME 短期 TXT 记录触发链上发布并产生额外 gas。该调用不写 BNS 文档。未来用户不再依赖 web3 bridge 解析 `did:bns:xxx`，或传统 DNS 解析服务已广泛原生支持 `did:bns:xxx` 后，应删除这项兼容例外，使 BNS 名称的 `add_dns_record` 回归链上发布；传统 `user_domain` 记录仍保持本地授权语义。

## zone_info 更新

`zone_info` 是运行态缓存，典型更新来源：

- bind zone 成功后，从 BNS `zone`/`boot` 文档同步基础缓存。
- `sn_relay_manager` 调整 zone -> relay 分配后写入 `relay_sn`。
- `sn_acme_client` 完成证书签发后写入 `self_cert=true` 和证书时间。
- 证书校验失败或证书过期巡检时写入 `self_cert=false`。

权限要求：

- `self_cert` 不能仅因客户端声明就永久置 true；应由 ACME 成功结果、证书有效性校验或受信任 device 上报驱动。
- device 上报 `self_cert` 时，必须由 `sn_authority` 校验 device token，得到 `Device(zone, device_name, did)`。
- `relay_sn` 应由 `sn_relay_manager` 写入，用户 session token 不能直接设置。

当前实现：

- 阶段一已完成：`update_zone_info` 提供 patch 写入，`update_user_self_cert` 走该统一入口（sn_auth.rs:1407-1416、1916-2014）。
- 待实现（阶段二，绕过风险）：`user.set_self_cert` V2 用裸 access token 即可把 `self_cert` 置 true（user.rs:59-67）；DNS mutation 已停止消费客户端 `has_cert`，不会再修改 `self_cert`。
- 旧 `set_user_self_cert` 的 device-signed token 分支已随旧代码移除；`Device(zone,device,did)` 上下文现由 `sn_authority::require_sn_device` 提供（见「设备级凭证」小节），但 `user.set_self_cert` 尚未接入该上下文。
- 目标实现应把这些入口收敛到 `sn_authority + update_zone_info`，并记录审计事件。

## Admin 能力

### 激活码

目标能力：

- 生成激活码。
- 查询未使用激活码。
- 禁用或回收激活码。
- 审计激活码发放和使用。

当前实现（阶段一已完成）：

- `sn_auth.rs` 生成 32 位字母数字激活码（sn_auth.rs:417-425、857-883）。
- `check_active_code` 判断 code 存在且未使用（sn_auth.rs:885-893）。
- `register_user` 成功后在事务内标记 `used=1`（sn_auth.rs:1080）。
- `clear_state_by_active_code` 可事务化删除该激活码关联用户、设备、DNS 记录、DID 文档、session、binding、zone_info 并重置激活码（sn_auth.rs:895-987）。

`clear_state_by_active_code` 更像测试/运维清理接口，不应作为普通产品能力暴露给终端用户。

### 传统账号安全

属于 `sn_auth` 的传统账号安全能力包括：

- change password。
- password reset（本版本要求，使用注册时唯一绑定的邮箱定位账号）。
- 账号冻结/解冻。
- 登录失败次数、限流和风险控制。
- session 撤销。

这些能力只影响 SN 登录能力，不影响 BNS owner 权限。

当前实现状态：账号冻结/解冻已实现（`set_user_state`，sn_auth.rs:1662-1675，置非 active 时撤销该用户全部 session），session 撤销已接线并在校验路径即时生效（见 account_session 小节）。注册邮箱唯一绑定已实现；TODO（本版本）：password reset 尚未实现，change password、登录失败次数/限流/风控也仍缺失。验证码逻辑不在本轮要求内。

## 对外查询

`sn_auth` 应提供给其他模块的查询能力：

- 根据 username 获取 SN 用户基础资料。
- 根据 username 获取当前 `zone_info`。
- 根据 `user_domain` 或其子域名找到 owner `sn_user`。
- 查询某用户可管理的传统 DNS records。
- 校验 active code 是否可用。
- 校验/刷新 SN session token。

`sn_resolver` 消费这些能力时，应把 `sn_auth` 返回的结果与 BNS 文档、`sn_device_info` 在线态、`sn_relay_manager` 分配关系合成最终解析结果。`sn_auth` 不直接承担 DNS resolver。

## API 建议

模块内部 API 可以按以下方向收敛：

```rust
trait SnAuthStore {
    async fn check_active_code(&self, code: &str) -> Result<bool>;
    async fn register_user(&self, req: RegisterSnUserRequest) -> Result<RegisterSnUserResult>;
    async fn get_user(&self, username: &str) -> Result<Option<SnUser>>;
    async fn get_user_by_email(&self, normalized_email: &str) -> Result<Option<SnUser>>;
    async fn get_user_by_domain(&self, domain: &str) -> Result<Option<SnUser>>;
    async fn set_user_state(&self, username: &str, state: UserState) -> Result<()>;

    async fn get_password_credential(&self, username: &str) -> Result<Option<PasswordCredential>>;
    async fn update_password_credential(&self, username: &str, credential: PasswordCredential) -> Result<()>;
    async fn update_last_login(&self, username: &str, ts: u64) -> Result<()>;

    /// 外部 DNS PKX proof 成功后的激活入口（proof 由调用方完成）。
    async fn activate_user_domain_binding(&self, username: &str, domain: &str, pkx: &str) -> Result<DomainBinding>;
    async fn unbind_user_domain(&self, username: &str, domain: &str) -> Result<()>;

    async fn get_zone_info(&self, username: &str) -> Result<Option<ZoneInfo>>;
    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> Result<()>;
}
```

RPC 层可以使用 breaking API，不要求保留旧 method alias。内部不应让每个 handler 自己解析权限：

- `auth.register`
- `auth.login`
- `auth.refresh`
- `auth.logout`
- `auth.me`
- TODO：密码找回申请和重置 RPC（具体 method 名及参数在实现前定稿）
- `user.bind_owner_key`
- `user.get_owner_key`
- `user.get_profile`
- `zone.get`
- `zone.bind_config`
- `domain.bind`（一站式绑定）
- `domain.unbind`
- `dns.add_record`
- `dns.remove_record`
- `dns.list_records`
- `admin.clear_state_by_active_code`

其中 `zone.bind_config`、BNS DNS TXT 写入、owner key rotation 等涉及 BNS 权限的接口，必须先经 `sn_authority` 和 `sn_bns_controller`。

## 当前实现对照

### 阶段一已完成（数据层 / 状态机重写）

`src/components/cyfs-sn/src/sn_auth.rs` 已实现：

- `SnAuthDB` trait（sn_auth.rs:144-247）。
- SQLite 初始化 `activation_codes`、`users`、`user_auth`、`user_domain_history`、`user_domain_bindings`、`zone_info`、`account_sessions`（sn_auth.rs:282-408）。
- 32 位随机激活码生成、查询、写入（sn_auth.rs:417-425、835-893）。
- `register_user` 事务化注册（含 zone_info 写入与激活码标记）。
- `create_auth`、`get_user_info`、`get_user_by_domain`、`get_auth`、`update_last_login`、`set_user_state`。
- user_domain 绑定 DB 层（阶段二重写）：`activate_user_domain_binding`/`unbind_user_domain` + supersede 事务（`activate_binding_tx`，sn_auth.rs:1013-1119、1876-1960）；history 仅审计，无冲突检查。
- 独立 `zone_info`：`get_zone_info`/`update_zone_info`/`update_zone_relay_sn` + backfill（sn_auth.rs:1883-2041、548-600）。
- `account_sessions` 撤销表方法：`create_account_session`/`revoke_account_session`/`revoke_user_sessions`/`get_account_session`（sn_auth.rs:2125-2218），签发/校验/登出路径已接线（见 account_session 小节）。
- `clear_state_by_active_code`，包含可选清理旧 `devices`、`user_dns_records`、`did_documents`（sn_auth.rs:895-987）。

相关实现分散在：

- `src/components/cyfs-sn/src/sn_auth_manager.rs`: 密码 PBKDF2、Ed25519 JWT 签发/校验。
- `src/components/cyfs-sn/src/api/common.rs`: username/public key 规范化、token 解析 helper。
- `src/components/cyfs-sn/src/api/auth.rs`: `auth.*` RPC。
- `src/components/cyfs-sn/src/api/zone.rs`: `zone.get`、`zone.bind_config`。
- `src/components/cyfs-sn/src/api/user.rs`: owner key、profile、self_cert。
- `src/components/cyfs-sn/src/api/dns.rs`: user DNS records。
- `src/components/cyfs-sn/src/sn_server.rs`: RPC 路由、旧 alias 兼容、device-signed token 校验。
- `src/components/cyfs-sn/src/sqlite_db.rs`: 兼容期 `SnDB` SQLite 实现，包含 devices、DNS records、DID documents。

### 阶段二待实现（主要差距）

- `sn_authority` 统一鉴权上下文尚不完整：已有 `AuthContext::SnUser`（含 session 撤销校验，V2 统一走 `require_account_username`→`sn_authority::require_sn_user`，common.rs:177-186）与 `AuthContext::Device(zone,device,did)`（2026-07 落地，见「设备级凭证」小节，device.register/update 经 `require_sn_user_or_device` 接入），但 `Owner(name)`/`Controller(name,scope)` 上下文仍不存在，旧接口仍各自 `RPCSessionToken::from_string(...).verify_by_key(...)`（sn_server.rs:1114-1132 等）。
- 注册流程还没有和 `sn_bns_controller` 提交 BNS 合约注册 TX 串成一个幂等流程（无 `request_id`，无 BNS owner 创建/恢复）。
- ~~PKX proof 在 DB 层已实现但无 RPC handler、无 DNS TXT 查询接线，端到端不可达。~~ 已完成：一站式 `domain.bind` + 外部 DoH proof path（见 user_domain 小节）。
- ~~绕过风险：`register_user_with_owner_key` 能不经 proof 把 `user_domain` 置 active~~ 已收窄为 seed/import trusted 路径（不在对外 RPC 暴露）；`self_cert` 仍可被 `dns.*` 的 `has_cert=true` 置 true（无证书校验），待收敛。
- owner 权限仍是“本地 `public_key` = owner”，不是 BNS authority；`owner_key_ref` 列从不写入。
- ~~`auth.logout` 与 session 撤销表已建但未接线~~ 已接线：签发/刷新写 `account_sessions`、校验查撤销、logout 撤销 access+refresh session（见 account_session 小节）；剩余待办：token 无 `kid`、key rotation 未实现。
- 注册邮箱已完成：`users`/`SNUserInfo`/注册 DTO 已有 email，并实现规范化、格式校验、唯一索引、按邮箱查询、存量数据兼容迁移和并发测试；TODO（本版本）：密码找回 RPC、重置凭证和邮件投递仍未实现。
- 传统账号安全仍缺失：change password、登录失败限流/风控未实现。
- `zone.bind_config` 还没有发布 BNS `zone` / `boot` 文档。

## 迁移步骤

阶段一已完成：

1. ~~引入明确的 `zone_info` 数据结构~~：已落地独立 `zone_info` 表（sn_auth.rs:365-380）。
2. ~~为 `user_domain` 增加 PKX 绑定表和 PKX TXT 校验流程~~：已完成，并在阶段二重写为一站式服务端 proof（`user_domain_bindings` id 主键 schema + `domain.bind` + `sn_dns_proof.rs`）。
3. ~~调整 `auth.login`，去掉普通登录对 `active_code` 的依赖~~：已完成（auth.rs:91-133）。
4. ~~给 PKX 绑定加 RPC handler 与 DNS TXT 查询接线，使端到端可达；并堵住无证明置 active 的绕过~~：已完成——一站式 `domain.bind`（服务端外部 DoH 查询 + 事务激活），客户端 `txt_records` 不再被信任，`update_user_domain` / `register_user_with_owner_key` 收窄为 seed/import trusted 路径。

阶段二已完成：

5. ~~把 session 签发/校验接到 `account_sessions`，使 `auth.logout` 和账号冻结立即生效~~：已完成（2026-07）——签发/刷新路径写 `account_sessions`（token 含 `jti`），校验路径经 `sn_authority::validate_account_session` 检查撤销与过期，`auth.logout` 撤销 access+refresh session，账号冻结即时生效；`kid`/key rotation 仍为待办（见 account_session 小节）。

阶段二待办：

6. 把 `zone.bind_config` 拆成 owner authority 校验、BNS document 发布、`zone_info` 缓存更新三段。
7. 引入 `sn_authority` 统一鉴权上下文，把 BNS 修改类请求统一接入，禁止业务 handler 自行把 SN access token 当 owner token 使用。（部分完成：`Device` 上下文已落地并接入 device.register/update；`Owner`/`Controller` 仍待实现。）
8. 把 `self_cert` 更新入口收敛为可信 ACME/device 上报 + 证书校验，并记录来源和审计日志。
9. 注册强制传入 email、规范化邮箱唯一绑定、迁移和并发测试已完成；TODO（本版本）：实现基于该绑定的 password reset（不含注册邮箱验证码），重置后撤销现有 sessions。
10. 补齐其余传统账号安全（change password、限流），并写入 `owner_key_ref`。
11. 删除旧 RPC method alias 或让旧 alias 显式失败，内部只走新的 authority 和 store API。
