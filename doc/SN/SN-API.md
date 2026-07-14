# SN-RPC-API

本文定义当前 `cyfs-sn` 对外暴露的 SN RPC API。除明确标记为 TODO 的本版本目标外，本文以现有实现为准：

- 服务端路由：`src/components/cyfs-sn/src/sn_server.rs`
- RPC handler：`src/components/cyfs-sn/src/api/*.rs`
- BNS proxy 编排/签名：`src/components/cyfs-sn/src/sn_bns_proxy.rs`、`src/components/cyfs-sn/src/sn_bns_signer.rs`
- Rust 客户端：`src/components/cyfs-gateway-api/src/sn_client.rs`

SN RPC 负责账号会话、user_domain 相关本地记录、设备在线运行态、OOD 连接信息查询，以及一个受限的 BNS 写代理（bns-proxy，见第 6 节）。BNS 的完整读写能力仍由独立 BNS API / `bns-client` 承担；bns-proxy 只覆盖 SN 产品路径需要的代付 gas 操作，包括注册后独立发布内容型 document，不提供自选 authority、任意 calldata、revoke 或 policy 管理能力。

## 1. 传输模型

协议为 kRPC over HTTP。请求体是 kRPC `RPCRequest`，常用字段如下：

```json
{
  "method": "auth.login",
  "params": {},
  "token": "optional access token",
  "seq": 1,
  "trace_id": "optional trace id"
}
```

成功响应里的业务 payload 是 `RPCResult::Success` 的值。除特别说明外，成功 payload 带 `"code": 0`。错误响应为 `RPCResult::Failed(string)`；SN 业务错误字符串通常带 `[SN:<code>:<name>]` 前缀。

RPC method 必须使用 `namespace.method` 形式。当前实现不再做 legacy 裸方法名归一化。

## 2. 路径与职责

| HTTP path | 公开性 | 职责 | 方法 |
|-----------|--------|------|------|
| `/kapi/sn` | 公网 | SN 命名空间根，不承载 RPC 方法 | 无 |
| `/kapi/sn/auth` | 公网 | 账号、会话、user/zone profile、user_domain、user DNS record | `auth.*`、`user.*`、`zone.*`、`domain.*` |
| `/kapi/sn/deviceinfo` | 公网 | 设备在线态上报、在线态查询、OOD 连接信息解析 | `device.*`、`deviceinfo.*` |
| `/kapi/sn/bns-proxy` | 公网 | SN 代付 gas 的受限 BNS 写代理 | `bns.publish_dns_txt`、`bns.publish_document` |
| `/` | 内网/管理面 | 运维管理、bns-proxy 内部/恢复方法 | `admin.clear_state_by_active_code`、`bns.publish_relay_assignment`、`bns.register_name_bootstrap` |

路径是强约束。方法发到非首选路径会返回 unknown method，例如 `auth.check_username` 不能再发到 `/kapi/sn`；`bns.publish_relay_assignment` / `bns.register_name_bootstrap` 不能发到 `/kapi/sn/bns-proxy`，只能发到内网 `/`。

## 3. 认证规则

- `auth.check_username`、`auth.check_active_code`、`auth.register`、`auth.login`、`auth.refresh` 不需要 access token。
- `auth.logout` 可同时吊销请求里的 access token 和参数里的 refresh token。
- `auth.me`、`user.*`、`domain.*`、`device.register`、`device.update`、`device.get`、`device.list`、`bns.publish_dns_txt`、`bns.publish_document` 需要 SN access token。
- `zone.get_info` 接受账号 access token 或 `aud=sn-device` 的短期设备 token；服务端必须从已验证 token 推导 zone，不能接受客户端指定任意 zone。
- `deviceinfo.resolve_ood_by_did`、`deviceinfo.resolve_ood_by_hostname` 是匿名只读接口。
- 带用户作用域的接口只允许访问 token 所属用户；即使参数里带 `name`，也必须等于当前登录用户。`bns.publish_dns_txt`、`bns.publish_document` 同样受此约束。
- `bns.publish_relay_assignment`、`bns.register_name_bootstrap`、`admin.clear_state_by_active_code` 只在内网管理路径 `/` 可用，不做 SN access token 校验，靠网络边界隔离外部访问。

`auth.register` 和 `auth.login` 返回 access/refresh token。access token 放在 kRPC request 的 `token` 字段中。

## 4. `/kapi/sn/auth`

### 4.1 `auth.*`

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `auth.check_username` | `name: string` | `valid`, `reason`, `message`, `normalized_name` | 检查用户名格式、保留名和是否已存在。用户名会 trim + lowercase。 |
| `auth.check_active_code` | `active_code: string` | `valid: bool` | 检查激活码是否可用。 |
| `auth.register` | `name`, `email`, `pwd_hash`, `active_code`, `region?`, `request_id?`, `asset_owner?`, `owner_config?`, `initial_documents?` | `code`, `access_token`, `refresh_token`, `need_bind_owner_key`, `bns?` | 注册 SN 用户。`region` 是 relay 调度的非可信地区偏好；具体 relay 与可信 source IP 均不能由客户端指定。账号创建后会自动分配 relay，暂时无可用节点时注册仍成功。SN 启用 bns-proxy 时会先原子性注册同名 BNS name，再建本地账号，并在响应里带上 `bns` TX 信息（见下）。 |
| `auth.login` | `name`, `pwd_hash` | `code`, `access_token`, `refresh_token`, `need_bind_owner_key` | 登录已激活用户。 |
| `auth.refresh` | `refresh_token` | `code`, `access_token` | 用 refresh token 换新 access token。 |
| `auth.logout` | `refresh_token?` | `code` | 吊销当前 access token 和/或给定 refresh token。 |
| `auth.me` | `{}` | 同 `user.get_profile` | 返回当前登录用户 profile。 |

#### 注册邮箱（已实现）与密码找回 TODO

- `auth.register.email` 必填。服务端应先 trim，再按产品规则统一大小写并校验基本邮箱格式；唯一性判断和存储都必须使用同一个规范化结果。
- 一个规范化邮箱地址全局只能绑定一个 SN 账号。该约束必须同时由注册事务和数据库唯一约束保证，不能只依赖注册前查询。
- 邮箱属于 SN 本地账号和密码找回数据，不属于 BNS owner/controller 身份，也不得写入公开 BNS 文档。
- 本版本不要求注册邮箱验证码、邮箱所有权验证或 `email_verified` 状态；但仅知道邮箱地址不能成为直接修改密码的凭证。
- 密码找回是本版本要求，找回入口应按规范化邮箱定位唯一账号。重置 token、邮件投递和消费流程仍需单独设计并实现，不得改变 BNS owner/controller 权限。
- 已完成：服务端 `RegisterReq`、客户端 `SnAuthRegisterReq`、用户模型和 SQLite schema 已增加 `email`；存量账号迁移后暂保留 `NULL` 等待可信补录，新 `auth.register` 强制传入邮箱；已增加规范化、唯一索引和并发重复邮箱注册测试。
- 已完成：新增稳定的 `invalid_email`、`email_already_bound` 错误名并分配错误码。TODO：新增密码找回 RPC、一次性重置凭证及 session 撤销逻辑。

当前代码已实现注册邮箱字段和约束，并分配 `invalid_email` / `email_already_bound` 稳定错误码；密码找回 RPC、重置凭证、邮件投递和消费后的 session 撤销仍待实现。

#### 注册时的 relay 自动分配

- `region` 可选，使用与 SN `relay_allocation` 配置相同的 region label 命名空间。服务端会 trim、转小写，并把空白、`_`、`/`、`.` 统一为 `-`；例如 `US_WEST` 规范化为 `us-west`。
- `region` 只作为调度提示，不参与账号、zone 或 BNS 权限判断。非法值或没有匹配节点时继续使用 GeoIP 和 fallback，不会令注册失败。
- source IP 只取 HTTP/连接上下文中的可信 real remote IP。RPC params 没有 `source_ip` 或 relay node 字段；即使客户端发送同名未知字段也不会进入调度请求。
- relay 分配在本地账号创建后执行。成功时 `relay_assignments` 与 `zone_info.relay_sn` 同步完成，注册返回后可立即调用 `zone.get_info`；失败时记录 `relay_allocation_pending`，`relay_sn` 保持 `null`，注册仍正常返回。

`auth.register` 的 BNS 行为取决于 SN 是否启用了 bns-proxy（`bns_write_enabled`/`bns_indexer_url` + `bns_evm`，可选 `bns_proxy` 多 controller 配置块；完整配置见 `doc/SN/sn-bns-proxy-todo.md`）：

- 未启用：只创建 SN 本地账号，`need_bind_owner_key = true`，响应没有 `bns` 字段。
- 已启用：注册前先原子性执行 BNS `registerName`（`assetOwner` = 用户地址、`controllerPolicy.actor` = 该用户分配到的 SN controller、`initialDocuments` = 固定的 `owner` document + 请求携带的 `zone`/`boot`/`dns_txt`）；BNS 写入失败则不创建本地账号（用户名可重试注册），成功后才建本地账号，`need_bind_owner_key = false`。
  - 生产多 controller 配置（`bns_proxy.controllers` 非空）下 `require_user_asset_owner` 缺省 `true`：`asset_owner` 必填，缺失返回 `invalid_params`。
  - 仅旧版单 controller 配置（`bns_evm.controller_private_key*`，未配置 `bns_proxy.controllers`）下缺省 `false`：`asset_owner` 缺省回落为该用户绑定 controller 的地址（devtest 语义）。
  - `request_id` 缺省为 `sn:register:<username>`；同 `request_id` 重放幂等，返回同一笔已提交的 TX。

响应里的 `bns` 字段结构与 bns-proxy 写操作的返回结构一致（见 6.2），例如：

```json
{
  "request_id": "sn:register:alice",
  "operation": "register_name_bootstrap",
  "name": "alice",
  "controller_id": "controller-a",
  "controller_address": "0x...",
  "asset_owner": "0x...",
  "chain_id": 31337,
  "nonce": 12,
  "tx_hash": "0x...",
  "raw_tx": "0x...",
  "status": "submitted",
  "reused": false
}
```

### 4.2 `user.*`

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `user.get_profile` | `{}` | `code`, `name`, `owner_key_bound`, `user_domain`, `self_cert`, `sn_ips`, `zone_config` | 返回当前用户 profile。 |
| `user.set_self_cert` | `self_cert: bool`, `device_did?` | `code` | 开启 `self_cert` 时必须提供属于当前用户的在线设备 DID。关闭时不需要 DID。 |
| `user.add_dns_record` | `device_did`, `domain`, `record_type`, `record`, `ttl?`, `has_cert?` | `code`, `device_name` | 管理当前用户 `user_domain` 或 SN 提供的 `<username>.web3.<server_host>` 范围内的本地 DNS 记录。 |
| `user.remove_dns_record` | `device_did`, `domain`, `record_type`, `record?`, `has_cert?` | `code` | 删除上述范围内的本地 DNS 记录；device token 调用时 `record` 必填并精确删除。 |
| `user.list_dns_records` | `{}` | `code`, `items[]` | 列出当前用户本地 DNS 记录。 |

`user.add_dns_record` / `user.remove_dns_record` 要求 `device_did` 属于当前用户，并允许管理以下两个范围：

- 已完成 active PKX 绑定的传统 `user_domain` 及其子域；
- 当前账号自己的 `<username>.web3.<server_host>` 及其子域，例如 `_acme-challenge.alice.web3.<server_host>`。不能写入其他账号的 web3 bridge 域名。

`record_type` 主要面向 `A`、`AAAA`、`TXT`。这两个范围的记录都保存在 SN compatibility store，由 SN DNS NameServer 优先解析；调用不会发布 BNS `dns_txt`、不会发起链上交易，也不会产生 gas 成本。因此 ACME 可以通过同一 API 创建和删除短期 challenge TXT 记录，而不必为临时状态上链。

账号 access token 保持上述管理能力。`aud=sn-device` 的短期设备 token 只允许所属 zone 范围内的 `_acme-challenge.*` TXT；SN 使用已验证 token 得到的 zone/device/DID，忽略请求中的身份声明。TXT 使用多值 RRset 语义，重复添加同一 value 幂等，删除必须指定本次 challenge value，因此并发的根域和 wildcard order 不会互相覆盖或误删。`has_cert` 仅作为兼容字段解析，DNS mutation 不据此更新证书状态。

> **过渡设计：** `<username>.web3.<server_host>` 的本地写入是 web3 bridge 仍承担 `did:bns:<username>` 到传统 DNS 名称转换期间的兼容措施。未来如果用户不再通过 web3 bridge 解析 `did:bns:xxx`，或者已有足够多 DNS 解析服务原生支持 `did:bns:xxx`，应移除这个本地例外，让 BNS 名称的 `add_dns_record` 重新回归 BNS 链上发布。传统 `user_domain` 的本地记录不受这一迁移方向影响。

`items[]` 结构：

```json
{
  "domain": "home.example.com",
  "record_type": "A",
  "record": "203.0.113.10",
  "ttl": 600
}
```

### 4.3 `zone.*`

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `zone.get_info` | `{}` | `code`, `zone`, `bns_name`, `relay_sn`, `self_cert`, `cert_checked_at`, `cert_expires_at`, `source_version`, `updated_at` | 返回调用方所属 zone 的 SN 本地运行态。 |

返回结构：

```json
{
  "code": 0,
  "zone": "alice",
  "bns_name": "alice",
  "relay_sn": "us-sn.buckyos.ai",
  "self_cert": false,
  "cert_checked_at": null,
  "cert_expires_at": null,
  "source_version": "v2",
  "updated_at": 1780000000
}
```

查询和权限约束：

- 账号 access token 使用 token 所属 username 作为 zone；设备 token 使用验证后的 `Device(zone, device_name, did)` 上下文中的 zone。
- 请求参数固定为 `{}`。任何非空参数（包括 `zone`、`username` 等身份字段）都返回 `invalid_params` 而不是被忽略，避免"看起来在查别的 zone"的误用与跨 zone 查询。
- handler 调用 auth 库的 `get_zone_info(zone)`，不直接向客户端暴露 relay manager 查询接口。
- `relay_sn` 是客户端可见的稳定 relay 名称；`relay_id`、节点负载、容量、调度来源、backup relay 和迁移内部状态不通过该接口暴露。
- 尚未分配 relay 时返回 `relay_sn: null`。查询操作只读，不应隐式创建或修改 relay assignment。
- node_daemon 应周期调用该接口检测 `relay_sn` 变化并重新建立 `keep_tunnel`；连接到错误 relay 时，可再使用 relay admission 返回的 `expected_relay_sn` 做快速切换。

该接口返回的是 SN 本地 `zone_info` 运行态，不是 BNS `zone` document。BNS zone document 仍通过 BNS reader / 标准 resolver 查询，不能用 `zone.get_info` 替代。

### 4.4 `domain.*`

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `domain.bind` | `domain` | `code`, `domain`, `pkx`, `pkx_record_name`, `pkx_source`, `verified_at` | 一站式绑定：校验用户 active → 从 `did:bns:<username>` 链上 owner 文档解析期望 PKX（取不到时按本地记录回落）→ SN 服务端自己查外部 DNS TXT → 命中后原子激活绑定（supersede 旧绑定）。 |
| `domain.unbind` | `domain` | `code` | 解绑当前用户的 user_domain。 |

`domain.*` 管的是 SN 账号的 `user_domain`，不是 BNS Domain 所有权变更。

TXT 未配置或不匹配时返回可重试错误 `domain_proof_failed`（错误码 1016），message 是 JSON：

```json
{
  "domain": "home.alice.example.com",
  "pkx_record_name": "_pkx.home.alice.example.com",
  "pkx": "PKX(...)",
  "retryable": true,
  "reason": "expected PKX TXT record not found at ... (0 TXT records observed)"
}
```

客户端按 `pkx_record_name` / `pkx` 配置好 TXT 记录后重新调用 `domain.bind` 即可完成绑定。breaking change：客户端不能再提交 `txt_records` / `txt_record` / `record` 参数来影响校验结果——SN 只信任自己发起的外部 DNS 查询（`pkx_doh_url` 配置的 DoH resolver），未知字段会被忽略而不是拒绝。`domain.begin_verify` / `domain.verify` / `domain.create_pkx_binding` / `domain.verify_pkx_binding` 已删除，见第 10 节。

## 5. `/kapi/sn/deviceinfo`

### 5.1 `device.*`

`device.*` 现在表示设备在线/运行态，不再发布设备身份文档。

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `device.register` | `device_name`, `device_did`, `device_ip`, `device_info`, `endpoints?`, `report_seq?`, `ttl?` | `code` + `SnDeviceStateView` | 首次或重复上报设备在线态。 |
| `device.update` | `device_name`, `device_did?`, `device_ip`, `device_info`, `endpoints?`, `report_seq?`, `ttl?` | `code` + `SnDeviceStateView` | 更新在线态。首次上报必须有 `device_did`；已有记录可省略。 |
| `device.get` | `device_name?` 或 `device_did?` | `code` + `SnDeviceStateView` | 查询当前用户某设备在线态。 |
| `device.list` | `state?`, `offset?`, `limit?` | `code`, `items[]` | 列出当前用户设备在线态。 |

`device.update` 如果携带 `mini_config_jwt` 会返回 `invalid_params`，因为设备身份文档发布已经迁移到 BNS API。

`endpoints[]` 的元素结构：

```json
{
  "endpoint_id": "rtcp-public-1",
  "protocol": "rtcp",
  "host": "203.0.113.10",
  "port": 8080,
  "scope": "public",
  "priority": 100,
  "source": "device_report",
  "expires_at": 1760000000
}
```

枚举值：

| 字段 | 可选值 |
|------|--------|
| `state` | `online`, `offline`, `stale`, `blocked` |
| `protocol` | `tcp`, `udp`, `quic`, `rtcp`, `http`, `https` |
| `scope` | `public`, `private`, `relay`, `loopback`, `unknown` |
| `source` | `device_report`, `from_ip`, `relay_observed`, `admin` |

`SnDeviceStateView` 结构：

```json
{
  "code": 0,
  "did": "did:dev:...",
  "zone": "alice",
  "device_name": "ood1",
  "device_role": "ood",
  "state": "online",
  "public_ips": ["203.0.113.10"],
  "private_ips": [],
  "active_endpoints": [],
  "preferred_endpoint": null,
  "nat_type": "unknown",
  "is_wan_device": true,
  "last_seen_at": 1760000000,
  "expires_at": 1760000300
}
```

`ttl` 默认 300 秒。`device_name == "ood1"` 会被标记为 `ood` 角色，其余默认为 `normal`。

### 5.2 `deviceinfo.*`

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `deviceinfo.resolve_ood_by_did` | `source_device_id` | `did_hostname`, `owner_id`, `self_cert`, `state` | 按设备 DID 解析 OOD 连接信息。 |
| `deviceinfo.resolve_ood_by_hostname` | `dest_host` | `did_hostname`, `owner_id`, `self_cert`, `state` | 按 hostname 解析 OOD 连接信息。 |

`state` 是面向连接决策的状态：在线设备返回 `active`，离线/过期返回 `suspended`，被阻断返回 `banned`。该接口供 relay / QA / process-chain 获取建连所需运行态；它不是通用 DID 或域名解析接口。

## 6. `/kapi/sn/bns-proxy`

SN 代付 gas 的受限 BNS 写代理：用户不需要持有 gas，就能通过 SN 完成 BNS name 注册和受控 document 更新；SN 负责构造、签名（多把内部 controller key，业务代码接触不到明文私钥）、投递 EVM TX。完整设计与实施状态见 `doc/SN/sn-bns-proxy-todo.md`。

不要与已下线的 `/kapi/sn/bns` 混淆（见第 10 节）：旧路径曾承载通用文档读写代理，已完全移除；bns-proxy 只覆盖下面四个受控操作。`publish_document` 虽允许内容型 doc_type 通用化，但 authority、controller 和 TX 都由服务端构造，不能提交任意 calldata。

只有 SN 配置了 BNS 写链路（`bns_write_enabled`/`bns_indexer_url` + `bns_evm`）时才启用；配置了 `bns_proxy` 块时还可以显式 `bns_proxy.enabled: false` 关闭。未启用时所有 `bns.*` 调用返回 `bns_proxy_unavailable`（1026），`auth.register` 回落为纯本地注册（不带 `bns` 字段）。

### 6.1 方法

| Method | 可达路径 | Params | 说明 |
|--------|----------|--------|------|
| `bns.publish_dns_txt` | `/kapi/sn/bns-proxy`（需 SN access token） | `name`, `mode`, `request_id?`, `ttl?`, `value?`, `records?` | 通过当前用户绑定的 controller 更新 `dns_txt` document。`name` 必须等于 token 所属用户。 |
| `bns.publish_document` | `/kapi/sn/bns-proxy`（需 SN access token） | `name`, `doc_type`, `document`, `request_id?` | 注册后独立发布 JSON object 或 compact JWT string document；`name` 必须等于 token 所属用户。`relay_assignment` 禁止，`owner` 受身份字段保护。 |
| `bns.publish_relay_assignment` | 仅内网 `/` | `name`, `relay_assignment`, `request_id?` | SN 内部发布 relay assignment，不经外部 HTTP 路径。 |
| `bns.register_name_bootstrap` | 仅内网 `/` | `name`, `asset_owner`, `request_id?`, `owner_config?`, `initial_documents?` | 注册阶段以外的恢复/重放入口，不创建本地 SN 账号。 |

所有参数结构 `deny_unknown_fields`：客户端不能塞 `controller_address` / `authority` 之类字段来影响服务端的 controller 选择。服务端按 `name`（即 BNS name / 用户名本身）经稳定分配（带权重 rendezvous hashing）取绑定 controller；分配结果持久化在本地 sqlite（`sn_bns_controller_bindings`），一旦写入不会静默改分配——绑定指向的 controller 从配置中消失时，写操作返回 `bns_controller_unavailable`（1027），需要人工迁移。

`bns.publish_dns_txt` 的 `mode`：

| `mode` | 必需字段 | 行为 |
|--------|----------|------|
| `add` | `value`（`ttl?` 缺省 600） | 追加一条 TXT 记录。 |
| `remove` | `value` | 删除匹配的 TXT 记录。 |
| `replace` | `records: [{ttl?, value}]` | 整体替换 `dns_txt` document 的记录集合。 |

`bns.publish_document` 的 `document` 必须是 JSON object 或非空 compact JWT string；其它 JSON scalar 和 array 均拒绝。JSON object 按其 JSON bytes 发布，JWT string 按 UTF-8 原文发布，不会额外包裹 JSON 引号。单个 inline document 上限 4KB。SN 会从当前投影读取版本并自动填写 `expected_version`；客户端不传版本号。成功响应的 `status=submitted` 只表示 TX 已投递，调用方必须等待 bns-indexer 投影并读回相同原文后才能把业务标记为完成。除下面两个保留类型外，`zone`、`boot`、`device_mini_doc` 和自定义 doc_type 均不做产品级 schema 限制：

- `relay_assignment`：返回 `invalid_params`，必须改走内网 `bns.publish_relay_assignment`。
- `owner`：只接受 JSON object，不接受 JWT string；允许首次补齐身份字段，也允许更新其它内容；但当前 owner 文档里已经存在的 `public_key`、`owner_key`、`default_key`、`key`、`verificationMethod[0].publicKeyJwk` 不得改值或删除，否则返回 `invalid_params`，且不会构造/投递 TX。

### 6.2 返回结构

四个方法成功时都返回同一种 TX 投递结果（`code: 0` + 以下字段）：

```json
{
  "code": 0,
  "request_id": "sn:...",
  "operation": "publish_dns_txt",
  "name": "alice",
  "controller_id": "controller-a",
  "controller_address": "0x...",
  "asset_owner": "0x...",
  "doc_type": "dns_txt",
  "document_version": 2,
  "chain_id": 31337,
  "nonce": 13,
  "tx_hash": "0x...",
  "raw_tx": "0x...",
  "status": "submitted",
  "reused": false
}
```

| 字段 | 说明 |
|------|------|
| `asset_owner` | 只在 `register_name_bootstrap` 有值。 |
| `doc_type` / `document_version` | 只在 document 类操作（`publish_dns_txt` / `publish_document` / `publish_relay_assignment`）有值；`document_version` 是 SN 提交前推算的目标版本号，不代表链上已确认。 |
| `status` | 恒为 `"submitted"`：SN 只保证已投递 TX，不等待 receipt。链上最终状态经 `bns-indexer` 投影，读侧可能有短暂延迟窗口。 |
| `reused` | 命中同 `request_id` 幂等重放时为 `true`，返回上一次的 TX 结果而不重新提交。 |

`request_id` 缺省时服务端随机生成（每次调用视为新意图）；显式提供时是幂等键，同 `request_id` 重放返回同一笔 TX。

### 6.3 `initial_documents`（`register_name_bootstrap` / `auth.register` 共用）

```json
{
  "zone": { "...": "..." },
  "boot": { "...": "..." },
  "dns_txt": [ { "ttl": 600, "value": "pkx=..." } ]
}
```

三个字段都可选；非空的会随 `registerName` 原子发布为初始 document（连同服务端固定生成的 `owner` document）。单个内联 document 上限 4KB。

### 6.4 权限与白名单

- 私钥只存在于 SN 内部签名组件（`SnBnsTxSigner`）；RPC handler、日志、DB、错误信息都不会出现明文私钥或原始 calldata。
- 每个部署可配置多把 controller key（`bns_proxy.controllers`，带 `weight`；`weight: 0` 表示排水，不接新用户但已绑定用户不受影响）；不配置 `bns_proxy.controllers` 时回落旧版单 controller（`bns_evm.controller_private_key*`，id 固定为 `default`）。
- `bns_proxy.allowed_operations` 是服务端白名单（缺省 = 全部四个操作）；命中白名单外操作同样返回 `bns_proxy_unavailable`。`dns_txt` 和 `relay_assignment` 仍映射到各自专属 operation，其余 doc_type 映射到 `publish_document`。签名组件另有一层独立白名单（chain id / contract / method selector / operation×doc_type / gas 上限），未知一律拒签，双重防护。
- 新注册用户的 controller policy 使用空 doc_type 通配规则，以承载注册后新增的内容型 document；SN 应用层继续硬隔离 relay 专用入口，并通过受保护的 owner 路径锁定已经存在的身份字段。存量用户的链上 policy 不会自动升级。
- `bns_proxy.require_user_asset_owner`：配置了 `bns_proxy.controllers`（生产多 controller 模式）缺省 `true`；仅旧版单 controller 配置缺省 `false`（devtest，`asset_owner` 缺省回落为该用户绑定 controller 的地址）。

## 7. 内网管理 RPC

`admin.clear_state_by_active_code` 只允许发到内网管理根路径 `/`，不允许出现在 `/kapi/sn/auth`、`/kapi/sn/deviceinfo`、`/kapi/sn/bns-proxy` 或 `/kapi/sn`。

| Method | Params | Result | 说明 |
|--------|--------|--------|------|
| `admin.clear_state_by_active_code` | `{}` | `code`, `deleted_users`, `deleted_devices`, `deleted_domain_records`, `deleted_did_documents`, `activation_code_reset` | 清理内置激活码关联的测试/运维状态。请求参数中不允许带 `active_code`。 |

`/` 同时还承载 bns-proxy 的内部/恢复方法 `bns.publish_relay_assignment`、`bns.register_name_bootstrap`（参数与返回见 6.1、6.2）：同一机制，只允许出现在 `/`，不出现在任何公网路径。

## 8. 非 RPC 解析接口

SN 仍然提供两个标准解析面，但它们不是 SN RPC：

| 接口 | 形式 | 说明 |
|------|------|------|
| W3C DID Resolver | `GET /1.0/identifiers/{did}?type={doc_type}` | 支持 `did:bns`、`did:dev`、`did:web`，返回 `application/json` 或 `application/jwt`。 |
| DNS NameServer | DNS `A` / `AAAA` / `TXT` 查询 | 解析 SN 自身、user_domain、本地 DNS 记录、BNS 文档和设备在线态。 |

需要解析 DID 或域名时优先使用这两个标准接口，不再通过 kRPC `query.resolve_*`。

## 9. 错误码

| Code | Name |
|------|------|
| 1000 | `invalid_params` |
| 1001 | `invalid_username` |
| 1002 | `username_already_exists` |
| 1003 | `invalid_active_code` |
| 1004 | `user_auth_not_found` |
| 1005 | `invalid_password` |
| 1006 | `auth_required` |
| 1007 | `invalid_token` |
| 1008 | `user_not_found` |
| 1012 | `device_not_found` |
| 1013 | `device_permission_denied` |
| 1014 | `invalid_device_did` |
| 1015 | `invalid_domain` |
| 1016 | `domain_proof_failed` |
| 1017 | `hostname_not_found` |
| 1018 | `cross_user_access_denied` |
| 1019 | `unsupported_password_algo` |
| 1020 | `invalid_password_storage` |
| 1022 | `user_not_activated` |
| 1023 | `bns_permission_denied` |
| 1024 | `bns_name_already_exists` |
| 1025 | `bns_write_failed` |
| 1026 | `bns_proxy_unavailable` |
| 1027 | `bns_controller_unavailable` |
| 1028 | `invalid_email` |
| 1029 | `email_already_bound` |
| 1099 | `internal_error` |

`domain_proof_failed` 只从 `domain.bind` 冒出，message 是 JSON，见 4.4。

BNS 写入错误会从任意 bns-proxy 写路径冒出：`auth.register` 的 BNS 代注册、`bns.publish_dns_txt`、`bns.publish_document`、`bns.publish_relay_assignment`、`bns.register_name_bootstrap`。`CONTROLLER_SCOPE_DENIED` / `NOT_EFFECTIVE_OWNER` 映射为 `bns_permission_denied`，`NAME_ALREADY_EXISTS` 映射为 `bns_name_already_exists`，其他 BNS 写入错误映射为 `bns_write_failed`；请求结构、保留 doc_type 和 owner 身份字段保护失败映射为 `invalid_params`。`bns_proxy_unavailable` 对应「bns-proxy 未启用」或「operation 不在白名单内」；`bns_controller_unavailable` 对应「用户绑定的 controller 已不在当前配置」，需要人工迁移，不会静默重分配。

## 10. 从旧 SN API 迁移

| 旧接口/路径 | 新用法 |
|-------------|--------|
| `/kapi/sn` 上调用任意 RPC | 按方法改发 `/kapi/sn/auth` 或 `/kapi/sn/deviceinfo`；`/kapi/sn` 不再承载 RPC。 |
| `/kapi/sn/bns` | 不再属于 SN。BNS 文档、zone、DID、device mini doc、BNS DNS TXT 写入改用 `/kapi/bns` 或 `bns-client`。新 `/kapi/sn/bns-proxy`（第 6 节）是不同的东西——SN 代付 gas 的白名单写代理，不是该路径复活。 |
| 裸方法名，如 `register`、`get`、`bind_zone_config` | 改为 namespaced method，例如 `auth.register`、`device.get`。 |
| `zone.bind_config`、`zone.get` | SN 代付发布可用 `bns.publish_document`（`doc_type=zone`）；owner 直写仍用 BNS API。读取走 BNS reader 和标准 resolver。 |
| `did.set_document`、`did.get_document` | 写/读文档改用 BNS API；解析 DID 用 `GET /1.0/identifiers/{did}`。 |
| `device.register` 发布 `mini_config_jwt` | 设备身份文档改用 BNS API；SN 的 `device.register/update` 只上报在线态。 |
| `dns.add_record` / `dns.remove_record` | user_domain 本地记录改为 `user.add_dns_record` / `user.remove_dns_record`；BNS Domain 的 TXT/记录改用 BNS API 或 bns-proxy 的 `bns.publish_dns_txt`。 |
| `domain.begin_verify` / `domain.verify` / `domain.create_pkx_binding` / `domain.verify_pkx_binding` | 已删除（含对应 DB 方法）。改用一站式 `domain.bind`；服务端不接受客户端提交的 `txt_records` / `txt_record` / `record` 作为 proof。 |
| `query.resolve_did` / `query.resolve_hostname` / `query.resolve_device` | DID 和域名解析改用 W3C DID Resolver / DNS NameServer；OOD 建连信息改用 `deviceinfo.resolve_ood_by_*`。 |
| `user.bind_owner_key` / `user.get_owner_key` | 已移除。owner/controller 权限管理走 BNS 侧流程（生产路径见 bns-proxy 的 `auth.register`）。 |

`cyfs-gateway-api::SnClient` 已按新路径封装 auth、deviceinfo 与 bns-proxy 三个 target；传入旧 `/kapi/sn` 或 `/kapi/sn/bns` 后缀的 base URL 时，会自动归一化到目标方法对应的新路径。`SnAuthRegisterReq` 已支持必填 `email`、可选 relay 地区偏好 `region`，以及 `asset_owner`、`owner_config` 与 `initial_documents`；客户端也提供 `get_zone_info`、`publish_dns_txt`、`publish_document` 便捷方法。
