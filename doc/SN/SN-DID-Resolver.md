# SN-DID-Resolver

`SN-DID-Resolver` 是 `cyfs-sn` 暴露的 HTTP DID resolver 服务面。它复用现有
`sn_resolver` 的 BNS、user_domain、device_info 和兼容存储读能力，为外部客户端和
SN 集群内部提供 DID 文档查询。

本文描述目标需求；当前实现位于 `src/components/cyfs-sn/src/sn_resolver.rs` 与
`src/components/cyfs-sn/src/sn_server.rs`，只能作为现状和迁移参考。

## 设计定位

SN-DID-Resolver 同时有两个 profile：

1. **Public supplement profile**：公网入口，典型地址为
   `https://sn.buckyos.ai/1.0/identifiers/{did}?type={doc_type}`。在
   `name-client` provider 顺序中，它是 `did:web` / `did:bns` 的末位补充源，不是
   DID method 权威源。
2. **Internal zone-resolver profile**：SN 集群内部或 zone 内使用的 resolver cache
   入口，可被配置为 `127.0.0.1:3180 -> sn-did-resolver` 的 upstream。它语义上更接近
   `zone_resolver`：是内部控制面 cache / override，不参与公网 provider 权威排序。

这两个 profile 使用同一套查询核心，但返回 metadata 和权限策略不同。未来可以把两者拆成
不同监听地址或不同认证策略。

## 目标

- 提供符合 BuckyOS HTTP DID resolver 协议的 `GET /1.0/identifiers/{did}?type={doc_type}`。
- 在 SN 管理范围内，为 `did:web` / `did:bns` 返回可验证的候选 DID document 或内部
  zone cache 结果。
- 解决 `did:web` zone / owner 在 booting 阶段权威 HTTPS 站点尚未启动时的 owner
  document 解析问题。
- 为 RTCP `keep_tunnel` 验证 `hello.device_doc_jwt` 提供稳定的 owner document 和设备
  document 查询路径。
- 支持从 BNS indexer、SN user_domain、SN device_info 和 legacy compatibility store 合成
  现有 SN 用户和设备的 DID 查询结果。
- 明确区分“SN 知道的内部事实”和“DID method 权威发布状态”，避免补充源冒充权威源。

## 非目标

- 不实现 `GET /.well-known/{doc_type}.json`。`sn.buckyos.ai` 是 resolver host，不是某个
  用户 DID 的 did:web 权威站点；`.well-known` 由静态配置或用户自己的站点负责。
- 不写入 BNS document，不注册 name，不修改 owner/controller；写路径属于 BNS API /
  `sn_bns_controller`。
- 不替代 `web_resolver`、`bns_resolver` 或 `dns_resolver` 的 method 权威职责。
- 不向用户域名发起递归查询，例如不会访问 `https://example.com/.well-known/did.json`
  或 `https://alice.web3.buckyos.ai/...` 来补齐结果。
- 不把 `did:dev` / `did:key` 作为标准 `resolve_did` 入口。当前 `cyfs-sn` 接受
  `did:dev` 只属于兼容私有查询能力，不能注册进标准 provider 语义。

## 基本语义

### DR 与 unknown

SN-DID-Resolver 必须遵守 `resolve_did` 的二分语义：

- **DR（Document Result）**：SN 明确得到了回答。回答可以是 document，也可以是
  `Missing / Revoked / Tombstoned` 等状态。
- **unknown**：SN 没有得到回答，例如依赖的 BNS indexer 不可用、内部 DB 错误、请求超时。

不能把依赖故障伪装成 Missing。Missing 只能在 SN 对该请求有明确管理范围且能确认
“从未发布/不存在”时返回。

### 发布权与签字权

SN-DID-Resolver 不是 `did:web` 或 `did:bns` 的权威发布渠道。Public supplement profile
返回的 document 默认只是候选 body，`name-client` 应按补充源规则把它当成 `need_proof`
候选，再通过 expected_owner、owner document 和 JWT 签名验证。

Internal zone-resolver profile 可以把 SN 集群内部已经认可的结果作为 zone cache 命中返回，
但这是 cache/control-plane 权威，不是 DID method 权威。它只对内部调用方生效。

### owner 不由候选文档自证

SN-DID-Resolver 必须为自己管理范围内的名字提供外部约束来源，不能让候选 document 的
`owner` 字段单方面决定验签 owner。

owner 约束来源：

- `did:bns:{device}.{zone}` 的结构 owner 是 `did:bns:{zone}`。
- `did:web:{device}.{domain}` 的结构 owner 是 `did:web:{domain}`。
- `did:web:{domain}` 精确命中 SN `user_domain` 时，SN 可以用该绑定找到内部 canonical
  zone（通常是 BNS name），但不能把返回 document 的 `id`/`owner` 偷换成 `did:bns`。
- BNS indexer 返回的 owner / owner_config 可作为 SN 合成 owner document 的 key 来源和
  provenance，但 Public supplement profile 不能因此声称自己是 `did:bns` 权威源。

## HTTP 接口

### 标准 DID resolver

```http
GET /1.0/identifiers/{did}?type={doc_type}
Accept: application/did-resolution
```

- `{did}` 是完整 DID 字符串，例如 `did:bns:alice`、`did:web:example.com`。
- `type` 是 doc_type。缺省时目标协议默认 `zone`；当前 `cyfs-sn` 对二级 `did:bns`
  兼容地默认 `doc`，新调用方不应依赖这个兼容行为。
- `iat` 历史查询第一阶段不要求支持；如收到，应返回“不支持历史查询”的明确响应，而不是
  退化成当前状态。
- 返回应优先使用 W3C DID Resolution Result 信封，并在
  `didDocumentMetadata.buckyos` 中携带 BuckyOS 扩展 metadata。

当前实现直接返回 bare JSON/JWT body，尚未实现完整 DID Resolution Result 信封。

### 不支持 well-known

SN-DID-Resolver 不处理：

```http
GET /.well-known/{doc_type}.json
GET /{path}/{doc_type}.json
```

这些路径属于 `web_resolver` 读取的 did:web 权威发布面。SN resolver host 只提供
`/1.0/identifiers`。

### Public supplement response profile

公网补充源返回 document 时：

- HTTP `200`，body 包含 `didDocument` 或 bare document。
- 不应在 `buckyos.documentStatus` 中写 `active / missing / revoked / tombstoned`，除非
  该响应明确处于 internal zone-resolver profile。
- 可以携带非权威 metadata，例如 `docType`、`source`、`canonicalZone`、`resolverRole:
  "supplement"`，但客户端不得把这些字段当成发布状态。
- 对不属于 SN 管理范围的 DID，返回 NotApplicable：`404` 且无
  `buckyos.documentStatus`。这不是 Missing。
- 内部依赖不可用返回 `500/502/503`，不能返回 `404 missing`。

### Internal zone-resolver response profile

内部 profile 可返回完整 zone cache 语义：

- 明确命中 document：`200` + `documentStatus: "active"`。
- 明确 Missing：`404` + `documentStatus: "missing"`。
- 明确 Revoked/Tombstoned：`410` + 对应 `documentStatus`。
- 不知道或不管理：NotApplicable/unknown，不写 `documentStatus`。

Internal profile 只应绑定在内网、loopback 或受 SN 集群鉴权保护的入口。对公网开放时必须降级为
Public supplement profile。

## 数据来源

SN-DID-Resolver 只读以下数据源：

| 数据源 | 当前实现 | 用途 |
| --- | --- | --- |
| BNS indexer | `BnsIndexerDocumentReader` | 读取 BNS owner、owner_config、`zone`、`boot`、`device_mini_doc`、`dns_txt` 和任意 doc_type |
| SN Auth DB | `SnAuthResolverReader` | 读取 `user_domain -> username`、legacy `zone_config`、legacy public key、`self_cert`、`zone_info` |
| SN DeviceInfo DB | `SnDeviceInfoResolverReader` | 读取 device DID、`zone + device_name`、在线状态、endpoint、NAT/公网状态 |
| Relay manager | `SnRelayManagerResolverReader` | 读取 zone 当前 relay 分配；可作为 `info` 类结果的辅助 metadata |
| Compatibility store | `LegacyResolverCompatibilityReader` | 兼容旧 `devices`、`user_dns_records`、`did_documents` 数据 |

查询优先级应保持 BNS-first：BNS document / owner 有结果时优先使用，legacy 本地数据只作为迁移
fallback。

## 支持的 DID 与 doc_type

### `did:bns:{zone}`

根 BNS DID 表示一个 zone / user name。

| doc_type | 目标行为 |
| --- | --- |
| `owner` | 返回该 BNS name 的 owner document。优先使用 BNS `owner` document / owner_config；legacy fallback 可由 SN 用户 public key 合成最小 owner document |
| `zone` | 返回 BNS `zone` document；缺失时可回退到 legacy `SNUserInfo.zone_config` 合成结果 |
| `boot` | 返回 BNS `boot` document；缺失时可使用 `zone.boot_jwt` 或 legacy `zone_config` |
| `device_mini_doc` | 返回 BNS 聚合设备 mini document |
| 其它 | 优先直接读取 BNS 同名 doc_type；缺失时才查 legacy did document |

如果 BNS name 不存在且 SN 本地也没有该用户，Public profile 返回 NotApplicable；Internal profile
可以在明确属于本 SN 管理范围时返回 Missing。

### `did:bns:{object}.{zone}`

二级 BNS DID 通常表示 zone 内设备，也可以表示普通对象。

| doc_type | 目标行为 |
| --- | --- |
| `doc` | 返回设备/对象 document。设备场景优先读取 `{object}.{zone}` 的 `device_mini_doc` 或 `doc`，再读 `{zone}` 聚合 `device_mini_doc`，再读 `zone.devices`，最后 legacy fallback |
| `info` | 返回运行态信息。优先读取 `sn_device_info` 在线态；没有在线态但能找到设备身份时返回 offline info；`info` 是免验证运行态 doc_type，不代表已发布文档 |
| 其它 | 优先读取 BNS child document `{object}.{zone}/{doc_type}`；缺失时查 legacy did document |

owner 约束必须是 `did:bns:{zone}`。返回的 `doc` 若是 JWT，JWT 内 `id` 必须等于请求 DID，
`owner` 必须等于 `did:bns:{zone}`；否则只能作为兼容裸 JSON 返回，不能被标成已验证/已发布。

### `did:web:{domain}`

只有当 `{domain}` 精确命中 SN 账号的 `user_domain` 时，SN 才管理该 DID。

目标行为：

- 找到绑定用户 `{username}`，canonical zone 为 `did:bns:{username}`。
- `type=owner` 必须返回 `id = did:web:{domain}` 的 owner document，key 来源优先为 BNS
  owner/owner_config，其次 legacy SN 用户 public key。
- `type=zone` / `type=boot` 可从 canonical zone 的 BNS document 合成，但 document 中的
  `id`/`owner` 不能伪装成 `did:bns:{username}` 后直接返回给 `did:web:{domain}` 调用方。
- 如果无法构造与请求 DID 自述一致的 document，Public profile 应返回 NotApplicable 或只返回
  明确标注的候选；Internal profile 可按 zone cache 策略短路。

SN 不访问 `https://{domain}/.well-known/...`。这正是 booting 场景需要 SN 内部逻辑的原因：
用户 zone 尚未启动时，标准 did:web 权威源不可达，但 SN 已经通过 user_domain 绑定、BNS 和
device_info 掌握了足够的内部事实。

### `did:web:{device}.{domain}`

当 `{domain}` 精确命中 SN `user_domain` 时，`{device}.{domain}` 表示该 zone 下的设备 DID。

目标行为：

- owner 结构约束是 `did:web:{domain}`。
- `type=doc` 映射到 canonical BNS zone 的设备 document 来源，但返回 document 的 `id` 必须
  保持请求 DID：`did:web:{device}.{domain}`。
- `type=info` 返回 `sn_device_info` 运行态；没有在线态但设备存在时返回 offline info。
- `type=owner` 一般不用于设备 DID；需要 owner document 时应解析 `did:web:{domain}` 的
  `type=owner`。

这个能力是 RTCP `keep_tunnel` 的关键路径：客户端用 `did:web:ood1.example.com` 和
`hello.device_doc_jwt` 握手时，relay 必须能通过内部 SN-DID-Resolver 得到
`did:web:example.com` 的 owner document，才能用正确 owner key 校验设备 JWT。

### `did:dev:*`

当前 `cyfs-sn` 已实现 `did:dev` 的 `doc` / `info` 兼容查询：按 device DID 查
`sn_device_info` 或 compatibility store，返回设备 document / info。

目标上它应被标记为私有兼容接口：

- 不作为标准 `resolve_did` provider 输入。
- Public profile 可以保留一段迁移期，但不得在文档中声称这是 DID method 权威结果。
- Internal profile 可继续用于 SN relay / 调试路径里的 key 到设备反查。

## owner document 合成要求

当 SN 需要为 `did:web:{domain}` 或 legacy BNS 用户合成 owner document 时，必须满足：

- `id` 等于请求的 owner DID，例如 `did:web:example.com`。
- public key 来自请求 DID 之外的可信来源：BNS owner_config、BNS effective owner key、SN
  账号 legacy public key。
- document 中应记录 provenance，例如 `canonicalZone: "did:bns:alice"`、`source:
  "bns-owner-config"`，但这些字段不能替代 `id` 和 `owner` 语义。
- 如果返回 JWT，签名 key 必须与 owner document 声明的 key 关系一致；如果无法签名，Internal
  profile 可返回 JSON owner document，Public profile 应避免让客户端误判为已验证结果。
- owner document TTL 应较短，默认可沿用当前 `DEFAULT_SN_RESOLVER_TTL_SECS = 60`。

## 兜底查询规则

SN-DID-Resolver 只在“SN 自己能用内部可信数据完成查询”的范围内兜底：

- `did:bns:alice`：如果 `alice` 是 BNS name 或 SN 注册用户，则返回根 DID 相关文档。
- `did:bns:ood1.alice`：如果能从 BNS `device_mini_doc`、`zone.devices`、`sn_device_info` 或
  legacy store 找到设备，则返回 `doc` / `info`。
- `did:web:example.com`：如果 `example.com` 已绑定到 SN 用户 `user_domain`，则返回 owner /
  zone / boot 候选或内部 cache 结果。
- `did:web:ood1.example.com`：如果 `example.com` 是 SN `user_domain`，则按对应 BNS zone 的
  设备文档和在线态合成。

不得为了兜底向用户域名或 web3 兼容域名发起 HTTP 查询。避免递归时，SN-DID-Resolver 内部如需再
调用 `name-client`，必须显式关闭 zone resolver，例如使用 `ResolvePolicy::without_zone_resolver()`；
更推荐直接使用 `BnsDocumentReader` / `SnAuthReader` / `DeviceOnlineReader` 等内部 reader。

## 缓存与失效

- Public profile 可按 document TTL / SN 默认 TTL 设置 HTTP cache，但不应缓存依赖故障。
- Internal profile 可缓存 active / missing / negative 状态；negative 状态必须短 TTL 或跟随 BNS
  version/name_seq 失效，避免旧负状态长期压制新发布。
- `info` 类运行态应使用 device TTL 或更短 TTL，不应按 BNS document TTL 长期缓存。
- user_domain 绑定、BNS document 更新、device online update、relay assignment 变化都应触发相关
  cache 失效。

当前实现有 `NameInfoCache` 和 `SnResolverCache` 两层 DNS cache；DID resolver 路径尚未有完整的
按 `(did, doc_type, source version)` 缓存模型。

## 错误与状态映射

| 场景 | Public supplement profile | Internal zone-resolver profile |
| --- | --- | --- |
| DID 格式错误 / doc_type 非法 | `400` | `400` |
| SN 不管理该 DID | `404`，无 `documentStatus` | unknown / NotApplicable，无 `documentStatus` |
| 明确不存在且属于 SN 管理范围 | `404`，无 `documentStatus` 或候选缺失 | `404` + `documentStatus: "missing"` |
| BNS/DB/内部依赖不可用 | `500/502/503` | `500/502/503` 或 unknown，不能伪装 Missing |
| document 命中 | `200`，候选 document，无权威 `documentStatus` | `200` + `documentStatus: "active"` |
| BNS 明确 Revoked/Tombstoned | Public 不应自行声明，除非实现为受信 BNS gateway | `410` + 对应 `documentStatus` |

## 当前实现状态

- 已有 HTTP 路由：`SNServer::serve_request` 处理
  `/1.0/identifiers/{did}?type=...`，调用 `SNServer::query_did`。
- 已有 resolver core：`SnResolver::resolve_did` 支持 `web`、`bns`、`dev` 三种 method。
- `did:web` 当前通过 `sn_auth.get_user_by_domain` 映射到 BNS username，再复用
  `resolve_bns_did`。这解决了部分 booting 查询，但还没有完整的 owner document 合成和
  DID 自述一致性处理。
- `did:bns` 当前 BNS-first：优先读 BNS document，缺失时回退 legacy `SNUserInfo` /
  compatibility store。
- 设备 `doc` / `info` 已接入 BNS `device_mini_doc`、`zone.devices`、`sn_device_info` 和
  legacy devices。
- BNS indexer reader 已能读取 owner、owner_config 和 BNS document。
- HTTP response 当前直接返回 bare JSON/JWT，尚未实现 DID Resolution Result 信封、
  `documentStatus`、`effectiveOwner`、`source` 等 metadata。
- `from_ip` 参数当前传入 `resolve_did` 但未使用。
- `did:dev` 当前仍对公网 resolver 路径可用，应在目标语义中降级为兼容/私有能力。

## 验收测试

- `GET /1.0/identifiers/did:web:example.com?type=owner`：当 `example.com` 绑定到 SN 用户时，
  booting 阶段无需访问 `https://example.com` 即可得到 `id=did:web:example.com` 的 owner
  document。
- `GET /1.0/identifiers/did:web:ood1.example.com?type=doc`：能从对应 BNS zone 的
  `device_mini_doc` / `zone.devices` 合成设备 document，owner 约束为 `did:web:example.com`。
- RTCP `keep_tunnel`：客户端提交 `did:web:ood1.example.com + hello.device_doc_jwt` 时，
  relay 能解析 `did:web:example.com?type=owner` 并完成设备 JWT 验证。
- `did:bns:alice` 和 `did:bns:ood1.alice`：BNS document 优先，legacy store 只在缺失时 fallback。
- 不管理的 `did:web:not-bound.example`：Public profile 返回 NotApplicable，不访问该域名。
- BNS indexer 故障：返回 5xx/unknown，不能返回 Missing。
- 内部 zone-resolver upstream 配置到 SN-DID-Resolver 时，不发生 resolver 自递归。
- Public profile 不把补充源候选结果标成 `documentStatus: "active"`。
