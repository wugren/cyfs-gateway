# BNS Server RPC API

本文档按 Beta2.2 当前代码整理 BNS-Client 与 BNS-Server 之间的 kRPC 接口。接口定义以
`src/components/bns-client/src/rpc.rs` 为准，BNS-Server 实际暴露范围以
`src/components/bns-server/src/lib.rs` 中的 `BnsContractServerRpcHandler` 为准。

> 当前 BNS-Server 是“读投影 + raw EVM TX 转发器”：读请求查询 BNS-Indexer 的本地投影；
> 写请求必须由客户端先构造并签名 EVM 交易，再通过 `tx.submit_raw` 提交。Server 不持私钥、
> 不解释交易 calldata，也不执行 `CallAuthority` 写逻辑。

## 1. Endpoint 与传输协议

### 1.1 Endpoint

| 用途 | 默认路径 | BNS-Client 构造方法 |
| --- | --- | --- |
| 当前 BNS-Server | `POST /kapi/bns` | `BnsIndexerClient::new_bns_server_url(...)` |
| 遗留/独立 BNS-Indexer | `POST /kapi/bns-indexer` | `BnsIndexerClient::new_krpc_url(...)` |

构造方法收到的 URL 如果只有 scheme/host/port，会自动追加默认路径；如果 URL 已包含非根路径，
则保留该路径。例如 `http://127.0.0.1:18080/custom/rpc` 不会再追加 `/kapi/bns`。

本文后续只描述当前 BNS-Server 的 `/kapi/bns`。

### 1.2 kRPC 请求

BNS 使用 kRPC JSON，而不是标准 JSON-RPC 2.0；请求中没有 `jsonrpc` 和 `id` 字段。

```json
{
  "method": "name.query_state",
  "params": {
    "name": "alice"
  },
  "sys": [42]
}
```

`sys` 的格式为：

```text
[seq]
[seq, session_token]
[seq, null, trace_id]
[seq, session_token, trace_id]
```

- `seq`：`u64` 请求序号；响应必须返回同一个序号。
- `session_token`：可选会话令牌。
- `trace_id`：可选链路追踪 ID。

### 1.3 kRPC 响应与 BNS 业务信封

kRPC 的 `result` 字段内还有一层 `BnsRpcEnvelope<T>`。

成功：

```json
{
  "result": {
    "ok": true,
    "result": {
      "tx_hash": "0x0123...abcd"
    },
    "error": null
  },
  "sys": [42]
}
```

BNS 业务错误：

```json
{
  "result": {
    "ok": false,
    "result": null,
    "error": {
      "code": "NAME_NOT_FOUND",
      "message": "name `alice` was not found",
      "name": "alice",
      "doc_type": null,
      "expected": null,
      "actual": null
    }
  },
  "sys": [42]
}
```

信封类型：

```ts
interface BnsRpcEnvelope<T> {
  ok: boolean;
  result: T | null;
  error: BnsRpcErrorInfo | null;
}

interface BnsRpcErrorInfo {
  code: string;
  message: string;
  name: string | null;
  doc_type: string | null;
  expected: number | null;
  actual: number | null;
}
```

参数无法反序列化或 method 未注册时，失败发生在 kRPC 层，不会返回上述 BNS 业务错误信封。
`BnsIndexerClient` 会把这类失败映射为 `BnsClientError::Transport`。

## 2. 当前接口总览

当前 `/kapi/bns` 有 11 个可用方法：10 个读取方法和 1 个 raw TX 写方法。

| method | 兼容别名 | params | 信封内 `result` | 状态 |
| --- | --- | --- | --- | --- |
| `name.query_state` | `query_name_state` | `BnsNameReq` | `NameState \| null` | 可用 |
| `name.resolve_owner` | `resolve_owner` | `BnsNameReq` | `OwnerResolution` | 可用 |
| `authority.get_set` | `get_authority_set` | `BnsNameReq` | `AuthoritySetState` | 可用 |
| `authority.get_key` | `get_authority_key` | `BnsAuthorityKeyReq` | `AuthorityKey \| null` | 可用 |
| `document.resolve` | `resolve_document` | `BnsDocumentReq` | `ResolveResult` | 可用 |
| `document.get_version` | `get_document_version` | `BnsDocumentVersionReq` | `DocumentState \| null` | 可用 |
| `name.query_by_addr` | `query_names_by_address`、`query_by_addr` | `BnsAddressReq` | `BnsNamePage` | 可用 |
| `tx.query_state` | `query_tx_state` | `BnsTxHashReq` | `BnsTxState` | 可用 |
| `tx.submit_raw` | `submit_raw_tx` | `BnsSubmitRawTxReq` | `BnsSubmitRawTxResp` | 可用 |
| `events.list` | `list_events` | `BnsListEventsReq` | `EventLogRecord[]` | 可用 |
| `checkpoint.latest` | `latest_checkpoint` | `{}` | `LogCheckpoint \| null` | 可用 |

BNS-Client 始终使用点号形式的 canonical method；下划线别名只用于兼容旧调用方。

## 3. 读取接口

### 3.1 `name.query_state`

查询名称的完整投影状态。

```json
{
  "name": "alice"
}
```

返回 `NameState | null`。名称不存在时底层结果为 `null`；名称格式非法时返回
`INVALID_NAME`。

### 3.2 `name.resolve_owner`

解析名称当前生效的语义 owner，以及该 owner 对应的 authority 信息。

```json
{
  "name": "alice"
}
```

返回 `OwnerResolution`。名称不存在时返回 `NAME_NOT_FOUND`。

### 3.3 `authority.get_set`

查询名称的 authority 集合摘要。

```json
{
  "name": "alice"
}
```

返回 `AuthoritySetState`。当前实现找不到 authority set 记录时返回一个空集合：
`authority_seq = 0`、`active_key_count = 0`、`authority_root = ZERO_HASH`。

### 3.4 `authority.get_key`

按 `kid` 查询单个 authority key。

```json
{
  "name": "alice",
  "kid": "owner-key-1"
}
```

返回 `AuthorityKey | null`；key 不存在时底层结果为 `null`。

### 3.5 `document.resolve`

解析指定名称和 `doc_type` 的当前文档，同时返回名称、owner、controller、alias 和投影证明信息。

```json
{
  "name": "alice",
  "doc_type": "owner"
}
```

返回 `ResolveResult`。名称不存在时返回 `NAME_NOT_FOUND`；从未发布过该类型文档时返回
`DOCUMENT_NOT_FOUND`。

### 3.6 `document.get_version`

读取文档的指定历史版本。

```json
{
  "name": "alice",
  "doc_type": "owner",
  "version": 1
}
```

返回 `DocumentState | null`；指定版本不存在时底层结果为 `null`。

### 3.7 `events.list`

按事件序号顺序读取投影事件日志。

```json
{
  "from_seq": 100,
  "limit": 50
}
```

返回 `EventLogRecord[]`。查询条件是 `seq >= from_seq`，结果按 `seq` 升序排列，最多返回
`limit` 条。继续翻页时可把下一次 `from_seq` 设为上一页最后一条的 `seq + 1`。

### 3.8 `checkpoint.latest`

读取 `last_seq` 最大的日志 checkpoint。

```json
{}
```

返回 `LogCheckpoint | null`；还没有 checkpoint 时底层结果为 `null`。

### 3.9 `name.query_by_addr`

通过一个 EVM 地址查询该地址持有的 name 列表。“持有”严格指当前 `NameState.asset_owner`，
不按可能继承或指向 BNS name 的 `effective_owner` 查询。

请求：

```json
{
  "address": "0x0123456789abcdef0123456789abcdef01234567",
  "cursor": null,
  "limit": 100
}
```

返回：

```json
{
  "names": ["alice", "bob.example"],
  "next_cursor": null
}
```

分页规则：

- EVM 地址会解析并规范化为小写 `0x` 十六进制地址；非法地址返回 `INVALID_ADDRESS`。
- SQLite 投影使用 `(asset_owner, name)` 联合索引，结果按 canonical name 的字典序稳定排序。
- `cursor` 是上一页最后一个 canonical name；下一页查询 `name > cursor`，不重复返回 cursor
  对应项。cursor 格式非法时返回 `INVALID_NAME`。
- `limit` 必须在 `1..=1000`；否则返回 `INVALID_LIMIT`。
- 只有确实存在下一页时 `next_cursor` 才有值，其值为本页最后一个 name。

类型：

```ts
interface BnsAddressReq {
  address: string;
  cursor: string | null;
  limit: number;
}

interface BnsNamePage {
  names: string[];
  next_cursor: string | null;
}
```

### 3.10 `tx.query_state`

按交易 hash 查询交易是否仍在 pending、已经成功执行、已经 revert，或者链节点尚未找到该交易。
返回非 nullable 的状态对象，以避免 `result: null` 与 BNS 信封缺少 result 的现有歧义。

请求：

```json
{
  "tx_hash": "0x0123...abcd"
}
```

返回：

```json
{
  "tx_hash": "0x0123...abcd",
  "state": "succeeded",
  "block_number": 12345,
  "confirmations": 3
}
```

类型：

```ts
type BnsTxExecutionState = "not_found" | "pending" | "succeeded" | "reverted";

interface BnsTxHashReq {
  tx_hash: string;
}

interface BnsTxState {
  tx_hash: string;
  state: BnsTxExecutionState;
  block_number: number | null;
  confirmations: number;
}
```

判定规则：

- receipt 存在且 `status == 0`：`reverted`；其他 receipt 状态：`succeeded`。
- receipt 不存在、但 `eth_getTransactionByHash` 找到交易：`pending`。
- receipt 和 transaction 都找不到：`not_found`。
- 已入块交易的确认数定义为 `latest_block - receipt_block + 1`；pending、not found 或 receipt
  缺少 block number 时为 `0`。

`not_found` 只表示当前上游节点没有该 transaction 和 receipt，无法区分“从未见过”、mempool
丢弃、同 nonce 替换或节点裁剪历史。需要这种区分时，调用方应自行保存提交记录和 replacement
关系。

当前 `BnsEvmControllerClient::wait_for_receipt` 已能由 Client 直连链节点轮询 receipt，并可通过
`with_receipt_wait(...)` 在提交后等待指定确认数；它适合提交方主动等待，`tx.query_state` 则适合
任意 BNS-Client 后续查询。

## 4. 写接口

### 4.1 `tx.submit_raw`

提交已经签名的 EVM raw transaction。BNS-Server 只做 hex 解码，然后调用链节点的
`eth_sendRawTransaction`；Server 不签名、不校验 calldata 业务含义，最终授权由 BNS 合约根据
`msg.sender` 执行。

请求：

```json
{
  "raw_tx": "0x02f901..."
}
```

`raw_tx` 约束：

- 字符串 trim 后不能为空；
- `0x` 前缀可有可无；
- hex 字符长度必须为偶数；
- 必须是有效 hex。

返回：

```json
{
  "tx_hash": "0x0123...abcd"
}
```

返回成功只表示链节点接受了该 raw TX，并不表示交易已打包或执行成功。需要确认最终状态时，
客户端还应查询 transaction receipt。

无效 hex 返回 `SERIALIZATION_ERROR`；链节点连接失败或拒绝提交通常返回
`RPC_TRANSPORT_ERROR`。

#### 手续费由谁设置

`tx.submit_raw` 本身不能设置或修改手续费。EIP-1559 raw TX 在签名之前已经包含以下字段：

- `gas_limit`
- `max_fee_per_gas`
- `max_priority_fee_per_gas`

这些字段参与签名；BNS-Server 收到 raw TX 后如果修改任何字段，签名就会失效。因此手续费必须
由构造并签名交易的一方设置，而不是作为 `tx.submit_raw` 的额外参数传入。

当前 BNS-Client 从 `BnsEvmClientConfig` 读取上述三个值。`BnsEvmClientConfig::anvil(...)` 的
默认值为：

| 字段 | 默认值 | 单位 |
| --- | --- | --- |
| `gas_limit` | `3_000_000` | gas |
| `max_fee_per_gas` | `2_000_000_000` | wei/gas，即 2 gwei |
| `max_priority_fee_per_gas` | `1_000_000_000` | wei/gas，即 1 gwei |

`EthRpcClient` 提供 `gas_price`、`max_priority_fee_per_gas`、`estimate_gas` 和
`suggest_eip1559_fees`。动态 fee cap 使用
`2 * eth_gasPrice + eth_maxPriorityFeePerGas`，为短期 base fee 增长保留余量。

`BnsEvmStandardClient::build_unsigned_tx_with_suggestion(call, from, nonce)` 会调用上述 helper，
给 `eth_estimateGas` 结果增加向上取整的 20% buffer，并同时返回 unsigned TX 和
`BnsEvmTxSuggestion`。`BnsEvmControllerClient` 可通过 `with_dynamic_tx_params(true)` 对每笔交易
启用相同流程。该选项默认关闭，以保留 Anvil 测试和自定义 fee policy 的确定性；生产调用方应
显式开启，或继续自行提供经过评估的静态配置。

### 4.2 交易构造、签名与提交 helper

当前已有交易构造 helper，无需调用方手工编码 ABI：

| 层次 | 现有 helper | 作用 |
| --- | --- | --- |
| 合约调用对象 | `register_name_call`、`bootstrap_name_call`、`apply_mutations_call`、`publish_document_call`、`revoke_document_call`、`set_min_document_iat_call`、`set_controller_policy_call`、`update_authority_keys_call` | 把 BNS 请求结构转换为 Alloy `SolCall` |
| calldata | `BnsEvmStandardClient::build_calldata` | ABI 编码一个 `SolCall` |
| unsigned TX | `BnsEvmStandardClient::build_unsigned_tx` | 使用 config 和调用方传入的 nonce 构造 `TxEip1559` |
| 动态 unsigned TX | `BnsEvmStandardClient::build_unsigned_tx_with_suggestion` | 使用 `eth_estimateGas` 和动态 EIP-1559 fee suggestion 构造交易 |
| 签名 | `BnsEvmKeyManager::sign_transaction`、`StaticBnsEvmKeyManager` | 对 `TxEip1559` 签名并生成 raw TX |
| 完整流程 | `BnsEvmControllerClient::sign_and_submit` 及各业务方法 | 获取 nonce、构造、签名、提交，并可选等待 receipt |

`BnsEvmStandardClient::build_unsigned_tx(call, nonce)` 使用 `BnsEvmClientConfig` 中的
`chain_id`、`contract_address`、`gas_limit`、`max_fee_per_gas` 和
`max_priority_fee_per_gas`，并把 `value` 设为 0。

Standard Client 要求调用方自行传入 nonce；Controller Client 会通过
`eth_getTransactionCount(address, "pending")` 获取初始 nonce，并在进程内串行提交和缓存后续
nonce。提交失败时会清除缓存，下次重新查询链节点。

典型的外部签名流程为：

```rust
let call = register_name_call(&request)?;
let unsigned_tx = standard_client.build_unsigned_tx(&call, nonce)?;
let signed_tx = key_manager.sign_transaction(&sign_request, unsigned_tx).await?;
let response = bns_server.submit_raw_tx(
    BnsSubmitRawTxReq::from_bytes(&signed_tx.raw_tx),
).await?;
```

## 5. 公共响应数据结构

以下为 JSON 对应的 TypeScript 风格描述。Rust 的 `u64`、`u32` 和 `usize` 当前都编码为 JSON
number；JavaScript 调用方处理可能超过 `Number.MAX_SAFE_INTEGER` 的 `u64` 时需要特别注意。
Rust 的 `Vec<u8>` 编码为 JSON 整数数组，而不是 base64 字符串。

### 5.1 枚举与 Principal

```ts
type NameStatus =
  | "available" | "active" | "expired" | "released" | "tombstoned";

type DocumentStatus =
  | "missing" | "active" | "revoked" | "expired" | "migrated" | "tombstoned";

type AliasKind = "none" | "alias" | "migrated_to" | "canonical";

type PrincipalKind = "unset" | "chain_account" | "bns_name";
type OwnerSource =
  | "none" | "asset_owner_fallback" | "explicit_semantic_owner" | "parent_inherited";
type AuthorityKeyStatus = "missing" | "active" | "revoked" | "expired";

interface Principal {
  kind: PrincipalKind;
  value: string;
}
```

### 5.2 名称与 owner

```ts
interface NameState {
  name: string;
  asset_owner: string;
  semantic_owner: Principal;
  effective_owner: Principal;
  owner_source: OwnerSource;
  standard_transfer_enabled: boolean;
  status: NameStatus;
  registered_at: number;
  expire_at: number;
  grace_until: number;
  updated_at: number;
  name_seq: number;
  owner_document_version: number;
  min_document_iat: number;
  owner_policy_seq: number;
  lineage_epoch: number;
  renewable: boolean;
  transferable: boolean;
  allow_delegated_subnames: boolean;
  namespace_policy_hash: string;
  payment_policy_hash: string;
  alias_state_hash: string;
}

interface OwnerResolution {
  effective_owner: Principal;
  source: OwnerSource;
  authority_root: string;
  authority_seq: number;
}
```

### 5.3 Authority

```ts
interface AuthoritySetState {
  name: string;
  authority_seq: number;
  authority_root: string;
  active_key_count: number;
}

interface AuthorityKey {
  kid: string;
  verification_method: string;
  key_data: number[];
  purposes: number;
  valid_from: number;
  valid_until: number;
  status: AuthorityKeyStatus;
  metadata_hash: string;
}
```

`AuthorityKey.purposes` 是位掩码：`1` 表示 authentication，`2` 表示 recovery，`4` 表示
sign-document，可以按位组合。

### 5.4 Document

```ts
interface DocumentRef {
  storage_type: string;
  uri: string;
  inline_document: number[];
  content_hash: string;
  schema: string;
  codec: string;
  extra_hash: string;
}

interface DocumentState {
  name: string;
  doc_type: string;
  version: number;
  previous_version: number;
  status: DocumentStatus;
  document: DocumentRef;
  controller: Principal;
  beneficiary: Principal;
  payment_target: string;
  valid_from: number;
  expire_at: number;
  revoked_at: number;
  controller_policy_hash: string;
  payment_policy_hash: string;
  split_policy_hash: string;
  price_policy_hash: string;
  rights_policy_hash: string;
  document_state_hash: string;
}

interface ResolveResult {
  name_state: NameState;
  document_state: DocumentState;
  owner: OwnerResolution;
  effective_controller: Principal;
  status: DocumentStatus;
  alias_kind: AliasKind;
  alias_target_did: string;
  proof_root: string;
}
```

### 5.5 Event 与 checkpoint

```ts
interface EventLogRecord {
  seq: number;
  event_type: string;
  observed_at: number;
  event_hash: string;
  previous_log_root: string;
  log_root: string;
  event: {
    type: string;
    data: Record<string, unknown>;
  };
}

interface LogCheckpoint {
  log_root: string;
  last_seq: number;
  issued_at: number;
  issuer: Principal;
  external_anchor: string;
}
```

`event.type` 及其 `data` 字段如下：

| `event.type` | `data` 字段 |
| --- | --- |
| `name_registered` | `name`, `asset_owner`, `expire_at`, `lineage_epoch`, `name_seq` |
| `name_renewed` | `name`, `expire_at`, `name_seq` |
| `name_asset_transferred` | `name`, `old_asset_owner`, `new_asset_owner`, `standard_transfer`, `name_seq` |
| `name_owner_updated` | `name`, `owner`, `owner_source`, `standard_transfer_enabled`, `name_seq` |
| `authority_keys_updated` | `name`, `authority_seq`, `authority_root` |
| `name_released` | `name`, `mode`, `reason_hash`, `name_seq` |
| `document_published` | `name`, `doc_type`, `version`, `content_hash`, `document_state_hash` |
| `document_revoked` | `name`, `doc_type`, `previous_version`, `new_version`, `reason_hash` |
| `owner_document_iat_floor_updated` | `name`, `previous_min_document_iat`, `new_min_document_iat`, `owner_policy_seq`, `name_seq`, `reason_hash` |
| `controller_policy_updated` | `name`, `policy_hash`, `name_seq` |
| `namespace_policy_updated` | `name`, `allow_delegated_subnames`, `namespace_policy_hash`, `name_seq` |
| `did_alias_set` | `name`, `target_did`, `kind`, `proof_hash`, `name_seq` |
| `payment_target_updated` | `name`, `doc_type`, `payment_target`, `payment_policy_hash`, `version` |
| `log_checkpoint_published` | `log_root`, `last_seq`, `issued_at`, `external_anchor` |

其中 `name_released.data.mode` 为 `release_after_grace` 或 `tombstone_forever`。
注意 `owner_document_iat_floor_updated` 事件当前的外层 `EventLogRecord.event_type` 值为
`owner_iat_floor_updated`，与内层 `event.type` 不同；消费方应优先按内层带 tag 的 `event` 反序列化。

## 6. 参数格式与常见错误

名称和文档类型在读取时都会进行 canonical 校验：

- `name` 不能带 `did:bns:` 前缀，总长最多 253 字节；只允许小写 ASCII 字母、数字、`-` 和
  `.`；每个 label 最多 126 字节，不能为空且不能以 `-` 开头或结尾。
- `doc_type` 最长 32 字节；只允许小写 ASCII 字母、数字、`-` 和 `_`。
- `name.query_by_addr.address` 必须是 20 字节 EVM 地址；`tx.query_state.tx_hash` 必须是 32 字节
  transaction hash。

常见错误码：

| code | 含义 |
| --- | --- |
| `INVALID_NAME` | 名称格式非法 |
| `INVALID_DOC_TYPE` | 文档类型格式非法 |
| `INVALID_ADDRESS` | EVM 地址格式非法 |
| `INVALID_LIMIT` | 分页 limit 不在 `1..=1000` |
| `NAME_NOT_FOUND` | 名称不存在 |
| `DOCUMENT_NOT_FOUND` | 当前文档不存在 |
| `DOCUMENT_INCONSISTENT` | 投影文档与链上状态不一致 |
| `SERIALIZATION_ERROR` | Client/Server JSON、raw TX hex 或 transaction hash 编解码失败 |
| `RPC_TRANSPORT_ERROR` | HTTP/kRPC 或上游 EVM RPC 调用失败 |
| `SQLITE_ERROR` / `DB_LOCK_POISONED` | 本地投影存储失败 |

`error.name`、`error.doc_type`、`error.expected`、`error.actual` 仅在对应错误包含这些上下文时
有值，其余情况下为 `null`。

## 7. 已删除的遗留写 RPC

Beta2.2 已从 BNS-Client 和 BNS-Server 删除遗留中心化写 RPC 的 method 常量、响应类型、
`BnsIndexerApi` trait 方法、kRPC client 调用和 server/indexer route。以下 method 现在统一由 kRPC
返回 `UnknownMethod`：

- `name.register`
- `name.bootstrap`
- `mutation.apply`
- `document.publish`
- `document.revoke`
- `owner.set_min_document_iat`
- `controller.set_policy`
- `authority.update_keys`

`BnsRegisterNameReq`、`BnsBootstrapNameReq`、`BnsApplyMutationsReq`、`BnsPublishDocumentReq` 等请求
结构仍保留，因为 EVM calldata 构造、签名管理器和 SN BNS Controller 会复用这些业务参数；保留
请求结构不代表存在同名 RPC。

正确写入流程为：

```text
BNS-Controller / 外部签名方
  -> 构造 BNS 合约 calldata
  -> 构造并签名 EIP-1559 transaction
  -> BNS-Client 调用 tx.submit_raw
  -> BNS-Server 调用 eth_sendRawTransaction
  -> BNS 合约按 msg.sender 和合约状态执行鉴权
```

## 8. 当前实现注意事项

1. 读接口返回的是 Indexer 投影，不保证与链 tip 同步；需要结合 Indexer 同步状态判断新鲜度。
2. `tx.submit_raw` 不等待 receipt；方法成功不能替代交易成功确认。可随后调用
   `tx.query_state`，或由提交方使用 `wait_for_receipt`。
3. `BnsRpcEnvelope<T>` 用 `Option<T>` 同时表示“信封是否有 result”和“业务结果可为空”。对于
   `NameState | null`、`AuthorityKey | null`、`DocumentState | null`、`LogCheckpoint | null`
   这类结果，Server 可以在线上返回 `ok: true, result: null`，但当前 Rust
   `BnsIndexerClient::into_result` 会把反序列化后的 `null` 当成“信封缺少 result”，返回
   `INVALID_RESPONSE`。在该实现修正前，Rust kRPC 调用方不能依赖这些接口的成功空值路径。
