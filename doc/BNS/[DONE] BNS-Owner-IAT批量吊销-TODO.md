# BNS Owner IAT 批量吊销合约改造 TODO

> 目标读者：CodeAgent / 合约实现者。
> 状态：合约仍在开发中、未上线，可以接受 ABI 和存储结构 breaking change。

## 背景

当前 `revokeDocument(name, docType, ..., revokedBeforeIat, ...)` 只实现了精确 `name + docType` 的当前版本吊销。`revokedBeforeIat` 只进入事件和 event log hash，没有进入合约状态，也没有被 `resolveDocument`、indexer、SN resolver 用来判断文档有效性。

这不能解决下面的安全场景：

1. Owner 私钥泄露。
2. 攻击者用泄露私钥签署大量二级名字或设备文档。
3. 这些二级名字/文档默认可以不上链，Owner 不知道完整列表。
4. 如果只能逐个精确吊销，无法清理未知残留文档。

需要一个 Owner 级别的安全阈值：Owner 声明“由我控制的文档，只有 `iat >= minDocumentIat` 才有效”。当 Owner 发现私钥泄露后，提高该阈值，并重新签发自己仍需要的文档。

## 设计结论

### 这不是普通 publishDocument 的参数

不要把这个能力设计成通用 `publishDocument` 的普通参数。

原因：

- `publishDocument` 是 `name + docType` 的链上当前版本状态机，影响的是某个精确文档。
- IAT 批量吊销影响的是 Owner 签名能力下的所有链下文档，尤其是未上链的二级名字文档。
- 把它塞进普通 `publishDocument` 会让参数含义依赖 `docType == "owner"` 或“一级名字”，容易出现调用者以为普通文档发布也带有批量吊销语义。

正确建模：把它作为 Owner 安全策略状态。

### 它可以写在 OwnerDocument 里，但合约状态必须有权威字段

OwnerDocument / OwnerConfig 可以包含同名字段，作为人可读配置和链下 schema 的一部分，例如：

```json
{
  "public_key": { "...": "..." },
  "min_document_iat": 1770000000
}
```

但如果需要全网 resolver 一致执行，合约必须暴露权威状态字段或权威 view。不要只依赖合约不解析的 OwnerDocument JSON 内容，否则：

- 合约无法证明该策略确实生效。
- indexer/resolver 容易遗漏解析。
- controller 可能错误发布 owner 文档但没有更新安全阈值。

推荐做法：

- 合约状态保存 `minDocumentIat`。
- OwnerDocument 中可以镜像该值。
- 如果两者不一致，resolver 必须以合约状态为准。

### 权限控制属于 Owner 级权限，不属于 controller 文档权限

提高 `minDocumentIat` 等价于批量吊销旧 Owner 签名文档，风险等级接近 authority key rotation。第一版应只允许 effective owner 执行。

不要让普通 controller 通过 `PERMISSION_PUBLISH_DOCUMENT` 或 `PERMISSION_REVOKE_DOCUMENT` 设置该阈值。SN controller 也不应拥有这个能力。

## 合约改造 TODO

### 1. 新增 Owner 安全策略状态

在 `NameState` 增加字段，或增加独立 mapping。合约未上线，优先直接加字段，读 API 更简单。

建议字段名：

```solidity
uint64 minDocumentIat;
uint64 ownerPolicySeq;
```

语义：

- `minDocumentIat == 0` 表示不启用 IAT floor。
- 当 `minDocumentIat > 0` 时，Owner 签名的链下文档必须满足 `iat >= minDocumentIat`。
- 缺少 `iat` 的链下签名文档在 floor 启用后必须视为无效。
- 比较使用 Unix seconds。
- 使用 `iat < minDocumentIat` 判无效，`iat == minDocumentIat` 有效。
- `ownerPolicySeq` 每次 owner 安全策略更新递增，用于 resolver/cache 判断策略变化。

命名不要继续使用 `revokedBeforeIat` 作为状态字段。该名字适合事件描述，不适合作为当前策略字段。

### 2. 新增 owner-only setter

新增函数：

```solidity
function setMinDocumentIat(
    string calldata name,
    uint64 minDocumentIat,
    bytes32 reasonHash,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 nameSeq, uint64 ownerPolicySeq);
```

规则：

- `name` 必须是 active name。
- 必须通过 `_authorizeOwner(...)`。
- 必须检查 `MutationGuard`。
- `minDocumentIat` 必须单调不降：`new >= old`。
- 更新时递增 `state.nameSeq`、`state.ownerPolicySeq`，并更新 `state.updatedAt`。
- 发事件并写入 `_commitEvent`。

单调不降的理由：降低 floor 会重新激活已经被安全事件吊销的旧签名文档。第一版不提供降低能力。误设过高时，Owner 应重新签发所需文档。

### 3. 新增事件

新增专用事件：

```solidity
event OwnerDocumentIatFloorUpdated(
    bytes32 indexed nameHash,
    string name,
    address indexed actor,
    uint64 previousMinDocumentIat,
    uint64 newMinDocumentIat,
    uint64 ownerPolicySeq,
    uint64 nameSeq,
    bytes32 reasonHash
);
```

同时新增 `EVENT_OWNER_IAT_FLOOR_UPDATED = keccak256("owner_iat_floor_updated")`，并在 `_commitEvent` payload 中包含：

```solidity
abi.encode(
    nameHash,
    previousMinDocumentIat,
    newMinDocumentIat,
    ownerPolicySeq,
    state.nameSeq,
    reasonHash
)
```

### 4. 修改 applyMutations 支持原子恢复

密钥泄露后的标准恢复流程通常需要在一个 TX 里完成：

1. 撤销旧 authority key。
2. 添加新 authority key。
3. 发布新的 owner 文档。
4. 提高 `minDocumentIat`。

当前 `applyMutations` 只支持 authority key + documents。建议增加 owner policy update 入参，避免恢复流程拆成多个 TX。

建议结构：

```solidity
struct OwnerPolicyUpdate {
    bool updateMinDocumentIat;
    uint64 minDocumentIat;
    bytes32 reasonHash;
}
```

修改签名：

```solidity
function applyMutations(
    string calldata name,
    AuthorityKeyUpdate[] calldata authorityUpdates,
    DocumentUpdate[] calldata documents,
    OwnerPolicyUpdate calldata ownerPolicy,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot, uint64 ownerPolicySeq);
```

规则：

- `ownerPolicy.updateMinDocumentIat == true` 时必须 owner-only。
- 如果同时包含 authority updates 和 owner policy update，只做一次 `_authorizeOwner`。
- `documents` 仍按当前 docType controller/owner policy 授权，但如果同一批中含 `docType == "owner"` 或 owner policy update，建议要求整批 owner-only，避免 SN controller 借批量调用参与 owner 恢复。
- `nameSeq` 在一个批量 TX 中只递增一次，或者明确文档化每类状态递增规则。推荐一次。

### 5. 清理 revokeDocument 中的 revokedBeforeIat

合约未上线，建议移除 `revokeDocument` 的 `revokedBeforeIat` 参数和 `DocumentRevoked` 事件字段，避免产生“已经实现批量吊销”的误解。

如果为了兼容内部代码暂时保留：

- 明确标注 deprecated。
- 不要让 resolver/indexer 从 `DocumentRevoked.revokedBeforeIat` 推导 owner floor。
- 真正的 owner floor 只能来自 `NameState.minDocumentIat` 或 `OwnerDocumentIatFloorUpdated` 投影。

### 6. Owner policy source 规则

不要在合约里硬编码“一级名字”字符串层级作为唯一判断。

推荐 resolver 侧规则：

- 对链上精确文档：以 `resolveDocument(name, docType)` 的 current status 为准。
- 对链下 Owner 签名文档：先解析目标 name 的 effective owner，再找到对应的 owner policy source。
- 常见场景下，`device.alice` 继承 `alice` 的 owner，因此使用 `alice.minDocumentIat`。
- 如果 `semanticOwner = BnsName("org")`，则该文档由 `org` authority key 签名时，resolver 应使用 `org` 的 owner policy，或者明确要求业务层使用 target namespace 的 policy。这个规则必须写入测试，不能靠实现者猜。

第一版如果不想引入复杂 owner-policy-source 解析，可以先规定：

- 对未上链二级名字，使用最近的已注册父名字作为 policy source。
- 对显式 `semanticOwner = BnsName(x)` 的名字，使用 `x` 作为 policy source。

### 7. resolve/query API

`queryNameState` 返回的 `NameState` 必须包含：

- `minDocumentIat`
- `ownerPolicySeq`

如果为了减少 `NameState` 膨胀，也可以新增：

```solidity
function getOwnerPolicy(string calldata name) external view returns (
    uint64 minDocumentIat,
    uint64 ownerPolicySeq,
    bytes32 proofRoot
);
```

但由于当前 ABI 已经返回完整 `NameState`，优先直接加入 `NameState`。

## Rust / Indexer / Resolver 联动 TODO

### 1. bns-evm / ABI

- 重新 `forge build`。
- 更新 `bns-evm` alloy binding。
- 更新 calldata builder：`setMinDocumentIat` 和新的 `applyMutations` 签名。
- 更新事件 decode：`OwnerDocumentIatFloorUpdated`。

### 2. bns-client model

更新：

- `NameState` 增加 `min_document_iat`、`owner_policy_seq`。
- `RegistryEvent` 增加 `OwnerDocumentIatFloorUpdated`。
- RPC request/response 增加 `BnsSetMinDocumentIatReq/Resp`。

### 3. bns-indexer projection

- 从链上 `queryNameState` 读取新字段并写入投影。
- 投影事件表保留 `OwnerDocumentIatFloorUpdated`。
- `resolve_document` 返回的 `ResolveResult.name_state` 必须带新字段。

### 4. SN resolver

resolver 必须在所有 Owner 签名链下文档路径执行 IAT floor：

- `device_mini_config_jwt`
- 聚合 `zone` 文档中嵌入的 `mini_config_jwt`
- 独立 child BNS document 中承载的 JWT
- 未来其它 Owner 签名的 off-chain document

验证顺序：

1. 解析 owner / owner config，拿到 owner public key。
2. 验证 JWT 签名。
3. 从已验证 claims 中读取 numeric `iat`。
4. 读取 policy source 的 `minDocumentIat`。
5. 如果 `minDocumentIat > 0` 且 `iat < minDocumentIat`，拒绝该文档。
6. 如果 `minDocumentIat > 0` 且缺少 `iat`，拒绝该文档。

不要使用未验签 claims 做最终判断。

### 5. 顺手修正 revoked document 读取

当前 BNS reader 需要确认 `ResolveResult.status == Active` 后再解码 inline document。Revoked/Missing/Expired 不应被当作有效文档返回给 SN resolver。

## 合约测试 TODO

新增 Foundry 测试：

- owner 可以 `setMinDocumentIat`，`NameState` 字段更新，`nameSeq` 和 `ownerPolicySeq` 递增。
- 非 owner 不能设置。
- 普通 controller 即使有 `PUBLISH_DOCUMENT` / `REVOKE_DOCUMENT` 权限，也不能设置。
- `minDocumentIat` 不能降低。
- 事件字段正确。
- `applyMutations` 可以原子完成 authority key 更新 + owner 文档发布 + floor 提升。
- `applyMutations` 中包含 owner policy update 时，SN controller 无法借批量调用更新。
- `registerName` 初始化 `minDocumentIat = 0`、`ownerPolicySeq = 0`。
- Released 后重新注册的名字策略重置，并由 `lineageEpoch` 表达信任断点。

## Resolver 集成测试 TODO

新增 Rust/SN resolver 测试：

- Owner floor 为 0 时，旧无 `iat` 的兼容 JWT 行为按迁移策略处理。
- Owner floor > 0 时，无 `iat` JWT 被拒绝。
- `iat < minDocumentIat` 被拒绝。
- `iat == minDocumentIat` 被接受。
- `iat > minDocumentIat` 被接受。
- 未上链 child name 的旧签名文档被父 owner floor 拒绝。
- Owner 重新签发的新 child document 被接受。
- 显式 `semanticOwner = BnsName(x)` 的 policy source 行为有固定测试。

## 文档更新 TODO

同步更新：

- `doc/BNS/BNS 智能合约接口设计.md`
- `doc/BNS/SN-BNS-Contoller.md`
- `doc/BNS/BNS-签名边界改造-EVM-TX-TODO.md`
- BNS README / smoke example

需要明确写下：

- `revokeDocument` 是精确文档 current pointer revoke。
- `setMinDocumentIat` 是 Owner 级批量吊销旧签名文档。
- OwnerDocument 可以镜像 `min_document_iat`，但合约状态是权威。
- SN controller 默认不能设置 owner IAT floor。
