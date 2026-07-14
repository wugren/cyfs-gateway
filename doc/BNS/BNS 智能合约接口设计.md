# BNS 智能合约接口设计

> 版本：v0.3
> 本文定义的是可确定执行的 BNS Registry 状态机接口。当前实现是中心化模拟服务；未来可以在不改变核心业务语义的前提下切换为智能合约实现。

本文基于 `认识BNS.md` 和 `BNS 去中心的名字系统.md`，把 BNS 的协议目标收敛成一组与实现方式无关的接口。

这里的“合约”首先表示一份可验证、可重放、状态转换确定的逻辑合约，不要求第一版立即部署到公链。当前中心化实现负责模拟同一套状态机、权限检查和事件日志；未来的 EVM、Move 或其它链实现只需要替换认证适配器和持久化层，不应改变 owner、controller、document version 等核心语义。

BNS Registry 不保存所有 DID Document，也不替代内容网络、支付合约、DNS、SN 或 Zone resolver。它只保存不能由中心化 provider 单方面覆盖的全局事实（中心化阶段，这一不可单方面覆盖性由 §16.2 的防篡改 checkpoint 提供可审计保证，而不是由去中心化提供）：

- 名字是否存在、对应的名字资产归谁、是否过期、是否允许标准 NFT 转移。
- 名字当前由哪个 BuckyOS 语义 owner 控制，以及该 owner 的可验证 key 状态。
- `did:bns:$name + doc_type` 当前版本、历史版本及吊销状态。
- 哪个 owner 或 controller 可以执行某类状态更新。
- 名字是否迁移、别名指向哪里、旧状态如何追溯。
- 收款目标、收益策略和支付流程需要绑定的 purchase context。

## 1. 实现目标与设计边界

### 1.1 逻辑接口先于部署形态

当前和未来实现共享同一个核心状态机：

```text
当前中心化实现
  BNS RPC / HTTP
      -> RPC authentication adapter
      -> IBnsRegistryCore
      -> centralized state store + append-only event log

未来智能合约实现
  direct transaction / signed executor
      -> chain authentication adapter
      -> IBnsRegistryCore
      -> contract storage + chain events
```

核心接口不感知登录 session、HTTP header、RPC request signature、nonce 或 relayer。它只接收已经由执行环境认证过的调用主体，并根据更新前的 BNS 状态判断该主体是 owner 还是 controller。

因此：

- RPC 签名属于传输层或调用适配层，不属于每一个业务接口。
- 链上直接调用可以从 `msg.sender` 得到认证主体。
- 链上代理调用可以由独立的 `executeSigned(...)` 验证签名、nonce 和 deadline，再调用同一套核心状态机。
- 核心接口中的 `CallAuthority` 类似 `kid`/key selector：它说明使用哪个主体、哪个 key、按哪个角色申请授权，但它本身不是签名证明。
- 中心化实现不得直接相信客户端提交的 `CallAuthority`；必须由认证适配器验证并注入。
- 链上实现不得直接相信调用者自报的 `role` 或 `actor`；必须从 `msg.sender` 或已验证签名中推导并复核。

### 1.2 Registry 必须负责

- `did:bns:$name` 的全局名字状态和名字资产状态。
- 名字资产 owner、BuckyOS 语义 owner、controller 三者的明确区分。
- 语义 owner 和 controller 使用的链上可验证 authority key 状态。
- DID Document 的 `doc_type` 版本、当前指针、内容 hash、吊销状态和历史 proof anchor。
- Owner key 轮换、controller policy 更新、alias 和 migration。
- 支付流程可查询的 beneficiary、payment target 和 policy hash。
- 确定性的状态序号和事件日志，供 resolver、indexer、钱包和未来链上迁移使用。

### 1.3 Registry 不负责

- `did:dev` 自认证设备身份。`did:dev` 由设备公钥和握手证明；BNS 文档只能引用它。
- 大型 DID Document、AppDoc、content meta、ZoneConfig、ObjId bytes 的默认托管。Registry 通常只保存 `DocumentRef` 和 hash；调用者也可以选择 inline 保存短文档。
- 解析或信任 DID Document 内部的 owner/controller 字段。Registry 不依赖文档内容做本次授权。
- 内容购买扣款和 receipt 发行。标准支付合约或中心化支付模拟器负责 `purchase(...)`。
- DNS TXT、`.well-known`、SN、Repo、Source、HTTPS 或本地缓存的可信化。它们只能提供候选内容。
- 全文搜索、排名、信用评分、应用商店和推荐。

### 1.4 逻辑状态与物理存储可以不同

接口层明确暴露 `assetOwner`、`semanticOwner`、`effectiveOwner` 等语义。具体实现可以分表保存，也可以归一化成统一状态，只要所有查询结果、权限判断、状态转换和事件输出与本文一致。

## 2. 核心接口分层

一个实现可以把接口部署在同一个服务或合约中，但协议上分为四个接口面：

```text
IBnsRegistryCore
  名字生命周期
  authority key 生命周期
  文档版本生命周期
  controller / alias / payment policy

IBnsResolverView
  queryNameState / resolveOwner / resolveDocument
  getDocumentVersion / getAlias / getAuthoritySet

IBnsPaymentView
  resolvePaymentTarget / getPurchaseContext

IBnsInvocationAdapter
  RPC session / request signature
  direct chain caller / signed transaction executor
  生成经过认证的 CallAuthority
```

`IBnsRegistryCore` 是唯一改变协议状态的接口。`IBnsInvocationAdapter` 只负责认证、防重放和调用封装，不定义 BNS 权限。

## 3. Owner、Controller 与 Document 声明

### 3.1 三种 owner 概念

BNS 中存在三种容易混淆但语义不同的 owner：

| 名称 | 含义 | 是否能授权 Registry 状态更新 |
| --- | --- | --- |
| `assetOwner` | 名字 NFT 的产权持有人 | 仅在它是当前 fallback owner 时可以 |
| `semanticOwner` | Registry 显式记录的 BuckyOS owner | 可以，是最高 BuckyOS 权限来源 |
| `documentOwner` | DID Document 内容里声明的 owner | 不可以，只是链下文档声明 |

其中 `semanticOwner` 对 `assetOwner` 是覆盖关系，不是并列关系。

### 3.2 effective owner

Registry 对每个名字计算唯一的 `effectiveOwner`：

```text
一级名字：
  semanticOwner == Unset
      -> effectiveOwner = assetOwner
      -> ownerSource = AssetOwnerFallback

  semanticOwner == BnsName(x)
      -> effectiveOwner = BnsName(x)
      -> ownerSource = ExplicitSemanticOwner

二级名字：
  semanticOwner == Unset
      -> effectiveOwner = parent.effectiveOwner
      -> ownerSource = ParentInherited

  semanticOwner == BnsName(x)
      -> effectiveOwner = BnsName(x)
      -> ownerSource = ExplicitSemanticOwner
```

只有当前 `effectiveOwner` 能执行 owner 级操作。

因此：

- `assetOwner` 不是一个永远有效的独立授权分支。
- 一级名字未配置 `semanticOwner` 时，`assetOwner` 才是 owner。
- 一旦设置显式 `semanticOwner`，该名字的 `assetOwner` 不再拥有更新、释放、owner 变更或标准 NFT 转让权限。
- 二级名字继承父 owner 时，其自身 `assetOwner` 也不是有效 owner。
- 将 `semanticOwner` 清回 `Unset` 后，权限才按上述 fallback 规则重新计算。

### 3.3 semantic owner 是 authority name

第一版中，显式 `semanticOwner` 只允许指向一个 BNS name，不直接保存任意公钥：

```text
semanticOwner = BnsName("org")
```

这表示名字由 `org` 的链上可验证 authority key set 控制，而不是由 `org` 名字 NFT 的 owner 自动控制。

设置 `semanticOwner = BnsName(x)` 前，`x` 必须：

- 是有效 BNS name；
- 拥有至少一个当前有效、可用于认证的 authority key；
- 能被当前实现支持的 verifier 验证。

这样，当 `alice.semanticOwner = BnsName("org")` 后：

- `alice.assetOwner` 的传统 NFT 权限失效；
- 更新 `alice` 必须使用 `org` authority set 中的有效 key；
- `org` 轮换 authority key 后，所有由 `org` 控制的名字自动使用新 key；
- Registry 不需要读取 `org` 的 DID Document 才能完成授权判断。

一个名字可以先由 `assetOwner` 写入初始 authority key，再把 `semanticOwner` 设置为自身或另一个 authority name，从而完成从 NFT fallback 控制到显式 key 控制的迁移。

### 3.4 controller

controller 是低于 owner 的受限授权主体：

- owner 可以更新名字级状态和所有文档。
- controller 只能执行 policy 允许的操作。
- controller 可以按 `doc_type`、名字范围、时间和 permission bitmap 限制。
- controller 可以是链账户，也可以是拥有 authority key set 的 BNS name。
- 如果一个 `doc_type` 没有匹配的 controller，则回落到当前 effective owner。
- controller 无权通过提交一份新文档，把自己提升为 owner 或扩大本次调用权限。

### 3.5 Document 内的 owner/controller

DID Document、OwnerConfig 或 AppDoc 中可以声明 owner、controller、verification method 和 payment 信息，但这些字段不参与 Registry 本次状态更新的授权。

正确关系是：

```text
Registry 显式状态
  -> 决定谁有权更新

Document 内部声明
  -> 由有权更新者负责写正确
  -> 由 resolver 在取回文档后校验
```

标准 resolver 必须确认文档中的声明覆盖并符合 Registry 记录。如果文档缺少 Registry 要求的 owner/controller，或者与 Registry 状态冲突，则该文档非法。文档可以声明更多链下用途的 key 或 service，但不能借此获得 Registry 权限。

### 3.6 owner 图不变量与防 brick

由于显式 `semanticOwner` 一旦生效，对应名字的 `assetOwner` 权限**立即彻底失效**（见 §3.2），`semanticOwner = BnsName(x)` 会把若干名字串成一张有向图。如果不加约束，这张图可能出现环或不可达，导致名字被永久锁死且无任何恢复路径。

第一版强制以下不变量：

- **有界深度。** 解析任意名字的 effective 控制方时，沿 `semanticOwner = BnsName` 边的跳数不得超过 `MAX_OWNER_REF_DEPTH = 8`。超过即视为非法状态。
- **无环。** `semanticOwner` 形成的有向图必须无环。
- **可达具体签名者。** 任意 Active 名字必须能在 `MAX_OWNER_REF_DEPTH` 跳内解析到至少一个具体可用签名者，即某个 `AssetOwnerFallback` 链账户，或某个拥有至少一个当前有效认证 key 的 authority name。

任何会把 `semanticOwner` 设为 `BnsName` 的写操作（`setNameOwner`、`transferName`、带 `initialSemanticOwner` 的 `registerName`）在提交前必须基于更新前状态做一次图检查：

- 若新边会构成环，拒绝，错误码 `OWNER_GRAPH_CYCLE`。
- 若新状态会使本名字（或图中任何受其影响的名字）失去可达的具体签名者，拒绝，错误码 `NO_CONCRETE_SIGNER`。
- 若解析深度会超过 `MAX_OWNER_REF_DEPTH`，拒绝，错误码 `OWNER_GRAPH_TOO_DEEP`。

完整的 social recovery 状态机仍属于第一版暂不解决的范围（见 §17），但上述检查是**现在就必须存在**的最小兜底，确保任何单步合法操作都不会把名字变成不可恢复的死状态。`assetOwner` 在显式 semantic owner 模式下不再拥有日常权限，但实现**可以**保留一条受时间锁保护、仅用于「图已无可用签名者」这一极端情形的 recovery-only 通道；该通道的具体设计留待 recovery 状态机一并定义。

## 4. NFT 转让语义

每个已注册 name 可以对应一份 ERC-721 或等价名字资产。`assetOwner` 必须等价于该名字资产的当前持有人。

但是标准 NFT 转让只在下面条件全部成立时启用：

```text
name.transferable == true
AND name.ownerSource == AssetOwnerFallback
AND name.status == Active
```

即：

```text
standardTransferEnabled(name)
    = transferable
      && effectiveOwner source is AssetOwnerFallback
```

所有标准转让路径，包括 `transferFrom`、两个 `safeTransferFrom`、approved address 和 operator，都必须经过同一个底层检查。

### 标准转让启用时

- 当前 `assetOwner` 同时就是 effective owner。
- 标准 NFT 转让成功后，新的 `assetOwner` 自动成为新的 effective owner。
- 不需要额外修改 semantic owner，因为它仍然是 `Unset`。

### 标准转让禁用时

以下任一情况都会禁用普通 ERC-721 transfer：

- 名字设置了显式 semantic owner；
- 二级名字正在继承父 owner；
- 名字被 policy 标记为不可转让；
- 名字不处于 Active 状态。

此时只能调用 BNS-aware 的 `transferName(...)`。该接口由更新前的 effective owner 授权，可以原子更新：

- `assetOwner`；
- `semanticOwner`；
- controller policy；
- payment target；
- 相关文档版本。

因此，通用 NFT 市场只能交易 fallback 模式的名字。显式语义 owner 控制的名字必须通过理解 BNS 状态的市场或交易流程转移。

## 5. name、DID、doc_type 与版本约定

### 5.1 name 与 DID

核心 Registry 接口统一接收不带 `did:bns:` 前缀的 canonical name：

```text
alice
jarvis.alice
book1.alice
filebrowser.buckyos
$objid.alice
```

RPC resolver 可以提供 `resolveDid("did:bns:alice", ...)` 便捷接口，但内部必须先转换为 canonical name，再调用核心 view。

名字规则：

- 名字最多两级，不存在三级或更深的全局名字。
- 一级名字示例：`alice`。
- 二级名字示例：`abc.alice`、`$objid.alice`。
- 二级名字的父级必须是有效一级名字。
- exact global name 的优先级永远高于 delegated subname。
- `did:dev` 不进入全局名字资产表。
- `did:web` 只能作为 discovery 或 alias 目标，不能覆盖 BNS 状态。

### 5.2 二级名字

- 注册二级名字默认需要父名字当前 effective owner 授权。
- 二级名字注册后拥有独立名字资产、状态序号、文档版本和 payment context。
- 二级名字 `semanticOwner = Unset` 时继承父名字 effective owner。
- 二级名字显式设置 semantic owner 后，不再继承父 owner。
- 某个 `doc_type` 显式配置 controller 后，该类型不再继承父 controller。
- 二级名字继承父 owner 时，标准 NFT transfer 被禁用。

### 5.3 doc_type

`doc_type` 使用 canonical lower-case ASCII string，建议限制在 32 bytes 以内，按 byte exact match。

第一版标准类型：

| doc_type | 语义 |
| --- | --- |
| `owner` | OwnerConfig / user profile |
| `boot` | ZoneBootConfig |
| `zone` | ZoneConfig |
| `doc` | 通用 DID Document |
| `device` | DeviceConfig 或设备文档指针 |
| `service` | ServiceInfo |
| `agent` | AgentDocument |
| `app` | AppDoc |
| `video` | 视频内容文档 |
| `music` | 音乐内容文档 |
| `ebook` | 电子书内容文档 |
| `content` | 通用内容 meta |
| `payment` | 支付策略扩展文档 |

DNS 记录型文档保留 `dns_` 前缀：

```text
doc_type = "dns_" + lower_case_dns_rrtype
```

其中 `lower_case_dns_rrtype` 是传统 DNS 记录类型的小写名字，例如 `dns_a`、`dns_aaaa`、`dns_cname`、`dns_mx`、`dns_txt`、`dns_srv`、`dns_caa`、`dns_ns`。

当通过 `publishDocument` 发布 `doc_type = dns_xxx` 的文档时，`DocumentRef` 指向的文档内容可以是一组同类型 DNS 记录数组。该数组表示同一个 `(name, rrtype)` 的 RRset；记录类型由 `doc_type` 隐含，数组元素只需要保存该类型对应的 rdata、ttl 以及必要的优先级、权重、端口等字段。建议使用 canonical JSON array，以保证 `contentHash` 稳定。

示例：

```json
[
  { "ttl": 600, "value": "v=spf1 include:_spf.example.net -all" },
  { "ttl": 600, "value": "google-site-verification=..." }
]
```

依赖 BNS 合约的 DNS Server 可以把传统 DNS 查询 `(qname, qtype)` 映射为 `resolveDocument(canonical_name(qname), "dns_" + lower_case(qtype))`，验证 `DocumentRef.contentHash` 后从记录数组合成 DNS Answer。这样，即使权威数据来自 BNS Registry，仍能兼容 `TXT`、`MX`、`AAAA` 等传统 DNS 记录查询模型。

`info` 是运行时上报信息，默认不作为 Registry 文档类型。

### 5.4 版本和并发保护

每个 `(name, docType)` 维护单调递增的 `version`：

- `version = 0` 表示不存在。
- 发布新版本必须匹配更新前的 `expectedVersion`。
- 名字级变更必须匹配更新前的 `expectedNameSeq`。
- `expectedVersion` 和 `expectedNameSeq` 是状态并发保护，不是身份认证。
- 历史版本和事件不删除。

谱系连续性：

- `nameSeq` 在名字的**整个生命周期内单调递增，跨 `Released -> 重新注册` 不重置**。它天然是该名字事件流的连续性指纹。
- 名字经历 `Released -> 重新注册` 时，`lineageEpoch` 加一，并重新发出 `NameRegistered`（其 `nameSeq` 严格大于该名字此前任何事件）。
- 跨 `lineageEpoch` 边界的 effective owner 变化属于**信任断点**：客户端、钱包和信用系统不得把新世代的 owner 与旧世代的历史 receipt、签名或信用记录默认视为同一主体。
- 对已售出内容或有非平凡历史的高价值名字，建议默认采用 `TombstoneForever` 而非 `ReleaseAfterGrace`，从根本上避免名字被重注册后造成身份混淆。

## 6. 协议级数据类型

以下是逻辑 IDL。具体实现可以映射为 Solidity、Move、Rust service types 或其它语言。

```solidity
enum NameStatus {
    Available,
    Active,
    Expired,
    Released,
    Tombstoned
}

enum DocumentStatus {
    Missing,
    Active,
    Revoked,
    Expired,
    Migrated,
    Tombstoned
}

enum AliasKind {
    None,
    Alias,
    MigratedTo,
    Canonical
}

enum ReleaseMode {
    ReleaseAfterGrace,
    TombstoneForever
}

enum PrincipalKind {
    Unset,
    ChainAccount,
    BnsName
}

enum OwnerSource {
    None,
    AssetOwnerFallback,
    ExplicitSemanticOwner,
    ParentInherited
}

enum AuthorityRole {
    None,
    Owner,
    Controller
}

enum AuthorityKeyStatus {
    Missing,
    Active,
    Revoked,
    Expired
}

struct Principal {
    PrincipalKind kind;
    bytes value;
}

// Principal 语义：
// - Unset: 未配置。
// - ChainAccount: ABI encoded chain account/address；合约账户也使用该类型。
// - BnsName: canonical BNS name UTF-8 bytes。

struct CallAuthority {
    // 本次调用走 owner 还是 controller 授权分支。
    AuthorityRole role;

    // 经过认证的主体。不得直接信任客户端自报值。
    Principal actor;

    // actor key set 中的 key identifier。
    // ChainAccount 直接调用时可以为 0 或由 adapter 生成规范值。
    bytes32 kid;
}

// CallAuthority 不是签名，不包含 nonce/deadline。
// 它必须由 RPC/chain invocation adapter 在完成认证后注入。

struct MutationGuard {
    // 被修改 name 的更新前 nameSeq。
    uint64 expectedNameSeq;

    // 仅二级名字首次注册或依赖父状态的原子操作使用；其它情况为 0。
    uint64 expectedParentNameSeq;
}

struct AuthorityKey {
    bytes32 kid;

    // eip155-account、erc1271、secp256k1、ed25519、custom-verifier 等。
    bytes32 verificationMethod;

    // address、public key bytes、contract address 或 verifier-specific material。
    bytes keyData;

    // authentication/recovery/sign_document 等用途位图。
    uint32 purposes;

    uint64 validFrom;
    uint64 validUntil;
    AuthorityKeyStatus status;

    bytes32 metadataHash;
}

struct AuthorityKeyUpdate {
    AuthorityKey key;

    // true 表示添加或替换；false 表示撤销对应 kid。
    bool active;
}

struct AuthoritySetState {
    string name;
    uint64 authoritySeq;
    bytes32 authorityRoot;
    uint32 activeKeyCount;
}

struct DocumentRef {
    // inline、ipfs、cyfs、https、zone-resolver、source、repo 等。
    bytes32 storageType;
    string uri;

    // storageType = inline 时保存完整文档原文；否则必须为空。
    bytes inlineDocument;

    // 文档原文的内容 hash。
    bytes32 contentHash;

    // 文档 schema / codec，例如 OwnerConfig v1、AppDoc v1、canonical-json。
    bytes32 schema;
    bytes32 codec;

    bytes32 extraHash;
}

struct NameState {
    string name;

    // 名字资产当前持有人。
    address assetOwner;

    // 显式 BuckyOS 语义 owner，只允许 Unset 或 BnsName。
    Principal semanticOwner;

    // 以下三个字段可以由 view 动态计算，不要求物理存储。
    Principal effectiveOwner;
    OwnerSource ownerSource;
    bool standardTransferEnabled;

    NameStatus status;

    uint64 registeredAt;
    uint64 expireAt;
    uint64 graceUntil;
    uint64 updatedAt;

    uint64 nameSeq;
    uint64 ownerDocumentVersion;

    // 谱系世代：每次名字经历 Released -> 重新注册 时 +1，全生命周期单调。
    // 用于让 resolver、钱包、信用系统检测「同名但已换主」的信任断点。
    uint64 lineageEpoch;

    bool renewable;
    bool transferable;
    bool allowDelegatedSubnames;

    bytes32 namespacePolicyHash;
    bytes32 paymentPolicyHash;
    bytes32 aliasStateHash;
}

struct DocumentState {
    string name;
    string docType;
    uint64 version;
    uint64 previousVersion;

    DocumentStatus status;
    DocumentRef document;

    // controller 可为 Unset、ChainAccount 或 BnsName。
    Principal controller;
    Principal beneficiary;
    address paymentTarget;

    uint64 validFrom;
    uint64 expireAt;
    uint64 revokedAt;

    bytes32 controllerPolicyHash;
    bytes32 paymentPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;
    bytes32 documentStateHash;
}

struct ControllerRule {
    // ChainAccount 或 BnsName。
    Principal controller;

    // 空字符串表示全部 doc_type。
    string docType;

    // create/update/revoke/set_payment/set_alias/delegate 等位图。
    uint32 permissions;

    bytes32 namespaceScopeHash;
    uint64 validFrom;
    uint64 validUntil;
    bytes32 constraintHash;
}

struct RegisterOptions {
    uint64 duration;
    uint64 gracePeriod;
    bool renewable;
    bool transferable;

    // 一级名字 Unset -> assetOwner fallback。
    // 二级名字 Unset -> 继承父 effective owner。
    Principal initialSemanticOwner;

    bool allowDelegatedSubnames;

    address initialPaymentTarget;
    bytes32 initialPaymentPolicyHash;
    bytes32 initialNamespacePolicyHash;
}

struct DocumentUpdate {
    string docType;
    uint64 expectedVersion;

    DocumentRef document;
    Principal controller;
    Principal beneficiary;
    address paymentTarget;
    uint64 expireAt;

    bytes32 controllerPolicyHash;
    bytes32 paymentPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;
}

struct OwnerResolution {
    Principal effectiveOwner;
    OwnerSource source;

    // 注意：authorityRoot/authoritySeq 指向「实际控制方」的 authority set。
    // 当 effectiveOwner = BnsName(org) 时，这里是 org 的 authority set，
    // 而不是被解析名字自身的 set。getAuthoritySet(name) 返回的才是该 name 自己的 set，
    // 两者在 fallback 模式下相同、在显式 semantic owner 模式下通常不同。
    bytes32 authorityRoot;
    uint64 authoritySeq;
}

struct ResolveResult {
    NameState nameState;
    DocumentState documentState;
    OwnerResolution owner;

    Principal effectiveController;
    DocumentStatus status;

    AliasKind aliasKind;
    string aliasTargetDid;

    bytes32 proofRoot;
}

struct AliasState {
    string name;
    AliasKind kind;
    string targetDid;
    bytes32 proofHash;
    uint64 setAt;
    uint64 nameSeq;
}

struct PurchaseContext {
    string name;
    string docType;
    uint64 documentVersion;

    Principal beneficiary;
    address paymentTarget;
    bytes32 paymentPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;

    DocumentStatus status;
    bytes32 proofRoot;
}

struct LogCheckpoint {
    // 截至 lastSeq 为止整个 append-only event log 的承诺，例如事件序列的 Merkle root。
    bytes32 logRoot;

    // 本 checkpoint 覆盖到的最后一个全局事件序号。
    uint64 lastSeq;

    uint64 issuedAt;

    // 运营方（中心化阶段）或治理合约（链上阶段）的签名主体。
    Principal issuer;

    // 可选：把 logRoot 锚定到某条公链时的外部锚点引用 hash。
    bytes32 externalAnchor;
}
```

## 7. Authority key 接口

Authority key 是 Registry 可见、可验证的授权状态。它与 `owner` 文档中的 verification method 可以对应，但不能只存在于文档内。

### getAuthoritySet

```solidity
function getAuthoritySet(string calldata name)
    external view returns (AuthoritySetState memory state);
```

### getAuthorityKey

```solidity
function getAuthorityKey(string calldata name, bytes32 kid)
    external view returns (AuthorityKey memory key);
```

### updateAuthorityKeys

```solidity
function updateAuthorityKeys(
    string calldata name,
    AuthorityKeyUpdate[] calldata updates,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (
    uint64 authoritySeq,
    bytes32 authorityRoot
);
```

规则：

- 本次授权依据是 `name` 更新前的 effective owner。
- `authority.role` 必须是 `Owner`。
- `authority.actor` 必须等于更新前的 effective owner。
- 如果 actor 是 BnsName，`kid` 必须是该 actor authority set 中的有效认证 key。
- 如果 actor 是 ChainAccount，执行适配器必须证明本次调用来自该账户。
- 新增 key 不能授权其自身所在的本次调用。
- 删除或撤销 key 后，之后的调用立即不能再使用该 key。
- authority key 变化会影响所有把该 name 作为 semantic owner 或 controller 的名字。
- 当一个 authority name 正在控制其它名字时，实现应阻止无恢复路径地删除最后一个有效认证 key，或者要求在同一原子操作中迁移 owner。

### rotateAuthorityAndOwnerDocument

Registry 可以提供一个原子快捷接口，同时更新链上 authority key 和 `owner` 文档：

```solidity
function rotateAuthorityAndOwnerDocument(
    string calldata name,
    AuthorityKeyUpdate[] calldata keyUpdates,
    DocumentUpdate calldata ownerDocumentUpdate,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (
    uint64 authoritySeq,
    uint64 ownerDocumentVersion
);
```

其中：

- authority key 状态决定 Registry 授权。
- owner document 只负责向 resolver 和客户端声明相同或更丰富的 key 信息。
- Registry 不解析 owner document 来决定本次调用是否有效。

## 8. 名字资产接口

### queryNameState

```solidity
function queryNameState(string calldata name)
    external view returns (NameState memory state);
```

回答名字是否存在、资产持有人、显式 owner、effective owner、owner 来源及标准 NFT transfer 是否启用。

### resolveOwner

```solidity
function resolveOwner(string calldata name)
    external view returns (OwnerResolution memory result);
```

该接口必须返回当前 effective owner 和其 authority root。客户端不应仅通过 `assetOwner` 判断控制权。

### registerName

```solidity
function registerName(
    string calldata name,
    address assetOwner,
    RegisterOptions calldata options,
    DocumentUpdate[] calldata initialDocuments,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external payable returns (uint64 nameSeq);
```

规则：

- 注册只接受 canonical name，最多两级。
- 注册成功后 mint 或绑定同名 NFT。
- 一级名字注册由 registrar policy、公开注册规则、拍卖或其它部署策略决定；此时 `authority.role` 可以为 `None`。
- 二级名字首次注册必须由父名字更新前的 effective owner 授权；此时 `authority.role = Owner`，并校验 `guard.expectedParentNameSeq`。
- 一级名字 `initialSemanticOwner = Unset` 时，effective owner 为 `assetOwner`。
- 二级名字 `initialSemanticOwner = Unset` 时，继承父 effective owner。
- `initialSemanticOwner = BnsName(x)` 时，`x` 必须有有效 authority key set，并通过 §3.6 的图检查。
- 重新注册一个已 `Released` 的名字时，`lineageEpoch` 加一，`nameSeq` 续用该名字的历史最大值继续递增（不重置）。
- 初始文档不能授权本次注册。
- exact global name 优先于 delegated subname。

### renewName

```solidity
function renewName(string calldata name, uint64 duration)
    external payable returns (uint64 expireAt);
```

规则：

- 任何人可以代付续期费用。
- 续期不改变 owner、controller、authority key 或文档版本。
- 过期不删除历史。

### isStandardTransferEnabled

```solidity
function isStandardTransferEnabled(string calldata name)
    external view returns (bool enabled);
```

所有 ERC-721 transfer 路径必须调用等价的内部检查。

### transferName

```solidity
function transferName(
    string calldata name,
    address newAssetOwner,
    Principal calldata newSemanticOwner,
    DocumentUpdate[] calldata atomicDocumentUpdates,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 nameSeq);
```

规则：

- 授权主体必须是更新前的 effective owner。
- `newSemanticOwner` 只允许 `Unset` 或 `BnsName`。
- 设置为 BnsName 时，目标 authority set 必须有效。
- 该接口可以在普通 ERC-721 transfer 被禁用时改变 `assetOwner`。
- 所有原子文档更新分别校验 `DocumentUpdate.expectedVersion`。
- 新 owner、controller、文档和 payment 字段不能授权本次调用。
- 一级名字 `newSemanticOwner = Unset` 后，新 `assetOwner` 成为 effective owner。
- 二级名字 `newSemanticOwner = Unset` 后，重新继承父 effective owner。
- `newSemanticOwner` 为 `BnsName` 时，同样必须通过 §3.6 的图检查后才能提交。

### setNameOwner

```solidity
function setNameOwner(
    string calldata name,
    Principal calldata semanticOwner,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 nameSeq);
```

规则：

- 只有更新前的 effective owner 可以调用。
- `semanticOwner` 只允许 `Unset` 或 `BnsName`。
- `BnsName(x)` 必须存在有效 authority key set。
- 设置显式 semantic owner 后，asset owner 权限立即失效，标准 NFT transfer 立即禁用。
- 清回 `Unset` 后，按一级/二级 fallback 规则重新计算 effective owner。
- 若新 owner 是本 name 自身，应先写入至少一个有效 authority key，再切换 owner，避免名字被锁死。
- 设置 `semanticOwner = BnsName` 前必须通过 §3.6 的图检查（无环、可达具体签名者、深度不超限），否则按对应错误码拒绝。

### releaseName

```solidity
function releaseName(
    string calldata name,
    ReleaseMode mode,
    bytes32 reasonHash,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 nameSeq);
```

只有 effective owner 可以释放或永久 tombstone 名字。`assetOwner` 仅在 AssetOwnerFallback 模式下等于 effective owner。

### setNamespacePolicy

```solidity
function setNamespacePolicy(
    string calldata name,
    bool allowDelegatedSubnames,
    bytes32 namespacePolicyHash,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 nameSeq);
```

只有 effective owner 或被明确授予该 permission 的 controller 可以调用。

## 9. DID 文档接口

### resolveDocument

```solidity
function resolveDocument(
    string calldata name,
    string calldata docType
) external view returns (ResolveResult memory result);
```

这是核心 view。RPC resolver 可以额外暴露：

```solidity
function resolveDid(
    string calldata did,
    string calldata docType
) external view returns (ResolveResult memory result);
```

`resolveDid` 只负责把 `did:bns:$name` 转换为 canonical name，再调用 `resolveDocument`。

### getDocumentVersion

```solidity
function getDocumentVersion(
    string calldata name,
    string calldata docType,
    uint64 version
) external view returns (DocumentState memory state);
```

用于验证旧签名、旧 receipt、旧 ObjId 和审计记录。

### publishDocument

```solidity
function publishDocument(
    string calldata name,
    string calldata docType,
    uint64 expectedVersion,
    DocumentRef calldata document,
    Principal calldata controller,
    Principal calldata beneficiary,
    address paymentTarget,
    uint64 expireAt,
    bytes32 controllerPolicyHash,
    bytes32 paymentPolicyHash,
    bytes32 splitPolicyHash,
    bytes32 pricePolicyHash,
    bytes32 rightsPolicyHash,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 version);
```

授权规则：

- 先读取更新前的 NameState、OwnerResolution、DocumentState 和 controller policy。
- `expectedVersion` 必须等于当前版本。
- `guard.expectedNameSeq` 必须匹配更新前状态。
- `authority.role = Owner` 时，actor 必须是更新前的 effective owner。
- `authority.role = Controller` 时，actor 和 kid 必须命中一个当前有效且允许本操作的 controller rule。
- asset owner 只有在 ownerSource 为 AssetOwnerFallback 时才能作为 owner actor。
- 新文档、新 controller、新 payment target 都不能授权本次调用。
- Registry 只验证 `DocumentRef`、hash 和显式状态字段，不解析文档内 owner/controller。

完整文档规则：

- `storageType = inline` 时，`inlineDocument` 保存完整原文，`uri` 应为空。
- JSON 文档应先生成 canonical JSON UTF-8 bytes。
- `contentHash` 必须等于文档原文 hash。
- 链下 provider 返回的文档也必须匹配同一 `contentHash`。
- `docType` 使用 `dns_` 前缀时，文档原文建议为 canonical JSON 记录数组；该数组表示对应 DNS 记录类型的 RRset，供 DNS Server 验证 hash 后转换为传统 DNS Answer。
- inline 文档应有大小上限（建议 `MAX_INLINE_DOCUMENT = 4 KiB`），仅用于短 OwnerConfig、关键 tombstone 说明等；超限文档必须走 `DocumentRef` 外链。该上限在中心化阶段防止状态膨胀，在未来链上实现里同时也是 gas 保护。

### revokeDocument

```solidity
function revokeDocument(
    string calldata name,
    string calldata docType,
    uint64 expectedVersion,
    bytes32 reasonHash,
    uint64 revokedBeforeIat,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 newVersion, uint64 nameSeq);
```

owner 或具有 revoke permission 的 controller 可以吊销当前文档状态。吊销不删除历史，也不原地修改旧版本。

current 指针语义（防静默降级）：

- `expectedVersion` 只作为并发保护，必须等于当前版本。
- `expectedVersion = 0` 表示此前没有链上文档，允许首次发布负声明（`Missing -> Revoked v1`）。
- 吊销总是创建新的当前版本，例如 `Active v1 -> Revoked v2`。
- `resolveDocument` 必须返回当前 `status = Revoked`，绝不自动回滚到任何更早的 Active 版本。
- 要恢复一个可用的当前版本，必须显式 `publishDocument` 发布新版本；新版本的 `version` 仍单调递增，不复用旧号。

### setControllerPolicy

```solidity
function setControllerPolicy(
    string calldata name,
    ControllerRule[] calldata rules,
    bytes32 policyHash,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 nameSeq);
```

规则：

- 默认只有 effective owner 可以改变 controller policy。
- controller rule 中的 BnsName controller 必须拥有有效 authority key set。
- policy 只影响未来调用。
- 文档内部 controller 声明不能替代该接口。

### setDidAlias

```solidity
function setDidAlias(
    string calldata name,
    string calldata targetDid,
    AliasKind kind,
    bytes32 proofHash,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 nameSeq);
```

只有 effective owner 或具有对应 permission 的 controller 可以调用。alias/migration 不改写历史 DID、receipt 或签名。

### getAlias

```solidity
function getAlias(string calldata name)
    external view returns (AliasState memory state);
```

### setPaymentTarget

```solidity
function setPaymentTarget(
    string calldata name,
    string calldata docType,
    uint64 expectedVersion,
    address paymentTarget,
    Principal calldata beneficiary,
    bytes32 paymentPolicyHash,
    bytes32 splitPolicyHash,
    bytes32 pricePolicyHash,
    bytes32 rightsPolicyHash,
    CallAuthority calldata authority,
    MutationGuard calldata guard
) external returns (uint64 version);
```

owner 或具有 `set_payment` permission 的 controller 可以调用。收益主体不等于控制权 owner。

## 10. 调用认证适配器

### 10.1 中心化模拟实现

中心化 BNS service 的建议流程：

```text
1. 接收 RPC request。
2. 验证 session、request signature 或其它认证凭证。
3. 根据签名定位 actor 和 kid。
4. 生成经过认证的 CallAuthority。
5. 调用 IBnsRegistryCore。
6. Core 根据更新前状态验证 actor 是 owner 还是 controller。
7. 原子写入状态并追加事件。
```

RPC 层可以使用自己的 envelope：

```solidity
struct RpcSignedInvocation {
    bytes callData;
    Principal actor;
    bytes32 kid;
    uint64 nonce;
    uint64 deadline;
    bytes signature;
}
```

但该结构不进入每个业务接口，也不作为 Registry 持久状态。

### 10.2 未来链上直接调用

```text
actor = ChainAccount(msg.sender)
kid   = adapter-defined chain account key id
```

合约仍必须根据当前 BNS 状态判断 `msg.sender` 是否等于 effective owner 或匹配 controller rule。

### 10.3 未来链上代理调用

链上可以提供独立的：

```solidity
function executeSigned(SignedInvocation calldata invocation)
    external returns (bytes memory result);
```

该层负责：

- 签名验证；
- nonce；
- deadline；
- chain / contract domain separation；
- 从签名恢复 actor 和 kid；
- 生成 CallAuthority；
- 调用同一套 Registry Core。

是否支持 relayer、session key、ERC-1271 或非 EVM key，是 adapter 能力，不改变业务接口。

## 11. 统一授权算法

所有写操作遵循同一原则：

```text
authorize_update(name, doc_type, operation, callAuthority, guard):
  1. adapter 已完成调用认证，得到 actor + kid。
  2. 加载更新前的 NameState。
  3. 校验 expectedNameSeq / expectedVersion。
  4. 计算更新前的 effectiveOwner。

  5. if callAuthority.role == Owner:
       assert actor == effectiveOwner
       assert kid/account 对 effectiveOwner 当前有效
       assert operation 属于 owner 权限

     else if callAuthority.role == Controller:
       找到匹配 actor + kid + doc_type + operation 的有效 controller rule

     else:
       仅允许无需 owner/controller 的公开操作，例如 root registration 或 renew

  6. 使用更新前状态完成授权。
  7. 原子应用新状态。
  8. 增加 nameSeq / document version / authoritySeq。
  9. 追加事件。
```

关键约束：

- `CallAuthority.role` 只是授权分支选择，不是调用者自证身份。
- `kid` 是 key selector，不是权限本身。
- asset owner 只有在 `ownerSource = AssetOwnerFallback` 时具有 owner 权限。
- 显式 semantic owner 或父 owner 一旦生效，asset owner 权限消失。
- 新提交的 owner、key、controller 或文档不能授权本次提交。
- Document 内容永远不能单独授权 Registry 写操作。
- 支付目标可以由 owner 或被授权的 payment controller 更新。
- release、tombstone、transferName、setNameOwner、authority key rotation 默认是 owner 级高风险操作。

## 12. Resolver 映射规则

标准 resolver 的强验证路径：

```text
resolve(did:bns:$name, doc_type):
  1. 规范化 DID，得到 canonical name。
  2. 查询 exact NameState 和 OwnerResolution。
  3. 查询当前 DocumentState。
  4. 从 inline 或 DocumentRef provider 获取文档原文。
  5. 校验 hash(document) == contentHash。
  6. 查询 effective owner/controller 的 Registry authority 状态。
  7. 校验文档中的 owner/controller/key 声明覆盖 Registry 状态且不冲突。
  8. 输出 document、effective owner、controller、proof、provider/cache/warnings。
```

注意：

- 第 6 步使用 Registry 显式 authority key，不依赖文档自报。
- 第 7 步是校验文档是否写对，不是反过来让文档决定谁有权限。
- 文档中看不到、漏写或冲突的 owner/controller 会使文档无效，但不会改变 Registry owner。

二级名字 delegated fallback：

```text
resolve(did:bns:cam01.alice, doc):
  1. exact global name 存在 -> 使用 exact state。
  2. exact name 不存在 -> 查询父名字 alice。
  3. alice.allowDelegatedSubnames == true -> 获取父 zone/owner resolver。
  4. provider 返回子名字文档。
  5. 使用 alice 当前 effective owner/controller authority 校验。
```

三级名字不进入该 fallback。

## 13. 支付查询接口（V2 概念）

BNS 不扣款，不发行购买 receipt，只提供可绑定的 purchase context。

### getPurchaseContext

```solidity
function getPurchaseContext(
    string calldata name,
    string calldata docType
) external view returns (PurchaseContext memory context);
```

### resolvePaymentTarget

```solidity
function resolvePaymentTarget(
    string calldata name,
    string calldata docType,
    uint64 version
) external view returns (
    Principal memory beneficiary,
    address paymentTarget,
    bytes32 paymentPolicyHash,
    bytes32 splitPolicyHash,
    bytes32 pricePolicyHash,
    bytes32 rightsPolicyHash,
    bytes32 proofRoot
);
```

购买 receipt 至少绑定：

- buyer；
- name；
- doc_type；
- document version；
- amount / token；
- payment target；
- payment/split/price/rights policy hash；
- proof root；
- transaction / block 或中心化模拟事件序号。

## 14. 事件

中心化模拟实现和未来智能合约都应产生语义一致的 append-only 事件。

> 编码注意（链上实现）：Solidity 中 `string indexed` 只把字符串的 keccak 哈希写进 topic，原文不可从日志恢复。未来链上实现若要 indexer 同时能按 name 过滤又能读出可读 name，应把 name 以非 indexed 形式放进 data，另加一个 `bytes32 indexed nameHash` 供过滤。中心化阶段 event log 为结构化记录，name 是可读列，不受此限。下文事件签名沿用逻辑形态。

```solidity
event NameRegistered(
    string indexed name,
    address indexed assetOwner,
    uint64 expireAt,
    uint64 lineageEpoch,
    uint64 nameSeq
);

event NameRenewed(
    string indexed name,
    uint64 expireAt,
    uint64 nameSeq
);

event NameAssetTransferred(
    string indexed name,
    address indexed oldAssetOwner,
    address indexed newAssetOwner,
    bool standardTransfer,
    uint64 nameSeq
);

event NameOwnerUpdated(
    string indexed name,
    PrincipalKind ownerKind,
    bytes ownerValue,
    OwnerSource ownerSource,
    bool standardTransferEnabled,
    uint64 nameSeq
);

event AuthorityKeysUpdated(
    string indexed name,
    uint64 authoritySeq,
    bytes32 authorityRoot
);

event NameReleased(
    string indexed name,
    ReleaseMode mode,
    bytes32 reasonHash,
    uint64 nameSeq
);

event DocumentPublished(
    string indexed name,
    string docType,
    uint64 indexed version,
    bytes32 contentHash,
    bytes32 documentStateHash
);

event DocumentRevoked(
    bytes32 indexed nameHash,
    string name,
    string docType,
    address indexed actor,
    uint64 previousVersion,
    uint64 newVersion,
    uint64 revokedBeforeIat,
    bytes32 reasonHash
);

event ControllerPolicyUpdated(
    string indexed name,
    bytes32 policyHash,
    uint64 nameSeq
);

event NamespacePolicyUpdated(
    string indexed name,
    bool allowDelegatedSubnames,
    bytes32 namespacePolicyHash,
    uint64 nameSeq
);

event DidAliasSet(
    string indexed name,
    string targetDid,
    AliasKind kind,
    bytes32 proofHash,
    uint64 nameSeq
);

event PaymentTargetUpdated(
    string indexed name,
    string docType,
    address paymentTarget,
    bytes32 paymentPolicyHash,
    uint64 version
);

event LogCheckpointPublished(
    bytes32 indexed logRoot,
    uint64 lastSeq,
    uint64 issuedAt,
    bytes32 externalAnchor
);
```

## 15. 最小闭环接口

第一版优先实现：

```solidity
// views
queryNameState
resolveOwner
isStandardTransferEnabled
getAuthoritySet
getAuthorityKey
resolveDocument
getDocumentVersion
getAlias

// name
registerName
renewName
transferName
setNameOwner
releaseName
setNamespacePolicy

// authority
updateAuthorityKeys
rotateAuthorityAndOwnerDocument
setControllerPolicy

// document
publishDocument
revokeDocument
setDidAlias
setPaymentTarget

// payment view，V2 概念
getPurchaseContext
resolvePaymentTarget
```

这组接口形成以下闭环：

- 名字可以注册、续期、释放和转让。
- asset owner 只在 fallback 模式拥有 BuckyOS 权限。
- 显式 semantic owner 通过 Registry 可见 authority key 控制名字。
- 设置显式 owner 后，普通 ERC-721 transfer 自动失效。
- owner/controller 的认证与 RPC 签名格式解耦。
- `did + doc_type` 可以解析到可验证文档。
- 文档可以更新、吊销并保留历史版本。
- 文档内部 owner/controller 只能被校验，不能反向授予 Registry 权限。
- 中心化模拟实现和未来智能合约可以共享同一套状态转换语义。

## 16. 中心化模拟到智能合约的兼容约束

### 16.1 兼容约束

为了保证未来迁移，中心化实现必须遵守：

- 核心状态中不保存 RPC session、HTTP token 或服务端私有认证字段。
- name、doc_type、kid、hash 和事件字段使用稳定的 canonical encoding。
- 所有写操作必须原子执行并产生单调序号。
- 所有权限判断必须基于更新前状态。
- 所有 view 应能仅从 Registry 状态和事件推导。
- adapter 认证结果与 Registry 授权判断分离。
- 错误类型应稳定，例如 `STALE_NAME_SEQ`、`STALE_DOCUMENT_VERSION`、`INVALID_KID`、`NOT_EFFECTIVE_OWNER`、`CONTROLLER_SCOPE_DENIED`、`STANDARD_TRANSFER_DISABLED`、`OWNER_GRAPH_CYCLE`、`NO_CONCRETE_SIGNER`、`OWNER_GRAPH_TOO_DEEP`、`INLINE_DOCUMENT_TOO_LARGE`。
- 中心化 event log 应可导出为确定性 snapshot，供未来 genesis import、migration contract 或审计使用。
- `registerName` / `renewName` 的 `payable` 是面向链上实现的逻辑标记。中心化阶段不通过 `msg.value` 收费，注册与续期费用走业务支付通道，费用处理属于 adapter/业务层，不进入 Registry 核心状态。

### 16.2 中心化阶段的防篡改 checkpoint

本文开头声明 Registry 保存的是「不能由中心化 provider 单方面覆盖的全局事实」。在 V1，实现本身就是那个中心化 provider，因此 append-only 还不足以兑现这一声明——运营方理论上仍能改写历史。为了让该性质在中心化阶段就有**可审计**保证（而非纯信任运营方），实现必须：

- 把整个 event log 组织成可承诺结构（如按全局事件序号累积的 Merkle 树），并周期性发布 `LogCheckpoint`：`{ logRoot, lastSeq, issuedAt, issuer, externalAnchor }`，由运营方 key 签名，并以 `LogCheckpointPublished` 事件公开。
- 任意客户端、resolver 或第三方都能用最新 checkpoint 验证任一历史事件确实包含在已公开的日志中，从而检测「事后改写历史」。
- 建议把 `logRoot` 周期性 anchor 到一条公链（填入 `externalAnchor`），使运营方无法在不被发现的情况下回滚或分叉日志。
- checkpoint 序列本身必须 append-only 且 `lastSeq` 单调递增；运营方一旦发布某个 checkpoint，就不能再发布与之冲突、覆盖更早区间的另一份。

这样，从「信任运营方」降级为「信任运营方 + 任何人可事后审计」。迁移到链上时，这些已公开、已锚定的 checkpoint 可直接作为 genesis import 的 proof，使历史信任跨越迁移点而无需重新锚定。

## 17. 第一版暂不解决的问题

- 具体定价、拍卖、短名保护、保留字和争议仲裁。
- Unicode、同形字、大小写和多语言显示策略。
- 各类 public key/verifier 在具体链上的实现成本和支持范围。
- recovery/social recovery 的完整状态机（§3.6 已给出最小防 brick 兜底，完整 recovery 通道留待后续）。
- 跨链名字同步和跨链支付。
- 隐私保护；Registry 是公开状态层。
- 标准支付合约、显式分账、refund、escrow 和 receipt NFT/SBT。
- Source、indexer、review report 和信用机构的业务协议。
