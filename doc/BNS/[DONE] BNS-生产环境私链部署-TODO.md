# BNS 生产环境私链部署 TODO（稳定期 3 个月，未来可迁移公链）

> 目标：在正式发布到公链前，先让 **BNS 合约作为生产真相源** 在受控私有 EVM 环境中稳定运行至少 3 个月。
> 这不是 Anvil 长期运行模式；Anvil 只用于开发、CI 和短期集成测试。生产稳定期必须使用生产级私链节点或等价的嵌入式 EVM 执行环境。

## 0. 部署原则

- [ ] 真相源只能是 BNS 合约状态和链上事件；BNS Server / Indexer / DB 都只是读投影或缓存。
- [ ] 所有写操作必须走签名 EVM TX，使用 `msg.sender` / 合约授权逻辑作为签名边界。
- [ ] 私链稳定期不能依赖未来公链无法接受的特权：
  - [ ] 不禁用 EIP-170 contract code size limit。
  - [ ] 不依赖无限 gas、超大 block gas、特殊 opcode、特殊 precompile。
  - [ ] 不使用只有 Anvil 才支持的测试 cheat / RPC 行为。
- [ ] ABI、event schema、错误码、chainId、合约地址、部署交易和 genesis 必须纳入版本管理或发布记录。
- [ ] Indexer 数据库必须可从链上 block 0 / 部署块完整重建。

## 1. 环境分层

### 1.1 开发 / CI

- [ ] 继续使用 Anvil：
  - [ ] 快速跑 `forge test`。
  - [ ] 本地 `forge script` 冒烟测试。
  - [ ] Rust 端到端测试可用 `alloy-node-bindings` 自动拉起 Anvil。
- [ ] Anvil 可以使用固定 mnemonic、临时 state、快速重部署。
- [ ] Anvil 的 `--disable-code-size-limit` 只能作为原型/测试便利，不能作为生产兼容性依据。

### 1.2 生产稳定期私链

- [ ] 使用生产级 EVM 私链节点，建议优先评估 **Besu + QBFT**。
- [ ] 至少 4 个 validator，分布在不同机器 / 可用区 / 运维账号下。
- [ ] 节点角色分离：
  - [ ] Validator nodes：只参与共识，不对公网开放 RPC。
  - [ ] RPC nodes：只提供受控 RPC，可水平扩容。
  - [ ] Archive / backup node：用于审计、回放和索引器灾备。
- [ ] 私链必须启用持久化存储、日志轮转、监控、备份和恢复演练。
- [ ] 不建议使用 Geth Clique 作为新生产方案；Clique 已不适合作为长期新方案基础。

### 1.3 后续公链迁移

- [ ] 稳定期开始前就定义迁移边界：
  - [ ] 私链合约版本。
  - [ ] 公链候选合约版本。
  - [ ] snapshot 导出格式。
  - [ ] checkpoint 验证方式。
  - [ ] migration contract / 批量导入交易策略。
- [ ] 3 个月后不是直接“搬链”，而是：
  - [ ] 公链部署同版或升级版 BNS 合约。
  - [ ] 从私链导出 BNS state snapshot 和事件 checkpoint。
  - [ ] 在公链导入或锚定历史状态。
  - [ ] 公布私链最终 checkpoint，供外部验证历史未被改写。

## 2. 合约进入生产稳定期前的要求

- [ ] 当前 `src/apps/bns/src/Bns.sol` 原型必须瘦身或拆分，确保在标准 EVM 限制下部署：
  - [ ] deployed bytecode <= 24 KiB。
  - [ ] 不需要 `--disable-code-size-limit`。
  - [ ] 生产部署命令不含 Anvil-only 参数。
- [ ] 明确合约拆分方式：
  - [ ] 单主合约 + 外部 view/helper library；
  - [ ] 或 Diamond / facet；
  - [ ] 或 Registry Core + Resolver View 分离。
- [ ] 保持第一版必须闭环：
  - [ ] `registerName`
  - [ ] `bootstrapName`
  - [ ] `publishDocument`
  - [ ] `revokeDocument`
  - [ ] `setControllerPolicy`
  - [ ] `updateAuthorityKeys`
  - [ ] `queryNameState`
  - [ ] `resolveOwner`
  - [ ] `resolveDocument`
  - [ ] `getDocumentVersion`
  - [ ] `getAuthoritySet`
  - [ ] `getAuthorityKey`
- [ ] 所有事件必须同时包含：
  - [ ] 可过滤的 `nameHash` topic。
  - [ ] 可读的 `name` data 字段。
  - [ ] actor / version / contentHash / nameSeq 等 indexer 重放所需字段。
- [ ] 所有 revert 必须能被客户端稳定解码：
  - [ ] `STALE_NAME_SEQ`
  - [ ] `STALE_DOCUMENT_VERSION`
  - [ ] `NOT_EFFECTIVE_OWNER`
  - [ ] `CONTROLLER_SCOPE_DENIED`
  - [ ] `INVALID_KID`
  - [ ] `NO_CONCRETE_SIGNER`
  - [ ] `OWNER_GRAPH_CYCLE`
  - [ ] `OWNER_GRAPH_TOO_DEEP`
  - [ ] `INLINE_DOCUMENT_TOO_LARGE`

## 3. 私链 Genesis / Chain 参数

- [ ] 固定 chainId，避免与任何公链、测试网、开发链冲突。
- [ ] 固定 block time，建议 1-3 秒，根据运维和写入量评估。
- [ ] 固定 gas limit，不能用不现实的大 gas 上限掩盖合约问题。
- [ ] 明确 base fee / gas 策略：
  - [ ] EIP-1559 还是 legacy。
  - [ ] Controller Client 如何估算 gas。
  - [ ] gas spike / pending queue 处理策略。
- [ ] Genesis 文件进入受控配置仓库或发布包。
- [ ] Validator 地址、初始权限、初始 funded accounts 必须可审计。
- [ ] 生产 chainId、genesis hash、BNS contract address 写入 `SNServerConfig` / BNS client config。

## 4. Key / 权限 / 账户管理

- [ ] Deployer 私钥只用于部署，部署完成后离线保存或销毁热权限。
- [ ] Controller Client 私钥必须独立于 deployer / validator key。
- [ ] Controller 私钥存放方式明确：
  - [ ] 环境变量只允许开发/测试。
  - [ ] 生产使用 KMS、HSM、Vault 或等价密钥系统。
- [ ] Validator key 与 BNS owner/controller key 分离。
- [ ] 定义 emergency owner / governance 操作流程：
  - [ ] 增加/撤销 authority key。
  - [ ] 暂停 Controller Client。
  - [ ] 替换 RPC endpoint。
  - [ ] 合约升级或迁移。
- [ ] 所有高风险操作必须有审计日志和人工审批记录。

## 5. BNS Client / TX 提交要求

- [ ] `bns-evm` crate 统一生成 ABI binding、calldata、event decode 和 revert decode。
- [ ] Standard Client：
  - [ ] 只接收外部已签名 raw TX。
  - [ ] 调用 `eth_sendRawTransaction`。
  - [ ] 不持有私钥。
- [ ] Controller Client：
  - [ ] 持有托管私钥或调用 KMS 签名。
  - [ ] 自动查询 nonce。
  - [ ] 本地维护 pending nonce 队列。
  - [ ] 失败后回查链上 nonce / receipt。
  - [ ] 支持幂等 `request_id -> tx_hash / nonce / receipt`。
- [ ] 明确 TX finality 策略：
  - [ ] 提交成功即返回；
  - [ ] 等待 receipt；
  - [ ] 等待 N 个 finalized blocks。
- [ ] 写请求错误必须区分：
  - [ ] RPC 失败。
  - [ ] TX rejected。
  - [ ] TX included but reverted。
  - [ ] guard stale。
  - [ ] nonce conflict。

## 6. Indexer / Server 要求

- [ ] Indexer 从链上事件重放，不包含业务 mutation 逻辑。
- [ ] Indexer 启动参数：
  - [ ] chain RPC endpoint。
  - [ ] chainId。
  - [ ] contract address。
  - [ ] start block。
  - [ ] confirmation depth / finality depth。
- [ ] Indexer 存储：
  - [ ] raw event logs。
  - [ ] decoded event records。
  - [ ] projection tables：names / documents / authority / controller policy。
  - [ ] sync cursor：block number / block hash / log index。
- [ ] 支持从空库重放到最新块。
- [ ] 支持合约重部署后的新 deployment namespace。
- [ ] BNS Server 只提供读 API 和可选写代理；默认不承载权威状态。
- [ ] BNS Server 读结果必须包含 indexer lag / source block 信息，便于排查读延迟。

## 7. Checkpoint / 审计 / 防篡改

- [ ] 合约维护或事件派生 `logRoot`。
- [ ] 周期性发布 checkpoint：
  - [ ] block number。
  - [ ] block hash。
  - [ ] BNS `logRoot`。
  - [ ] global event seq。
  - [ ] issuedAt。
  - [ ] issuer。
- [ ] Checkpoint 写入：
  - [ ] 私链合约事件；
  - [ ] 外部不可变存储；
  - [ ] 可选锚定到公链。
- [ ] 第三方必须能用 checkpoint 验证某个历史 BNS event 被包含。
- [ ] 公链迁移前发布最终 checkpoint。

## 8. 运维监控

- [ ] 链节点监控：
  - [ ] block height。
  - [ ] validator online status。
  - [ ] peer count。
  - [ ] finality status。
  - [ ] disk usage。
  - [ ] RPC latency / error rate。
- [ ] BNS 业务监控：
  - [ ] TX submit rate。
  - [ ] TX revert rate。
  - [ ] pending nonce queue length。
  - [ ] indexer lag blocks / seconds。
  - [ ] failed event decode count。
  - [ ] query latency。
- [ ] 告警：
  - [ ] validator 掉线。
  - [ ] 停块超过阈值。
  - [ ] indexer lag 超阈值。
  - [ ] Controller nonce 卡住。
  - [ ] 连续 revert 或异常写入激增。

## 9. 备份 / 恢复 / 演练

- [ ] 定期备份：
  - [ ] chain data。
  - [ ] genesis。
  - [ ] validator keys。
  - [ ] contract artifacts。
  - [ ] deployment records。
  - [ ] indexer DB。
- [ ] Indexer DB 备份不是权威备份，必须能从链重建。
- [ ] 每周或每个发布周期演练：
  - [ ] 新 RPC node 从备份恢复。
  - [ ] Indexer 从空库重放。
  - [ ] Controller Client nonce 恢复。
  - [ ] validator 替换。
- [ ] 记录恢复时间目标：
  - [ ] RPO。
  - [ ] RTO。

## 10. 发布门槛

- [ ] 合约测试：
  - [ ] `forge test`。
  - [ ] fuzz / invariant tests。
  - [ ] gas snapshot。
  - [ ] ABI compatibility check。
- [ ] Rust 端到端：
  - [ ] 起私链。
  - [ ] 部署合约。
  - [ ] Controller Client 提交 TX。
  - [ ] Indexer 同步事件。
  - [ ] BNS Server 读 API 命中。
- [ ] 灾备演练通过。
- [ ] 监控和告警上线。
- [ ] 部署记录完整：
  - [ ] chainId。
  - [ ] genesis hash。
  - [ ] contract address。
  - [ ] deployment tx hash。
  - [ ] ABI hash。
  - [ ] bytecode hash。
- [ ] 运行 3 个月稳定期前冻结 BNS ABI v1。

## 11. 3 个月稳定期退出标准

- [ ] 无不可恢复链故障。
- [ ] 无无法解释的 event / projection 不一致。
- [ ] Indexer 至少完成一次从空库全量重放并与生产 projection 对齐。
- [ ] 所有 checkpoint 可验证。
- [ ] 合约 ABI、事件和错误码足够稳定。
- [ ] 明确公链部署路线：
  - [ ] 原合约上链；
  - [ ] 拆分版合约上链；
  - [ ] migration contract；
  - [ ] 或继续私链生产并周期性公链锚定。
