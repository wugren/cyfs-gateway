# SN Seed Config（sn_seed.yaml）

SN（cyfs-sn / web3_sn server）启动时的 C 类种子文件，同时支持
离线 devtest 显式声明已预置证书状态。格式真值：
[cyfs-sn/src/sn_seed.rs](../../src/components/cyfs-sn/src/sn_seed.rs) 的
`SnSeedConfig`（serde + YAML）；[make_sn_config.ts](../../src/make_sn_config.ts)
中的 TS interface 仅是镜像。生产方是 make_sn_config（`makeSnAuthSeedConfig`），
消费方是 `SnServerFactory::create`（DB 初始化之后、服务对外之前）。

## 内容边界：C 类 + 可信 dev 证书状态

按 [SN运行态lazy-init改造TODO.md](./SN运行态lazy-init改造TODO.md) 的分类，seed
只包含**无合理默认值、必须显式创建**的 SN-local 数据：

- `activation_codes`：未使用的激活码（Web2 注册流程测试用）。
- `users`：sn_user 账号（用户名 / dev 明文密码 / owner ed25519 公钥 /
  bns_name 绑定关系）。可选 `self_cert` 仅用于可信 dev seed：测试
  证书已由环境预置、ACME 不可用时显式设为 `true`。未声明仍默认
  `false`。
- `user_domains`：did:web 型 zone 的自有域名绑定（domain / owner / pkx /
  ZoneDocument JWT）。did:web 的 ZoneDocument 权威就在 SN 的 user_domain
  机制里，所以属于 C 类。

**明确不含**：`zone_config`（did:bns 的 zone/boot 权威在 BNS，由
`bns_dv_seed.yaml` 上链、indexer 投影，A 类）、设备行 / 在线态 / relay 分配。
生产环境中 `self_cert` 仍是证书验证成功后刷新的 B 类运行态；上述字段
是离线 devtest 的显式例外。

## 示例

```yaml
# sn_seed.yaml
activation_codes:
  - "dev-code-1"
  - "dev-code-2"
  - "dev-code-3"
  - "dev-code-4"
  - "dev-code-5"
  - "dev-code-6"
  - "dev-code-7"
  - "dev-code-8"
  - "dev-code-9"
  - "dev-code-10"
  - "dev-code-11"
  - "dev-code-12"
  - "dev-code-13"
  - "dev-code-14"
  - "dev-code-15"
  - "dev-code-16"
users:
  - username: alice            # 词汇沿用 devenv_config.ts
    email: "alice@buckyos.org" # 必填；规范化后全局唯一
    password: "devtest-pwd"    # dev 明文，导入时走现有 PBKDF2 哈希路径
    owner_public_key: "uh7R..."  # ed25519 公钥（JWK x 分量，base64url）
    bns_name: alice            # sn_user <-> BNS name 绑定（仅绑定关系）
    self_cert: true            # devtest 已预置证书，不等待 ACME
user_domains:
  - domain: charlie.me         # did:web 型 zone
    owner: charlie             # 须在 users 列表中，或 DB 已有该用户
    pkx: "PY9u..."             # 与 owner 的 owner_public_key 一致
    zone_document_jwt: "eyJ..."  # owner key 签名，SN 保存用于 did:web 解析
```

## 幂等语义：ensure-exists

- 种子只保证"存在"；已存在的账号内容**不覆盖**。
- 例外：显式声明的 `self_cert` 是可信 dev 环境事实，导入时会幂等
  对齐 `users` 和 `zone_info` 两处投影。
- 每个种子用户必须提供有效且全局唯一的邮箱；devtest 统一使用
  `<username>@buckyos.org`。
- 已存在且内容不一致 → `warn!` 并跳过（绝不覆盖运行中的账号/密码）。
- 带相同 seed 二次启动 → 零写入、无副作用（行数与 `updated_at` 均不变）。
- 需要变更种子内容时，dev 环境用 `--fresh` 重建，不原地覆盖。
- user_domain 种子是开发捷径：绑定直接置 verified（绕过 domain proof 流程），
  仅 seed 路径允许；线上绑定必须走 `create_pkx_binding` + `verify_pkx_binding`。
- 每个种子用户经专属激活码 `seed-user-<username>` 注册（provenance 可追溯），
  不消耗 `activation_codes` 里留给注册流程测试的码。

## 配置入口与失败策略

- `web3_gateway.yaml` 的 `web3_sn` block：`seed_path: "sn_seed.yaml"`。
  相对路径按网关主配置目录解析（与 `local_dns` 的 `file_path` 同语义）。
- 文件不存在 → 日志提示后跳过（无种子也能正常启动）。
- 文件存在但解析/校验失败 → **启动失败**（fail fast，坏种子不能静默）。

## 测试

```
cd src && cargo test -p cyfs-sn sn_seed -- --test-threads=1
```

覆盖：全新导入 / 同 seed 二次导入零变更 / 同名不同内容跳过告警 /
文件缺失正常启动、格式坏启动报错 / 存量用户补 user_domain 绑定。
