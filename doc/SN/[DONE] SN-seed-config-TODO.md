# SN seed config 与 make_sn_config 完成 TODO

## 背景与目标

`make_sn_config.ts` 已从 buckyos 仓库移入本仓库（[src/make_sn_config.ts](../../src/make_sn_config.ts)，内含 seed-v2 骨架：均为签名 + `throw TODO(seed-v2)`）。目标模式是**组件"从配置初始化"**：make_sn_config 只产出各组件的种子配置文件，组件自己实现幂等导入——范本是 bns_dv 的 `serve --seed-config`（[bns_dv.rs:42-113](../../src/components/bns-server/src/bin/bns_dv.rs:42) 的 `BnsDvInitConfig`：`seed` + `on_init_txs`，`if_exists=apply_mutations` 幂等重放）。

边界与原则：

1. **只产种子，不写派生态**：SN 侧只有 lazy-init 分类中的 C 类（sn_user 账号等无默认值数据）进 seed；A 类（zone/boot/device_mini_doc）经 bns_dv seed 上链、由 indexer 投影；B 类默认由运行时刷新。例外是离线 devtest 已预置证书且 ACME 不可用，因此可在可信 seed 中显式声明 `self_cert=true`；未声明时仍使用安全默认值 `false`。分类见 [SN运行态lazy-init改造TODO.md](./SN运行态lazy-init改造TODO.md)。
2. **幂等契约 = ensure-exists**：种子只保证"存在"；已存在的账号内容不覆盖（内容不同则告警）；显式 devtest `self_cert` 会对齐两处状态投影；带相同 seed 二次启动零写入、无副作用。
3. **schema 归组件所有**：make_sn_config 不再维护表结构副本，也不直写组件私有 DB。
4. **环境构造出栈**：hosts / DNS 指向 / CA 信任 / VM 生命周期归 buckyos-devtest（见 buckyos `doc/CI/基于VM的开发环境构造.md`），本工具专注 seed config。

---

## 任务 1：cyfs-sn 支持 seed config（含测试）

### 1.1 格式定义（系统公共格式）

- [x] 新建 `cyfs-sn/src/sn_seed.rs`，定义 `SnSeedConfig` 作为格式真值（serde + YAML，workspace 已有 `serde_yaml_ng`）：
  ```yaml
  # sn_seed.yaml —— 仅 C 类：无合理默认值、必须显式创建的 SN-local 数据
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
    - username: alice          # 词汇沿用 devenv_config.ts（username/zone_id/user_domain）
      email: "alice@buckyos.org" # 必填；规范化后全局唯一
      password: "devtest-pwd"  # dev 明文，导入时走现有 PBKDF2 哈希路径
      owner_public_key: "..."  # ed25519 公钥（jwk x），与用户 env 一致
      bns_name: alice          # sn_user <-> BNS name 绑定（仅绑定关系，非权威文档）
  user_domains:
    - domain: charlie.me       # did:web 型 zone：ZoneDocument 走 user_domain 机制
      owner: charlie
      pkx: "..."
      zone_document_jwt: "..."
  ```
- [x] 明确**不含**：`zone_config`、设备行、在线态、relay 分配——zone/boot/device_mini_doc 权威在 BNS（由 make_sn_config 的 `bns_dv_seed.yaml` 上链），运行态走 lazy 默认。
- [x] 约定与 bns_dv seed 对齐：snake_case、YAML、幂等语义命名；Rust 结构为真值，[make_sn_config.ts](../../src/make_sn_config.ts) 中保留 TS 镜像并注释"真值在 Rust 侧，勿漂移"（同现有 `BnsDvSeedConfig` 镜像的做法）。
- [x] 新增 `doc/SN/SN-Seed-Config.md` 记录格式与幂等语义（一页即可）。

### 1.2 配置入口

- [x] `SNServerConfig` 增加 `seed_path: Option<String>`（结构体见 [sn_server.rs:1782](../../src/components/cyfs-sn/src/sn_server.rs:1782)），相对配置目录解析（与 `local_dns` 的 `file_path` 同语义）。
- [x] [web3_gateway.yaml](../../src/web3-gateway/web3_gateway.yaml) 的 `web3_sn` block 增加 `seed_path: "sn_seed.yaml"`。

### 1.3 导入实现

- [x] 执行点：`SnServerFactory::create` 完成 DB 初始化之后（[sn_server.rs:2112](../../src/components/cyfs-sn/src/sn_server.rs:2112) 附近）。
- [x] 写入路径：经 `SnAuthDB` 公开方法（插激活码 / 注册账号 / user_domain 绑定），**不写裸 SQL**；密码复用现有 PBKDF2 哈希。
- [x] 幂等：逐条 ensure-exists；已存在 → no-op；已存在且内容不一致 → `warn!` 并跳过（绝不覆盖运行中的账号/密码）。
- [x] user_domain 种子是开发捷径：直接置 verified 状态（绕过 domain proof 流程），代码注释注明仅 seed 路径允许。
- [x] 失败策略：`seed_path` 指向的文件不存在 → 日志提示后跳过；文件存在但解析失败 → **启动失败**（fail fast，坏种子不能静默）。

### 1.4 测试

- [x] `cargo test -p cyfs-sn sn_seed -- --test-threads=1`，覆盖：
  - 全新 DB 导入 → 账号可查、激活码可用、user_domain 绑定存在；
  - **同 seed 二次导入 → 零变更**（断言行数与 `updated_at` 均不变）；
  - 已存在同名账号但内容不同 → 跳过 + 告警，原数据不动；
  - seed 文件缺失 → 正常启动；格式坏 → 启动报错；
  - 临时 DB 隔离，不与现有 sn_auth/s2s 用例互扰。

---

## 任务 2：基于任务 1 与现有骨架，完成新版 make_sn_config

### 2.0 移动后的接线修复（当前脚本无法运行，先做）

- [x] 新建 `src/deno.json`：imports 映射与 buckyos 一致
  `"buckyos/provision": "https://raw.githubusercontent.com/buckyos/buckyos-websdk/beta2.2/dist/provision.mjs"`，并加 task `make_sn_config`。
- [x] `./devenv_config.ts` 落位：从 buckyos `src/devenv_config.ts` 拷贝进 `src/`，头注释注明"种子案例书，与 buckyos 同源同步"（SN 是该种子的消费方之一，允许两仓各持一份，靠注释锚定同步义务）。
- [x] 解除对 buckyos `make_config.ts` 的 import（`buildUserEnv/ensureDir/makeMachineConfig`）：
  - `ensureDir` 本地实现（三行）；
  - `buildUserEnv` 用 websdk `createUserEnv` + `createNodeConfigs` 重写薄版（它本来就是二者的组合）；
  - `makeMachineConfig`：先确认 web3_gateway 进程是否消费 `machine.json`；不消费则**删除该步骤**（旧 py 版注释已断言 SN 不需要）。
- [x] 文件头注释与 usage 改名为 `make_sn_config.ts`（现仍是复数旧名）。
- [x] 验收：`deno check make_sn_config.ts` 通过；默认路径（不带 `--seed-v2`）在本机可完整跑通，产物与 buckyos 版一致。

### 2.1 实现 seed-v2 骨架函数（现均为 throw）

- [x] `getSeedUserSpecs()`：从 devenv_config 推导 alice/bob/charlie（charlie 带 `userDomain`），**新增一个 `snAccount=false` 的纯 Web3 用户位**（devenv 注释："did:bns:alice 可以不是 SN 注册用户"），同步在 devenv_config.ts 增组。
- [x] `deriveUserEvmAccount()`：固定助记词确定性派生（与 ed25519 owner key 同源不同用途）。
- [x] `makeBnsDvSeedConfig()`：产 `bns_dv_seed.yaml` + `bns_seed_docs/<user>/*.json`；文档 JWT 取自 `<env_root>` 用户 env；`asset_owner` = 用户 EVM 地址；多文档随 `register_name` 一次提交（原子批量）。
- [x] `makeSnAuthSeedConfig()`：按任务 1 定稿的格式产 `sn_seed.yaml`（TS 镜像与 Rust 真值对齐）。
- [x] `alignBnsRuntimeParams()`：存在 `dv-env.json` 时以其为准，把 `bns_indexer_url`/`bns_server_url` 等写入 params.json。
- [x] P1 骨架维持不动：`makeSnControllerSeed`（依赖 bns_dv 扩展 controller policy 类 tx type）、`makeDevtestLocalDns`。

### 2.2 组件侧接线

- [x] [start.py](../../src/web3-gateway/start.py)：部署目录存在 `bns_dv_seed.yaml` 时给 bns_dv 追加 `--seed-config <path>`（bns_dv 已接受 `--config/--seed-config`，见 [bns_dv.rs:315](../../src/components/bns-server/src/bin/bns_dv.rs:315)）。
- [x] [web3_gateway.yaml](../../src/web3-gateway/web3_gateway.yaml)：`bns_indexer_url` 写死值改为 `{{bns_indexer_url}}`（由 params.json 提供）；`web3_sn` 加 `seed_path`（见 1.2）。
- [x] [dev_configs/sn_test/apps/web3-gateway.json](../../src/dev_configs/sn_test/apps/web3-gateway.json)：`build_all` 从 `make_sn_config.py`（已删除）改为 `deno run -A ./make_sn_config.ts sn_server 等价参数`。

### 2.3 切换与退役

- [x] 任务 1 + 3 验证通过后：seed-v2 行为已转为默认，`--seed-v2` 仅保留为 no-op 兼容参数。
- [x] 删除脚本内 legacy 块：`initializeSnDatabaseSchema` / `backfillSnDerivedTables` / `syncSnDatabase` / `preregisterDevUsers`，并去掉 websdk `registerUserToSn/registerDeviceToSn`（DevSnDb 直写）依赖。
- [ ] 跨仓库收尾：buckyos `src/make_sn_configs.ts` 与其 deno task 退役；buckyos-devtest 的 `web3-gateway.build_all` 改指本仓库脚本（buckyos 侧提交，单独 PR）。

---

## 任务 3：本机（非 VM）拉起 + seed 生效集成测试

### 3.1 端口非特权化（前置）

- [x] web3_gateway.yaml 五个 bind（53/80/2980/3443/443）参数化为 `{{dns_bind}}`/`{{http_bind}}`/`{{rtcp_bind}}`/`{{tls_bind}}`/`{{sni_bind}}`，params.json 默认值保持现状（VM 行为不变）。
- [x] make_sn_config 增加 `--dev-local` profile：`sn_ip=127.0.0.1`，高位端口（建议 15353/18081/12980/13443/14443），避开 bns_dv 的 18080 与 buckyos 测试常用 19xxx/2xxx 段（历史上有 TIME_WAIT 干扰）。

### 3.2 本机拉起脚本（仿 bns 的 dv 三件套）

- [x] `src/web3-gateway/scripts/sn-dev-up.sh`：临时 rootfs（如 `var/sn-dev/`）→ `make_sn_config --rootfs <dir> --dev-local` → 拉起 bns_dv（带 `--seed-config`）→ 拉起 web3_gateway → 健康检查；支持 `--fresh/--resume`。
- [x] `sn-dev-smoke.sh` / `sn-dev-down.sh` 同套路（参考 `src/apps/bns/scripts/dv-up.sh` 的结构与输出约定）。

### 3.3 集成测试组（验证 seed 确实生效）

- [x] 位置与惯例：`cargo test -p cyfs_gateway --test e2e_sn_seed -- --ignored --test-threads=1`（仿 `bns-client e2e_anvil` 的 ignored 真集成模式），内部拉起/复用 3.2 的环境。
- [x] 用例：
  - **T1 账号种子**：alice 用测试密码登录成功、拿到 token；用种子激活码走通新用户注册。
  - **T2 DNS 种子**：向 dev DNS 端口查 `alice.web3.devtests.org` A 记录 → 返回 `sn_ip`；TXT 含 zone/boot 内容。
  - **T3 链上种子**：`GET sn host /1.0/identifiers/did:bns:alice` 经 indexer 投影解析成功（证明 `bns_dv_seed.yaml` 的 `on_init_txs` 已生效）。
  - **T4 user_domain 种子**：charlie.me 的绑定可查询、解析生效。
  - **T5 幂等**：不动 seed 重启 web3_gateway → sqlite 行数与 `updated_at` 快照不变、上述接口行为一致；重跑 make_sn_config → 产物稳定（确定性密钥，diff 干净）。
  - **T6 纯 Web3 位**（依赖 2.1 新用户组）：无 sn_user 行的用户仍可经 BNS 路径解析。
- [x] 隔离要求：临时 rootfs/临时 sqlite/唯一端口，禁止依赖本机已有服务（对应 [SN-测试计划.md](./SN-测试计划.md) §4.4）。

### 3.4 文档与 CI

- [x] [SN-测试计划.md](./SN-测试计划.md) §1/§5/§6 补入口：`sn-dev-up.sh + e2e_sn_seed` 属"真集成，默认跳过"层。
- [x] 快速回归基线（`cd src && cargo test -- --test-threads=1`）不受影响。

---

## 建议实施顺序

1. **2.0**（接线，让脚本能跑）——独立可先行。
2. **任务 1**（cyfs-sn seed 模块 + 单测）——格式定稿是 2.1 的输入。
3. **2.1 + 2.2**（骨架实现与接线；`makeBnsDvSeedConfig` 不依赖任务 1，可与之并行）。
4. **3.1 + 3.2**（端口参数化、本机拉起）。
5. **3.3 + 3.4**（集成测试与文档）。
6. **2.3**（切默认 + 退役 legacy，最后做）。

## 风险与决策记录

- **解析路径依赖**：seed 严格 C 类的前提是 resolver 能经 indexer 读 BNS 文档（`test_sn_bns_integration` 已覆盖该能力）。若本机验证发现某条解析仍依赖 `users.zone_config` legacy 缓存，按 [SN运行态lazy-init改造TODO.md](./SN运行态lazy-init改造TODO.md) §2 补 lazy 读，**不要把 zone_config 塞回 seed**。
- **覆盖语义**：ensure-exists 不做 update。需要变更种子内容时，dev 环境用 `--fresh` 重建，不原地覆盖。
- **密钥安全**：确定性助记词、明文测试密码、bns_dv 默认 dev key 仅限 devtest，沿用 bns_dv 对默认 key 的启动告警惯例，不得进生产路径。
