# web3-gateway devtest 干净 staging 改造 TODO

## 目标

将 VM test 中 web3-gateway 的宿主机构建产物与运行数据彻底分离：宿主机使用一个可重复清空、只包含待部署文件的 staging 目录，VM 仍部署到 `/opt/web3-gateway`。

完成后，执行 `buckyos-devtest ... uninstall` 再 `install` 时，不得把宿主机历史 `sn.sqlite3`、BNS indexer DB、Anvil state、日志或 pid 文件重新复制进 VM。

## 已确认的故障原因

当前 [dev_configs/apps/web3-gateway.json](../../src/dev_configs/apps/web3-gateway.json) 同时配置：

```text
host source: /opt/web3-gateway
VM target:   /opt/web3-gateway
```

`build_all` 在宿主机更新 `/opt/web3-gateway` 中声明过的模块，但不会清空未声明文件；随后 devtest 将整个 source 目录递归 push 到 VM。

本次故障的时间线和数据已经证明：

- SN VM 中旧 `/opt/web3-gateway` 在 uninstall 时已被正确删除。
- 新目录和 `sn.sqlite3` 都在 install 阶段的 `17:58:30` 同时出现，SN 进程直到 `18:01:57` 才启动。
- 宿主机 `/opt/web3-gateway/sn.sqlite3` 创建于 7 月 6 日，包含旧绑定：
  `ood1.alice -> did:dev:E1oQDYqzyX4ysrNgTJ5DAVaMgA3By8XpBa0e6r2gBqQ`。
- 新 SN 启动后因此发现 alice 已存在，seed importer 输出 `keep existing data, seed entry skipped`，最终和 BNS 中的 `did:dev:QnAu...` 冲突。

所以问题不在 VM uninstall 的删除语义，而在于宿主机构建目录混入运行态数据，并在下一次 install 时被重新部署。

## 设计要求

- [ ] VM 运行目录继续使用 `/opt/web3-gateway`，不改变 VM 内启动脚本、systemd unit 和运行时路径。
- [ ] 宿主机 devtest source 改为专用 staging，例如 `/tmp/buckyos-vmtest/cyfs-gateway/web3-gateway`；不要继续使用宿主机 `/opt/web3-gateway`。
- [ ] staging 路径应集中定义，避免在多个 command 中散落不同字符串。若 JSON 配置无法复用变量，优先增加一个小型 host-side staging 脚本统一管理路径和步骤。
- [ ] 每次 `build_all` 必须先安全地删除并重建 staging；删除前校验目标确实位于约定的临时根目录下，禁止对空路径、`/`、`/opt` 或仓库根目录执行递归删除。
- [ ] staging 只允许包含构建模块、静态配置、生成的 seed/identity/TLS 文件和 BNS Foundry 源码，不得包含任何运行态数据库、状态、日志或 pid。
- [ ] `build`/update 路径也必须从同一个 staging 读取 `web3_gateway`，不能退回宿主机 `/opt/web3-gateway/web3_gateway`。
- [ ] 不以“给当前几个数据库文件加 `rm -f`”作为唯一修复；核心约束是构建输出目录从未被服务运行使用，并且全量 staging 可从零重建。

## 建议修改

### 1. 修改 devtest app source

修改 [src/dev_configs/apps/web3-gateway.json](../../src/dev_configs/apps/web3-gateway.json)：

- [ ] `directories.source` 指向新的宿主机 staging 目录。
- [ ] `directories.source_bin` 指向 staging 内的 `web3_gateway`。
- [ ] `directories.target` 和 `target_bin` 继续使用 VM 内 `/opt/web3-gateway`。
- [ ] `build` 和 `build_all` 不再读写宿主机 `/opt/web3-gateway`。

### 2. 从零构造 staging

为 `build_all` 增加明确的 staging 流程，建议顺序：

1. 校验 staging 路径并删除旧 staging。
2. 创建空 staging 目录。
3. 设置 `APPDATA` 为 staging 的父目录，执行 `uv run ./build.py aarch64`，让 `buckyos-update` 将 web3-gateway 模块写入 staging。
4. 将 BNS `foundry.toml` 和 `src/` 复制到 staging 的 `bns/`。
5. 执行 `make_sn_config.ts` 时显式传入 `--rootfs <staging>`，不要依赖其 Unix 默认值 `/opt/web3-gateway`。
6. 在 push 前执行 staging 内容校验，发现运行态文件时立即失败。

`make_sn_config.ts` 已支持 `--rootfs`，本任务不应再新增第二套输出路径逻辑。

### 3. 增加 staging 运行态文件保护

push 前至少拒绝以下文件或同名前缀：

```text
sn.sqlite3
sn.sqlite3-shm
sn.sqlite3-wal
bns_indexer.sqlite
bns_indexer.sqlite-shm
bns_indexer.sqlite-wal
anvil-state.json
anvil.pid
start.log
anvil.log
*.pid
```

- [ ] 校验失败时输出具体文件路径并返回非零退出码。
- [ ] 检查应覆盖子目录，防止运行态文件换目录后绕过。
- [ ] 如果后续确认某个生成文件必须部署，应通过显式 allowlist/模块清单纳入，不能直接放宽为复制任意数据库或日志。

### 4. 更新开发文档

更新 [src/dev_configs/readme.md](../../src/dev_configs/readme.md)：

- [ ] 说明宿主机 staging 路径、生命周期以及它和 VM `/opt/web3-gateway` 的区别。
- [ ] 说明 uninstall 只删除 VM 目标；staging 会在下一次 `build_all` 时从零重建。
- [ ] 删除或修正任何将宿主机 `/opt/web3-gateway` 描述为 devtest 部署 source 的说明。
- [ ] 给出排查命令，能分别查看 staging 内容和 VM 运行目录内容。

## 回归测试与验收

### A. 静态 staging 验收

- [ ] 在宿主机旧 `/opt/web3-gateway` 放置或保留一个测试哨兵（例如旧 `sn.sqlite3`），执行新的 `build_all`。
- [ ] 确认 staging 不受旧 `/opt/web3-gateway` 内容影响。
- [ ] 确认 staging 内不存在上述数据库、Anvil state、日志和 pid 文件。
- [ ] 确认 staging 包含启动必需文件：`web3_gateway`、`bns_dv`、`web3_gateway.yaml`、`params.json`、`sn_seed.yaml`、`bns_dv_seed.yaml`、SN identity/key、TLS 文件、`start.py`、`stop.py`、`init_anvil.py` 和 `bns/`。

### B. VM fresh install 验收

从 `src/` 执行等价流程：

```bash
uv run buckyos-devtest sn_test uninstall sn --apps web3-gateway
uv run buckyos-devtest sn_test install sn --apps web3-gateway
```

在尚未启动 web3-gateway 前检查：

```bash
multipass exec sn -- test ! -e /opt/web3-gateway/sn.sqlite3
multipass exec sn -- test ! -e /opt/web3-gateway/bns_indexer.sqlite
multipass exec sn -- test ! -e /opt/web3-gateway/anvil-state.json
```

- [ ] 三项检查全部通过，证明运行态不是随 install 复制进去的。
- [ ] 执行 `init_anvil_fresh`/`start_bg` 后，运行态文件才在 VM 内创建。
- [ ] fresh SN 日志不得在首次 seed import 时出现 `alice already exists ... seed entry skipped`。
- [ ] fresh SN 数据库不得在 OOD 第一次注册前包含来自宿主机历史环境的 device 绑定。

### C. 污染回归验收

- [ ] 启动 SN/OOD，使 VM 内生成 `sn.sqlite3`、indexer DB、Anvil state 和日志。
- [ ] 执行 web3-gateway uninstall，确认 VM 内 `/opt/web3-gateway` 不存在。
- [ ] 再次 install，但先不启动；确认所有运行态文件仍不存在。
- [ ] 启动后确认 seed、BNS canonical device DID 和 OOD 实际 device DID 一致，不再因为部署旧 DB 出现 registered binding mismatch。

### D. 保持 update 行为

- [ ] 验证仅更新 Rust 二进制的日常流程仍能使用 staging 中的 `source_bin`。
- [ ] update 不应主动删除 VM 内现有数据库或 Anvil state；“fresh”语义只由 uninstall/install 或显式 `init_anvil_fresh` 提供。
- [ ] `src/web3-gateway/scripts/sn-dev-up.sh --fresh` 和现有 SN smoke test 不受影响。

## 完成标准

- [ ] `rg -n '"source": "/opt/web3-gateway"|"source_bin": "/opt/web3-gateway' src/dev_configs` 无匹配。
- [ ] devtest 的 host build/generate 命令不再向宿主机 `/opt/web3-gateway` 写文件。
- [ ] 从被旧数据库污染的宿主机环境执行 uninstall/install，VM 在首次启动前仍没有任何运行态数据库。
- [ ] staging 校验能稳定阻止数据库、state、log、pid 被部署。
- [ ] fresh VM 流程和保留运行态的 update 流程均通过。

## 非本任务范围与后续项

- `~/buckycli` 中 legacy identity 文件与新 `local/identity`、`security` 文件的选择冲突是另一条配置构造问题；干净 staging 不应掩盖它，也不自动删除用户的 `~/buckycli`。
- devtest `Workspace.run(..., check=False)` 导致 uninstall 子命令失败时仍可能整体返回成功，建议在 buckyos-devkit 单独修复退出码传播；这不是本次旧 DB 被重新部署的直接原因。
- 不要在本任务中删除真实用户的宿主机 `/opt/web3-gateway`。完成迁移后它应被完全忽略，是否清理由开发者手工决定。
