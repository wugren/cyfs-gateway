# dev_configs: cyfs-sn VM DV Test 开发循环

本文档给 CodeAgent 使用。当前 VM DV 环境的目标不是覆盖所有拓扑，而是用最小
`sn_test` 环境把 `cyfs-sn` 放进真实 VM、真实端口和真实 BNS/Anvil 依赖里运行，
然后支持不同 DV Test 通过统一入口复用这套环境。

## 当前拓扑

- group 名称：`sn_test`
- VM 节点：`sn`
- App：`web3-gateway`
- SN 进程形态：`cyfs-sn` 不是独立命令启动，而是作为 `web3_gateway` 配置中的
  `web3_sn` server 被拉起。
- 宿主机部署 staging：`/tmp/buckyos-vmtest/cyfs-gateway/web3-gateway`
- VM 运行目录：`/opt/web3-gateway`
- 主要配置来源：
  - `src/dev_configs/sn_test.json`（`buckyos-devtest sn_test ...` 的 group 入口）
  - `src/dev_configs/apps/web3-gateway.json`（devtest 实际读取的 app 定义）
  - `src/dev_configs/templates/ubuntu_basic.yaml`（devtest 实际读取的 VM 模板）
  - `src/dev_configs/sn_test/nodes.json`
  - `src/dev_configs/sn_test/apps/web3-gateway.json`
  - `src/web3-gateway/start.py`
  - `src/web3-gateway/init_anvil.py`
  - `src/make_sn_config.ts`

所有 `buckyos-devtest` 命令建议从 `src/` 目录执行：

```bash
cd /Users/liuzhicong/project/cyfs-gateway/src
```

## 逻辑分层

`sn_test` 只管理 VM 生命周期、构建产物、部署和启动。具体 DV Test 不应写死在
VM 框架里，而应按以下方式接入：

1. 宿主机驱动：测试在宿主机运行，通过 VM IP 访问 SN 的 DNS/HTTP/RTCP 端口。
2. VM 内执行：测试脚本或命令已经在 VM 内时，用 `multipass exec sn -- bash -lc "<cmd>"` 执行。
3. App 命令执行：需要调用 app 配置里的命令时，用
   `buckyos-devtest sn_test exec web3-gateway.<cmd> --device sn`。注意当前
   `web3-gateway.start` 是前台长进程，不要直接用 `exec` 启动；后台启动用
   `web3-gateway.start_bg`。

这样同一套 VM 可以跑 `sn-dev-smoke`、手写 curl/dig 检查、后续新的 SN DV Test，
以及需要真实 Linux/特权端口的测试。

## 一次完整初始化

```bash
cd /Users/liuzhicong/project/cyfs-gateway/src

# 1. 清理旧 VM，创建基础 VM。
uv run buckyos-devtest sn_test clean_vms
uv run buckyos-devtest sn_test create_vms
uv run buckyos-devtest sn_test snapshot init

# 2. 构建并部署 web3-gateway。
# build_all 会从零重建宿主机 staging、构建 Linux 产物、复制 BNS Foundry
# 工程、运行 make_sn_config.ts --seed-v2，并在 push 前拒绝运行态文件。
uv run buckyos-devtest sn_test install sn --apps web3-gateway

# 3. 在 VM 内初始化 Anvil + BNS 合约。
# 首次 VM 缺 Foundry 时加 --install-foundry；之后通常不需要。
uv run buckyos-devtest sn_test exec web3-gateway.init_anvil_fresh --device sn

# 4. 记录“已安装且链已初始化”的快照。
uv run buckyos-devtest sn_test snapshot installed

# 5. 后台启动 web3-gateway。start.py 会拉起 bns_dv，再启动 web3_gateway/cyfs-sn。
uv run buckyos-devtest sn_test exec web3-gateway.start_bg --device sn

# 6. 可选：服务启动并通过 smoke 后再创建 started 快照。若恢复 started 后
#    进程状态不稳定，优先 restore installed 后重新执行上面的 start_bg。
uv run buckyos-devtest sn_test snapshot started
```

## 跑 SN VM 冒烟

优先使用 `sn-dev-smoke.sh --vm`。它会验证 DNS A/TXT、BNS indexer 投影解析、
`did:web` user_domain seed 和纯 Web3 用户解析。

```bash
cd /Users/liuzhicong/project/cyfs-gateway/src
SN_IP=$(multipass info sn | awk '/IPv4/{print $2; exit}')

./web3-gateway/scripts/sn-dev-smoke.sh --vm \
  --expected-a "$SN_IP" \
  --dns-server "$SN_IP" \
  --http-origin "http://$SN_IP"
```

如果宿主机已经把 `sn.devtests.org` 指到 VM IP，也可以省略 `--http-origin`。
Multipass 不能固定 IP，重建 VM 后必须重新获取 `SN_IP`。

## 通用 DV Test 运行方式

宿主机测试需要真实 VM SN 时，先取 VM IP，再把目标地址传给测试：

```bash
SN_IP=$(multipass info sn | awk '/IPv4/{print $2; exit}')
# 示例：测试脚本自己决定如何使用 SN_HTTP_ORIGIN / SN_DNS_SERVER。
SN_HTTP_ORIGIN="http://$SN_IP" SN_DNS_SERVER="$SN_IP" ./path/to/dv-test.sh
```

VM 内临时命令直接用 `multipass exec`：

```bash
multipass exec sn -- bash -lc "curl -fsS http://127.0.0.1:18080/health"
multipass exec sn -- bash -lc "dig @127.0.0.1 alice.web3.devtests.org A"
multipass exec sn -- bash -lc "tail -200 /opt/web3-gateway/anvil.log"
```

如果 DV Test 需要严格依赖退出码，也直接用 `multipass exec`：

```bash
multipass exec sn -- bash -lc "cd /opt/web3-gateway && ./path/to/dv-test.sh"
```

App 命令用 `exec`：

```bash
uv run buckyos-devtest sn_test exec web3-gateway.stop --device sn
uv run buckyos-devtest sn_test exec web3-gateway.init_anvil --device sn
uv run buckyos-devtest sn_test exec web3-gateway.start_bg --device sn
```

## 宿主机 staging 与 VM 运行目录

devtest 只从宿主机
`/tmp/buckyos-vmtest/cyfs-gateway/web3-gateway` 部署文件。这个目录是一次性的构建
staging，不是服务运行目录：每次 `web3-gateway.build_all` 都会先校验路径位于约定的
`/tmp/buckyos-vmtest/cyfs-gateway` 临时根目录下，再删除并从零重建。构建通过
`APPDATA=/tmp/buckyos-vmtest/cyfs-gateway` 将 `buckyos-update` 输出定向到 staging；
BNS 源码、seed、identity 和 TLS 文件也只生成到这里。
`params.json` 中的 SN DB 和 token key 路径使用部署目录相对路径，避免把宿主机
staging 的绝对路径带进 VM。

VM 仍然在 `/opt/web3-gateway` 运行，并在其中创建 `sn.sqlite3`、BNS indexer DB、
Anvil state、日志和 pid。`uninstall` 只删除这个 VM 目标目录，不删除宿主机 staging；
下一次 `install` 调用的 `build_all` 会在 push 前重新清空 staging，因此 VM 的旧运行
数据和宿主机遗留的 `/opt/web3-gateway` 都不会进入新部署。不要在宿主机 staging 中
启动服务或保存运行数据。

当前 devtest 版本没有顶层 `uninstall` 子命令；清理 app 后重新安装使用：

```bash
uv run buckyos-devtest sn_test exec web3-gateway.uninstall --device sn
uv run buckyos-devtest sn_test install sn --apps web3-gateway
```

只更新 Rust 二进制时，`buckyos-devtest update` 会运行较轻量的 `build`，并从同一
staging 的 `web3_gateway` 更新 VM 二进制。该流程不会清理 VM 中的数据库或 Anvil
state；需要 fresh 环境时应使用 uninstall/install 或显式执行 `init_anvil_fresh`。

分别检查宿主机 staging 和 VM 运行目录：

```bash
find /tmp/buckyos-vmtest/cyfs-gateway/web3-gateway -maxdepth 3 -print | sort
uv run ./dev_configs/web3_gateway_staging.py validate
multipass exec sn -- find /opt/web3-gateway -maxdepth 3 -print
```

## 日常开发循环

### 只改 Rust 代码

不需要重建 VM。只刷新 `web3_gateway` 二进制时可以保留 VM 内运行态：

```bash
cd /Users/liuzhicong/project/cyfs-gateway/src
uv run buckyos-devtest sn_test exec web3-gateway.stop --device sn
uv run buckyos-devtest sn_test update sn --apps web3-gateway
uv run buckyos-devtest sn_test exec web3-gateway.init_anvil --device sn
uv run buckyos-devtest sn_test exec web3-gateway.start_bg --device sn
```

### 改了配置、seed、`make_sn_config.ts` 或 BNS 合约

回到干净 VM，重新部署和初始化链：

```bash
cd /Users/liuzhicong/project/cyfs-gateway/src
uv run buckyos-devtest sn_test restore init
uv run buckyos-devtest sn_test install sn --apps web3-gateway
uv run buckyos-devtest sn_test exec web3-gateway.init_anvil_fresh --device sn
uv run buckyos-devtest sn_test snapshot installed
uv run buckyos-devtest sn_test exec web3-gateway.start_bg --device sn
```

### 只重跑测试

测试会污染 SN DB、BNS chain 或 indexer 状态时，用快照隔离：

```bash
uv run buckyos-devtest sn_test restore installed
uv run buckyos-devtest sn_test exec web3-gateway.start_bg --device sn
# run DV Test here
```

如果测试目标是验证 resume 或持久化游标，就不要 restore；直接重跑测试，或只重启
`web3-gateway`。

## 选择正确的测试入口

- 快速组件回归：`cd src && cargo test -p cyfs-sn -- --test-threads=1`
- BNS 真 EVM 集成：`cd src && cargo test -p bns-client --test e2e_anvil -- --ignored --test-threads=1`
- BNS 本机 DV：`cd src/apps/bns && scripts/dv-up.sh --fresh && scripts/dv-smoke.sh && scripts/dv-down.sh`
- SN 本机 DV：`cd src/web3-gateway && scripts/sn-dev-up.sh --fresh && scripts/sn-dev-smoke.sh`
- SN VM DV：按本文启动 `sn_test`，然后运行
  `src/web3-gateway/scripts/sn-dev-smoke.sh --vm ...` 或自定义 DV Test。

CodeAgent 处理任务时，优先跑最窄测试；只有涉及真实 VM 端口、Linux 行为、SN seed
部署、Anvil/BNS 与 `cyfs-sn` 组合时，才进入 `sn_test` VM 循环。

## 常见定位

```bash
uv run buckyos-devtest sn_test info_vms
uv run buckyos-devtest sn_test clog
find /tmp/buckyos-vmtest/cyfs-gateway/web3-gateway -maxdepth 3 -print | sort
multipass exec sn -- bash -lc "ps aux | egrep 'web3_gateway|bns_dv|anvil'"
multipass exec sn -- bash -lc "ls -la /opt/web3-gateway"
multipass exec sn -- bash -lc "tail -200 /opt/web3-gateway/start.log"
multipass exec sn -- bash -lc "tail -200 /opt/web3-gateway/anvil.log"
```

启动失败时先确认：

- `/opt/web3-gateway/init_anvil.py --fresh` 已经在 VM 内成功执行。
- VM 内有 `anvil`、`forge`；没有时重新执行 `init_anvil.py --install-foundry`。
- `/opt/web3-gateway/bns_dv_seed.yaml` 和 `sn_seed.yaml` 来自最新
  `make_sn_config.ts --seed-v2`。
- 宿主机访问 VM 时使用了当前 VM IP；重建 VM 后旧 IP 不可信。
