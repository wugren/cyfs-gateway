#!/usr/bin/env bash
# SN 本机（非 VM）开发环境一键拉起（doc/SN/SN-seed-config-TODO.md §3.2）。
#
#   sn-dev-up.sh [--fresh | --resume] [--keep-running]
#
# 编排（仿 src/apps/bns/scripts/dv-up.sh 三件套）：
#   anvil（私链，--state 持久化）→ forge 部署 Bns.sol → 写 dv-env.json →
#   make_sn_config.ts --seed-v2 --dev-local（产 rootfs + 种子配置）→
#   bns_dv serve --seed-config（种子上链 + indexer 投影，健康门控含种子完成）→
#   web3_gateway（cyfs-sn 启动时幂等导入 sn_seed.yaml）→ 健康检查。
#
#   --fresh   ：删除 var/sn-dev 全部状态（rootfs / anvil-state / indexer db / 用户 env）。
#   --resume  ：复用已有状态重启（种子幂等重放应零写入）。
#   --keep-running：前台保活（Ctrl-C 后用 sn-dev-down.sh 清理）；默认后台托管。
#
# 隔离约定（SN-测试计划 §4.4）：临时 rootfs、临时 sqlite、独立 env_root、
# 高位唯一端口（avoid 18080 与 19xxx/2xxx 段），不依赖本机已有服务。
set -euo pipefail

cd "$(dirname "$0")/.."
APP_DIR="$(pwd)"
SRC_DIR="$(cd .. && pwd)"
BNS_APP_DIR="$SRC_DIR/apps/bns"

# 全部可用环境变量覆盖（e2e 测试隔离用）。
VAR="${SN_DEV_VAR_DIR:-$APP_DIR/var/sn-dev}"
ROOTFS="$VAR/rootfs"
ENV_ROOT="${SN_DEV_ENV_ROOT:-$VAR/env_root}"
ANVIL_HOST="127.0.0.1"
ANVIL_PORT="${SN_DEV_ANVIL_PORT:-18545}"
CHAIN_ID="${SN_DEV_CHAIN_ID:-31337}"
BNS_SERVER_PORT="${SN_DEV_BNS_PORT:-18082}"
# 网关五个 bind 由 make_sn_config --dev-local profile 固定：
#   dns 15353/udp  http 18081  rtcp 12980  tls 13443  sni 14443
GW_HTTP_PORT=18081
GW_DNS_PORT=15353

RPC="http://${ANVIL_HOST}:${ANVIL_PORT}"
BNS_SERVER_URL="http://127.0.0.1:${BNS_SERVER_PORT}"
MNEMONIC="test test test test test test test test test test test junk"
# account[9] 作部署者，与 bns_dv 托管发送方 account[0]、种子用户 account[1..4]
# 的 nonce 相互独立。
DEPLOYER_KEY="0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"

ANVIL_STATE="$VAR/anvil-state.json"
DEPLOY_JSON="$VAR/bns-deployment.json"
INDEXER_DB="$VAR/indexer.sqlite"
ANVIL_PID="$VAR/anvil.pid"
BNS_PID="$VAR/bns-dv.pid"
GW_PID="$VAR/web3-gateway.pid"
ANVIL_LOG="$VAR/anvil.log"
BNS_LOG="$VAR/bns-dv.log"
GW_LOG="$VAR/web3-gateway.log"
ENV_JSON="$VAR/sn-dev-env.json"

MODE="fresh"
KEEP_RUNNING=0
for arg in "$@"; do
  case "$arg" in
    --fresh) MODE="fresh" ;;
    --resume) MODE="resume" ;;
    --keep-running) KEEP_RUNNING=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

for bin in anvil forge cast cargo deno curl dig; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing required tool: $bin" >&2; exit 1; }
done

json_get() { # json_get <file> <key>
  local v=""
  v="$(grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*"//;s/"$//')" || true
  printf '%s' "$v"
}

wait_for() { # wait_for <desc> <timeout_s> <cmd...>
  local desc="$1" timeout="$2"; shift 2
  local i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -ge $((timeout * 5)) ]; then
      echo "TIMEOUT waiting for: $desc" >&2
      return 1
    fi
    sleep 0.2
  done
}

anvil_chain_id_ok() { [ "$(cast chain-id --rpc-url "$RPC" 2>/dev/null)" = "$CHAIN_ID" ]; }
contract_deployed() { local c="$1"; [ "$(cast code "$c" --rpc-url "$RPC" 2>/dev/null)" != "0x" ]; }
bns_healthy() { [ "$(curl -fsS "$BNS_SERVER_URL/health" 2>/dev/null)" = "ok" ]; }
gw_http_up() { curl -fsS -o /dev/null -H "Host: sn.devtests.org" "http://127.0.0.1:${GW_HTTP_PORT}/kapi/sn" 2>/dev/null || [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: sn.devtests.org" "http://127.0.0.1:${GW_HTTP_PORT}/kapi/sn" 2>/dev/null)" != "000" ]; }

clear_port() {
  if command -v lsof >/dev/null 2>&1; then
    local pids; pids="$(lsof -ti "tcp:$1" 2>/dev/null || true)"
    [ -n "$pids" ] && kill $pids 2>/dev/null || true
  fi
}

stop_if_running() {
  for pf in "$GW_PID" "$BNS_PID" "$ANVIL_PID"; do
    [ -f "$pf" ] || continue
    local pid; pid="$(cat "$pf" 2>/dev/null || true)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; fi
    rm -f "$pf"
  done
  clear_port "$ANVIL_PORT"
  clear_port "$BNS_SERVER_PORT"
  clear_port "$GW_HTTP_PORT"
  sleep 0.3
}

# --- 1) 状态准备 ---
mkdir -p "$VAR"
stop_if_running
if [ "$MODE" = "fresh" ]; then
  echo "[sn-dev-up] --fresh: clearing $VAR"
  rm -rf "$ROOTFS" "$ENV_ROOT" "$VAR/buckyos_root"
  rm -f "$ANVIL_STATE" "$DEPLOY_JSON" "$INDEXER_DB" "$INDEXER_DB-wal" "$INDEXER_DB-shm" "$ENV_JSON"
else
  echo "[sn-dev-up] --resume: reusing state in $VAR"
  [ -f "$DEPLOY_JSON" ] || { echo "no deployment to resume ($DEPLOY_JSON); run --fresh" >&2; exit 1; }
fi
mkdir -p "$ROOTFS" "$ENV_ROOT" "$VAR/buckyos_root"

# --- 2) anvil ---
echo "[sn-dev-up] starting anvil on $RPC (chain $CHAIN_ID)"
anvil --host "$ANVIL_HOST" --port "$ANVIL_PORT" --chain-id "$CHAIN_ID" \
  --mnemonic "$MNEMONIC" --disable-code-size-limit --state "$ANVIL_STATE" \
  >"$ANVIL_LOG" 2>&1 &
echo $! > "$ANVIL_PID"
wait_for "anvil eth_chainId" 30 anvil_chain_id_ok

# --- 3) 部署/复用 Bns.sol ---
if [ "$MODE" = "fresh" ]; then
  echo "[sn-dev-up] deploying Bns.sol"
  (cd "$BNS_APP_DIR" && forge create src/Bns.sol:Bns \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast --json) >"$DEPLOY_JSON.tmp" 2>"$VAR/forge.err" \
    || { echo "forge create failed:" >&2; cat "$VAR/forge.err" >&2; exit 1; }
  sed -n '/{/,/}/p' "$DEPLOY_JSON.tmp" > "$DEPLOY_JSON"
  rm -f "$DEPLOY_JSON.tmp"
fi
CONTRACT="$(json_get "$DEPLOY_JSON" deployedTo)"
[ -n "$CONTRACT" ] || { echo "could not determine contract address from $DEPLOY_JSON" >&2; exit 1; }
wait_for "contract code at $CONTRACT" 30 contract_deployed "$CONTRACT"

# --- 4) rootfs 模板 + dv-env.json + make_sn_config --seed-v2 --dev-local ---
# 仅 fresh 时构造 rootfs：--resume 语义是"不动 seed 重启"（T5），不得重跑
# make_sn_config 以免重写 rootfs/seed 产物。产物稳定性（重跑 make_sn_config
# diff 干净）由 e2e_sn_seed 用独立 scratch rootfs 验证。
if [ "$MODE" = "fresh" ]; then
  echo "[sn-dev-up] staging rootfs templates into $ROOTFS"
  for f in web3_gateway.yaml local_dns.toml website.yaml params.json; do
    cp "$APP_DIR/$f" "$ROOTFS/$f"
  done

  # alignBnsRuntimeParams 以 rootfs 里的 dv-env.json 为准写 bns_rpc_url 等。
  cat > "$ROOTFS/dv-env.json" <<EOF
{
  "rpc_endpoint": "$RPC",
  "chain_id": $CHAIN_ID,
  "contract_address": "$CONTRACT",
  "server_url": "$BNS_SERVER_URL",
  "server_rpc_path": "/kapi/bns"
}
EOF

  echo "[sn-dev-up] make_sn_config.ts --seed-v2 --dev-local"
  (cd "$SRC_DIR" && deno run -A ./make_sn_config.ts \
    --rootfs "$ROOTFS" --seed-v2 --dev-local \
    --env_root "$ENV_ROOT" --ca "$ENV_ROOT/ca") >"$VAR/make_sn_config.log" 2>&1 \
    || { echo "make_sn_config failed; see $VAR/make_sn_config.log" >&2; tail -20 "$VAR/make_sn_config.log" >&2; exit 1; }
else
  [ -f "$ROOTFS/sn_seed.yaml" ] && [ -f "$ROOTFS/bns_dv_seed.yaml" ] \
    || { echo "no seeded rootfs to resume ($ROOTFS); run --fresh" >&2; exit 1; }
  echo "[sn-dev-up] --resume: reusing rootfs and seed products as-is"
fi

# --- 5) 构建二进制 ---
echo "[sn-dev-up] building bns_dv + web3_gateway (cargo)"
BNS_DV_BIN="$(cd "$SRC_DIR" && cargo build -p bns-server --bin bns_dv --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*bns_dv"' | tail -1 | sed 's/.*:"//;s/"$//')"
[ -n "$BNS_DV_BIN" ] && [ -x "$BNS_DV_BIN" ] || { echo "failed to build bns_dv binary" >&2; exit 1; }
GW_BIN="$(cd "$SRC_DIR" && cargo build -p cyfs_gateway --bin cyfs_gateway --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*cyfs_gateway"' | tail -1 | sed 's/.*:"//;s/"$//')"
[ -n "$GW_BIN" ] && [ -x "$GW_BIN" ] || { echo "failed to build cyfs_gateway (web3_gateway) binary" >&2; exit 1; }

# --- 6) bns_dv serve --seed-config（种子上链完成后才开 HTTP，健康门控即种子门控）---
echo "[sn-dev-up] starting bns_dv serve on $BNS_SERVER_URL (with seed config)"
"$BNS_DV_BIN" serve \
  --rpc "$RPC" --contract "$CONTRACT" --chain-id "$CHAIN_ID" \
  --db "$INDEXER_DB" --listen "127.0.0.1:${BNS_SERVER_PORT}" \
  --start-block 0 --confirmations 0 --interval-ms 500 \
  --seed-config "$ROOTFS/bns_dv_seed.yaml" >"$BNS_LOG" 2>&1 &
echo $! > "$BNS_PID"
wait_for "bns-dv /health (incl. seed txs projected)" 120 bns_healthy

# --- 7) web3_gateway ---
echo "[sn-dev-up] starting web3_gateway (dns :$GW_DNS_PORT/udp, http :$GW_HTTP_PORT)"
# 注意启动形态：subshell 内 exec 让 $! 就是网关本体，且网关的 fd 全部指向
# 日志（不残留本脚本 stdout 管道——否则调用方等管道 EOF 会被长活进程挂死）。
(
  cd "$ROOTFS"
  exec env BUCKYOS_ROOT="$VAR/buckyos_root" \
    "$GW_BIN" --config_file "$ROOTFS/web3_gateway.yaml" >"$GW_LOG" 2>&1 </dev/null
) &
echo $! > "$GW_PID"
wait_for "web3_gateway http :$GW_HTTP_PORT" 60 gw_http_up

# --- 8) 写环境摘要 ---
cat > "$ENV_JSON" <<EOF
{
  "rootfs": "$ROOTFS",
  "env_root": "$ENV_ROOT",
  "rpc_endpoint": "$RPC",
  "chain_id": $CHAIN_ID,
  "contract_address": "$CONTRACT",
  "bns_server_url": "$BNS_SERVER_URL",
  "gw_http_port": $GW_HTTP_PORT,
  "gw_dns_port": $GW_DNS_PORT,
  "sn_host": "devtests.org",
  "sn_db": "$ROOTFS/sn.sqlite3",
  "anvil_pid_file": "$ANVIL_PID",
  "bns_pid_file": "$BNS_PID",
  "gw_pid_file": "$GW_PID"
}
EOF

echo "[sn-dev-up] READY ($MODE)"
echo "  env:     $ENV_JSON"
echo "  rootfs:  $ROOTFS"
echo "  dns:     127.0.0.1:$GW_DNS_PORT/udp    (dig @127.0.0.1 -p $GW_DNS_PORT alice.web3.devtests.org)"
echo "  http:    127.0.0.1:$GW_HTTP_PORT       (Host: sn.devtests.org)"
echo "  bns:     $BNS_SERVER_URL/kapi/bns"
echo "  logs:    $ANVIL_LOG , $BNS_LOG , $GW_LOG"

if [ "$KEEP_RUNNING" = "1" ]; then
  echo "[sn-dev-up] --keep-running: foreground (Ctrl-C to stop, then run sn-dev-down.sh)"
  trap 'echo; "$APP_DIR/scripts/sn-dev-down.sh" || true; exit 0' INT TERM
  tail -f "$GW_LOG"
fi
