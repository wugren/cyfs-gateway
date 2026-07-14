#!/usr/bin/env bash
# DV（开发验证）集成环境一键启动（doc/SN/SN-测试计划.md §5.1）。
#
#   dv-up.sh [--fresh | --resume] [--keep-running]
#
# 编排：anvil（私链，--state 持久化）→ deploy.sh 部署 Bns.sol → bns-dv serve
# （BNS-Indexer 轮询 sync_once + BNS-Server 读投影/写转发）。每步健康门控后才进入下一步，
# 全部就绪后写出 dv-env.json。
#
#   --fresh   ：删除 anvil-state / 部署记录 / indexer db，全新拉起并部署。
#   --resume  ：复用已存在的 anvil-state + 合约地址 + indexer 游标继续同步；
#               校验链上 chainId/合约地址与 dv-env.json 一致，否则报错要求 --fresh。
#   --keep-running：前台保活（Ctrl-C 退出后用 dv-down.sh 清理）；默认后台托管（PID 文件）。
set -euo pipefail

cd "$(dirname "$0")/.."
APP_DIR="$(pwd)"
SRC_DIR="$(cd ../.. && pwd)"

VAR="$APP_DIR/var"
DEPLOY_DIR="$APP_DIR/deployments"
mkdir -p "$VAR" "$DEPLOY_DIR"

ANVIL_STATE="$VAR/anvil-state.json"
DEPLOY_JSON="$DEPLOY_DIR/anvil.local.json"
INDEXER_DB="$VAR/indexer.sqlite"
ENV_JSON="$APP_DIR/dv-env.json"
ANVIL_PID="$VAR/anvil.pid"
NODE_PID="$VAR/bns-dv.pid"
ANVIL_LOG="$VAR/anvil.log"
NODE_LOG="$VAR/bns-dv.log"

ANVIL_HOST="${ANVIL_HOST:-127.0.0.1}"
ANVIL_PORT="${ANVIL_PORT:-8545}"
CHAIN_ID="${ANVIL_CHAIN_ID:-31337}"
BLOCK_TIME="${ANVIL_BLOCK_TIME:-}"
SERVER_PORT="${BNS_DV_SERVER_PORT:-18080}"
RPC="http://${ANVIL_HOST}:${ANVIL_PORT}"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
MNEMONIC="${ANVIL_MNEMONIC:-test test test test test test test test test test test junk}"
# account[1] 作部署者（与 smoke 写账户 account[0] nonce 独立）。
DEPLOYER_KEY="${BNS_DEPLOYER_PRIVATE_KEY:-0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d}"

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

for bin in anvil forge cast cargo; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing required tool: $bin" >&2; exit 1; }
done

json_get() { # json_get <file> <key>  (string value)
  local v=""
  v="$(grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*"//;s/"$//')" || true
  printf '%s' "$v"
}

json_get_num() { # json_get_num <file> <key>  (numeric value)
  local v=""
  v="$(grep -o "\"$2\"[[:space:]]*:[[:space:]]*[0-9][0-9]*" "$1" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*//')" || true
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
server_healthy() { [ "$(curl -fsS "$SERVER_URL/health" 2>/dev/null)" = "ok" ]; }

clear_port() { # clear_port <port>
  if command -v lsof >/dev/null 2>&1; then
    local pids; pids="$(lsof -ti "tcp:$1" 2>/dev/null || true)"
    [ -n "$pids" ] && kill $pids 2>/dev/null || true
  fi
}

stop_if_running() {
  for pf in "$ANVIL_PID" "$NODE_PID"; do
    [ -f "$pf" ] || continue
    local pid; pid="$(cat "$pf" 2>/dev/null || true)"
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; fi
    rm -f "$pf"
  done
  # 兜底：清掉占用本环境端口的残留进程，避免 anvil/server 绑定失败。
  clear_port "$ANVIL_PORT"
  clear_port "$SERVER_PORT"
  sleep 0.3
}

# --- 1) 准备状态 ---
stop_if_running
if [ "$MODE" = "fresh" ]; then
  echo "[dv-up] --fresh: clearing persisted state"
  rm -f "$ANVIL_STATE" "$DEPLOY_JSON" "$INDEXER_DB" "$INDEXER_DB-wal" "$INDEXER_DB-shm" "$ENV_JSON"
else
  echo "[dv-up] --resume: reusing anvil-state / deployment / indexer cursor"
  [ -f "$DEPLOY_JSON" ] || { echo "no deployment to resume ($DEPLOY_JSON); run --fresh" >&2; exit 1; }
fi

ANVIL_ARGS=(
  --host "$ANVIL_HOST" --port "$ANVIL_PORT" \
  --chain-id "$CHAIN_ID" \
  --mnemonic "$MNEMONIC" \
  --disable-code-size-limit \
  --state "$ANVIL_STATE"
)
MINING_MODE="auto"
if [ -n "$BLOCK_TIME" ]; then
  ANVIL_ARGS+=(--block-time "$BLOCK_TIME")
  MINING_MODE="interval ${BLOCK_TIME}s"
fi

# --- 2) 起 anvil（--state 持久化/自动加载）---
echo "[dv-up] starting anvil on $RPC (chain $CHAIN_ID, mining ${MINING_MODE})"
anvil "${ANVIL_ARGS[@]}" >"$ANVIL_LOG" 2>&1 &
echo $! > "$ANVIL_PID"
wait_for "anvil eth_chainId" 30 anvil_chain_id_ok

# --- 3) 部署（fresh）或复用（resume）合约 ---
if [ "$MODE" = "fresh" ]; then
  echo "[dv-up] deploying Bns.sol"
  forge create src/Bns.sol:Bns \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast --json >"$DEPLOY_JSON.tmp" 2>"$VAR/forge.err" \
    || { echo "forge create failed:" >&2; cat "$VAR/forge.err" >&2; exit 1; }
  # 取出 JSON 对象（forge 可能 pretty-print 多行）。
  sed -n '/{/,/}/p' "$DEPLOY_JSON.tmp" > "$DEPLOY_JSON"
  rm -f "$DEPLOY_JSON.tmp"
fi
CONTRACT="$(json_get "$DEPLOY_JSON" deployedTo)"
[ -n "$CONTRACT" ] || { echo "could not determine contract address from $DEPLOY_JSON" >&2; exit 1; }
wait_for "contract code at $CONTRACT" 30 contract_deployed "$CONTRACT"

# resume 一致性校验：链上 chainId 与已记录合约地址必须吻合（否则 source 漂移）。
if [ "$MODE" = "resume" ] && [ -f "$ENV_JSON" ]; then
  prev_contract="$(json_get "$ENV_JSON" contract_address)"
  prev_chain="$(json_get_num "$ENV_JSON" chain_id)"
  if [ -n "$prev_contract" ] && [ "$prev_contract" != "$CONTRACT" ]; then
    echo "resume mismatch: dv-env contract $prev_contract != on-chain $CONTRACT; run --fresh" >&2; exit 1
  fi
  if [ -n "$prev_chain" ] && [ "$prev_chain" != "$CHAIN_ID" ]; then
    echo "resume mismatch: dv-env chain_id $prev_chain != $CHAIN_ID; run --fresh" >&2; exit 1
  fi
fi

DEPLOY_BLOCK="$(cast block-number --rpc-url "$RPC" 2>/dev/null || echo 0)"

# --- 4) 起 bns-dv serve（indexer 轮询 + server 读/写）---
echo "[dv-up] building bns-dv"
BNS_DV_BIN="$(cargo build -p bns-server --bin bns_dv --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*bns_dv"' | tail -1 | sed 's/.*:"//;s/"$//')"
[ -n "$BNS_DV_BIN" ] && [ -x "$BNS_DV_BIN" ] || { echo "failed to build bns-dv binary" >&2; exit 1; }

echo "[dv-up] starting bns-dv serve on $SERVER_URL"
"$BNS_DV_BIN" serve \
  --rpc "$RPC" \
  --contract "$CONTRACT" \
  --chain-id "$CHAIN_ID" \
  --db "$INDEXER_DB" \
  --listen "127.0.0.1:${SERVER_PORT}" \
  --start-block 0 \
  --confirmations 0 \
  --interval-ms 1000 >"$NODE_LOG" 2>&1 &
echo $! > "$NODE_PID"
wait_for "bns-dv /health" 30 server_healthy

# --- 5) 写 dv-env.json ---
cat > "$ENV_JSON" <<EOF
{
  "rpc_endpoint": "$RPC",
  "chain_id": $CHAIN_ID,
  "contract_address": "$CONTRACT",
  "server_url": "$SERVER_URL",
  "server_rpc_path": "/kapi/bns",
  "indexer_db": "$INDEXER_DB",
  "anvil_state": "$ANVIL_STATE",
  "deployer_key": "$DEPLOYER_KEY",
  "deploy_block": $DEPLOY_BLOCK,
  "anvil_pid_file": "$ANVIL_PID",
  "node_pid_file": "$NODE_PID"
}
EOF

echo "[dv-up] READY ($MODE)"
echo "  dv-env.json: $ENV_JSON"
echo "  rpc:         $RPC"
echo "  contract:    $CONTRACT (deploy block $DEPLOY_BLOCK)"
echo "  server:      $SERVER_URL  (POST /kapi/bns)"
echo "  logs:        $ANVIL_LOG , $NODE_LOG"

if [ "$KEEP_RUNNING" = "1" ]; then
  echo "[dv-up] --keep-running: foreground (Ctrl-C to stop, then run dv-down.sh)"
  trap 'echo; "$APP_DIR/scripts/dv-down.sh" || true; exit 0' INT TERM
  tail -f "$NODE_LOG"
fi
