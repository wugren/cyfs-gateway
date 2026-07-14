#!/usr/bin/env bash
# 跨全分层冒烟（doc/SN/SN-测试计划.md §5.2B）。
#
#   dv-smoke.sh [--name <bns-name>]
#
# 读 dv-up.sh 生成的 dv-env.json，用 bns-dv smoke 驱动
# 注册 → 发布(inline) → 等待 indexer 投影 → 经 BNS-Server 读命中 的最小路径，
# 打印每步耗时与结果，作为"环境是否健康"的快速门禁（Smoke.s.sol 的跨全分层版）。
#
# 默认 name 带时间戳，便于在 --resume 后重复冒烟而不撞已注册的名字
# （从而也验证 indexer 游标延续、对新写从当前游标增量投影，而非从 0 重放）。
set -euo pipefail

cd "$(dirname "$0")/.."
APP_DIR="$(pwd)"
ENV_JSON="$APP_DIR/dv-env.json"
[ -f "$ENV_JSON" ] || { echo "no dv-env.json; run dv-up.sh first" >&2; exit 1; }

NAME=""
for arg in "$@"; do
  case "$arg" in
    --name) shift; ;;
  esac
done
# 解析 --name <value>
while [ $# -gt 0 ]; do
  case "$1" in
    --name) NAME="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$NAME" ] || NAME="smoke$(date +%s)"

json_get() { local v=""; v="$(grep -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$ENV_JSON" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*"//;s/"$//')" || true; printf '%s' "$v"; }
json_get_num() { local v=""; v="$(grep -o "\"$1\"[[:space:]]*:[[:space:]]*[0-9][0-9]*" "$ENV_JSON" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*//')" || true; printf '%s' "$v"; }

RPC="$(json_get rpc_endpoint)"
CONTRACT="$(json_get contract_address)"
SERVER_URL="$(json_get server_url)"
CHAIN_ID="$(json_get_num chain_id)"
# account[0] 作 smoke 写账户（与部署者 account[1] nonce 独立）。
SMOKE_KEY="${BNS_SMOKE_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

echo "[dv-smoke] env: rpc=$RPC contract=$CONTRACT server=$SERVER_URL chain=$CHAIN_ID name=$NAME"

BNS_DV_BIN="$(cargo build -p bns-server --bin bns_dv --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*bns_dv"' | tail -1 | sed 's/.*:"//;s/"$//')"
[ -n "$BNS_DV_BIN" ] && [ -x "$BNS_DV_BIN" ] || { echo "failed to build bns-dv binary" >&2; exit 1; }

START="$(date +%s)"
"$BNS_DV_BIN" smoke \
  --server "$SERVER_URL" \
  --rpc "$RPC" \
  --contract "$CONTRACT" \
  --chain-id "$CHAIN_ID" \
  --key "$SMOKE_KEY" \
  --name "$NAME" \
  --timeout-ms 30000
echo "[dv-smoke] total $(( $(date +%s) - START ))s"
