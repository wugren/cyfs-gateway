#!/usr/bin/env bash
# 关停 dv-up.sh 后台托管的 DV 环境（doc/SN/SN-测试计划.md §5.1）。
#
#   dv-down.sh [--purge]
#
# 默认：kill anvil + bns-dv（anvil 在收到信号时把链状态落盘到 --state，供 --resume）。
# --purge：额外删除持久化状态（anvil-state / deployment / indexer db / dv-env.json）。
set -euo pipefail

cd "$(dirname "$0")/.."
APP_DIR="$(pwd)"
VAR="$APP_DIR/var"
ANVIL_PID="$VAR/anvil.pid"
NODE_PID="$VAR/bns-dv.pid"

PURGE=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

stop_pidfile() { # stop_pidfile <file> <name>
  local pf="$1" name="$2"
  [ -f "$pf" ] || { echo "[dv-down] $name: no pid file"; return 0; }
  local pid; pid="$(cat "$pf" 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
    echo "[dv-down] stopping $name (pid $pid)"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 25); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  else
    echo "[dv-down] $name: not running"
  fi
  rm -f "$pf"
}

# 先停 node（释放 SQLite），再停 anvil（让其落盘 state）。
stop_pidfile "$NODE_PID" "bns-dv"
stop_pidfile "$ANVIL_PID" "anvil"

if [ "$PURGE" = "1" ]; then
  echo "[dv-down] --purge: removing persisted state"
  rm -f "$VAR/anvil-state.json" "$VAR/indexer.sqlite" "$VAR/indexer.sqlite-wal" \
        "$VAR/indexer.sqlite-shm" "$APP_DIR/deployments/anvil.local.json" "$APP_DIR/dv-env.json"
fi

echo "[dv-down] done"
