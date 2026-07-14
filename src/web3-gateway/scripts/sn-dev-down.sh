#!/usr/bin/env bash
# 停止 sn-dev-up.sh 拉起的 SN 本机开发环境。
#
#   sn-dev-down.sh [--purge]
#
# --purge：额外删除 var/sn-dev 全部持久化状态（rootfs / anvil-state /
#          indexer db / 用户 env / 日志）。
set -euo pipefail

cd "$(dirname "$0")/.."
APP_DIR="$(pwd)"
VAR="${SN_DEV_VAR_DIR:-$APP_DIR/var/sn-dev}"

PURGE=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

stop_pid_file() {
  local pf="$1" name="$2"
  [ -f "$pf" ] || return 0
  local pid; pid="$(cat "$pf" 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
    echo "[sn-dev-down] stopping $name (pid $pid)"
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.2
    done
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pf"
}

# 关停顺序与依赖相反：gateway -> bns_dv -> anvil。
stop_pid_file "$VAR/web3-gateway.pid" "web3_gateway"
stop_pid_file "$VAR/bns-dv.pid" "bns_dv"
stop_pid_file "$VAR/anvil.pid" "anvil"

if [ "$PURGE" = "1" ]; then
  echo "[sn-dev-down] --purge: removing $VAR"
  rm -rf "$VAR"
fi

echo "[sn-dev-down] done"
