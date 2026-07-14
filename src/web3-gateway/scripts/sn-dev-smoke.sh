#!/usr/bin/env bash
# SN 开发环境冒烟。
#
#   sn-dev-smoke.sh [--local]
#   sn-dev-smoke.sh --vm
#
# --local（默认）读 sn-dev-up.sh 生成的 sn-dev-env.json，验证本机高位端口
# 环境。--vm 验证 buckyos-devtest 已按 src/dev_configs/sn_test 部署到
# multipass VM 的 web3-gateway，此时 SN 使用 VM/生产 profile 的特权端口
# （DNS :53 / HTTP :80），本机需已把 sn.devtests.org 配到该 VM IP。
#
# 验证 seed 确实生效（对应 doc/SN/SN-seed-config-TODO.md §3.3 的 curl/dig 面）：
#   S1 DNS A     alice.web3.devtests.org -> sn_ip（本机模式 127.0.0.1；VM 模式为 VM IP）
#   S2 DNS TXT   alice.web3.devtests.org 含 PKX= / BOOT= / DEV=
#   S3 链上种子  GET /1.0/identifiers/did:bns:alice 经 indexer 投影解析成功
#   S4 user_domain 种子  GET /1.0/identifiers/did:web:charlie.me 解析成功
#   S5 纯 Web3 位  did:bns:dave（无 sn_user 行）仍可经 BNS 路径解析
#   S6 BNS proxy   auth.register 用户只给 asset_owner，SN 代付 gas 注册 BNS；
#                  再用 access token 经 bns.publish_dns_txt 代理写 dns_txt，
#                  最后从 DNS TXT 读回 indexer 投影。
#   S7 keep-tunnel  OOD peer 到 SN 的 RTCP keep-tunnel 处于 ESTABLISHED
#      （仅 --vm；经 buckyos-devtest <group> run sn 检查 rtcp 端口的入站长
#      连接。tunnel 断开时该 case 必须失败；单节点 group 用 --no-keep-tunnel
#      显式关闭。）
# 登录/激活码走 kRPC 协议，由 e2e_sn_seed 测试覆盖（T1）。
set -euo pipefail

cd "$(dirname "$0")/.."
APP_DIR="$(pwd)"
SRC_DIR="$(cd .. && pwd)"
VAR="${SN_DEV_VAR_DIR:-$APP_DIR/var/sn-dev}"
ENV_JSON="$VAR/sn-dev-env.json"
DEFAULT_VM_CONFIG_DIR="$SRC_DIR/dev_configs/sn_test"

usage() {
  cat <<EOF
Usage:
  scripts/sn-dev-smoke.sh [--local]
  scripts/sn-dev-smoke.sh --vm [--expected-a <vm-ip>] [--dns-server <ip>] [--http-origin <url>]

Options:
  --local              Test the local sn-dev-up.sh environment (default).
  --vm                 Test the buckyos-devtest/multipass VM environment.
  --sn-host <domain>   Base SN domain, default devtests.org.
  --expected-a <ip>    Expected A record for alice.web3.<domain>; defaults to sn.<domain> host resolution in VM mode.
  --dns-server <addr>  DNS server address; defaults to 127.0.0.1 locally and the VM IP in VM mode.
  --http-origin <url>  HTTP origin; defaults to local high port or http://sn.<domain> in VM mode.
  --config-dir <path>  VM devtest config dir; default $DEFAULT_VM_CONFIG_DIR.
  --devtest-group <g>  buckyos-devtest group for the S6 keep-tunnel check; default sntest.
  --devtest-dir <dir>  Directory to run buckyos-devtest from (must contain dev_configs/<group>.json);
                       auto-detected from this repo and the sibling buckyos checkout.
  --rtcp-port <port>   SN RTCP listen port for the keep-tunnel check; default 2980.
  --no-bns-proxy       Skip S6 (older dev environments without bns_proxy enabled).
  --no-keep-tunnel     Skip S7 (single-node groups without an OOD peer).
EOF
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }
}

json_get() {
  local v=""
  v="$(grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*"//;s/"$//')" || true
  printf '%s' "$v"
}
json_get_num() {
  local v=""
  v="$(grep -o "\"$2\"[[:space:]]*:[[:space:]]*[0-9][0-9]*" "$1" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*//')" || true
  printf '%s' "$v"
}

resolve_ipv4() {
  local host="$1"
  local ip=""
  if command -v getent >/dev/null 2>&1; then
    ip="$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')" || true
  fi
  if [ -z "$ip" ] && command -v dscacheutil >/dev/null 2>&1; then
    ip="$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/ip_address:/ {print $2; exit}')" || true
  fi
  if [ -z "$ip" ] && command -v python3 >/dev/null 2>&1; then
    ip="$(python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$host" 2>/dev/null)" || true
  fi
  if [ -z "$ip" ]; then
    ip="$(ping -c 1 "$host" 2>/dev/null | sed -n 's/^PING [^(]*(\([^)]*\)).*/\1/p' | head -1)" || true
  fi
  printf '%s' "$ip"
}

MODE="${SN_DEV_SMOKE_MODE:-local}"
SN_HOST_ARG="${SN_DEV_SN_HOST:-}"
EXPECTED_A="${SN_DEV_EXPECTED_A:-${SN_DEV_VM_IP:-}}"
DNS_SERVER_ARG="${SN_DEV_DNS_SERVER:-}"
HTTP_ORIGIN_ARG="${SN_DEV_HTTP_ORIGIN:-}"
VM_CONFIG_DIR="${SN_DEV_VM_CONFIG_DIR:-$DEFAULT_VM_CONFIG_DIR}"
SMOKE_RETRIES="${SN_DEV_SMOKE_RETRIES:-10}"
SMOKE_RETRY_DELAY="${SN_DEV_SMOKE_RETRY_DELAY:-2}"
DEVTEST_GROUP="${SN_DEV_DEVTEST_GROUP:-sntest}"
DEVTEST_DIR="${SN_DEV_DEVTEST_DIR:-}"
RTCP_PORT="${SN_DEV_RTCP_PORT:-2980}"
KEEP_TUNNEL_CHECK="${SN_DEV_KEEP_TUNNEL_CHECK:-1}"
BNS_PROXY_CHECK="${SN_DEV_BNS_PROXY_CHECK:-1}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --local) MODE="local"; shift ;;
    --vm) MODE="vm"; shift ;;
    --sn-host)
      [ "$#" -ge 2 ] || { echo "--sn-host requires a value" >&2; exit 2; }
      SN_HOST_ARG="$2"; shift 2 ;;
    --expected-a|--vm-ip)
      [ "$#" -ge 2 ] || { echo "$1 requires a value" >&2; exit 2; }
      EXPECTED_A="$2"; shift 2 ;;
    --dns-server)
      [ "$#" -ge 2 ] || { echo "--dns-server requires a value" >&2; exit 2; }
      DNS_SERVER_ARG="$2"; shift 2 ;;
    --http-origin)
      [ "$#" -ge 2 ] || { echo "--http-origin requires a value" >&2; exit 2; }
      HTTP_ORIGIN_ARG="$2"; shift 2 ;;
    --config-dir)
      [ "$#" -ge 2 ] || { echo "--config-dir requires a value" >&2; exit 2; }
      VM_CONFIG_DIR="$2"; shift 2 ;;
    --devtest-group)
      [ "$#" -ge 2 ] || { echo "--devtest-group requires a value" >&2; exit 2; }
      DEVTEST_GROUP="$2"; shift 2 ;;
    --devtest-dir)
      [ "$#" -ge 2 ] || { echo "--devtest-dir requires a value" >&2; exit 2; }
      DEVTEST_DIR="$2"; shift 2 ;;
    --rtcp-port)
      [ "$#" -ge 2 ] || { echo "--rtcp-port requires a value" >&2; exit 2; }
      RTCP_PORT="$2"; shift 2 ;;
    --no-bns-proxy) BNS_PROXY_CHECK=0; shift ;;
    --no-keep-tunnel) KEEP_TUNNEL_CHECK=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

require_tool curl
require_tool dig
if [ "$BNS_PROXY_CHECK" = "1" ]; then
  require_tool python3
fi

case "$MODE" in
  local)
    [ -f "$ENV_JSON" ] || { echo "no sn-dev-env.json; run sn-dev-up.sh first" >&2; exit 1; }
    DNS_PORT="$(json_get_num "$ENV_JSON" gw_dns_port)"
    HTTP_PORT="$(json_get_num "$ENV_JSON" gw_http_port)"
    SN_HOST="$(json_get "$ENV_JSON" sn_host)"
    [ -n "$SN_HOST_ARG" ] && SN_HOST="$SN_HOST_ARG"
    [ -n "$SN_HOST" ] || SN_HOST="devtests.org"
    [ -n "$DNS_PORT" ] || { echo "missing gw_dns_port in $ENV_JSON" >&2; exit 1; }
    [ -n "$HTTP_PORT" ] || { echo "missing gw_http_port in $ENV_JSON" >&2; exit 1; }
    DNS_SERVER="${DNS_SERVER_ARG:-127.0.0.1}"
    HTTP_ORIGIN="${HTTP_ORIGIN_ARG:-http://127.0.0.1:${HTTP_PORT}}"
    EXPECTED_A="${EXPECTED_A:-127.0.0.1}"
    ;;
  vm)
    SN_HOST="${SN_HOST_ARG:-devtests.org}"
    DNS_PORT=53
    HTTP_PORT=80
    [ -d "$VM_CONFIG_DIR" ] || { echo "VM config dir not found: $VM_CONFIG_DIR" >&2; exit 1; }
    if [ -z "$EXPECTED_A" ]; then
      EXPECTED_A="$(resolve_ipv4 "sn.$SN_HOST")"
    fi
    [ -n "$EXPECTED_A" ] || {
      echo "could not resolve sn.$SN_HOST; configure hosts or pass --expected-a <vm-ip>" >&2
      exit 1
    }
    DNS_SERVER="${DNS_SERVER_ARG:-$EXPECTED_A}"
    HTTP_ORIGIN="${HTTP_ORIGIN_ARG:-http://sn.$SN_HOST}"
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac

SN_HTTP_HOST="sn.$SN_HOST"
ALICE_HOST="alice.web3.$SN_HOST"

# S6 keep-tunnel 依赖 buckyos-devtest（VM 后端保持透明，不直接调 multipass）。
# devtest 要求 cwd 含 dev_configs/<group>.json：优先显式 --devtest-dir，
# 其次本仓库，再次同级 buckyos checkout（sntest 组即在那里）。
detect_devtest_dir() {
  local cand
  for cand in "$SRC_DIR" "$SRC_DIR/../buckyos/src" "$SRC_DIR/../../buckyos/src"; do
    if [ -f "$cand/dev_configs/$DEVTEST_GROUP.json" ]; then
      (cd "$cand" && pwd)
      return 0
    fi
  done
  return 1
}

if [ "$MODE" = "vm" ] && [ "$KEEP_TUNNEL_CHECK" = "1" ]; then
  if [ -z "$DEVTEST_DIR" ]; then
    DEVTEST_DIR="$(detect_devtest_dir || true)"
  fi
  if [ -z "$DEVTEST_DIR" ] || [ ! -f "$DEVTEST_DIR/dev_configs/$DEVTEST_GROUP.json" ]; then
    echo "keep-tunnel check needs buckyos-devtest group '$DEVTEST_GROUP'; pass --devtest-dir or --no-keep-tunnel" >&2
    exit 1
  fi
  require_tool uv
fi

PASS=0
FAIL=0
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  local attempt=1
  while [ "$attempt" -le "$SMOKE_RETRIES" ]; do
    if "$@" >/dev/null 2>&1; then
      echo "  PASS  $desc"
      PASS=$((PASS + 1))
      return
    fi
    if [ "$attempt" -lt "$SMOKE_RETRIES" ]; then
      sleep "$SMOKE_RETRY_DELAY"
    fi
    attempt=$((attempt + 1))
  done
  echo "  FAIL  $desc" >&2
  FAIL=$((FAIL + 1))
}

dns_a_matches_expected() {
  dig +short +time=3 +tries=1 @"$DNS_SERVER" -p "$DNS_PORT" "$ALICE_HOST" A | grep -Fxq "$EXPECTED_A"
}
dns_txt_has() { # dns_txt_has <marker>
  dig +short +time=3 +tries=1 @"$DNS_SERVER" -p "$DNS_PORT" "$ALICE_HOST" TXT | grep -Fq "$1"
}
identifiers_ok() { # identifiers_ok <did>
  # 当前兼容 API 顶层返回 boot/user_name；旧 DID 文档形态可能返回 id/oods。
  # 任一形态都说明 resolver 成功返回了可用文档。
  curl -fsS --connect-timeout 3 --max-time 10 -H "Host: $SN_HTTP_HOST" "$HTTP_ORIGIN/1.0/identifiers/$1" | grep -Eq '"(boot|user_name|id|oods)"'
}
bns_proxy_real_path_ok() {
  SN_HOST="$SN_HOST" \
  SN_HTTP_HOST="$SN_HTTP_HOST" \
  HTTP_ORIGIN="$HTTP_ORIGIN" \
  DNS_SERVER="$DNS_SERVER" \
  DNS_PORT="$DNS_PORT" \
  SMOKE_RETRIES="$SMOKE_RETRIES" \
  SMOKE_RETRY_DELAY="$SMOKE_RETRY_DELAY" \
  python3 <<'PY'
import json
import os
import subprocess
import time
import urllib.error
import urllib.request

sn_host = os.environ["SN_HOST"]
sn_http_host = os.environ["SN_HTTP_HOST"]
http_origin = os.environ["HTTP_ORIGIN"].rstrip("/")
dns_server = os.environ["DNS_SERVER"]
dns_port = os.environ["DNS_PORT"]
retries = int(os.environ.get("SMOKE_RETRIES", "10"))
delay = float(os.environ.get("SMOKE_RETRY_DELAY", "2"))

active_code = "zX6cV7bN8mK9lJ0hG1fD"
asset_owner = os.environ.get(
    "SN_DEV_BNS_PROXY_ASSET_OWNER",
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
)
username = os.environ.get("SN_DEV_BNS_PROXY_USER")
if not username:
    username = f"smokebns{int(time.time()) % 1_000_000_000}"
password = "smoke-pwd"
initial_marker = f"PKX=smoke-init-{username}"
live_marker = f"PKX=smoke-live-{username}"


def rpc(path, method, params, token=None):
    body = {"method": method, "params": params, "sys": [1]}
    if token:
        body["token"] = token
        body["sys"] = [1, token]
    request = urllib.request.Request(
        f"{http_origin}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Host": sn_http_host,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        payload = err.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} HTTP {err.code}: {payload}") from err
    data = json.loads(payload)
    if "error" in data:
        raise RuntimeError(f"{method} failed: {data['error']}")
    if "result" not in data:
        raise RuntimeError(f"{method} response has no result: {data}")
    result = data["result"]
    if isinstance(result, dict) and "Success" in result:
        return result["Success"]
    if isinstance(result, dict) and "Failed" in result:
        raise RuntimeError(f"{method} failed: {result['Failed']}")
    if isinstance(result, str):
        raise RuntimeError(f"{method} failed: {result}")
    return result


def assert_tx_result(label, result, expected_status="submitted"):
    if result.get("status") != expected_status:
        raise RuntimeError(f"{label} status is not {expected_status}: {result}")
    tx_hash = result.get("tx_hash")
    if not isinstance(tx_hash, str) or not tx_hash.startswith("0x"):
        raise RuntimeError(f"{label} missing tx_hash: {result}")
    controller = result.get("controller_address", "")
    if controller.lower() == asset_owner.lower():
        raise RuntimeError(f"{label} used asset_owner as controller: {result}")


def dig_txt():
    host = f"{username}.web3.{sn_host}"
    output = subprocess.run(
        [
            "dig",
            "+short",
            "+time=3",
            "+tries=1",
            f"@{dns_server}",
            "-p",
            str(dns_port),
            host,
            "TXT",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return output.stdout


def wait_txt_contains(*markers):
    last = ""
    for _ in range(retries):
        last = dig_txt()
        if all(marker in last for marker in markers):
            return
        time.sleep(delay)
    raise RuntimeError(f"DNS TXT for {username}.web3.{sn_host} did not contain {markers}: {last}")


# Reset the dedicated test activation code through the same internal admin path
# used by Rust integration tests. The BNS name stays unique per run, so old chain
# state cannot conflict with this registration.
rpc("/", "admin.clear_state_by_active_code", {})

register = rpc(
    "/kapi/sn/auth",
    "auth.register",
    {
        "name": username,
        "email": f"{username}@example.com",
        "pwd_hash": password,
        "active_code": active_code,
        "request_id": f"sn:smoke-register:{username}",
        "asset_owner": asset_owner,
        "initial_documents": {
            "dns_txt": [{"ttl": 600, "value": initial_marker}],
        },
    },
)
if register.get("code") != 0:
    raise RuntimeError(f"auth.register returned non-zero code: {register}")
token = register.get("access_token")
if not isinstance(token, str) or not token:
    raise RuntimeError(f"auth.register returned no access_token: {register}")
bns = register.get("bns")
if not isinstance(bns, dict):
    raise RuntimeError(f"auth.register did not return bns tx info; bns_proxy may be disabled: {register}")
if bns.get("operation") != "register_name_bootstrap":
    raise RuntimeError(f"unexpected register bns operation: {bns}")
if bns.get("asset_owner", "").lower() != asset_owner.lower():
    raise RuntimeError(f"register asset_owner mismatch: {bns}")
assert_tx_result("auth.register bns", bns, expected_status="confirmed")

wait_txt_contains(initial_marker)

publish = rpc(
    "/kapi/sn/bns-proxy",
    "bns.publish_dns_txt",
    {
        "name": username,
        "request_id": f"sn:smoke-dns:{username}",
        "mode": "add",
        "ttl": 300,
        "value": live_marker,
    },
    token=token,
)
if publish.get("code") != 0:
    raise RuntimeError(f"bns.publish_dns_txt returned non-zero code: {publish}")
if publish.get("operation") != "publish_dns_txt" or publish.get("doc_type") != "dns_txt":
    raise RuntimeError(f"unexpected publish result: {publish}")
assert_tx_result("bns.publish_dns_txt", publish)

wait_txt_contains(initial_marker, live_marker)
PY
}
keep_tunnel_established() {
  # OOD -> SN 的 RTCP keep-tunnel 是一条常驻 TCP 长连接；SN 侧 rtcp 端口
  # 存在非本机来源的 ESTABLISHED 即视为 keep-tunnel 在线。tunnel 断开时
  # 连接消失，本检查失败——这正是 S6 的验收语义。
  local out
  out="$(cd "$DEVTEST_DIR" && uv run buckyos-devtest "$DEVTEST_GROUP" run sn \
    "ss -tnH state established '( sport = :$RTCP_PORT )' | grep -v 127.0.0.1 | wc -l" 2>/dev/null)" || return 1
  printf '%s\n' "$out" | grep -qE '^[[:space:]]*[1-9][0-9]*[[:space:]]*$'
}

echo "[sn-dev-smoke] mode: $MODE"
if [ "$MODE" = "vm" ]; then
  echo "[sn-dev-smoke] vm config: $VM_CONFIG_DIR"
fi
echo "[sn-dev-smoke] targets: dns $DNS_SERVER:$DNS_PORT, http $HTTP_ORIGIN (Host $SN_HTTP_HOST)"
echo "[sn-dev-smoke] expected SN A: $EXPECTED_A"
check "S1 DNS A $ALICE_HOST -> $EXPECTED_A" dns_a_matches_expected
check "S2 DNS TXT contains PKX=" dns_txt_has "PKX="
check "S2 DNS TXT contains BOOT=" dns_txt_has "BOOT="
check "S2 DNS TXT contains DEV=" dns_txt_has "DEV="
check "S3 resolve did:bns:alice via indexer projection" identifiers_ok "did:bns:alice"
check "S4 resolve did:web:charlie.me via user_domain seed" identifiers_ok "did:web:charlie.me"
check "S5 resolve did:bns:dave (pure Web3, no sn_user row)" identifiers_ok "did:bns:dave"
if [ "$BNS_PROXY_CHECK" = "1" ]; then
  check "S6 auth.register + bns.publish_dns_txt via SN-paid BNS proxy" bns_proxy_real_path_ok
fi
if [ "$MODE" = "vm" ] && [ "$KEEP_TUNNEL_CHECK" = "1" ]; then
  echo "[sn-dev-smoke] keep-tunnel via: buckyos-devtest $DEVTEST_GROUP (cwd $DEVTEST_DIR)"
  check "S7 OOD keep-tunnel to SN rtcp :$RTCP_PORT is ESTABLISHED" keep_tunnel_established
fi

echo "[sn-dev-smoke] $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
