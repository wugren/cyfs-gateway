#!/usr/bin/env -S uv run

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

MAX_START_ATTEMPTS = 30
STARTUP_STABLE_SECONDS = 5
RETRY_DELAY_SECONDS = 2
BNS_HEALTH_TIMEOUT_SECONDS = 30
BNS_HEALTH_INTERVAL_SECONDS = 0.5
PROCESS_STOP_TIMEOUT_SECONDS = 10

BNS_RPC_ENDPOINT = os.environ.get("BNS_RPC_ENDPOINT", "http://127.0.0.1:8545")
BNS_CONTRACT_ADDRESS = os.environ.get(
    "BNS_CONTRACT_ADDRESS", "0x8464135c8F25Da09e49BC8782676a84730C318bC"
)
BNS_CHAIN_ID = os.environ.get("BNS_CHAIN_ID", "31337")
BNS_LISTEN = "127.0.0.1:18080"
BNS_SERVER_URL = "http://127.0.0.1:18080"
BNS_INDEXER_DB = "bns_indexer.sqlite"
BNS_START_BLOCK = "0"
BNS_CONFIRMATIONS = "0"
BNS_INTERVAL_MS = "1000"
BNS_DEPLOYMENT_FILE = "bns-deployment.json"

children: list[subprocess.Popen] = []


def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def terminate_all_children() -> None:
    for process in reversed(list(children)):
        terminate_process(process)
        if process in children:
            children.remove(process)


def signal_handler(signum: int, _frame) -> None:
    terminate_all_children()
    raise SystemExit(128 + signum)


def run_child(cmd: list[str], cwd: Path) -> int:
    process = subprocess.Popen(cmd, cwd=cwd)
    children.append(process)
    try:
        return process.wait()
    finally:
        if process in children:
            children.remove(process)


BNS_SEED_CONFIG_FILE = "bns_dv_seed.yaml"
MACHINE_CONFIG_FILE = "machine.json"


def install_machine_config(current_dir: Path) -> None:
    # web3_gateway 在启动时读 {BUCKYOS_ROOT:-/opt/buckyos}/etc/machine.json
    # 初始化 name-client 的 web3_bridge；不装这份文件时 bns 权威落到内置默认
    # web3.buckyos.ai（生产环境），SN 对 keep-tunnel 来源设备的 DID 验证会
    # 打到生产环境而失败。machine.json 由 make_sn_config.ts 生成在部署目录。
    src = current_dir / MACHINE_CONFIG_FILE
    if not src.exists():
        return
    etc_dir = Path(os.environ.get("BUCKYOS_ROOT", "/opt/buckyos")) / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, etc_dir / MACHINE_CONFIG_FILE)
    print(f"installed {src} -> {etc_dir / MACHINE_CONFIG_FILE}")


def install_dev_ca(current_dir: Path) -> None:
    # SN 进程用 https 回访自己的 resolver（machine.json 的 bns bridge 指向
    # web3.<sn_host>，证书由 dev CA 签发）。web3_gateway 的 reqwest 走
    # rustls-native-roots（读系统 CA bundle），所以把部署目录 ca/ 下的
    # dev CA 装入系统信任；非 Linux 或无 CA 文件时静默跳过。
    ca_dir = current_dir / "ca"
    if not ca_dir.is_dir() or not Path("/usr/local/share/ca-certificates").is_dir():
        return
    installed = False
    for cert in sorted(ca_dir.glob("*_ca_cert.pem")):
        target = Path("/usr/local/share/ca-certificates") / (cert.stem + ".crt")
        if target.exists() and target.read_bytes() == cert.read_bytes():
            continue
        shutil.copyfile(cert, target)
        installed = True
        print(f"installed dev CA {cert} -> {target}")
    if installed:
        subprocess.run(["update-ca-certificates"], check=False)


def json_rpc(method: str, params: list | None = None) -> dict:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": 1,
        }
    ).encode("utf-8")
    request = Request(
        BNS_RPC_ENDPOINT,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def anvil_chain_id_ok() -> bool:
    try:
        response = json_rpc("eth_chainId")
        return int(response.get("result", "0"), 16) == int(BNS_CHAIN_ID)
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return False


def contract_deployed(contract: str) -> bool:
    if not contract:
        return False
    try:
        response = json_rpc("eth_getCode", [contract, "latest"])
        code = response.get("result", "")
        return isinstance(code, str) and code not in ("", "0x")
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return False


def load_deployed_contract(current_dir: Path) -> str | None:
    deployment_path = current_dir / BNS_DEPLOYMENT_FILE
    if deployment_path.exists():
        try:
            deployed = json.loads(deployment_path.read_text()).get("deployedTo")
            if isinstance(deployed, str) and contract_deployed(deployed):
                return deployed
        except (OSError, json.JSONDecodeError):
            pass

    if contract_deployed(BNS_CONTRACT_ADDRESS):
        return BNS_CONTRACT_ADDRESS

    return None


def ensure_bns_contract(current_dir: Path) -> str:
    if not anvil_chain_id_ok():
        raise RuntimeError(
            f"BNS anvil RPC is not healthy at {BNS_RPC_ENDPOINT}; run init_anvil.py first"
        )

    contract = load_deployed_contract(current_dir)
    if contract is not None:
        return contract

    raise RuntimeError(
        "BNS contract is not deployed or has no code on the current chain; "
        "run init_anvil.py first"
    )


def start_bns_server(current_dir: Path, contract: str) -> subprocess.Popen:
    cmd = [
        str(current_dir / "bns_dv"),
        "serve",
        "--rpc",
        BNS_RPC_ENDPOINT,
        "--contract",
        contract,
        "--chain-id",
        BNS_CHAIN_ID,
        "--db",
        str(current_dir / BNS_INDEXER_DB),
        "--listen",
        BNS_LISTEN,
        "--start-block",
        BNS_START_BLOCK,
        "--confirmations",
        BNS_CONFIRMATIONS,
        "--interval-ms",
        BNS_INTERVAL_MS,
    ]
    # 部署目录带 BNS 种子（make_sn_config.ts --seed-v2 产物）时交给 bns_dv
    # 幂等重放（if_exists=apply_mutations），把种子用户的权威文档上链。
    seed_config = current_dir / BNS_SEED_CONFIG_FILE
    if seed_config.exists():
        cmd += ["--seed-config", str(seed_config)]
    process = subprocess.Popen(cmd, cwd=current_dir)
    children.append(process)
    try:
        wait_for_bns_server(process)
        return process
    except Exception:
        if process in children:
            children.remove(process)
        terminate_process(process)
        raise


def wait_for_bns_server(process: subprocess.Popen) -> None:
    health_url = f"{BNS_SERVER_URL}/health"
    deadline = time.monotonic() + BNS_HEALTH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"bns_dv exited during startup with code {process.returncode}")
        try:
            with urlopen(health_url, timeout=2) as response:
                if response.status == 200 and response.read().decode("utf-8").strip() == "ok":
                    return
        except (URLError, OSError):
            pass
        time.sleep(BNS_HEALTH_INTERVAL_SECONDS)
    raise RuntimeError(f"bns_dv did not become healthy at {health_url}")


def main() -> int:
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    args = sys.argv[1:]

    current_dir = Path(__file__).resolve().parent
    install_machine_config(current_dir)
    install_dev_ca(current_dir)
    contract = ensure_bns_contract(current_dir)
    bns_process = start_bns_server(current_dir, contract)
    config_file = current_dir / "web3_gateway.yaml"
    cmd = [str(current_dir / "web3_gateway"), "--config_file", str(config_file)]
    if "debug" in args:
        cmd.append("--debug")

    try:
        for attempt in range(MAX_START_ATTEMPTS):
            if bns_process.poll() is not None:
                return bns_process.returncode or 1
            started_at = time.monotonic()
            returncode = run_child(cmd, current_dir)
            elapsed = time.monotonic() - started_at
            if "debug" in args or elapsed >= STARTUP_STABLE_SECONDS:
                return returncode
            if attempt == MAX_START_ATTEMPTS - 1:
                return returncode
            time.sleep(RETRY_DELAY_SECONDS)
    finally:
        terminate_all_children()

    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as err:
        print(f"start.py error: {err}", file=sys.stderr)
        terminate_all_children()
        raise SystemExit(1)
