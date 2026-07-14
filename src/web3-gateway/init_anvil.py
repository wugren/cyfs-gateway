#!/usr/bin/env -S uv run

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ANVIL_HEALTH_TIMEOUT_SECONDS = 30
CONTRACT_DEPLOY_TIMEOUT_SECONDS = 30
POLL_INTERVAL_SECONDS = 0.5

BNS_RPC_ENDPOINT = os.environ.get("BNS_RPC_ENDPOINT", "http://127.0.0.1:8545")
BNS_CHAIN_ID = os.environ.get("BNS_CHAIN_ID", "31337")
BNS_DEPLOYMENT_FILE = os.environ.get("BNS_DEPLOYMENT_FILE", "bns-deployment.json")
BNS_CONTRACT_ADDRESS = os.environ.get(
    "BNS_CONTRACT_ADDRESS", "0x8464135c8F25Da09e49BC8782676a84730C318bC"
)
BNS_DEPLOYER_PRIVATE_KEY = os.environ.get(
    "BNS_DEPLOYER_PRIVATE_KEY",
    # anvil account[9], kept separate from bns_dv account[0] and seed users.
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
)
BNS_SERVER_URL = os.environ.get("BNS_SERVER_URL", "http://127.0.0.1:18080")
BNS_SERVER_RPC_PATH = os.environ.get("BNS_SERVER_RPC_PATH", "/kapi/bns")

ANVIL_STATE_FILE = os.environ.get("ANVIL_STATE_FILE", "anvil-state.json")
ANVIL_PID_FILE = os.environ.get("ANVIL_PID_FILE", "anvil.pid")
ANVIL_LOG_FILE = os.environ.get("ANVIL_LOG_FILE", "anvil.log")
ANVIL_MNEMONIC = os.environ.get(
    "ANVIL_MNEMONIC", "test test test test test test test test test test test junk"
)
ANVIL_BLOCK_TIME = os.environ.get("ANVIL_BLOCK_TIME")

INDEXER_DB_FILES = [
    "bns_indexer.sqlite",
    "bns_indexer.sqlite-wal",
    "bns_indexer.sqlite-shm",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize the local Anvil chain and deploy the BNS contract."
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="stop the managed anvil process and remove local chain/deployment/indexer state",
    )
    parser.add_argument(
        "--force-deploy",
        action="store_true",
        help="deploy a new BNS contract even if the current deployment is healthy",
    )
    parser.add_argument(
        "--no-deploy",
        action="store_true",
        help="only start/check anvil; do not deploy BNS",
    )
    parser.add_argument(
        "--install-foundry",
        action="store_true",
        help="install Foundry in this VM before starting anvil/deploying BNS",
    )
    parser.add_argument(
        "--configure-sn-bns-proxy",
        action="store_true",
        help="write the deployed BNS runtime values into params.json for cyfs-sn",
    )
    return parser.parse_args()


def candidate_names(command: str) -> list[str]:
    if os.name == "nt":
        return [f"{command}.exe", f"{command}.cmd", f"{command}.bat", command]
    return [command]


def find_executable(current_dir: Path, name: str) -> str | None:
    env_name = f"{name.upper()}_BIN"
    configured = os.environ.get(env_name)
    if configured:
        path = Path(configured)
        if path.exists() and os.access(path, os.X_OK):
            return str(path)

    search_dirs = [
        current_dir,
        current_dir / "foundry",
        Path.home() / ".foundry" / "bin",
        Path("/home/ubuntu/.foundry/bin"),
        Path("/root/.foundry/bin"),
        Path("/usr/local/bin"),
        Path("/usr/bin"),
    ]
    for directory in search_dirs:
        for candidate_name in candidate_names(name):
            candidate = directory / candidate_name
            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)

    return shutil.which(name)


def rpc_endpoint_parts() -> tuple[str, int]:
    parsed = urlparse(BNS_RPC_ENDPOINT)
    return (
        os.environ.get("ANVIL_HOST", parsed.hostname or "127.0.0.1"),
        int(os.environ.get("ANVIL_PORT", parsed.port or 8545)),
    )


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


def process_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def stop_managed_anvil(current_dir: Path) -> None:
    pid_path = current_dir / ANVIL_PID_FILE
    if not pid_path.exists():
        return
    try:
        pid = int(pid_path.read_text().strip())
    except (OSError, ValueError):
        pid_path.unlink(missing_ok=True)
        return

    if process_is_running(pid):
        print(f"Stopping managed anvil pid={pid}")
        os.kill(pid, 15)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not process_is_running(pid):
                break
            time.sleep(0.2)
        if process_is_running(pid):
            os.kill(pid, 9)
    pid_path.unlink(missing_ok=True)


def clear_state(current_dir: Path) -> None:
    for name in [ANVIL_STATE_FILE, BNS_DEPLOYMENT_FILE, "dv-env.json", *INDEXER_DB_FILES]:
        path = current_dir / name
        if path.exists():
            path.unlink()
            print(f"Removed {path}")


def wait_for_anvil(process: subprocess.Popen | None = None) -> None:
    deadline = time.monotonic() + ANVIL_HEALTH_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"anvil exited during startup with code {process.returncode}")
        if anvil_chain_id_ok():
            return
        time.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"anvil did not become healthy at {BNS_RPC_ENDPOINT}")


def start_or_reuse_anvil(current_dir: Path) -> None:
    if anvil_chain_id_ok():
        print(f"Reusing running anvil at {BNS_RPC_ENDPOINT}")
        return

    anvil = find_executable(current_dir, "anvil")
    if anvil is None:
        raise RuntimeError(
            "anvil is not running and no anvil executable was found. "
            "Install Foundry in the VM or place anvil in /opt/web3-gateway."
        )

    anvil_host, anvil_port = rpc_endpoint_parts()
    cmd = [
        anvil,
        "--host",
        anvil_host,
        "--port",
        str(anvil_port),
        "--chain-id",
        BNS_CHAIN_ID,
        "--mnemonic",
        ANVIL_MNEMONIC,
        "--disable-code-size-limit",
        "--state",
        str(current_dir / ANVIL_STATE_FILE),
    ]
    if ANVIL_BLOCK_TIME:
        cmd += ["--block-time", ANVIL_BLOCK_TIME]

    log_path = current_dir / ANVIL_LOG_FILE
    log = log_path.open("ab")
    print(f"Starting anvil: {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        cwd=current_dir,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
    )
    log.close()
    (current_dir / ANVIL_PID_FILE).write_text(f"{process.pid}\n")
    try:
        wait_for_anvil(process)
    except Exception:
        if process.poll() is None:
            process.terminate()
        raise
    print(f"Anvil ready at {BNS_RPC_ENDPOINT}, pid={process.pid}, log={log_path}")


def parse_forge_create_output(output: str) -> dict:
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        start = output.find("{")
        end = output.rfind("}")
        if start >= 0 and end > start:
            return json.loads(output[start : end + 1])
        raise


def find_bns_project_dir(current_dir: Path) -> Path | None:
    candidates = []
    if os.environ.get("BNS_PROJECT_DIR"):
        candidates.append(Path(os.environ["BNS_PROJECT_DIR"]))
    candidates += [
        current_dir / "bns",
        current_dir / "apps" / "bns",
        current_dir.parent / "apps" / "bns",
        current_dir.parent / "src" / "apps" / "bns",
    ]
    for candidate in candidates:
        if (candidate / "foundry.toml").exists() and (candidate / "src" / "Bns.sol").exists():
            return candidate
    return None


def load_current_deployment(current_dir: Path) -> str | None:
    deployment_path = current_dir / BNS_DEPLOYMENT_FILE
    if deployment_path.exists():
        try:
            deployed = json.loads(deployment_path.read_text()).get("deployedTo")
            if isinstance(deployed, str) and contract_deployed(deployed):
                print(f"Reusing deployed BNS contract {deployed}")
                return deployed
        except (OSError, json.JSONDecodeError):
            pass

    if contract_deployed(BNS_CONTRACT_ADDRESS):
        print(f"Reusing default BNS contract {BNS_CONTRACT_ADDRESS}")
        write_deployment(current_dir, {"deployedTo": BNS_CONTRACT_ADDRESS})
        return BNS_CONTRACT_ADDRESS

    return None


def run_checked(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\n"
            f"cwd: {cwd}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def run_checked_shell(command: str, cwd: Path) -> None:
    result = subprocess.run(
        command,
        cwd=cwd,
        shell=True,
        executable="/bin/bash",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed: {command}\n"
            f"cwd: {cwd}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )


def install_foundry(current_dir: Path) -> None:
    if find_executable(current_dir, "anvil") and find_executable(current_dir, "forge"):
        print("Foundry already available")
        return

    if find_executable(current_dir, "curl") is None:
        raise RuntimeError("cannot install Foundry: curl is not available")

    print("Installing Foundry")
    run_checked_shell("curl -L https://foundry.paradigm.xyz | bash", current_dir)
    foundryup = find_executable(current_dir, "foundryup")
    if foundryup is None:
        raise RuntimeError("foundryup was not installed")
    run_checked([foundryup], current_dir)

    if not (find_executable(current_dir, "anvil") and find_executable(current_dir, "forge")):
        raise RuntimeError("Foundry install completed but anvil/forge are still unavailable")


def write_deployment(current_dir: Path, deployment: dict) -> None:
    deployment = {
        **deployment,
        "rpcEndpoint": BNS_RPC_ENDPOINT,
        "chainId": int(BNS_CHAIN_ID),
    }
    (current_dir / BNS_DEPLOYMENT_FILE).write_text(json.dumps(deployment, indent=2) + "\n")


def deploy_bns_contract(current_dir: Path) -> str:
    forge = find_executable(current_dir, "forge")
    bns_project_dir = find_bns_project_dir(current_dir)
    missing = []
    if forge is None:
        missing.append("forge")
    if bns_project_dir is None:
        missing.append("BNS Foundry project")
    if missing:
        raise RuntimeError(
            "cannot deploy BNS contract; missing "
            f"{', '.join(missing)}. Install Foundry and/or set BNS_PROJECT_DIR."
        )

    assert forge is not None
    assert bns_project_dir is not None
    print(f"Building BNS contract in {bns_project_dir}")
    run_checked([forge, "build"], bns_project_dir)

    cmd = [
        forge,
        "create",
        "src/Bns.sol:Bns",
        "--rpc-url",
        BNS_RPC_ENDPOINT,
        "--private-key",
        BNS_DEPLOYER_PRIVATE_KEY,
        "--broadcast",
        "--json",
    ]
    print("Deploying BNS contract")
    result = run_checked(cmd, bns_project_dir)
    deployment = parse_forge_create_output(result.stdout)
    contract = deployment.get("deployedTo")
    if not isinstance(contract, str) or not contract:
        raise RuntimeError(f"forge create output missing deployedTo: {result.stdout}")

    deadline = time.monotonic() + CONTRACT_DEPLOY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if contract_deployed(contract):
            write_deployment(current_dir, deployment)
            print(f"BNS contract deployed at {contract}")
            return contract
        time.sleep(POLL_INTERVAL_SECONDS)

    raise RuntimeError(f"BNS contract has no code after deployment: {contract}")


def ensure_bns_contract(current_dir: Path, force_deploy: bool) -> str:
    if not force_deploy:
        deployed = load_current_deployment(current_dir)
        if deployed is not None:
            return deployed
    return deploy_bns_contract(current_dir)


def write_dv_env(current_dir: Path, contract: str) -> None:
    data = {
        "rpc_endpoint": BNS_RPC_ENDPOINT,
        "chain_id": int(BNS_CHAIN_ID),
        "contract_address": contract,
        "server_url": BNS_SERVER_URL,
        "server_rpc_path": BNS_SERVER_RPC_PATH,
    }
    path = current_dir / "dv-env.json"
    path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Wrote {path}")


def configure_sn_bns_proxy(current_dir: Path, contract: str) -> None:
    params_path = current_dir / "params.json"
    if not params_path.is_file():
        raise RuntimeError(
            f"cannot configure SN BNS proxy: params.json not found at {params_path}"
        )
    try:
        document = json.loads(params_path.read_text())
    except json.JSONDecodeError as error:
        raise RuntimeError(f"cannot parse {params_path}: {error}") from error
    params = document.setdefault("params", {})
    if not isinstance(params, dict):
        raise RuntimeError(f"cannot configure SN BNS proxy: {params_path} params is not an object")
    params.update(
        {
            "bns_rpc_endpoint": BNS_RPC_ENDPOINT,
            "bns_chain_id": str(BNS_CHAIN_ID),
            "bns_contract_address": contract,
            "bns_server_url": BNS_SERVER_URL,
            "bns_rpc_url": BNS_SERVER_URL,
        }
    )
    temporary_path = params_path.with_suffix(".json.tmp")
    temporary_path.write_text(json.dumps(document, indent=2) + "\n")
    temporary_path.replace(params_path)

    gateway_path = current_dir / "web3_gateway.yaml"
    if not gateway_path.is_file():
        raise RuntimeError(
            f"cannot configure SN BNS proxy: gateway config not found at {gateway_path}"
        )
    print(f"Configured SN BNS RPC runtime value in {params_path}")


def main() -> int:
    args = parse_args()
    if args.force_deploy and args.no_deploy:
        print("--force-deploy and --no-deploy are mutually exclusive", file=sys.stderr)
        return 2

    current_dir = Path(__file__).resolve().parent
    if args.install_foundry:
        install_foundry(current_dir)

    if args.fresh:
        stop_managed_anvil(current_dir)
        clear_state(current_dir)
        if anvil_chain_id_ok():
            raise RuntimeError(
                f"{BNS_RPC_ENDPOINT} is still occupied by an external chain after --fresh"
            )

    start_or_reuse_anvil(current_dir)
    if args.no_deploy:
        print("Skipped BNS deployment (--no-deploy)")
        return 0

    contract = ensure_bns_contract(current_dir, args.force_deploy)
    write_dv_env(current_dir, contract)
    if args.configure_sn_bns_proxy:
        configure_sn_bns_proxy(current_dir, contract)
    print("\nAnvil/BNS environment is ready")
    print(f"  rpc:      {BNS_RPC_ENDPOINT}")
    print(f"  chain_id: {BNS_CHAIN_ID}")
    print(f"  contract: {contract}")
    print(f"  deploy:   {current_dir / BNS_DEPLOYMENT_FILE}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as err:
        print(f"init_anvil.py error: {err}", file=sys.stderr)
        raise SystemExit(1)
