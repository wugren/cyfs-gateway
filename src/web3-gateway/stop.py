#!/usr/bin/env -S uv run

import subprocess


def run_stop_command(cmd: list[str]) -> int:
    result = subprocess.run(cmd)
    if result.returncode in (0, 1):
        return 0
    return result.returncode


if __name__ == "__main__":
    supervisor_result = run_stop_command(["pkill", "-f", "/opt/web3-gateway/start.py"])
    gateway_result = run_stop_command(["killall", "web3_gateway"])
    bns_result = run_stop_command(["killall", "bns_dv"])
    raise SystemExit(supervisor_result or gateway_result or bns_result)
