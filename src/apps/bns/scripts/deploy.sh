#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${BNS_RPC_URL:=http://127.0.0.1:8545}"
: "${BNS_DEPLOYER_PRIVATE_KEY:?set BNS_DEPLOYER_PRIVATE_KEY}"

mkdir -p deployments

forge build

forge create src/Bns.sol:Bns \
  --rpc-url "$BNS_RPC_URL" \
  --private-key "$BNS_DEPLOYER_PRIVATE_KEY" \
  --broadcast \
  --json | tee deployments/anvil.local.json
