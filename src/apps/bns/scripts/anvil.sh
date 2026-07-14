#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p var

ANVIL_ARGS=(
  --host "${ANVIL_HOST:-127.0.0.1}" \
  --port "${ANVIL_PORT:-8545}" \
  --chain-id "${ANVIL_CHAIN_ID:-31337}" \
  --mnemonic "${ANVIL_MNEMONIC:-test test test test test test test test test test test junk}" \
  --disable-code-size-limit \
  --state "${ANVIL_STATE:-var/anvil-state.json}"
)

if [ -n "${ANVIL_BLOCK_TIME:-}" ]; then
  ANVIL_ARGS+=(--block-time "$ANVIL_BLOCK_TIME")
fi

exec anvil "${ANVIL_ARGS[@]}"
