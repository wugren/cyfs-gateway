# BNS Contracts

First EVM implementation of the BNS registry described in
`../../../doc/BNS/BNS 智能合约接口设计.md`.

## Layout

- `src/Bns.sol`: registry contract and protocol structs.
- `test/Bns.t.sol`: Solidity tests for authorization, guards, documents and events.
- `script/Smoke.s.sol`: deploys a fresh contract to a local chain and runs a minimal write flow.
- `scripts/anvil.sh`: starts a persistent local Anvil chain.
- `scripts/deploy.sh`: builds and deploys `Bns.sol` to an RPC endpoint.

## Local Chain

Install Foundry first if `forge`, `cast` and `anvil` are not on `PATH`:

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Run tests:

```bash
cd src/apps/bns
forge test
```

Start a private chain:

```bash
cd src/apps/bns
./scripts/anvil.sh
```

Deploy in another terminal:

```bash
cd src/apps/bns
BNS_RPC_URL=http://127.0.0.1:8545 \
BNS_DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
./scripts/deploy.sh
```

Run an on-chain smoke flow against Anvil:

```bash
cd src/apps/bns
BNS_RPC_URL=http://127.0.0.1:8545 \
BNS_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
forge script script/Smoke.s.sol:Smoke \
  --rpc-url "$BNS_RPC_URL" \
  --broadcast \
  --disable-code-size-limit
```

## DV Integration Environment (end-to-end)

See `doc/SN/SN-测试计划.md` §5. Two ways to exercise the full
`BNS(contract) <-> Indexer <-> Server <-> Client <-> Controller` path against a real
private chain (requires Foundry: `anvil`, `forge`, `cast`).

**(A) Self-contained Rust e2e** (recommended, CI-able). Spawns its own anvil + deploys
in-process; `#[ignore]` by default, skipped gracefully when Foundry is absent:

```bash
cd src
cargo test -p bns-client --test e2e_anvil -- --ignored
```

**(B) Scripted DV environment + smoke.** `dv-up.sh` brings up anvil, deploys `Bns.sol`,
and runs `bns-dv serve` (indexer `sync_once` poll loop + contract server over a shared
SQLite projection), then writes `dv-env.json`:

```bash
cd src/apps/bns
./scripts/dv-up.sh --fresh        # fresh chain + deploy + indexer/server (background)
./scripts/dv-smoke.sh             # register -> publish -> wait sync -> read (cross-layer)
./scripts/dv-down.sh              # stop services (anvil state persists for --resume)
./scripts/dv-up.sh --resume       # reuse anvil-state + contract + indexer cursor
./scripts/dv-smoke.sh             # cursor continues (no replay from 0)
./scripts/dv-down.sh --purge      # stop + remove persisted state
```

Use `dv-up.sh --keep-running` to run in the foreground for manual debugging.

## V1 Scope

Implemented:

- `registerName`, `applyMutations`, `renewName`, `transferName`, `setNameOwner`,
  `releaseName`, `setNamespacePolicy`
- `updateAuthorityKeys`, `setControllerPolicy`
- `publishDocument`, `revokeDocument`, `setDidAlias`, `setPaymentTarget`
- core query APIs from the interface design

Direct EVM calls keep `CallAuthority` in the ABI, but identity is not trusted from
that struct. The contract derives the concrete signer from `msg.sender` and checks it
against either the effective chain-account owner or a registered BNS authority key.
This is the intended signing boundary for the Anvil/private-chain V1.

The V1 contract intentionally keeps the full closed-loop interface in one contract, so
its bytecode is above the public-chain EIP-170 size limit. The Anvil script disables
that limit for the private-chain workflow. Before a public-chain deployment, split the
contract into facets/modules or move read-heavy helpers out of the write contract.
