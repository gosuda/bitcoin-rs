# Stratum V2 example: bitcoin-rs as the mining owner behind the SRI stack

This example runs bitcoin-rs (regtest) with its native SV2 Template
Distribution Protocol server enabled. An SRI pool connects directly to
bitcoin-rs via SV2 — no external bridge container.

## Architecture

```text
miner-1 (SV2)    miner-2 (SV2)
    | SV2             | SV2
    +---------+-------+
              v
       pool (SRI upstream)
              | SV2 TDP (Noise)
              v
  bitcoin-rs native SV2 TP (crates/mining/src/sv2/)
              | MiningControl
              v
       bitcoin-rs regtest node
```

## Run

```console
cd examples/stratum-sv2
docker compose up -d
docker compose logs -f miner-1 pool
```

bitcoin-rs starts first (healthcheck: `getblockchaininfo`). The SRI pool
connects to bitcoin-rs's SV2 endpoint via Noise. Devices open channels
and mine.

## Pinned images

| Component | Image |
|-----------|-------|
| bitcoin-rs | built from repo-root `Dockerfile` with `FEATURES=fjall,kernel,sv2` |
| pool | `stratumv2/pool_sv2:v0.8.0` |
| miners | SRI upstream mining device |

## Verify

```console
# Check blocks are being produced
docker compose logs pool | grep -i "block found"

# Check tip is advancing
curl -s -u bitcoin-rs:bitcoin-rs \
  -H 'content-type: text/plain' \
  --data-binary '{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:18443/
```

## Non-claims

- Example-only keys and regtest payout address. Do not reuse outside regtest.
- No ASIC or commercial-miner guarantee. Only CPU `mining_device` exercised.
- Not a pool product. No balances, accounting, or wallet.
- bitcoin-rs remains authoritative for transaction selection and validation.
