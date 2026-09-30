# Stratum V2 example: bitcoin-rs as the mining owner behind the SRI stack

This example runs bitcoin-rs (regtest) together with the SRI pool and CPU
mining devices. The SRI template-provider bridge connects to bitcoin-rs's
JSON-RPC interface (`getblocktemplate`/`submitblock`).

## Architecture

```text
miner-1 (SV2)          miner-2 (SV2)
    | SV2                   | SV2
    +-----------+-----------+
                |
                v
         pool (SRI upstream)
                | templates / solutions (Noise)
                v
    template-provider (SRI upstream)
                | JSON-RPC: getblocktemplate / submitblock
                v
         bitcoin-rs (regtest)
```

## Run

```console
cd examples/stratum-sv2
docker compose up -d
docker compose logs -f miner-1 pool
```

bitcoin-rs starts first (healthcheck: `getblockchaininfo`). The
template-provider connects to bitcoin-rs via RPC, then the pool connects
to the template-provider via Noise. Devices open channels and mine.

## Pinned images

| Component | Image |
|-----------|-------|
| bitcoin-rs | built from repo-root `Dockerfile` |
| pool | `stratumv2/pool_sv2:v0.8.0` |
| template-provider | SRI upstream template provider |
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
