# Stratum V2 example: bitcoin-rs as the mining owner behind the SRI stack

This example runs bitcoin-rs (regtest) together with the pinned Stratum
Reference Implementation (SRI) pool, translator and CPU mining devices, with a
thin template-distribution bridge in between. It exists to prove
[gosuda/bitcoin-rs#1289](https://github.com/gosuda/bitcoin-rs/issues/1289):
**an unmodified, pinned SRI mining stack can use bitcoin-rs as its Bitcoin
node / template source through a documented adapter**, while bitcoin-rs keeps
mining ownership (transaction selection, fees, coinbase and
witness-commitment rules, candidate validation, block submission) and no SRI
dependency lands anywhere below `examples/`.

> **Noise key pinning:** the pool config pins the bridge's Noise public key
> (`config/pool.toml`, `public_key = "9bWTZifgp9aVa23vtHqGT74UwK9bDRQxm77jf3u2tZ3ysM2ncMW"`).
> It is derived from the fixed example key in
> `template-provider/src/main.rs` (`EXAMPLE_PRIVATE_KEY_HEX`, overridable via
> `TP_PRIVATE_KEY_HEX`). If you override the key, update the pool config with
> the value the template-provider logs at startup, then `docker compose up -d pool`.
> Until the pin matches, the pool refuses the connection by design — the pin
> is the security feature.

## Architecture

```text
device-direct-1 (SV2)   device-direct-2 (SV2)      host SV1 miner (optional, unpinned)
        | SV2                    | SV2                        | SV1
        +------------------------+------------+               v
                                             |      translator (stratumv2/translator_sv2:v0.8.0)
                                             |               | SV2
                                             v               v
                                    pool (stratumv2/pool_sv2:v0.8.0)
                                             | templates / solutions (Noise, pinned TP pubkey)
                                             v
                    template-provider bridge (this repo: ./template-provider)
                                             | JSON-RPC: getblocktemplate (long-poll) / submitblock
                                             v
                              bitcoin-rs mining owner (regtest)
                                             |
                                             v
                                    Bitcoin network (regtest)
```

The default `docker compose up` set exercises the two direct SV2 devices
(two simultaneous channels). The translator is always on but idle until an
SV1 miner connects — see [Optional SV1 leg](#optional-sv1-leg-unpinned).

## Pinned revisions

| Component          | Revision                                                        | Source                                             |
|--------------------|-----------------------------------------------------------------|----------------------------------------------------|
| bitcoin-rs         | this PR's HEAD (branch `example/stratum-sv2`, base `origin/main` `f24b0096`) | built from the repo-root `Dockerfile` by compose |
| sv2-apps           | tag `v0.8.0` = commit `7f49074357e54da4f5b13acfcc29dc3cbb9e541f` (verified at build time) | device clone; pool/translator images |
| pool image         | `stratumv2/pool_sv2:v0.8.0`                                     | upstream image, config in `config/pool.toml`       |
| translator image   | `stratumv2/translator_sv2:v0.8.0`                               | upstream image, config in `config/translator.toml` |
| mining device      | `mining_device` built from sv2-apps `v0.8.0` (`cargo build --locked --release --bin mining_device` in `integration-tests/`) | `device/Dockerfile` |
| bridge Rust deps   | `stratum-apps = "0.8.0"` (pulls `stratum-core 0.6.0`)           | `template-provider/Cargo.toml`                     |

## Prerequisites

- Docker with Compose v2 (`docker compose version`).
- ~4 GB disk for images + regtest chainstate (trivial: regtest stays near-empty).

## Run

```console
$ cd examples/stratum-sv2
$ docker compose build            # bitcoin-rs node, bridge, two devices
$ docker compose up -d
$ docker compose logs -f template-provider pool device-direct-1
```

Bootstrap order is `bitcoin-rs` (healthcheck: JSON-RPC `getblockchaininfo`)
→ `template-provider` → `pool` → devices. The template-provider's Noise
**public key** is fixed at build time; read it from the bridge's startup log
or from `template-provider/src/main.rs`:

```console
$ docker compose logs template-provider | grep -i key
$EDITOR config/pool.toml          # paste it as template_provider_type.Sv2Tp.public_key
$ docker compose up -d pool       # pool starts and connects
```

Within ~a minute the devices open channels, receive jobs and produce shares;
on regtest (difficulty floor 1) a solved block follows quickly. Device
`--cores 32 --handicap 0` is tuned for an ~80-thread host — scale `--cores`
to your machine so a share lands within seconds.

## How to read the evidence

| Claim                              | Observation                                                                                                                                            |
|------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| Two channels opened                | `curl -s http://127.0.0.1:9090` (pool monitoring, one channel per device) or `docker compose logs pool \| grep -i channel`                               |
| Shares accepted                    | `docker compose logs pool \| grep -i share` (accepts / batch acks); device logs show shares sent                                                        |
| Block accepted                     | `docker compose logs template-provider` logs the solution and the `submitblock` result; bitcoin-rs log shows the accepted block                          |
| Tip advanced                       | `curl -s -u bitcoin-rs:bitcoin-rs -H 'content-type: text/plain' --data-binary '{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/` → `blocks` grows |
| New job after tip change           | template-provider logs a new template id + `SetNewPrevHash` right after the tip advances; pool/devices pick up the new job                                |

## Payout destination and coinbase ownership

- The pool pays `coinbase_tx_value_remaining` (subsidy + fees from the
  bitcoin-rs template) to its `coinbase_reward_script`:
  `addr(bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080)`
  (regtest P2TR, bech32m) — set in `config/pool.toml`.
- bitcoin-rs's mining owner owns the coinbase/witness-commitment rules and
  the bridge mirrors them: `coinbase_prefix` is the BIP34 height push only,
  version/sequence/locktime follow bitcoin-rs's coinbase construction, and
  `coinbase_tx_outputs` carries **only the witness-commitment output**
  (value 0, from the GBT `default_witness_commitment`) when the template has
  one — zero outputs otherwise. The pool's reward output is therefore the
  only value-carrying coinbase output; the pool appends its signature and
  extranonce to the scriptSig, which the bridge's solution check ignores.

## Optional SV1 leg (unpinned)

SRI v0.8.0 ships no SV1 miner, so this leg cannot be pinned with SRI-only
components and is **not exercised** by the default setup. The translator is
running and publishes SV1 on `127.0.0.1:3333`; point any Stratum V1 miner
(e.g. a host-run `cgminer`/BMSB-compatible client) at it to add a third leg
(one aggregated upstream channel via `aggregate_channels = true`). Treat any
result from this leg as anecdotal until pinned and verified.

## Configuration mechanism (why mounted TOML)

The upstream images are built to take an optional TOML from the binary's
`-c/--config` **default path** (`pool-config.toml` / `translator-config.toml`
relative to the image workdir `/app`), with `POOL__*` / `TPROXY__*` env vars
as an override layer (see upstream `docker/docker_env.example`:
"Every app is configured entirely from the environment — there are no
mounted config files" refers to their compose shipping no file; the loader
accepts either, env-only is unit-tested in `pool-apps/pool/src/args.rs`).
We mount `config/pool.toml` and `config/translator.toml` read-only at those
default paths, so the stock entrypoint (`exec /app/${APP}`) picks them up
with no env vars needed.

## Explicit non-claims

- **No ASIC or commercial-miner guarantee.** The only miners exercised are
  SRI's own CPU `mining_device`; no real SV2 ASIC or SV1 farm was tested.
- **Example-only keys.** The pool/translator authority keypair is the SRI
  reference example keypair (public in upstream examples); the bridge Noise
  key is a fixed example key; the payout address is a fixed regtest address.
  Do not reuse any of them outside regtest.
- **Regtest-only evidence.** Nothing here claims mainnet/testnet viability.
- **Not a pool product.** No balances, PPS/PPLNS accounting, withdrawals or
  wallet — the pool just pays each accepted block on-chain.
- **Not a consensus oracle.** SRI consumes bitcoin-rs templates; bitcoin-rs
  remains authoritative for transaction selection and candidate validation.

## Evidence (from verification run, 2026-09-30, this tree)

- [x] `docker compose config` validates.
- [x] `bitcoin-rs` healthy on regtest; `getblockchaininfo` reachable on
      127.0.0.1:18443 (`{"chain":"regtest"}`).
- [x] template-provider bridge connected by the pool (Noise handshake with
      pinned public key): pool log `Noise handshake completed successfully`,
      bridge log `pool setup connection completed`.
- [x] Two simultaneous channels exercised: pool monitoring API
      (`127.0.0.1:9090/api/v1/clients`) reports two Sv2 mining clients, each
      with one standard channel (plus the idle translator client), and the
      pool log records `OpenStandardMiningChannel` for both
      `...worker1` and `...worker2` from distinct container IPs.
- [x] Shares accepted from both devices (SRI `mining_device` real SHA256d:
      `Found share ...` / `Received SubmitSharesSuccess` on both devices).
- [x] Block candidates produced through the Stratum path and accepted by
      bitcoin-rs via `submitblock`: bridge log
      `block accepted by bitcoin-rs via submitblock template_id=13
      block_hash=0000000c940acca0...`, 60+ blocks accepted, zero rejects
      after the fix below.
- [x] Tip advanced: `getblockchaininfo.blocks` climbed past 60 during the
      run (regtest difficulty floor; two 32-core devices ≈ one block every
      few seconds).
- [x] New template/job issued after each tip change: bridge long-poll
      returns on every tip change and re-issues
      `issued template template_id=N+1 height=N+1 longpoll=<new tip hash>`,
      the pool activates the new job, and devices log
      `Received new mining job ... job id: 35` immediately after
      `Received SetNewPrevHash`.
- [x] Payout destination honored: the accepted coinbase carries the pool's
      reward output `0014 751e76e8199196d454941c45d1b3a323f1433bd6`
      (= `bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080`, the `coinbase_reward_script`)
      funded with `coinbase_tx_value_remaining`, plus bitcoin-rs's
      witness-commitment output `6a24aa21a9ed e2f61c3f...` (value 0) —
      bitcoin-rs's mining owner kept coinbase/commitment ownership end to end.

### Debugging notes (kept honestly)

Two integration bugs were found and fixed during verification, both in the
bridge, both invisible until a real pool talked to it:

1. The SRI pool's bootstrap gate only records templates flagged
   `future_template`, so the bridge must send `future_template: true` and let
   the paired `SetNewPrevHash` activate the job (the upstream Core adapter's
   idle behavior).
2. SV2 `coinbase_tx_outputs` is a serialized-`TxOut` list: the commitment
   script must be wrapped as `TxOut { value: 0, script }` (8 zero bytes +
   compactsize + script), not sent as a bare script. The unit tests pin both
   behaviors.
