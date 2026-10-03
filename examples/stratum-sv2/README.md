# Stratum V2 example: bitcoin-rs as the mining owner behind the SRI stack

This example runs bitcoin-rs (regtest) together with the pinned Stratum
Reference Implementation (SRI) pool, translator and CPU mining devices, with a
thin template-distribution bridge in between. It exists to prove
[gosuda/bitcoin-rs#1289](https://github.com/gosuda/bitcoin-rs/issues/1289):
**an unmodified, pinned SRI mining stack can use bitcoin-rs as its Bitcoin
node / template source through a documented adapter**, while bitcoin-rs keeps
mining ownership (transaction selection, fees, coinbase and
witness-commitment rules, candidate validation, block submission) and no SRI
dependency lands anywhere outside `examples/` (the bridge's `stratum-apps`
dependency lives in `template-provider/`).

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
| bitcoin-rs         | this PR's HEAD                                                  | built from the repo-root `Dockerfile` by compose   |
| sv2-apps           | tag `v0.8.0` = commit `7f49074357e54da4f5b13acfcc29dc3cbb9e541f` (verified at build time) | device clone; pool/translator images |
| pool image         | `stratumv2/pool_sv2:v0.8.0@sha256:679e08ae5dd99bac01394b0c592c97f45982d0d9d24e03f460ccd1c2592d3a00` | upstream image, config in `config/pool.toml`       |
| translator image   | `stratumv2/translator_sv2:v0.8.0@sha256:a6b7380999fb6048caa269766afc64541880849cec6c34594e48133ca4d454ef` | upstream image, config in `config/translator.toml` |
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
→ `template-provider` → `pool` → devices. With the default example key
nothing needs editing: `config/pool.toml` already pins the build-time
`template_provider_type.Sv2Tp.public_key` the bridge logs at startup.

Only when `TP_PRIVATE_KEY_HEX` is overridden does the pin change: read the
new public key from the bridge's startup log, update the pool config, and
restart the pool:

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
| Two channels opened                | `curl -s http://127.0.0.1:9090/api/v1/clients` (pool monitoring, one channel per device) or `docker compose logs pool \| grep -i channel`                |
| Shares accepted                    | `docker compose logs pool \| grep -i share` (accepts / batch acks); device logs show shares sent                                                        |
| Block accepted                     | `docker compose logs template-provider` logs the solution and the `submitblock` result; bitcoin-rs log shows the accepted block                          |
| Tip advanced                       | `curl -s -u bitcoin-rs:bitcoin-rs -H 'content-type: text/plain' --data-binary '{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/` → `blocks` grows |
| New job after tip change           | template-provider logs a new template id + `SetNewPrevHash` right after the tip advances; pool/devices pick up the new job                                |

## Payout destination and coinbase ownership

- The pool pays `coinbase_tx_value_remaining` (subsidy + fees from the
  bitcoin-rs template) to its `coinbase_reward_script`:
  `addr(bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080)`
  (regtest P2WPKH, bech32) — set in `config/pool.toml`.
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

## Bridge configuration (environment)

The bridge is env-configured (regtest defaults shown):

| Variable               | Default                      | Purpose                              |
|------------------------|------------------------------|--------------------------------------|
| `TP_LISTEN`            | `0.0.0.0:8442`               | TDP listener the pool connects to    |
| `BITCOINRS_RPC_URL`    | `http://127.0.0.1:18443`     | bitcoin-rs JSON-RPC endpoint         |
| `BITCOINRS_RPC_USER`   | `bitcoin-rs`                 | RPC basic-auth user                  |
| `BITCOINRS_RPC_PASS`   | `bitcoin-rs`                 | RPC basic-auth password              |
| `TP_PRIVATE_KEY_HEX`   | fixed example key            | Noise secret key (64 hex chars)      |
| `TP_CERT_VALIDITY_SECS`| `3600`                       | Noise certificate lifetime           |

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

## Evidence (from verification run, this tree)

Recorded on this branch with the pinned components above (`docker compose up -d`):

- **Two simultaneous worker channels.** `GET http://127.0.0.1:9090/api/v1/clients` reported 3 clients: the two `mining_device`s with `standard_channels_count: 1` each (~32 MH/s each on an 8-CPU container) and the idle translator; the pool log shows `OpenStandardMiningChannel` for `…worker1` and `…worker2`.
- **Jobs flow to miners.** Both devices log `Received new mining job … is future: true` and `Received SetNewPrevHash` on every template refresh.
- **Shares validate.** Devices log `Found share …` → `Received SubmitSharesSuccess`; the pool logs `SubmitSharesStandard` acceptance.
- **Blocks accepted through the normal path.** For each found share the pool logs `💰 Block Found!!! … Propagating solution to the Template Provider`; the template-provider logs `block accepted by bitcoin-rs via submitblock` — the production `submitblock` RPC. Every `SubmitSolution` was accepted in the recorded run (15+ consecutive).
- **Tip advance → new job.** After each accepted block the provider long-poll returns, issues a new template id and pushes `NewTemplate` + `SetNewPrevHash` (`pushed template to pool`), and the devices receive the replacement job; `getblockchaininfo` showed `blocks` climbing past 15 during the run.

Representative log slice (template-provider):

```text
INFO issued template template_id=1 height=1 txs=0 value_remaining=5000000000
INFO pushed template to pool template_id=1
INFO block accepted by bitcoin-rs via submitblock template_id=1 \
     block_hash=0000000461737e004f46344d1813131756f1781effc93d43d99ae8bbbc5ac1f7
INFO issued template template_id=2 height=2 ...
INFO tip advanced tip_height=1
```

### Debugging notes (kept honestly)

Three integration boundary rules the unit tests and this run pin, found
during verification of this design:

1. The SRI pool's bootstrap gate only records templates flagged
   `future_template`, so the bridge sends `future_template: true` and lets
   the paired `SetNewPrevHash` activate the job (the upstream Core adapter's
   idle behavior).
2. SV2 `coinbase_tx_outputs` is a serialized-`TxOut` list: the commitment
   script must be wrapped as `TxOut { value: 0, script }` (8 zero bytes +
   compactsize + script), not sent as a bare script.
3. `watch::Sender::send` **silently drops the value while the channel has
   zero receivers** (every publish before the first pool connects). The hub
   uses `send_replace`, which stores unconditionally and still notifies —
   otherwise the initial template push is a no-op and the pool waits for
   its first template forever.
