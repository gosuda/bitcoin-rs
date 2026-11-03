# What works today

This page maps each surface to its honest state and to the file that owns the evidence. Read the state as a scoped claim, not as a compatibility verdict.

| Surface | State | Evidence owner |
| --- | --- | --- |
| Native consensus and script validation (default) | implemented, in-tree tested, kernel-free | [BIP support matrix](https://github.com/gosuda/bitcoin-rs/blob/main/docs/bip-support.md), [validation default contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/validation-default.md) |
| Optional `kernel` validation engine | implemented as an opt-in lane and engine, not default | [Getting started, validation engine](https://github.com/gosuda/bitcoin-rs/blob/main/docs/getting-started.md), [validation default contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/validation-default.md) |
| P2P v1 wire protocol | externally verified against unmodified Core 31.1 for the recorded outcomes | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml) |
| BIP324 v2 transport | externally verified in both directions; on by default (`--v2transport=false` opts out) | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml), [BIP support matrix](https://github.com/gosuda/bitcoin-rs/blob/main/docs/bip-support.md) |
| BIP152 compact block relay | externally verified for request and response; proactive announcements implemented, CORE-05 qualification pending | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml) |
| BIP157/BIP158 compact filters | externally verified with Kyoto on regtest; index is optional | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml) |
| JSON-RPC | implemented, in-tree only; no external RPC client run recorded | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml), [RPC reference](https://github.com/gosuda/bitcoin-rs/blob/main/docs/rpc-reference.md) |
| REST | implemented, in-tree only | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml) |
| ZeroMQ notifications | implemented, in-tree only | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml) |
| Esplora HTTP API | implemented, in-tree only | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml), [wallet-facing contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/wallet-facing.md) |
| GetBlockTemplate and `submitblock` | implemented, in-tree only; no external mining consumer recorded | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml), [BIP support matrix](https://github.com/gosuda/bitcoin-rs/blob/main/docs/bip-support.md) |
| Native mining pool | implemented behind the `pool` feature; opt-in; no external miner interoperability claimed | [Pool operation](https://github.com/gosuda/bitcoin-rs/blob/main/docs/pool.md), [pool contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md) |
| AssumeUTXO snapshot load, dump, and query | implemented; `loadtxoutset` and `dumptxoutset` carry Core `Deviation` status, `gettxoutsetinfo` is `Implemented (unverified)` | [RPC reference](https://github.com/gosuda/bitcoin-rs/blob/main/docs/rpc-reference.md), [external API contract `API-33`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md) |
| Pruning | implemented; in-tree recovery tests cover pruned history as unavailable, never empty | [recovery contract `RCV-07`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md), [crash recovery evidence lane](https://github.com/gosuda/bitcoin-rs/blob/main/docs/validation-tooling.md) |
| Transaction and script indexes | implemented; queries expose capability state instead of empty answers | [Indexing contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/indexing.md) |
| Silent Payments | experimental, default-off `silent-payments` feature | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml), [Silent Payments limits](https://github.com/gosuda/bitcoin-rs/blob/main/docs/silent-payments.md) |
| Compressed transactions | experimental, default-off `--compressed-transactions` extension | [BIP support matrix](https://github.com/gosuda/bitcoin-rs/blob/main/docs/bip-support.md) |
| Stratum V2 template adapter | experimental regtest example, not a compatibility commitment | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml) |
| USDT tracepoints | implemented ABI, asserted against built probe notes; live tracing run planned | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml), [tracing](https://github.com/gosuda/bitcoin-rs/blob/main/docs/tracing.md) |
| Bitcoin Core IPC interfaces | intentionally unsupported | [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml) |
| BIP330 Erlay | unsupported; recorded as deferred | [BIP adoption policy, applied decisions](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/bip-adoption.md) |
| Performance | page-specific status only: `planned_not_executed`, `measured` without acceptance verdict, `measured_rejected`, or `BLOCKED`; no accepted campaign is implied | [Benchmark evidence rules](https://github.com/gosuda/bitcoin-rs/blob/main/docs/benchmarks/README.md) |

## How to read the states

Implemented means the code is merged and in-tree tests or vectors exercise it. It does not mean an external program has used it.

Externally verified means an unmodified external consumer exercised the surface, and the run is recorded in [`ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml) with the scope that was checked. The claim covers only the outcomes named there.

Experimental means the feature is merged but default-off or pinned to a draft. Partial means a consumer can use it with recorded differences; the evidence row names the difference owner.

`BLOCKED` is not a pass and not a skip. It means a required identity, such as a binary digest, corpus, or hardware record, is missing. [Benchmark evidence rules](https://github.com/gosuda/bitcoin-rs/blob/main/docs/benchmarks/README.md) define the six identities every sample carries.

An in-tree harness, a copied reference vector, or a shape comparison never upgrades a row to externally verified. [Ecosystem compatibility contract `ECO-08`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/ecosystem-compatibility.md) owns that rule.

## Next

Run the node: [Install](run/install.md).
