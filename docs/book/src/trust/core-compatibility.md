# Compatibility with Bitcoin Core

bitcoin-rs claims compatibility one surface at a time. Consensus validity, the RPC and REST surface, the peer handshake, and mempool policy each have a pinned reference, a named evidence lane, and a limit. A claim on one surface does not carry to another.

## What a compatibility claim contains

A claim names three things: the reference identity, the evidence type, and the scope it covers. The released reference is Bitcoin Core 31.1. The file [`crates/rpc/core-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/rpc/core-compat.toml) pins its `bitcoind -version` line and artifact SHA-256. The development kernel oracle is a different identity in the same file and is never treated as the release.

Two evidence axes exist. In-tree differential evidence compares native code with Core vectors, `libbitcoinkernel`, or a pinned Core process. External evidence means an unmodified program used the public P2P, RPC, REST, or ZMQ surface, and the matrix records the run in [`docs/api/ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml). Contracts own the rules: [`CORE-01` to `CORE-07`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/core-differential.md) for live Core comparison and [`ECO-08`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/ecosystem-compatibility.md) for the external matrix.

A registry status is a shape claim about an API row. It is not verification.

## Consensus

### The live Core lane

The live lane starts a pinned Core 31.1 artifact and a bitcoin-rs node on regtest. `scripts/install-bitcoind.sh` checks the platform SHA-256 before it extracts the binary. `scripts/run-p2p-core-interop.sh` then runs the comparison and writes an evidence document.

`CORE-02` requires agreement on `getblockcount`, `getbestblockhash`, and `getblockchaininfo.{chain,blocks}` after bitcoin-rs catches up over P2P. `CORE-03` checks BIP152 compact-block relay against Core. That check covers a three-transaction `getblocktxn` recovery, a 130-transaction fallback to a full block, and the serving side through a raw scripted peer. `CORE-04` sends the same serialized blocks and transactions to both nodes through `submitblock` and `testmempoolaccept` and fails on any accept/reject disagreement. The harness keeps reject-reason strings without asserting equality.

Three limits matter. `CORE-05` (proactive announcements across a reorg) and `CORE-06` (BIP324 in both directions) are main-only qualification lanes, so ordinary pull-request CI does not execute them. `CORE-07` runs Core's functional suite through an adapter and needs a local Core checkout, so CI does not run it either. `CORE-04` is a bounded curated suite; coverage-guided live Core fuzzing and broader rule-family coverage remain follow-up work under issue #1323.

### The kernel oracle

The default validation engine is the native Rust interpreter. The optional `kernel` feature compiles Bitcoin Core's C++ consensus engine, and `validation.engine = "kernel"` routes input-script verification through it. `native` remains the default in every build, including builds that contain the kernel.

Three in-tree tests exercise the kernel path. `kernel_vector_parity` checks the kernel against Core script vectors, excluding `BADTX` rows that fail before script verification. `kernel_block_parity` compares kernel and native accept/reject on six mainnet fixtures: legacy P2PK, P2PKH, P2SH, SegWit v0, Taproot key path, and Taproot script path. `kernel_boundary_parity` compares native and kernel on synthetic consensus limits such as a 10,000-byte script, 201 operations, a 520-byte push, a 1,000-deep stack, and Taproot control-block shapes.

The block and boundary tests compare kernel and native verdicts on those fixtures and limits. The vector test checks the kernel against Core vectors. They do not prove parity over all inputs.

### The two decoder divergences we report

Two disagreements with `rust-bitcoin`'s transaction decoder are known. The differential fuzz target allows exactly these two and panics on every other disagreement. Neither verdict changes.

A transaction with zero inputs and a zero flag byte is accepted by the native decoder and rejected by `rust-bitcoin`. The parser reads the four-byte version, an input count of zero, and the next byte. A zero next byte means the transaction is not SegWit and has zero outputs, so the transaction decodes with no inputs and no outputs. The fuzz target excuses this case only when the parsed transaction has no inputs and bytes 4 and 5 of the serialized transaction are both zero.

A BIP144 marker and flag whose witness section is empty for every input is rejected by the native decoder and accepted by `rust-bitcoin`. After parsing all witness stacks, the layout code returns `DecodeError::SuperfluousWitness` before it reads the lock time. [`QAC-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/qa-corpus.md) records `superfluous_witness` as the documented exception class for corpus verdicts.

Both arms are visible in [`fuzz/fuzz_targets/tx_differential.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/fuzz/fuzz_targets/tx_differential.rs). When both decoders accept, the target compares txid, wtxid, weight, and re-encoded bytes. When both reject, it says nothing. A disagreement outside the two arms fails the target.

### What the consensus evidence does not prove

Consensus evidence does not prove equivalence over the full script or transaction space. The Core vector suites pin runnable rows and enumerate skip reasons; they do not execute every row. The kernel oracle covers named fixtures and synthetic boundaries. The live lanes compare named observable outcomes on regtest. They do not replay mainnet or prove a performance property.

Read [`VAL-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/validation-default.md) for the native interpreter's proof boundary and the generated [evidence index](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/evidence-index.md) for which clauses have a tagged artifact.

## RPC and REST surface

The API surface makes no differentially verified Core method claim at this commit. Read a row's status as the claim it is, not as external proof.

[`REGISTRY`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/rpc/src/registry.rs) owns one status per surface: `Supported`, `Deviation`, `Implemented (unverified)`, `Extension`, `Disabled`, or `Unimplemented`. The generated [`docs/rpc-reference.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/rpc-reference.md) renders that table. `Supported` requires `reference.differential_harness = true` in `crates/rpc/core-compat.toml`. The flag is `false` at this commit, so the reference contains no `Supported` row.

External evidence is a separate axis. In [`docs/api/ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml), JSON-RPC, REST, ZMQ, and Esplora are `implemented`, which means in-tree tests only. The externally verified rows are P2P surfaces, not the application APIs. `crates/rpc/core-compat.toml` pins the Core identity; the registry states the API shape; the ecosystem matrix records which real consumers ran. None substitutes for another.

The chapters [RPC](../use/rpc.md) and [REST and Esplora](../use/rest-esplora.md) describe the surface. They do not upgrade its status.

## Peer handshake

The handshake has the same shape as Core's and rejects more cases. [`docs/policies/p2p-compatibility.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md) owns the wire policy.

bitcoin-rs advertises protocol version `70017` and a `user_agent` of `/bitcoin-rs:<version>/`. Core 31.1 advertises `70016`. The higher number is the BIP434 negotiation threshold; Core 31.1 does not support BIP434. The `version.timestamp` field is always `0`, which is a recorded deviation.

The stricter cases are deliberate. The node disconnects the peer and temporarily avoids its IP on a duplicate `verack` or `version`, on a `sendheaders`, `sendaddrv2`, `sendcmpct` or `wtxidrelay` before `version`, or on any other message before readiness. Core ignores some of those pre-version messages and a duplicate `verack`. The node also disconnects and avoids the IP on a version-1 checksum failure; Core rejects the message and resets its decoder. The policy documents these rules. It does not relax them for Core parity.

Two Core commands are absent by policy. The node decodes `getblocks` and `mempool` and ignores them; Core answers them with an `inv`. BIP330 `sendtxrcncl` stays untyped: a ready peer ignores it like any unknown command, and the node disconnects a peer that sends it before readiness. Core whitelists that command during the handshake, so the affected topology is a Core peer dialing bitcoin-rs with `-txreconciliation=1`.

BIP324 v2 transport is on by default in the node. `--v2transport=false` keeps every connection on v1. The embedder default is different: `P2pServiceConfig::default()` sets `v2_transport: false`, and an embedder must enable it. See [`crates/p2p/src/service.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/p2p/src/service.rs).

## Mempool policy

The mempool policy records these differences under `POL-01` to `POL-07` in [`docs/policies/mempool-policy.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/mempool-policy.md). Replacement does not depend on BIP125 signaling. The incremental relay fee is 1,000 sat/kvB, while pinned Core 31.1 uses 100. The node measures capacity as dynamic memory usage, not virtual size. The mempool keeps cluster order exact at each mutation instead of Core's bounded linearization. The node claims no default or throughput equivalence from these choices.

## Where we differ

Each row is a verified difference with a named owner. The linked owners remain the authority.

| Surface | bitcoin-rs | Reference |
| :--- | :--- | :--- |
| Transaction decoder, zero inputs | Accepts version, input count 0, flag 0, lock time | `rust-bitcoin` rejects a zero-input transaction ([fuzz target](https://github.com/gosuda/bitcoin-rs/blob/main/fuzz/fuzz_targets/tx_differential.rs)) |
| Transaction decoder, empty witness section | Rejects with `superfluous_witness` | `rust-bitcoin` accepts ([QAC-05](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/qa-corpus.md)) |
| P2P protocol version | `70017` | Core 31.1 advertises `70016` ([policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md)) |
| Handshake rejection | Disconnect and temporarily avoid IP on duplicate handshake messages, pre-version negotiation messages, and checksum failure | Core ignores some of these and resets its v1 decoder on a checksum error ([policy §6](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md)) |
| `getblocks` and `mempool` | Ignored | Core answers with an `inv` ([policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md)) |
| BIP330 `sendtxrcncl` | Untyped; ignored when ready, disconnect before readiness | Core whitelists it during the handshake ([policy §7](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md)) |
| Block download window | 256 in flight and 256 staged; 16 per peer once 8 peers exist | Core runs 1,024 ahead, with 16 per peer ([policy §7](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md)) |
| Rolling minimum fee | 1,000 sat/kvB incremental fee; dynamic memory usage | Core 31.1 uses 100 sat/kvB and allocator usage ([mempool policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/mempool-policy.md)) |
| Default validation engine | Native Rust interpreter; `kernel` is optional | Core runs its C++ engine ([VALID-01](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/validation-default.md)) |

Owner: [`docs/contracts/core-differential.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/core-differential.md). Next: [BIP support](bip-support.md) explains the capability matrix, and [Verification](verification.md) explains how to run each lane.
