# Experimental BIP352 public scan material

`getblocktweaks` is an opt-in, authenticated JSON-RPC prototype over the existing
listener. It projects certified retained inputs through the stateless
[`bitcoin-rs-index/silent-payments` codec](../crates/index/src/silent_payments.rs).
It adds no durable rows, wallet state or startup scan. Complete scanning, funded
wallet discovery and a cost benefit over existing APIs remain unverified.

## RPC usage and publication

Build with `cargo build --locked -p bitcoin-rs --features silent-payments` and
start with `--silent-payments` (default: off). The environment variable is
`BITCOIN_RS_SILENT_PAYMENTS`; the TOML key is `silent_payments`. Enabling the
option without the build feature fails configuration before opening node data.
Ordinary RPC authentication applies; REST enablement is independent.

Accept one positional or named `block`: an applied-chain height or block hash.
Unknown/additional parameters are rejected; there are no ranges, subscriptions,
wallet keys or interest filters. Example:

```json
{"jsonrpc":"2.0","id":1,"method":"getblocktweaks","params":{"block":850000}}
```

The result contains `height`, `hash`, `tip_height`, `tip_hash`, `taproot_active`
and `transactions`. Each transaction has its display `txid`, a compressed 33-byte
`tweak` in hex, and complete `outputs` containing `vout` and the 32-byte hex
`output_key`. Dust and duplicate candidates remain. An empty transaction list
means complete ineligibility, including pre-Taproot blocks, never missing inputs.
A candidate establishes neither ownership nor unspentness: verify it against
complete transaction/block data and subsequent spends.

| Condition | RPC outcome |
| --- | --- |
| Unknown hash | `-5` |
| Stale/header-only hash or height above the applied tip | `-8` |
| Incomplete history/ancestry, resource refusal, busy slot, recovery or changed chain | `-1`, with the reason; no partial or empty success |
| Storage/undo/integrity read failure | `-32603`; internal read diagnostics stay in the node log |
| Runtime disabled / feature absent / IBD | `-32603` / `-32601` / `-10` |

Selection uses one captured applied publication and the requested height's native
Taproot activation rule. After projection and JSON construction, a nonwaiting
transition check revalidates recovery state and the exact applied hash. This is
the response's consistency point; clients retain block identities and rewind
when the chain changes. Restart recomputes from certified data.

One nonqueued work slot spans computation, JSON rendering and publication.
The shared full-block permit covers source materialization and `block_tweaks`;
the adapter drops the owned `BlockSpends`, then the permit, before rendering the
derived JSON. Existing full-body responses retain their permit through rendering.
Body I/O and CPU projection hold no tree/transition guard. Ancestry fallback is
limited to 4,096 parent hops; IBD is refused before history I/O. These are resource
bounds, not measured throughput, latency or global-RSS guarantees.

## Input owner, limits and semantics

`Chainstate` implements the existing `utxo::contract::BlockUndoSource` directly.
It authenticates body/witness commitments, certifies native undo against durable
receipts, resolves same-block inputs, and rechecks applied hash, receipt and
retention lease. The [retained-input contract](contracts/external-api.md#retained-block-inputs)
owns these rules; the RPC adds no reader or availability authority. Current UTXOs
or independent transaction lookups cannot establish complete historic prevouts.

Every requested body and undo must be retained and certified, including inputs
funded before a wallet birthday. Missing/pruned history needs restore/replay or
another complete source; snapshots require archived validation progress. Txindex
is not required and cannot substitute for missing certified inputs.

The source bounds body copies to 4,000,000 bytes and undo copies to 64 MiB,
with decoded counts and script lengths bounded by the block and record. It does
not estimate verbose JSON expansion. The codec separately bounds body bytes and
aggregate prevout scripts (64 MiB). A raw-read or codec limit still requires
another complete source; unchanged retries cannot bypass it. `getblock`
verbosity 3 and `/rest/spenttxouts` share the input owner and its raw-read limits.
These are not heap or JSON-size caps. Complete BIP352 scanning and mainnet CPU
and memory costs remain unverified.

[BIP352 and its reference vectors](https://github.com/bitcoin/bips/blob/8754690b725e9aa93ca8bd91bf0ac85dc44ce096/bip-0352.mediawiki)
are pinned to `8754690b725e9aa93ca8bd91bf0ac85dc44ce096`; the
[WIP server specification](https://github.com/silent-payments/BIP0352-index-server-specification/blob/dc705a055e72024e332e232cf038c96afd42d50e/README.md)
is pinned separately to `dc705a055e72024e332e232cf038c96afd42d50e`.
The codec owns eligibility, key aggregation, the lowest serialized outpoint
among all inputs, input hashing and complete candidate indices. Its public API
requires consensus-validated transactions and exact input-ordered prevout scripts;
it does not execute consensus scripts or authenticate caller-supplied prevouts.
The receiver performs ECDH and discovery locally.

## Evidence and interoperability

The codec's 29 receiving-vector projections and pinned Python reference run are
recorded in [vector provenance](../crates/index/tests/data/bip352-PROVENANCE.md).
The adapter's owner-local tests cover unavailable history, read failures,
publication/recovery races, IBD and backpressure. The
`bin/bitcoin-rs/tests/silent_payments.rs` ProcessNode case applies a signed mature
P2PKH spend with three P2TR candidates and checks the exact tweak and each
candidate through authenticated HTTP, reorg and restart. The 100 funding blocks
are required for coinbase maturity. Source commit/recovery and lease tests remain
with `crates/chainstate/tests/unit/block_spends_tests.rs`. The separate
`bin/bitcoin-rs/tests/block_inputs.rs` regression applies a signed spend with
12,500 P2TR outputs, which exceeded the removed JSON estimate. It checks complete
`getblock` verbosity 3, binary spent-output REST and BIP352 candidates using real
certified undo; it adds no lifecycle or external consumer scenarios.

A recorded standalone REST probe ran unmodified
[BlindBit Oracle](https://github.com/setavenger/blindbit-oracle/blob/f9ab7fd8bc35467c492324f743ba1b69049a2bb6/internal/server/README.md),
pinned to `f9ab7fd8bc35467c492324f743ba1b69049a2bb6`, through existing REST.
It used no native tweak feature or runtime option. Oracle consumed
`/rest/chaininfo.json`, `/rest/blockhashbyheight/101.bin`,
`/rest/block/<hash>.bin` and `/rest/spenttxouts/<hash>.bin`. Its `/tweaks/101`
published the confirmed block hash and independently expected nonempty tweak.
The recorded configuration, logs and response were stored in `target/process-harness/e2e/run-*/blindbit*`.
The pinned binary passed the REST probe on 2026-10-16 under WSL/Linux
(Go 1.25.0, Rust 1.99.0); its SHA256 was
`0d386c6920ed3582c38b9f541cf9e57c761e3c9979c63f07193ad42af6bde4f4`.

The Oracle runner is not part of this PR's active tests. Reproduce the recorded
probe from its immutable historical checkout (Go and a C compiler required):

```sh
git clone https://github.com/setavenger/blindbit-oracle target/consumer-evidence/blindbit-oracle
git -C target/consumer-evidence/blindbit-oracle checkout --detach f9ab7fd8bc35467c492324f743ba1b69049a2bb6
go -C target/consumer-evidence/blindbit-oracle build -o ../blindbit-oracle-bin ./cmd/blindbit-oracle
git worktree add --detach target/consumer-evidence/l1-rest 12116e7390fc88d3f3dcbe570f051152c864716b
BLINDBIT_ORACLE="$PWD/target/consumer-evidence/blindbit-oracle-bin" cargo test --manifest-path target/consumer-evidence/l1-rest/Cargo.toml --locked -p bitcoin-rs --no-default-features --features fjall --test silent_payments_interop -- --ignored
```

This proves the L1 REST-to-sidecar path. The probe pays a P2TR candidate, not a
wallet-derived Silent Payment. Oracle's wallet-facing API prefers gRPC; its
legacy `block_identifier`/`index` shape also differs from the WIP specification.
The native RPC implements neither protocol. A complete scan-service claim needs
a real wallet's required protocol, funded discovery/confirmation, measured
benefit and a coverage decision. REST shares the source limit; the sidecar does
not resolve it. No unmodified wallet interoperability is claimed.

The API registry and [ecosystem inventory](api/ecosystem-compat.toml) retain
experimental status. No wallet secret, address subscription or per-user history
is accepted. Keyless computation is not anonymity: height queries and network
or query logs can reveal birthdays/access patterns. Compact filters are a
separate capability, not a codec requirement.
