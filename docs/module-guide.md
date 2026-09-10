# Bitcoin, one module at a time

Choose the question you want to answer, then follow its owner. This is an
informative source-navigation guide, not another architecture specification or
a promise that every crate has a stable, independently supported API.

The [workspace manifest](../Cargo.toml) lists twelve library crates and one
binary. The [architecture contract](contracts/architecture.md) owns their
five-layer assignments, dependency direction, exceptions, and live gaps.

## Choose a starting point

| Layer | Crate | Question to explore |
| --- | --- | --- |
| 0: Core | [primitives](../crates/primitives) | How are blocks, transactions, hashes, and network identities represented? |
| 0: Core | [script](../crates/script) | How are transaction spending conditions interpreted and checked? |
| 0: Core | [consensus](../crates/consensus) | Where are consensus rules and the native/kernel validation boundary? |
| 1: Storage | [storage](../crates/storage) | How do services access persistent data without naming a database engine? |
| 2: Services | [chain](../crates/chain) | How are the block tree and chain context represented? |
| 2: Services | [utxo](../crates/utxo) | Where is the unspent coin state tracked? |
| 2: Services | [p2p](../crates/p2p) | How does the node exchange data with peers? |
| 2: Services | [mempool](../crates/mempool) | How are pending transactions admitted and mutations coordinated? |
| 2: Services | [index](../crates/index) | How do derived lookup views follow the applied chain? |
| 2: Services | [mining](../crates/mining) | How are candidate blocks and mining-facing data assembled? |
| 3: Surface | [rpc](../crates/rpc) | How are capabilities exposed through public protocols? |
| 4: Compose | [node](../crates/node) | How are services configured, started, accessed, and stopped? |
| 4: Compose | [bitcoin-rs binary](../bin/bitcoin-rs) | How do process inputs reach the assembled node? |

The corresponding library package names use the `bitcoin-rs-` prefix; the
binary package is `bitcoin-rs`. This table groups responsibilities, not runtime
call order. It does not assert that every call traverses all five layers.

## Three reading routes

### Understand validation

Start with primitives, then script and consensus. Read the
[validation-default contract](contracts/validation-default.md) alongside the
implementation: a kernel-free binary build and the library defaults are not
the same feature selection. A specified vector test is narrower evidence than
exhaustive consensus equivalence. Use the feature-specific test commands in
[CONTRIBUTING.md](../CONTRIBUTING.md), not an assumed kernel-free workspace run.

### Connect a Rust application

Read the [embedding contract](contracts/embedding.md), then
[`crates/node/src/embed.rs`](../crates/node/src/embed.rs). Follow `Node::start`,
`snapshot`, `capabilities`, and the consuming `shutdown` operation. The daemon
and embedder share a lifecycle implementation. Startup and shutdown drive
synchronous work even though their public signatures are async.

The contract points to
[`crates/node/tests/embed.rs`](../crates/node/tests/embed.rs), including
`embedded_node_lifecycle_round_trip`, as a concrete reading and test entry
point. Referencing that test is not a claim that this guide executed it.

### Explore data services

Begin with storage, chain, UTXO, and index; identify which component owns each
fact before following its RPC projection. Read the
[indexing contract](contracts/indexing.md) for capability and readiness rules.
Unavailable data is not an empty result.

For an external application, continue through the
[wallet-facing contract](contracts/wallet-facing.md) and its public-process test
entry point, [`bin/bitcoin-rs/tests/wallet_facing.rs`](../bin/bitcoin-rs/tests/wallet_facing.rs).
Signing stays in the consumer. The test's documented dialect does not establish
compatibility with every BDK, LDK, wallet, or client version.

## Boundaries and unfinished work

Storage-engine dependencies belong to the storage crate. Dependency direction
is checked by
[`g17_dependency_direction.rs`](../bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs).
The normative rules and named proofs remain in the
[architecture contract](contracts/architecture.md), rather than being copied
into this guide.

Read that contract's **Live gaps** before proposing an extraction. In this
workspace, a dedicated `crates/chainstate` is still target work; the guide does
not depict it as an existing thirteenth library. Some domain mechanics remain
in node. Modularity here does not imply hot-swappable plugins, operating-system
isolation, or completion of every planned dependency cut.

## Make a bounded first contribution

Select one question in the table. Trace an existing input, output, and owner;
link one existing contract or test; then improve the explanation or report the
specific setup step that failed. Follow [CONTRIBUTING.md](../CONTRIBUTING.md)
and check for overlapping work before opening a change.

Start with documentation, examples, and tightly specified tests. Do not label
consensus-critical implementation work as an easy beginner task, and do not
present a proposed design as implemented behavior.
