# Native LDK L1 adapter

Experimental consumer for [issue #815](https://github.com/gosuda/bitcoin-rs/issues/815),
pinning `lightning = 0.2.7` and `lightning-block-sync = 0.2.0` with its own
`Cargo.lock` and independent Cargo workspace. LDK stays out of the authoritative
workspace dependency graph and default CI.

The adapter borrows the production public `Node`. It uses neither `NodeState`
nor `test-seam`, and makes no RPC/REST/ZMQ requests. It owns no chain/mempool
store, worker, event journal or channel persistence.

| LDK entry point | Node capability | Behavior |
| --- | --- | --- |
| `BroadcasterInterface` | `broadcast`, `broadcast_package` | Single submission or atomic child-with-independent-parents package; arbitrary package order. |
| `FeeEstimator` | `fee_estimate` | Existing history estimator, explicit fallback when insufficient. |
| `BlockSource::get_best_block` | `settled_snapshot` | Coherent applied hash/height after node follower/mempool settlement. |
| `BlockSource::get_block` | `block_by_hash` | Full block via consensus encoding; pruned, corrupt or mismatched bodies are persistent errors. Unknown blocks remain transient. |
| `BlockSource::get_header` | `block_header` | Header, authoritative height and cumulative work, independent of advisory hints and body retention. |

Conversions use consensus encoding and hash byte arrays, without display-string
endian conversion. `try_broadcast_transactions` returns admission errors. LDK's
void broadcaster records errors through `tracing`; applications must install a
subscriber to collect them. No retry state is kept.

## Runtime and policy

Run the consumer on an application-owned blocking OS thread, outside executor
tasks and node locks. The test uses a named `ldk-consumer` thread. Current Node
async storage/admission operations do synchronous work when polled. The
synchronous broadcaster drives them with `futures_executor::block_on` on that
thread; this does not offload work or create a runtime.

Native packages contain one child and its independent direct parents, at most
25 transactions and 404,000 aggregate wire WU. Resident or positively confirmed
members contribute no
fees. There is no package RBF or capacity eviction. All new members pass the
canonical scripts, graph/TRUC, ephemeral-spend, aggregate relay/pressure fee
and per-member maximum-fee checks before atomic insertion. RPC `submitpackage`
and Esplora package compatibility remain independently scoped.

Illustrative fee horizons are 1 block for `MaximumFeeEstimate`, 6 for urgent
sweeps/non-anchor channel fees, and 25 for other targets. Conversion is
`ceil(sat/kvB / 4)`, clamped to LDK's 253 sat/kw floor and `u32::MAX`. The
constructor requires an explicit fallback in sat/kw, clamped to the same floor.
The fallback is application policy, not a node estimate. These fee policies
and channel persistence are not qualified for real funds.

## Chain observation and recovery

LDK block-sync can poll `BlockSource` with header metadata. Applications can
also use the public Node polling seam:

1. `subscribe_chain()` captures a settled observation cursor.
2. `poll_chain(&mut subscription)` returns a change and opaque `ChainTarget`.
   Multiple commits or an epoch change flag a gap. No events are queued.
3. `replay_chain(applied_hash, &target, limit)` returns disconnects followed by
   connects toward that fixed target, up to 256 steps and 4096 ancestry hops
   per call. Fetch bodies with `block_by_hash` outside the locks, apply steps,
   and advance the consumer's applied hash only after success.
4. Finish the target, then poll again. After restart resume a persisted
   observation with `Node::resume_chain`, re-pin, and reconcile from the
   consumer's actual persisted applied hash. Targets cannot cross node runs.

This is positional replay, not an event log of every intermediate reorg prefix.
Targets pin identity rather than retained bodies; missing headers, pruned data
and ancestry-budget exhaustion report errors. Re-pin or restore required data;
never skip a failed body and mark it applied. See
[EVT-06](../../docs/contracts/chain-events.md#evt-06-public-settled-polling-and-positional-replay).

## Verification

With the repository's Rust toolchain and a C compiler for secp256k1:

```sh
cargo test --locked --manifest-path tools/ldk/Cargo.toml
cargo clippy --locked --manifest-path tools/ldk/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path tools/ldk/Cargo.toml --check
cargo test --locked -p bitcoin-rs-mempool --lib
cargo test --locked -p bitcoin-rs-node --no-default-features --features fjall --lib chain_feed::tests
```

The public consumer starts a temporary fjall regtest Node, reads genesis
through real LDK traits, validates its best header with LDK block-sync,
checks byte conversions and fee fallback, exercises admission errors and
settled polling, then shuts down and reopens. The ordinary lifecycle binds
an ephemeral RPC listener which the consumer never contacts; ZMQ and block-sync
RPC/REST clients are disabled in this dependency graph.

Owner tests additionally exercise aggregate CPFP admission, atomic failure,
publication, fee-stamp retry, capacity/topology refusal, bounded replay,
reorg order, missed commits, restart and settlement fencing. There is no
channel lifecycle, ChannelMonitor persistence or native-versus-RPC performance
claim. `tx_by_id` still returns bytes with index gating, not confirmation
block/height identity; block-based LDK synchronization does not require that
additional query.
