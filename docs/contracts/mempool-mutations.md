# Mempool mutations contract

Current mutation records plus target lifecycle extensions. Bounded observer
delivery, nonblocking callbacks, persistent estimator state, and the full orphan
owner migration are not all implemented. Planned tests below are obligations,
not evidence of completion.

The canonical mempool lifecycle, its records, and the observer delivery
built on them. Owners: `MempoolGateway` in `crates/mempool/src/gateway.rs`;
`MutationResult`, `MutationOutcome`, `RemovalReason`, and
`MutationEnvelope` in `crates/mempool/src/mutation.rs`; the orphan owner
in `crates/mempool/src/orphan.rs`; the fee estimator in
`crates/mempool/src/fee_estimator.rs`. Mempool owns orphan mechanics.
The node owns peer-event routing only.
The ZMQ sequence observer lives in `crates/rpc/src/zmq.rs`.

## Clauses

### `MPL-01`: Single mutation gateway and canonical lifecycle

- Every production mempool mutation routes through `MempoolGateway`.
  Chain confirmations use `remove_for_block`. Reorg reconsideration uses
  `reconsider_disconnected` through the normal admission pipeline. No
  production code outside the gateway takes the mempool write lock.
- On connect, the gateway keeps valid children of mined parents inside
  the odd-generation window. Those children resolve the parent's outputs
  from chainstate thereafter. Mined conflicts remove descendants with
  `MutationOutcome::Removed(RemovalReason::Conflict)`.
- Estimator confirmation accounting runs inside the same mutation,
  before removals publish. A bounded observer queue may drop an
  optional record; it never drops the estimator update.
- On disconnect, the gateway collects candidates in a bounded
  topological queue and re-admits them through the admission pipeline
  under the new branch context. Refused candidates carry typed reasons;
  descendants of a refused parent stay withheld. The gateway rechecks
  existing entries for invalidated lock points and spend assumptions,
  and clears chain-sensitive recent-reject entries on generation change.
- Publication precedes observer delivery and callbacks run outside the pool
  writer. Today an elected caller drains callbacks inline, so a slow observer
  can block that caller, including a chain transition. Isolated nonblocking
  delivery is a target, not a guarantee of the present queue.

### `MPL-02`: Mempool-owned orphans

- `crates/mempool/src/orphan.rs` is the sole orphan owner: one orphan
  map, one missing-parent reverse index, and one bounded recent-reject
  cache. Two sources for one txid is a defect, not a fallback.
- `crates/node/src/tx_admission.rs` keeps peer-event routing only: inv
  filtering, `getdata` body serving, per-peer eviction on disconnect,
  and forwarding to the gateway. It stores no orphan state.
- Orphan mutation is a canonical mempool lifecycle operation. The wake
  path requeues exactly the children a newly available parent unblocks.
  Count and weight quotas, oldest-first eviction, and expiry follow the
  owner's declared bounds.

### `MPL-03`: Mutation records, ZMQ mapping, and relay source

- Every mutating method returns `MutationResult`: an ordered
  `Vec<MutationChange>` with one change per affected transaction, in
  commit order. `RemovalReason` is one of `BlockInclusion`, `Conflict`,
  `Replaced`, `Descendant`, `PolicyEviction`, `Expiry`, `Clear`,
  `Reorg`. `Mempool::sequence_number` advances once per emitted change.
- `SequenceEvent::Added(Txid, seq)` publishes label `A` (`0x41`);
  `SequenceEvent::Removed(Txid, seq)` publishes label `R` (`0x52`). The
  body frame is reversed txid (32 bytes) plus label byte (1) plus
  little-endian sequence (8), 41 bytes. The transport counter stays in
  its own trailing frame. `BlockInclusion` emits no `R`; every other
  removal reason does. One event per change, in commit order.
- Relay candidates come only from accepted-and-retained committed
  entries. An entry the same commit evicted is never announced.

### `MPL-04`: Bounded observer delivery with gaps

**Target.** The gateway's pending `VecDeque` is currently unbounded and the
first publisher can drain inline. ZMQ socket high-water marks do not bound this
queue. The required replacement must preserve canonical accounting:

- The publish queue is bounded. Overflow records sticky gap counters and
  a reconcile signal instead of growing memory. Delivery runs outside
  all domain locks; observer re-entry stays legal.
- Canonical estimator accounting and relay accounting are exempt from
  dropping. Optional consumers detect sequence gaps and reconcile from
  gateway-owned snapshots. ZMQ high-water marks stay per endpoint
  (`DEFAULT_ZMQ_HWM = 1_000`).

### `MPL-05`: Generation fencing and estimator persistence

- `MempoolGateway` carries the odd-even `chain_generation` fence.
  `begin_chain_change` closes admission and mixed reads. Only `finish`
  reopens them. A guard destructor never reopens the fence after an
  error. `stable_generation()` returns the even value when stable and
  `None` during a chain change.
- The fee estimator owns separate versioned persisted state. Corruption,
  a missing file, or an unknown version resets estimation to
  insufficient-data status. The node starts; no default confidence and
  no zero rate appear. A rejected estimator file stays in place until an
  authorized rebuild.
- `mempool.dat` encoding is unchanged for graph or owner refactoring.
  Loaded entries re-enter through the normal admission pipeline. Only
  real admission re-feeds the estimator.

## Proven by


- `crates/rpc/src/zmq.rs`:
  `admission_publishes_one_a_frame_with_core_payload_bytes`,
  `policy_eviction_publishes_r_frames_in_commit_order`,
  `block_inclusion_suppresses_r_frames`,
  `policy_eviction_publishes_r_frames_with_contiguous_sequences`,
  `mempool_event_payloads_carry_reversed_txid_label_and_le_sequence`,
  `sequence_event_payload_uses_core_hash_orientation_and_label`.
- `crates/node/tests/overhaul_mempool_lifecycle.rs` (planned): mined
  parent keeps its valid child; mined conflict removes descendants;
  reconsider refuses nonfinal candidates and withholds children;
  blocked observers never hold the write lock; queue overflow produces
  gap counters; estimator accounting precedes observer delivery; orphan
  wake requeues exactly the unblocked children; recent-reject
  invalidation on chain change.
- `crates/mempool/tests/overhaul_admission_owner.rs` (planned): preview
  purity and sequence accounting.
- `crates/mempool/tests/overhaul_fee_history.rs` (planned): estimator
  persistence restart and insufficient-data reset.
- Existing suites keep their verdicts: `crates/mempool/src/gateway.rs`
  inline tests (`remove_for_block` ordering, generation fencing),
  `crates/node/tests/tx_ingress_e2e.rs`, `crates/node/tests/mining.rs`
  long-poll wake tests, `crates/rpc/src/zmq.rs` payload
  tests, `crates/node/tests/crash_recovery.rs`.

## Vocabulary

[MempoolGateway](../../CONCEPTS.md),
[MutationEnvelope](../../CONCEPTS.md).
