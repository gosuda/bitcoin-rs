# Mempool policy contracts

The mempool owner implements the selected Core 31.1 replacement and preview
profile. [The policy matrix](../policies/mempool-policy.md) records behavior,
reference evidence and intentional unsupported cases. Compatibility claims
live in the RPC registry (`crates/rpc/src/registry.rs`), whose deviation
notes carry the rationale; [core-compat.toml](../../crates/rpc/core-compat.toml)
holds the reference pins and the admission-profile evidence.

## Clauses

### `POL-01`: Core 31.1 policy pin and versioned `AdmissionPolicy`

- Core source and binary identities are pinned by the reference-set manifest.
  Tests use the selected rates explicitly: minimum and incremental relay
  1,000 sat/kvB, dust 3,000 sat/kvB and nulldata budget 83 bytes. Core 31.1
  defaults to 100 sat/kvB for both relay rates; these selected settings are
  not a claim about upstream defaults.
- Implemented owners are `MempoolLimits` and `MempoolPolicySnapshot`.
  Cluster count is 64, cluster weight is at most 404,000, and at most
  100 distinct direct-conflict clusters participate in a replacement.
  `MAX_PACKAGE_COUNT` is 25. Raw trusted insertion may supply a policy vsize;
  production admission derives sigop-adjusted weight and size.
- A dedicated resolved/versioned `AdmissionPolicy` startup object remains a
  target design. The current preparation stamp copies the actual enforced
  settings and rechecks them; no new configuration or persistence authority
  is introduced by the replacement implementation.

### `POL-02`: One admission owner and admission mode

- `MempoolGateway` owns RPC, Esplora and peer submission, preview, reorg
  reconsideration, typed policy verdicts and publication. Producers do not
  repeat replacement rules.
- Single preview follows the same preparation, graph and script verification
  as a single commit, stopping before mutation. Multi-transaction preview uses
  Core's `PackageTestAccept` semantics: replacement and fee aggregation are
  disabled. Native `submit_local_package` admits a child and its independent
  direct parents atomically, in arbitrary input order. New members pay one
  aggregate relay/pressure floor; resident or positively confirmed fees are excluded. It uses
  the same preparation, scripts, graph/TRUC and ephemeral-spend owners, with
  no replacement or capacity eviction. RPC package submission remains
  unsupported, not a hidden fallback to separate successful submissions.
- Chain reads, script execution and fee-diagram solving run outside write locks.
  Callbacks run after pool/lifecycle locks are released.

### `POL-03`: Admission pipeline, stamp, and precedence

- Preparation captures chain generation, membership sequence, enforced settings
  and the owner's private fee-delta sequence. Any mismatch makes the result
  retryable. Four attempts bound the shared producer; exhaustion is typed.
- Fee-only prioritisation changes do not advance the public mempool sequence,
  but invalidate prepared graphs and contextual rejection-cache entries.
- Standardness, available inputs, sigop limits, modified fee floors, next-block
  finality and graph policy precede scripts. The caller maximum fee guard runs
  only after successful admission verification, comparing the base fee to
  `CFeeRate::GetFee(vsize)` rather than a rounded rate quote. An invalid transaction cannot
  select a more convenient maximum-fee error.
- A verified plan carries prepared insertion and ordered removals. The writer
  rechecks its stamp before any mutation. Capacity refusal, stale preparation
  or a rejected replacement changes no pool membership, fee overlay, estimator
  input or observer sequence. Successful mutations use the ordered gateway
  publication seam in [MPL-01](mempool-mutations.md#mpl-01-single-mutation-gateway-ordering-invariant).

### `POL-04`: Owner-computed sigop cost

- The gateway computes BIP141 sigop cost against copied resolved outputs.
  Caller-provided sigop counts do not reach stored entries. More than 16,000
  is a typed rejection.
- Exact policy weight is `max(wire_weight, sigop_cost * 20)`. Virtual size is
  the ceiling of that weight divided by four. Cluster sums and fee diagrams
  retain weight precision rather than summing rounded virtual sizes.
- Confirmed inputs, admitted parents and earlier package outputs feed the same
  accounting owner. Missing input facts are preserved.

### `POL-05`: Replacement, cluster, and package policy

- Signaling and the old new-unconfirmed-input restriction do not gate replacement.
  At most 100 distinct direct-conflict clusters are considered. Victims include
  every descendant, and the candidate must not spend an evicted dependency.
- Modified fees retain the existing signed i128 representation of a u64 base
  fee plus i64 prioritisation. Large legal priority overlays cannot disable
  template construction, and only actual fees contribute to the coinbase.
  Modified fees, including priority deltas, cover all victims plus the integer
  incremental relay charge. Exact checked arithmetic rejects an unrepresentable
  fee/weight. Equality or crossing of complete affected fee diagrams rejects;
  surviving relatives and newly joined clusters participate in the comparison.
- Existing entries and their dependency links are the graph authority. The
  pool keeps each cluster's exact linearization current on every insert,
  removal, and fee-delta change; one index orders all chunks (feerate, then
  equal-feerate prefix weight, then greatest member txid), so mining and
  eviction walk the maintained order instead of re-solving. Replacement keeps
  its own projection and re-solves the affected diagrams before and after.
  Work per mutation is bounded by the cluster limits; a from-scratch re-solve
  of the whole pool is the test oracle, not a runtime path.
- Mining treats every derived fee chunk as indivisible. If its finality,
  weight, serialized-size or sigop check fails, all members are skipped and
  dependent later chunks remain unavailable. The configured candidate limits
  are inclusive. Top-chunk selection reads only the pool owner's maintained
  index under one read guard (`chunks_by_feerate`). Generate/ordered and RPC
  mining paths instead take one whole-pool `mining_snapshot` with the lock
  released and remap ancestors through `snapshot_for_selection`; the snapshot
  carries the pool's own ancestor topology, so there is no independently
  solved graph to validate.
  Core 31.1 `node/miner.cpp::addChunks` supplies the independent reference
  for whole-chunk skipping; local configured limits and BIP68 checks follow
  this contract and POL-06.
- Core's bounded, history-dependent SFL work behavior is intentionally not
  emulated. The exact solver and its independently checked arithmetic do not
  prove Core parity in non-optimal transient states. This difference remains a
  recorded `Deviation` in the registry and prevents a whole-surface `Supported`
  claim.
- Combined package previews enforce count/weight, txid uniqueness, dependency
  order, internal consistency and projected cluster bounds. First precheck
  failure leaves other rows unfinished. Script failures preserve only earlier
  script-success rows. `submitpackage` stays `Unimplemented` and Esplora
  `/txs/package` stays 404; native CPFP does not imply RPC compatibility or
  package RBF support.
- TRUC requires matching unconfirmed versions, at most one ancestor/descendant,
  10,000 adjusted vB for a root and 1,000 for a child. An eligible sole sibling
  joins single-transaction RBF and remains subject to its fees and diagrams.
  Multi-transaction preview forbids sibling eviction.
- At most one ephemeral dust output is standard, and both actual and modified
  fees must be zero. Any child of that unconfirmed transaction must spend its
  dust. The selected positive relay floor cannot admit such a parent alone.

### `POL-06`: Preview purity and finality

- Preview changes no membership, estimator state, fee overlay, relay state,
  admission sequence or victims. It may populate safe verification caches.
- Absolute locktime evaluates at tip+1. BIP68 evaluates confirmed height/MTP
  metadata and treats unconfirmed parents as the next block. The CSV gate
  controls these relative locks. Coinbase spends require depth at least 100.
- Completed preview rows use the pinned v31 response type. Unfinished package
  rows contain identities and optional package error, with no fabricated
  `allowed` value or fee. Generic script-detail and numeric-error differences
  are listed in the manifest.

## Restart snapshots

`mempool::snapshot` owns the optional `mempool-snapshot.dat` artifact. It is a
set of admission candidates and operator fee deltas, never a second membership
or Chainstate authority. Its independent version, genesis identity, checksum,
configurable file-byte bound (64 MiB by default) and 400,000-byte transaction
bound do not change `CURRENT_SCHEMA`. Record counts are bounded by file bytes
and the format's u32 count fields, without a separate 100,000-record cap.
Format version 2 also stores each member's pending initial-broadcast flag.
No cluster/chunk graph, computed fee, policy stamp, sequence, orphan or
per-peer relay state is persisted.

Startup revalidates after authoritative recovery and before RPC/P2P workers
or external mempool observers are exposed. Snapshot membership is optional;
restoration does not promise to reproduce historical admission cohorts or to
maximize membership across the whole pool. The recovered Chainstate and the
fee overlay are quiescent during this startup phase.

**Admission selection.** Restore forms saved dependency families in
deterministic parent-first seed order. One immutable, symmetric graph of saved
input references defines their partition. Current confirmation does not erase
a historical fee-sharing association or let a later family revisit an earlier
decision. Expired and positively confirmed members remain graph connectors
but are excluded from new
membership. A complete family of at most 25 saved members is considered as a
unit. Its nonempty subsets are submitted through the existing atomic gateway
package operation in descending transaction count, with deterministic
parent-first ordering inside each subset. Failed attempts change no live
membership, operator priorities or public mutation sequence. The first
successful subset is committed once; rejected members of that family are not
subsequently admitted singly. The gateway retains all fee, script, finality,
TRUC, ephemeral-spend, cluster and capacity checks. Resident and confirmed fees
are never counted again. Restore uses non-evicting package admission even for
a singleton, so a later family cannot evict an earlier committed choice.

**Guarantee and limits.** With stable Chainstate/policy and enough cooperative
time, a committed subset has the greatest number of newly admitted members
among the subsets of that complete family, against the live pool prefix at
that point. This is a per-family cardinality guarantee, not a choice of maximum
fees, preservation of every individually valid alternative, global optimality,
or a Core-equivalence claim. At most 256 package attempts are made per family.
For eight or fewer members all 255 or fewer nonempty subsets fit this attempt
budget; time or changing admission fences can still stop the search. Larger
families may find a maximal subset before the attempt budget runs out, but
are not guaranteed to do so. Discovering a 26th family member stops collection
without admitting a truncated family. This bound counts saved connectors as
well as new-membership candidates. These search limits are independent of the
file-byte budget and timeout settings. Search exhaustion, unavailable admission
facts or an unstable fence, or a family over 25 leaves that search uncommitted
and increments the `limited` candidate count. There is no fallback that commits a parent before
higher-cardinality alternatives have been rejected.

Graph construction reads each saved transaction's confirmation facts at most
once, then family collection walks the same saved dependency projection.
The gateway re-reads current inputs for every subset: spent confirmed ancestors
are not forced back into membership, and subsets omitting them remain eligible.
The deadline is checked before chain reads, input/neighbor visits and each subset
attempt. A running gateway operation or chain read is cooperative and cannot
be preempted. On timeout the current family has no tentative membership to
roll back; previous successful families remain. Reports distinguish
`timed_out`, `limited`, `package_attempts` and total `skipped`. Candidates not
restored remain in the existing artifact until a subsequent save; the next
clean shutdown still saves only the then-current live pool and all priorities,
so it can omit these candidates. There is no deferred-candidate journal.

Ages use saved wall-clock admission seconds; future-dated or more-than-fourteen-
day-old candidates are excluded. Each committed member retains its own saved
time. Fee deltas, including absent-txid overlays, retain their operator meaning
even when membership is refused. After decoding and dependency validation
succeed, all saved fee deltas are applied before candidate admission,
independently of its deadline. Timeout cannot leave a priority prefix for the
next save to publish.

Restored transactions do not register fresh estimator samples or blanket
relay announcements. Successfully re-admitted members retain their saved
initial-broadcast flags; the P2P relay worker retries only pending local bodies
through its ordinary peer/fee/inventory policy. Fresh local RPC/Esplora commits
mark the live entry pending before publication; successful getdata body responses
clear that flag through the gateway without changing membership or its sequence.
The pool maintains an ordered index derived from these flags. Retry batches
resume strictly after the last witness id and visit at most 1,024 indexed
pending entries; an empty index does not scan ordinary membership.
Removal drops the flag with the entry. Ordinary gateway sequence assignment and mining wakes
still run; fee-estimator history remains a separately owned file.

Saving captures shared transaction handles and scalar metadata under one
bounded read, then encodes and writes without the pool lock. If transaction
bytes or count exceed the snapshot budget, saving keeps a prefix of complete
connected families and logs the omitted count. It never saves a CPFP parent
without its connected paying child. All fee deltas are reserved first; if
operator overlays alone exceed their bound, saving fails without truncating them.
The snapshot budget is independent of the live pool's virtual-size limit.
`mempool_snapshot_max_mb` (CLI `--mempool-snapshot-max-mb`, environment
`BITCOIN_RS_MEMPOOL_SNAPSHOT_MAX_MB`) raises the shared read/write budget;
a large enough budget retains every live family, subject to the cooperative
deadline. Selection stops at the first family that does not fit.
`mempool_snapshot_restore_timeout_secs` (CLI `--mempool-snapshot-restore-timeout-secs`,
environment `BITCOIN_RS_MEMPOOL_SNAPSHOT_RESTORE_TIMEOUT_SECS`) configures the
startup restore deadline in seconds. When unset, its default scales with the
configured byte budget (`max(60, mempool_snapshot_max_mb)`); an explicit value
is used as configured. Zero and durations outside the platform clock's range
are configuration errors. The deadline is cooperative and can expire before
all candidates have been revalidated.

Clean teardown waits at most ten seconds for a staging worker, which cannot
touch the live file. Mempool persistence applies exclusively to clean, graceful
shutdowns (`TeardownMode::CleanShutdown`); abrupt termination (power failure, crash,
SIGKILL) does not record a snapshot. The shutdown thread owns publication and completes it
before returning; abandoning a worker therefore cannot overwrite a later run.
Deadline checks are cooperative: individual OS calls, including publication,
cannot be preempted. A synced staging file is renamed before syncing the
directory where supported. Incompatible/corrupt ordinary live files are moved
intact into a unique `mempool-snapshot-rejected-*` directory before publishing
a fresh snapshot. Unreadable files, directories and symlinks are not replaced.
Interrupted staging files are never loaded. Restore runs within the configured
cooperative deadline and reports missing, restored, partially restored or
rejected status; it does not retry indefinitely. Selected multi-generational CPFP
subsets are committed atomically in topological order within standard package
limits (`MAX_PACKAGE_COUNT`). Each candidate record persists
precomputed BIP16/BIP141 `sigop_cost` in format version 2, validated upfront against standardness
limits before script execution. Successfully re-admitted entries survive budget exhaustion,
and the next clean shutdown snapshots the then-current pool. Startup aborts and failed
clean checkpoints do not save.

`persist_mempool=false` disables both load and save and leaves existing files
untouched. There is no periodic writer. `savemempool` and `importmempool`
remain unsupported RPCs; this format makes no Core disk-format claim.

## Proven by

- `pool::chunk_order_tests::maintained_chunk_order_matches_the_from_scratch_solver`
  (proptest): random insert/remove/confirm/replace/prioritise/clear sequences
  over multi-output transactions; after every mutation the maintained order
  equals an independent per-component re-solve ordered by the index key, and
  the index satisfies its partition, totals, topology, and rate invariants.
- `pool::chunk_order_tests::equal_rate_parent_sorts_before_its_child`:
  an equal-rate parent and child stay two chunks with the parent first.
- `pool::chunk_order_tests::remove_for_block_confirms_and_conflicts` and
  `rbf_replacement_keeps_the_index_current`: inclusion, conflict, and
  replacement removals keep every surviving piece indexed.
- `chunk_index::tests`: the key order pins (rate beats prefix, prefix beats
  raw weight, greatest txid breaks cross-component ties), total-order
  proptest, and relinearize-replaces/forget-drops maintenance.
- `crates/mempool/src/snapshot/tests.rs` covers candidate revalidation,
  CPFP/ephemeral dust and bounded subset selection, multi-generational CPFP
  package restoration, upfront sigop standardness validation, per-member times,
  whole-family capacity bounds, raised byte budgets, more than 100,000 records,
  pending initial-broadcast flags and rejected-file quarantine.
  `restores_cpfp_after_saved_ancestors_confirm_and_are_fully_spent` compares
  restored descendants with direct gateway package admission after the saved
  ancestors confirm. `restore_timeout_preserves_all_priorities_through_the_next_save`
  expires the admission budget after decoding and checks the next saved overlay.
  `restores_parent_paying_for_a_low_fee_child_before_standalone_admission`
  compares native admission with restart restoration, including a paying sibling.
  `family_collection_stops_at_the_package_count_boundary` checks collected member counts
  at and beyond the package limit; `graph_build_stops_when_a_chain_read_exhausts_the_deadline`
  verifies that graph construction performs no next read after budget exhaustion.
  `snapshot::tests::restore_model::generated_small_graphs_match_direct_gateway_maximal_subsets`
  generates selected two-to-four-member DAG shapes across fee placement,
  nonfinal-member masks, unchanged/confirmed/spent funding, expired connectors, capacity and record
  order. Its independent bitmask oracle tests every subset on a fresh gateway;
  it is finite local evidence, not a proof for arbitrary transaction graphs.
  `search_limits_do_not_commit_a_parent_before_subset_search_finishes` and
  `deadline_exhaustion_leaves_the_current_family_uncommitted` cover the explicit
  incomplete-search boundary, including absence of mutation publication.
- `tx_relay::tests::pending_local_broadcast_survives_absent_peers_and_saturation`
  and `dispatch::tests::getdata_completes_initial_broadcast_only_after_successful_send`
  cover retry and completion through the existing relay/getdata owners.
  `tx_relay::tests::pending_broadcast_batches_resume_by_key_after_completion_and_removal`
  covers batch progress as pending entries complete or leave the pool.
- `lifecycle::tests::timed_out_snapshot_worker_cannot_overwrite_the_next_runs_snapshot`
  covers shutdown timeout followed by a newer save and late worker completion.
- `bin/bitcoin-rs/tests/mempool_restart.rs` drives real daemon shutdowns,
  restarts, RPC membership/lookup, mining, changed-tip reconciliation and
  initial-broadcast continuation over the P2P wire.
- `overhaul_process_harness::replacement_signaling_matches_pinned_core` and
  `policy_cases`: isolated Core/candidate processes, identical funding blocks,
  real signatures, nonsignaling replacement, insufficient fees, graph merge/split,
  100/101 conflicting clusters, 64/65 connected members, 1 sat incremental
  boundaries, prioritisation, TRUC siblings/sizes and package verdict shapes.
- `crates/mempool/src/fee_diagram/tests.rs`: pinned Core comparison vectors,
  independent exhaustive small-DAG oracle and maximal 64-node topology.
- `crates/mempool/tests/replacement_profile.rs`, `graph_limits.rs`,
  `policy_contract.rs` and `admission.rs`: exact graph/TRUC bounds, atomic
  failures, fee arithmetic, next-block finality and sigops.
- `crates/mempool/src/package/tests.rs`: 25/26 and 404,000/404,001 package
  boundaries, reference-checked weight, TRUC/cluster projections, zero-floor
  ephemeral spending and fee-only invalidation.
- Gateway tests: publication order under concurrency/reentrancy, stale verdicts
  and rejected replacement preservation of estimator history and fee overlays.
- Mining/RPC suites: shared chunks, block resource limits, witness commitment
  oracle, both-RPC verdicts and manifest projection consistency.

Performance, Core transient SFL/churn behavior and the project-wide formal
model matrix remain unmeasured. Correctness tests do not promote defaults.

## Vocabulary

[Chain generation](../../CONCEPTS.md),
[MempoolGateway](../../CONCEPTS.md).
