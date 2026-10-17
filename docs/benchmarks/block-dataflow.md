# Block preparation and commit allocation audit

The measured change replaces the full-block serialization used only to check
the length of preserved bytes in `chainstate::connect` with
`ConsensusEncode::consensus_size`. This removes a temporary full-body buffer
after validation. The exact raw/decoded identity proof remains in
`prepare::bytes_are_block`; the debug serialization assertion and the
no-preserved-body fallback remain too.

The follow-up transfers resolved prevouts into native/kernel prepared checks.
The retained output owner and parallel-check lifetimes stay the same; script
buffers move instead of being cloned. Borrowed transaction callers keep their
existing cloning API. See the separate incremental comparison below.

Block facts now transfer as well: `BlockParse::into_parts` consumes the
parse, moves native facts or the kernel txid vector into `BlockView`, and
returns only the backend state needed by scripts. No mutable empty-facts
state, shared cache, extra allocation, or expanded parallel lifetime is added.

This is a bounded native-engine allocation result for #1570. Historical
mainnet receive-to-commit and whole-node IBD non-regression are **BLOCKED**:
this run has no contiguous historical corpus with its predecessor UTXO state
or before/after release daemon IBD artifacts. It does not qualify a whole-node
speedup or close the issue. Kernel performance was not measured.

## Ownership and repeated work

The following are source-trace counts and ownership findings, not dynamic
decode/hash counters. Both single-block connect and the prepared-window path
reach the same `connect` persistence transaction.

| Boundary | Current work and decision |
| --- | --- |
| P2P `InboundBlock` | A wire block owns one decoded `Block` and its preserved `Bytes`. Local `from_decoded` injection instead serializes a supplied tree; that is fixture work, not an extra production receive serialization. |
| `BlockStager` / `sync::commit` | Staging moves the tree and bytes into `ReceivedBlock`, then `DrainedBlock`. Successful windows borrow `&Block` and shallow-clone `Bytes`; they do not deep-clone each tree. Partial-failure restoration clones the uncommitted suffix, intentionally keeping retry state. No staging changes. |
| `prepare::parse_block_for_apply` | One streaming canonical encode/compare binds raw bytes, including witness, to the tree without allocating a whole-body buffer. One native checked borrowed-layout parse derives facts; it is not another materialized transaction tree. Keep both independent checks. |
| `kernel::BlockParse` / `BlockView` | After the existing byte-identity and count checks, `into_parts` consumes the parse. Native facts, including cached txids/wtxids and Merkle verdicts, move into the view. Kernel facts take ownership of the collected txid vector; `BlockScriptSource` retains the kernel block for script borrows. Planning borrows the same fact IDs rather than creating a separate ID vector. No transaction rehash or changed independent verification. |
| Transaction planning / resolved UTXOs | One plan tracks same-block dependencies; ordered overlay/prevout resolution fixes each transaction's inputs before parallel scripts. Existing serial-lookup evidence remains authoritative. Structural prechecks currently follow window resolution; no rejection-order change. |
| Script preparation | Resolved `TxOut`s move into `TxPrep`, then into native/kernel retained outputs after ordered-identity validation. Native `PreparedTransaction::from_owned` moves script buffers; borrowed `new` callers still clone. Transaction-wide sighash material remains shared across inputs. No parallel-unit lifetime expansion or borrowed-prevout redesign. |
| `connect` / persistence | With a body consumer and preserved raw bytes, the old release guard called `consensus_bytes(block).len()`: one allocation and one complete output serialization per committed block. The candidate computes sizes, retaining the already-bound `Bytes`. No transaction precomputation, UTXO/undo mutation, journal ordering, head publication, or durable representation changes. |

The targeted output writes eliminated are exactly the serialized lengths of
the committed blocks (header, transaction fields and witness). Allocator
counters below measure requested heap bytes, not memcpy traffic, RSS, live
memory, database write volume, or CPU instructions. Other copy volumes and
dynamic decode/precompute counts remain unmeasured; the table must not be used
as a full-path profiler result.

## Reproduction and workload

Build the same harness at baseline `ed806ddec` and candidate `bc008b61a`:

```powershell
cargo +1.99.0 build --locked -p bitcoin-rs-node --no-default-features --features fjall --bench block_dataflow --profile quickstart
$env:RAYON_NUM_THREADS = '4'
# Run the produced executable directly with argument 6, on CPUs 0..3.
# Alternate baseline/candidate three times; retain each stdout as JSONL.
```

`block_dataflow` uses the existing `NodeState` test seam with fresh fjall
storage per sample, default regtest configuration, full native validation,
assume-valid height zero, no listeners and 32 MiB dbcache. Bootstrap and
header admission happen outside the timed region. `commit` connects each
block through the authoritative transition; `sync` sends local inbound
blocks through production BlockSync admission, bounded staging, window
verification and commit. Each sample asserts the exact final tip hash.
Commit durability is unchanged. Teardown is outside the measured interval.
The body index uses `write_deferred`; body/index sync precedes the final
`write_durable_if` head receipt (fjall `PersistMode::SyncAll`). Direct connects
retain per-block receipts and BlockSync retains its existing grouped
publication. The default journal policy is 500 blocks / 5 seconds.

| Corpus | Measured range | Blocks | Raw bytes | Scripts |
| --- | --- | ---: | ---: | --- |
| `early_coinbase` | regtest 1..32 | 32 | 4,592 | Small coinbase-only bodies |
| `legacy_512_inputs` | regtest 101..116 | 16 | 338,528 | One 512-input spend per block, mature funding coinbases, OP_TRUE |
| `witness_512_inputs` | regtest 101..116 | 16 | 4,657,072 | One 512-input P2WSH spend per block; 520-byte witness item followed by OP_DROP OP_TRUE; valid BIP141 commitment |

These are deterministic synthetic early-shaped and modern-shaped workloads,
not historical Bitcoin blocks. The scripts isolate body handling and do not
represent signature throughput. The separately timed
`decode_and_ingress_fixture` includes `deserialize` plus `from_decoded`'s local
serialization; production socket receive preserves bytes instead. Do not add
that interval to apply and call the result network IBD.

The global System allocator counts allocation/reallocation events and their
requested sizes across all threads while each interval is enabled. Body-size
buckets count any allocation of a corpus body length, not a tagged allocation
type: small coinbase sizes alias unrelated allocations. Metrics include
background allocation activity, so total requested bytes can vary even when
the removed serialization is deterministic. The instrumentation itself adds
atomic-counter overhead to both arms.

The `quickstart` profile is optimized without debug assertions, with LTO off
and 16 codegen units. Its wall times are diagnostic, not release-IBD
qualification. The retained manifest supplements the embedded Windows
`unknown-cpu` identity with CPU, affinity, RAM, OS, storage and toolchain.
Per-corpus identities include binary/config/corpus digests and stop hashes;
the config digest uses the common base config, excluding each fresh temporary
directory. See the shared [evidence rules](README.md) for qualification rules.

## Retained results

[Manifest](data/preserved-body-20261017/manifest.json) records both source
commits and binary hashes. [Summary](data/preserved-body-20261017/summary.json)
contains p50/p95/p99/max/min and counts for every metric and interval. Raw
stdout is retained in the same directory as `baseline-{1,2,3}.jsonl` and
`candidate-{1,2,3}.jsonl`, in alternating execution order. All six processes
exited successfully; no timing outliers were removed. Each arm has 18 timed
samples per corpus/mode, plus three excluded warmups. Quantiles use nearest
rank; p50 averages the middle two observations.

Apply allocation results, p50 per measured block group:

| Corpus / mode | Events baseline -> candidate | Requested bytes baseline -> candidate | Removed serialized output bytes |
| --- | ---: | ---: | ---: |
| Early / commit | 3,578 -> 3,546 | 2,401,022 -> 2,396,430 | 4,592 |
| Early / sync | 2,976 -> 2,944 | 2,540,678 -> 2,536,086 | 4,592 |
| Legacy / commit | 78,052 -> 78,036 | 22,662,652 -> 22,324,124 | 338,528 |
| Legacy / sync | 77,890.5 -> 77,874.5 | 26,832,950 -> 26,494,422 | 338,528 |
| Witness / commit | 95,174.5 -> 95,158.5 | 41,193,424 -> 36,536,352 | 4,657,072 |
| Witness / sync | 95,060 -> 95,044 | 45,365,274 -> 40,708,202 | 4,657,072 |

In both high-input corpora, every baseline apply sample has 16 body-length
bucket allocations; every candidate has zero. Each early candidate removes
32 events, but its remaining body-size bucket entries are aliases, not body
serializations. Fractional event medians reflect background-event variation,
not fractional allocations. Fixture decode/ingress event counts and requested
bytes are unchanged. Native layout parses, identity comparisons and
transaction precomputations were not altered.

Diagnostic apply wall in milliseconds (18 samples per arm/cell):

| Corpus / mode | Baseline p50 | Baseline p95/p99/max | Candidate p50 | Candidate p95/p99/max |
| --- | ---: | ---: | ---: | ---: |
| Early / commit | 152.014 | 190.257 | 149.282 | 194.660 |
| Early / sync | 19.844 | 49.069 | 21.599 | 28.574 |
| Legacy / commit | 249.896 | 345.441 | 260.761 | 2,872.231 |
| Legacy / sync | 183.792 | 226.394 | 187.779 | 661.307 |
| Witness / commit | 354.131 | 604.434 | 339.321 | 1,343.465 |
| Witness / sync | 279.728 | 351.789 | 290.468 | 900.758 |

Per-run apply medians in milliseconds, preserving execution order within
each arm:

| Corpus / mode | Baseline runs 1 / 2 / 3 | Candidate runs 1 / 2 / 3 |
| --- | --- | --- |
| Early / commit | 141.058 / 154.026 / 153.601 | 153.368 / 146.326 / 146.861 |
| Early / sync | 19.075 / 23.254 / 19.648 | 22.837 / 22.254 / 19.906 |
| Legacy / commit | 248.831 / 244.423 / 283.033 | 249.109 / 467.485 / 255.407 |
| Legacy / sync | 179.484 / 184.143 / 191.353 | 179.277 / 206.349 / 183.886 |
| Witness / commit | 363.457 / 349.993 / 368.534 | 332.527 / 903.982 / 322.051 |
| Witness / sync | 286.672 / 284.618 / 278.738 | 279.530 / 617.437 / 278.788 |

The allocation reduction exceeds background variation and matches one
serialized-body buffer per block. **The timing/non-regression gate did not
pass.** Candidate run 2 has large delays, stability exceeds the 5% rule, and
several pooled medians/tails regress beyond the shared guard limits. The
cause of the delays was not established. These observations neither qualify
a speedup nor establish IBD non-regression; they must not be dismissed as
noise to promote the change. This is a draft optimization pending a stable
release-profile comparison and the missing historical/whole-node cells.

## Resolved-prevout transfer comparison

This incremental control already includes the preserved-body length fix:
baseline `bc008b61a`, candidate `e5bf79eb3`. The exact same harness and three
corpora are used. Both engines consume `Vec<(OutPoint, TxOut)>` after validating
the ordered identities and retain the moved outputs for their checks. Their
output vectors request `shrink_to_fit` after collection so in-place reuse of
the larger tuple buffer does not intentionally retain spare outpoint capacity
through parallel verification. No peak-RSS claim follows from this.

Before moving `TxPrep.prevouts`, preparation computes the pure value/sigop
post-error and holds it for the existing ordered scan. A backend setup error
still returns the preparation error; input scripts still outrank their own
transaction's post-error; that post-error still outranks later transactions.
Only verdict computation moves earlier, not rejection publication or commit.
The same one-cache/owned-prevout lifetime and per-input script context remain.

The copy removed here is the prevout's script-buffer clone, not witness bytes
or hashing. Each measured high-input corpus spends 8,192 nonempty prevouts:
legacy scripts contain one byte each and P2WSH scripts 34 bytes each. Scalar
output movement and allocator-internal relocation are not memcpy counters.

[Manifest](data/prevout-transfer-20261017/manifest.json) and
[summary](data/prevout-transfer-20261017/summary.json) retain this comparison's
identities and full metric quantiles. The same directory contains all six
`baseline-{1,2,3}.jsonl` / `candidate-{1,2,3}.jsonl` stdout files. Each arm/cell
has 18 timed samples and three excluded warmups, using the quantile method
above. All processes exited zero and all samples reached the exact expected
tip. Fixture ingress allocation metrics and body-length buckets are unchanged.

Incremental apply allocation results, p50 per block group:

| Corpus / mode | Events baseline -> candidate | Requested bytes baseline -> candidate |
| --- | ---: | ---: |
| Early / commit | 3,546 -> 3,546 | 2,399,790 -> 2,399,790 |
| Early / sync | 2,944 -> 2,944 | 2,539,446 -> 2,539,446 |
| Legacy / commit | 78,036 -> 69,844 | 22,325,804 -> 22,317,612 |
| Legacy / sync | 77,874.5 -> 69,682.5 | 26,496,102 -> 26,487,910 |
| Witness / commit | 95,158.5 -> 86,966.5 | 36,538,032 -> 36,259,504 |
| Witness / sync | 95,044 -> 86,852 | 40,709,882 -> 40,431,354 |

The high-input groups remove 8,192 allocation/reallocation events, about
8.6–10.5% of apply events. Requested-byte medians decrease by exactly the
script payload totals above. This exceeds the observed one/two-event
background variation. This is not an 8.6–10.5% reduction in RSS or IBD time.
Vector compaction can still allocate/reallocate and relocate output structs;
the claim is removal of the per-input script-buffer clones.

Diagnostic apply wall in milliseconds (18 samples per arm/cell):

| Corpus / mode | Baseline p50 | Baseline p95/p99/max | Candidate p50 | Candidate p95/p99/max |
| --- | ---: | ---: | ---: | ---: |
| Early / commit | 144.144 | 171.481 | 146.859 | 248.727 |
| Early / sync | 20.369 | 28.081 | 19.700 | 24.220 |
| Legacy / commit | 270.368 | 404.768 | 271.177 | 1,674.237 |
| Legacy / sync | 187.897 | 238.581 | 193.822 | 461.948 |
| Witness / commit | 351.900 | 458.876 | 355.116 | 451.558 |
| Witness / sync | 300.751 | 388.019 | 284.304 | 331.335 |

Per-run apply medians in milliseconds:

| Corpus / mode | Baseline runs 1 / 2 / 3 | Candidate runs 1 / 2 / 3 |
| --- | --- | --- |
| Early / commit | 156.287 / 140.649 / 150.768 | 144.194 / 158.947 / 150.446 |
| Early / sync | 20.625 / 17.975 / 21.138 | 19.433 / 20.091 / 20.146 |
| Legacy / commit | 266.689 / 271.030 / 269.078 | 250.974 / 344.665 / 259.428 |
| Legacy / sync | 187.140 / 196.503 / 187.709 | 179.968 / 314.998 / 187.226 |
| Witness / commit | 347.812 / 344.031 / 398.116 | 364.150 / 338.042 / 354.356 |
| Witness / sync | 300.933 / 296.364 / 320.123 | 284.304 / 282.181 / 285.797 |

The witness-sync diagnostic median improves, but the shared timing gate
still **does not pass**: stability and other-cell median/tail guards fail.
The delays have not been attributed; no outliers are discarded. Release,
historical-mainnet and whole-node non-regression qualification remain
outstanding. Only the allocation/copy reduction is established here.

## Parsed-fact transfer comparison

This incremental baseline `fafae0dc0` already includes the body-length and
prevout-transfer changes. Candidate `6d8d90bd0` consumes parsed facts instead
of cloning them. Both binaries use the same expanded harness: the original
three corpora plus `legacy_512_transactions` and `witness_512_transactions`.
The added corpora keep 512 mature funding outputs and 512 inputs per block,
but split them into 512 one-input spends, so each block has 513 transactions
including coinbase. Witness blocks commit all witness IDs in their BIP141
commitment; validation remains Full/native with no assume-valid shortcut.

Native removes two cloned txid vectors per block and a cloned wtxid vector
when present, retaining the original facts in `BlockView`. The planning and
commit paths borrow or consume those same IDs. Kernel moves its collected
txid vector into facts and retains the parsed kernel block only as script
backend state. The consuming handoff cannot be called a second time; no
empty-facts sentinel or new shared cache is needed. Exact raw/decoded binding,
the pre-handoff transaction-count error, script context and publication stay
at their existing owners.

Kernel weight/Merkle fact construction now completes inside the consuming
parse handoff, before planning. In the window path this pure work therefore
runs with the existing parallel parse jobs, and its diagnostic time moves
from prepare to parse. It changes no rejection or mutation ordering, but is
an unmeasured kernel timing/dispatch change; native allocation results do not
qualify kernel performance. Ordered UTXO/prevout resolution remains serial.

For a 513-transaction block, the removed native ID-vector payload copies are
32,832 legacy bytes or 49,248 witness bytes. This is a source-attributed byte
count (32-byte IDs times two or three vectors), not a dynamic memcpy counter.
Container-size changes can also affect total requested heap bytes in the
window path. Hashing, Merkle reduction and independent raw-byte verification
are unchanged; no reduction in their invocation counts is claimed.

[Manifest](data/block-facts-transfer-20261017/manifest.json) and
[summary](data/block-facts-transfer-20261017/summary.json) retain both binary
hashes, source commits, all identities, quantiles and per-run medians. The
same directory holds the six `baseline-{1,2,3}.jsonl` /
`candidate-{1,2,3}.jsonl` stdout files. All six processes exited zero; all 420
sample/warmup executions reached their exact expected tip. Each arm/cell has
18 timed samples and three excluded warmups, with the quantile method above.
Fixture-ingress allocation metrics are unchanged. No outliers are removed.

The two added corpora cover regtest heights 101..116, with 16 blocks each:
502,048 raw bytes for legacy and 4,836,944 for witness. Bootstrap, configuration,
durability, allocator and pinning follow the earlier cells; fixtures and
header admission remain outside apply timing.

Incremental apply allocation results, p50 per measured block group:

| Corpus / mode | Events baseline -> candidate | Requested bytes baseline -> candidate |
| --- | ---: | ---: |
| Early / commit | 3,546 -> 3,482 | 2,400,142 -> 2,398,094 |
| Early / sync | 2,944 -> 2,880 | 2,539,798 -> 2,531,350 |
| 512-input legacy / commit | 69,844 -> 69,812 | 22,317,788 -> 22,315,740 |
| 512-input legacy / sync | 69,682.5 -> 69,650.5 | 26,488,086 -> 26,482,838 |
| 512-input witness / commit | 86,966.5 -> 86,918.5 | 36,259,680 -> 36,256,608 |
| 512-input witness / sync | 86,852 -> 86,804 | 40,431,530 -> 40,425,258 |
| 512-transaction legacy / commit | 191,510 -> 191,478 | 47,806,476 -> 47,281,164 |
| 512-transaction legacy / sync | 199,540 -> 199,508 | 56,798,942 -> 56,270,430 |
| 512-transaction witness / commit | 218,222 -> 218,174 | 61,669,223 -> 60,881,255 |
| 512-transaction witness / sync | 226,300 -> 226,252 | 71,449,657 -> 70,658,489 |

For the added corpora, direct connect removes exactly the vector payload
totals above; BlockSync removes a further 3,200 requested bytes, consistent
with its smaller parse/prepared containers. Counters do not type-tag these
additional allocations.
The repeated high-transaction BlockSync requested-byte counts are stable to
within one 1,520-byte background event for legacy and exact for witness.
Removed events match two vectors per block, or three with witness. These
counts show an allocation/copy reduction, not a measured RSS reduction.

Diagnostic apply wall in milliseconds (18 samples per arm/cell):

| Corpus / mode | Baseline p50 | Baseline p95/p99/max | Candidate p50 | Candidate p95/p99/max |
| --- | ---: | ---: | ---: | ---: |
| Early / commit | 154.580 | 368.066 | 361.181 | 439.715 |
| Early / sync | 19.772 | 28.532 | 24.911 | 34.141 |
| 512-input legacy / commit | 292.953 | 365.198 | 341.422 | 420.434 |
| 512-input legacy / sync | 178.757 | 205.985 | 178.749 | 202.585 |
| 512-input witness / commit | 447.565 | 497.412 | 446.412 | 484.005 |
| 512-input witness / sync | 273.705 | 329.374 | 272.029 | 566.347 |
| 512-transaction legacy / commit | 394.234 | 456.932 | 394.331 | 474.119 |
| 512-transaction legacy / sync | 233.617 | 256.372 | 231.207 | 241.216 |
| 512-transaction witness / commit | 505.256 | 560.407 | 495.391 | 530.411 |
| 512-transaction witness / sync | 337.412 | 523.477 | 337.924 | 409.575 |

**The timing/non-regression gate did not pass.** Early direct-commit pooled
p50 regresses about 2.34x; its baseline run medians are 145.398 / 139.034 /
357.373 ms, versus candidate 140.328 / 365.961 / 368.488 ms. Other stability,
median and tail guards also fail. These delays have not been causally
attributed and cannot be discarded or dismissed to qualify this change.
Release-profile and whole-node qualification remain outstanding despite
reproducible allocation savings and passing functional tests.

## Regression evidence

After fact transfer, the native selection passed 72 tests: 47 consensus
library, 11 borrowed-fact boundary, five parse/golden parity, four shared
sighash, two engine-selection and three witness/sigop activation cases.
The parse-parity tests now consume the handoff and compare IDs, count, weight
and Merkle results against independent rust-bitcoin/golden fixtures. Existing
witness-only mutation, malformed layout, same-block spend, error-order and
activation oracles remain. The chainstate native/fjall library suite passed
132 tests. Strict Clippy covered consensus, chainstate and node with all test
and benchmark targets; formatting passed. The Linux kernel gate includes
parse parity alongside the existing library/shared-sighash/oracle cases.
On `6d8d90bd0`, the [kernel-feature job](https://github.com/gosuda/bitcoin-rs/actions/runs/39021308739/job/117363563464)
passed 71 selected tests and consensus/script kernel Clippy. The
[full-node job](https://github.com/gosuda/bitcoin-rs/actions/runs/39021308739/job/117363563268)
also passed Clippy with rocksdb/fjall/redb/kernel and all targets. These are
functional/feature-build results, not IBD or kernel performance evidence.

For prevout transfer, the existing shared-sighash boundary tests now cover
both borrowed and owned constructors: count before identity checks, swapped
and foreign outpoints, valid inputs, and typed input-index bounds. The signed
fixture compares the owned block-preparation path with the borrowed
transaction API and independently generated ECDSA/SegWit/Taproot signatures,
including ordered failures. Existing block/unit tests retain script-before-
post-error, earlier-transaction precedence and same-block spend behavior.

The native consensus/script selection passed 86 tests (47 consensus library,
25 script library, four shared-sighash, four Core-vector and six Taproot-rule
tests). Chainstate's 132-test native/fjall library suite also passed after the
ownership change. The capacity-shrink follow-up passed the four shared-sighash
tests and strict consensus/script Clippy. The chainstate fixture helper now
propagates mining errors, fixing the previous CI `expect_used` failure; strict
chainstate Clippy included its test targets. The existing Linux merge gate
also runs consensus library and shared-sighash tests with `kernel`, so it
executes owned block preparation alongside borrowed-API oracle parity.
Its [kernel-consensus job](https://github.com/gosuda/bitcoin-rs/actions/runs/39020717179/job/117361819657)
passed on `e5bf79eb3`: consensus/script kernel Clippy, the library and
shared-sighash cases, kernel oracle parity and script Core vectors. This is
correctness/compile evidence, not kernel performance or whole-node evidence.

The new owner-local `connect::tests` regression rejects equal-length
raw/decoded witness disagreement before commit, checks exact persisted and
returned bytes, rejects a matching-raw invalid body without advancing the
tip, then disconnects and reconnects through the no-raw fallback. It runs for
each compiled supported validation engine; this local run compiled native.
It is not a process-restart test.

The native fjall chainstate library suite passed 132 tests, including existing
checkpoint, replay/reopen, crash/failure and window tests. The shared-sighash
integration suite passed four tests. Strict Clippy covered the new node bench
and chainstate library; formatting passed. Existing CI/reference and daemon
journeys remain their own proof owners.
