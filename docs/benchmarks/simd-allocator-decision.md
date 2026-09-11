# SIMD, hash dispatch and allocator decisions (MERKLE-ALL)

This document owns the hash, SIMD and allocator decisions for the target node, including the MERKLE-ALL requirement: optimize Merkle for all architectures and platforms. Owner task: T37, gate G10, with T38 for cache, allocation and I/O treatments. Every prior adoption (AVX2 Merkle, mimalloc, v5 UTXO layout) stays in force as recorded in the prior-evidence section; none of it is evidence for another target.

## Decisions it owns

- Which Merkle and SHA256d kernels dispatch on which targets.
- The global allocator for each measured production configuration.
- Whether a proposed zero-copy, arena, pool or cache treatment is adopted, deferred or rejected.

## MERKLE-ALL target matrix

Every row is classified `measured`, `compile-only` or `unavailable` once T37 runs. A classification is recorded, never invented. One x86 result never proves a win on another target. Emulation is correctness evidence only; missing native hardware blocks that target's performance proof.

| Target | Classification | Portable path | Specialized kernel considered | Status |
|---|---|---|---|---|
| x86_64 Linux | `UNMEASURED` | required | AVX2 (existing), x86 SHA | `planned_not_executed` |
| x86_64 Windows | `UNMEASURED` | required | AVX2, x86 SHA | `planned_not_executed` |
| x86_64 macOS | `UNMEASURED` | required | AVX2, x86 SHA | `planned_not_executed` |
| x86_64 FreeBSD | `UNMEASURED` | required | AVX2, x86 SHA | `planned_not_executed` |
| aarch64 Linux | `UNMEASURED` | required | ARMv8 SHA2 | `planned_not_executed` |
| aarch64 Windows | `UNMEASURED` | required | ARMv8 SHA2 | `planned_not_executed` |
| aarch64 macOS | `UNMEASURED` | required | ARMv8 SHA2 | `planned_not_executed` |
| i686 Linux | `UNMEASURED` | required | none until measured headroom | `planned_not_executed` |
| i686 Windows | `UNMEASURED` | required | none until measured headroom | `planned_not_executed` |
| armv7 Linux | `UNMEASURED` | required | none until measured headroom | `planned_not_executed` |
| riscv64gc Linux | `UNMEASURED` | required | none until measured headroom | `planned_not_executed` |
| powerpc64 Linux | `UNMEASURED` | required | none until measured headroom | `planned_not_executed` |
| powerpc64le Linux | `UNMEASURED` | required | none until measured headroom | `planned_not_executed` |
| s390x Linux | `UNMEASURED` | required | none until measured headroom | `planned_not_executed` |
| wasm32-wasip1 (domain crate only) | `UNMEASURED` | required | none | `planned_not_executed` |

Any additional declared Rust release target joins this table with the same columns.

## Dispatch rules

- A portable correct implementation exists on every compilable target. `sha2 0.11.0` is the maintained library kernel.
- Architecture kernels live in small modules with documented unsafe preconditions. Runtime feature detection gates each kernel with its own guard. AVX2, x86 SHA and ARMv8 SHA2 are three independent capabilities. ARMv8 SHA2 is never implied by NEON. An unsupported instruction never executes.
- Release binaries stay portable for their declared baseline. A `target-cpu=native` build is a separate artifact with its own identity, never a generic release.
- AVX-512 is not selected because it is wider; it needs the same measured win as any other kernel.
- Each independent parent hashes a 64-byte concatenation; SHA256 padding and the second SHA pass are part of the exact kernel. Batching is across independent parents, never across bytes of one digest. At an odd level only the terminal leaf is duplicated, and equal sibling pairs are checked in the original level before the duplication so the mutation-detection flag is preserved.

## Correctness gate

`crates/consensus/tests/overhaul_hash_dispatch.rs` forces every scalar and accelerated arm and requires identical outputs at every alignment, batch tail and Merkle level, with mutation detection, odd-leaf handling, byte order and the public API unchanged. Per-kernel forcing uses the existing correctness tests; no broad runtime override framework is added.

```bash
cargo test --locked -p bitcoin-rs-consensus --test overhaul_hash_dispatch -- --nocapture
```

## Fixed-work measurement mode

The existing bench `crates/consensus/benches/merkle.rs` gains a benchmark-only fixed-work mode. With no flags it keeps its Criterion behavior. With `--fixed-work --leaves N --rounds N` it runs a deterministic preallocated input for identical total rounds in candidate and control and consumes the result black-box. No production CLI flag and no new crate.

Obtain the executable from the compiler artifact, never from a guessed hashed filename:

```bash
cargo bench --locked -p bitcoin-rs-consensus --bench merkle --no-run --message-format=json
```

Read the `executable` field of the `compiler-artifact` message, then time that exact invocation with Hyperfine:

```bash
hyperfine --warmup 1 --runs 3 '<exe> --fixed-work --leaves 16 --rounds R16' \
                             '<exe> --fixed-work --leaves 128 --rounds R128' \
                             '<exe> --fixed-work --leaves 2048 --rounds R2048'
```

Representative leaf counts are 16, 128 and 2048. Increase rounds before freezing until each run takes at least one second, then freeze the same rounds for both arms. Unequal rounds across arms, a guessed executable path or a changed default Criterion invocation fails harness review.

## End-state cells

| Cell | Owner | Status |
|---|---|---|
| Merkle root per target, fixed-work 16/128/2048 leaves, scalar versus each guarded kernel | `crates/consensus/src/sha256d64.rs` | `planned_not_executed` |
| Full-domain replay attribution of Merkle work per target | T02 replay cell | `planned_not_executed` |
| Allocator per measured production configuration (system versus mimalloc, RSS and retained bytes) | T38 | `planned_not_executed` |
| Cache, allocation and I/O treatments, one per landing, each naming its removed copy, allocation, lookup or stall | T38, recorded in `overhaul-optimization-decisions.md` when created | `planned_not_executed` |

Previous production kernels are retained until the gate passes. After the new state is published there is no silent fallback. Rejected candidates are recorded as rejected with their measured reason.

## Required identities per sample

Every sample in this cell records six identities. The T02 collector rejects a sample that lacks any of them; a rejected sample is not evidence.

| Identity | Content |
|---|---|
| Artifact | SHA-256 of the exact binary, library or image measured; source commit |
| Configuration | Resolved `NodeConfig`, feature set, allocator, validation mode |
| Corpus | Corpus digest, height range, stop height and stop hash |
| Durability | Backend, batch mode (`write`, `write_deferred`, `write_durable`), flush and sync posture |
| Toolchain | `rustc 1.95.0`, edition 2024, profile, enabled features |
| Hardware | CPU model, pinned core set, memory, storage device, OS kernel |

## Acceptance rule

- Promotion of a candidate over its control requires a median gain of at least 1.05x over at least three alternating candidate/control runs. Each arm stays within 5% of its own median. The improvement must exceed the observed host noise.
- Non-target cells guard at no more than 3% median regression and no more than 5% p99 regression, measured with repeated runs and reported uncertainty. Average-only reporting never passes.
- Report p50, p95, p99 and max with the sample count. Never sum nested intervals. Never sum concurrent intervals. Parallel worker walls and inclusive stage histograms are reported beside the process wall, not added to it.
- Retain raw samples beside every summary. A Criterion adaptive elapsed total is not a median source.
- A missing binary, corpus, hardware target or digest marks the cell `BLOCKED` with the missing identity named. `BLOCKED` is never a pass and never a skip.

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement. The section `Prior candidate evidence` below is historical and unchanged; it does not prove any end-state cell.

## Prior candidate evidence (2026-08-09 AVX2 custody, 2026-08-18 SHA comment, allocator custody)

Retained verbatim from the pre-rewrite document. Headings are demoted one level. Nothing below is end-state proof.

This note closes the architecture question in issue #40 against the evidence that
already exists. It does not report a new benchmark. A disposition applies only to
the workload and host class named with it.

### Decision rule

A **measured observation** below copies a field or result from a cited artifact.
An **inference** interprets those observations or identifies evidence that is
missing. An adoption requires a controlled treatment on the workload it changes,
a correctness check, and a benefit that pays for the extra implementation path.
Host-specific results do not transfer across instruction-set architectures.

### Disposition summary

| Lever from issue #40 | Disposition | Scope |
|---|---|---|
| AVX2 Merkle reduction | **Adopted** | Runtime-dispatched AVX2 on supported x86-64 hosts; scalar spine for small trees and unsupported hosts |
| x86 SHA-NI hashing | **Defer** | No controlled whole-domain candidate on a project measurement host |
| ARM SIMD and ARMv8 SHA acceleration | **Defer** | No ARM candidate/control custody artifact |
| Global allocator choice | **Adopt** | mimalloc for the measured x86-64 Linux production configuration; keep the system-allocator comparison arm |
| Domain arena or object pool | **Reject** | A UTXO-record arena/pool in the measured design; reconsider only with new domain attribution |
| UTXO container layout | **Adopt** | The v5 directory layout measured on the height-412,732 chainstate |
| Additional zero-copy mechanisms | **Defer** | No isolated whole-domain zero-copy treatment is recorded |

These are seven distinct decisions. In particular, adopting one x86 AVX2 kernel
does not approve an ARM implementation or a separate SHA acceleration path.

### AVX2 Merkle reduction: adopted

#### Measured observations

The AVX2 Merkle custody artifact (campaign JSON retired from the tree by
#224; the fields below are quoted from it) has schema
`bitcoin-rs-avx2-merkle-custody-v1`, capture date `2026-08-09`,
control commit `9f9eb0b5aca6bb6776cf919ee9dac8fc8843a1f2`, prepared-txids commit
`b7e56570523111ff21727887af03ad140e07d7e7`, and AVX2 commit
`65bae8dab0cbab41f2ef5d7cbc2cb906b2105643`. It identifies the control and
candidate binaries as SHA-256
`d97e429acaa2216ab1f6bfd20354f0be631a04626649be4f561c80f9b1e93e6d` and
`f48272d53b163bb46a234abcda08f680175c783c5d799ad349637e98591bf30a`.
The immutable block corpus is
`c0a2b9aa35498dacdf1aec792a1b68d9ec68e372fba88ef0e62bbccb1732fe2c`.
The scope is full validation of mainnet blocks 0 through 150,000, pinned to CPUs
0-31 with 30-second cooldowns.

The artifact records three alternating candidate/control runs per backend. Its
summary fields report:

| Backend | `wall_speedup` | `cpu_speedup` | `rss_ratio` |
|---|---:|---:|---:|
| fjall | 1.1769538561 | 1.0199408080 | 0.9785967549 |
| rocksdb | 1.1712120087 | 1.0227751842 | 1.0309185377 |
| redb | 1.1120008320 | 1.0061286277 | 0.9992814941 |

Field values in this section are quoted rounded to ten decimal places; the JSON
carries full precision.

The Merkle criterion fields record `leaves_16_speedup = 1.7882885566`,
`parents_64_speedup = 4.5644758589`, and `parents_1024_speedup =
5.5749675465`. Those ratios include the same scratch-buffer refill work in both
arms. The correctness section records `equal at every Merkle level` over blocks
0-150,000 and the same stop hash, MuHash, UTXO count, total amount, and
`hash_serialized_3` for all three backends.

#### Inference and decision

The repeated wall-time direction across three storage backends, isolated Merkle
ratios, and corpus parity justify the decision to adopt runtime-dispatched AVX2.
Production validation uses this kernel when the host and tree can fill an 8-lane
batch; otherwise the scalar spine. The CPU speedups are much smaller than the
wall speedups, so this decision does not claim that Merkle work alone caused
every whole-replay difference. The artifact does not record a CPU model or
architecture field; the AVX2 treatment itself bounds this result to AVX2-capable
x86 hosts. A scalar fallback remains part of the selected design.

### SHA acceleration: defer x86 SHA-NI and ARM SIMD

#### Measured observations

Issue #40's comment dated 2026-08-18 reports 144 ns for SHA-256 of a 22-byte
script on Apple Silicon. Multiplying that measured operation by 4,400 output
scripts gives 634 microseconds of a 995.70-microsecond Electrum scan arm. The
same comment says the tested `bitcoin_hashes 0.14` implementation had an x86
SHA-NI path and no aarch64 path. These numbers describe the scalar baseline, not
a measured accelerated candidate.

Neither AVX2 custody nor allocator custody contains an ARM candidate/control
pair. The AVX2 artifact also measures SHA256d Merkle reduction, not SHA-NI script
hashing. No cited artifact records a whole-domain ARMv8 crypto-extension or NEON
treatment.

#### Inference and decision

The comment's projected 3-5x SHA reduction and projected 996-to-520-microsecond
scan change are projections, not measurements. Position-based resolution also
changes how often that baseline hashes scripts, so a faster hashing primitive
cannot be assigned the old scan-arm share without a fresh profile. Defer both an
x86 SHA-NI project implementation and any ARM SIMD/SHA implementation until each
has its own same-host candidate/control custody. Nothing measured on AVX2 x86 is
used as evidence for ARM.

### Global allocator: adopt mimalloc for the measured production configuration

#### Measured observations

The allocator custody artifact (campaign JSON retired from the tree by #224;
fields quoted from it) has schema `bitcoin-rs-allocator-custody-v1` and source commit
`ff2615a2946cfdf980ed80ed14c0ad5986631d8a`. Its source identity is
`x86_64-unknown-linux-gnu` on an Intel Xeon Gold 6138, pinned to CPUs 0-31. The
mimalloc and system binaries have SHA-256 identities
`6e6fdb149c524f7458f7c07a7f073762964331ad0d4dc21f10f0e574b8aa583c` and
`376dbcf7dda8613bf09331941a4594b2ab05ca88feff1a3789a78ece0e32af07`.
Both arms use fjall, full validation (`assume_valid_height = 0`), the same
688,584,209-byte corpus with SHA-256
`c0a2b9aa35498dacdf1aec792a1b68d9ec68e372fba88ef0e62bbccb1732fe2c`,
and stop at height 150,000.

Across three rotated rounds, the median mimalloc arm recorded 56.1622474201 wall
seconds, 396.50481 total CPU seconds, and 664,252,416 bytes peak RSS. The system
arm recorded 63.4334685040 wall seconds, 399.627767 total CPU seconds, and
573,440,000 bytes peak RSS. The comparison fields are
`system_to_mimalloc_wall_speedup = 1.1294681288`,
`system_to_mimalloc_cpu_speedup = 1.0078762147`, and
`mimalloc_to_system_rss_ratio = 1.1583642857`. With `required_speedup = 1.05`,
`mimalloc_wall_pass` is true and `mimalloc_cpu_pass` is false. Correctness fields
match between allocator arms and against Core's MuHash, stop hash, amount, and
UTXO count.

#### Inference and decision

Adopt the artifact's `canonical_allocator = "mimalloc"` selection for this
production configuration because it clears the declared wall-time gate. Do not
describe CPU time as improved: its measured ratio misses the gate. Mimalloc also
raises median peak RSS by 15.8%, so the system arm remains necessary for memory
campaigns and future allocator decisions. This x86-64 Linux result says nothing
about the preferred allocator on ARM or another operating system.

### Domain arena or pool: reject for the UTXO record store

#### Measured observations

[`docs/benchmarks/utxo-memory.md`](utxo-memory.md) identifies its fragmentation
harness as the system allocator on Apple Silicon. At three million live outputs,
monotonic insertion used 105.7 RSS bytes/output (`RSS / accounted = 1.207x`).
Replacing 50% used 108.3 bytes/output (`1.237x`), and replacing 200% used 110.5
bytes/output (`1.263x`). The document reports a 5% RSS increase after churn equal
to twice the live set. It separately records a real chainstate at height 412,732
with 38,145,360 outputs and 10,519,335 records, but it does not claim that this
real-chainstate load is the churn experiment.

#### Inference and decision

Reject a UTXO-record arena or pool now. On the measured allocator and harness,
fragmentation did not grow enough to justify a second ownership and allocation
model. This is not a universal claim about arenas, mimalloc, or ARM: the churn
run used Apple's system allocator, while the Linux production comparison used
mimalloc. A future arena proposal needs attribution on its own production
allocator and domain workload rather than reusing the 5% result.

### UTXO container layout: adopt the v5 directory layout

#### Measured observations

The v4 and v5 arms in [`docs/benchmarks/utxo-memory.md`](utxo-memory.md) loaded
the same 2.03 GiB `utxo-v4.dat` chainstate from height 412,732 on the same
machine. That chainstate contains 10,519,335 records and 38,145,360 outputs. The
document records 11.18 payload bytes/output saved and 11.49 RSS bytes/output
saved. At the measured 3.626 outputs/record average, lookup costs about 3 ns more;
at block scale the document estimates 12 microseconds for roughly 4,000 spent
inputs. It records commit p95 increases of 3%, 8%, and 21% for the existing,
uniform, and concentrated fixtures, with the worst measured value at 2.57 ms.
Both layouts produced the same
`hash_serialized_3 = 438e59e4c0400b89cd06a5bb3623234a299ba5cf600043fb298ab345c328edfb`.

The directory layout superseded a flat-varint draft that measured 4.4-4.9x slower
on the 256-output lookup fixture. A separate `SmallVec` directory-staging attempt
measured 505.7 ns against 428.5 ns on a 16-output record and was rejected.

#### Inference and decision

Adopt the v5 directory container layout. The decision trades measured lookup and
commit cost for measured payload and isolated-set RSS reduction while preserving
the recorded chainstate digest. It is not a full-node tip-RSS claim:
`utxo-memory.md` explicitly says the load excludes fjall, CoinStats, the block
record log, and the runtime. The A-B-A commit benchmark and isolated chainstate
load also do not prove how much v5 changes end-to-end sync wall time.

### Additional zero-copy mechanisms: defer

#### Measured observations

The AVX2 criterion includes identical scratch-buffer refill overhead in scalar
and candidate arms. Its prepared-txids scalar attribution is one recorded run
(`wall_seconds = 51.9746711040`, `total_cpu_seconds = 388.264416`,
`prepare_seconds = 2.766098163`), not a paired zero-copy treatment. The UTXO v5
layout changes encoding and lookup locality; it does not provide an isolated
zero-copy arm. [`docs/benchmarks/end-to-end-sync.md`](end-to-end-sync.md) warns
that older same-range files without treatment identity are observations only and
do not establish a causal effect.

#### Inference and decision

Defer any additional zero-copy mechanism. Buffer reuse, prepared identifiers,
and denser containers may reduce copying, but the existing artifacts do not
isolate copy count or a zero-copy treatment. A proposal must name the ownership
boundary it removes, count or profile copies there, and compare the same workload
before adoption.

### Evidence boundary

This document adopts runtime-dispatched AVX2 Merkle reduction on supported x86
hosts and the v5 UTXO layout measured on the stated host and chainstate. It
keeps mimalloc as the canonical allocator for the measured x86-64 Linux
production configuration. It rejects the current UTXO arena/pool proposal and
defers SHA-specific SIMD, ARM SIMD, and additional zero-copy work. The bounded
0-150,000 replays are not live IBD or current-tip evidence; the older runs
catalogued in [`docs/benchmarks/end-to-end-sync.md`](end-to-end-sync.md) remain
historical and non-causal unless their own custody states otherwise.
