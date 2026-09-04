# Hot-path attribution

The normative owner of how product-domain wall time is attributed. The
ledger file is the owner of inventory, overlap groups, and dispositions.
This page does not record measured seconds.

Owners:
- Method: this page (`HPA-01`–`HPA-11`)
- Inventory and dispositions: `docs/benchmarks/hot-path-ledger.toml`
- Proof: `bin/bitcoin-rs/tests/gates/g18_hot_path_ledger.rs`

The 2.0× speed gate and the 36-cell denominator live in issues #33 and
#45. This contract does not change either.

## Clauses

### `HPA-01`: Frozen 36-cell denominator

- A product cell is one coordinate of the cartesian product frozen by
  #45: domain × corpus × native architecture × backend.
- Domains: `offline` (full-validation chainstate construction), `p2p`
  (controlled loopback initial sync), `muhash` (production full-UTXO
  MuHash RPC query).
- Corpora: `c150` and `cmodern`.
- Architectures: native `x86_64` and native `arm64`.
- Backends: `fjall`, `rocksdb`, `redb`.
- That product is exactly 36 cells. Allocator variants, scalar/AVX2
  builds, source forms, test networks, pruning experiments,
  microbenchmarks, and `mdbx` are diagnostics. They are not cells and
  cannot replace a cell.
- For `muhash`, the backend coordinate is how the identical committed
  state was constructed, checkpointed, reopened, and served. The live
  scan traverses the in-memory `UtxoSet`.

### `HPA-02`: Frozen trial protocol

- Attribution rides the statistical protocol already frozen in #44:
  seven valid interleaved Core 31.1 / bitcoin-rs pairs per cell, schedule
  hashed before execution, no optional stopping, no outcome-based
  rejection.
- Primary cell speed remains `median(C1..C7) / median(B1..B7)`.
  Attribution never replaces that ratio.
- Whole-run wall time is the external monotonic interval defined by the
  domain comparator (#46 offline, #35 P2P, #41 MuHash). Internal stage
  histograms cannot supply or alter primary wall time.

### `HPA-03`: Frozen attribution noise floor

- Freeze now, before any attribution number is admitted: a cell's
  bitcoin-rs noise floor is the observed range of its seven valid
  bitcoin-rs walls, `max(B1..B7) - min(B1..B7)`.
- A disable/neutralize delta, or an unclassified residual, is
  above-noise only when its absolute value exceeds that range.
- Until those seven walls exist for a cell, the noise floor is
  `unobserved`. An unobserved floor cannot classify a cost as small, and
  cannot hide a residual as within noise.
- Do not introduce a percentage, sigma, or IQR materiality rule after
  seeing data.

### `HPA-04`: Overlap-aware wall account

- Every ledger row names a parent interval and a concurrency group.
- Nested child inclusive time is never added to its parent. Parallel
  workers in one concurrency group contribute the group span, not the
  sum of worker walls.
- The exclusive account of a cell is the overlap-aware union of
  exclusive leaves under `cell.wall`. The residual is `cell.wall` minus
  that union. The residual is a named field; it is never stored as
  `other`.
- Existing `metrics::histogram!` names in the ledger are diagnostic
  hooks. They are nested. They are not addends.

### `HPA-05`: One ledger

- `docs/benchmarks/hot-path-ledger.toml` is the only inventory of
  measured product hot paths, cost classes, known levers, and forbidden
  probes.
- A row records applicability, custody, wall contribution,
  disable/neutralize delta, overlap, affected cells, and disposition.
- Shared versus backend-, corpus-, domain-, or architecture-specific
  grouping is derived from applicability. Do not keep a parallel table.
- A measured wall contribution or disable delta requires a custody
  digest. Unmeasured is the default.

### `HPA-06`: Forbidden product-weakening probes

- These mutations cannot supply a comparator result: assume-valid script
  skip, skipping Merkle or witness checks, a dummy UTXO mutator,
  suppressing undo or body writes, weakening durability, dropping the
  MuHash stable-view lock, replacing UTXO decode or MuHash arithmetic
  with constants, or suppressing checkpoint/recovery/reopen work.
- A source-level disable experiment must preserve full validation,
  durable checkpoint, reopen, body/undo/index readiness, state
  commitment, and reorg-readiness. Otherwise the row stays
  `blocked_pending_safe_probe`.

### `HPA-07`: Disposition enum

Every repeatable above-noise cost, and every named lever, uses exactly
one of:

- `optimize` — attributed cost large enough to move a product cell;
  next step is a product-safe change plus fresh whole-workload
  remeasurement of every affected cell.
- `already_bounded` — measured, and either too small to move a cell or
  already at a measured optimum.
- `blocked` — a product-safe probe, host, corpus, or comparator is
  missing; the evidence field names the blocker.
- `rejected` — a product-safe probe or measurement refuted the lever;
  the evidence field names the result.

`other`, omission because a larger cost exists, and dismissal because a
cell already exceeds 2.0× are not dispositions.

### `HPA-08`: Residual honesty

- Every one of the 36 cells has a residual field.
- A residual may be recorded as within the noise floor only after that
  cell's seven bitcoin-rs walls exist and the overlap-aware exclusive
  union has been subtracted from whole-run wall.
- `unmeasured` means the residual is the whole unattributed wall. It is
  not within noise.

### `HPA-09`: Diagnostics are not cells

Criterion targets, allocator A/B arms, SIMD microbenchmarks, and
historical campaign artifacts diagnose mechanisms. They cannot satisfy a
product cell, and they cannot be copied into the ledger as wall
contribution without new product-cell custody.

### `HPA-10`: Campaign candidate rule

A mechanism becomes an `optimize` candidate only when a product-safe
disable/neutralize delta on total product wall exceeds the cell noise
floor in `HPA-03`. Historical stage sums and isolated-stage speedups
are not that delta.

### `HPA-11`: Completeness does not close the speed gate

Attribution completeness does not alter the fixed 36-cell speed
denominator. No candidate may rely on weaker consensus, validation,
durability, recovery, body availability, cache posture, or index
posture.

## Proven by

- `bin/bitcoin-rs/tests/gates/g18_hot_path_ledger.rs`
  (`cargo test -p bitcoin-rs --test g18_hot_path_ledger`)
