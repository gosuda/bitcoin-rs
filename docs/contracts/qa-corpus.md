# QA corpus contract (pointer)

Fuzz seed provenance is owned by
[fuzz/CORPUS_PROVENANCE.md](../../fuzz/CORPUS_PROVENANCE.md). That document
is the owner: it records the upstream corpus, the pinned commit, the
license, the per-target mapping, and the refresh rule. This page places the
document under the [contracts precedence rule](README.md) and states the
end-state evidence roles.

## Clauses

### `QAC-01`: Fuzz seed provenance and corpus maintenance

- **Owner**: `fuzz/CORPUS_PROVENANCE.md` owns fuzz seed provenance (seeds
  imported from `rust-bitcoin/qa-assets` (CC0-1.0) and from the
  `bitcoin/bitcoin` (MIT) and `btcsuite/btcd` (ISC) reference corpora,
  minimized with `cargo fuzz cmin`).
- **Scope**: seeds under `corpus/<target>/` in the companion repository
  [`gosuda/bitcoin-rs-fuzz-corpus`](https://github.com/gosuda/bitcoin-rs-fuzz-corpus),
  feeding fuzz targets `fuzz/fuzz_targets/p2p_message.rs`, `block_validate.rs`,
  `tx_validate.rs`, `script_eval.rs`, and `utxo_snapshot.rs`. The corpus repo
  is the single seed home; this repository keeps no committed `fuzz/corpus/`
  (a local `fuzz/corpus/` overlay stays untracked for ad-hoc runs). Each
  upstream source has its own run-dependent record section in the provenance
  document; the `## Reference corpora` section is owned and refreshed by
  `scripts/import-reference-corpora.sh`.
- Importers write into the corpus repo checkout pointed at by
  `FUZZ_CORPUS_DIR` (default: a sibling checkout named
  `bitcoin-rs-fuzz-corpus`); they refuse to run when that directory is
  absent rather than silently republishing into this repository.
- `scripts/fuzz-policy.sh` owns `FUZZ_MAX_SEED_BYTES`, the input-size bound
  shared by QA import and scheduled corpus evolution. Provenance publishes the
  current value; it does not own a second copy.
- Provenance rows must be updated in the same commit as any corpus re-import via
  `scripts/import-qa-assets.sh` or `scripts/import-reference-corpora.sh`.

### `QAC-04`: Published seed-file permissions

- Published corpus seed files created by the importer use repository-readable
  mode `0644`, independent of the caller's umask.
- This mode is a publication contract for shared checkouts; it does not claim
  crash durability or define permissions for unrelated generated files.

### `QAC-02`: End-state evidence roles

- G0 pins: the pinned `rust-bitcoin/qa-assets`, `bitcoin/bitcoin`, and
  `btcsuite/btcd` commits and the minimized seed set are recorded in
  `fuzz/CORPUS_PROVENANCE.md`; the reference-set digests identify replay
  corpora separately. The fuzz-source identity is its upstream commit pins,
  not a repository tag alone.
- G5 replay and parity arms: the QA corpus feeds parser, transaction, block,
  P2P message, and script-evaluation fuzz targets. Invalid and
  nonstandard-but-consensus-valid inputs are counted and classified.
- G6 policy and admission: the `script_eval` and `tx_validate` targets exercise
  standardness and admission edge cases in addition to consensus decoding.

### `QAC-05`: Native-consensus-codec round-trip over corpus seeds

- **Owner**: `crates/primitives/tests/differential.rs` enforces the contract
  over `tx_validate` and `block_validate` seeds read from
  `BITCOIN_RS_FUZZ_CORPUS/<target>` (a `gosuda/bitcoin-rs-fuzz-corpus`
  checkout) or, when the variable is unset, a local `fuzz/corpus/<target>/`
  overlay. The gate loud-skips only when no corpus directory exists.
- The corpus evolves in the companion repository — the scheduled campaign
  minimizes and grows it continuously — so the gate cannot pin per-seed
  verdicts. It pins the verdict *shape* every seed must satisfy:
  - `accepted`: the native consensus codec decodes the seed under the exact-consume
    `deserialize` entry the wire codec uses, and re-encodes it byte-identically;
  - `rejected:<kind>`: the native codec rejects the seed with a typed error
    (`end_of_data`, `varint`, `invalid_segwit_flag`, `superfluous_witness`,
    `trailing_bytes`). The `superfluous_witness` family is the documented
    exception class of this contract: a BIP144 marker/flag with an all-empty
    witness section cannot re-encode byte-identically, so the codec rejects it
    before the lock time, at the same check position as Core and rust-bitcoin.
- A seed that decodes to neither verdict — an untyped error or a panic —
  fails the gate, so a decoder change that alters verdict classification
  surfaces here rather than drifting silently.

### `QAC-03`: Importer acquisition and provenance publication

`scripts/import-qa-assets.sh` and `scripts/import-reference-corpora.sh` first
verify that their required tools are available and create their isolated
staging paths. What follows describes the importer pattern both scripts
implement. Setup failures propagate the
failing tool status and remove any staging path before acquisition begins.
After setup succeeds, the importer uses fail-closed acquisition and publication
semantics:

- the pinned upstream commit check, clone-size measurement, each corpus
  minimization, and the UTC import timestamp must succeed; a nonzero tool status
  is not hidden by valid output from that tool;
- provenance is not replaced until mapping and all minimization commands
  have succeeded;
- a refresh is written to a same-directory staging file, completed successfully,
  set to repository-document mode `0644`, and then atomically replaces the
  `fuzz/CORPUS_PROVENANCE.md` directory entry;
- a failed provenance write, mode change, or replacement preserves the prior
  destination. A destination symlink is replaced as an entry rather than
  followed, and a destination directory is not treated as a container;
- normal exit and `HUP`/`INT`/`TERM` cleanup remove clone/provenance staging.
  Signal exits use the shell convention `128 + signal`;
- these guarantees are process-level failure atomicity. They do not claim
  `fsync`/power-loss durability or one transaction spanning corpus files and
  provenance.

Injected numeric statuses in regression tests are sentinels used to prove
nonzero-status propagation; they are not stable public status-code assignments.

## Proven by

- `fuzz/CORPUS_PROVENANCE.md` (existing): records the upstream identity,
  license, per-target mapping, and refresh rule.
- `scripts/tests/test_import_qa_assets_provenance.py`: `QAC-03` acquisition,
  minimization, cleanup, mode, and failure-atomic provenance publication.
- `scripts/tests/test_import_reference_corpora.py`: `QAC-03` pinned-clone
  acquisition, per-source provenance-section refresh, authored-head
  preservation, and failure atomicity for the reference importer.
- `bin/bitcoin-rs/tests/overhaul_reference_set.rs`: G0 pin; rejects
  a corpus absent from the manifest and reports an unpinned manifest digest
  as custody-blocked (the upstream qa-assets commit is pinned by
  `fuzz/CORPUS_PROVENANCE.md`).
- `crates/consensus/tests/overhaul_consensus_matrix.rs` (planned): G5 arm;
  counts and classifies invalid corpora with fixed skip reasons.
- `crates/primitives/tests/differential.rs`: `QAC-05` gate; every
  `tx_validate`/`block_validate` seed in the external corpus must decode to a
  typed verdict, with byte-identical re-encoding of accepted seeds.
- Fuzz targets executed via `cargo fuzz run <target> -- -runs=10000` (see
  [fuzz/README.md](../../fuzz/README.md)).

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
QA corpus, fuzz target.
