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
  imported from `rust-bitcoin/qa-assets`, CC0-1.0, minimized with `cargo fuzz cmin`).
- **Scope**: seeds under `fuzz/corpus/` feeding fuzz targets
  `fuzz/fuzz_targets/p2p_message.rs`, `block_decode.rs`, `tx_decode.rs`, and
  `script_eval.rs`.
- Provenance rows must be updated in the same commit as any corpus re-import via
  `scripts/import-qa-assets.sh`.

### `QAC-02`: End-state evidence roles

- G0 pins: the pinned `rust-bitcoin/qa-assets` commit and the minimized seed
  set are recorded in `fuzz/CORPUS_PROVENANCE.md` and mirrored by the
  reference set. The identity is a commit hash and a manifest digest, not a
  repository tag alone.
- G5 replay and parity arms: the QA corpus feeds parser, transaction, block,
  P2P message, and script-evaluation fuzz targets. Invalid and
  nonstandard-but-consensus-valid inputs are counted and classified.
- G6 policy and admission: the `script_eval` and `tx_decode` targets exercise
  standardness and admission edge cases in addition to consensus decoding.

### `QAC-03`: Importer acquisition and provenance publication

After the setup contract in `CONSTRAINTS.md` succeeds, `scripts/import-qa-assets.sh`
uses fail-closed acquisition and publication semantics:

- the pinned upstream commit check, clone-size measurement, each corpus
  minimization, and the UTC import timestamp must succeed; a nonzero tool status
  is not hidden by valid output from that tool;
- provenance is not replaced until mapping and all four minimization commands
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
- `bin/bitcoin-rs/tests/overhaul_reference_set.rs` (planned): G0 pin; rejects
  a QA corpus with a missing or mismatched upstream commit.
- `crates/consensus/tests/overhaul_consensus_matrix.rs` (planned): G5 arm;
  counts and classifies invalid corpora with fixed skip reasons.
- Fuzz targets executed via `cargo fuzz run <target> -- -runs=10000` (see
  [fuzz/README.md](../../fuzz/README.md)).

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
QA corpus, fuzz target.
