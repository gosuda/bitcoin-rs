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

- G0 pins: the pinned `rust-bitcoin/qa-assets` commit and minimized seed set
  are recorded in `fuzz/CORPUS_PROVENANCE.md`. The identity is a commit hash
  and a manifest digest, not a repository tag alone.
- G5 replay and parity arms: the QA corpus feeds parser, transaction, block,
  P2P message, and script-evaluation fuzz targets. Invalid and
  nonstandard-but-consensus-valid inputs are counted and classified.
- G6 policy and admission: the `script_eval` and `tx_decode` targets exercise
  standardness and admission edge cases in addition to consensus decoding.

## Proven by

- `fuzz/CORPUS_PROVENANCE.md` (existing): records the upstream identity,
  license, per-target mapping, and refresh rule.
- `crates/consensus/tests/overhaul_consensus_matrix.rs` (planned): G5 arm;
  counts and classifies invalid corpora with fixed skip reasons.
- Fuzz targets executed via `cargo fuzz run <target> -- -runs=10000` (see
  [fuzz/README.md](../../fuzz/README.md)).

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
QA corpus, fuzz target.
