# QA corpus contract (pointer)

Fuzz seed provenance is owned by
[fuzz/CORPUS_PROVENANCE.md](../../fuzz/CORPUS_PROVENANCE.md). That document
is the owner: it records the upstream corpus, the pinned commit, the
license, the per-target mapping, and the refresh rule. This page adds
nothing normative; it places the document under the
[contracts precedence rule](README.md).

## Clauses

### `QAC-01`: Fuzz seed provenance and corpus maintenance

- **Owner**: `fuzz/CORPUS_PROVENANCE.md` owns fuzz seed provenance (seeds
  imported from `rust-bitcoin/qa-assets`, CC0-1.0, minimized with `cargo fuzz cmin`).
- **Scope**: seeds under `fuzz/corpus/` feeding fuzz targets
  `fuzz/fuzz_targets/p2p_message.rs`, `block_decode.rs`, `tx_decode.rs`, and
  `script_eval.rs`.
- Provenance rows must be updated in the same commit as any corpus re-import via
  `scripts/import-qa-assets.sh`.

## Proven by

- Fuzz targets executed via `cargo fuzz run <target> -- -runs=10000` (see
  [fuzz/README.md](../../fuzz/README.md)).
