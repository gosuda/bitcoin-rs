# QA corpus contract (pointer)

[fuzz/CORPUS_PROVENANCE.md](../../fuzz/CORPUS_PROVENANCE.md) owns fuzz seed provenance.
That document is the owner.
It records the upstream corpus, the pinned commit, the license, the per-target mapping, and the refresh rule.
This page places the document under the [contracts precedence rule](README.md).
This page states the end-state evidence roles.

## Clauses

### `QAC-01`: Fuzz seed provenance and corpus maintenance

- **Owner**: `fuzz/CORPUS_PROVENANCE.md` owns fuzz seed provenance.
- Importers import seeds from `rust-bitcoin/qa-assets` (CC0-1.0), `bitcoin/bitcoin` (MIT), and `btcsuite/btcd` (ISC) reference corpora.
- Importers minimize seeds with `cargo fuzz cmin`.
- **Scope**: Seeds under `corpus/<target>/` in the companion repository [`gosuda/bitcoin-rs-fuzz-corpus`](https://github.com/gosuda/bitcoin-rs-fuzz-corpus).
- Seeds feed fuzz targets `fuzz/fuzz_targets/p2p_message.rs`, `block_validate.rs`, `tx_validate.rs`, `script_eval.rs`, and `utxo_snapshot.rs`.
- The companion corpus repository is the single seed home.
- This repository keeps no committed `fuzz/corpus/`.
- A local `fuzz/corpus/` overlay stays untracked for ad-hoc runs.
- Each upstream source has its own record section in the provenance document.
- `scripts/import-reference-corpora.sh` owns and refreshes the `## Reference corpora` section.
- Importers write into the corpus repository checkout pointed at by `FUZZ_CORPUS_DIR`.
- The default value is a sibling checkout named `bitcoin-rs-fuzz-corpus`.
- Importers MUST refuse to run when that directory is absent.
- Importers MUST NOT silently republish into this repository.
- `scripts/fuzz-policy.sh` owns `FUZZ_MAX_SEED_BYTES`.
- This parameter is the input-size bound shared by QA import and scheduled corpus evolution.
- The provenance document publishes the current value and MUST NOT own a second copy.
- Maintainers MUST update provenance rows in the same commit as any corpus re-import via `scripts/import-qa-assets.sh` or `scripts/import-reference-corpora.sh`.

### `QAC-04`: Published seed-file permissions

- Published corpus seed files created by the importer MUST use repository-readable mode `0644`.
- This permission applies regardless of the caller umask.
- This mode is a publication contract for shared checkouts.
- It does not claim crash durability.
- It does not define permissions for unrelated generated files.

### `QAC-02`: End-state evidence roles

- G0 pins: `fuzz/CORPUS_PROVENANCE.md` records the pinned `rust-bitcoin/qa-assets`, `bitcoin/bitcoin`, and `btcsuite/btcd` commits and minimized seed set.
- Reference-set digests identify replay corpora separately.
- The fuzz-source identity is its upstream commit pins, not a repository tag alone.
- G5 replay and parity arms: The QA corpus feeds parser, transaction, block, P2P message, and script-evaluation fuzz targets.
- Test runs MUST count and classify invalid and nonstandard-but-consensus-valid inputs.
- G6 policy and admission: The `script_eval` and `tx_validate` targets exercise standardness and admission edge cases in addition to consensus decoding.

### `QAC-05`: Native-consensus-codec round-trip over corpus seeds

- **Owner**: `crates/primitives/tests/differential.rs` enforces the contract over `tx_validate` and `block_validate` seeds.
- The harness reads seeds from `BITCOIN_RS_FUZZ_CORPUS/<target>`.
- The variable names the companion repository `corpus/` directory.
- A checkout-root value is wrong and causes the gate to skip.
- When the variable is unset, the harness reads from a local `fuzz/corpus/<target>/` overlay.
- The gate skips with a notice only when no corpus directory exists.
- Other `read_dir` failures MUST surface as test failures.
- The companion repository is the authoritative verdict record.
- When `<corpus>/verdicts.json` exists, the gate checks every seed against its pinned per-seed verdict in both directions.
- An unlisted seed fails.
- A listed seed absent from the corpus fails.
- A changed verdict fails.
- A decoder change that silently flips a classification (rejected or accepted, or a different rejection kind) surfaces here rather than drifting.
- `CORPUS_VERDICTS_WRITE=1` regenerates `verdicts.json` from observed verdicts.
- The publish-corpus job runs this documented maintenance route after it applies campaign output.
- The gate degrades to the verdict-shape check alone and reports the downgrade when `verdicts.json` is absent.
- This condition applies to a local overlay or to an early corpus checkout.
- Every seed MUST satisfy the pinned verdict shape:
  - `accepted`: The native consensus codec decodes the seed under the exact-consume `deserialize` entry the wire codec uses. The codec re-encodes it byte-identically.
  - `rejected:<kind>`: The native codec rejects the seed with a typed error (`end_of_data`, `varint`, `invalid_segwit_flag`, `superfluous_witness`, `trailing_bytes`).
- The `superfluous_witness` family is the documented exception class of this contract.
- A BIP144 marker/flag with an all-empty witness section cannot re-encode byte-identically.
- The codec rejects it before the lock time, at the same check position as Core and rust-bitcoin.
- A seed that decodes to neither verdict (an untyped error or a panic) MUST fail the gate regardless of `verdicts.json` presence.

### `QAC-03`: Importer acquisition and provenance publication

`scripts/import-qa-assets.sh` and `scripts/import-reference-corpora.sh` verify that required tools are available and create isolated staging paths.
Both scripts implement the importer pattern described below.
Setup failures propagate the failing tool status and remove any staging path before acquisition begins.
After setup succeeds, the importer uses fail-closed acquisition and publication semantics:

- The pinned upstream commit check, clone-size measurement, each corpus minimization, and the UTC import timestamp MUST succeed.
- A nonzero tool status MUST NOT be hidden by valid output from that tool.
- Provenance is not replaced until mapping and all minimization commands have succeeded.
- A refresh is written to a same-directory staging file and completed successfully.
- The script sets repository-document mode `0644` on the file.
- The script then atomically replaces the `fuzz/CORPUS_PROVENANCE.md` directory entry.
- A failed provenance write, mode change, or replacement preserves the prior destination.
- A destination symlink is replaced as an entry rather than followed.
- A destination directory is not treated as a container.
- Normal exit and `HUP`/`INT`/`TERM` cleanup remove clone/provenance staging.
- Signal exits use the shell convention `128 + signal`.
- These guarantees are process-level failure atomicity.
- They do not claim `fsync` or power-loss durability.
- They do not claim one transaction spanning corpus files and provenance.

Injected numeric statuses in regression tests are sentinels used to prove nonzero-status propagation.
They are not stable public status-code assignments.

## Verification boundaries

Corpus/schema tests exercise malformed, incomplete, mismatched, and unbound evidence, including custody and bounded input handling.
A fixture/schema check does not certify a measured campaign or a missing external result.

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
native protocol primitives, native Rust interpreter.
