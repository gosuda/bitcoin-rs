# Validation default contract

## Current status

Promotion has **not** happened. `g19_validation_default` records `KeepKernel`.
`crates/consensus` and `crates/node` still enable `kernel` by default. The binary
is kernel-free by default; that is not evidence that all product defaults were
promoted. See the actual feature manifests and the image build separately.

### `VAL-01`: Coordinated default promotion (target)

Promote the library, binary, and released image together only after the evidence
below is complete. The target default is strict-Rust validation without a
transitive kernel dependency. `--no-default-features --features fjall` selects
a candidate build; it does not describe today's library defaults.

### `VAL-02`: Explicit oracle (target)

Keep native and kernel comparison artifacts in separate `CARGO_TARGET_DIR`s,
with distinct identities. After promotion, kernel support remains explicit and
must not silently override a native result. Today's default kernel-enabled
library path must not be described as oracle-only.

### `VAL-03`: Promotion is measured and reversible

Required evidence: parsing and contextual/script parity on the pinned valid and
invalid corpora; independently checked strict-Rust cryptographic vectors; stable
signed-spend and full-replay measurements on the final artifact; and kernel-free
closure for each promoted product. Record exclusions and unexplained mismatches.

`g19_validation_default` checks the recorded verdict against feature defaults.
It does **not** run those experiments or certify their results. Changing its
constant is not promotion evidence. Keep `KeepKernel` while required evidence is
missing or a prerequisite gate is blocked.

## Evidence owners

- `bin/bitcoin-rs/tests/gates/g19_validation_default.rs`: feature/default guard.
- `bin/bitcoin-rs/tests/overhaul_default_closure.rs`: dependency-closure checks,
  not a signed-spend benchmark.
- `crates/consensus/tests/overhaul_parse_parity.rs`: golden-fixture parity,
  not full product-replay parity.
- [Native validation decision](../benchmarks/native-validation-default.md):
  measured results, missing campaigns, and retained verdict.

The broader strict-crypto, consensus-matrix, and product promotion campaigns
remain required work, not proofs supplied by this document.
