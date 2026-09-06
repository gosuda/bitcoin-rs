# Validation default contract

The node validates natively by default. `bitcoinkernel` is an explicit
opt-in oracle and is never a silent fallback.

## Clauses

### `VAL-01`: Native strict-Rust validation is the default

- The library, binary, and released image build with native Rust
  validation by default.
- `bitcoinkernel` is not built into the default artifact. It is an
  opt-in feature.
- Default builds compile with `--no-default-features --features fjall` and
  carry no kernel dependency in the binary's transitive graph.
- The default validation path is `crates/consensus` and `crates/script`
  using the strict-Rust cryptography from `crates/script`.

### `VAL-02`: `bitcoinkernel` is an explicit oracle

- The `bitcoinkernel` crate is an oracle used only for differential
  comparison, not for consensus authority.
- Native and oracle artifacts are built independently, with separate
  `CARGO_TARGET_DIR` and distinct artifact identities.
- A kernel result never overrides a native result except in an explicit
  comparison mode. The kernel result is not published as a chain
  authority.
- The kernel feature requires an explicit operator choice. It is not
  enabled by any default profile.

### `VAL-03`: Promotion is measured and reversible

- The `g19_validation_default` gate flips from kernel to native only after
  all of the following hold:
  1. Native parsing, identifier, weight, and Merkle computation match the
     oracle for the full pinned replay and invalid corpora.
  2. Full contextual and script parity is achieved against the pinned
     Core 31.1 reference with zero unexplained mismatches and counted
     exclusions.
  3. The strict-Rust cryptographic path passes full signed-spend apply
     measurement and independent vector verification.
  4. Stable signed-spend and full-replay evidence is regenerated on the
     actual final strict artifact; earlier candidate results are not
     reused.
- The binary, library, and image defaults flip together with matching
  manifests and packaging in one changeset.
- `g19` verdict flips only with evidence recorded in
  `docs/benchmarks/native-validation-default.md`.

## Proven by

- `bin/bitcoin-rs/tests/gates/g19_validation_default.rs` (existing): owns
  the default promotion verdict.
- `bin/bitcoin-rs/tests/overhaul_default_closure.rs` (planned): proves the
  default binary, library, and image are transitively kernel-free and that
  the oracle remains explicitly available.
- `crates/script/tests/overhaul_native_crypto.rs` (planned): strict-Rust
  cryptography, including ECDSA, Schnorr, and Taproot boundary vectors.
- `crates/consensus/tests/overhaul_consensus_matrix.rs` (planned): full
  contextual and script parity against the Core 31.1 reference.
- `crates/consensus/tests/overhaul_parse_parity.rs` (planned): one-pass
  native identifier, weight, and Merkle parity with the oracle.
- `docs/benchmarks/native-crypto-decision.md` (planned): records the T16
  strict-Rust cryptographic decision and signed-spend measurement.
- `docs/benchmarks/native-validation-default.md` (planned): records the
  measured T17 promotion verdict and the kernel-free closure evidence.

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md):
strict-Rust validation, oracle, default promotion.
