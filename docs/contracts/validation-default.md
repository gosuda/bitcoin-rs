# Validation default contract

The owner of which script engine the production path uses, and of the
recorded #213 promotion verdict that is allowed to change it.

Owners:
- `crates/consensus/Cargo.toml`, `crates/node/Cargo.toml`,
  `bin/bitcoin-rs/Cargo.toml`
- Gate: `bin/bitcoin-rs/tests/gates/g19_validation_default.rs`
- Decision evidence: `docs/benchmarks/native-validation-default.md`

## Clauses

### `VAL-01`: Library default stays on `kernel` until promotion

- `bitcoin-rs-consensus` and `bitcoin-rs-node` default features include
  `kernel` while the recorded verdict in `g19_validation_default.rs` is
  `KeepKernel`.
- The verdict may move to `PromoteNative` only together with those two
  manifests dropping `kernel` from `default`, and only after the
  measurement gates in
  [`docs/benchmarks/native-validation-default.md`](../benchmarks/native-validation-default.md)
  all pass: Core-vector parity, signed-spend **apply-path** native median
  faster than the pinned kernel median with both arms inside five percent
  of their own three-run median, and the end-to-end full-mainnet replay
  wall owned by #34. #42 froze the C150/Cmodern corpus contracts; that
  freeze does not run the comparator.
- The signed-spend Criterion target times `NodeState::apply_block`. It is
  the in-tree engine comparison that can run without the held corpus. It
  is not a CLI/P2P wall and does not substitute for the missing replay
  cell. A failed or unstable measurement leaves `KeepKernel` in place.

### `VAL-02`: Native interpreter is the complete portable engine

- With `kernel` off, `Interpreter::execute` / `execute_with_prevouts` in
  `crates/script/src/interpreter.rs` verify every consensus spend class:
  legacy and P2SH through `eval::eval_script`, SegWit v0 through BIP143,
  Taproot key-path and script-path through local BIP341/BIP342.
- `crates/consensus/src/verify_tx.rs` routes that path through
  `verify_input_script_portable` under `#[cfg(not(feature = "kernel"))]`.
- Core `script_tests.json`, `tx_valid.json`, and `tx_invalid.json` native
  columns pin zero mismatches on **runnable** rows in
  `crates/script/tests/core_vectors.rs`, and pin skip counts **and**
  skip-reason allow-lists so a silent coverage shrink cannot stay green.
  The only accepted `script_tests` skip is a one-string prose/section
  header; the only accepted `tx_invalid` skip is `BADTX` (fails
  `CheckTransaction` before script verification). `tx_valid` accepts no
  skips.

### `VAL-03`: Default binary stays kernel-free

- `bin/bitcoin-rs` default features are `fjall`, `redb`, and `zmq`. They
  never include `kernel`.
- `--features kernel` remains the opt-in production engine on the binary
  and the Compose image (`Dockerfile` builds `fjall,kernel`).
- This split is the C++-free quickstart. Promoting native in `VAL-01`
  does not add `kernel` to the binary default.

## Proven by

- `bin/bitcoin-rs/tests/gates/g19_validation_default.rs`:
  `library_defaults_match_recorded_verdict`,
  `binary_default_excludes_kernel`,
  `kernel_feature_exists_on_each_manifest`,
  `alias_and_dep_forwarding_count_as_kernel`,
  `crate_feature_forwarding_counts_as_kernel`.
- `crates/script/tests/core_vectors.rs`: `script_tests_native_column`,
  `tx_valid_native_column`, `tx_invalid_native_column`
  (`NATIVE_*_FAILURES = 0`, pinned skip counts and skip-reason allow-lists).
- `crates/consensus/tests/kernel_block_parity.rs`:
  `script_verdict_parity` (Taproot key-path differential),
  `differential_is_non_vacuous` (script-path non-vacuity).
- Manifests: `crates/consensus/Cargo.toml` `default = ["kernel"]`,
  `crates/node/Cargo.toml` `default = ["fjall", "kernel", "zmq"]`,
  `bin/bitcoin-rs/Cargo.toml` `default = ["fjall", "redb", "zmq"]`.
