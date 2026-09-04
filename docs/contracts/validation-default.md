# Validation default contract

The owner of which script engine the production path uses, and of the
recorded #213 promotion verdict that is allowed to change it.

Owners:
- `crates/consensus/Cargo.toml`, `crates/node/Cargo.toml`,
  `bin/bitcoin-rs/Cargo.toml`
- Gate: `bin/bitcoin-rs/tests/gates/g19_validation_default.rs`
- Decision evidence: `docs/benchmarks/native-validation-default.md`

## Clauses

### `VAL-01`: Library default is native; `kernel` is an oracle feature

- `bitcoin-rs-consensus` and `bitcoin-rs-node` default features do not
  include `kernel` while the recorded verdict in `g19_validation_default.rs`
  is `PromoteNative`.
- Production apply is always the native Rust path: decode once, hash each
  transaction once (from preserved wire bytes when present, otherwise from
  the decoded `Tx`), verify scripts through `Interpreter` with a shared
  `SighashCache`. Enabling `--features kernel` compiles `libbitcoinkernel`;
  it does not replace that path or feed kernel-owned data into apply.
- The verdict may move back to `KeepKernel` only together with those two
  manifests putting `kernel` in `default` again. That would reintroduce a
  C++ execution backend and is not the intended architecture.

### `VAL-02`: Native interpreter is the complete production engine

- `Interpreter::execute` / `execute_with_prevouts` / `execute_cached` in
  `crates/script/src/interpreter.rs` verify every consensus spend class:
  legacy and P2SH through `eval::eval_script`, SegWit v0 through BIP143,
  Taproot key-path and script-path through local BIP341/BIP342.
- `crates/consensus/src/verify_tx.rs` always routes scripts through
  `verify_input_script_portable`. The `kernel` feature does not change that
  dispatch.
- Core `script_tests.json`, `tx_valid.json`, and `tx_invalid.json` native
  columns pin zero mismatches on **runnable** rows in
  `crates/script/tests/core_vectors.rs`, and pin skip counts **and**
  skip-reason allow-lists so a silent coverage shrink cannot stay green.
  The only accepted `script_tests` skip is a one-string prose/section
  header; the only accepted `tx_invalid` skip is `BADTX` (fails
  `CheckTransaction` before script verification). `tx_valid` accepts no
  skips.

### `VAL-03`: Default binary and image stay kernel-free

- `bin/bitcoin-rs` default features are `fjall`, `redb`, and `zmq`. They
  never include `kernel`.
- The Compose image (`Dockerfile`) builds `--features fjall`.
- `--features kernel` compiles the independent Core oracle. `--verify-kernel`
  (env `BITCOIN_RS_VERIFY_KERNEL`, toml `verify_kernel`) sends the same
  Rust-owned inputs to Core and compares accept/reject only: block parse
  and txids from the preserved wire bytes, then script verdicts from the
  already-resolved Rust prevouts. Turning it on must not become an
  alternative apply implementation.

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
- Manifests: `crates/consensus/Cargo.toml` `default = []`,
  `crates/node/Cargo.toml` `default = ["fjall", "zmq"]`,
  `bin/bitcoin-rs/Cargo.toml` `default = ["fjall", "redb", "zmq"]`.
