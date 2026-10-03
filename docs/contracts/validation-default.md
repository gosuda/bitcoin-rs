- `Interpreter::execute_with_prevouts` and `PreparedTransaction::verify_input` in
  `crates/script/src/interpreter.rs` verify every consensus spend class:
  legacy and P2SH through `eval::eval_script`, SegWit v0 through BIP143,
  Taproot key-path and script-path through local BIP341/BIP342.
- `crates/consensus/src/verify_tx.rs` routes that path through
  `verify_input_script_native`, which is compiled in every build — including
  `kernel` builds, where `validation.engine = "native"` still reaches it.
- Block and transaction verification retain one native sighash cache and ordered
  prevout set per prepared transaction. Transaction aggregates initialize once
  across parallel input checks; script, input index, hash mode, annex and
  code-separator context remain local to each check.
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
- `--features kernel` means "bitcoinkernel support is compiled in" on the
  binary and the Compose image (`Dockerfile` builds `fjall,kernel`); it does
  not select the engine. Selection is `validation.engine = "kernel"`
  (`--validation-engine kernel`, `BITCOIN_RS_VALIDATION_ENGINE=kernel`, or
  TOML `validation_engine = "kernel"`). The shipped image selects it at the
  **config-file** layer (`/etc/bitcoin-rs/default.toml`, handed to the node
  with `--config`) so bare `docker run` keeps the historical kernel behavior
  while an environment override or a mounted config file still overrides it
  under the documented precedence (defaults -> file -> environment -> CLI).
  A CLI override replaces `CMD` wholesale under docker semantics (running
  `bitcoin-rs <args>` instead of the shipped argument list), so it must
  repeat the full `--config --data-dir --rpc-bind --p2p-listen` set.
- The kernel-free default is the C++-free quickstart. Changing the production
  default engine under `VAL-01` does not add `kernel` to any manifest default.

## Proven by

- `scripts/check-feature-matrix.sh` builds the declared feature combinations.
  Source review owns the manifest default; measurements own engine promotion.
- `crates/script/tests/core_vectors.rs`: `script_tests_native_column`,
  `tx_valid_native_column`, `tx_invalid_native_column`
  (`NATIVE_*_FAILURES = 0`, pinned skip counts and skip-reason allow-lists).
- `crates/consensus/tests/shared_sighash.rs`: concurrent transaction aggregates
  against independent digests, independently signed mixed-input checks through
  transaction and block preparation, and typed count/index failure precedence.
- `crates/consensus/tests/kernel_block_parity.rs`:
  `script_verdict_parity` (Taproot key-path differential),
  `differential_is_non_vacuous` (script-path non-vacuity).
- Manifests: `crates/consensus/Cargo.toml` and
  `crates/chainstate/Cargo.toml` `default = []`,
  `crates/node/Cargo.toml` `default = ["fjall", "zmq"]`,
  `bin/bitcoin-rs/Cargo.toml` `default = ["fjall", "redb", "zmq"]`.
