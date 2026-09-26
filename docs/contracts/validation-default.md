# Validation default contract

The owner of which script engine the production path uses, and of the
measured decision that is required to change it. A Rust constant is not promotion evidence.

Capability is not selection. The `kernel` Cargo feature means "bitcoinkernel
support is compiled into this build"; it never selects an engine. Selection is
one runtime setting, `validation.engine = "native" | "kernel"`
(`validation_engine` in TOML, `BITCOIN_RS_VALIDATION_ENGINE`,
`--validation-engine`), resolved once in `crates/node/src/config.rs`
(`ValidationConfig.engine`, default `ValidationEngine::Native`) and passed
down to every seam that dispatches between the script backends.

Owners:
- `crates/consensus/Cargo.toml`, `crates/chainstate/Cargo.toml`,
  `crates/node/Cargo.toml`, `bin/bitcoin-rs/Cargo.toml`
- Engine selection: `crates/consensus/src/engine.rs`, `crates/node/src/config.rs`
- Decision evidence: `docs/benchmarks/native-validation-default.md`

## Clauses

### `VAL-01`: Capability is not selection; defaults are kernel-free

- `bitcoin-rs-consensus` and `bitcoin-rs-chainstate` default features are
  `[]`; `bitcoin-rs-node` defaults to `fjall`, `zmq`. None include `kernel`:
  a plain build of any of the three compiles no bitcoinkernel support and
  needs no C++ toolchain.
- `validation.engine` selects the engine at runtime, default `native`. The
  `kernel` selection requires a `--features kernel` build; on any other build
  it is rejected during configuration validation with an unsupported-build
  error, never by silent engine substitution.
- Switching the production default engine is a measured decision under the
  promotion evidence below, not a manifest edit: the evidence gates keep or
  move that default (Core-vector parity, signed-spend **apply-path** native
  median vs the pinned kernel median with both arms inside five percent of
  their own three-run median, and the end-to-end full-mainnet replay wall
  owned by #34. #42 froze the C150/Cmodern corpus contracts; that freeze does
  not run the comparator).
- The signed-spend Criterion target times `NodeState::apply_block`. It is the
  in-tree engine comparison that can run without the held corpus. It is not a
  CLI/P2P wall and does not substitute for the missing replay cell. A failed,
  unavailable or unstable measurement leaves the current default engine in
  place.

### `VAL-02`: Native interpreter is the complete portable engine

- `Interpreter::execute` / `execute_with_prevouts` in
  `crates/script/src/interpreter.rs` verify every consensus spend class:
  legacy and P2SH through `eval::eval_script`, SegWit v0 through BIP143,
  Taproot key-path and script-path through local BIP341/BIP342.
- `crates/consensus/src/verify_tx.rs` routes that path through
  `verify_input_script_native`, which is compiled in every build — including
  `kernel` builds, where `validation.engine = "native"` still reaches it.
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
- `crates/consensus/tests/kernel_block_parity.rs`:
  `script_verdict_parity` (Taproot key-path differential),
  `differential_is_non_vacuous` (script-path non-vacuity).
- Manifests: `crates/consensus/Cargo.toml` and
  `crates/chainstate/Cargo.toml` `default = []`,
  `crates/node/Cargo.toml` `default = ["fjall", "zmq"]`,
  `bin/bitcoin-rs/Cargo.toml` `default = ["fjall", "redb", "zmq"]`.
