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
- Preparation validates the prevout count and each row's outpoint against the
  corresponding transaction input before script evaluation. A mismatch is a
  caller-wiring error, not a script verdict; the native owner retains cloned
  outputs against an immutable borrowed transaction after this check.
- Core `script_tests.json`, `tx_valid.json`, and `tx_invalid.json` native
  columns pin zero mismatches on **runnable** rows in
  `crates/script/tests/core_vectors.rs`, and pin skip counts **and**
  skip-reason allow-lists so a silent coverage shrink cannot stay green.
  The only accepted `script_tests` skip is a one-string prose/section
  header; the only accepted `tx_invalid` skip is `BADTX` (fails
  `CheckTransaction` before script verification). `tx_valid` accepts no
  skips.

### Native Taproot witness rules

- Bare P2TR is recognized in the existing witness-program path when witness
  verification is active. Taproot verification runs only with its activation
  flag. A recognized v1/32-byte program before activation succeeds even with
  `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`; wrapped v1 and other program sizes
  retain their upgradeable-program policy. The former generic-version path
  incorrectly applied that policy to inactive native P2TR. ScriptSig push-only and script
  evaluation errors precede the native-witness empty-scriptSig check. A
  push-only nonempty scriptSig fails `WITNESS_MALLEATED` for both key-path and
  script-path spends.
- Key-path and tapscript signatures use the same native Schnorr checker.
  A 64-byte key-path signature selects `SIGHASH_DEFAULT`; a 65-byte signature
  must append one of `01`, `02`, `03`, `81`, `82`, or `83`. An appended `00`
  is forbidden, and malformed suffixes/sizes fail before signature verification.
  Annex handling remains per input and enters the existing BIP341 sighash.
- After script-path commitment and leaf-version checks, the existing opcode
  parser scans tapscript for `OP_SUCCESS`. Success bypasses initial stack count
  and element limits, evaluation, and final truth/clean-stack checks. A malformed
  push before success fails; bytes inside pushes are not opcodes. Policy's
  `DISCOURAGE_OP_SUCCESS` fails before stack limits. This corrects the former
  placement inside evaluation, after initial bounds and before final checks,
  which incorrectly rejected consensus-valid success paths.
- This corrects the previous native P2TR fast path, which bypassed scriptSig
  validation and passed all 65 bytes to a 64-byte Schnorr parser. Previously
  accepted nonempty-scriptSig spends are rejected; correctly signed nondefault
  hash modes are accepted. Network activation heights, flag definitions and
  the selected default validation engine are unchanged.
- `crates/script/tests/taproot_spend_rules.rs` uses rust-bitcoin-produced
  signatures and control blocks against both native complete-prevout entry
  points, including flag activation, wrapped-v1 and error-order cases.
  `overhaul_process_harness::taproot_spend_cases` compares 40 transaction
  signature/scriptSig cases and 28 `OP_SUCCESS` cases through actual
  native/Core 31.1 block validation over identical funded regtest histories.
  Block proposals isolate consensus from annex relay policy. Fixture keys exist only in test targets; no performance claim
  or production signing capability follows from these checks.

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
