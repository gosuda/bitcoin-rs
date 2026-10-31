# Validation default contract

## Clauses

### `VAL-01`: The production default engine is a measured decision

- The production default is `native` (`validation.engine = "native"`).
- [Getting started](../getting-started.md#validation-engine) owns the option spelling and resolution order.
- A different production default requires product-cell promotion evidence under [HPA-13](hot-path-attribution.md#hpa-13-promotion-and-regression-thresholds).
- A compiled `kernel` capability, a microbenchmark, or a historical verdict does not change the default.

### `VAL-02`: The native interpreter is the complete portable engine

- `Interpreter::execute_with_prevouts` and `PreparedTransaction::verify_input` in `crates/script/src/interpreter.rs` verify every consensus spend class.
- The functions verify legacy and P2SH through `eval::eval_script`.
- The functions verify SegWit v0 through BIP143.
- The functions verify Taproot key-path and script-path through local BIP341/BIP342.
- `crates/consensus/src/verify_tx.rs` routes verification through `verify_input_script_native(prepared, input_index, flags, signature_cache)`.
- Every build compiles this function, including `kernel` builds where `validation.engine = "native"` still reaches it.
- Block and transaction verification retain one native sighash cache and ordered prevout set per prepared transaction.
- Transaction aggregates initialize once across parallel input checks.
- Script, input index, hash mode, annex, and code-separator context remain local to each check.
- Preparation validates prevout count and each outpoint against the transaction input before script evaluation.
- An outpoint mismatch is a caller-wiring error, not a script verdict.
- The native owner retains owned outputs against an immutable borrowed transaction after this check.
- Block preparation transfers resolved outputs into that owner.
- Borrowed callers clone their outputs when constructing the owner.
- Core `script_tests.json`, `tx_valid.json`, and `tx_invalid.json` native columns pin zero mismatches on **runnable** rows in `crates/script/tests/core_vectors.rs`.
- The columns pin skip counts **and** skip-reason allow-lists so silent coverage loss cannot remain green.
- The only accepted `script_tests` skip is a one-string prose/section header.
- The only accepted `tx_invalid` skip is `BADTX`, which fails `CheckTransaction` before script verification.
- `tx_valid` accepts no skips.

#### Native Taproot witness rules

- Bare P2TR is recognized in the existing witness-program path when witness verification is active.
- Taproot verification runs only with its activation flag.
- A recognized v1/32-byte program before activation succeeds even with `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`.
- Wrapped v1 and other program sizes retain their upgradeable-program policy.
- The former generic-version path incorrectly applied that policy to inactive native P2TR.
- ScriptSig push-only checks and script evaluation errors precede the native-witness empty-scriptSig check.
- A push-only nonempty scriptSig fails `WITNESS_MALLEATED` for both key-path and script-path spends.
- Key-path and tapscript signatures use the same native Schnorr checker.
- A 64-byte key-path signature selects `SIGHASH_DEFAULT`.
- A 65-byte signature MUST append one of `01`, `02`, `03`, `81`, `82`, or `83`.
- An appended `00` byte is forbidden.
- Malformed suffixes and invalid sizes fail before signature verification.
- Annex handling remains per input and enters the existing BIP341 sighash.
- After script-path commitment and leaf-version checks, the opcode parser scans tapscript for `OP_SUCCESS`.
- `OP_SUCCESS` bypasses initial stack count limits, element limits, evaluation, and final clean-stack checks.
- A malformed push before `OP_SUCCESS` fails closed.
- Bytes inside pushes are data, not opcodes.
- Policy rule `DISCOURAGE_OP_SUCCESS` fails before stack limits.
- This rule corrects the former placement inside evaluation, which rejected consensus-valid success paths.
- This rule corrects the former native P2TR fast path that bypassed scriptSig validation.
- That former path passed all 65 bytes to a 64-byte Schnorr parser.
- Spends with nonempty scriptSig are rejected.
- Correctly signed nondefault hash modes are accepted.
- Network activation heights, flag definitions, and the default validation engine are unchanged.
- `crates/script/tests/taproot_spend_rules.rs` tests rust-bitcoin signatures and control blocks against both complete-prevout entry points.
- The tests verify flag activation, wrapped-v1 rules, and error-order cases.
- `overhaul_process_harness::taproot_spend_cases` compares 40 transaction signature/scriptSig cases and 28 `OP_SUCCESS` cases.
- The harness runs native and Core 31.1 block validation over identical funded regtest histories.
- Block proposals isolate consensus from annex relay policy.
- Fixture keys exist only in test targets.
- No performance claim or production signing capability follows from these checks.

#### Admission signature cache

- `PreparedAdmission::verify_scripts` constructs a local `SignatureCache`.
- Native verification shares this cache across the `STANDARD` pass and the next-block script pass.
- This cache reuses positive cryptographic signature results for one transaction across both passes.
- `PreparedTransaction::verify_input` accepts an optional `&SignatureCache` argument.
- The prepared transaction does not store the cache reference.
- The prepared transaction remains `Sync` and shareable across parallel block input checks.
- Block verification and uncached callers pass `None`.
- The cache MUST enforce a hard capacity limit of 64 entries.
- This limit is an independent resource bound, not a configuration setting or policy rule.
- At capacity, existing entries remain valid and continue to hit.
- The cache refuses new distinct entries at capacity and never evicts entries.
- The trust boundary is strictly positive-only.
- The cache stores only keys for successful signature verifications.
- Verification failures MUST never be stored.
- A cache hit skips only the `secp256k1` group operation.
- Every check still executes flag-dependent rules, signature and public key encodings, and sighash calculations.
- Every check still executes script evaluation steps and `NULLFAIL` requirements.
- Keys use unambiguous 32-byte digests with domain tags, algorithm prefixes, length-prefixed bytes, and sighash messages.
- `ValidationEngine::Kernel` ignores the signature cache and verifies scripts independently.
- The cache is serial admission-local state wrapped in a `RefCell`.
- The cache exists only for the duration of `PreparedAdmission::verify_scripts`.
- The runtime drops the cache immediately when admission verification completes.
- Entries MUST never persist into mempool storage, blocks, or chain state.
- `ScriptExecutionCache` remains the sole owner of admission-to-block reuse.
- `ScriptExecutionCache` is a long-lived, thread-safe cache shared between the mempool gateway and block connect.
- It stores whole transaction execution outcomes keyed by witness transaction id and verify flags.
- In contrast, `SignatureCache` is temporary and single-threaded.
- It reuses individual signature operations only between the two admission passes of a single transaction.

### `VAL-03`: Default binary stays kernel-free

- `bin/bitcoin-rs` default features MUST be `fjall`, `redb`, and `zmq`.
- Default features MUST never include `kernel`.
- `--features kernel` means bitcoinkernel support is compiled in on the binary.
- The Compose image `Dockerfile` builds `fjall,kernel`.
- Compiling `kernel` does not select the engine.
- Selection is `validation.engine = "kernel"` (`--validation-engine kernel`, `BITCOIN_RS_VALIDATION_ENGINE=kernel`, or TOML `validation_engine = "kernel"`).
- The shipped image selects `kernel` at the **config-file** layer (`/etc/bitcoin-rs/default.toml`, handed to the node with `--config`).
- Bare `docker run` keeps historical kernel behavior.
- An environment override or mounted config file overrides defaults under precedence (defaults -> file -> environment -> CLI).
- A CLI override replaces `CMD` wholesale under docker semantics (running `bitcoin-rs <args>` instead of the shipped argument list).
- The CLI override MUST repeat the full `--config --data-dir --p2p-listen` set.
- The kernel-free default keeps `kernel` out of every manifest default.
- This rule is not a C++-free claim.
- The default build compiles bundled ZeroMQ C++ from source.
- The build needs C/C++ compilers plus `ar` (see [getting-started prerequisites](../getting-started.md#prerequisites)).
- Changing the production default engine under `VAL-01` does not add `kernel` to any manifest default.

## Verification boundaries

- Configuration, backend metadata, native/kernel capability, and startup failure tests own selection and refusal behavior.
- CI and provisioned reference campaigns own execution evidence.
- Compiling a capability does not select it at runtime.
- Compiling a capability does not establish consensus parity.

## Consensus difficulty

### `DAA-01`: Bitcoin Core 31.1 difficulty adjustment

- Permanent tests MUST follow the Core 31.1 product reference (`REF-02` in [reference-set.md](reference-set.md)).
- The retarget timespan MUST clamp to between 1/4 and 4x the target.
- Testnet allows a minimum-difficulty exception after a gap over 20 minutes (1,800 s).
- Timely blocks MUST inherit the last non-minimum target.
- Retarget boundaries MUST take precedence over that exception.
- Rules map to Core `GetNextWorkRequired` and `CalculateNextWorkRequired`.
- Update contract and reference identity together on consensus review.
