# Validation

Scripts run on the native Rust interpreter by default. A build with the optional `kernel` feature can also run scripts on Bitcoin Core's C++ engine, but compiling the capability does not select it: `validation.engine = "native"` stays the production default (`VAL-01`, [validation-default contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/validation-default.md#val-01-the-production-default-engine-is-a-measured-decision)).

```text
block from peer or miner
  |
  v
chain::BlockTree        header proof of work, best-tip selection
  |
  v
chainstate              pre-write consensus gates, assume-valid decision
  |
  +--> consensus          structural rules, merkle binding, sigops, finality
  |
  +--> script             native interpreter or kernel, per input
  |
  v
utxo contract           apply the validated block's changes
```

The five layers map to crate directories:

| Layer | Directory | Owns |
| --- | --- | --- |
| primitives | [`crates/primitives/src`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/primitives/src) | `Tx`, `TxIn`, `TxOut`, `Block`, `Header`, `OutPoint`, `Hash256`, `Amount`, sighash types and cache keys; no execution |
| script | [`crates/script/src`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/script/src) | `Interpreter`, `VerifyFlags`, `PreparedTransaction`, Taproot, sigop counting, signature cache |
| consensus | [`crates/consensus/src`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/consensus/src) | `ValidationEngine`, transaction rules, block rules, kernel dispatch |
| chainstate | [`crates/chainstate/src`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/chainstate/src) | Validation mode, assume-valid gate, apply path and its skip decision |
| mempool | [`crates/mempool/src`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/mempool/src) | Admission-time script checks, standardness, sigop policy |

## The native interpreter

`Interpreter::execute_with_prevouts` verifies one input under a `VerifyFlags` set, taking one spent output per input in transaction order. It covers legacy and P2SH through the opcode evaluator, SegWit v0 through BIP143 sighashes, and Taproot key-path and script-path through local BIP341 and BIP342 code. `PreparedTransaction` holds the resolved prevouts and sighash cache for one transaction, so block verification can check that transaction's inputs in parallel.

Every build compiles this function, including `kernel` builds where `validation.engine = "native"` still reaches it (`VAL-02`). The native engine is the portable one: it needs no C++ toolchain and no extra feature.

`crates/consensus/src/verify_tx.rs` routes verification through `verify_input_script_native(prepared, input_index, flags, signature_cache)`. A signature cache is optional at the call site; the block path keeps one cache per prepared transaction.

## Native versus kernel

`ValidationEngine` has two variants:

- `Native` is the default and is supported in every build.
- `Kernel` is supported only when the `kernel` feature compiled bitcoinkernel in.

Selection is a runtime setting, spelled identically at each layer:

| Layer | Engine | Mode |
| --- | --- | --- |
| CLI | `--validation-engine kernel` | `--validation-mode full` |
| Environment | `BITCOIN_RS_VALIDATION_ENGINE=kernel` | `BITCOIN_RS_VALIDATION_MODE=full` |
| TOML | `validation_engine = "kernel"` | `validation_mode = "full"` |
| Layers | defaults, then `--config`, then `--bitcoin-conf`, then environment, then CLI | same |

A kernel-free binary refuses the setting at startup, before chain state opens. `$DATA` is a data directory:

```text
$ bitcoin-rs --network regtest --data-dir $DATA \
    --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --validation-engine kernel
bitcoin-rs: validation engine `kernel` is not supported by this build: bitcoinkernel support is not compiled in (enable the `kernel` feature)
```

The process exits with status 1. The default `bitcoin-rs` binary is kernel-free (`VAL-03`). The shipped Docker image builds `fjall,kernel` and selects kernel in its config file, so a bare container runs kernel while a bare binary runs native.

With `Kernel` selected, block parsing uses `bitcoinkernel::Block::new` and script verification calls the kernel engine after native prevout validation. The kernel path ignores the signature cache; the cache is a native optimization, and the kernel engine does not use it.

## Assume-valid

`ValidationMode` controls which historical scripts the apply path may skip:

- `AssumeValid` is the default. Scripts are skipped only while all of these hold: an anchor is configured, the assume-valid height is nonzero, the block height is at or below that setting, the block is at or below the pinned height, the gate is trusted, and the pinned hash is on the best header chain.
- `Full` executes every script and ignores `--assume-valid-height`.

Skipping scripts never skips structure. Block admission still runs proof-of-work checks, merkle binding, BIP30 and BIP34 checks, finality, and sigop limits. The apply profile records the split: `block_rules_us` and `bip30_bip34_us` measure structure, and `script_verify_us` measures input scripts. A coinbase-only block shows zero input-script time because it has no input scripts to run.

The compiled anchor exists for mainnet only. Testnet3, Testnet4, Signet, and Regtest have no anchor, so `AssumeValid` skips nothing there.

Starting `full` on a chain that was committed with weaker attestation triggers a cold rebuild from stored blocks. That rebuild needs the bodies. A pruned data directory stops with:

```text
full validation requires an unpruned datadir; restart with --validation-mode assume-valid or resync
```

The [recovery contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md) owns the attestation levels that decide when a rebuild is required.

## Evidence and limits

Core's script vectors pin zero native mismatches on runnable rows:

| Vector set | Failures | Skips | Executed | Skipped rows |
| --- | --- | --- | --- | --- |
| `script_tests.json` | 0 | 55 | 1233 | one-string prose headers only |
| `tx_valid.json` | 0 | 0 | 121 | none |
| `tx_invalid.json` | 0 | 9 | 84 | `BADTX` parse-stage rows only |

The counts are constants in [`crates/script/tests/core_vectors.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/script/tests/core_vectors.rs); the vectors themselves are the pinned Core corpus, so they do not run without it. Kernel builds also run the same catalog through the kernel column and the parity test `kernel_verdict_matches_mandatory_core_catalogs`.

The kernel is an oracle, not a second production default. The dated benchmark artifact [`docs/benchmarks/native-validation-default.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/benchmarks/native-validation-default.md) records native at 50.014 ms apply p50 against kernel at 45.784 ms, a ratio of 1.092, with the verdict `KeepKernel`. Native is 9.2 percent slower on that proxy. Full-mainnet replay is blocked on issue #34 and is not measured here. The signed-spend proxy is engine diagnostics, not a daemon throughput result.

Do not read "zero mismatches" as blanket consensus parity. The claim covers the runnable rows of those three catalogs with the listed skip reasons. Kernel-versus-interpreter parity outside those rows is not proven.

## Tests that pin validation

| Invariant | Test | File |
| --- | --- | --- |
| Native column of `script_tests.json` passes | `script_tests_native_column` | [`crates/script/tests/core_vectors.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/script/tests/core_vectors.rs) |
| Native column of `tx_valid.json` passes | `tx_valid_native_column` | [`crates/script/tests/core_vectors.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/script/tests/core_vectors.rs) |
| Native column of `tx_invalid.json` passes | `tx_invalid_native_column` | [`crates/script/tests/core_vectors.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/script/tests/core_vectors.rs) |
| An unmatched pin does not skip scripts | `assume_valid_without_matching_pin_does_not_skip_scripts` | [`crates/chainstate/src/tests/assumevalid_trust_tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/chainstate/src/tests/assumevalid_trust_tests.rs) |
| A reorg that drops the pin revokes trust | `assume_valid_trust_is_revoked_when_a_reorg_drops_the_pin` | [`crates/chainstate/src/tests/assumevalid_trust_tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/chainstate/src/tests/assumevalid_trust_tests.rs) |
| The engine defaults to native across layers | `validation_engine_defaults_to_native_and_layers_field_by_field` | [`crates/node/src/config/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/config/tests.rs) |

The [BIP support](../trust/bip-support.md) page lists the activated soft forks, and the [verification](../trust/verification.md) page covers the wider evidence set.
