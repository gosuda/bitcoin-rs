# bitcoin-rs-script

Native script verification for every consensus spend class, plus the sigop
counters that surround execution.

`Interpreter::execute` and `Interpreter::execute_with_prevouts` run one script
spend under a `VerifyFlags` set (parseable from Core test-vector flag strings
via `VerifyFlags::from_core_names`). The opcode evaluator covers legacy and
P2SH, SegWit v0 uses BIP143 sighashes, and Taproot key-path and script-path
spends go through local BIP341/BIP342 verification. Multi-input Taproot
spends require the complete ordered prevout set. Around the interpreter sit
`sigops` (signature-operation counting) and the signature checker. Failures
surface as `ScriptError`. Core's `script_tests`, `tx_valid`, and `tx_invalid`
vectors pin zero native mismatches in `tests/core_vectors.rs`. The `kernel`
feature on `bitcoin-rs-consensus` remains the library production default;
see [`docs/contracts/validation-default.md`](../../docs/contracts/validation-default.md).

## Features

- `rocksdb`, `fjall`, `redb`: no-op in this crate — this crate has no backend code; the names exist so the shared storage-backend features can be enabled uniformly across the workspace.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
