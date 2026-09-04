# bitcoin-rs-script

Script verification for the portable posture, plus the sigop counters and
signature-hash caching that surround script execution.

`Interpreter::execute` and `Interpreter::execute_with_prevouts` run one script
spend under a `VerifyFlags` set (parseable from Core test-vector flag strings
via `VerifyFlags::from_core_names`). The native evaluator covers legacy and
P2SH, SegWit v0 (BIP143), and Taproot key-path and script-path (BIP341/BIP342).
Multi-input Taproot spends require the complete ordered prevout set. Around
the interpreter sit `sigops` (signature-operation counting) and the local
script helpers. Failures surface as `ScriptError`. The `kernel` feature on
`bitcoin-rs-consensus` remains the library production default; see
[`docs/contracts/validation-default.md`](../../docs/contracts/validation-default.md).

## Features

- `rocksdb`, `fjall`, `redb`: no-op in this crate — this crate has no backend code; the names exist so the shared storage-backend features can be enabled uniformly across the workspace.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
