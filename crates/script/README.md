`Interpreter::execute_with_prevouts` verifies one input under a `VerifyFlags`
set, taking one spent output per input in transaction order (flags parseable
from Core test-vector strings with `VerifyFlags::from_core_names`). The opcode evaluator covers legacy and P2SH.
SegWit v0 uses BIP143 sighashes, and Taproot uses local BIP341/BIP342
verification. The `sigops` module counts signature operations; the signature
checker verifies signatures. Failures surface as `ScriptError`. Core's
`script_tests`, `tx_valid`, and `tx_invalid` vectors pin zero native mismatches
in `tests/core_vectors.rs`. This interpreter is the `native` engine — compiled
in every build and the default `validation.engine`; the `kernel` feature on
`bitcoin-rs-consensus` is an opt-in capability that compiles bitcoinkernel in
alongside it (selection is runtime, see
[`docs/contracts/validation-default.md`](../../docs/contracts/validation-default.md)).

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
