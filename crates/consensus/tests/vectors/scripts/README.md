# Kernel script-parity fixture corpus

Per-transaction script-verdict fixtures for
`crates/consensus/tests/kernel_block_parity.rs` (plan 2026-06-10-001, R4/U3).
One JSON per script class; each carries the raw transaction hex, its expected
`txid` **and** `wtxid`, **every** input's prevout (scriptPubKey hex + amount
in sats — the kernel taproot path needs all prevouts for
`PrecomputedTransactionData`), and the Core-named verify flags the production
apply path computes at the spend height. For pre-segwit transactions
`wtxid == txid`; it is recorded (computed, not assumed) so the schema stays
uniform. Reject cases are generated as in-code mutations by the harness,
never stored here.

The corpus is committed so CI depends on neither the local datadir nor the
network. The test loader recomputes each transaction's txid **and wtxid**
from `tx_hex` and fails loudly on any mismatch with the `txid`/`wtxid` fields
below. The txid alone covers only the witness-stripped serialization; the
wtxid commits to the witness bytes too, so the full raw data — witnesses
included — is self-authenticating against the recorded provenance.

## Manifest

| file | class | txid | height | flags | interpreter parity | source |
|---|---|---|---|---|---|---|
| `legacy_p2pk.json` | P2PK | `f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16` | 170 | `P2SH` | no | local mainnet datadir via `bitcoind -rest`, `/rest/block/00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee.json` |
| `legacy_p2pkh.json` | P2PKH | `74c1a6dd6e88f73035143f8fc7420b5c395d28300a70bb35b943f7f2eddc656d` | 2812 | `P2SH` | no | local mainnet datadir via `bitcoind -rest`, `/rest/block/0000000049a63b4dda3a43450c19d085d6c28bfb4cbb2e0576815d7f31919c5d.json` |
| `p2sh_spend.json` | P2SH (2-of-2 `OP_CHECKMULTISIG` redeem) | `3a12b4f2361806a2f8508ebcf1968cd07052351c24bfe069f143ef244c24a7e8` | 400000 | `P2SH,DERSIG,CHECKLOCKTIMEVERIFY` | no | <https://mempool.space/api/tx/3a12b4f2361806a2f8508ebcf1968cd07052351c24bfe069f143ef244c24a7e8> |
| `segwit_v0_spend.json` | segwit v0 (P2WPKH) | `f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd` | 481824 | `P2SH,DERSIG,NULLDUMMY,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS` | no | <https://mempool.space/api/tx/f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd> |
| `taproot_keypath_spend.json` | taproot key path | `33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036` | 709635 | `P2SH,DERSIG,NULLDUMMY,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,TAPROOT` | **yes** | <https://mempool.space/api/tx/33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036> |
| `taproot_scriptpath_spend.json` | taproot script path | `905ecdf95a84804b192f4dc221cfed4d77959b81ed66013a7e41a6e61e7ed530` | 709635 | `P2SH,DERSIG,NULLDUMMY,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,WITNESS,TAPROOT` | no | <https://mempool.space/api/tx/905ecdf95a84804b192f4dc221cfed4d77959b81ed66013a7e41a6e61e7ed530> |

## Selection notes

- **`legacy_p2pk`** is the canonical block-170 Satoshi→Finney transaction —
  the first ever non-coinbase Bitcoin transaction, spending the block-9
  coinbase P2PK output.
- **`legacy_p2pkh`** is the first transaction in the local 0→150k datadir
  whose every input spends a P2PKH (`pubkeyhash`) prevout, found by a forward
  scan from genesis (height 2812).
- **`p2sh_spend`** is post-activation (BIP16 activated at height ≈173,805,
  satisfying R4's `≥ 173,805` bound). Height 400,000 was chosen after
  mechanical scans of the activation window (173,805–173,905 plus spot blocks
  at 183k/200k/220k/250k/290k/320k) found no all-P2SH-input spend — organic
  P2SH usage stayed rare for years after activation. The redeem script is a
  2-of-2 multisig, so this fixture also exercises `OP_CHECKMULTISIG`
  (the "multisig era" legacy semantics) through the kernel.
- **`segwit_v0_spend`** is from block 481,824, the segwit activation block.
- **`taproot_keypath_spend`** is the widely documented **first taproot spend
  on mainnet** (block 709,635, single input, one 64-byte Schnorr signature,
  no annex). It is the one fixture inside the in-repo Rust interpreter's
  native scope (single-input key-path), so it carries
  `interpreter_parity: true`.
- **`taproot_scriptpath_spend`** is a single-input script-path spend from the
  same block. It doubles as the fixture-grounded half of the
  `differential_is_non_vacuous` pin: the kernel accepts it while the key-path-
  only Rust interpreter rejects it.

Esplora data was fetched from `mempool.space` (the recorded source URLs);
`blockstream.info` serves the identical transactions under the same API paths
for independent cross-checking.

## Flags

`flags` strings parse via `VerifyFlags::from_core_names` and match the
derivation in production's `compute_verify_flags`
(`crates/node/src/apply.rs`): `P2SH` is set **unconditionally** at every
height (BIP16 is treated as always-on for supported validation paths — hence
`P2SH`, never `NONE`, on the height-170/2812 legacy fixtures, where it is
verdict-identical because no P2SH-pattern output is spent), and the remaining
bits follow mainnet activation heights (BIP66 DERSIG ≥ 363,725; BIP65 CLTV ≥
388,381; CSV ≥ 419,328; segwit WITNESS+NULLDUMMY ≥ 481,824; TAPROOT ≥
709,632). They stay within `VerifyFlags::MANDATORY`, the set `kernel_bits()`
forwards to `bitcoinkernel::verify`.
