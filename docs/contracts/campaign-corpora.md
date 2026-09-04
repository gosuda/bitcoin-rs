# Campaign corpora contract

The two immutable cumulative corpora every product-domain cell uses. This page
owns the identities, archive format, validation posture, script census, and
chain-state oracle. Numeric pins live in
[`tools/campaign-corpus/products.json`](../../tools/campaign-corpus/products.json).
The exporter and classifier live in
[`tools/campaign-corpus/corpus.py`](../../tools/campaign-corpus/corpus.py).

Owners:
- `tools/campaign-corpus/products.json`
- `tools/campaign-corpus/corpus.py`

Offline parity work that consumes these corpora is defined by issue #46 and
implemented by the offline comparator (#34). This page does not own timing,
reopen proofs, or backend selection.

## Clauses

### `CORP-01`: Two product corpora

Every product-domain cell uses exactly one of two mainnet cumulative archives:

| Corpus | Inclusive range | Stop hash | Blocks |
| --- | --- | --- | ---: |
| C150 | genesis .. 150,000 | `0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b` | 150,001 |
| Cmodern | genesis .. 709,635 | `00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f` | 709,636 |

Cmodern is the first height at which every required modern script class has
executed, not Taproot activation (709,632). No other stop height may satisfy a
product cell. A length-prefixed diagnostic file is not a product corpus.

### `CORP-02`: Core-framed archive and manifest

- Encode each block as a Bitcoin Core block-file record: 4-byte mainnet magic
  `f9beb4d9`, 4-byte little-endian payload length, then consensus block bytes.
- Bind the archive with schema `bitcoin-rs-corpus-manifest` version 1: network,
  magic, genesis hash, contiguous `0..stop` entries (height, header hash, byte
  offset, payload length), archive size, archive SHA-256, and a canonical
  `manifest_sha256`.
- Distinct container formats are allowed only after converting into this
  framing. `convert` turns a `[u32 le length][payload]` stream into the same
  archive the REST exporter writes.
- Archive bytes are not stored in git. A cell names the certified archive by
  the manifest digest produced at export time.

### `CORP-03`: Validation posture

- Full script and consensus validation. `assume_valid_height` is `0`.
- Height-correct consensus flags. No sampled or REST-live certification.
- Fresh native stores per trial. The timed work and reopen gates are owned by
  #46 / #34 / #36, not by this freeze.

### `CORP-04`: Script census

Eleven special context counters must be present and classified:

`p2sh_redeem_spends`, `native_witness_v0_spends`,
`p2sh_wrapped_witness_v0_spends`, `bare_multisig_checks`,
`p2sh_multisig_checks`, `native_witness_v0_multisig_checks`,
`p2sh_wrapped_witness_v0_multisig_checks`, `taproot_key_path_spends`,
`tapscript_spends`, `tapscript_schnorr_checks`,
`tapscript_checksigadd_checks`.

C150 (file-bound historical census): `context_count` =
`ffi_verify_entries` = `op_checksig` = 2,868,199; `eval_script_entries` =
5,736,398; `op_checksigverify`, `op_checkmultisig`,
`op_checkmultisigverify`, `op_checksigadd`, `checkschnorr_entries`, and
`schnorr_verify_calls` are 0; every special counter is 0. P2SH, witness v0,
and Taproot are inactive in this range.

Cmodern: every special counter is ≥ 1. Schnorr accounting is
`checkschnorr_entries >= schnorr_verify_calls` and
`schnorr_verify_calls == schnorr_verify_ok + schnorr_verify_fail`. A nonzero
Schnorr total without Tapscript and `OP_CHECKSIGADD` does not qualify.

### `CORP-05`: Chain-state oracle

The cross-node commitment is the 32-byte `MuHash3072` digest from Bitcoin
Core 31.1:

```text
gettxoutsetinfo "muhash" <stop_height> true
```

`coinstatsindex` must be synchronized. `hash_serialized_3` is not the
campaign oracle. Cells match height, `bestblock`, `txouts`, satoshi
`total_amount`, and `muhash`.

C150 frozen state:

| Field | Value |
| --- | --- |
| height | 150,000 |
| bestblock | `0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b` |
| txouts | 1,127,181 |
| total_amount | 749,989,998,999,999 sat |
| muhash | `383a0b41ac28ddf6ac91723b41527fa64c0b54451cee5f2c4b3823ef92117116` |

Cmodern uses the same RPC at height 709,635. The numeric `txouts`,
`total_amount`, and `muhash` are the first certified Core 31.1 response at
that height. No Cmodern cell may close on a guessed or recalled UTXO total.

## Proven by

- `tools/campaign-corpus/test_corpus.py` (`python3 tools/campaign-corpus/test_corpus.py`)
  pins both identities, the eleven specials, C150 census zeros, Cmodern
  all-positive specials, Core framing, manifest digest binding, and
  `assume_valid_height = 0`.
- Export: `python3 tools/campaign-corpus/corpus.py export --rest-url HOST:PORT --corpus-id C150|Cmodern --archive blocks.dat --manifest manifest.json`
- Convert: `python3 tools/campaign-corpus/corpus.py convert --length-prefixed FILE --corpus-id C150 --archive blocks.dat --manifest manifest.json`
- Verify / classify: `verify` and `classify` subcommands of the same tool.
