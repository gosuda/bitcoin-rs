# Fuzz corpus provenance

Seeds under fuzz/corpus/ were imported from
[rust-bitcoin/qa-assets](https://github.com/rust-bitcoin/qa-assets), license
[CC0-1.0](https://github.com/rust-bitcoin/qa-assets/blob/master/LICENSE)
(public domain; no attribution required, recorded here for provenance).

| Field | Value |
|---|---|
| Upstream commit | ffd27e4ee51266673859e3d1314369e780e26a4e |
| Import date | 2026-08-28T04:59:44Z |
| License | CC0-1.0 |
| Import tool | scripts/import-qa-assets.sh (clone pinned to the commit above, then cargo fuzz cmin per target) |
| Size policy | source files >= 65536 bytes are skipped and counted in the import log (repo-size bound matching the targets' input caps) |

## Mapping

| Target | Upstream corpus | Transformation |
|---|---|---|
| p2p_message | fuzz_corpora/p2p_deserialize_raw_net_msg | 24-byte envelope stripped; header command mapped to the harness selector byte; payload kept as-is (harness rebuilds magic/length/checksum) |
| block_validate | fuzz_corpora/bitcoin_deserialize_block | consensus-serialized blocks; rust-bitcoin deserializes, then bitcoin-rs `verify_block_rules`. `bitcoin_arbitrary_block` is Unstructured bytes, not imported. Current seeds were the minimized `bitcoin_deserialize_block` set, moved from the retired `block_decode` target. |
| tx_validate | fuzz_corpora/bitcoin_deserialize_transaction, fuzz_corpora/bitcoin_deserialize_witness | consensus-serialized txs/witnesses; rust-bitcoin deserializes, then bitcoin-rs consensus + mempool `check_acceptance`. `bitcoin_arbitrary_*` Unstructured streams are not imported. Current seeds were the minimized `bitcoin_deserialize_transaction` set, moved from the retired `tx_decode` target. |
| script_eval | fuzz_corpora/bitcoin_deserialize_script, fuzz_corpora/bitcoin_script_bytes_to_asm_fmt | raw script bytes wrapped into the script_eval framing (selector 0x00 = NONE); files >= 32 bytes also emit a P2TR key-path variant (selector 0x03 = TAPROOT) |

Corpora were minimized with cargo fuzz cmin after import; only minimized
seeds are tracked here. Re-run the script after major decoder changes to
refresh.

See also docs/contracts/qa-corpus.md for the contracts index and precedence rule.
