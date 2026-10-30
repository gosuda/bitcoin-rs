# p2pk-scan

`p2pk-scan` lists unspent pay-to-pubkey outputs from a raw block file. It never starts a node. It never opens a database. It writes nothing except standard output.

## Input

The tool reads one hexadecimal block per line.

- Line 1 is the genesis block. Line N is block height N-1.
- The file must hold the canonical chain from genesis, in order.
- Blank lines are refused, because they would shift every later height.
- A line can hold at most 8,000,000 hexadecimal characters.
- The tool checks header linkage. Each block's `prev_blockhash` must equal the previous block's hash. A missing, extra or reordered block stops the scan with the line number.
- The tool does not check proof of work, transaction signatures, script execution, or value balance. It decodes each block and replays its UTXO adds and removes. A file that keeps the linkage but holds invalid transactions gives a wrong UTXO set without an error. See [Verification](#verification).

Build the file on a node. Core's `getblock` prints the raw block in hexadecimal with verbosity `0`:

```sh
TIP=$(bitcoin-cli -regtest getblockcount)
: > blocks.hex
for height in $(seq 0 "$TIP"); do
  bitcoin-cli -regtest getblock "$(bitcoin-cli -regtest getblockhash "$height")" 0 >> blocks.hex
done
```

## Output

The default output is a table with one row for each unspent P2PK output. Run `--json` for the same report as JSON.

```sh
cargo run --locked -p bitcoin-rs-p2pk-scan -- tools/p2pk-scan/examples/regtest-p2pk.blocks.hex
```

```
TXID:VOUT HEIGHT VALUE_SAT KEY PUBKEY
fa997dac52a56bda0324bf7be6b8efea055a870588e9d62f1c31e602457aa376:0 101 5000 compressed 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
fa997dac52a56bda0324bf7be6b8efea055a870588e9d62f1c31e602457aa376:1 101 6000 uncompressed 0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
fa997dac52a56bda0324bf7be6b8efea055a870588e9d62f1c31e602457aa376:7 101 9000 compressed 02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
p2pk_outputs 3 value_sat 20000 utxo_outputs 110 blocks 103 tip_height 102
```

The last line holds the report totals. `utxo_outputs` counts every unspent output in the replayed set.

## Example dataset

`examples/regtest-p2pk.blocks.hex` holds 103 regtest blocks.

- Block 0 is the regtest genesis block.
- Blocks 1 to 100 hold one coinbase transaction each.
- Block 101 spends the matured block-1 coinbase into eight outputs: two unspent P2PK outputs, one P2PK output that block 102 spends, P2PKH, P2SH, bare multisig, a P2PK-shaped output whose 33-byte push starts with `0x09`, and a P2PK output whose `0x02` key is not a curve point.
- Block 102 spends the P2PK output at vout 2. Block 102 also creates a P2PK output, and a second transaction in the same block spends it.

The fixture test builds the same chain and asserts the exact report. Regenerate the committed file from that builder:

```sh
P2PK_SCAN_WRITE_EXAMPLE=1 cargo test --locked -p bitcoin-rs-p2pk-scan
```

## Verification

Run the fixture tests:

```sh
cargo test --locked -p bitcoin-rs-p2pk-scan
```

The tests assert these properties:

- only unspent P2PK outputs appear, so a spent output, a same-block spend, P2PKH, P2SH, bare multisig and a `0x09`-prefixed key stay out;
- a `0x02` key that is not a curve point appears, because the shape rule cannot reject it;
- a reordered file stops at the first block that does not extend its predecessor and names the line;
- a malformed line names its line number;
- the binary prints three rows for the example dataset.

Cross-check a real dataset in two steps.

1. Compare the total with Core on the same tip. `gettxoutsetinfo` reports `txouts`. The scan reports `utxo_outputs`. Both must be equal. A mismatch means the file is not the canonical chain from genesis.
2. Compare each output with Core's `scantxoutset` on the same node:

```sh
bitcoin-cli -regtest scantxoutset start '[{"desc":"pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)","range":1}]'
```

`total_amount` is in BTC. Multiply by 100,000,000 to compare with `value_sat`. The `unspents` array holds `txid`, `vout`, `height` and `amount`.

Core's `pk()` descriptor rejects a key that is not a curve point. A `pk()` cross-check cannot confirm the row for such a key. The fixture test covers that row instead.

## Reported and missed outputs

A reported output must match the workspace P2PK rule in `bitcoin_rs_script::is_p2pk`: one push of 33 or 65 bytes, followed by `OP_CHECKSIG`. A 33-byte key must start with `0x02` or `0x03`. A 65-byte key must start with `0x04`, `0x06` or `0x07`. The output must stay unspent at the tip of the file.

The scan reports some outputs that no one can spend.

- Invalid key. A key with a correct prefix and length that is not a valid curve point still matches the shape rule. `OP_CHECKSIG` always fails for it, so the coin is lost. Core matches the same way: `MatchPayToPubkey` in `.references/bitcoin-core/src/script/solver.cpp` calls `CPubKey::ValidSize` in `.references/bitcoin-core/src/pubkey.h`, which checks only the length and the prefix and never the curve. The example dataset holds one such output at vout 7. Check every reported key against a curve if you need spendable coins only. The scan performs no key check.

The scan misses these outputs.

- Bare multisig. The script is `OP_1 <pubkey> OP_1 OP_CHECKMULTISIG`, not a single key push.
- P2PK inside P2SH or P2WSH. The UTXO script holds the hash, not the redeem script.
- P2PKH, P2WPKH, P2TR and every other script template.
- An output that starts with `OP_RETURN` or carries a script longer than 10,000 bytes. Core never adds such an output to the UTXO set, and the scan skips it.
- A key push with another prefix, such as `0x09`, even though no `OP_CHECKSIG` can spend it.

## Scope

The tool keeps the entire replayed UTXO set in memory and holds one decoded block at a time. The dataset in this file is a regtest fixture. No mainnet or testnet measurement is recorded here.

Default node behavior does not change. This tool links the UTXO crate and runs its own in-memory set. It does not open a node data directory.
