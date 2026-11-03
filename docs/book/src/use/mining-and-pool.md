# Mining and the native pool

Generate solo blocks with `generatetoaddress` or `generateblock`. Run a Stratum V1 or V2 pool only if you built the binary with the `pool` feature and accept that the pool is opt-in and not a production deployment default.

## Solo generation

`generatetoaddress` assembles a fresh candidate, solves it, and submits it. It accepts a network-valid address and returns one hash per block, in order:

```
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":40,"method":"generatetoaddress","params":[3,"mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result | {blocks:length, first:.[0], last:.[-1]}'
{
  "blocks": 3,
  "first": "69ad8a7b5c83be436d92c7e6978780972830985df3bbb302757177d2749cd078",
  "last": "6413acd603500191006203485273980fe76a062027f5aaf7e2845e0d8683019f"
}
```

Each block is a separate commit. An error after N successes leaves those N blocks durable, so read the applied tip before retrying. `nblocks` is uncapped and the result vector grows one block at a time. The path uses mempool package selection and collects fees.

`generateblock` takes an address or a descriptor and an explicit transaction list. The list may be empty for a coinbase-only block. A 64-character hex string is treated as a mempool txid; any other hex is decoded as a raw transaction. Listed order is kept, and listed fees are not added to the coinbase. Descriptors with a checksum are verified; ranged and multipath descriptors are refused.

`submitblock` and `submitheader` accept externally solved work. A block already connected after a later reorg is a duplicate. Extra bytes after a complete block and BIP22's dummy second argument are ignored. A decode failure is `-22` (`Block decode failed`).

## Templates

`getblocktemplate` returns a BIP22/BIP23 template from the current candidate:

```
$ curl -s --user book:bookpass --data-binary '{"jsonrpc":"2.0","id":41,"method":"getblocktemplate","params":[{"rules":["segwit"]}]}' -H 'content-type: application/json' http://127.0.0.1:45869/ | jq '.result | {height,previousblockhash,coinbasevalue,capabilities,longpollid,rules}'
{
  "height": 105,
  "previousblockhash": "6413acd603500191006203485273980fe76a062027f5aaf7e2845e0d8683019f",
  "coinbasevalue": 5000000000,
  "capabilities": [
    "proposal",
    "longpoll"
  ],
  "longpollid": "6413acd603500191006203485273980fe76a062027f5aaf7e2845e0d8683019f0",
  "rules": [
    "!segwit",
    "taproot"
  ]
}
```

The client must advertise `segwit`, and `signet` on signet. The advertised capabilities are the producer's implemented set: `proposal` and `longpoll`. Client-advertised capability names are not echoed back. `submitold` and `workid` are unmodeled BIP23 extras and are never emitted.

`longpollid` is the tip hash in hex followed by the mempool sequence. A successful `prioritisetransaction` adds `:{fee_delta_sequence}` and wakes long-poll waiters with the new id. A template read that follows captures membership and fee revisions together. On signet the template carries `signet` in `rules` and `signet_challenge`.

On mainnet, template mode requires at least one live peer and a finished initial block download. Otherwise it answers `-9` (`bitcoin-rs is not connected!`) or `-10` (`bitcoin-rs is in initial sync and waiting for blocks...`). Proposal mode and non-mainnet chains skip those gates.

`getmininginfo` reports the current height, pool transaction count, and next-block facts. `prioritisetransaction` applies a signed fee delta to candidate ordering, and `getprioritisedtransactions` projects the overlay.

## Native pool prerequisites

The pool combines Stratum V1 and optional Stratum V2 mining listeners with PPLNS accounting and an external payout signer. It is disabled by default and does not enable itself from the build feature. The binary needs `pool`, and an SV2 listener also needs `pool-sv2`.

The head binary used for this book was built without the pool feature, so pool startup could not be exercised here. Its refusal is (with `$DATA` as the node data directory and `$POOL_DATA` as the pool data directory):

```
$ ./target/release/bitcoin-rs --network regtest --data-dir $DATA --pool --pool-datadir $POOL_DATA --pool-v1-bind 127.0.0.1:3333 --pool-share-difficulty 1 --pool-window-work 1 --pool-reward-script 76a914751e76e8199196d454941c45d1b3a323f1433bd688ac --mining-payout-address mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r
Error: --pool requires the pool build feature
```

To start a pool you must supply all of these:

- A dedicated `--pool-datadir`. The service locks it and opens the selected storage backend under `ledger/`.
- At least one of `--pool-v1-bind` or `--pool-sv2-bind`. Ports must be nonzero, and the two addresses must differ.
- `--pool-share-difficulty` as an exact plain-decimal string such as `1` or `0.001`. Zero, signs, and exponent notation are refused.
- A positive `--pool-window-work` in accepted-share work units, not a share count.
- `--pool-reward-script` as hexadecimal scriptPubKey bytes, nonempty, at most 10,000 bytes, minimally encoded, and not starting with `OP_RETURN`.
- `--mining-payout-address`, whose coinbase script must match the reward script. The ledger only credits coinbase outputs matching its configured reward script.
- An SV2 authority key at `--pool-sv2-authority-key` when an SV2 bind is set. On Unix the file must be mode `0600` and contain a 64-hex BIP340 x-only public key followed by a 64-hex secret, separated by whitespace.

Defaults and bounds:

| Option | Default | Bound |
| --- | --- | --- |
| `--pool-fee-bps` | 0 | At most 10,000. |
| `--pool-max-connections` | 128 | Positive. Shared by SV1 and SV2. |
| `--pool-max-connections-per-ip` | 8 | Positive and not above the total. |
| `--pool-maturity` | 100 | At least 100. |
| `--pool-payout-confirmations` | 6 | Positive. |
| `--pool-reorg-watch-depth` | 1,000 | Covers maturity, payout confirmations, and the fixed six-confirmation abandon depth. |
| `--pool-min-payout-sat` | 546 | 546 through 2,100,000,000,000,000. |
| `--pool-max-payout-outputs` | 2,500 | 1 through 2,500. |

Loopback binds are the default expectation. A non-loopback bind requires `--pool-allow-non-loopback`, including a wildcard address. The authority key authenticates the SV2 transport; it is not a payout key.

A regtest startup looks like this, with your own paths, address, script, and key file:

```
bitcoin-rs --network regtest --data-dir /var/lib/bitcoin-rs \
  --txindex=true \
  --mining-payout-address <regtest-address> \
  --pool --pool-datadir /var/lib/bitcoin-rs-pool \
  --pool-v1-bind 127.0.0.1:3333 \
  --pool-sv2-bind 127.0.0.1:3336 \
  --pool-sv2-authority-key /etc/bitcoin-rs/sv2-authority \
  --pool-share-difficulty 1 \
  --pool-window-work 1000000 \
  --pool-reward-script <scriptPubKey-hex>
```

Management RPC stays on the authenticated management listener. Pool methods exist only when the feature is compiled. With the runtime off they answer `-32603` (`Pool service is disabled`).

## Pool accounting and payouts

Miner logins are decimal account ids, optionally followed by one worker suffix such as `7.rig1`. An account must be registered before admission:

- `registerpoolaccount [account, script_hex]` registers the payout script for future batches.
- `getpoolinfo` returns the PPLNS configuration, share count, and the last 20 audit records.
- `getpoolbalances [account]` returns available, reserved, paid, and deficit satoshis plus the payout script.
- `getpoolrounds [first_round, count]` reads round states and rewards; count defaults to 100 and is at most 1,000.
- `preparepayoutbatch [key_hex32, min_payout_sat, max_outputs]` reserves eligible balances and returns a BRPR request for the external signer, or null.
- `getpayoutrequest [batch_id_hex32]` exports the canonical request for a reserved batch.
- `recordpayoutreceipt [receipt_hex]` records a signed BRPT receipt. It does not broadcast or confirm payment.
- `getpayoutbatch [batch_id_hex32]` returns the batch state and observed status.
- `cancelpayoutbatch [batch_id_hex32, basis]` cancels with an explicit basis and refuses after signing.

The node holds no wallet and no payout keys. The signer funds and signs; the ledger recomputes the txid and checks the exact output multiset. Confirmation advances from observed mempool or chain state at the configured depth. Payout confirmation needs `txindex` observations, and confirmed conflicting-spend observation needs `--scriptindex=full`. Missing index evidence is not proof that a transaction cannot confirm.

PPLNS fixes each found block's work window at its solving share. The ledger observes the exact block hash on the active chain, verifies the coinbase claim, and pays only outputs matching the reward script. Confirmations are `tip_height - block_height + 1`. Within the reorg watch depth, displacement reverses matured allocations; amounts already reserved or paid become a deficit that future credits offset. This is not an indefinite deep-reorg guarantee.

Once a block is accepted, the job retires immediately. Further shares on it are stale (SV1 error 21, SV2 `stale-share`), and an identical replay is a duplicate (SV1 error 22, SV2 `duplicate-share`). Neither earns a second credit.

Protocol tests do not establish interoperability with a particular miner or proxy. No external miner interoperability is claimed, and deployment or existing-data cutover needs separate approval.

The operator guide is [docs/pool.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/pool.md). The financial and lifecycle rules are [POOL-01](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md#pool-01-explicit-enablement-and-operator-configuration) through [POOL-05](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md#pool-05-one-mining-owner-and-acknowledgement-boundaries). Solo generation is owned by [API-05](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-05-solo-mining-generate-path), and template extras by [API-11](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/external-api.md#api-11-bip22bip23-template-extras).

Next: [Mempool policy](mempool-and-policy.md) decides which transactions reach these candidates.
