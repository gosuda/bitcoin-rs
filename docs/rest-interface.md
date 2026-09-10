# REST interface

bitcoin-rs can expose the small Bitcoin Core-compatible REST surface needed by
remote chain validators. REST uses the existing JSON-RPC listener and port; it
does not create a second listener. Enable it with Core-style configuration:

```ini
rest=1
```

The REST requests are unauthenticated, as in Bitcoin Core. JSON-RPC requests on
the same listener continue to require their configured authentication. Select
the listener with the existing `--rpc-bind` option (or its layered config
equivalent).

The gateway registers these Core REST prefixes:

| Prefix | Formats | Notes |
| --- | --- | --- |
| `/rest/tx/{txid}` | JSON, hex, binary | Transaction lookup |
| `/rest/block/notxdetails/{hash}` | JSON, hex, binary | Block JSON uses transaction IDs |
| `/rest/block/{hash}` | JSON, hex, binary | Block JSON includes transaction details |
| `/rest/blockpart/{hash}` | Hex, binary | Raw block payload |
| `/rest/chaininfo` | JSON | Chain summary |
| `/rest/mempool/{info,contents}` | JSON | Mempool summary or contents |
| `/rest/headers/{hash}` | JSON, hex, binary | Active-chain header walk |
| `/rest/getutxos[/checkmempool]/{txid}-{vout}...` | JSON, hex, binary | URI-form UTXO lookup; at most 15 outpoints |
| `/rest/deploymentinfo[/{hash}]` | JSON | Deployment state |
| `/rest/blockhashbyheight/{height}` | JSON, hex, binary | Block hash by height |
| `/rest/spenttxouts/{hash}` | JSON, hex, binary | Explicitly unavailable: no undo data |

## Current consistency and limits

REST does not currently capture one request-wide `ReadStamp` or retry every
response when the chain generation changes. Consistency is route-local and the
handler's actual locks/snapshots define the guarantee.

- `/rest/headers` loads one applied-tip snapshot while holding the block-tree
  read lock, verifies that snapshot still names the locked tip, and walks only
  that active chain. A well-formed unknown, side-branch, orphaned, or
  header-only start hash returns HTTP 200 with an empty JSON array (or empty
  hex/binary body).
- `/rest/getutxos[/checkmempool]` captures the applied height and hash, then
  reads the mempool and requested UTXOs. It does not revalidate a chain
  generation after those reads, so this route is not a request-atomic
  chain/mempool/UTXO snapshot and does not promise a reorg-triggered 503.
- `/rest/mempool/*` and `/rest/tx` use the locking and lookup behavior of their
  existing RPC handlers. Unknown transactions return HTTP 404. The REST layer
  does not add a separate capability-state 503 contract around
  `getrawtransaction`.
- `/rest/block`, `/rest/block/notxdetails`, and `/rest/blockpart` return HTTP
  404 for an unknown well-formed block hash or unavailable pruned body. Full
  block/body materialization is capped at 4,000,000 bytes and shares a
  two-request render budget; only that explicit capacity limit returns HTTP
  503 with the retry message.

Header `count` defaults to 5 and must be in the inclusive range 1–2000.
Out-of-range, negative, non-numeric, and overflowing values return HTTP 400
with Core's invalid-count message. Unknown query parameters are ignored, so
cache-buster parameters do not affect the response.

These are current implementation guarantees, not the target coherent-view
model described elsewhere. A future request-wide stamp must land with the
handler implementation and observable route tests before this guide can claim
that stronger behavior.

The REST gateway does not change the reported `getnetworkinfo` version. When
using the unmodified `bip300301_enforcer`, pass
`--bitcoin-core-skip-version-check`.

bitcoin-rs publishes the Core-compatible `pubsequence` ZMQ topic with block
connect (`C`) and disconnect (`D`) events. The configured endpoint is reported
by `getzmqnotifications`, so the unmodified enforcer can discover it through
its normal startup path rather than requiring an external publisher or an
explicit `--node-zmq-addr-sequence`. Mempool admissions publish `A` events and
removals publish `R` events on the same topic, each carrying the txid and the
mempool sequence assigned to the change. A transaction mined in a connected
block emits no `R`: the block's `C` event covers it, matching Core.

REST is off by default. With REST disabled, `/rest/*` returns HTTP 404.
Unknown REST routes return HTTP 404. On endpoints that parse a hash, height, or
outpoint before selecting a format, a missing extension returns HTTP 404 while
an unknown extension remains part of that parameter and returns HTTP 400.
`/rest/chaininfo` and `/rest/deploymentinfo` return HTTP 404 for a non-JSON
format. `/rest/mempool` validates its `info` or `contents` resource first, so
an unknown suffix returns HTTP 400. Malformed hashes and header `count` values
return HTTP 400. Probe a known supported endpoint such as
`/rest/chaininfo.json` to distinguish a disabled REST gateway from an invalid
request.

The checked-in Compose stack (`tools/bip300301-enforcer/docker-compose.yaml`)
supplies the REST, `pubsequence`, version-check bypass, and drynet4 network
settings required to run the unmodified enforcer. Because `pubsequence`
carries transaction `A`/`R` events, the stack enables `--enable-mempool` so
the enforcer tracks the mempool too.

See also [docs/contracts/external-api.md](contracts/external-api.md) for the
API manifest contract and precedence rule, and [rpc-reference.md](rpc-reference.md)
for the generated per-route status table.
