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
| `/rest/getutxos[/checkmempool]/{txid}-{vout}...` | JSON, hex, binary | URI GET and binary/hex POST UTXO lookup; at most 15 outpoints |
| `/rest/deploymentinfo[/{hash}]` | JSON | Native deployment state and script flags; declared Core activation deviations (external API contract) |
| `/rest/blockhashbyheight/{height}` | JSON, hex, binary | Block hash by height |
| `/rest/spenttxouts/{hash}` | JSON, hex, binary | Explicitly unavailable: no undo data |

## UTXO POST input

`POST /rest/getutxos.bin` accepts a one-byte `checkmempool` boolean followed
by a canonical CompactSize count and that many outpoints (32-byte transaction
hash in consensus byte order, then little-endian `u32` output index).
`POST /rest/getutxos.hex` accepts the same bytes as hex; ASCII whitespace is
allowed between byte pairs. Input and response formats must match.

Both forms share GET's lookup and response encoding. With `checkmempool`,
outputs spent in the pool are absent and pool-created outputs are present
with Core's REST height sentinel `2147483647`. Confirmed-only requests
exclude chain transitions during the tip/coin capture; mixed requests retain
the existing mempool generation checks. Locks are released before rendering.

The maximum body is 2048 bytes including hex whitespace, enforced before
HTTP body allocation/read. The decoded request contains at most 15
outpoints. A zero-point serialized vector is valid. Empty requests,
JSON bodies, mixed URI/body input, noncanonical counts, truncation, trailing
bytes and excessive counts/bodies return HTTP 400. Oversized HTTP requests
close the connection without reading the body. Empty-body POST with URI
outpoints retains the URI request form. Other REST resources remain GET-only;
REST remains opt-in, unauthenticated, and without CORS headers.

This endpoint intentionally differs from Bitcoin Core 31.1 POST: its
`src/rest.cpp` serializes the incoming string into a DataStream, prepending
its length and shifting the boolean/count/outpoints. Canonical POST here is
decoded directly. The process test compares complete response bytes with
same-tip Core GET and independent wire fixtures, and explicitly verifies
the released Core POST discrepancy. This is a declared deviation, not exact
Core POST parity. Malformed bodies are rejected rather than reproducing
Core's permissive handling of some hex/JSON/trailing inputs.

## Coherent views

Handlers that read chain state capture the applied-tip publication
(`ChainHandles::applied_view`, one `TipSnapshot` load) and assemble their
responses from that view: `route_block` in its `json` arm, `route_getutxos`
inside its stable plain read or after its mixed mempool read, plus headers,
chaininfo, and deploymentinfo.
`/rest/tx/<hash>.hex` and `/rest/blockpart` return without it. A response
never mixes a tip loaded from one commit with coins, mempool contents, or
index rows from another.

- If the chain generation is odd when the request arrives, or moves before the
  response is assembled, the gateway returns HTTP 503 with a short retry
  message. Retry the request; the next attempt reads a fresh view.
- Routes that combine confirmed and mempool data (`/rest/getutxos/checkmempool`,
  `/rest/mempool/*`) use a mempool view reconciled to the same chain
  generation. A stable chain alone is not enough; the reconciled pool is part
  of the stamp.
- Routes backed by an optional capability (`/rest/tx` for non-mempool
  transactions through `TxLookup`) return HTTP 503 with the capability state
  when that capability is not `Ready` at the requested tip. Unavailable is not
  empty: a lagging, rebuilding, or disabled index never produces an empty
  successful body. A well-formed identifier the node has never seen returns
  HTTP 404 as in Core. A route the manifest declares unavailable
  (`/rest/spenttxouts`) answers with its declared unavailable response, never
  an empty success.

Full-block `/rest/block` and `/rest/blockpart` requests share a budget of two
concurrent materializations. When it is full, the gateway returns HTTP 503;
retry the request after a short delay. Request bodies, header counts, and
response assembly are bounded so a public read cannot consume the validation
CPU and memory budget.

Header `count` defaults to 5 and must be in the inclusive range 1–2000.
Out-of-range, negative, non-numeric, and overflowing values return HTTP 400
with Core's invalid-count message. Unknown query parameters are ignored, so
cache-buster parameters do not affect the response.

Active-chain requests walk forward by height from the tip in the request's
view. A side-branch, orphaned, or header-only hash above that tip returns HTTP
200 with an empty JSON array (or an empty hex/binary body), just like an
unknown well-formed hash, because Core only walks hashes contained in its
active chain. This empty answer is a chain-membership fact from a coherent
view, not an unavailable capability.

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

See also [docs/contracts/external-api.md](contracts/external-api.md) for the
API manifest contract and precedence rule, and [rpc-reference.md](rpc-reference.md)
for the generated per-route status table.
