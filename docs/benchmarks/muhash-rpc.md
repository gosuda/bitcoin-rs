# MuHash RPC comparator

`tools/benchmark-campaign/muhash_rpc.py` compares the production full-UTXO
MuHash query in Bitcoin Core 31.1 with the same query in bitcoin-rs. It is a
custody controller, not a benchmark result. This repository does not claim
that a live corpus run has been performed: the seven-pair campaign and any
comparative number remain pending external execution against unmodified
daemons (see "Status").

## Measured contract

Every measured observation is exactly one JSON-RPC call, and the client can
send no other:

```json
{"method":"gettxoutsetinfo","params":["muhash",null,false]}
```

The historical-height argument is `null` and `use_index` is `false`, so both
processes must already be committed at the frozen corpus tip. Core 31.1
performs `ForceFlushStateToDisk(false)` inside this production RPC; that
flush stays inside the measured interval because it is part of the call. No
supervisor RPC, warm-up query, or explicit flush call exists in v2 — the
handler records every POST a trial makes, and the protocol test asserts the
fixture saw exactly one request.

The monotonic interval spans the whole one-shot exchange: `perf_counter_ns`
is read immediately before the fixed request body is handed to the
transport and again only after the bounded response has been fully received,
decoded as JSON, envelope-validated (`jsonrpc == "2.0"`, matching id,
`error: null`), parsed into the strict eight-field UTXO state, and checked
against the frozen tip. Core always answers a JSON-RPC 2.0 request with
HTTP 200 and reports RPC errors in the body's `error` field, so the
envelope check is authoritative. A non-positive or non-monotonic duration
refuses the run.

## Transport and custody limits

- The endpoint must be a literal-loopback HTTP URL (`127.0.0.1` or `::1`)
  with an explicit port and a path, and no userinfo, query, or fragment.
  Environment proxies are irrelevant by construction: the trial speaks HTTP
  over a raw nonblocking socket, so no proxy library or environment
  variable is consulted, and any non-200 status is refused.
- One monotonic end-to-end deadline (at most 300 seconds) covers connect,
  status line, headers, and body. The client is a small HTTP/1.1 loopback
  client: selector interest is set per operation (write for connect and
  send, read for receive) so a permanently write-ready socket can never
  spin a read wait, every wait is bounded by the remaining absolute
  budget, the fixed request is sent with `Connection: close`, the header
  block is byte-capped, and the exchange is refused unless the response
  carries status 200 with exactly one valid `Content-Length` within the
  response cap. `Transfer-Encoding`/chunked framing, obsolete header
  folding, duplicate, leading-zero, overlong, or non-numeric lengths,
  short bodies, bytes coalesced beyond the declared length, and delayed
  post-length bytes (proven by waiting for EOF under the same deadline)
  are all refused, and the absolute deadline is verified again after
  decoding.
- All parsed JSON — trial input,
  receipts, observations, aggregate manifests, RPC envelopes, and the
  embedded raw response — is depth-limited and parsed with a
  duplicate-member-rejecting hook, so two members with the same name at any
  nesting level refuse the run instead of silently last-value-wins. The
  duplicate-member refusal is a fixed generic message that never echoes the
  member-name text, and decoder failures that would otherwise escape as a
  traceback — recursion exhaustion and overlong integer tokens — are
  translated into the same typed refusal.
- Every `total_amount` is validated as a Bitcoin amount before it can reach
  canonical hashing: finite, nonnegative, at most 21,000,000 BTC, and at
  most eight fractional digits. Extreme exponents such as `1e999999999` or
  `1e-999999999` are refused cheaply instead of being expanded into
  fixed-point text.
- Files named by a `FileRef` (`path`, `sha256`, `bytes`) are opened once
  with `O_NONBLOCK`, fstat-checked as regular files before any read (a FIFO
  or device is refused immediately instead of blocking on a missing
  writer), size-capped, read from that single
  descriptor, and hashed from the bytes read; an identity change mid-read
  refuses the run. The credential file is held to the same nonblocking,
  regular-file, exact-byte-count
  and stable-identity rule through one read descriptor, checked to owner
  mode `0600`, and parsed in-process only; credentials are never emitted,
  logged, or written into any record or error message.

## Receipts are controller declarations

The pre- and post-receipt files are operator declarations, not endpoint
attestation. The operator is the trust root; the comparator explicitly
disclaims remote binary authentication via the required
`operator_trust_boundary` field. What the receipts do provide is a hash
graph that binds declarations to observations:

trial input file   --canonical_sha256--> observation.input_sha256
fixed request body --sha256--> observation.request_sha256
pre-receipt bytes  --sha256--> observation.controller_declaration_sha256
                             and post.pre_receipt_sha256
observation fields --canonical_sha256--> observation.self_sha256
                                 --> post.observation_sha256
raw response bytes --base64 in observation.raw_response_b64,
                   --sha256--> observation.raw_response_sha256
aggregate manifest --sha256--> result.config_sha256
result record      --canonical_sha256--> result.result_sha256

The pre-receipt declares the observed executable, node config, corpus,
backend, datadir, endpoint, affinity, cache-policy action, frozen tip, and
`/proc` fault and I/O counters, plus the attested PID and process starttime
binding the endpoint to a specific process lifecycle. The post-receipt
re-records the PID/starttime (which must equal the pre-receipt within one
observation) and the counter deltas. Each aggregate triple therefore pins
four files: the trial input, pre-receipt, observation, and post-receipt.
Aggregate re-verifies the trial input's FileRef, re-parses it strictly,
checks its coordinates, endpoint, corpus, frozen tip, and pre-receipt
reference against the triple, recomputes its canonical hash, recomputes the
fixed request body hash, and base64-decodes the embedded raw response to
re-hash it, strict-parse its envelope, and prove its parsed state equals
the observation's state. A single mismatch anywhere refuses the campaign.

## One policy, seven alternating pairs

A campaign declares exactly one cache policy; a second policy is a second
campaign and a second result file. There is no fresh/warm dual phase.

- `warm`: one untimed exact production query per arm after frozen-tip
  verification (declared in `cache_policy_action`), then one stable
  PID/starttime across all seven observations per arm, and the two
  arms' stable identities must differ from each other.
- `process-cold/page-cache-unspecified`: a fresh PID/starttime before
  every one of the fourteen observations, unique across the whole
  campaign; distinct endpoint strings do not prove a distinct process,
  so reusing an identity across arms is refused.
- `process-cold/page-cache-evicted`: the same campaign-wide
  fresh-lifecycle rule plus a pinned
  `eviction_procedure` artifact in the pre-receipt and a per-observation
  `eviction_execution` record with exit status 0 in the post-receipt whose
  monotonic timestamp precedes the observation's start. Hashing the
  procedure is not proof it ran, and a timestamp at or after the timed
  query is refused as internally impossible evidence.

The aggregate consumes 14 strict pre-receipt/observation/post-receipt
triples — seven pairs, even pairs Core then bitcoin-rs, odd pairs
bitcoin-rs then Core, each pair index appearing exactly twice. Missing,
duplicated, reordered, or extra triples are refused; no retry based on an
alternative outcome exists anywhere. The declared schedule is also bound
to physical chronology: in manifest order, every observation's monotonic
start must be at or after the previous observation's monotonic end, so
overlapping or reordered intervals are refused and the alternating
labels cannot disguise concurrent or regrouped execution.

## Correctness gate

No result file is created unless all of these hold:

- every receipt file matches its pinned byte count and SHA-256 and the full
  hash graph above recomputes — including the trial-input, request-body,
  and embedded-raw-response edges;

`bogosize` and `disk_size` remain in every observation for diagnosis but are
not equality fields: storage implementations legitimately represent the
same UTXO set differently. `total_amount` is compared as a Decimal value,
never as JSON text, so `12.50000000` equals `12.5`.

A timeout, redirect, HTTP failure, JSON-RPC error, oversized or too-deep
body or file, duplicated JSON member, unknown schema member, out-of-domain
amount, malformed
field, custody change, broken hash edge, policy violation, or pre-existing
output path ends the run with exit status 2 and no comparative record.
Refusal messages name the failed gate and never include credentials, raw
untrusted response bodies, or attacker-controlled member names: wrong-key
diagnostics carry counts only, and duplicate-member refusals are fixed
strings.

## Statistics and result identity

Each arm receives nearest-rank percentiles over its exactly seven samples:
for sorted observations $x_1 \ldots x_n$, percentile $p$ is
$x_{\lceil pn/100 \rceil}$. With seven samples, p95 and p99 equal the
maximum. No arithmetic mean is emitted or used for a verdict. The verdict
names the arm with the lower nearest-rank p50, or records a tie; it is
emitted only after every gate above has passed. `result_sha256` hashes the
Decimal-safe canonical JSON record before the field is added.

## Invocation

Run one timed observation:

```text
python3.14 tools/benchmark-campaign/muhash_rpc.py trial \
  --input /bench/trial-input.json --output /bench/obs.json
```

Run a full lifecycle-owned campaign (spawns both arms, applies the declared
cache policy, writes the 14 receipt triples, and publishes the result):

```text
python3.14 tools/benchmark-campaign/muhash_rpc.py campaign \
  --input /bench/campaign.json --workspace /bench/work --output /bench/result.json
```

Aggregate a complete campaign:

```text
python3.14 tools/benchmark-campaign/muhash_rpc.py aggregate \
  --input /bench/aggregate-manifest.json --output /bench/result.json
```

The trial input is a strict `muhash-rpc-trial-input-v2` object (unknown or
missing keys rejected) carrying the coordinates, endpoint, credential file
reference, timeout, response cap, corpus, expected frozen tip, and the
controller pre-receipt reference. The campaign config is a strict
`muhash-rpc-campaign-config-v2` object that binds one Core arm (`backend` is
always `coinsdb`) to one bitcoin-rs arm (`backend` is exactly one of
`fjall`, `rocksdb`, or `redb`), the single cache policy, the corpus, and the
pinned binaries and commands. `{binary}` is copied and re-hashed before every
spawn; `{config}` is required so the receipt's pinned config is the file the
daemon received (`docs/contracts/muhash-rpc.md` `MRPC-03`): the controller
copies that file into the workspace, re-hashes the copy before every spawn,
and substitutes the copy path. `{rpc_bind}`, `{rpc_port}`, `{data_dir}`, and
`{cookie}` are the only other placeholders. Readiness requires the listening
socket inode to belong to the spawned child. The timed query is sent only
after the ESTABLISHED peer inode belongs to that same attested process
(`MRPC-02`). The controller owns process lifecycle and `/proc`
fault and I/O snapshots, writes each pre-receipt/trial/observation/post-receipt
triple, and then hands the same 14 triples to `aggregate`. A second backend
is a second campaign and a second result file.

The aggregate manifest is a strict
`muhash-rpc-aggregate-input-v2` object carrying the campaign, the single
policy, the corpus, and the 14 triple references in schedule order; each
triple pins its trial input, pre-receipt, observation, and post-receipt
files. Every referenced file must already exist with its declared size and
hash; the comparator never fetches anything. Output paths must not already
exist. Publication establishes namespace trust component by component:
every ancestor is opened with `O_NOFOLLOW` from the previously opened
directory descriptor, and any ancestor an untrusted user could rename
through is refused unless it follows the root-owned sticky `01777`
contract with an effective-user-owned, non-writable child. The record is
written to an anonymous `O_TMPFILE` inode in the held trusted directory,
fsynced, and the parent's namespace identity is re-established (a fresh
trusted traversal must resolve to the same inode) immediately before
publishing with `linkat(AT_EMPTY_PATH)` against the still-open descriptor;
a rename/rebind of the requested pathname therefore refuses instead of
returning a success the caller cannot see. No replaceable temporary name
ever exists, a final inode check proves the published bytes are the
record, and if any verification or durability step fails after the link,
the linked name is removed through the held directory descriptor only
after a no-follow check that it still identifies the linked inode,
followed by a best-effort directory sync — a substituted inode is never
removed. A refused run or caught post-link failure leaves no comparator-owned
partial record. An uncatchable interruption after `linkat` can leave a complete
record whose final durability check did not run.

## Status

The protocol contract above is implemented and covered by local fixture
tests, including a lifecycle-owned campaign against fixture RPC daemons for
every bitcoin-rs backend (`fjall`, `rocksdb`, `redb`) paired with a Core
arm. The live evidence is not: no unmodified-daemon smoke has confirmed
that both Bitcoin Core 31.1 and the bitcoin-rs RPC server accept the exact
triplet against a frozen-tip corpus. Any future comparative claim must come
from executing that campaign against unmodified daemons and publishing its
result file; until then this document records a controller, not a
measurement.
