# USDT tracepoints (Bitcoin Core-compatible)

bitcoin-rs can emit User-space Statically Defined Tracing probes whose
provider names, probe names, and argument ABI match Bitcoin Core's
`doc/tracing.md`, so Core-oriented tooling consumes a bitcoin-rs node without
any bitcoin-rs-specific runtime. Where probe payloads sit relative to
`metrics::` signals and `tracing::` diagnostics is owned by
[`observability.md`](observability.md) (OBS-03): detailed per-event data —
payloads, hashes, durations — belongs in probe arguments and must not pollute
metrics cardinality. The probes are compiled in only with the
`usdt` cargo feature (default **off**):

```bash
cargo build --release --features usdt -p bitcoin-rs
```

Probe emission follows the `usdt` crate's platform support: x86-64 Linux via
SystemTap SDT notes (ARM Linux is untested upstream and may work by
accident), macOS, FreeBSD, and illumos.

With the feature on, probe payloads are prepared **only** while a consumer
(bpftrace, BCC, DTrace) has attached to a probe: each call site passes a lazy
`prepare` closure that the emitter runs behind the probe's `.probes` semaphore
(the same guard Core's `src/util/trace.h` uses). Unattached, the cost is one
volatile semaphore load per probe site; with the feature off, the call sites
are empty functions and the payload preparation is skipped.

The machine-readable ABI table lives in
[`crates/consensus/probes.d`](../crates/consensus/probes.d) (the generator
input of the `usdt` crate) and is asserted against the built binary's
SystemTap SDT notes by `crates/consensus/tests/sdt_notes.rs`.

## Compatibility table

Argument types are given as published by Core's `doc/tracing.md`, with the
SystemTap layout string of Core's shipped `bitcoind` binary in parentheses
(the layout is what consumer scripts bind to).

| Core probe | Core argument ABI | bitcoin-rs emission point | Payload mapping | Unsupported fields / semantic differences |
| --- | --- | --- | --- | --- |
| `validation:block_connected` | 1. block hash `uint8_t*` (32 bytes LE) (`8@`)<br>2. height `int32` (`-4@`)<br>3. tx count `uint64` (`8@`)<br>4. input count `int32` (`-4@`)<br>5. sigops cost `uint64` (doc) — Core's binary emits `int64` (`-8@`)<br>6. connect duration ns `uint64` (doc) — Core's binary emits `int64` (`-8@`) | `crates/chainstate/src/connect.rs` `emit_block_connected`, fired after the block's consensus state is committed in `apply_block_admitted` (the same point Core fires at the end of `ConnectBlock`) | 1. `block_hash.as_byte_array().as_ptr()` (caller-owned hash local that outlives the probe)<br>2. applied height<br>3. `block.txs.len()`<br>4. sum of `tx.inputs.len()` over all txs (coinbase included, as Core's `nInputs`)<br>5. sum of `bitcoin_rs_consensus::transaction_sigop_cost` over all txs against the connect view — the same rules as Core's `GetTransactionSigOpCost`<br>6. `total_started.elapsed()` in ns, captured after the in-memory UTXO application — the `UpdateCoins`/`SetBestBlock` tail of Core's `ConnectBlock` interval; it therefore spans prevout resolution, undo persistence, block-body persistence, and block-tree insertion, and excludes the later durable flush (Core's `view.Flush()` in `ConnectTip`) | Args 5/6 are signed 64-bit (`-8@`) in Core's shipped notes although `doc/tracing.md` says `uint64`; bitcoin-rs matches the **binary** so consumer scripts bind identically. The per-tx prevout resolution for arg 5 runs inside `prepare`, so it costs nothing when no consumer is attached. Windowed (`PublishMode::Grouped`) applies still fire at consensus-commit time, not at the later durable-publish time. |
| `mempool:added` | 1. txid `uint8_t*` (32 bytes LE) (`8@`)<br>2. vsize `int32` (`-4@`)<br>3. fee `int64` (`-8@`) | `crates/mempool/src/pool.rs` `Mempool::commit_insert`, after the entry is linked into the pool (Core fires from `CTxMemPool::addUnchecked`, the same install funnel) | 1. `entry.txid.as_bytes().as_ptr()`<br>2. `entry.vsize` (policy vsize; Core uses its entry's `GetTxSize()` — same quantity: the virtual size counted for policy)<br>3. `entry.fee` | — |
| `mempool:removed` | 1. txid `uint8_t*` (`8@`)<br>2. reason `char*` (max 9 chars) (`8@`)<br>3. vsize `int32` (`-4@`)<br>4. fee `int64` (`-8@`)<br>5. entry time (epoch) `uint64` (`8@`) | `crates/mempool/src/pool.rs` `Mempool::remove_entries_with_reasons` and `Mempool::clear`, per entry as it is retired (Core fires from `CTxMemPool::removeUnchecked`) | 1. `entry.txid.as_bytes().as_ptr()`<br>2. Core's `RemovalReasonToString` values: `block`, `replaced`, `conflict`, `expiry`, `sizelimit`, `reorg`<br>3. `entry.vsize`<br>4. `entry.fee`<br>5. `entry.time` | bitcoin-rs maps `PolicyEviction` → `sizelimit`, replacement descendants → `replaced`, and a wholesale pool clear → `unknown`, the string Core's `RemovalReasonToString` emits for `MemPoolRemovalReason::UNKNOWN` (7 chars, within the 9-char limit). Arg 5 is the acceptance timestamp recorded by the node's clock — Core records the mempool entry acceptance time likewise; both are seconds-since-epoch. |
| `net:inbound_message` | 1. peer id `int64` (`-8@`)<br>2. address:port `char*` (`8@`)<br>3. connection type `char*` (`8@`)<br>4. message type `char*` (`8@`)<br>5. message size `uint64` (`8@`)<br>6. message bytes `uint8_t*` (`8@`) | `crates/p2p/src/net_trace.rs`, fired per checksum-valid wire message before typed decoding in the connection read loop and during the handshake | 1. `PeerLease::node_id()` (process-unique connection id, Core `nodeid`)<br>2. peer `SocketAddr` as `host:port`<br>3. `inbound` for accepted connections<br>4. wire command (e.g. `inv`, `ping`, `getdata`); for messages with no known command it is the raw 12-byte header command — UTF-8-validated only, not a decoded type<br>5. encoded payload length<br>6. the checksum-validated wire payload as read | bitcoin-rs labels connections with Core's `ConnectionTypeAsString` values for the classes it has: accepted connections report `inbound`; dialed connections report `outbound-full-relay`, `block-relay-only`, or `manual` by role and dial kind (there is no `addr-fetch`/`feeler` class). The message-bytes argument is passed **by value** as Core does: the consumer receives the buffer address and reads `size` bytes from it. |
| `net:outbound_message` | same as `net:inbound_message` | `crates/p2p/src/net_trace.rs`, fired per write **attempt** (a write can fail after the probe fires) by the connection writer and during the handshake | as above; arg 6 is the `FramedMessage`'s encoded payload — the same bytes the vectored write emits. Each message encodes into a frame once, shared by the write path and the probe, the way Core reuses `CSerializedNetMsg`. | Message bytes are the encoded payload; Core passes the same payload view it sends. Size is the payload length (not the 24-byte framed length). |

### Not implemented

Core's `utxocache:*`, `mempool:replaced`, `mempool:rejected`,
`net:inbound_connection`, `net:outbound_connection`,
`net:closed_connection`, `net:evicted_inbound_connection`,
`net:misbehaving_connection`, and `coin_selection:*` probes are out of scope
for this slice (see the issue's non-goals). IPC compatibility is not a goal:
the consumer surface is the SDT note only.

### Byte-pointer arguments (ABI note)

Core's hash/message buffer arguments bind as *pointers by value* (`8@%reg`):
the consumer receives the buffer address. The `usdt` crate's `uint8_t*`
declaration instead generates the dereferencing operand `8@(%reg)`, which
would hand the consumer the buffer's first bytes. bitcoin-rs therefore
declares those arguments `uint64_t` in `crates/consensus/probes.d` and feeds
the buffer address, reproducing Core's operand form exactly. String arguments
(`char*`) need no workaround: the `usdt` crate's `char*` generates Core's
by-value pointer operand. `crates/consensus/tests/sdt_notes.rs` asserts the
artifact's argument-layout strings (via `SDT_ELF=<binary>`) against this
table: the full `size@operand` strings on x86-64, where the register
spellings are verified, and the `size@` prefix sequence on other ELF
architectures (AArch64's `w`-register spellings are unverified upstream),
so an operand-form regression fails the test on the verified architecture.

## Smoke test

`docs/tracing/smoke.bt` is adapted from Core's
`contrib/tracing/log_p2p_traffic.bt` and binds Core's argument positions
directly. On a Linux host with `bpftrace` and root:

```bash
cargo build --release --features usdt -p bitcoin-rs
sudo bpftrace docs/tracing/smoke.bt
./target/release/bitcoin-rs   # in a second terminal, once bpftrace has attached
```

When bpftrace and the kernel support uprobe refcounts, path-based `usdt:`
probes also work on an already-running node. Without that support, start
the node before bpftrace attaches and pass `-p $(pgrep bitcoin-rs)` to
bpftrace to activate its semaphores. Every `usdt:` selector embeds the
`./target/release/bitcoin-rs` path literally — bpftrace reads the SDT notes
from that file and takes no binary argument. To run the same script against
a running or Core `bitcoind`, replace the selector paths with that binary's
own path; the probe names and argument positions are identical.

**Live run status: RUN.** Verified 2026-09-29 on x86-64 Linux (kernel
7.0.0-31-generic, bpftrace v0.25.0) against a release build with
`--features usdt`: two `--network regtest` nodes (one dialing with
`--connect`, one accepted inbound, one late dialer connecting only after
the tracer attached), then three `generatetoaddress` blocks over RPC, with
the full `smoke.bt` program attached in one session:

```bash
sudo bpftrace -e "$(cat docs/tracing/smoke.bt)"
```

In a ~10 s window that session printed 15 `net:inbound_message` and 15
`net:outbound_message` events — complete `version`/`wtxidrelay`/
`sendaddrv2`/`sendheaders`/`verack`/`sendcmpct` handshakes in both
directions, the manual dial reporting conn type `manual` and accepted
connections `inbound` — plus 4 `validation:block_connected` events with
sane payloads (`block connected at height 3: 1 txs, 1 inputs, 0 sigops
cost in 207676 ns`). The `mempool:added`/`mempool:removed` blocks compiled
and attached but did not fire: nothing relayed a transaction in the window,
so they stand verified by the SDT note assertion below. This closes the
live-runtime acceptance item of #1121; before #1292 the `net:*` notes were
absent from the node binary entirely because `crates/p2p` had no emission
sites.

Two bpftrace packaging notes from that run, so the next runner does not
re-diagnose them: bpftrace 0.25.0 as shipped on Ubuntu 26.04 asserts in
`SourceLocation::source_context` while rendering BPF-compiler warnings for
**file**-based scripts (an upstream rendering bug; the inline
`-e "$(cat ...)"` form above is the workaround), and bpftrace 0.27.0 runs
the file script and fires `validation:block_connected` but delivered no
`net:*` events.

**bpftrace 0.27 follow-up: both implementations emitted `net:*`.** A
same-host comparison on 2026-09-29 used x86-64 Linux 6.8.0-117-generic,
bpftrace v0.27.0, the pinned Core 31.1 release, and bitcoin-rs source
`73f9ee62115de60e6b89f1a05a97a71cd2032674` built with
`--release --no-default-features --features fjall,usdt`. Each implementation
ran two isolated regtest nodes. The tracer attached before `addnode onetry`
connected them; both nodes received `ping` calls and the traced node mined
three blocks. The same `smoke.bt` program was supplied with `-e` and `-p`,
changing only its binary selector path between implementations.

| Implementation | Inbound events | Outbound events | Block-connected events |
| --- | ---: | ---: | ---: |
| Bitcoin Core 31.1 | 52 | 52 | 6 |
| bitcoin-rs | 18 | 12 | 6 |

Both runs retained one peer per node and the tracer exited successfully.
Counts include only complete runtime event lines, excluding compiler-warning
excerpts that echo the script's `printf` calls. They are not a parity
requirement. The original Ubuntu 26.04/kernel 7.0 file-script invocation
was **not re-tested**; its earlier silence remains unresolved. This run used
a different kernel and inline invocation and does not isolate the cause or
certify that original environment.
It does show that bpftrace 0.27 can consume both implementations' `net:*`
probes in the tested environment. No mempool event delivery is claimed.

Artifact identities (SHA-256):

- bpftrace: `16194f713ba1fbff2dd76b7abffad4cd61f91e5663b116a5b03c907ae3e20cd8`
- Core `bitcoind`: `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`
- bitcoin-rs: `edda12332fb24361f70db758e08b705832f91cdd40af929fb075f48b2ac9e9ac`

The static evidence shipped alongside the live run is the SDT note
assertion in `crates/consensus/tests/sdt_notes.rs`, which reads the built
binary's `.note.stapsdt` section and checks provider, probe name, and the
full `size@operand` argument layout strings against `probes.d` on the
verified x86-64 architecture. It passes against the node binary built with
`--features usdt` (cargo runs the test binary from `crates/consensus`, so the
path must reach the artifact from there):

```bash
cargo build --release --features usdt -p bitcoin-rs
SDT_ELF=$PWD/target/release/bitcoin-rs cargo test -p bitcoin-rs-consensus --features usdt
```
