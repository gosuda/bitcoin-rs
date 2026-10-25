# P2P overlay interoperability test specification

This document specifies the end-to-end integration and verification harness for Tor (onion v3) and I2P overlay networking in `bitcoin-rs` (#1601), implemented by `scripts/run-p2p-overlay-interop.sh`.

## 1. Overview and objectives

`bitcoin-rs` supports peer-to-peer connectivity across privacy overlay networks:
- Tor v3: outbound connections via SOCKS5 proxy with remote DNS resolution (`ATYP=0x03`), inbound hidden service publication via the Tor ControlPort using ephemeral or persisted ed25519-v3 keys.
- I2P: outbound and inbound streaming connections via the I2P SAM (Simple Anonymous Messaging) v3.3 bridge.

The `run-p2p-overlay-interop.sh` script executes an automated regtest integration suite between two independent `bitcoin-rs` daemon processes, verifying:
1. Strict toolchain and binary pins for external daemons (Tor 0.4.9.14 and IVNP Go 1.27.0 source pin).
2. Wire protocol compliance through a non-invasive, bounded loopback recorder proxy.
3. Transport isolation, ensuring Onion and I2P transports operate independently without IP leaks or cross-transport crosstalk.
4. Bidirectional header and block propagation over both overlay transports.
5. Persistent daemon identity and private key security, including POSIX file mode `0600` and byte-identical key retention across restarts.
6. Fail-closed error handling with honest evidence reporting (schema `bitcoin-rs-overlay-interop-v1`).
7. Child process ownership: every daemon the script launches is signaled and reaped only through a validated Linux pidfd, never by a bare process number (section 3.2).

---

## 2. External daemon pins and build verification

The test harness requires exact, reproducible external daemons. Any version or metadata mismatch causes the script to fail closed immediately.

### Tor pin: release 0.4.9.14
- Requirement: official Tor release `0.4.9.14`.
- Verification: the first line of `${TOR_COMMAND} --version` must match the regular expression:
  ```regex
  ^Tor version 0\.4\.9\.14(?:\s+\(git-[0-9a-fA-F]+\))?\.?$
  ```
- Rejection: pre-release versions (`-alpha`, `-rc`, `-dev`) or different minor/major versions are strictly rejected.

### IVNP pin: commit 0a1b746ba98b58510eb5dcde679ca43184f4b60e built with Go 1.27.0
- Requirement: IVNP I2P daemon built from commit `0a1b746ba98b58510eb5dcde679ca43184f4b60e` with compiler `go1.27.0`.
- Upstream build metadata and release stamping:
  - In upstream IVNP source (`cmd/ivnpd/main.go`), the version string variable defaults to `var version = "dev"`.
  - Upstream release packaging builds with linker flags (`-ldflags "-X main.version=v0.4.1"`). When built directly from git checkout using standard `go build ./cmd/ivnpd`, the binary `-version` prints `dev`.
  - The Go toolchain automatically embeds buildinfo metadata in the ELF binary header. Running `go version -m <binary>` exposes:
    - Go runtime/compiler version in the header (for example `go1.27.0`).
    - `build vcs.revision=0a1b746ba98b58510eb5dcde679ca43184f4b60e`.
    - `build vcs.modified=false`.
- Verification rule: the script reads the Go binary metadata using `go version -m` to enforce:
  1. `go_header == "go1.27.0"`
  2. `vcs.revision == "0a1b746ba98b58510eb5dcde679ca43184f4b60e"`
  3. `vcs.modified == "false"`
  4. `-version` execution produces output `dev` (qualifying the exact source pin honestly, rather than inventing or spoofing release tag strings).

---

## 3. Test architecture and topology

The test spins up a localized multi-daemon network whose listeners all bind loopback (`127.0.0.1`). Loopback binding is not isolation from the outside world: Tor and I2P are overlay networks, so the Tor and IVNP daemons need outbound internet access to bootstrap, and the run is `BLOCKED` without it:

```
+--------------------------------------------------------------------------+
| Workdir (ephemeral or user-specified)                                    |
|                                                                          |
|   +-------------------+              +-------------------------------+   |
|   | Tor Daemon        |              | IVNP Daemon                   |   |
|   | - ControlPort     |              | - SAM Bridge (127.0.0.1:7656) |   |
|   | - SOCKS5 Backend  |              +---------------+---------------+   |
|   +---------+---------+                              |                   |
|             |                                        |                   |
|             v                                        v                   |
|   +---------+----------------------------------------+---------------+   |
|   | Bounded Overlay Loopback Recorder Proxy (overlay_recorder.py)    |   |
|   | - Listens on recorder SOCKS and SAM proxy ports                  |   |
|   | - Sanitizes auth passwords and private SESSION DESTINATION lines |   |
|   | - Records ATYP=0x03 length=62, SAM 3.3 handshakes and streams    |   |
|   +---------+----------------------------------------+---------------+   |
|             ^                                        ^                   |
|             |                                        |                   |
|   +---------+---------+              +---------------+---------------+   |
|   | Node A (Listener) |              | Node B (Dialer)               |   |
|   | - Onion service   |              | - Outbound proxy dialer       |   |
|   | - I2P accept      |              | - Connects via Tor / I2P      |   |
|   +-------------------+              +-------------------------------+   |
+--------------------------------------------------------------------------+
```

### Components
1. Tor process: starts with loopback `ControlPort` (cookie authentication enabled) and `SocksPort`.
2. IVNP process: starts listening on pinned SAM port `127.0.0.1:7656`.
3. Loopback recorder proxy (`overlay_recorder.py`): transparent `asyncio` proxy positioned between the nodes and the overlay daemons. It captures wire observations to a JSON file. Its deadlines bound negotiation and writes; they never bound the lifetime of an established connection:
   - Bounded: SOCKS5 handshake reads, SAM lock-step negotiation (each command and its reply, up to `SESSION CREATE` or `STREAM CONNECT`/`STREAM ACCEPT`), and every `drain` into a peer wait at most `30.0`s (`IO_TIMEOUT`). The one exception is the reply to an exact `SESSION CREATE`, which waits at most `135.0`s (`SESSION_CREATE_TIMEOUT`): the node's whole root budget (TCP connect, `HELLO`, the 120 s pinned readiness wait, `NAMING LOOKUP`), fixed before the node connects, so the recorder never ends a root the node is still entitled to wait for. No other reply and no write drain uses the longer bound, and it is not an idle timer. A peer that does not accept a write within `30.0`s ends that connection.
   - Unbounded while idle: an established SAM session root and an established relayed stream (Tor SOCKS stream, `STREAM CONNECT`, `STREAM ACCEPT`) stay open across any idle period. The session root keeps observing later commands such as `NAMING LOOKUP`, redacting `DESTINATION` and `PASSWORD` exactly as before, and passes replies through raw.
   - Teardown: EOF, reset, or a failed bounded write in either direction cancels the other direction and closes both sockets, so the node and the daemon each see the close. Each connection handler is a task owned by the recorder's `main()`. Cancelling `main()` stops accepting, cancels every handler, and then closes the listeners. The recorder process itself is a child owned by the script (section 3.2): its `cleanup` trap sends `SIGTERM` through the recorder's validated handle, waits up to 5 seconds, then sends `SIGKILL` through the same handle and reaps it.
   - Non-EOF relay endings are written to `recorder.log` as the exception type only; no payload or SAM line is logged there.
4. Node A (`bitcoin-rs`, service host):
   - Configured with `--onion 127.0.0.1:<recorder_socks>`, `--torcontrol 127.0.0.1:<tor_control>`, `--i2psam 127.0.0.1:<recorder_sam>`, `--i2pacceptincoming`.
   - Generates persistent key files: `onion_v3_private_key` and `i2p_private_key`.
   - I2P inbound: after `STREAM ACCEPT` returns `RESULT=OK`, the bridge writes `<destination> [FROM_PORT=<n>] [TO_PORT=<n>]`. `TO_PORT` is parsed as `u16`. An absent `TO_PORT`, or `TO_PORT=0` (I2CP port 0, any or unspecified service, valid in SAM), yields the application fallback port the caller supplies; a nonzero value is used as reported. Non-numeric, overflowing, and duplicate `TO_PORT` fields are refused, a zero counting as present, so `TO_PORT=0 TO_PORT=9999` is a duplicate. The logical peer endpoint parser still refuses port 0; only this accept adapter normalizes it.
5. Node B (`bitcoin-rs`, dialer):
   - Configured with `--proxy 127.0.0.1:<recorder_socks>`, `--i2psam 127.0.0.1:<recorder_sam>`, `--v2transport=false`.

### 3.1 Observation persistence and the completion protocol
An observation snapshot is only evidence once the recorder has finalized it. The protocol has one authoritative failure path and one publication point:

- **Single failure path.** Any failed observation write (snapshot, temporary file, `rename`, or completion marker) records a sticky failure verdict and requests the run to stop. It is never cleared and never retried. A connection handler that raises is reported to the same verdict through its completion callback, and an accept loop that ends without a stop request is a failure too. Nothing else ends the run successfully.
- **Publication only at finalization.** During the run each connection writes `<workdir>/protocol_observations.json.partial` and nothing else. Finalization writes the snapshot to `<workdir>/protocol_observations.json` (temp file, `fsync`, atomic rename), then writes `<workdir>/protocol_observations.done` (temp file, `fsync`, atomic rename) containing `schema: "bitcoin-rs-overlay-observations-v1"`, `complete: true`, the snapshot's byte length, and its SHA-256. A recorded failure suppresses both writes, so no final snapshot or marker is produced.
- **Stale files never count.** The runner removes the snapshot, marker, and their temporary files before spawning the recorder, and the recorder removes them again at startup before its first write. A previous run in a reused `--workdir` therefore cannot supply evidence.
- **Bounded wind-down.** The recorder bounds its own shutdown with `FINALIZE_GRACE`. Stopping the listeners, cancelling every handler, and closing every socket must finish inside that grace. Exceeding it records a failure, prints it to `recorder.log`, and exits non-zero without publishing anything. The runner's own 20 second wait (that grace plus 5 seconds) is only a backstop for a recorder that cannot run its own guard; past it the recorder is killed through its handle and finalization fails.
- **Runner-side gate.** Immediately after the last node-level assertion and before the first observation read, the runner calls `finalize_recorder`. That sends `SIGTERM` through the recorder's validated handle, waits up to 20 seconds for the exit (then `SIGKILL` through the same handle, which fails finalization), and reaps the recorder with `wait` only after the handle observed the exit. It requires exit status `0` (a recorder that was already gone has no status and fails the run), then requires a marker whose schema is `bitcoin-rs-overlay-observations-v1`, whose `complete` is `true`, and whose recorded length and SHA-256 match the snapshot bytes actually read. Any mismatch fails the run. Only then are the SOCKS/SAM observations read, and only a run that passes this gate can print `overlay interop: PASS`.
- **Normal exit.** A completed run stops the recorder with `SIGTERM`, which the recorder handles by stopping its listeners, cancelling handlers (each closes its sockets within the bounded writer timeout), publishing the snapshot and marker, and exiting `0`. The script's `cleanup` trap still owns the recorder for every earlier failure path.

### 3.2 Child process ownership
A process number is a name that the kernel reissues once the process is reaped. `kill -0`, or a parent-pid read followed by a numeric `kill`, cannot prove that the name still means the launched child at the instant of the signal. The script therefore never signals by number:

- **Capability gate.** Before any daemon is launched, the script runs a self-test of its private process-ownership helper. The helper is an inline script for the same `python3` the runner already uses (standard-library `os.pidfd_open`, `signal.pidfd_send_signal`, and `select.poll`; no dependency and no generic supervisor). It needs Linux 5.3 or newer, Python 3.9 or newer, and a `/proc` that belongs to the script's pid namespace. A host that cannot supply them fails closed with exit `1` and an explicit message, and the caller records the run as `BLOCKED`.
- **Identity at launch.** Immediately after each launch the script records the child in its owner table as `pid -> start time`, where the start time is field 22 of `/proc/<pid>/stat`. The shell reads that file itself, before it spawns anything else, so the only child of the script that can carry the number is the one just launched, and a process that reused the number would have another parent. The parent must be the script's own pid and the state must not be zombie or dead. Parent, pid, and start time name exactly one process. A child that already exited, or is not a live child of the script, cannot be recorded and stops the run. No helper process is involved at this step, so a helper can never be mistaken for the launched child, and the stop-time helper additionally refuses to treat its own pid as an owned child. Tor, the recorder, and every `bitcoin-rs` node are plain background commands. IVNP is started as `( cd <dir> && exec <ivnp-command> ... ) &` so the owned pid is the daemon itself and not a disposable subshell whose death would leave the real daemon unowned.
- **Validation before any signal.** Every stop opens a fresh pidfd, then reads `/proc/<pid>/stat`, then reads the pidfd's `fdinfo`. A `Pid:` that still equals the number after the `/proc` read proves the number belonged to the handle's process throughout, so the parent and start time read are its own. They must equal the recorded identity. If the number is absent, already reaped, or now names another process (including one with the right parent but a different start time), the owned child no longer exists: nothing is signaled and the entry is dropped as `gone`.
- **Signal, wait, and kill only through the handle.** `SIGTERM` is sent with `pidfd_send_signal` and the handle is polled for exit; it polls readable when the process exits, so a number reissued after validation is harmless. Every wait is finite. A child that has not exited when its `SIGTERM` budget ends gets `SIGKILL` through the same handle and a second finite wait. Budgets: Node A restart 15 s then 5 s, recorder finalization 20 s then 5 s, and `cleanup` and the final daemon teardown 5 s then 5 s, applied to all owned children together.
- **Reaping.** The shell calls `wait` only for a child whose exit the handle observed, so the call cannot block. The status value decides only the recorder's finalization, and the Node A restart requires that its exit was observed. A child reported `gone` is not waited on and has no status. Reaped and gone children leave the owner table, so a finished child is never addressed again.
- **Unkillable or unverifiable children.** A child that is still running after `SIGKILL` and its wait (for example in uninterruptible kernel sleep), or whose ownership could not be verified, is reported on stderr as stuck. It is never waited on and never signaled by number. The run fails: the teardown before `PASS` exits `1`, and `cleanup` forces a non-zero exit status. The workdir is kept while any child remains unconfirmed, including when `--keep` was not set.
- **No group signals.** The script uses no numeric `kill`, `killall`, `pkill`, or process-group signal, so it cannot touch itself, its caller, or an unrelated process.

### 3.3 I2P session root lifecycle and budgets
The node holds one persistent `SESSION CREATE STYLE=STREAM` root per SAM session (`crates/p2p/src/sam.rs`). The pinned IVNP bridge answers `SESSION CREATE` only once its destination is ready (inbound tunnel, outbound tunnel, confirmed publication), which can take its default two-minute readiness wait. The client therefore keeps three budgets apart and never widens the per-stream exchange to cover the readiness wait:

| Budget | Value | Owns |
|---|---|---|
| Root readiness (`ROOT_READINESS_BUDGET`) | 135 s: the 120 s pinned readiness wait plus three 5 s steps (connect, `HELLO`, `NAMING LOOKUP`) | One root, from just before its TCP connect to its install, so the connect is charged to the budget. Fixed once per root, before the connect; no caller and no phase moves it. |
| Stream exchange (`EXCHANGE_BUDGET`) | 5 s | `STREAM CONNECT`, `NAMING LOOKUP` for a peer, and one bounded key step. The `accept` wait stays the caller's own 1 s poll. |
| Startup owner (`I2P_STARTUP_BUDGET`) | 142.75 s: one key step (5 s), one full root readiness window (135 s), and the longest retry pause (2.75 s) | Everything node startup does for I2P, as one absolute monotonic deadline. A bridge that never accepts a connection gets only the 20 s unreachable window (below), not this budget. |

- **One resumable exchange.** A root under construction is one `PendingRoot` inside the session's `recovery` state: its socket, its readiness deadline, an explicit phase (`Hello`, `Create`, `Lookup`, or `Ready`), the number of bytes of the current command the socket already accepted, and the bounded (16,384-byte) partial reply line. Only a connect or accept caller holding `recovery` advances it, bounded by the earlier of its own deadline and the root deadline. No worker thread, retry queue, or second session map exists.
- **Caller deadlines pause, never discard.** A caller whose deadline ends mid-exchange gets `TimedOut` and leaves the exchange intact, partial reply line and write offset included; the next caller resumes it. A phase ends only when its reply line is consumed, and the next phase starts in the same step, so each of `HELLO`, `SESSION CREATE`, and `NAMING LOOKUP` reaches the bridge exactly once per root. A TCP connect that cannot finish inside a caller's deadline is abandoned with nothing sent, so it keeps no state.
- **What discards a pending root.** Only a hard protocol or I/O failure (including end of stream mid-reply), the root deadline, or `close`. Every discard shuts the socket down, so the bridge never keeps a session id alive for a root the client forgot. A caller that times out waiting for `recovery` or `control` reports `TimedOut` as a local transport failure, never peer evidence.
- **Install.** A complete root is installed under `recovery` then `control` only if the session is not closed, the root deadline has not passed, and the reported public destination equals the persisted one. The generation rises only at that point, so a delayed `INVALID_ID` about an older installed generation can never retire a pending or newer root. If the caller's own deadline passes while waiting for `control`, the complete root stays pending for the next caller.
- **Lock order.** `recovery` then `control`, never the reverse. `wake` is a leaf lock holding a clone of the socket the `recovery` holder is blocked on; no lock is taken while it is held.
- **Close.** `close` stores `closed`, wakes root I/O in progress through `wake`, then takes `recovery` and drains the pending root and the installed root. No root can install after the drain. Once the root socket exists, the wake interrupts its read or write at once: the holder reports `NotConnected` and releases `recovery`, and `close` waits for no budget. Before the socket exists there is nothing to wake: the holder is inside one TCP connect attempt, which cannot be interrupted, so `close` waits for that one attempt, at most the 5 s exchange budget, and the holder then sees `closed` before it starts another. A handshake needs a full round trip inside its timeout, which is why a connect attempt is not sliced as finely as a read or write. `close` never waits out the 135 s root readiness budget. The holder's `closed` check and its `wake` store share the `wake` lock that `close` takes after storing `closed`: a close either finds the socket or the holder finds the close. A cancellation predicate without a session to close (startup) is polled between connect attempts, so a connect attempt in flight delays it by at most 5 s, and at least every 100 ms while a connected root reads or writes.
- **Startup.** The service passes one absolute owner deadline and a cancellation predicate: the process shutdown latch, or any `P2pService::shutdown` call after the start began (a persistent counter, so it survives the per-start epoch tokens and reaches a `shutdown` still waiting for the worker slot). One successful identity load or generation supplies every session attempt. A failed key exchange may retry within its own bounded startup window; session retries never generate another identity. Each network step and each retry pause is clipped to the remaining owner deadline; the pause polls cancellation. A corrupt key, a malformed bridge reply (`InvalidData`), and a bridge that does not negotiate 3.3 (`Unsupported`) fail at once because retrying cannot change them; every other failure, a `DUPLICATED_ID` left by a root the bridge has not yet released included, retries until the deadline. A bridge that has never accepted a connection (a refused or black-holed `--i2psam` address) is the exception: it is given up on 20 s after startup began, the overall limit this node had before the readiness budget existed, and the key step is held to the same window, so a mistyped address does not delay the listeners for the full 142.75 s. The window also clips each root attempt's TCP connect: no connect waits past it while no connection has ever been accepted, so a black-holed address cannot hold one connect for the 135 s root budget, and a connect cut off by the window fails `TimedOut` with nothing sent. The window is checked after each failure and again when the pause after it ends, so a refused address reports its `ConnectionRefused` instead of a second doomed connect. The first accepted connection ends the window for good. Every later attempt, a refused connect after a retryable failure such as `I2P_ERROR` included, retries until the owner deadline and gets its own 135 s root budget, connect included, clipped to that deadline. Cancellation and the root deadline are checked again after the last reply: a cancelled start returns `Interrupted`, a root whose deadline passed meanwhile returns `TimedOut`, and neither publishes a session.
- **Recovery cadence.** After a root is lost, the accept worker's 1 s polls advance the same pending root across calls, so a root that needs longer than one poll completes. A node with `--i2pacceptincoming` unset has no periodic caller; its next outbound I2P dial drives recovery.
- **Limits.** This design bounds the client; it does not make the bridge ready. The recorded direct probe of the pinned IVNP got no `SESSION STATUS` within 135 s, so live I2P handshake qualification stays `BLOCKED` until a bridge answers inside the readiness budget. The recorder (section 3) bounds the reply to `SESSION CREATE` (`SESSION STATUS` included) at its 135 s `SESSION_CREATE_TIMEOUT` and every other SAM negotiation read at its 30 s `IO_TIMEOUT`, so a bridge that legitimately answers inside the node's readiness budget is severed by neither the recorder nor the node.

---

## 4. Security and sanitization rules

To prevent secret leakage in logs, test output, or committed artifacts:
- Private key files:
  - Located at `<datadir>/onion_v3_private_key` and `<datadir>/i2p_private_key`.
  - Must have POSIX permissions mode `0600` (`-rw-------`). Any other permission triggers immediate test failure.
  - Reader contract on Unix (`read_key_file`, used by the I2P destination load and the Tor onion key load): the key path is opened once with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK`, and that one handle is then type-checked, mode-repaired, and read. A final-component symbolic link (dangling ones included) is refused, so another file's mode is never changed and its contents are never supplied as a key. A directory, FIFO, or any other non-regular file is refused before any permission change, and `O_NONBLOCK` keeps a FIFO from blocking the open. A refused path is an error, never an absent key, so it never selects key generation; only a missing path does. A reused regular file with another mode is tightened to `0600` through the handle (`fchmod`); failure to tighten is an error. Content and existing no-overwrite creation are unchanged, and no error text carries key material.
  - Unix limits: `O_NOFOLLOW` covers only the final path component, so a symbolic link in a parent directory (a linked data directory) is still followed. The type check runs after the open, so opening a planted device node still runs that device's own open. Reuse of a key file owned by another user fails when the mode cannot be repaired. These guarantees come from the Unix open path only; the reader makes no link or permission claim on other platforms, where it is a plain read-only open with no mode repair, and this document records no gate for them.
  - I2P key generation contract (only when `i2p_private_key` is absent): after `HELLO` negotiates `3.3`, the node sends exactly `DEST GENERATE SIGNATURE_TYPE=7`. SAM defaults an omitted signature type to DSA-SHA1, and type `7` is Ed25519, so the node selects it explicitly even though the pinned IVNP bridge also accepts and defaults to `7`. The standard success reply is `DEST REPLY PUB=<public> PRIV=<private>` and carries no `RESULT` (SAM v3 specification; pinned IVNP `client/internal/sam/protocol.go` writes exactly this form, and its explicit failures are `DEST REPLY RESULT=I2P_ERROR ...`). This is the only SAM reply read without `RESULT=OK`: `HELLO REPLY`, `SESSION STATUS`, `NAMING REPLY`, and `STREAM STATUS` still require it.
  - `DEST REPLY` handling: the reply is parsed once through the strict field grammar (quotes honored, duplicate keys refused). A `RESULT` other than `OK` fails the request before any key field is read, including one beside keys, so a failure status never succeeds. An explicit `RESULT=OK` is not a failure and is tolerated. A reply succeeds, with no `RESULT` or with `RESULT=OK`, only when it carries both `PUB` and `PRIV` and both pass the existing validation (strict base64, a structurally valid public destination, and the private destination layout check). The key file is written only after that validation, so a refused reply creates no file and leaves no temporary file. Errors name only the sanitized result (a closed set, otherwise `UNKNOWN`) or a fixed reason; they never reflect `PUB`, `PRIV`, or any other reply text. The recorder relays `DEST REPLY` unmodified and observes only commands, so the reply, `PRIV` included, never enters the observation snapshot or evidence.
  - Key file contents are never echoed, printed, or saved in evidence.
  - Restart identity reuse is proven by calculating `sha256sum` locally in memory before and after restart, asserting identical digest output.
- Wire sanitization:
  - SOCKS5 username/password authentication frames (RFC 1929) are passed through to the backend but never logged or stored.
  - SAM `SESSION CREATE` commands contain private destination keys. The recorder sanitizes `DESTINATION=<privkey>` to `DESTINATION=[REDACTED]` and `PASSWORD=<pass>` to `PASSWORD=[REDACTED]`.
- Evidence hashes:
  - The evidence JSON records `sha256(onion_address)` and `sha256(i2p_destination_b32)` under labels `onion_service_id_sha256` and `i2p_destination_sha256`.

---

## 5. Execution flow and assertions

The script proceeds through five sequential phases:

### Phase 1: Environment and binary qualification
1. Process-ownership self-test (section 3.2): Linux pidfd support is proven before anything is launched.
2. Strict Tor release regex check.
3. IVNP ELF buildinfo metadata and compiler header checks.
4. Verification that port `7656` is free on `127.0.0.1`.
5. Creation of workdir and configuration files.

### Phase 2: Daemons and node startup
Every launched child (Tor, IVNP, the recorder, and each node) is claimed immediately after launch (section 3.2).
1. Tor daemon spawned and TCP ports polled until accepting connections. Before Node A starts, the runner also waits within its operation deadline for that owned Tor process to report `Bootstrapped 100% (done): Done`.
2. IVNP daemon spawned and port `7656` polled until accepting connections.
3. `overlay_recorder.py` spawned, providing recording proxies for SOCKS and SAM.
4. Node A started. The script waits for Node A's `getnetworkinfo` to publish both a `.onion` address and a `.b32.i2p` address.
5. Disk permissions of Node A private key files verified to be `0600`.
6. Initial 5 blocks mined on Node A via `generatetoaddress`.
7. Node B started with proxy routing.

### Phase 3: Leg 1, isolated Tor onion transport
1. Node B connects to Node A via `addnode "<onion_address>:18444" "add"`.
2. Height catch-up polled on Node B until height 5.
3. Tip hash equality verified between Node A and Node B.
4. Peer isolation verified:
   - Node B has exactly 1 peer, with `network == "onion"` and `inbound == false`.
   - Node A has exactly 1 peer, with `network == "onion"` and `inbound == true`.
5. Bidirectional block and header propagation:
   - Node A mines 3 blocks, then Node B catch-up is polled to height 8.
   - Node B mines 2 blocks, then Node A catch-up is polled to height 10.
   - Tip hash equality verified.
6. Transport isolation teardown:
   - Node B removes and disconnects the onion peer.
   - Both Node B and Node A peer tables are polled until completely drained (0 active peers).

### Phase 4: Leg 2, isolated I2P transport
1. Pre-condition assertion: both Node B and Node A have 0 active peers.
2. Node B connects to Node A via `addnode "<i2p_b32_address>:18444" "add"`.
3. Peer isolation verified:
   - Node B has exactly 1 peer, with `network == "i2p"` and `inbound == false`.
   - Node A has exactly 1 peer, with `network == "i2p"` and `inbound == true`.
4. Bidirectional block and header propagation:
   - Node A mines 2 blocks, then Node B catch-up is polled to height 12.
   - Node B mines 2 blocks, then Node A catch-up is polled to height 14.
   - Tip hash equality verified.
5. Transport isolation teardown:
   - Node B removes and disconnects the I2P peer.
   - Both Node B and Node A peer tables are polled until completely drained (0 active peers).

### Phase 5: Restart identity reuse and protocol observations
1. Node A stopped through its validated handle with `SIGTERM` and a 15-second bounded deadline, falling back to `SIGKILL` through the same handle with a 5-second bounded wait. The run fails unless the handle observed the exit; the process is then reaped.
2. Node A restarted with preserved datadir.
3. Published onion and I2P addresses from `getnetworkinfo` asserted to match pre-restart addresses byte-for-byte.
4. Key file mode `0600` re-verified on disk.
5. Local SHA-256 digests of private key files compared and asserted identical.
6. Recorder finalization (section 3.1): `SIGTERM` is sent to the recorder through its validated handle, its exit is observed (20 seconds, then `SIGKILL`) and it is reaped, and its exit status, completion marker, and marker-bound length and SHA-256 of the snapshot are all verified. Any failure here ends the run before an observation is read.
7. Wire observation protocol assertions, read only from the verified snapshot:
   - SOCKS5: at least one connection with `atyp == 3` (`0x03`), `domain_length == 62` (`0x3e`), `target_domain` ending with `.onion`, and `direction == "outbound"`.
   - SAM: `HELLO VERSION` requested, negotiated version `3.3`, sanitized `SESSION CREATE`, `NAMING LOOKUP` observed, `STREAM CONNECT` observed, `STREAM ACCEPT` observed.
8. Evidence JSON emitted with schema `bitcoin-rs-overlay-interop-v1`.
9. Remaining daemons (Tor, IVNP, Node A, Node B) stopped and reaped through their validated handles (5 seconds, then `SIGKILL` and 5 seconds). A child that cannot be shown to have exited fails the run before `PASS`.
10. Script prints `overlay interop: PASS` and exits 0.

---

## 6. CLI usage and operator configuration

### Command-line arguments
```bash
./scripts/run-p2p-overlay-interop.sh \
  --tor-command <path-or-cmd> \
  --ivnp-command <path-or-cmd> \
  [--bitcoin-rs-command <path>] \
  [--workdir <dir>] \
  [--evidence <path>] \
  [--timeout-seconds <n>] \
  [--keep]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--tor-command` | Yes | none | Command or path to Tor binary (pinned to release 0.4.9.14). |
| `--ivnp-command` | Yes | none | Command or path to IVNP binary (pinned to Go 1.27.0 commit 0a1b746ba98b58510eb5dcde679ca43184f4b60e). |
| `--bitcoin-rs-command` | No | `target/debug/bitcoin-rs` | Path to `bitcoin-rs` executable. |
| `--workdir` | No | temporary directory | Explicit directory for daemon datadirs and logs. Preserved across runs. |
| `--evidence` | No | `<workdir>/evidence.json` | Destination path for output evidence JSON. |
| `--timeout-seconds` | No | `240` | Maximum wait deadline in seconds for individual operations. |
| `--keep` | No | disabled | Keep temporary workdir on exit. |

### Host prerequisites
- Linux 5.3 or newer with a `/proc` of the script's pid namespace, and `python3` 3.9 or newer providing `os.pidfd_open` and `signal.pidfd_send_signal` (section 3.2). The script checks this before it launches anything.
- Outbound internet access for the Tor and IVNP daemons. Every listener binds loopback, but Tor and I2P are overlay networks that bootstrap externally.
- Free loopback port `7656`, the pinned IVNP SAM port.

### Example invocation
```bash
./scripts/run-p2p-overlay-interop.sh \
  --tor-command /tmp/overlay/tor/tor \
  --ivnp-command /tmp/overlay/ivnpd-go1.27.0 \
  --bitcoin-rs-command ./target/debug/bitcoin-rs \
  --evidence /tmp/overlay/evidence.json \
  --keep
```

---

## 7. Result semantics: PASS, BLOCKED, and FAIL

To ensure test honesty and prevent false-green reporting:

- `PASS`:
  - All prerequisite binary checks succeeded.
  - Wire protocol observations recorded actual non-fallback packets matching specifications.
  - Exact peer counts, bidirectional block sync, and key retention verified.
  - Output ends with `overlay interop: PASS` and exit code `0`.

- `BLOCKED`:
  - External host environment lacks required capabilities or pinned binaries:
    - Tor binary absent or version does not match release `0.4.9.14`.
    - IVNP binary absent, Go compiler header is not `go1.27.0`, revision is not `0a1b746ba98b58510eb5dcde679ca43184f4b60e`, or `vcs.modified` is not `false`.
    - Port `7656` is in use by another service on the host.
    - Linux pidfd process ownership is unavailable (section 3.2), which is checked before anything is launched.
    - Outbound internet access is unavailable, or required external daemons fail to bootstrap within timeout or exit during launch.
  - Fails closed with standard error diagnostic and non-zero exit code (`1` or `2`). The caller records this run as `BLOCKED` with the explicit prerequisite cited.

- `FAIL`:
  - Required binaries were present, but a protocol assertion or security rule was violated:
    - Key file permission mode is not `0600`.
    - Private key content mutated across daemon restart.
    - Peer counts exceeded 1 or showed wrong transport during isolated legs.
    - Wire recorder failed to observe SOCKS `ATYP=0x03` length `62` or SAM `3.3` negotiation.
    - Block tip hash mismatch after mining and propagation.
    - A launched child could not be shown to have exited within its `SIGTERM`/`SIGKILL` budgets (reported as stuck, never signaled by number).
  - Exits non-zero immediately.
