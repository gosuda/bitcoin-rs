# P2P overlay interoperability test specification

This document specifies the end-to-end integration and verification harness for Tor (onion v3) and I2P overlay networking in `bitcoin-rs` (#1601), implemented by `scripts/run-p2p-overlay-interop.sh`.

## 1. Overview and objectives

`bitcoin-rs` supports peer-to-peer connectivity across privacy overlay networks:
- Tor v3: outbound connections via SOCKS5 proxy with remote DNS resolution (`ATYP=0x03`), inbound hidden service publication via the Tor ControlPort using ephemeral or persisted ed25519-v3 keys.
- I2P: outbound and inbound streaming connections via the I2P SAM (Simple Anonymous Messaging) v3.3 bridge.

### Qualification status

Private-fixture runs proved Tor transport and the initial I2P handshake plus bidirectional header and block exchange. Same-key I2P readmission after a Node A restart remains failed and unqualified. The combined launcher MUST NOT report `PASS` without observed readmission; it exits non-zero before recorder finalization or successful evidence publication (section 5, Phase 5).

An independent SAM-only control reproduced the failure with the pinned i2pd release and no `bitcoin-rs` process: the receiver reused its exact identity, the original sender root stayed alive, and five connections returned `RESULT=OK` but delivered no exchange within 300 seconds. A later new sender root with a new Destination succeeded. That secondary control changed both sender state and identity, and ran later; it does not isolate the cause or qualify same-key restart.

The `run-p2p-overlay-interop.sh` script executes an automated regtest integration suite between two independent `bitcoin-rs` daemon processes, verifying:
1. Strict toolchain and binary pins for external daemons (Tor 0.4.9.14 and official i2pd 3.0.0 release).
2. Wire protocol compliance through a non-invasive, bounded loopback recorder proxy.
3. Transport isolation, ensuring Onion and I2P transports operate independently without IP leaks or cross-transport crosstalk.
4. Bidirectional header and block propagation over both overlay transports.
5. Persistent daemon identity and private key security, including POSIX file mode `0600` and byte-identical key retention across restarts.
6. Fail-closed error handling with honest evidence reporting (schema `bitcoin-rs-overlay-interop-v1`).
7. Child process ownership: every daemon the script launches is signaled and reaped only through a validated Linux pidfd, never by a bare process number (section 3.2).
8. Isolation from operator state: fresh output paths, a minimal child environment, bounded fixture tools, and acceptance guards that cannot be stripped by `PYTHONOPTIMIZE` (section 4).

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

### i2pd pin: official release 3.0.0
- Requirement: official i2pd 3.0.0 release (tag commit `137dde2f`).
- Release artifact: `i2pd_3.0.0-1resolute1_amd64.deb`, sha256 `75365744e1347a6f1ee1d29eca3a6ee41dcd0c7e14c2f015401b283220b2e993`.
- Payload check: `usr/bin/i2pd` sha256 `2c77b7af098d385a14e0f19b47dde7f97c046ea8c712ac8521650eafe4cf8dc7`.
- Version output must contain a whole line equal to `i2pd version 3.0.0` (the official release appends a parenthesized numeric protocol annotation, for example `i2pd version 3.0.0 (0.9.71)`, which is accepted) and a whole line equal to `Boost version 1.90.0`. The match is on exact version tokens, not substrings, so `3.0.0.1`, `3x0x0`, or `1.90.01` are rejected.
- Verification rule: the script requires the exact 3.0.0 version line, records the actual binary sha256 in evidence (the payload sha256 above is documentation, not enforced by the script), and fails closed on unresolved `ldd` libraries. No Go toolchain dependency.

---

## 3. Test architecture and topology

The test spins up a private multi-daemon network whose listeners all bind loopback. No overlay daemon uses public bootstrap: Tor runs a private 3-authority plus 3-relay TestingTorNetwork on loopback, and I2P runs seven i2pd routers on netid 77 with distinct 127.0.77.x addresses and a ZIP of their own RouterInfos. Any public FallbackDir, public reseed URL, or non-loopback port fails closed.

### Components
1. Tor process: starts with loopback `ControlPort` (cookie authentication enabled) and `SocksPort`.
2. Seven i2pd routers start on netid 77 with distinct 127.0.77.x addresses and loopback SAM ports.
3. Loopback recorder proxy (`overlay_recorder.py`): transparent `asyncio` proxy positioned between the nodes and the overlay daemons. It captures wire observations to a JSON file. Its deadlines bound negotiation and writes; they never bound the lifetime of an established connection:
   - Bounded: SOCKS5 handshake reads, SAM lock-step negotiation (each command and its reply, up to `SESSION CREATE` or `STREAM CONNECT`/`STREAM ACCEPT`), and every `drain` into a peer wait at most `30.0`s (`IO_TIMEOUT`). The one exception is the reply to an exact `SESSION CREATE`, which waits at most `135.0`s (`SESSION_CREATE_TIMEOUT`): the live transport's 120 s `SESSION CREATE` deadline (`crates/p2p/src/overlay/sam.rs`) plus margin, so the recorder never ends a root the node is still entitled to wait for. No other reply and no write drain uses the longer bound, and it is not an idle timer. A peer that does not accept a write within `30.0`s ends that connection.
   - Unbounded while idle: an established SAM session root and an established relayed stream (Tor SOCKS stream, `STREAM CONNECT`, `STREAM ACCEPT`) stay open across any idle period. The session root keeps observing later commands such as `NAMING LOOKUP`, redacting `DESTINATION` and `PASSWORD` exactly as before, and passes replies through raw.
   - Teardown: EOF, reset, or a failed bounded write in either direction cancels the other direction and closes both sockets, so the node and the daemon each see the close. Each connection handler is a task owned by the recorder's `main()`. Cancelling `main()` stops accepting, cancels every handler, and then closes the listeners. The recorder process itself is a child owned by the script (section 3.2): its `cleanup` trap sends `SIGTERM` through the recorder's validated handle, waits up to 5 seconds, then sends `SIGKILL` through the same handle and reaps it.
   - Non-EOF relay endings are written to `recorder.log` as the exception type only; no payload or SAM line is logged there.
4. Node A (`bitcoin-rs`, service host):
   - Configured with `--onion-proxy 127.0.0.1:<recorder_socks>`, `--tor-control 127.0.0.1:<tor_control>`, `--i2p-sam 127.0.0.1:<recorder_sam>`, `--i2p-accept`, plus `--dns-seeds-enabled=false` (overlay routing rejects DNS seeding).
   - Generates persistent key files: `overlay-fabfb5da/onion.key` and `overlay-fabfb5da/i2p.key` (regtest identity dir; JSON envelope `{version,key,checksum}`).
   - I2P inbound: after `STREAM ACCEPT` returns `RESULT=OK`, the bridge writes `<destination> [FROM_PORT=<n>] [TO_PORT=<n>]`. `TO_PORT` is parsed as `u16`. An absent `TO_PORT`, or `TO_PORT=0` (I2CP port 0, any or unspecified service, valid in SAM), yields the application fallback port the caller supplies; a nonzero value is used as reported. Non-numeric, overflowing, and duplicate `TO_PORT` fields are refused, a zero counting as present, so `TO_PORT=0 TO_PORT=9999` is a duplicate. The logical peer endpoint parser still refuses port 0; only this accept adapter normalizes it.
5. Node B (`bitcoin-rs`, dialer):
   - Configured with `--proxy 127.0.0.1:<recorder_socks>`, `--onion-proxy 127.0.0.1:<recorder_socks>`, `--i2p-sam 127.0.0.1:<recorder_sam>`, `--v2transport=false`, plus `--dns-seeds-enabled=false` (overlay routing rejects DNS seeding; `--proxy` alone does not enable onion routing).

### 3.1 Observation persistence and the completion protocol
An observation snapshot is only evidence once the recorder has finalized it. The protocol has one authoritative failure path and one publication point:

- **Single failure path.** Any failed observation write (snapshot, temporary file, `rename`, or completion marker) records a sticky failure verdict and requests the run to stop. It is never cleared and never retried. A connection handler that raises is reported to the same verdict through its completion callback, and an accept loop that ends without a stop request is a failure too. Nothing else ends the run successfully.
- **Publication only at finalization.** During the run each connection writes `<workdir>/protocol_observations.json.partial` and nothing else. Finalization writes the snapshot to `<workdir>/protocol_observations.json` (temp file, `fsync`, atomic rename), then writes `<workdir>/protocol_observations.done` (temp file, `fsync`, atomic rename) containing `schema: "bitcoin-rs-overlay-observations-v1"`, `complete: true`, the snapshot's byte length, and its SHA-256. A recorded failure suppresses both writes, so no final snapshot or marker is produced.
- **Stale files never count.** An explicit `--workdir` must have been absent or empty when the run began (section 4), so no earlier run's snapshot or marker can exist in it, and the runner deletes nothing to make that true.
- **Bounded wind-down.** The recorder bounds its own shutdown with `FINALIZE_GRACE`. Stopping the listeners, cancelling every handler, and closing every socket must finish inside that grace. Exceeding it records a failure, prints it to `recorder.log`, and exits non-zero without publishing anything. The runner's own 20 second wait (that grace plus 5 seconds) is only a backstop for a recorder that cannot run its own guard; past it the recorder is killed through its handle and finalization fails.
- **Runner-side gate.** Immediately after the bounded post-restart readmit (Phase 5; a run that did not observe its required peer has already failed) and before the first observation read, the runner calls `finalize_recorder`. For each of the two recorders (A and B, one per SOCKS/SAM proxy pair) that sends `SIGTERM` through the recorder's validated handle, waits up to 20 seconds for the exit (then `SIGKILL` through the same handle, which fails finalization), and reaps it with `wait` only after the handle observed the exit. Each recorder's exit status is copied out before the next one is stopped, because the shell keeps only the latest reap's status. Both must have exited `0` (a recorder that was already gone has no status and fails the run), and each must have a marker whose schema is `bitcoin-rs-overlay-observations-v1`, whose `complete` is `true`, and whose recorded length and SHA-256 match the snapshot bytes actually read. Any mismatch fails the run. Only then are the two snapshots merged and the SOCKS/SAM observations read, and only a run that passes this gate can print `overlay interop: PASS`.
- **Normal exit.** A completed run stops the recorder with `SIGTERM`, which the recorder handles by stopping its listeners, cancelling handlers (each closes its sockets within the bounded writer timeout), publishing the snapshot and marker, and exiting `0`. The script's `cleanup` trap still owns the recorder for every earlier failure path.

### 3.2 Child process ownership
A process number is a name that the kernel reissues once the process is reaped. `kill -0`, or a parent-pid read followed by a numeric `kill`, cannot prove that the name still means the launched child at the instant of the signal. The script therefore never signals by number:

- **Capability gate.** Before any daemon is launched, the script runs a self-test of its private process-ownership helper. The helper is an inline script for the same `python3` the runner already uses (standard-library `os.pidfd_open`, `signal.pidfd_send_signal`, and `select.poll`; no dependency and no generic supervisor). It needs Linux 5.3 or newer, Python 3.11 or newer, and a `/proc` that belongs to the script's pid namespace. A host that cannot supply them fails closed with exit `1` and an explicit message, and the caller records the run as `BLOCKED`.
- **Identity at launch.** Immediately after each launch the script records the child in its owner table as `pid -> start time`, where the start time is field 22 of `/proc/<pid>/stat`. The shell reads that file itself, before it spawns anything else, so the only child of the script that can carry the number is the one just launched, and a process that reused the number would have another parent. The parent must be the script's own pid and the state must not be zombie or dead. Parent, pid, and start time name exactly one process. A child that already exited, or is not a live child of the script, cannot be recorded and stops the run. No helper process is involved at this step, so a helper can never be mistaken for the launched child, and the stop-time helper additionally refuses to treat its own pid as an owned child. Tor net processes, i2pd routers (each started with `--datadir` on argv so the owned pid is the daemon itself), the recorder, and every `bitcoin-rs` node are background commands owned the same way. Each is started through `env -i` with a minimal environment (section 4): the backgrounded subshell `exec`s `env`, which `exec`s the daemon, so the recorded pid and start time are the daemon's own.
- **Validation before any signal.** Every stop opens a fresh pidfd, then reads `/proc/<pid>/stat`, then reads the pidfd's `fdinfo`. A `Pid:` that still equals the number after the `/proc` read proves the number belonged to the handle's process throughout, so the parent and start time read are its own. They must equal the recorded identity. If the number is absent, already reaped, or now names another process (including one with the right parent but a different start time), the owned child no longer exists: nothing is signaled and the entry is dropped as `gone`.
- **Signal, wait, and kill only through the handle.** `SIGTERM` is sent with `pidfd_send_signal` and the handle is polled for exit; it polls readable when the process exits, so a number reissued after validation is harmless. Every wait is finite. A child that has not exited when its `SIGTERM` budget ends gets `SIGKILL` through the same handle and a second finite wait. Budgets: Node A restart 15 s then 5 s, recorder finalization 20 s then 5 s, and `cleanup` and the final daemon teardown 5 s then 5 s, applied to all owned children together.
- **Reaping.** The shell calls `wait` only for a child whose exit the handle observed, so the call cannot block. The status value decides only the recorder's finalization, and the Node A restart requires that its exit was observed. A child reported `gone` is not waited on and has no status. Reaped and gone children leave the owner table, so a finished child is never addressed again.
- **Unkillable or unverifiable children.** A child that is still running after `SIGKILL` and its wait (for example in uninterruptible kernel sleep), or whose ownership could not be verified, is reported on stderr as stuck. It is never waited on and never signaled by number. The run fails: the teardown before `PASS` exits `1`, and `cleanup` forces a non-zero exit status. The workdir is kept while any child remains unconfirmed, including when `--keep` was not set.
- **No group signals.** The script uses no numeric `kill`, `killall`, `pkill`, or process-group signal, so it cannot touch itself, its caller, or an unrelated process.

### 3.3 SAM lifecycle implemented by the live transport
The live owner is `crates/p2p/src/overlay.rs` (`OverlayTransport::start`) with workers in `crates/p2p/src/overlay/sam.rs` (`run_sam`) and `crates/p2p/src/overlay/tor.rs` (`run_tor`); identity persistence is `crates/p2p/src/overlay/identity.rs`. The legacy `crates/p2p/src/sam.rs` (`SamSession`/`PendingRoot`/`ROOT_READINESS_BUDGET`/`I2P_STARTUP_BUDGET`) is not the node runtime path and is not documented here.

- **Startup is synchronous on keys, asynchronous on the bridge.** `OverlayTransport::start` validates the config, then reads `identity_dir/onion.key` (when `tor_control` is set) and `identity_dir/i2p.key` (when `i2p_accept` is set) synchronously via `identity::read`. A damaged or unreadable key file fails startup; only a missing file selects generation. It then spawns one worker per configured service (`run_sam` for `i2p_sam`, `run_tor` for `tor_control`) and returns the join handles immediately without waiting for bridge readiness. Successful startup therefore does not imply I2P readiness.
- **SAM worker retries until cancelled.** `run_sam` loops until the service shutdown latch or session cancel fires. Each iteration opens a fresh control connection (`SETUP_TIMEOUT` 10 s per setup step), negotiates `HELLO` (`MIN=3.1 MAX=3.3`), generates a `DEST` (`SIGNATURE_TYPE=7`, Ed25519) only when `i2p_accept` is set and no key exists, persists it once via `identity::create` (`<datadir>/overlay-<magic>/i2p.key`), then sends `SESSION CREATE STYLE=STREAM` with a 120 s deadline, followed by `NAMING LOOKUP NAME=ME`. On success it publishes the `Session` (id plus liveness flag plus local `PeerEndpoint`) under the transport lock and heartbeats it (`PING`/`PONG`, `SETUP_TIMEOUT` per round trip); on any failure it retires the published session, wakes its streams, backs off (1 s doubling to 60 s), and retries. No per-root readiness budget, no `PendingRoot`, and no startup owner deadline exist on this path.
- **Tor worker is symmetric.** `run_tor` authenticates (`NULL` or `SAFECOOKIE` via `tor_cookie`), issues `ADD_ONION`, persists `onion.key` once, publishes the local onion endpoint, and heartbeats with `GETINFO`; loss clears the endpoint and retries with the same backoff.
- **Limits.** This design bounds the client; it does not make the bridge ready. Live I2P handshake qualification stays `BLOCKED` until the private i2pd router answers `SESSION CREATE` inside the 120 s deadline. The recorder (section 3) bounds the reply to `SESSION CREATE` (`SESSION STATUS` included) at its 135 s `SESSION_CREATE_TIMEOUT` and every other SAM negotiation read at its 30 s `IO_TIMEOUT`, so a bridge that legitimately answers inside the node's 120 s deadline is severed by neither the recorder nor the node.

---

## 4. Security and sanitization rules

To prevent secret leakage in logs, test output, or committed artifacts:
- Private key files:
  - Located at `<datadir>/overlay-<magic>/onion.key` and `<datadir>/overlay-<magic>/i2p.key` (regtest: `<datadir>/overlay-fabfb5da/onion.key` and `<datadir>/overlay-fabfb5da/i2p.key`). Each file is a JSON envelope `{"version":1,"key":"...","checksum":[...]}`; the I2P `key` is the private destination (I2P base64 alphabet) whose public prefix hashes to the `.b32.i2p` address.
  - Must have POSIX permissions mode `0600` (`-rw-------`). Any other permission triggers immediate test failure.
  - Reader contract on Unix (`overlay/identity.rs::read`, used by the I2P destination load and the Tor onion key load): the key path is opened once with `O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK`, and that one handle is then type-checked and read; a mode with any group/other bits is refused, never repaired. A final-component symbolic link (dangling ones included) is refused, so its contents are never supplied as a key. A directory, FIFO, or any other non-regular file is refused, and `O_NONBLOCK` keeps a FIFO from blocking the open. A refused path is an error, never an absent key, so it never selects key generation; only a missing path does. A reused regular file with another mode is refused with `overlay identity file must be private (0600)`; no permission change is attempted. Content and existing no-overwrite creation are unchanged, and no error text carries key material.
  - Unix limits: `O_NOFOLLOW` covers only the final path component, so a symbolic link in a parent directory (a linked data directory) is still followed. The type check runs after the open, so opening a planted device node still runs that device's own open. These guarantees come from the Unix open path only; the reader makes no link or permission claim on other platforms, where it is a plain read-only open, and this document records no gate for them.
  - I2P key generation contract (only when `i2p.key` is absent): after `HELLO` negotiates `3.3`, the node sends exactly `DEST GENERATE SIGNATURE_TYPE=7`. SAM defaults an omitted signature type to DSA-SHA1, and type `7` is Ed25519, so the node selects it explicitly even though some bridges also accept and default to `7`. The standard success reply is `DEST REPLY PUB=<public> PRIV=<private>` and carries no `RESULT` (SAM v3 specification). This is the only SAM reply read without `RESULT=OK`: `HELLO REPLY`, `SESSION STATUS`, `NAMING REPLY`, and `STREAM STATUS` still require it.
  - `DEST REPLY` handling: the reply is parsed once through the strict field grammar (quotes honored, duplicate keys refused). A `RESULT` other than `OK` fails the request before any key field is read, including one beside keys, so a failure status never succeeds. An explicit `RESULT=OK` is not a failure and is tolerated. A reply succeeds, with no `RESULT` or with `RESULT=OK`, only when it carries both `PUB` and `PRIV` and both pass the existing validation (strict base64, a structurally valid public destination, and the private destination layout check). The key file is written only after that validation, so a refused reply creates no file and leaves no temporary file. Errors name only the sanitized result (a closed set, otherwise `UNKNOWN`) or a fixed reason; they never reflect `PUB`, `PRIV`, or any other reply text. The recorder relays `DEST REPLY` unmodified and observes only commands, so the reply, `PRIV` included, never enters the observation snapshot or evidence.
  - Key file contents are never echoed, printed, or saved in evidence.
  - Restart identity reuse is proven by calculating `sha256sum` locally in memory before and after restart, asserting identical digest output.
- Isolation from operator state:
  - Fresh outputs: an explicit `--workdir` must not exist, or must be an empty directory owned by the caller (never a symbolic link), and `--evidence` must not exist. Both are decided right after argument parsing, before any directory, port, file, or child exists; a violation exits `2` with nothing created, deleted, or overwritten. The workdir is created (or tightened) to mode `0700` and made absolute, and the evidence file is written with exclusive create. The two fixture helpers (`overlay_tor_fixture.sh`, `overlay_i2pd_fixture.sh`) repeat the empty-directory check on their own directories before their first write and refuse symbolic links.
  - Child environment: every child (Tor net, i2pd mesh, both recorders, both nodes) starts through `env -i` with only `PATH`, `LD_LIBRARY_PATH` (when set), and a task-owned `HOME` (and `TMPDIR`) under the workdir. No `BITCOIN_RS_*` variable (for example `BITCOIN_RS_RPC_PUBLIC_BIND` or a connect setting), no proxy variable, and no other operator variable reaches a fixture or node. Tor also reads an empty task-owned `--defaults-torrc`, so no operator `torrc-defaults` applies. The RPC client runs `curl -q --noproxy '*'`, so neither `~/.curlrc` nor a proxy variable can carry the RPC credentials off the loopback listener.
  - Bounded fixture tools: `tor-gencert` and `tor --list-fingerprint` run under `timeout -k` (`SIGTERM` after 60 s, `SIGKILL` 5 s later) and fail the run with their own exit status (`124` timed out, `137` killed). i2pd key generation has no natural exit, so it runs for 15 s and `SIGTERM` ending it (exit `124`) is the expected outcome; an i2pd that ignores `SIGTERM` is killed 15 s later (exit `137`) and fails the run. The fixtures' children are never left running.
  - Acceptance guards: every check in the runner's embedded Python (peer, marker, SAM gate, readmit, wire, and evidence validation) is an explicit `sys.exit` failure, never an `assert`, so `PYTHONOPTIMIZE` cannot strip it.
- Wire sanitization:
  - SOCKS5 username/password authentication frames (RFC 1929) are passed through to the backend but never logged or stored.
  - SAM `SESSION CREATE` commands contain private destination keys. The recorder sanitizes `DESTINATION=<privkey>` to `DESTINATION=[REDACTED]` and `PASSWORD=<pass>` to `PASSWORD=[REDACTED]`.
- Evidence hashes:
  - The evidence JSON records `sha256(onion_address)` and `sha256(i2p_destination_b32)` under labels `onion_service_id_sha256` and `i2p_destination_sha256`.

---

## 5. Execution flow and assertions

The script proceeds through five sequential phases:

### Phase 1: Environment and binary qualification
1. Fresh outputs (section 4), decided right after argument parsing and before the self-test, any port, directory, file, or child exists: an explicit `--workdir` must not exist or must be an empty directory owned by the caller, and `--evidence` must not exist, otherwise the script exits `2` with nothing created.
2. Process-ownership self-test (section 3.2): Linux pidfd support is proven before anything is launched.
3. Strict Tor release regex check.
4. tor-gencert executable check plus i2pd 3.0.0 version and library checks, with actual binary digests recorded.
5. Allocation of free loopback ports for the Tor net and the i2pd mesh (no pinned SAM port).
6. Creation of the workdir (a new `0700` directory, or the validated empty one tightened to `0700`, then made absolute) and of the configuration files in it.

### Phase 2: Daemons and node startup
Every launched child (Tor net, i2pd mesh, the recorders, and each node) starts under a minimal environment (section 4) and is claimed immediately after launch (section 3.2).
1. Private Tor net spawned: authorities reach consensus, relays publish, client bootstraps 100 percent, all bounded and owned.
2. Private i2pd mesh spawned: seven routers on netid 77 with distinct 127.0.77.x addresses, reseed ZIP built from their own RouterInfos, SAM ports polled.
3. Tracked `scripts/overlay_recorder.py` spawned, providing recording proxies for SOCKS and SAM 3.3.
4. Node A started with `--onion-proxy`, `--tor-control`, `--i2p-sam`, `--i2p-accept`, and `--dns-seeds-enabled=false`. The script waits for Node A's `getnetworkinfo` to publish both a `.onion` address and a `.b32.i2p` address.
5. Disk permissions of Node A private key files verified to be `0600`.
6. Initial 5 blocks mined on Node A via `generatetoaddress`.
7. Node B started with `--proxy`, `--onion-proxy`, `--i2p-sam`, and `--dns-seeds-enabled=false`.

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
5. The I2P leg is deliberately not torn down. Node B's I2P peer stays up into the restart, so Phase 5 starts from a live session that stopping Node A leaves stale on Node B (I2P sends no remote FIN). That peer is removed only by the explicit disconnect in Phase 5 step 2.

### Phase 5: Restart identity reuse, bounded readmit, and protocol observations
1. Node A stopped through its validated handle with `SIGTERM` and a 15-second bounded deadline, falling back to `SIGKILL` through the same handle with a 5-second bounded wait. The run fails unless the handle observed the exit; the process is then reaped.
2. Explicit disconnect on Node B: the stale peer's id is read from Node B's `getpeerinfo` (the run fails if none is listed), Node B issues `disconnectnode` for that id (manual, no automatic retry), and Node B's peer table is polled until it holds zero peers (`peer_zero_observed`).
3. Node A restarted with the preserved datadir, so it reuses the same onion and I2P keys.
4. Published onion and I2P addresses from `getnetworkinfo` asserted to match pre-restart addresses byte-for-byte.
5. Key file mode `0600` re-verified on disk, and local SHA-256 digests of the private key files compared and asserted identical (same-key restart).
6. Post-restart Node A root readiness, then a transient lookup gate (no `SESSION STATUS` request is sent: per SAM 3.3, `SESSION STATUS` is a reply to `SESSION CREATE`, not a command). After Node A is reaped (old process gone) and before the restart launch the launcher records the baseline maximum `sam_session_create_ok ordinal=N` in the Node A recorder log (`recorder.log`, anchored `^sam_session_create_ok ordinal=[0-9]+$`); each recorder process emits one flushed line per validated `SESSION CREATE` OK (`SESSION STATUS RESULT=OK`, exact token match) and holds its own ordinal starting at 0, carrying no `DESTINATION`, `PASSWORD`, `VALUE`, or key. The run fails closed unless the baseline parses to an integer `>= 1` (Node A established its root before restart). After restart the launcher waits (existing per-operation timeout) until that log holds a greater ordinal value, proving a fresh post-restart Node A-owned `SESSION CREATE` received `RESULT=OK` through the owned recorder channel. Only then a fresh transient connection to the second i2pd router's SAM bridge negotiates `3.3` (`HELLO REPLY RESULT=OK` with `VERSION=3.3`, exact token match), creates `SESSION CREATE STYLE=STREAM DESTINATION=TRANSIENT` (`SESSION STATUS RESULT=OK`, exact token match, then the socket is closed cleanly), and looks up Node A's `.b32.i2p` name (`NAMING REPLY RESULT=OK`, exact token match, exactly one `VALUE`). The returned destination is decoded strictly (I2P base64 alphabet), its length must equal the size its certificate declares, and the base32 of its SHA-256 must equal Node A's published address. The transient `CREATE OK` proves bridge liveness only and never substitutes for the Node A root ordinal. All reply checks use exact field-grammar token equality (`RESULT` equals `OK`), never substring matching (so `RESULT=OKX` fails), and all errors are redacted to `RESULT=<value>` or `UNKNOWN` without echoing any reply body. Invariant: `PASS` requires `now > baseline` on `recorder.log` (A) plus transient `CREATE OK` plus hash-bound lookup. Failure cases: no greater ordinal within the timeout; `HELLO`/`CREATE`/`LOOKUP` `RESULT` not exactly `OK` or `VERSION` not exactly `3.3`; `VALUE` count not exactly 1; base64, length, certificate-size, or hash-bound mismatch; bridge EOF before a reply. Any failure ends the run before readmit.
7. Bounded manual readmit, only after the root-readiness plus lookup gate: the watcher is constructed before the first dial so the dial's own failure is not baselined away, then Node B issues `addnode "<i2p_b32_address>:18444" "onetry"`, then polls for an outbound I2P peer, with at most 30 attempts spaced 5 seconds apart inside a 300-second budget (failure retries on a new `outbound connection exited with error` line, stall retries on the elapsed schedule; both recorded in `restart-readmit.log`). The readmit flag is set only when Node B actually lists an outbound I2P peer (its table was empty after the explicit stale disconnect, so this is the restarted Node A). Reaching the attempt cap or the deadline without it exits non-zero (after one last observation following the final wait) before the recorder is finalized, any evidence is written, or `PASS` is printed. The evidence field `restart.readmit_onetry` derives from that flag, and `automatic_retry_claimed` stays `false`.
8. Recorder finalization (section 3.1): both recorders are stopped through their validated handles (20 seconds, then `SIGKILL`) and reaped, and each recorder's exit status, completion marker, and marker-bound length and SHA-256 of its snapshot are verified. Any failure here ends the run before an observation is read.
9. Wire observation protocol assertions, read only from the verified snapshot:
   - SOCKS5: at least one connection with `atyp == 3` (`0x03`), `domain_length == 62` (`0x3e`), `target_domain` ending with `.onion`, and `direction == "outbound"`.
   - SAM: `HELLO VERSION` requested, negotiated version `3.3`, sanitized `SESSION CREATE`, `NAMING LOOKUP` observed, `STREAM CONNECT` observed, `STREAM ACCEPT` observed.
10. Evidence JSON emitted with schema `bitcoin-rs-overlay-interop-v1`, written with exclusive create (an existing path is never overwritten). The SOCKS observation is recorded as the decimal fields `socks_atyp` and `socks_domain_length` only.
11. Remaining daemons (Tor net, i2pd mesh, Node A, Node B) stopped and reaped through their validated handles (5 seconds, then `SIGKILL` and 5 seconds). A child that cannot be shown to have exited fails the run before `PASS`.
12. Script prints `overlay interop: PASS` and exits 0.

---

## 6. CLI usage and operator configuration

### Command-line arguments
```bash
./scripts/run-p2p-overlay-interop.sh \
  --tor-command <path-or-cmd> \
  --tor-gencert-command <path-or-cmd> \
  --tor-gencert-sha256 <64-hex> \
  --i2pd-command <path> \
  [--bitcoin-rs-command <path>] \
  [--workdir <dir>] \
  [--evidence <path>] \
  [--timeout-seconds <n>] \
  [--keep]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--tor-command` | Yes | none | Command or path to Tor binary (pinned to release 0.4.9.14). |
| `--tor-gencert-command` | Yes | none | tor-gencert binary from the same 0.4.9.14 release. |
| `--tor-gencert-sha256` | Yes | none | Expected SHA-256 of the tor-gencert binary (64 hex chars; fail-closed on mismatch). |
| `--i2pd-command` | Yes | none | Path to i2pd binary (pinned to official release 3.0.0; supply the binary path, additional arguments are not parsed). |
| `--bitcoin-rs-command` | No | `target/debug/bitcoin-rs` | Path to `bitcoin-rs` executable. |
| `--workdir` | No | fresh temporary directory | Explicit directory for daemon datadirs and logs. Must not exist, or must be an empty directory owned by the caller; it is created or tightened to `0700` and never cleared (exit `2` otherwise). |
| `--evidence` | No | `<workdir>/evidence.json` | Destination path for output evidence JSON. Must not exist; its parent directory must exist (or be the new workdir). Never overwritten. |
| `--timeout-seconds` | No | `240` | Maximum wait deadline in seconds for individual operations. |
| `--keep` | No | disabled | Keep temporary workdir on exit. |

### i2pd binary-path semantics
The `--i2pd-command` value is used verbatim as the executable path (quoted, no shell evaluation); supply the binary path, additional arguments are not parsed. Quoting the path supports spaces in a real executable path. Private fixture arguments (i2pd `--datadir`/`--conf`, netid 77, loopback addresses/ports) are appended by the script and fixtures only; caller-supplied arguments can never override them.

### Host prerequisites
- Linux 5.3 or newer with a `/proc` of the script's pid namespace, and `python3` 3.11 or newer providing `os.pidfd_open`, `signal.pidfd_send_signal`, and `asyncio.timeout` (section 3.2). The script checks this before it launches anything.
- No public bootstrap. Every listener binds loopback; Tor runs a private TestingTorNetwork and I2P runs a private netid 77 mesh.
- Free loopback ports for the Tor net and the i2pd mesh.

### Example invocation
```bash
./scripts/run-p2p-overlay-interop.sh \
  --tor-command /opt/overlay/tor \
  --tor-gencert-command /opt/overlay/tor-gencert \
  --tor-gencert-sha256 <64-hex> \
  --i2pd-command /opt/overlay/i2pd \
  --bitcoin-rs-command ./target/debug/bitcoin-rs \
  --evidence ./evidence.json \
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
    - i2pd binary absent, version is not official 3.0.0, Boost is not 1.90.0, or libraries do not resolve.
    - No free loopback port for the Tor net or the i2pd mesh.
    - Linux pidfd process ownership is unavailable (section 3.2), which is checked before anything is launched.
    - Required private daemons fail to bootstrap within timeout or exit during launch.
    - An output path is not fresh: a nonempty or foreign `--workdir`, or an existing `--evidence` (exit `2`, before anything is created or launched).
  - Fails closed with standard error diagnostic and non-zero exit code (`1` or `2`). The caller records this run as `BLOCKED` with the explicit prerequisite cited.

- `FAIL`:
  - Required binaries were present, but a protocol assertion or security rule was violated:
    - Key file permission mode is not `0600`.
    - Private key content mutated across daemon restart.
    - Peer counts exceeded 1 or showed wrong transport during isolated legs.
    - Wire recorder failed to observe SOCKS `ATYP=0x03` length `62` or SAM `3.3` negotiation.
    - Block tip hash mismatch after mining and propagation.
    - Explicit stale-peer disconnect failed, or Node B's peer table did not reach zero after it.
    - The live SAM gate failed (recorder-A baseline missing or `< 1`; no recorder-A ordinal above the baseline within the timeout; transient session, lookup, or hash-bound destination mismatch).
    - The post-restart I2P readmit was not observed within 30 attempts or 300 seconds, or either recorder exited non-zero or lacks a verified completion marker.
    - A launched child could not be shown to have exited within its `SIGTERM`/`SIGKILL` budgets (reported as stuck, never signaled by number).
  - Exits non-zero immediately.
