# P2P loopback comparator contract

Harness: `tools/benchmark-campaign/p2p_loopback.py`. Tests:
`tools/benchmark-campaign/test_p2p_loopback.py`. Addresses issue #35.

The comparator feeds Bitcoin Core 31.1 and bitcoin-rs the identical external
peer experience — same framed bytes, same delays, same bandwidth ceilings, same
staller behavior, same disconnect points, same corpus order, same peer
parameters — and only then compares externally observed wall time. Each node
keeps its own internal scheduler; the harness never reaches inside it. A ratio
is computed only after every custody and correctness gate passes.

## What is held identical

One `p2p-loopback-config-v1` document binds every arm of a campaign:

- **Corpus**: an ordered list of complete P2P frames (hex). Every frame is
  validated at load: network magic, command padding, little-endian length
  matching the byte count, and the double-SHA256 checksum. Corrupt framing is a
  config error, not a runtime observation.
- **Schedule**: ordered steps of kinds `send`, `stall`, `disconnect`. A `send`
  names a corpus frame and an optional `bandwidth_bytes_per_second` ceiling; a
  `stall` holds the connection silently for `duration_ns`; any step may carry a
  `delay_ns` lead-in; the optional final `disconnect` may first read exactly
  `after_bytes` inbound. The schedule must send every corpus frame exactly
  once, in corpus order, and `disconnect` must be final.
- **Peer parameters**: network magic, protocol version, services bitmask,
  connect and I/O timeouts, socket buffer sizes, and the expected inbound
  transcript digest.
- **Lifecycle**: `fresh` or `restart` mode, a generation counter, the initial
  state seeded into the child, the expected final state, and — for restart —
  the expected post-restart state.
- **Binary identity**: both programs are pinned by SHA-256. `command[0]` and
  `restart_command[0]` must be the literal `{binary}` placeholder — the
  controller never execs the configured path directly. Before each arm it
  copies the pinned binary into that arm's private directory, verifies the
  copy's digest against the pin, then strips the owner write bit
  (`0o500`: read and execute only). Immediately before every spawn — primary
  and restart alike — the controller re-opens that exact copy `O_NOFOLLOW`,
  fstats it as a regular file, and re-hashes the open bytes against the pin,
  so the arm process cannot swap or mutate argv[0] between runs. Both runs
  expand `{binary}` to that copy; a non-regular source, a symlinked copy, or
  a digest mismatch at spawn time aborts the campaign.

The canonical SHA-256 of the corpus, schedule, peer parameters, and lifecycle
blocks are recorded separately and must be equal across every arm of the
campaign (they are, by construction, one config — and the comparator asserts
the per-arm transcript digests against them anyway).

## Execution model

- One run binds a listener on `127.0.0.1` at an ephemeral port, starts the
  peer thread, and only then spawns the child by direct argv substitution —
  `{binary}` expands to the arm's verified private copy, alongside
  `{peer_host}`, `{peer_port}`, `{data_dir}`, `{state_path}`. No shell is
  ever invoked with input-derived text (`shell=False`, list argv,
  unsupported `{...}` placeholders rejected at load).
- The first four bytes the peer connection presents must equal the
  configured `network_magic`. Accepted candidates are multiplexed in one
  selector under the arm's absolute deadline: a silent or partial
  candidate (external readiness probe, port scanner, slow peer) can never
  head-of-line block the real child, and one selector wake does a
  bounded slice of work: at most 16 accepts and one fixed snapshot of at
  most 16 pending classifications, with cancellation and the absolute
  deadline checked before every accept and classification. At most 16
  candidates are held at once; an arrival beyond that bound is closed on
  the spot — an older pending peer is never evicted merely because
  arrivals continue. Each candidate is peeked with `MSG_PEEK` — never
  consuming bytes — so magic may arrive in one or more TCP segments.
  Wrong-prefix and closed candidates are closed and dropped; the first
  candidate presenting the full magic wins, and every losing candidate
  is closed on success, cancellation, deadline, or error. The winner's
  magic bytes remain unconsumed for the schedule's configured disconnect
  read. The deadline is never reset per candidate or per attempt.
- Clocks are `time.monotonic_ns` throughout; sleeps target absolute
  deadlines and poll the cancellation event in ≤ 50 ms slices, so a cancelled
  peer never waits out a long stall.
- Parsers are byte- and depth-bounded before any semantic work, and open
  their input without following symlinks (`O_NOFOLLOW | O_NONBLOCK`), require
  a regular file, and read one bounded fd: config files ≤ 40 MiB,
  final/restart state files ≤ 1 MiB, JSON depth ≤ 32, argv lists ≤ 256
  arguments. Oversize, malformed, too-deep, FIFO, or symlinked input is
  rejected at the boundary; recursion failures during decode are contract
  errors.
- Binary custody uses one descriptor end to end: the configured binary is
  opened once with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`,
  fstat-verified as a regular file no larger than 1 GiB, and then hashed
  and copied from that same descriptor into the controller-owned private
  arm copy — no path is ever re-resolved between check and use. Direct
  FIFOs, symlinked sources, and oversize binaries are refused promptly,
  before any arm starts.
- Buffers are bounded: frames ≤ 4,000,024 bytes, corpus ≤ 16 MiB, inbound
  transcripts ≤ 16 MiB, schedules ≤ 4,096 steps. Exceeding a bound is a
  contract failure.
- Timing has fixed ceilings: `connect_timeout_ns` ≤ 10 s, `io_timeout_ns` ≤
  120 s, and one absolute arm deadline ≤ connect + 180 s from arm start that
  covers the ready wait, the primary wait, the worker join, the teardown,
  and the restart wait — there is no separate restart budget. The schedule's
  worst-case duration — the sum of every `delay_ns` and `duration_ns` plus
  every paced send's `frame_bytes × 10⁹ / bandwidth_bytes_per_second` — is
  computed at load and must fit inside the declared I/O deadline; a hostile
  schedule is refused before any process starts.
- Pacing sends in 64 KiB chunks against computed deadlines; a `stall` is an
  explicit silent interval, distinct from bandwidth pacing.
- Process ownership rests on one Linux boundary, never on session or
  process group. The comparator installs `PR_SET_CHILD_SUBREAPER` once
  per campaign — refusing to start when the setting is unavailable or a
  foreign child already exists, and restoring the prior setting only
  after a final verified-empty ownership check — so `setsid` and
  double-fork daemonization orphan a descendant straight into
  comparator custody. Every owned process is a `(pid, start-time,
  pidfd)` identity: the start time is read before and after
  `pidfd_open`, signals go through `signal.pidfd_send_signal` only, and
  reaping targets exactly known adopted pids — never `waitpid(-1)` and
  never a stale bare pid. One `ArmProcess` owner per arm holds the
  listener, the peer worker, and each phase's leader, and every outcome
  after the worker starts — digest or spawn failure, timeout, restart,
  exception — leaves through the same close path: TERM, bounded 1 s
  grace, KILL, reap, then descendant sweeps to an empty fixed point
  (two consecutive empty sweeps one cancellation slice apart), all
  inside the arm deadline's cleanup reserve. The arm owner pins the
  host's own children immediately before each spawn and injects that
  baseline into the arm's drain; the set stays forbidden for the
  drain's lifetime, and a direct child of the comparator that appears
  later is a reparented tree member — adopted, TERMed, KILLed, and
  reaped by the same drain whether or not the leader's identity ever
  published — so a fast double-fork that escapes registration cannot
  disguise itself as host-owned, and daemonized escapes surface as the
  arm's `processes running` refusal inside the campaign, not as a
  scope-exit report. A descendant discovered after a normal leader
  exit rejects the arm even when cleanup succeeds; a leader that
  outlives the deadline is TERMed, KILLed, and reaped first and the
  timeout is then fatal; a drain that cannot converge, or a worker
  that survives cancellation, aborts the campaign instead of
  lingering. Even a spawn whose identity never published drains
  through the same pre-spawn baseline and sweep. The primary must
  reach the clean fixed point
  before the state read and the restart; the restart must reach it
  before observation and scoring. `start_new_session` is terminal
  isolation only.
- Seven pairs run per campaign. Even-indexed pairs run Core first, odd pairs
  run bitcoin-rs first, so first-peer advantage alternates. Each pair consumes
  the same config object; nothing is regenerated between arms.

## Correctness gates, in order

`_require_comparable` runs before any statistics:

1. Exactly 14 arms, two per pair, one Core and one bitcoin-rs.
2. Alternation: even pairs Core-first, odd pairs bitcoin-rs-first.
3. Byte/schedule/peer/lifecycle custody digests equal across the pair, and
   each arm's outbound transcript equals the corpus digest.
4. Protocol success per arm: exit code 0, peer connected, every schedule step
   completed, no peer-side error, inbound transcript matches the expected
   digest.
5. State equality: final state equals the config expectation on both arms and
   the two arms agree with each other; restart arms additionally require exit
   0 and equal post-restart state matching the expectation.

Any refusal raises `ContractError`, the process exits 2, and **no result JSON
is emitted**. Publication is atomic, clobber-free, and substitution-proof:
the result bytes are written into an unnamed `O_TMPFILE` inode, fsynced,
and then linked into place with `linkat(AT_EMPTY_PATH)` from that same
descriptor — no attacker-visible temporary name ever exists, an existing
destination survives with its bytes intact, and the run fails closed on
any failure (Linux required; no name-based fallback). There is no
partial-result shape.


## Statistics

Wall time per arm covers the supervised lifecycle: spawn until the
leader has been reaped, the peer worker has finished its contract, and
the leader's owned descendant tree is verified empty — a leader that
exits before the peer contract completes, or that leaves daemonized
descendants behind, refuses the arm instead of scoring. Summaries use
the nearest-rank percentile over each role's seven samples: `p50`,
`p95`, `p99`, `max`. The only ratio emitted is
`candidate_over_core_p50_ratio`, and only on the gated path.

## Result contract

`p2p-loopback-result-v2` binds: config canonical hash, the custody block
(network magic, protocol version, services, corpus/schedule/peer/lifecycle
hashes, both binary hashes, lifecycle mode and generation), a `correctness`
block (all six gates recorded as `true` — the document cannot exist
otherwise), every arm's wall time, exit code, peer transcript digests,
final/restart states, the per-role statistics, and the ratio. The document
carries a `result_sha256` computed over its own canonical serialization
without that field.

Raw argv is never published, and no published commitment is an offline
oracle for secrets — this holds by category-only projection, not by a
name denylist. The durable `config_sha256` and each arm's
`command_sha256` hash the same projection, in which no source token
survives verbatim: argv0 becomes `<executable>`; the exact known
placeholders (`{binary}`, `{peer_host}`, `{peer_port}`, `{data_dir}`,
`{state_path}`) become their fixed markers; `--` becomes
`<end-options>` and every token after it `<argument>`; `--name=value`
becomes `<long-option=value>`; any other long option becomes
`<long-option>`; every one-dash token — including glued forms like
`-p1234` — becomes `<short-option>`; all remaining text becomes
`<argument>`. Two configs or argv vectors differing only in secret
values — recognized or not, in any option grammar — therefore produce
identical public evidence, and no plaintext argument text enters
durable output by construction. Schema moved from v1 to v2 for the
command-field removal; every other field kept its v1 meaning.



## Standalone usage

```
python3 tools/benchmark-campaign/p2p_loopback.py --config <config.json> --output <result.json>
python3 -m unittest test_p2p_loopback   # from tools/benchmark-campaign/
```

The tool is standalone: tests use real loopback sockets and deterministic
fixture nodes (tiny Python scripts that connect, echo, read the exact corpus
length, and write state files).

## Limits

Loopback isolates protocol-facing overhead (framing, handshake handling,
message processing under identical stimulus). It does not measure
download-bound IBD: a loopback fixture imposes no real bandwidth constraint,
so these numbers cannot be compared with full-sync figures. Host-level claims
still need the custody conventions in
CONCEPTS.md → *Matched-harness comparison*.
