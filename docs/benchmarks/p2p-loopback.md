# P2P loopback lanes

This document owns the loopback P2P lanes of the target node (gate G7): deterministic multi-peer handshake, headers, block download and serving, transaction ingress and egress, discovery, fee-filter relay, compact-block reconstruction with full-block fallback, and optional v2 transport and compact filters when enabled. No lane contacts public nodes.
Comparator `tools/benchmark-campaign/p2p_loopback.py` (contract `p2p-loopback-config-v1`, result `p2p-loopback-result-v2`); description below is prior contract text, and no completed campaign is claimed.

## Cells it owns

| Cell | Metric | Status |
|---|---|---|
| `replay.live_ibd_loopback` | wall to pinned stop, blocks/s, peak RSS vs Core `v31.1`, identical frames | `planned_not_executed` |
| `propagation.block` | announce to validated publication, with/without compact-block reconstruction | `planned_not_executed` |
| `propagation.tx` | accepted-and-retained tx reaches eligible second peer, never source; fee filter, relay flag, wtxid honored | `planned_not_executed` |
| `p2p.requeue_exactness` | disconnect requeue equals freed set; stale-session completion is typed no-op | `planned_not_executed` |
| `p2p.control_under_pressure` | control serviced under bulk saturation; drops accounted | `planned_not_executed` |
| `p2p.optional_off` | with `bip324`/compact filters off: no service bits/negotiation, validation identical (`g19` agrees) | `planned_not_executed` |

Every lane runs the same artifact under both `--features fjall` and `--features fjall,bip324` where the lane concerns transport; the two states MUST agree on validation. Disconnect classes, payload bounds, handshake exceptions are compared against the pinned Core contract in `crates/p2p/tests/core_compat.rs`.

Required identities per sample: six identities of [`README.md`](README.md), enforced by the T02 collector. Acceptance: promotion, regression, reporting, retention, `BLOCKED` rules of [`README.md`](README.md). Status: `planned_not_executed`.

## Comparator contract (prior text, not end-state proof)

Harness `tools/benchmark-campaign/p2p_loopback.py`, tests `tools/benchmark-campaign/test_p2p_loopback.py`; addresses issue #35. Feeds Core 31.1 and bitcoin-rs the identical external peer experience (same frames, delays, ceilings, stalls, disconnects, order, parameters); compares externally observed wall time only after every custody and correctness gate passes.

- Config `p2p-loopback-config-v1` binds every arm: ordered complete-frame corpus (magic/padding/length/checksum validated at load); schedule (`send`/`stall`/`disconnect`, every frame exactly once, disconnect final); peer params (magic, version, services, timeouts, buffers, transcript digest); lifecycle (`fresh`/`restart`, generation, seeded/expected state); binaries SHA-256 pinned, `command[0]`/`restart_command[0]` MUST be the literal `{binary}` placeholder, expanded to a per-arm verified `0o500` copy re-hashed `O_NOFOLLOW` before every spawn.
- Execution: listener on `127.0.0.1` at ephemeral port; `shell=False` list-argv substitution of `{binary}`, `{peer_host}`, `{peer_port}`, `{data_dir}`, `{state_path}`; magic-prefixed candidate multiplexing under one absolute arm deadline; `time.monotonic_ns` clocks; bounded inputs (frames ≤ 4,000,024 B, corpus/transcripts ≤ 16 MiB, schedules ≤ 4,096 steps; configs ≤ 40 MiB, argv ≤ 256, depth ≤ 32, `O_NOFOLLOW` regular files); binary custody one-descriptor open/hash/copy ≤ 1 GiB; pacing in 64 KiB chunks with fixed ceilings (connect ≤ 10 s, I/O ≤ 120 s, arm ≤ connect + 180 s); Linux `PR_SET_CHILD_SUBREAPER` ownership with TERM/KILL/reap-to-empty descendant drain; 7 pairs, even pairs Core-first, odd pairs bitcoin-rs-first.
- Correctness gates (`_require_comparable`, in order): exactly 14 arms (2 per pair, Core + bitcoin-rs); alternation; custody digests equal and outbound transcript equals corpus digest; per-arm exit 0, peer connected, full schedule, inbound digest match; final state equals expectation on both arms and agrees across arms (restart arms also exit 0 with equal post-restart state). Any refusal raises `ContractError`, exits 2, and emits NO result JSON. Publication is atomic via unnamed `O_TMPFILE` + `linkat(AT_EMPTY_PATH)` (Linux only); no partial-result shape.
- Statistics: wall per arm is spawn until leader reaped, peer worker done, descendant tree empty (early exit or surviving descendants refuse the arm). Nearest-rank `p50`/`p95`/`p99`/`max` over 7 samples per role; only ratio `candidate_over_core_p50_ratio`, only on the gated path.
- Result `p2p-loopback-result-v2`: config hash, custody block, `correctness` block (all six gates `true`), every arm wall/exit/digests/states, per-role summaries, ratio; `result_sha256` over canonical serialization without that field. Raw argv is never published; `config_sha256` and `command_sha256` hash the same category-only projection (no source token survives verbatim). Schema v1→v2 removed command fields only.

```bash
python3 tools/benchmark-campaign/p2p_loopback.py --config <config.json> --output <result.json>
```

Conclusion: loopback isolates protocol-facing overhead (framing, handshake, identical-stimulus processing), NOT download-bound IBD; host-level claims still need CONCEPTS.md *Matched-harness comparison*.
