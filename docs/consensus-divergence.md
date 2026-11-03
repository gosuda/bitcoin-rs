# Respond to a consensus disagreement

Use the optional POSIX monitor with a private bitcoin-rs data directory and a separate, independently validated Bitcoin Core witness. The node runs normally without a witness. A difference in tips can be an ordinary reorg. Never use the reference hash as an instruction to invalidate or reconsider a block.

## Connect the witnesses

Put each RPC credential in its own private file containing `user:password`. A Core cookie works. Use numeric loopback HTTP addresses, or local ends of authenticated tunnels. Run the monitor as the node data-directory owner on the same POSIX filesystem, with working hard links, directory fsync and POSIX record locks. Its local RPC must report the same directory in `getrpcinfo.logpath`.

Create a private JSON configuration like this:

```json
{
  "local": {
    "url": "http://127.0.0.1:8332",
    "credentials": "/private/bitcoin-rs.cookie",
    "settings": {"consensus": {"network": "main", "profile": "BTC mainnet"}, "full_validation": true}
  },
  "reference": {
    "url": "http://127.0.0.1:18332",
    "credentials": "/private/core.cookie",
    "settings": {"consensus": {"network": "main", "profile": "BTC mainnet"}, "full_validation": true}
  }
}
```

Audit each process's startup arguments, configuration and validation history before setting these values. `consensus` is an operator attestation of the effective parameters, including overrides and signet challenge where applicable. The monitor also checks the live genesis, active parent, work and deployment information. RPC cannot establish every startup option, historical script execution, correct software provenance, or the independence of the two witnesses. Use an independently synchronized reference with full validation. Record additional non-secret configuration and build identifiers under `settings`. An optional `log` path on each endpoint includes at most its last 1024 bytes in a confirmed incident. Protect these records as local diagnostic data.

For regtest, audit activation heights explicitly. The pinned Core 31.1 defaults differ from this node. The process regression configures Core with `-assumevalid=0`, `-testactivationheight=bip34@500`, `-testactivationheight=dersig@1251`, `-testactivationheight=cltv@1351`, and `-testactivationheight=csv@432`. Both sides must still pass the live parent checks.

Run an observation, then enable containment after checking the destination:

```sh
python3 scripts/consensus_monitor.py --datadir /private/node watch --config /private/witnesses.json --once
python3 scripts/consensus_monitor.py --datadir /private/node watch --config /private/witnesses.json --arm
```

Use `--block /path/to/block.bin` for a specific binary block. Otherwise the monitor finds the first differing height, probes both branches, and checks up to 16 invalid tips per side against a higher-work validated chain. It compares active rule heights irrespective of their buried/versionbits RPC representation and excludes the signaling-only testdummy bit. It does not accept chain selection by work alone. The local `getblockverdict` RPC checks complete encoded bytes against the applied parent without submitting them. On Core, proposal mode supplies a possible rejection. A matching hash or a successful proposal does not establish consensus acceptance. Both proposal paths omit checks such as proof of work; the monitor requires the exact body on a fully validated active chain. Unknown reject reasons, administrative invalidation, policy rejection and incomplete proposals do not authorize quarantine. The local classification uses the chainstate error disposition. Only explicitly recognized Core consensus reasons can escalate.

The latest observation replaces `consensus-divergence-latest.json` (at most 32 KiB). It reports consistent, suspected, confirmed or inconclusive. A matching tip means that the tips match at this observation. Reference outages, IBD, a tip older than a day, assumed chainstate, different settings, a moving parent, unavailable historical bytes, or different bytes for one header prevent confirmation. Sampling can miss a transient conflict. Historical side branches may need independent replay from the matching ancestor. A faulty or misconfigured witness can still misdiagnose a mismatch.

## During quarantine

Armed confirmation creates `consensus-divergence.json` once. It retains the exact block (up to 4,000,000 bytes, hex encoded), body digest, header identity, work context, both observations' time range, versions, settings, verdict categories, reasons and available log tails. A later observation cannot replace the first incident. Two fixed staging names bound interrupted writes; subsequent observations report the latched incident and current witness availability. Copy the incident, logs, binaries and configuration to a separate incident directory before touching existing data.

The node checks the marker on startup and polls it at 250 ms intervals. Check `getrpcinfo.consensus_quarantine`, the `node.consensus_quarantine` gauge, or `GET /api/health` (HTTP 503 when quarantined) to verify that the node observed it. Object-shaped diagnostic replies, including verbose block and header reads with confirmation counts, also mark their results. Economic RPC calls return `-32001`. REST and Esplora data reads return HTTP 503. Authenticated JSON-RPC provides hash-addressed block/header reads, read-only diagnostic validation, peer information and stop during quarantine. `getblockverdict` uses the RPC blocking-request budget. An in-flight validation can finish during shutdown. SV1/SV2 sessions disconnect and fresh templates, cached jobs and pool submissions stop. An already admitted mutation can finish and return its actual receipt. Scalar and array receipts retain their RPC wire shape. Check `getrpcinfo.consensus_quarantine` for their incident status. Operators can still abort an existing `scantxoutset` scan. Embedded consumers can check `Node::consensus_quarantined()`; new mining handles, transaction/package broadcasts, historical prefix queries, fee estimates and snapshot activation are unavailable during quarantine. A previously obtained mining handle can still inspect statistics, but cannot issue work or submit blocks or headers. P2P continues normal header and block observation with its existing relay and peer rules. Quarantine does not set `closed_for_recovery` or certify that the reference is correct.

## Verify and release

1. Stop the monitor and notify miners, index consumers and downstream operators. Record the first common ancestor and the first differing block. Save its exact bytes and both versions, settings, timestamps and logs. Preserve existing data directories.
2. Reproduce both verdicts on independent, disposable full-validation copies from the common parent. Check PoW, active rules, witness bytes and the failure category. Rule out administrative invalidation, pruning, I/O errors, stale tips, an incomplete snapshot and a bad reference. Treat storage corruption through the [recovery procedure](contracts/recovery.md).
3. Record the classification, impact and corrective action in a postmortem. A confirmed defect needs a regression vector for these bytes and parent context, with an independent expected verdict. Deploy the reviewed fix. Revalidate chainstate as needed and reconcile index watermarks, miner jobs, ledger observations and payouts.
4. Stop bitcoin-rs. Archive and acknowledge the exact incident only after verification:

   ```sh
   python3 scripts/consensus_monitor.py --datadir /private/node clear \
     --incident-id INCIDENT_ID_FROM_RECORD --archive /private/incidents/CASE.json \
     --verification "Reviewed fix, regression vector and revalidation report: CASE"
   ```

   The incident ID identifies the complete evidence record, including the body digest. The archive must be new. Clear refuses a running node, an unknown incident or an existing archive. A damaged marker needs evidence preservation and operator investigation. Restart, verify health, then reconnect miners and consumers. Restart alone keeps an unresolved incident latched.
