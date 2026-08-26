---
title: CHECKSIG census and the script-check floor
date: 2026-08-12
category: performance
module: checksig census
problem_type: performance_issue
component: census analyzer
severity: medium
symptoms:
  - A terminal census checkpoint can exist before child process teardown completes.
  - Revalidating recovered evidence can require redundant terabyte-scale reads.
root_cause: logic_error
resolution_type: code_fix
tags:
  - checksig
  - cmodern
  - custody
  - salvage
---

# CHECKSIG census and the script-check floor

Status: **OPEN.** The CHECKSIG census over mainnet blocks 0..150,000 shows
that `CPubKey::Verify` from libbitcoinkernel-sys 0.3.0 (via bitcoinkernel 0.2.1,
embedding Bitcoin Core 31.99.0 development sources) accounts for 39.32 µs
(53.41%) of the 73.62 µs width-1 kernel verification cost per input check.
The remaining 34.30 µs (46.59%) covers legacy sighash construction, script
evaluation, and wrapper overhead. That residual exceeds the 27.73% lever
threshold.

## Census methodology and 24-counter results

The production `libbitcoinkernel` FFI verification path was instrumented to capture all script execution and cryptographic operations across mainnet blocks 0..150,000 without altering verification semantics. The pipeline emits four file-bound native streams in the same process run using same-open parse-stream custody: `BRSCTX1\0` (contexts), `BRSJRN1\0` (journal), `BRSREC1\0` (records), and a 24-counter JSON header.

Across 2,868,199 input checks, the 24 u64 counters yielded:

| Counter Name | Count | Description |
|---|---|---|
| `verify_script_calls` | 2,868,199 | Total script verification invocations |
| `ffi_verify_entries` | 2,868,199 | Bitcoinkernel FFI verify entry calls |
| `ffi_verify_true` | 2,868,199 | Successful FFI verify returns |
| `eval_script_entries` | 5,736,398 | Script evaluator entry points (two passes: scriptSig + scriptPubKey per P2PKH check) |
| `op_checksig` | 2,868,199 | `OP_CHECKSIG` executions |
| `op_checksigverify` | 0 | `OP_CHECKSIGVERIFY` executions |
| `op_checkmultisig` | 0 | `OP_CHECKMULTISIG` executions |
| `op_checkmultisigverify` | 0 | `OP_CHECKMULTISIGVERIFY` executions |
| `op_checksigadd` | 0 | `OP_CHECKSIGADD` executions (Taproot/BIP342) |
| `checkecdsa_entries` | 2,868,199 | Internal ECDSA check entries |
| `checkecdsa_reject_pubkey` | 0 | Invalid public key pre-secp rejects |
| `checkecdsa_reject_empty_sig` | 0 | Empty signature pre-secp rejects |
| `checkecdsa_reject_missing_data` | 0 | Missing transaction data rejects |
| `ecdsa_verify_calls` | 2,868,199 | `secp256k1_ecdsa_verify` calls |
| `ecdsa_verify_ok` | 2,868,199 | Successful `secp256k1_ecdsa_verify` calls |
| `ecdsa_verify_fail` | 0 | Failed `secp256k1_ecdsa_verify` calls |
| `ecdsa_from_checksig` | 2,868,199 | ECDSA calls originating from `OP_CHECKSIG` |
| `ecdsa_from_checkmultisig` | 0 | ECDSA calls originating from `OP_CHECKMULTISIG` |
| `sighash_computed` | 2,868,199 | Legacy signature hash computations |
| `sighash_midstate_hit` | 0 | Sighash midstate cache hits |
| `checkschnorr_entries` | 0 | Schnorr check entries |
| `schnorr_verify_calls` | 0 | Schnorr verification calls |
| `schnorr_verify_ok` | 0 | Successful Schnorr verification calls |
| `schnorr_verify_fail` | 0 | Failed Schnorr verification calls |

**Key Census Fact**: Exactly $a = 1.0$ ECDSA attempts occur per kernel script check ($2,868,199 / 2,868,199$). Every input in mainnet blocks 0..150,000 is an ordinary legacy bare P2PKH spend. All 11 special context counters (`p2sh_redeem_spends`, `native_witness_v0_spends`, `p2sh_wrapped_witness_v0_spends`, `bare_multisig_checks`, `p2sh_multisig_checks`, `native_witness_v0_multisig_checks`, `p2sh_wrapped_witness_v0_multisig_checks`, `taproot_key_path_spends`, `tapscript_spends`, `tapscript_schnorr_checks`, `tapscript_checksigadd_checks`) are zero. `eval_script_entries` is exactly $2 \times 2,868,199 = 5,736,398$. The exact product predicate (`_c150_passed`) evaluates to `all_passed: true` and `c150_passed: true`.

**Certification Pipeline and Rule**: Authoritative certification requires strict `mainnet-prefix-replay-v3` inputs, file-bound binary streams, and exact classifier (`classify-corpus-v2`) validation. Version 3 includes the replay producer's always-present txindex timing keys; they are nullable when txindex is disabled. Direct Core REST export can export raw blocks prior to replay, but live REST export cannot replace file-bound census evidence for certification. Sampled evidence (such as `kernel_verify_spike`) cannot certify a product corpus.

## Recover terminal proof after slow process teardown

The diagnostic controller can receive the terminal `BRSHGT1` checkpoint after the child has closed and flushed all evidence sinks, but before the child finishes chainstate teardown. A fixed process-exit deadline must not redefine completed evidence as incomplete. It must also not report a killed child as a clean exit. Candidate schema v2 records evidence completion and process teardown separately.

`salvage-cmodern-height` recovers this state without changing the failed run. It retains one descriptor for each source and recovery artifact from semantic reconstruction through candidate publication. The reconstruction validates every checkpoint-committed context, record, and journal slice. It hashes those same source bytes in the validation pass. It then reads and hashes a physical tail only when the source contains bytes beyond the last committed endpoint. This produces a direct full-file digest and a committed-prefix digest without a second source-stream pass.

The recovery directory is new and single-writer. The recovery step creates each missing ancestor from root to leaf and fsyncs its parent before it creates the next child. Each source artifact is reflink-cloned when the filesystem supports it, or copied otherwise. Stream clones are truncated to the terminal endpoints. The recovery step replaces only fixed headers: it writes reconstructed terminal row counts to the context, record, journal, and sidecar clones. This normalization also handles a crash after the terminal checkpoint but before the native flush patches source header counts. The source files stay unchanged.

Custody records the source full-file, committed-prefix, and committed-body digests before it changes a recovery header. The finalizer parses and hashes each recovery stream once. It requires the recovery body digest to match the source committed-body digest for the context, record, journal, and sidecar files. It requires each exact replay and counters clone to match the source size and SHA-256 digest. The strict parsers independently require the normalized magic and reconstructed row-count headers. Thus, an exact header and exact body bind each normalized stream to the validated source bytes without a third pass over the large evidence streams. Source and recovery path identities and retained descriptors must remain stable through publication. A post-publication mismatch unlinks the candidate and fsyncs its parent before salvage fails.

The child replay artifact does not record the REST endpoint. Offline salvage therefore records `rest_url_provenance: operator_supplied_original_argv`. The exact `data_dir` string does exist in the replay artifact and must match without path normalization. A salvaged candidate records `child_exit_status: null`, `child_teardown: unobserved`, and the immutable source directory in `salvaged_from`. The candidate remains non-certifying until the selected Cmodern corpus receives the normal file-bound replay and classifier proofs.

## Freeze the selected Cmodern product tip

The recovered diagnostic candidate selected mainnet height `709635` and block
hash
`00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f`.
Bitcoin Core REST independently returned the same hash for that height. The
candidate has all 11 context classes, and its last first-occurrence height is
`709635`.

This result freezes the product tip only. It does not certify the recovered
diagnostic run. The classifier accepts Cmodern only when a fresh
`mainnet-prefix-replay-v3` file replay stops at the exact tip, passes archive
and stream custody, passes counter arithmetic, and has a positive count for
each Cmodern context class. Report field `cmodern_frozen` means that the tip is
fixed. Report field `cmodern_passed` means that the new file-bound corpus
passed certification.

`INV-7` uses a contract-neutral Schnorr equation:
`checkschnorr_entries >= schnorr_verify_calls` and
`schnorr_verify_calls == schnorr_verify_ok + schnorr_verify_fail`. Record
reconciliation separately requires the aggregate `op_checksigadd` count to
equal the number of captured `CHECKSIGADD` operation records. The exact C150
predicate still requires all Schnorr and `OP_CHECKSIGADD` counters to be zero.
This split removes the pre-Taproot zero assumption from Cmodern without
weakening C150.

## Capture corpus and integrity proofs

- **KSPIKE1 Corpus**: `/home/alpha/bench-g14/results/u0-spike-corpus/corpus.bin`
- **Native Comparator**: `CPubKey::Verify` from libbitcoinkernel-sys 0.3.0
  (via bitcoinkernel 0.2.1, embedding Bitcoin Core 31.99.0 development
  sources), executing public key parsing, lax DER parsing, signature
  normalization, and `secp256k1_ecdsa_verify`.
- **Capture Repeat (INV-13)**: Both 159,259-record captures produced sorted-record SHA-256 `9841e3afc79018400c568d86b60747f9a0c1d6d1184fc3caf4815860f88739d2`.
- **Source Integrity (INV-14)**: `bitcoin/src/pubkey.cpp` SHA-256 is byte-identical in pristine and instrumented trees (`0c86716f3626f591e643bd327fe0e48f6cebba8da3aba91ec6587256d725f1c0`). The 178-file `secp256k1` tree manifest SHA-256 is byte-identical (`b61a27000f45b4408f8699bea9ec69668677696fbc22685e8c4111e1a5e7c6ee`). Source identity is authoritative as the debug build (`RelWithDebInfo`) embeds source paths with no LTO/IPO.
- **Native Correctness (INV-8)**: 159,259 expected true vs 159,259 native true; 0 mismatches (`mismatches == 0`, `ok_equals_count_outcome_1 == true`).
- **Instrumentation Isolation (INV-15)**: All 24 counters stayed at 0 during direct native timing runs.
- **Rust Diagnostic**: Rust `secp256k1` 0.31.1 rejected 2 lax-DER records pre-verification due to strict DER parser differences; Core native parity is authoritative.

## Reproduce the experiment

Use the complete tracked workflow in
[`tools/checksig-census/README.md`](../../../tools/checksig-census/README.md). It
reconstructs the patched native source, isolates build outputs, records source
integrity, captures the corpus twice, runs the three timing panels, and applies
the analyzer gates.

## Three-run timing and decision arithmetic

All runs pinned to `taskset -c 0-31`:

- **Run D (Spike Width-1 Per-Input Verification Cost $X$)**:
  - Run 1: 74.361958 µs/check
  - Run 2: 70.508882 µs/check
  - Run 3: 73.622370 µs/check
  - **Median $X$**: **73.622370 µs/check**

- **Run C (native `CPubKey::Verify` per-attempt cost $Y$)**:
  - Run 1: 38.274023 µs/attempt (38,274.02 ns)
  - Run 2: 39.322511 µs/attempt (39,322.51 ns)
  - Run 3: 41.544015 µs/attempt (41,544.02 ns)
  - **Median $Y$**: **39.322511 µs/attempt**

- **Arithmetic**:
  - Attempts per check $a = 1.0$
  - Native comparator floor $F = a \times Y = 39.322511\ \mu\text{s/check}$
  - Residual $R = X - F = 73.622370 - 39.322511 = 34.299859\ \mu\text{s/check}$
  - Residual fraction $r = R / X = 34.299859 / 73.622370 = 0.465889$ (**46.5889%**)
  - Required 5% wall-time win threshold: $\text{threshold} = 0.05 \times 69.6\text{s} / 12.55\text{s} = 0.277291$ (**27.7291%**)
  - Residual ceiling in script stage: $r \times 12.55\text{s} = 5.846908\text{s}$ (~5.85s max theoretical win)
  - Conservative spread bound: 8.517721 µs. Subtracting it leaves
    25.782138 µs/check (35.0194%), still above the 27.7291% threshold.

Because $r = 46.5889\% \ge 27.7291\%$, the verdict is **OPEN**.

## Replay durability proof and storage custody

The census replays rest on stores proven stable across reorg and reopen, so a
census counter cannot be an artifact of a corrupted or drifting chainstate.
Untimed durability verification (`crates/node/examples/verify_replay_durability.rs`)
covers `fjall`, `rocksdb`, and `redb`, and leaves the original stores
byte-identical. The store digests, per-backend file counts and byte totals,
proof-artifact sizes and SHA-256 values, the digest framing, and the custody
summary path are in
[`tools/checksig-census/README.md`](../../../tools/checksig-census/README.md),
section *Durability proofs and custody*.

## Scope and limits

1. The 46.59% residual is a **ceiling**, not a promised speedup. It includes legacy sighash construction (re-serializing spending transactions), script parsing and stack evaluation, `bitcoinkernel` C++/FFI boundary costs, and memory allocation overhead.
2. This ticket treats `CPubKey::Verify` from libbitcoinkernel-sys 0.3.0
   (Bitcoin Core 31.99.0 development sources, $F = 39.32\ \mu\text{s}$) as the
   reference implementation and does not measure lower-level cryptographic
   optimizations or signature caching.
3. The non-crypto residual investigation remains **OPEN**, while transaction marshalling, parallel pool width, and threshold sweeps remain closed based on prior benchmarks.
4. This finding makes no production code changes or performance promises; it establishes the empirical ceiling for any future non-crypto script path optimization.
