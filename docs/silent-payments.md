# Experimental BIP352 public scan material

This is the feasibility and codec stage of #1491, based on PR #1554.
The opt-in `bitcoin-rs-index/silent-payments` Cargo feature exposes
`transaction_tweak` and `block_tweaks`. No durable rows, startup rescan,
runtime switch or wallet subsystem is added. A network service remains future
work; the codec supports one certified retained block.

## Semantics and reference pins

[BIP352 and its reference code/vectors](https://github.com/bitcoin/bips/blob/8754690b725e9aa93ca8bd91bf0ac85dc44ce096/bip-0352.mediawiki)
are pinned to `8754690b725e9aa93ca8bd91bf0ac85dc44ce096`.
The [WIP index-server specification](https://github.com/silent-payments/BIP0352-index-server-specification/blob/dc705a055e72024e332e232cf038c96afd42d50e/README.md)
is separately pinned to `dc705a055e72024e332e232cf038c96afd42d50e`.
Its JSON examples do not define BIP352 cryptography.

Given a **consensus-validated** transaction, exact input-ordered prevout scripts,
and an explicit Taproot activation status (`taproot_active`), the codec requires
a P2TR output and an eligible input. When Taproot is not active, pre-activation
native witness v1 scripts are unassigned programs rather than BIP341 Taproot
outputs: the transaction produces no tweaks, and blocks return empty tweaks
without misinterpreting pre-activation witness spends as corrupt. When Taproot
is active, spending a native witness program with version greater than one
excludes the whole transaction (`coin.out.scriptPubKey.IsWitnessProgram && version > 1`,
matching Core `src/common/bip352.cpp`). Inputs spending non-v0 P2SH programs (including
P2SH-wrapped future witness scripts) contribute no key to shared-secret derivation
rather than disqualifying other eligible inputs. It extracts compressed keys from
P2PKH (hash-matching even malleated scriptSigs), P2WPKH and P2SH-P2WPKH.
Unsupported scripts and uncompressed keys contribute no key. Taproot uses the
even lift of the output key; script-path spends with the BIP341 NUMS internal
key are excluded after inspecting an optional annex without mutating it.

Keys are summed with multiplicity; zero intermediate sums are permitted.
No keys or a final point at infinity means ineligibility. The input hash is
`hash_BIP0352/Inputs(lowest_outpoint || compressed_sum)`. The lowest outpoint
is among **all** inputs, including ineligible types, sorted by its 36
serialized little-endian bytes (not display txid or numeric vout). A
zero/out-of-range scalar fails explicitly. The result carries txid, sum,
input hash, the 33-byte compressed point `input_hash * sum`, and every P2TR
candidate with its output index. Dust, spent and duplicate outputs are kept.

The receiver performs ECDH, label/output derivation and discovery locally.
Candidates must be verified with complete block/transaction data and chain
membership. A tweak does not prove an output is unspent or a wallet balance.
This codec does not authenticate caller-supplied scripts or execute consensus
validation; full validity comes from the already-validated chainstate/input
contract. Only local structural checks are performed on Taproot witness and
control blocks (rejecting empty witnesses and invalid control-block lengths,
while accepting a correctly sized control block without validating its internal
key or leaf-version byte); shape violations produce an error rather than
consensus verification.

## Owners and coverage

Current UTXOs cannot answer historic spent prevouts. `TxLookup` stores
transaction locators, not coins; resolving a funding transaction additionally
needs its retained body and a ready watermark. A birthday scan can spend
funding outputs older than the birthday, and separate per-input queries do
not establish one coherent complete block view.

The existing `utxo::contract::BlockUndoSource`, implemented directly by
`Chainstate`, is the retained-window source. It authenticates body/witness
commitments, certifies native undo against durable receipts, resolves same-block
inputs from earlier transactions, and rechecks applied hash/receipt/retention
lease after reading. See the
[retained input contract](contracts/external-api.md#retained-block-inputs).
Call this owner directly with a captured applied hash, then project its
`BlockSpends`. No forwarding reader, availability store, txindex capability
or second UTXO owner is needed.

The codec checks row counts and outpoint alignment and returns the body's exact
hash. It makes no unverified height or active-tip claim. A future adapter must
resolve height/hash and Taproot activation on one applied ancestry and recheck
publication after projection; `BlockSpends` does not carry activation context or
height, and a completed source read cannot prevent a subsequent tip move.

| Situation | Coverage and error policy |
| --- | --- |
| Certified retained body/undo | One-block projection works without txindex or new durable rows. |
| Birthday / full Taproot-era scan | Every requested body and undo must be retained and certified. Being unpruned today does not prove an old missing prefix. |
| Pruned/reserved/missing history | Preserve the owner's typed history/read failure even for empty blocks; restore/replay required data before promising coverage. |
| Missing/unready txindex | No effect on the certified-undo codec path; cannot mask missing undo. |
| Snapshot prefix | Retained bytes are insufficient without certified archived validation progress. |
| Reorg/restart/full rescan | Recompute from the chosen body. Source receipts/leases own readiness; a future cache must key full block identity and invalidate active-chain assignments. |

Partial-success lists are not returned. `None` means complete transaction
ineligibility or coinbase, never missing history. Source commit, recovery,
snapshot and lock/lease behavior remains covered by
`crates/chainstate/tests/unit/block_spends_tests.rs`; those paths are unchanged.
Codec replay tests do not prove lifecycle behavior of a future durable index.

## Resources and consumer assessment

The codec stores zero durable bytes and admits at most 4,000,000 serialized
body bytes and 64 MiB aggregate prevout script bytes per projection. The existing
source separately bounds body/undo copies and spent-coin projection. Work scans
inputs/outputs, aggregates keys and multiplies one point per eligible transaction;
P2PKH extraction hashes 33-byte scriptSig windows. CPU, temporary memory and
mainnet throughput are unmeasured. These are input bounds, not latency or global
memory guarantees. Tweak points alone cost `33 * eligible_transaction_count`
bytes: hypothetically 115,500 bytes for 3,500 eligible transactions, before
framing/txids/candidates. Full history also retains native bodies/undo. No
mainnet disk-cost estimate follows from this arithmetic. A durable cache needs
measured benefit and the existing writer/fence/reconciliation/replay owners.

The evaluated target is [BlindBit Oracle](https://github.com/setavenger/blindbit-oracle/blob/f9ab7fd8bc35467c492324f743ba1b69049a2bb6/internal/server/README.md),
pinned to `f9ab7fd8bc35467c492324f743ba1b69049a2bb6`. It deprecates HTTP
block-data APIs and directs clients to gRPC `OracleService`; HTTP `/info`
remains supported. Its legacy tweak response has `block_identifier`/`index`,
whereas the draft describes `/getinfo` and `/tweaks/:height` with
`height`/`hash`/`tweaks`. Implementing only the draft examples would not
establish unmodified-client interoperability. This is a documented WIP
protocol incompatibility, not a successful wallet run.

An external sidecar speaking the pinned consumer protocol is the deployment
alternative: existing `getblock` verbosity 3 or `/rest/spenttxouts` supply
certified inputs, existing APIs supply complete blocks, and PR #1554's optional
filters can reduce downloads. It must reject missing prevouts and verify
identity/coverage; wallet scanning stays local. No full duplicate coin database
or wallet fork is justified by this stage. Funded regtest wallet discovery and
confirmation has **not** been run.

A production adapter still needs a pinned consumer contract, proven coverage
and bounded CPU admission. It must use existing node/RPC/REST serving and
materialization permits, bound ranges/responses, limit concurrency, rate-limit
callers and keep validation/IBD responsive. No HTTP scheduler/rate limiter is
introduced for this library-only stage.

## Evidence, privacy and API status

The Rust test checks 29 public receiving-vector projections against pinned
sums/tweaks, including labels/multiple outputs, NUMS, malleated P2PKH, invalid
P2SH, uncompressed keys and infinity cases. The unmodified pinned Python
reference passed the full vectors locally (WSL, Python 3.12.3). Additional
tests cover future witness versions, missing material/history, empty blocks,
output indices, limits and deterministic hash-scoped replay. Extraction is
recorded in `crates/index/tests/data/bip352-PROVENANCE.md`.

No parameter accepts wallet private keys, addresses, subscriptions or payment
history, and the codec performs no I/O/logging. Network metadata, height queries
and logs can still reveal birthdays/access times/ranges: keyless computation
alone is not anonymity. Spent/dust filtering and scan-interest parameters are
absent. Query-log and traffic privacy policies remain deployment concerns.

`REGISTRY`/`MANIFEST` gain no network entries: `/getinfo` and `/tweaks/:height`
are not served and Core behavior is unchanged. The
[ecosystem inventory](api/ecosystem-compat.toml) marks the codec experimental,
not a Core RPC or finalized index-server protocol. Compact filters inherited
from PR #1554 remain a separate capability, not a codec requirement.
