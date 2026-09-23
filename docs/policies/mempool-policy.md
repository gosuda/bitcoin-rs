# Mempool policy

## 1. Reference and selected settings

The [policy contract](../contracts/mempool-policy.md) owns the rules below;
this page maps them to evidence and intentional compatibility differences.
[core-compat.toml](../api/core-compat.toml) carries the Core source and
binary pins.

The process policy tests explicitly configure Core with
`-acceptnonstdtxn=0 -minrelaytxfee=0.00001000
-incrementalrelayfee=0.00001000 -dustrelayfee=0.00003000
-datacarriersize=83`. These reproduce the selected bitcoin-rs settings;
Core 31.1's default minimum and incremental relay rates are **100**, not
1,000 sat/kvB. Neither default equivalence nor performance equivalence is claimed.
Both processes run isolated regtest chains funded by identical block bytes.

## 2. Ownership and commit

`POL-02` and `POL-03` own admission, preparation stamps, and atomic refusal.
[Mempool mutations](../contracts/mempool-mutations.md) owns publication order:
replacement removes victims before publishing acceptance; ordinary insertion
keeps its accepted-before-capacity-removals event order. This page does not
define another graph, mutation owner, or commit protocol.

## 3. Policy matrix

| Policy | Implemented behavior | Evidence |
| --- | --- | --- |
| Full RBF | Signaling does not determine admission. Explicit/inherited BIP125 metadata remains available for reporting. | `replacement_signaling_matches_pinned_core` |
| New unconfirmed inputs | Allowed unless they depend on a transaction being evicted. | Process graph merge/split; `replacement_profile` |
| Replacement work bound | At most 100 distinct direct-conflict clusters, including an eligible TRUC sibling. Descendant transaction count is not this bound. | Process 100/101 boundary; 150-victim unit vector |
| Absolute replacement fee | Candidate modified fee covers the sum of all victims' modified fees. | Process underpayment and prioritisation cases |
| Incremental fee | Additional modified fee covers `CFeeRate::GetFee(vsize)`: integer truncation with a minimum 1 sat for nonzero size/rate. | Signed 1 sat boundary; small-rate unit vector |
| Diagram improvement | Exact checked rational comparison of complete affected curves, with horizontal tails. Equality and crossing reject. | Pinned Core numeric vectors, exhaustive small-DAG oracle, process crossing rejection |
| Cluster count | 64 transactions per connected component inclusive. Replacements use the projected graph after removals. | Process 64/65 boundary and replacement into full cluster; `graph_limits` |
| Cluster size | Sum of exact sigop-adjusted weights is at most 404,000 WU. | `graph_limits`, RPC size-limit and projection tests |
| Historical ancestry limits | No separate 25-ancestor, 25-descendant or ancestor-size admission limit. Query metadata remains. | `graph_limits`; both-RPC 26-member chain |
| Single preview | Same policy and script verification as submission, without mutation. | Process and gateway preview-purity tests |
| Multi-transaction preview | Count 1–25, total wire weight at most 404,000 for multi-tx packages, unique txids, topological order and no inter-transaction double-spends. | `package::tests`, process package cases |
| Package prechecks | No replacement or sibling eviction; every transaction pays its own modified relay fee. First precheck failure leaves every other row unfinished. | Process fail-fast and replacement-disallowed cases |
| Package graph | Combined additions must satisfy cluster/TRUC limits. Scripts run in dependency order after all prechecks; earlier script successes survive a later script failure. | Package owner tests; accepted signed parent/child process case |
| TRUC versions | Versions 1–3 are standard. Unconfirmed v3/non-v3 inheritance is forbidden in both directions. | TRUC unit and process cases |
| TRUC sizes/topology | Root at most 10,000 adjusted vB; child at most 1,000. At most one unconfirmed ancestor and one descendant. | Exact unit boundaries; process size/grandchild rejections |
| TRUC sibling eviction | An eligible existing 1-parent/1-child sibling joins the RBF conflict set even without a double-spend. Its fees and diagram remain binding. | Signed weak/strong sibling process cases |
| Ephemeral dust | At most one dust output; both base and modified fees must be zero. A child spending any output of that unconfirmed parent must spend all its dust. | Process fee rejections; zero-floor gateway spend/overlay/purity tests |
| Fee floors | Minimum relay uses modified fees and the integer relay charge. The pressure heuristic differs from Core (§5). | Both-RPC floor tests and process prioritisation |
| Sigops | Gateway computes BIP141 cost from resolved outputs; at most 16,000. Policy weight is `max(wire_weight, sigops * 20)`, and policy vsize is its ceiling divided by four. | Independent rust-bitcoin accounting tests and admission boundaries |
| Finality | Absolute locktime at tip+1; BIP68 uses confirmed height/MTP, unconfirmed parents at the next block, gated on CSV; coinbase depth at least 100. | `policy_contract`, `admission`, gateway tests |
| Maximum fee | After successful policy/script verification, base fee is compared to the integer charge at the caller rate and actual vsize; a zero charge disables the guard. | Both-RPC precedence tests and signed 1 sat maximum-fee boundary |

The raw trusted pool API accepts caller-provided policy vsize. If it does not
match resolved weight, the raw fixture is charged at `vsize * 4`. Production
admission derives consistent sigop-adjusted size and retains exact weight.

## 4. Error surface

Replacement uses `insufficient fee`, `replacement-failed` and
`too many potential replacements`. Fee/count failures involving an added TRUC
sibling include ` (including sibling eviction)`. TRUC rejects with
`TRUC-violation`; a cluster rejection is `too-large-cluster` on RPC.
Multi-transaction replacement rejects with `bip125-replacement-disallowed`.
Dust errors are `dust` or `missing-ephemeral-spends`.

An unfinished package row has only txid/wtxid and an optional `package-error`.
It does not contain `allowed`, fees or a fabricated rejection. Completed rows
use the pinned corepc v31 type; the identity-only variant supplies the Core
package shape missing from corepc-types 0.15. Rejected rows omit fee/size fields.
Accepted rows include captured modified `effective-feerate` and their wtxid.

Generic script errors and some numeric RPC error codes remain intentional
compatibility differences. The manifest retains `deviation` for both admission
RPCs; successful selected cases do not certify their entire surface.

## 5. Allowed differences and unsupported cases

The machine-readable list lives in `core-compat.toml` under `admission_profile`.

- `submitpackage` and aggregate CPFP/package RBF submission remain unsupported;
  the registry returns -32601 and Esplora `/txs/package` remains 404. Multi-row
  `testmempoolaccept` follows Core's non-aggregating test mode. Under the selected
  positive relay floor a zero-fee ephemeral parent cannot enter alone. The
  zero-floor owner tests prove dust spending rules, not default CPFP support.
- The graph owner computes exact optimal dependency closures. Core uses bounded,
  history-dependent SFL linearization and can temporarily have a non-optimal
  diagram. Those transient work-budget decisions and tie ordering are not
  emulated. An independently optimal diagram is not evidence of full Core
  parity. The 64-node process vector and exhaustive small-DAG oracle cover
  their stated cases only; adversarial/churn parity remains unverified.
- Capacity is a virtual-size sum rather than Core's allocator usage. The existing
  half-full/lowest-entry pressure-floor heuristic is not Core's rolling minimum
  with block/time decay. Candidate-capacity refusal is atomic here; no parity
  claim is made for Core's speculative insert-and-trim side effects.
- Generic consensus/script error details, the missing-input/max-fee numeric error
  codes, and the configured nulldata budget's CompactSize accounting retain
  their recorded differences. `getmempoolinfo.optimal` stays true for this
  exact-ordering implementation and does not track Core's background work state.

## 6. Verification

Run the production comparisons with the exact pinned binary supplied through
`BITCOIN_RS_REFERENCE_BITCOIND`:

```sh
cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_process_harness policy_cases:: -- --nocapture
cargo test --locked -p bitcoin-rs --no-default-features --features fjall --test overhaul_process_harness replacement_signaling_matches_pinned_core -- --exact --nocapture
cargo test --locked -p bitcoin-rs-mempool -p bitcoin-rs-mining -p bitcoin-rs-rpc
cargo test --locked -p bitcoin-rs-mining --test overhaul_resource_bounds -- --nocapture
bash scripts/ci-pr.sh clippy
```

Process custody, binary digests, argv and RPC transcripts remain in
`target/process-harness/run-*/`. Missing reference evidence fails instead of
skipping. Mathematical vectors are in `fee_diagram/tests.rs`; exact graph/TRUC
boundaries are in `replacement_profile` and `graph_limits`; package shape,
ephemeral spending and fee-only invalidation are in `package::tests`.
No throughput, latency or default promotion follows from these correctness tests.

The scoped CL-14 graph-resource capture emits RSS/retained-byte samples and
source digests into the same CI artifact directory. Its synthetic admitted
chains and one-pass times do not establish a product performance baseline.
