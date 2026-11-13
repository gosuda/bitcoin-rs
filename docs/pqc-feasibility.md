# Post-quantum migration feasibility

## Decision

Bitcoin-RS can host an isolated experiment for a post-quantum (PQ) soft fork.
The current implementation has the required consensus extension points.
It does not yet provide PQ signature validation or a PQ migration deployment.

Use an output commitment with no elliptic-curve-only spending path.
Add a separately specified PQ authorization rule through a reserved extension.
Keep activation and legacy-output restrictions explicit.
Start on regtest with native validation and a separate data directory.
The [BIP adoption policy](policies/bip-adoption.md) limits unactivated consensus
experiments to regtest or explicitly isolated test networks.

A later migration deadline can restrict the transactions that adopting nodes
accept. Such a restriction can remain a soft fork.
A soft fork cannot make unchanged nodes accept a later hard-fork block.
Do not use a scheduled chain halt to make adoption compulsory.
It creates an availability dependency without deciding which replacement rules
operators will accept.

This is a research assessment. It defines no activation height, deployed BIP
support, mainnet rule change, or production cryptographic suite.
PQC here means transaction authorization. Proof of work, transport security,
and the remaining hash assumptions need their own assessment.

## Evidence and scope

Assessment date: **2026-11-13**.

| Input | Revision |
| --- | --- |
| Bitcoin-RS default branch `dev` | [`60b33f6be7c55eb27e6892cdb7770687a8e40276`][baseline] |
| Bitcoin BIPs | [`b34d9f751791d4feb22feff4f2ed00bcac83961b`][bips-snapshot] |
| ML-DSA specification | [NIST FIPS 204][fips204], final publication |
| SLH-DSA specification | [NIST FIPS 205][fips205], final publication |

The review traced validation, activation, policy, and wallet ownership in source.
It also inspected existing tests and the pinned proposal texts.
Searches covered `crates`, `bin`, `docs`, `Cargo.toml`, and `Cargo.lock`.
No PQ verifier, BIP360 implementation, or BIP361 deployment was found in those
surfaces. The broad `pqc` search matched only an address substring in a fixture.

The review did not execute Rust tests. The review environment had neither
`cargo` nor `rustc` on `PATH`.
No PQ transaction, activation run, interoperability result, or benchmark was
produced. Existing test names below identify evidence to reuse; they are not
new passing results.

## What the repository already provides

All code links in this table point to the reviewed revision.

| Boundary | Observed implementation | Consequence for PQ work |
| --- | --- | --- |
| Witness dispatch | [`verify_witness_program`][interpreter] preserves acceptance of unknown nonzero witness versions under consensus flags. Policy can discourage them. | A new witness rule can restrict an existing extension point. |
| Script extensions | [The interpreter][interpreter] preserves future leaf versions and scans for `OP_SUCCESS`. [The evaluator][eval] preserves unknown tapscript public-key types. | Extension points exist. They do not verify PQ signatures. |
| Current signatures | [The signature checker][checker] verifies ECDSA and Schnorr using `secp256k1`. | A PQ verifier and its exact signature message remain to be specified. |
| Taproot authorization | [`verify_taproot`][interpreter] accepts either a key path or a script path. | A PQ script leaf alone leaves an elliptic-curve authorization path. |
| Deployment | [BIP9 code][bip9-code] computes activation states. [Deployment wiring][deployment] names only CSV and SegWit. Taproot uses a network height. | PQ activation, flags, RPC reporting, and mining signals need explicit wiring. |
| Resource limits | [Ordinary script elements][eval] are limited to 520 bytes. [Standard tapscript arguments][standardness] are limited to 80 bytes. | Large PQ objects need new bounded semantics and matching relay policy. |
| Engine selection | [Kernel dispatch][kernel] selects native or `libbitcoinkernel` verification. These are separate paths. | A native-only rule does not enforce PQ checks in the kernel path. |
| Wallet boundary | [The wallet contract][wallet] keeps keys and signing in external processes. | Consensus support does not supply wallet migration or PQ signing. |
| Existing quantum research | [The adoption decision for issue #1625][adoption] retains a read-only P2PK scan. | Enumeration is not PQ validation, a freeze, or a migration mechanism. |

The native path is a credible experiment boundary because it owns script
validation. It is not evidence that a mainnet PQ deployment is ready.
The [validation contract][validation] identifies the current engine and its
existing reference evidence.

## Why a soft fork can add PQ authorization

Compare rules at the same predecessor chain and validation context.
Let `V_old` be the set of next blocks accepted by the existing rules.
Let `V_pq` be the set accepted after the proposed restriction.

- A soft fork requires `V_pq` to be a subset of `V_old`.
- A hard fork permits at least one block outside `V_old`.

These are the compatibility definitions used by the
[Bitcoin developer guide][fork-guide]. They concern block validity, not
transaction relay policy or wallet support.

[BIP141][bip141] reserves witness versions for future interpretation.
An older node can accept a block containing such a spend without checking the
future authorization rule. An upgraded node can additionally require a valid
PQ proof. If every accepted block still satisfies the old rules, the change
is restrictive.

This does not make an unactivated output safe to fund.
Nodes that do not enforce the proposed rule do not enforce its authorization.
Activation and sufficient adoption are part of the security argument.

[BIP342][bip342] also provides future key types and `OP_SUCCESS` extensions.
It permits suitable `OP_SUCCESS` upgrades to define larger stack elements.
That is why a signature larger than 520 bytes does not, by itself, require a
hard fork. Merely changing the verifier for ordinary existing `CHECKSIG`
operations would not define all the necessary semantics.

The experiment must preserve the existing block envelope. In this revision,
[block validation][verify-block] limits weight to **4,000,000 WU**.
Allowing blocks above that existing limit would require separate compatibility
analysis and would be a hard fork relative to nodes enforcing it.

### Recommended authorization structure

Use a hash commitment without a spendable elliptic-curve output key.
Place the PQ verifier in a versioned leaf or an equivalent reserved witness
rule. Require PQ authorization on every usable spending path.

This replaces a PQ leaf inside ordinary Taproot as the first experiment.
The reason is the remaining Taproot key path. A classical assumption that no
party knows an internal private key does not remove the exposed output key.
Adding PQ requirements to one branch does not constrain another accepted
branch. This follows from the current [key-path dispatch][interpreter] and
the [BIP341 authorization rules][bip341].

A hybrid condition can require both classical and PQ authorization.
A classical-or-PQ condition leaves a classical-only route.
Recovery branches need the same review. This assessment recommends no
classical-only fallback for outputs described as PQ protected.

Keep signature encoding, transaction commitments, algorithm identifiers, and
verification cost in the consensus owner. Reuse existing transaction and
prevout representations. Do not add another UTXO authority.

### Current proposal status

[BIP360][bip360] is **Draft**, version **0.12.1**, titled
**Pay-to-Merkle-Root (P2MR)**. It proposes witness version 2 and removes the
Taproot key path. It does not define PQ signatures.
Its current depth-zero tree rule succeeds without script authorization.
A prototype must preserve that distinction and must not present that case as
a protected single-leaf wallet construction.

[BIP361][bip361] is **Draft** and **Informational**.
It depends on a still unspecified PQ signature BIP.
It proposes restrictions on new vulnerable destinations, followed by tighter
legacy-spend conditions with a rescue protocol.
The proposed timing is about three years for Phase A and two additional years
for Phase B. Neither timing is an activated Bitcoin schedule.
Rescue coverage remains an open research question.

Treat these documents as separate inputs: an output commitment and a migration
policy. Neither supplies a complete, deployed PQ signature system.

## Work required in Bitcoin-RS

### Consensus and resource rules

Specify the accepted public-key and signature encodings, exact algorithm
parameters, signature-message format, and failure results.
Bind authorization to the transaction and the relevant spent-output facts.
Define domain separation and the selected signature interface explicitly.
A library default must not decide consensus behavior.

Set bounds for witness bytes, element counts, decoding work, and verification
work. Charge the PQ operation according to measured costs.
The present [tapscript budget][eval] does not establish the cost of a different
signature algorithm.

Use borrowed input bytes where the representation permits them.
Validate lengths before allocation or cryptographic work.
Use typed errors at the parser and verifier boundary.
Reuse the transaction preparation owner and its immutable prevouts.

### Activation and every validation entry point

The existing `SoftforkState` contains CSV and SegWit fields only.
The deployment list is not a general PQ configuration interface.
An experiment needs a rule state derived from the candidate branch.
That state must reach block connection, transaction admission, mining
templates, and deployment reporting.

Reorganizations must recompute or retrieve state for the candidate ancestry.
The existing [deployment cache][deployment] uses branch anchors.
Preserve that property when adding a deployment.
Never use the active tip's state to validate an unrelated side branch.

Review script-execution cache keys when adding a rule flag.
The [validation contract][validation] keys reusable script outcomes by witness
transaction identity and verification flags.
An outcome checked under weaker rules must not stand for a stronger check.

The first experiment should support native validation only.
Reject unsupported engine and network combinations at startup.
Do not silently route an enabled PQ experiment through an unchanged kernel.
A later kernel configuration needs the same additional enforcement or an
updated kernel implementation. The existing kernel remains an oracle for old
Bitcoin validity, not for a PQ rule it does not implement.

### Relay, mining, and external wallets

The [standardness owner][standardness] rejects unknown witness programs and
limits ordinary tapscript arguments. Mempool support therefore needs a
separate change from block consensus.
Mining templates must use the same active consensus rules and the intended
relay policy.

External wallets need output encoding, PQ key management, signing, recovery,
and transaction construction. Descriptor and PSBT support require explicit
formats and interoperability evidence. The existing [wallet boundary][wallet]
remains authoritative; the node should not acquire wallet secrets.

Ordinary migration spends an old output under its existing authorization and
creates a protected new output. A new address format cannot retroactively
attach a PQ key to an old UTXO.

### Synchronization and durable state

The documentation change has no synchronization impact. It changes no
validation, transition, or commit path.
A future implementation would affect [synchronization obligations][sync],
particularly `SYNC-03`, `SYNC-04`, `SYNC-05`, and `SYNC-07`.

Verification work must remain bounded. Invalid inputs must not publish state.
Restart, replay, reorganization, and historical validation must apply the
correct rules. AssumeValid and AssumeUTXO need an explicit review under the
experimental rule schedule. They must not silently certify an incompatible
experimental history.

Use a separate data directory and an explicit experiment identity.
Refuse incompatible rule settings on reopen unless the documented rebuild or
replay path is used. Reuse block, undo, and UTXO owners.
Introduce no new durable representation unless the experiment requires one.

## Size evidence and its limits

These standardized parameter sets illustrate the bandwidth problem.
They are not a selection of the production Bitcoin signature scheme.
Their security categories differ, so the table is not an equal-security
performance comparison.

| Parameter set | NIST category | Public key | Signature | Key plus signature |
| --- | ---: | ---: | ---: | ---: |
| ML-DSA-44 | 2 | 1,312 bytes | 2,420 bytes | 3,732 bytes |
| SLH-DSA-SHA2-128s | 1 | 32 bytes | 7,856 bytes | 7,888 bytes |

Sources: [FIPS 204, Tables 1 and 2][fips204] and
[FIPS 205, Table 2][fips205]. ML-KEM is a key-encapsulation mechanism; it is
not a transaction signature scheme. [NIST's PQ standards list][nist-pqc]
separates these functions.

Assume that each spend reveals one full public key and one signature in its
witness, with no aggregation or compression. Under existing witness weight,
these bytes alone contribute 3,732 WU or 7,888 WU.
Those contributions equal 933 or 1,972 virtual bytes before other transaction
and proof data.

Dividing 4,000,000 by those contributions gives absolute payload-only ceilings
of 1,071 and 507 spends per block. Actual capacity is lower because blocks
also contain base transaction data, witness framing, proofs, and coinbase
data. These figures are arithmetic bounds, not throughput measurements.
The experiment must measure validation time, memory, relay behavior, and full
block costs before it selects operational limits.

## What can be mandatory

The classifications below follow from the validity-set test above.
They are design conclusions, not claims of implemented migration rules.

| Intended requirement | Feasibility | Limit |
| --- | --- | --- |
| Require PQ authorization for a newly defined output | Soft fork is possible | Older nodes do not independently check the new proof. |
| Disallow specified vulnerable new outputs after a height | Soft fork is possible | The rule needs an exact output definition, including change and coinbase treatment. |
| Restrict legacy spends after a deadline | Soft fork is possible | Every permitted spend must still satisfy the old rules. Owners can lose access. |
| Make Bitcoin-RS enforce a future schedule | Implementable for adopting clients | Operators can choose another release or another rule set. |
| Make an unchanged node accept a block its rules reject | Not possible through a soft fork | Its validation rules must change. |
| Guarantee adoption of a later hard fork | Not possible from repository code | Adoption and a possible chain split remain external coordination questions. |

[BIP9][bip9] supplies activation inputs to software that implements the new
rules. Miner signaling does not update other software.
The [Bitcoin developer guide][fork-guide] selects the chain with the most work
from chains that pass local validity checks.
More work does not make an invalid block valid.

An isolated stricter node also needs a source of blocks that satisfy its rules.
Without such blocks, it can stop advancing.
Local enforcement alone does not establish a viable network fork.

### A scheduled hard fork

A release can contain a soft-fork rule for one height and incompatible rules
for a later height. Installing that release adopts both schedules.
Nodes that never install it retain their old rules.
The first upgrade cannot provide their consent to the second.

If the later change only constrains an extension point that old nodes already
accept, it can remain another soft fork. Its label does not determine the
classification; accepted blocks do.

An expiration rule can pressure operators to replace software.
It cannot select their replacement rules or guarantee continued chain
progress. Operators can reject the expiration, change it, or stop.
This is why a deliberate halt is rejected as the migration design.

### Freeze first, recovery later

An unconditional freeze removes spends from the accepted set.
Allowing one of those spends later is a relaxation relative to clients that
enforce the freeze. That change is a hard fork relative to those clients,
even if pre-freeze clients would accept the spend.

An exit already encoded in the original rules has a different result.
Using that exit does not violate those rules.
A note promising future recovery does not encode such an exit.
Compare every proposed stage against all relevant deployed rule sets.

A rescue that preserves soft-fork compatibility with a legacy output must
retain the authorization that old nodes require and add restrictions.
Replacing a required ECDSA signature with an unrelated PQ signature alone
does not meet that condition.

After compromise of a key assumption, possession of the same recovered key
does not distinguish the original owner from another holder.
Recovery needs additional evidence, such as an earlier commitment or a
different secret that remains protected.
A hard fork alone does not supply that evidence.
Do not promise universal recovery of dormant or lost outputs.
The existing [P2PK research issue][p2pk-issue] also separates exposure from
proof of theft.

## Evidence required before an experimental implementation claim

Start with the existing evidence owners:

- [Taproot spend rules][taproot-tests] cover complete spends, activation,
  wrapped witness behavior, and `OP_SUCCESS` ordering.
- [BIP9 tests][bip9-code] cover activation windows and candidate signaling.
- [Deployment tests][deployment] cover history and branch-specific signaling.
- [Standardness tests][standardness-tests] reject undefined witness inputs.

A PQ experiment must add independent evidence for the new behavior.
The required results are:

1. Pinned cryptographic vectors and an independent verifier agree on accepted
   and rejected encodings and signatures.
2. A block accepted under the experimental rules also passes the old Bitcoin
   rules in an unmodified reference implementation.
3. Activation boundaries and reorganizations select the correct rule state.
   Inactive operation retains existing Bitcoin behavior.
4. Supported validation engines enforce the same rule. Unsupported experiment
   combinations fail before the node opens normal operation.
5. A valid experimental spend passes the intended wallet, admission, mining,
   block-validation, and restart path on an isolated network.
6. Measured full-block costs support explicit CPU, memory, and byte bounds.
   Measurements identify hardware, build profile, and algorithm parameters.
7. Any legacy restriction has a separate compatibility matrix for owners,
   recovery eligibility, and clients from each migration stage.

No result in this list is established by this source review.
The next implementation milestone is the isolated commitment and verifier
experiment. Legacy sunsets and any hard fork require their own decisions.

[baseline]: https://github.com/gosuda/bitcoin-rs/tree/60b33f6be7c55eb27e6892cdb7770687a8e40276
[bips-snapshot]: https://github.com/bitcoin/bips/tree/b34d9f751791d4feb22feff4f2ed00bcac83961b
[interpreter]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/consensus/src/script/interpreter.rs
[eval]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/consensus/src/script/eval.rs
[checker]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/consensus/src/script/checker.rs
[bip9-code]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/consensus/src/bip9.rs
[deployment]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/execution/src/chain/deployment.rs
[standardness]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/mempool/src/standardness.rs
[kernel]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/consensus/src/kernel.rs
[wallet]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/docs/contracts/wallet-facing.md
[adoption]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/docs/policies/bip-adoption.md
[validation]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/docs/contracts/validation-default.md
[verify-block]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/consensus/src/verify_block.rs
[sync]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/docs/contracts/synchronization.md
[taproot-tests]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/consensus/tests/script_taproot_spend_rules.rs
[standardness-tests]: https://github.com/gosuda/bitcoin-rs/blob/60b33f6be7c55eb27e6892cdb7770687a8e40276/crates/mempool/tests/standardness_spend.rs
[p2pk-issue]: https://github.com/gosuda/bitcoin-rs/issues/1625
[bip141]: https://github.com/bitcoin/bips/blob/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0141.mediawiki
[bip341]: https://github.com/bitcoin/bips/blob/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0341.mediawiki
[bip342]: https://github.com/bitcoin/bips/blob/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0342.mediawiki
[bip360]: https://github.com/bitcoin/bips/blob/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0360.mediawiki
[bip361]: https://github.com/bitcoin/bips/blob/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0361.mediawiki
[bip9]: https://github.com/bitcoin/bips/blob/b34d9f751791d4feb22feff4f2ed00bcac83961b/bip-0009.mediawiki
[fork-guide]: https://developer.bitcoin.org/devguide/block_chain.html#consensus-rule-changes
[fips204]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
[fips205]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
[nist-pqc]: https://csrc.nist.gov/projects/post-quantum-cryptography
