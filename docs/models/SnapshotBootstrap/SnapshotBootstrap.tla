\* SNP-01, SNP-02, SNP-03, SNP-04, SNP-05, SNP-06, SNP-07, SNP-08, SNP-09, SNP-10, SNP-11
------------------------- MODULE SnapshotBootstrap -------------------------
(***************************************************************************)
(* SnapshotBootstrap formal lifecycle and invariant safety model.          *)
(*                                                                         *)
(* Models SnapshotManifest artifact commitments, single-pass streaming of *)
(* coin store and ScriptLive base into an unpublished keyspace (SNP-06),  *)
(* publication gating on UTXO verification (SNP-07), index generation     *)
(* attachment only on verified commitment (SNP-05), index failure          *)
(* isolation vs assumed chainstate closure (SNP-10), three independent     *)
(* reported positions (SNP-09), and explicit historical body availability  *)
(* separated from index locators (SNP-08, SNP-11).                         *)
(*                                                                         *)
(* Design model only: specifies the state machine and invariant safety.    *)
(* Not an implementation refinement proof or physical durability proof.    *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
  \* @type: Bool;
  HasHistoricalBodies,
  \* @type: Int;
  BaseHeight,
  \* @type: Int;
  MaxHeight

VARIABLES
  \* @type: Str;
  bootstrapPhase,
  \* @type: Bool;
  unpublishedStreamed,
  \* @type: Bool;
  coinsPublished,
  \* @type: Bool;
  scriptLivePublished,
  \* @type: Bool;
  utxoVerified,
  \* @type: Bool;
  indexVerified,
  \* @type: Bool;
  indexAttached,
  \* @type: Bool;
  indexInvalidated,
  \* @type: Bool;
  chainstateClosed,
  \* @type: Bool;
  unpublishedDiscarded,
  \* @type: Int;
  activeTipHeight,
  \* @type: Int;
  historicalValHeight,
  \* @type: Int;
  projectionCoverage,
  \* @type: Int;
  bodyQueryHeight,
  \* @type: Str;
  bodyQueryResult

vars == << bootstrapPhase, unpublishedStreamed, coinsPublished, scriptLivePublished,
           utxoVerified, indexVerified, indexAttached, indexInvalidated,
           chainstateClosed, unpublishedDiscarded, activeTipHeight,
           historicalValHeight, projectionCoverage, bodyQueryHeight, bodyQueryResult >>

HeightDom == 0..MaxHeight

TypeOK ==
  /\ bootstrapPhase \in {"Init", "Streaming", "Verifying", "Ready", "Failed"}
  /\ unpublishedStreamed \in BOOLEAN
  /\ coinsPublished \in BOOLEAN
  /\ scriptLivePublished \in BOOLEAN
  /\ utxoVerified \in BOOLEAN
  /\ indexVerified \in BOOLEAN
  /\ indexAttached \in BOOLEAN
  /\ indexInvalidated \in BOOLEAN
  /\ chainstateClosed \in BOOLEAN
  /\ unpublishedDiscarded \in BOOLEAN
  /\ activeTipHeight \in HeightDom
  /\ historicalValHeight \in 0..BaseHeight
  /\ projectionCoverage \in HeightDom
  /\ bodyQueryHeight \in HeightDom
  /\ bodyQueryResult \in {"None", "BodyFound", "BodyUnavailable"}

Init ==
  /\ bootstrapPhase = "Init"
  /\ unpublishedStreamed = FALSE
  /\ coinsPublished = FALSE
  /\ scriptLivePublished = FALSE
  /\ utxoVerified = FALSE
  /\ indexVerified = FALSE
  /\ indexAttached = FALSE
  /\ indexInvalidated = FALSE
  /\ chainstateClosed = FALSE
  /\ unpublishedDiscarded = FALSE
  /\ activeTipHeight = 0
  /\ historicalValHeight = 0
  /\ projectionCoverage = 0
  /\ bodyQueryHeight = 0
  /\ bodyQueryResult = "None"

\* SNP-06: Streaming snapshot decode streams coin store AND ScriptLive base
\* together into an unpublished keyspace in a single pass.
StreamSnapshot ==
  /\ bootstrapPhase = "Init"
  /\ unpublishedStreamed' = TRUE
  /\ coinsPublished' = FALSE
  /\ scriptLivePublished' = FALSE
  /\ bootstrapPhase' = "Streaming"
  /\ UNCHANGED << utxoVerified, indexVerified, indexAttached, indexInvalidated,
                  chainstateClosed, unpublishedDiscarded, activeTipHeight,
                  historicalValHeight, projectionCoverage, bodyQueryHeight, bodyQueryResult >>

\* Verify commitments against compiled trust anchors (SNP-01, SNP-04).
\* Nondeterministically branches on whether UTXO and Index commitments match.
VerifyCommitments ==
  /\ bootstrapPhase = "Streaming"
  /\ \E utxoOk \in BOOLEAN, indexOk \in BOOLEAN :
        /\ utxoVerified' = utxoOk
        /\ indexVerified' = indexOk
  /\ bootstrapPhase' = "Verifying"
  /\ UNCHANGED << unpublishedStreamed, coinsPublished, scriptLivePublished,
                  indexAttached, indexInvalidated, chainstateClosed,
                  unpublishedDiscarded, activeTipHeight, historicalValHeight,
                  projectionCoverage, bodyQueryHeight, bodyQueryResult >>

\* SNP-07: Publication ONLY after UTXO commitment is verified.
\* SNP-05: Verified index artifact attached directly as Phase 5 generation.
\* SNP-10: Failed index commitment invalidates index capability only; chainstate remains open.
PublishValidSnapshot ==
  /\ bootstrapPhase = "Verifying"
  /\ utxoVerified = TRUE
  /\ coinsPublished' = TRUE
  /\ scriptLivePublished' = TRUE
  /\ IF indexVerified
     THEN /\ indexAttached' = TRUE
          /\ indexInvalidated' = FALSE
          /\ projectionCoverage' = BaseHeight
     ELSE /\ indexAttached' = FALSE
          /\ indexInvalidated' = TRUE
          /\ projectionCoverage' = 0
  /\ activeTipHeight' = BaseHeight
  /\ bootstrapPhase' = "Ready"
  /\ UNCHANGED << unpublishedStreamed, utxoVerified, indexVerified,
                  chainstateClosed, unpublishedDiscarded, historicalValHeight,
                  bodyQueryHeight, bodyQueryResult >>

\* SNP-07, SNP-10: On invalid UTXO commitment, discard unpublished data and close chainstate.
RejectInvalidUtxo ==
  /\ bootstrapPhase = "Verifying"
  /\ utxoVerified = FALSE
  /\ unpublishedDiscarded' = TRUE
  /\ chainstateClosed' = TRUE
  /\ coinsPublished' = FALSE
  /\ scriptLivePublished' = FALSE
  /\ indexAttached' = FALSE
  /\ indexInvalidated' = FALSE
  /\ bootstrapPhase' = "Failed"
  /\ UNCHANGED << unpublishedStreamed, utxoVerified, indexVerified,
                  activeTipHeight, historicalValHeight, projectionCoverage,
                  bodyQueryHeight, bodyQueryResult >>

\* Position 1 advances: Active-chain application progresses above base (SNP-09).
AdvanceActiveChain ==
  /\ bootstrapPhase = "Ready"
  /\ ~chainstateClosed
  /\ activeTipHeight < MaxHeight
  /\ activeTipHeight' = activeTipHeight + 1
  /\ UNCHANGED << bootstrapPhase, unpublishedStreamed, coinsPublished,
                  scriptLivePublished, utxoVerified, indexVerified,
                  indexAttached, indexInvalidated, chainstateClosed,
                  unpublishedDiscarded, historicalValHeight, projectionCoverage,
                  bodyQueryHeight, bodyQueryResult >>

\* Position 2 advances: Background historical validation progresses from genesis to base (SNP-08, SNP-09).
AdvanceHistoricalValidation ==
  /\ bootstrapPhase = "Ready"
  /\ historicalValHeight < BaseHeight
  /\ historicalValHeight' = historicalValHeight + 1
  /\ UNCHANGED << bootstrapPhase, unpublishedStreamed, coinsPublished,
                  scriptLivePublished, utxoVerified, indexVerified,
                  indexAttached, indexInvalidated, chainstateClosed,
                  unpublishedDiscarded, activeTipHeight, projectionCoverage,
                  bodyQueryHeight, bodyQueryResult >>

\* Position 3 advances: Projection coverage progresses independently (SNP-09).
AdvanceProjectionCoverage ==
  /\ bootstrapPhase = "Ready"
  /\ indexAttached
  /\ projectionCoverage < activeTipHeight
  /\ projectionCoverage' = projectionCoverage + 1
  /\ UNCHANGED << bootstrapPhase, unpublishedStreamed, coinsPublished,
                  scriptLivePublished, utxoVerified, indexVerified,
                  indexAttached, indexInvalidated, chainstateClosed,
                  unpublishedDiscarded, activeTipHeight, historicalValHeight,
                  bodyQueryHeight, bodyQueryResult >>

\* SNP-11: Query historical body. Trusted index locator does not imply raw body is on disk.
QueryHistoricalBody(h) ==
  /\ bootstrapPhase = "Ready"
  /\ bodyQueryHeight' = h
  /\ IF h <= BaseHeight
     THEN IF HasHistoricalBodies
          THEN bodyQueryResult' = "BodyFound"
          ELSE bodyQueryResult' = "BodyUnavailable"
     ELSE bodyQueryResult' = "BodyFound"
  /\ UNCHANGED << bootstrapPhase, unpublishedStreamed, coinsPublished,
                  scriptLivePublished, utxoVerified, indexVerified,
                  indexAttached, indexInvalidated, chainstateClosed,
                  unpublishedDiscarded, activeTipHeight, historicalValHeight,
                  projectionCoverage >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ StreamSnapshot
  \/ VerifyCommitments
  \/ PublishValidSnapshot
  \/ RejectInvalidUtxo
  \/ AdvanceActiveChain
  \/ AdvanceHistoricalValidation
  \/ AdvanceProjectionCoverage
  \/ \E h \in HeightDom : QueryHistoricalBody(h)
  \/ Stutter

\* Safety Invariants

\* SNP-07: Neither coins nor ScriptLive can be published without verified UTXO commitment
SafetyPublicationRequiresUtxoVerification ==
  /\ (coinsPublished \/ scriptLivePublished) => utxoVerified

\* SNP-07, SNP-10: An invalid UTXO commitment never publishes data
SafetyInvalidUtxoNeverPublished ==
  /\ (~utxoVerified /\ bootstrapPhase \in {"Verifying", "Failed"}) =>
       (~coinsPublished /\ ~scriptLivePublished)

\* SNP-05, SNP-04: Index generations attach only if index commitment is verified
SafetyIndexAttachRequiresVerification ==
  /\ indexAttached => indexVerified

\* SNP-10: Failed index commitment is isolated: invalidates projection only, chainstate remains open
SafetyIndexFailureIsolated ==
  /\ (utxoVerified /\ ~indexVerified /\ bootstrapPhase = "Ready") =>
       (~chainstateClosed /\ indexInvalidated /\ ~indexAttached)

\* SNP-10: Failed UTXO assumption closes the affected chainstate
SafetyInvalidUtxoClosesChainstate ==
  /\ (bootstrapPhase = "Failed") => chainstateClosed

\* SNP-11: Snapshot index locator does not imply raw transaction body when bodies are not retained
SafetyHistoricalBodyExplicit ==
  /\ (~HasHistoricalBodies /\ bodyQueryHeight <= BaseHeight /\ bodyQueryResult # "None") =>
       bodyQueryResult = "BodyUnavailable"

\* SNP-09: Three positions exist and are bounded independently
SafetyThreePositionsBounded ==
  /\ activeTipHeight \in HeightDom
  /\ historicalValHeight \in 0..BaseHeight
  /\ projectionCoverage \in HeightDom

Safety ==
  /\ SafetyPublicationRequiresUtxoVerification
  /\ SafetyInvalidUtxoNeverPublished
  /\ SafetyIndexAttachRequiresVerification
  /\ SafetyIndexFailureIsolated
  /\ SafetyInvalidUtxoClosesChainstate
  /\ SafetyHistoricalBodyExplicit
  /\ SafetyThreePositionsBounded

ConditionalProgress ==
  [][bootstrapPhase = "Failed" => bootstrapPhase' = "Failed"]_vars

=============================================================================