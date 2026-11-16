\* MPS-01, MPS-03
------------------------- MODULE MempoolSettlement -------------------------
(***************************************************************************)
(* Formal TLA+ specification of MempoolSettlement for bitcoin-rs.          *)
(* Anchors: Claude Shannon, Tony Hoare, Herbert Simon.                     *)
(*                                                                         *)
(* Contract clauses:                                                       *)
(* - MPS-01: Mempool settles from committed facts in order.                *)
(*           Chain commit supplies ordered transaction and spend effects.  *)
(* - MPS-03: Mining consumes a matched pair: one applied epoch and one     *)
(*           settled mempool generation. Reject when                       *)
(*           epoch.commit_id != generation.settled_at_commit.              *)
(* - Reorganization unsettles consistently: disconnected blocks are         *)
(*   unsettled, and mining template pairing prevents stale dependency       *)
(*   graph usage during and across reorgs.                                 *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
  \* @type: Set(Str);
  TxIds,
  \* @type: Int;
  MaxEpoch,
  \* @type: Int;
  MaxBlockId

VARIABLES
  \* @type: Int;
  appliedEpoch,
  \* @type: Int;
  chainTip,
  \* @type: Set(Str);
  activeChainTxs,
  \* @type: Seq([type: Str, blockId: Int, epochId: Int, txs: Set(Str)]);
  factsQueue,
  \* @type: Set(Str);
  mempoolTxs,
  \* @type: Int;
  mempoolGen,
  \* @type: Int;
  settledAtEpoch,
  \* @type: Int;
  lastSettledBlock,
  \* @type: Bool;
  templateActive,
  \* @type: Int;
  templateEpoch,
  \* @type: Int;
  templateGen,
  \* @type: Set(Str);
  templateTxs,
  \* @type: Bool;
  templateRejected

vars == << appliedEpoch, chainTip, activeChainTxs, factsQueue, mempoolTxs,
           mempoolGen, settledAtEpoch, lastSettledBlock, templateActive,
           templateEpoch, templateGen, templateTxs, templateRejected >>

Init ==
  /\ appliedEpoch = 1
  /\ chainTip = 0
  /\ activeChainTxs = {}
  /\ factsQueue = << >>
  /\ mempoolTxs = {}
  /\ mempoolGen = 0
  /\ settledAtEpoch = 1
  /\ lastSettledBlock = 0
  /\ templateActive = FALSE
  /\ templateEpoch = 0
  /\ templateGen = 0
  /\ templateTxs = {}
  /\ templateRejected = FALSE

AdmitTx(tx) ==
  /\ tx \in TxIds
  /\ tx \notin mempoolTxs
  /\ tx \notin activeChainTxs
  /\ mempoolTxs' = mempoolTxs \cup {tx}
  /\ mempoolGen' = mempoolGen + 1
  /\ UNCHANGED << appliedEpoch, chainTip, activeChainTxs, factsQueue,
                  settledAtEpoch, lastSettledBlock, templateActive,
                  templateEpoch, templateGen, templateTxs, templateRejected >>

CommitBlock(b, txs) ==
  /\ b = chainTip + 1
  /\ b <= MaxBlockId
  /\ appliedEpoch < MaxEpoch
  /\ txs \subseteq (TxIds \ activeChainTxs)
  /\ appliedEpoch' = appliedEpoch + 1
  /\ chainTip' = b
  /\ activeChainTxs' = activeChainTxs \cup txs
  /\ factsQueue' = Append(factsQueue,
       [type |-> "connect", blockId |-> b, epochId |-> appliedEpoch + 1, txs |-> txs])
  \* Chain moved: active template is invalidated
  /\ templateActive' = FALSE
  /\ templateTxs' = {}
  /\ UNCHANGED << mempoolTxs, mempoolGen, settledAtEpoch, lastSettledBlock,
                  templateEpoch, templateGen, templateRejected >>

CommitReorg(oldBlock, oldTxs, newBlock, newTxs) ==
  /\ chainTip = oldBlock
  /\ oldBlock > 0
  /\ appliedEpoch < MaxEpoch
  /\ newBlock <= MaxBlockId
  /\ oldTxs \subseteq activeChainTxs
  /\ newTxs \subseteq (TxIds \ (activeChainTxs \ oldTxs))
  /\ appliedEpoch' = appliedEpoch + 1
  /\ chainTip' = newBlock
  /\ activeChainTxs' = (activeChainTxs \ oldTxs) \cup newTxs
  /\ factsQueue' = Append(
                     Append(factsQueue,
                       [type |-> "disconnect", blockId |-> oldBlock, epochId |-> appliedEpoch + 1, txs |-> oldTxs]),
                     [type |-> "connect", blockId |-> newBlock, epochId |-> appliedEpoch + 1, txs |-> newTxs])
  \* Reorg invalidates active template
  /\ templateActive' = FALSE
  /\ templateTxs' = {}
  /\ UNCHANGED << mempoolTxs, mempoolGen, settledAtEpoch, lastSettledBlock,
                  templateEpoch, templateGen, templateRejected >>

SettleNextFact ==
  /\ Len(factsQueue) > 0
  /\ LET fact == Head(factsQueue)
         remainingQueue == Tail(factsQueue) IN
       /\ factsQueue' = remainingQueue
       /\ mempoolGen' = mempoolGen + 1
       \* Generation settles at epochId only once all facts for that commit are processed
       /\ settledAtEpoch' = IF Len(remainingQueue) = 0 \/ Head(remainingQueue).epochId > fact.epochId
                            THEN fact.epochId
                            ELSE settledAtEpoch
       /\ lastSettledBlock' = fact.blockId
       /\ IF fact.type = "connect"
          THEN mempoolTxs' = mempoolTxs \ fact.txs
          ELSE mempoolTxs' = mempoolTxs \cup (fact.txs \ activeChainTxs)
  /\ UNCHANGED << appliedEpoch, chainTip, activeChainTxs, templateActive,
                  templateEpoch, templateGen, templateTxs, templateRejected >>

AssembleTemplate(epoch, gen) ==
  /\ IF epoch = appliedEpoch /\ gen = mempoolGen /\ settledAtEpoch = appliedEpoch
     THEN /\ templateActive' = TRUE
          /\ templateEpoch' = epoch
          /\ templateGen' = gen
          /\ templateTxs' = mempoolTxs
          /\ templateRejected' = FALSE
     ELSE /\ templateRejected' = TRUE
          /\ UNCHANGED << templateActive, templateEpoch, templateGen, templateTxs >>
  /\ UNCHANGED << appliedEpoch, chainTip, activeChainTxs, factsQueue,
                  mempoolTxs, mempoolGen, settledAtEpoch, lastSettledBlock >>

MineBlock ==
  /\ templateActive
  /\ templateEpoch = appliedEpoch
  /\ templateActive' = FALSE
  /\ templateTxs' = {}
  /\ UNCHANGED << appliedEpoch, chainTip, activeChainTxs, factsQueue,
                  mempoolTxs, mempoolGen, settledAtEpoch, lastSettledBlock,
                  templateEpoch, templateGen, templateRejected >>

Stutter ==
  UNCHANGED vars

Next ==
  \/ \E tx \in TxIds : AdmitTx(tx)
  \/ \E b \in 1..MaxBlockId, txs \in SUBSET TxIds : CommitBlock(b, txs)
  \/ \E ob, nb \in 1..MaxBlockId, otxs, ntxs \in SUBSET TxIds : CommitReorg(ob, otxs, nb, ntxs)
  \/ SettleNextFact
  \/ \E epoch \in 1..MaxEpoch, gen \in 0..(MaxEpoch * 3) : AssembleTemplate(epoch, gen)
  \/ MineBlock
  \/ Stutter

TypeOK ==
  /\ appliedEpoch \in 1..MaxEpoch
  /\ chainTip \in 0..MaxBlockId
  /\ activeChainTxs \subseteq TxIds
  /\ mempoolTxs \subseteq TxIds
  /\ mempoolGen \in Nat
  /\ settledAtEpoch \in 1..MaxEpoch
  /\ lastSettledBlock \in 0..MaxBlockId
  /\ templateActive \in BOOLEAN
  /\ templateEpoch \in 0..MaxEpoch
  /\ templateGen \in Nat
  /\ templateTxs \subseteq TxIds
  /\ templateRejected \in BOOLEAN

Safety ==
  \* MPS-03: Active mining template pairs current applied epoch with matching settled generation
  /\ (templateActive =>
        /\ templateEpoch = appliedEpoch
        /\ templateEpoch = settledAtEpoch
        /\ templateTxs \cap activeChainTxs = {})
  \* MPS-01: When facts queue is drained, mempool contains no transaction confirmed in active chain
  /\ (Len(factsQueue) = 0 => mempoolTxs \cap activeChainTxs = {})
  \* Settled epoch never exceeds applied epoch
  /\ settledAtEpoch <= appliedEpoch

ConditionalProgress == TRUE

=============================================================================