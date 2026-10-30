---------------------------- MODULE Mining ----------------------------
(***************************************************************************)
(* Mining sub-machine of the projection and mining model.                  *)
(*                                                                         *)
(* Owned state: the active template generation, the pending-share count    *)
(* and the terminal flag. The projection sub-machine supplies committed    *)
(* rows as an environment input; this machine owns no projection state.    *)
(* Tip generation is an environment input fixed at `TipGen`.               *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
  \* @type: Int;
  TipGen,
  \* @type: Int;
  ShareCap

VARIABLES
  \* @type: Int;
  activeGen,
  \* @type: Int;
  pendingShares,
  \* @type: Bool;
  done

vars == << activeGen, pendingShares, done >>

Init ==
  /\ activeGen = 0
  /\ pendingShares = 0
  /\ done = FALSE

Advance ==
  /\ activeGen < TipGen
  /\ activeGen' = activeGen + 1
  /\ pendingShares' = 0
  /\ UNCHANGED << done >>

Accept ==
  /\ activeGen = TipGen
  /\ pendingShares < ShareCap
  /\ pendingShares' = pendingShares + 1
  /\ UNCHANGED << activeGen, done >>

Drain ==
  /\ pendingShares > 0
  /\ pendingShares' = pendingShares - 1
  /\ UNCHANGED << activeGen, done >>

Finish ==
  /\ ~done
  /\ activeGen = TipGen
  /\ done' = TRUE
  /\ pendingShares' = 0
  /\ UNCHANGED << activeGen >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ Advance
  \/ Accept
  \/ Drain
  \/ Finish
  \/ Stutter

TypeOK ==
  /\ activeGen \in 0..TipGen
  /\ pendingShares \in 0..ShareCap
  /\ done \in BOOLEAN

EnAdvance == activeGen < TipGen
EnDrain == pendingShares > 0
EnFinish == ~done /\ activeGen = TipGen

FairAdvance == ((<>[] EnAdvance) => ([]<> <<Advance>>_vars))
FairDrain == ((<>[] EnDrain) => ([]<> <<Drain>>_vars))
FairFinish == ((<>[] EnFinish) => ([]<> <<Finish>>_vars))

ConditionalProgress ==
  (FairAdvance /\ FairDrain /\ FairFinish)
  =>
  (<> done)

=============================================================================
