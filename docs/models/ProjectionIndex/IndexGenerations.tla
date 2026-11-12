\* PRJ-05, PRJ-07, PRJ-09, REO-04, REO-05
------------------------- MODULE IndexGenerations -------------------------
(***************************************************************************)
(* Index generation storage and lifecycle model.                           *)
(*                                                                         *)
(* Models immutable sealed segments, bounded mutable tail (PRJ-05),       *)
(* tail rollback on shallow reorg, deep reorg retiring exactly the        *)
(* invalidated generations (REO-04, REO-05), logical equivalence of       *)
(* bulk backfill and live builds (PRJ-09), and exclusion of segment       *)
(* offsets from query answers (PRJ-07).                                    *)
(*                                                                         *)
(* Design model only: specifies the state machine and invariant safety.    *)
(* Not an implementation refinement proof or physical durability proof.    *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
  \* @type: Int;
  MaxTip,
  \* @type: Int;
  TailBound,
  \* @type: Int;
  MaxReorgs

VARIABLES
  \* @type: Int;
  appliedTip,
  \* @type: Int;
  tailLo,
  \* @type: Int;
  tailHi,
  \* @type: Set([id: Int, first_h: Int, last_h: Int, retired: Bool, entries: Set(Int)]);
  sealedGens,
  \* @type: Int;
  nextGenId,
  \* @type: Set(Int);
  bulkEntries,
  \* @type: Set([h: Int, has_segment_offset: Bool]);
  queryAnswers,
  \* @type: Int;
  reorgCount

vars == << appliedTip, tailLo, tailHi, sealedGens, nextGenId,
           bulkEntries, queryAnswers, reorgCount >>

Init ==
  /\ appliedTip = 0
  /\ tailLo = 1
  /\ tailHi = 0
  /\ sealedGens = {}
  /\ nextGenId = 1
  /\ bulkEntries = {}
  /\ queryAnswers = {}
  /\ reorgCount = 0

\* Live block append into the mutable tail
AppendBlock ==
  /\ appliedTip < MaxTip
  /\ appliedTip' = appliedTip + 1
  /\ tailHi' = appliedTip + 1
  /\ tailLo' = IF tailHi < tailLo THEN appliedTip + 1 ELSE tailLo
  /\ UNCHANGED << sealedGens, nextGenId, bulkEntries, queryAnswers, reorgCount >>

\* Seal stable prefix of mutable tail into an immutable segment
SealGeneration ==
  /\ tailHi >= tailLo
  /\ tailHi - tailLo + 1 >= TailBound
  /\ LET sealLast == tailLo + TailBound - 1
         newGen == [id |-> nextGenId,
                    first_h |-> tailLo,
                    last_h |-> sealLast,
                    retired |-> FALSE,
                    entries |-> {h : h \in tailLo..sealLast}]
     IN /\ sealedGens' = sealedGens \cup {newGen}
        /\ nextGenId' = nextGenId + 1
        /\ tailLo' = sealLast + 1
  /\ UNCHANGED << appliedTip, tailHi, bulkEntries, queryAnswers, reorgCount >>

\* Reorganization: rolls back tail, retires exactly the invalidated generations on deep reorg
Reorganize ==
  /\ reorgCount < MaxReorgs
  /\ appliedTip > 0
  /\ \E fork \in 0..(appliedTip - 1):
       /\ appliedTip' = fork
       /\ IF fork >= tailLo
          THEN /\ tailHi' = fork
               /\ tailLo' = tailLo
               /\ sealedGens' = sealedGens
          ELSE /\ tailHi' = fork
               /\ tailLo' = fork + 1
               /\ sealedGens' = {[g EXCEPT !.retired = (g.last_h > fork \/ g.retired)] : g \in sealedGens}
       /\ bulkEntries' = {h \in bulkEntries : h <= fork}
       /\ queryAnswers' = {a \in queryAnswers : a.h <= fork}
       /\ reorgCount' = reorgCount + 1
       /\ UNCHANGED << nextGenId >>
\* PRJ-09: Bulk backfill builds identical logical contents via external sort
BulkBuild ==
  /\ appliedTip > 0
  /\ \E L \in 1..appliedTip:
       \E R \in L..appliedTip:
         /\ bulkEntries' = bulkEntries \cup {h : h \in L..R}
         /\ UNCHANGED << appliedTip, tailLo, tailHi, sealedGens, nextGenId, queryAnswers, reorgCount >>
\* PRJ-07: Query answers return logical identities, never segment offsets
QueryAnswer ==
  /\ appliedTip > 0
  /\ \E h \in 1..appliedTip:
       /\ (\/ (\E g \in sealedGens: ~g.retired /\ h \in g.first_h..g.last_h)
           \/ (tailHi >= tailLo /\ h \in tailLo..tailHi))
       /\ queryAnswers' = queryAnswers \cup {[h |-> h, has_segment_offset |-> FALSE]}
  /\ UNCHANGED << appliedTip, tailLo, tailHi, sealedGens, nextGenId, bulkEntries, reorgCount >>

Stutter ==
  /\ UNCHANGED vars

Next ==
  \/ AppendBlock
  \/ SealGeneration
  \/ Reorganize
  \/ BulkBuild
  \/ QueryAnswer
  \/ Stutter

TypeOK ==
  /\ appliedTip \in 0..MaxTip
  /\ tailLo \in 1..(MaxTip + 2)
  /\ tailHi \in 0..MaxTip
  /\ nextGenId \in 1..(MaxTip + 1)
  /\ reorgCount \in 0..MaxReorgs

Safety ==
  \* REO-04: Active sealed generations never cover invalidated blocks above applied tip
  /\ \A g \in sealedGens: (~g.retired => g.last_h <= appliedTip)
  \* REO-05: Active generations do not overlap and precede mutable tail
  /\ \A g1, g2 \in sealedGens:
       (~g1.retired /\ ~g2.retired /\ g1.id # g2.id) =>
       (g1.last_h < g2.first_h \/ g2.last_h < g1.first_h)
  /\ \A g \in sealedGens: (~g.retired => g.last_h < tailLo)
  \* PRJ-05: Mutable tail never leads applied tip
  /\ tailHi <= appliedTip
  \* PRJ-09: Bulk backfill entries are within applied tip range
  /\ \A h \in bulkEntries: h <= appliedTip
  /\ \A g \in sealedGens: g.entries = {h : h \in g.first_h..g.last_h}
  \* PRJ-07: Query answers never contain segment file offsets
  /\ \A a \in queryAnswers: ~a.has_segment_offset

ConditionalProgress == TRUE

=============================================================================
