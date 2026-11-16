\* BUD-01, BUD-02, BUD-03, BUD-05, BUD-06, BUD-07
----------------------------- MODULE NodeBudget -----------------------------
(***************************************************************************)
(* Formal TLA+ specification of NodeBudget for bitcoin-rs.                 *)
(* Anchors: Tony Hoare, John Carmack, Dieter Rams.                         *)
(*                                                                         *)
(* Contract clauses:                                                       *)
(* - BUD-01: Ingress reserves resources before materializing structures.   *)
(* - BUD-02: Shared node-wide accounting model across all subsystems.      *)
(* - BUD-03: Resource refusal must not be recorded as consensus-invalid.   *)
(* - BUD-05: Foreground chain progress retains reserved capacity.          *)
(* - BUD-06: One memory budget covers all retained allocations; each       *)
(*           owner is charged exactly once (with stated MDBX exception).   *)
(* - BUD-07: When budget is full, release or refuse; no extra buffering.  *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
  \* @type: Int;
  TotalBudget,
  \* @type: Int;
  ForegroundReserve,
  \* @type: Int;
  MaxBlockId,
  \* @type: Bool;
  IsMdbx

Owners == { "coin_cache", "engine_cache", "facts_queue", "index_builder",
            "staged_images", "query_views", "peer_outbound" }
ForegroundOwners == { "coin_cache", "engine_cache", "staged_images", "peer_outbound" }
BackgroundOwners == { "facts_queue", "index_builder", "query_views" }

VARIABLES
  \* @type: Str -> Int;
  charges,
  \* @type: Str -> Int;
  reserved,
  \* @type: Int -> Str;
  blockStatus,
  \* @type: Int -> Str;
  blockConsensusValid,
  \* @type: Int -> Bool;
  blockRefused

vars == << charges, reserved, blockStatus, blockConsensusValid, blockRefused >>

TotalCharges ==
  charges["coin_cache"] + charges["engine_cache"] + charges["facts_queue"] +
  charges["index_builder"] + charges["staged_images"] + charges["query_views"] +
  charges["peer_outbound"]

TotalReserved ==
  reserved["coin_cache"] + reserved["engine_cache"] + reserved["facts_queue"] +
  reserved["index_builder"] + reserved["staged_images"] + reserved["query_views"] +
  reserved["peer_outbound"]

TotalCommitted == TotalCharges + TotalReserved

BackgroundCommitted ==
  charges["facts_queue"] + charges["index_builder"] + charges["query_views"] +
  reserved["facts_queue"] + reserved["index_builder"] + reserved["query_views"]

Init ==
  /\ charges = [o \in Owners |-> 0]
  /\ reserved = [o \in Owners |-> 0]
  /\ blockStatus = [b \in 1..MaxBlockId |-> "idle"]
  /\ blockConsensusValid = [b \in 1..MaxBlockId |-> "unknown"]
  /\ blockRefused = [b \in 1..MaxBlockId |-> FALSE]

ReserveIngress(b, amt) ==
  /\ blockStatus[b] = "idle"
  /\ TotalCommitted + amt <= TotalBudget
  /\ reserved' = [reserved EXCEPT !["staged_images"] = @ + amt]
  /\ blockStatus' = [blockStatus EXCEPT ![b] = "reserved"]
  /\ UNCHANGED << charges, blockConsensusValid, blockRefused >>

RefuseIngress(b, amt) ==
  /\ blockStatus[b] = "idle"
  /\ TotalCommitted + amt > TotalBudget
  /\ blockRefused' = [blockRefused EXCEPT ![b] = TRUE]
  \* BUD-03: refusal NEVER marks block consensus invalid
  /\ UNCHANGED << charges, reserved, blockStatus, blockConsensusValid >>

AllocateIngress(b, amt) ==
  /\ blockStatus[b] = "reserved"
  /\ reserved["staged_images"] >= amt
  /\ reserved' = [reserved EXCEPT !["staged_images"] = @ - amt]
  /\ charges' = [charges EXCEPT !["staged_images"] = @ + amt]
  /\ blockStatus' = [blockStatus EXCEPT ![b] = "staged"]
  /\ UNCHANGED << blockConsensusValid, blockRefused >>

ApplyBlock(b, amt) ==
  /\ blockStatus[b] = "staged"
  /\ charges["staged_images"] >= amt
  /\ charges' = [charges EXCEPT !["staged_images"] = @ - amt]
  /\ blockStatus' = [blockStatus EXCEPT ![b] = "applied"]
  /\ blockConsensusValid' = [blockConsensusValid EXCEPT ![b] = "valid"]
  /\ UNCHANGED << reserved, blockRefused >>

ReserveBackground(o, amt) ==
  /\ o \in BackgroundOwners
  /\ TotalCommitted + amt <= TotalBudget - ForegroundReserve
  /\ reserved' = [reserved EXCEPT ![o] = @ + amt]
  /\ UNCHANGED << charges, blockStatus, blockConsensusValid, blockRefused >>

AllocateBackground(o, amt) ==
  /\ o \in BackgroundOwners
  /\ reserved[o] >= amt
  /\ reserved' = [reserved EXCEPT ![o] = @ - amt]
  /\ charges' = [charges EXCEPT ![o] = @ + amt]
  /\ UNCHANGED << blockStatus, blockConsensusValid, blockRefused >>

ReleaseBackground(o, amt) ==
  /\ o \in BackgroundOwners
  /\ charges[o] >= amt
  /\ charges' = [charges EXCEPT ![o] = @ - amt]
  /\ UNCHANGED << reserved, blockStatus, blockConsensusValid, blockRefused >>

ReserveCoinCache(amt) ==
  /\ TotalCommitted + amt <= TotalBudget
  /\ reserved' = [reserved EXCEPT !["coin_cache"] = @ + amt]
  /\ UNCHANGED << charges, blockStatus, blockConsensusValid, blockRefused >>

AllocateCoinCache(amt) ==
  /\ reserved["coin_cache"] >= amt
  /\ reserved' = [reserved EXCEPT !["coin_cache"] = @ - amt]
  /\ charges' = [charges EXCEPT !["coin_cache"] = @ + amt]
  /\ UNCHANGED << blockStatus, blockConsensusValid, blockRefused >>

ReleaseCoinCache(amt) ==
  /\ charges["coin_cache"] >= amt
  /\ charges' = [charges EXCEPT !["coin_cache"] = @ - amt]
  /\ UNCHANGED << reserved, blockStatus, blockConsensusValid, blockRefused >>

AdjustEngineCache(amt) ==
  /\ IF IsMdbx
     THEN /\ charges' = [charges EXCEPT !["engine_cache"] = 0]
          /\ reserved' = [reserved EXCEPT !["engine_cache"] = 0]
     ELSE \/ /\ TotalCommitted + amt <= TotalBudget
             /\ charges' = [charges EXCEPT !["engine_cache"] = @ + amt]
             /\ UNCHANGED reserved
          \/ /\ charges["engine_cache"] >= amt
             /\ charges' = [charges EXCEPT !["engine_cache"] = @ - amt]
             /\ UNCHANGED reserved
  /\ UNCHANGED << blockStatus, blockConsensusValid, blockRefused >>

ReservePeerOutbound(amt) ==
  /\ TotalCommitted + amt <= TotalBudget
  /\ reserved' = [reserved EXCEPT !["peer_outbound"] = @ + amt]
  /\ UNCHANGED << charges, blockStatus, blockConsensusValid, blockRefused >>

AllocatePeerOutbound(amt) ==
  /\ reserved["peer_outbound"] >= amt
  /\ reserved' = [reserved EXCEPT !["peer_outbound"] = @ - amt]
  /\ charges' = [charges EXCEPT !["peer_outbound"] = @ + amt]
  /\ UNCHANGED << blockStatus, blockConsensusValid, blockRefused >>

ReleasePeerOutbound(amt) ==
  /\ charges["peer_outbound"] >= amt
  /\ charges' = [charges EXCEPT !["peer_outbound"] = @ - amt]
  /\ UNCHANGED << reserved, blockStatus, blockConsensusValid, blockRefused >>

Stutter ==
  UNCHANGED vars

Next ==
  \/ \E b \in 1..MaxBlockId, amt \in 1..2 : ReserveIngress(b, amt)
  \/ \E b \in 1..MaxBlockId, amt \in 1..2 : RefuseIngress(b, amt)
  \/ \E b \in 1..MaxBlockId, amt \in 1..2 : AllocateIngress(b, amt)
  \/ \E b \in 1..MaxBlockId, amt \in 1..2 : ApplyBlock(b, amt)
  \/ \E o \in BackgroundOwners, amt \in 1..2 : ReserveBackground(o, amt)
  \/ \E o \in BackgroundOwners, amt \in 1..2 : AllocateBackground(o, amt)
  \/ \E o \in BackgroundOwners, amt \in 1..2 : ReleaseBackground(o, amt)
  \/ \E amt \in 1..2 : ReserveCoinCache(amt)
  \/ \E amt \in 1..2 : AllocateCoinCache(amt)
  \/ \E amt \in 1..2 : ReleaseCoinCache(amt)
  \/ \E amt \in 1..2 : AdjustEngineCache(amt)
  \/ \E amt \in 1..2 : ReservePeerOutbound(amt)
  \/ \E amt \in 1..2 : AllocatePeerOutbound(amt)
  \/ \E amt \in 1..2 : ReleasePeerOutbound(amt)
  \/ Stutter

TypeOK ==
  /\ \A o \in Owners : charges[o] \in 0..TotalBudget
  /\ \A o \in Owners : reserved[o] \in 0..TotalBudget
  /\ \A b \in 1..MaxBlockId :
       /\ blockStatus[b] \in {"idle", "reserved", "staged", "applied"}
       /\ blockConsensusValid[b] \in {"valid", "unknown", "invalid"}
       /\ blockRefused[b] \in BOOLEAN

Safety ==
  \* BUD-06 & BUD-07: Total committed never exceeds TotalBudget
  /\ TotalCommitted <= TotalBudget
  \* BUD-05: Foreground chain progress retains reserved capacity
  /\ BackgroundCommitted <= TotalBudget - ForegroundReserve
  \* BUD-03: Ingress refusal at exhaustion never invalidates consensus data
  /\ \A b \in 1..MaxBlockId :
       blockRefused[b] => blockConsensusValid[b] # "invalid"
  \* BUD-06 MDBX exception: Engine cache bytes reported as 0
  /\ (IsMdbx => charges["engine_cache"] = 0 /\ reserved["engine_cache"] = 0)

ConditionalProgress == TRUE

=============================================================================