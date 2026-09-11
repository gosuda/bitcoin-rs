---------------------------- MODULE PeerLeases ----------------------------
(***************************************************************************)
(* Finite model of the peer lease and session machine, plan appendix       *)
(* "Peer, projection, and mining lifecycle contract" section A.            *)
(*                                                                         *)
(* One peer P owns two session incarnations S0 and S1 with fixed, ordered  *)
(* generations G0 and G1, two primary request leases R0 and R1, and two    *)
(* fallback tickets F0 and F1 owned by compact-block reconstruction.       *)
(* Control, data, partial-input, and partial-output capacities are 1 and   *)
(* the external-event budget is 12.  The model gates owner bodies T24,    *)
(* T26, T27, and T28 through the g20 gate.                                *)
(*                                                                         *)
(* Why string atoms: every identity, kind, phase, and outcome is a string, *)
(* so the whole model carries one uniform element type.  Apalache type     *)
(* checking then never meets a mixed-type set or comparison.               *)
(***************************************************************************)

EXTENDS Naturals, Sequences

CONSTANTS
  \* Primitive identities, fixed by PeerLeases.cfg.
  \* @type: Str;
  Peer,            \* the single fixed peer
  \* @type: Str;
  S0,              \* session incarnation, allocated first, no reuse
  \* @type: Str;
  S1,              \* session incarnation, allocated second, no reuse
  \* @type: Str;
  G0,              \* generation of S0, fixed mapping
  \* @type: Str;
  G1,              \* generation of S1, fixed mapping
  \* @type: Str;
  R0,              \* primary request ticket, allocated at most once
  \* @type: Str;
  R1,              \* primary request ticket, allocated at most once
  \* @type: Str;
  F0,              \* fallback ticket of R0, allocated at most once
  \* @type: Str;
  F1,              \* fallback ticket of R1, allocated at most once
  \* @type: Str;
  D0,              \* scheduler demand identity, fixture atom
  \* @type: Str;
  D1,              \* scheduler demand identity, fixture atom
  \* Scale constants from appendix A.3.
  \* @type: Int;
  CtrlCap,         \* control queue capacity
  \* @type: Int;
  DataCap,         \* data queue capacity
  \* @type: Int;
  InCap,           \* partial input buffer capacity
  \* @type: Int;
  OutCap,          \* partial output buffer capacity
  \* @type: Int;
  ExternalBudget   \* external events the run admits, never replenished

(***************************************************************************)
(* Finite domains.                                                        *)
(***************************************************************************)

Sess == {S0, S1}
Gen == {G0, G1}
Primary == {R0, R1}
Fallback == {F0, F1}
Q == Primary \cup Fallback

\* Why a pair shaped absence tag: tags are then pairs of strings only, so
\* tag comparisons and tag fields stay type uniform.
\* @type: <<Str, Str>>;
NoTag == << "None", "None" >>
TagDom == {NoTag} \cup (Sess \X Gen)

NT == {"Reserved", "Issued", "Reconstructing", "Fallback"}

PhaseDom == {"Absent", "Handshaking", "Established", "Closing", "Closed"}
TransportDom == {"None", "Handshake", "CipherSession", "V1", "Dead"}
ReqPhaseDom == {"Unused"} \cup NT \cup {"Terminal"}
OutcomeDom == {"None", "Success", "Timeout", "NotFound", "Cancel",
               "Close", "Invalid", "Unavailable"}
BodyDom == {"None", "Partial", "Complete", "Validated", "Published"}

InKind == {"Fragment", "AuthOK", "AuthFail", "PolicyV1", "Frame"}
OutKind == {"Handshake", "Control"}

\* Tokens are triples of strings, so all four buffers share one token type.
\* @type: <<Str, Str, Str>>;
NoTok == << "None", "None", "None" >>
CtrlTok == Sess \X Gen \X {"Control"}
DataTok == Sess \X Gen \X Q
InTok == Sess \X Gen \X InKind
OutTok == Sess \X Gen \X (OutKind \cup Q)

\* Canonical optional-token storage: each buffer holds either the empty
\* sentinel NoTok or exactly one tagged triple.  This is the bijective
\* image of the former capacity-one sequence encoding under the map
\* << >> <-> NoTok and <<t>> <-> t, so every buffer state is preserved.
\* @type: Set(<<Str, Str, Str>>);
CtrlVal == {NoTok} \cup CtrlTok
\* @type: Set(<<Str, Str, Str>>);
DataVal == {NoTok} \cup DataTok
\* @type: Set(<<Str, Str, Str>>);
InVal == {NoTok} \cup InTok
\* @type: Set(<<Str, Str, Str>>);
OutVal == {NoTok} \cup OutTok

(***************************************************************************)
(* Demand domains.  Custody atoms are strings like every other identity,  *)
(* so dstate carries one uniform element type.                              *)
(***************************************************************************)

\* @type: Str;
NoDemand == "None"
D == {D0, D1}
\* @type: Set(Str);
DemandVal == {NoDemand} \cup D

DPending == "DPending"
DActive0 == "DActive0"
DActive1 == "DActive1"
DSatisfied == "DSatisfied"
DSettledShutdown == "DSettledShutdown"
DSettledInvalid == "DSettledInvalid"
DSettledNotFound == "DSettledNotFound"
DSettledCancel == "DSettledCancel"
DSettledUnavailable == "DSettledUnavailable"
\* @type: Set(Str);
DState == {DPending, DActive0, DActive1, DSatisfied,
           DSettledShutdown, DSettledInvalid, DSettledNotFound,
           DSettledCancel, DSettledUnavailable}

(***************************************************************************)
(* Approved demand-custody extension (bitcoin-rs-execution-amendments,     *)
(* agent://MinimalRequeueFixture).  This replaces the superseded staged    *)
(* ghost Requeue extension; the four tickets, sessions, credits, and       *)
(* K = 128 are unchanged, and no new external event, ticket, or retry      *)
(* budget is introduced.                                                   *)
(*                                                                         *)
(* Scheduler demand is modeled explicitly and kept separate from lease     *)
(* attempts.  A fixed carrier D = {D0, D1} names immutable demanded        *)
(* objects (block identity plus the fixed branch context of this          *)
(* fixture).  The tickets R0/R1/F0/F1 remain single-use lease resources:   *)
(*                                                                         *)
(*   demandOf[r]  per primary, "None" before allocation, immutable after   *)
(*                its one Reserve assignment.  A fallback never gains a    *)
(*                mapping of its own: its demand is demandOf[ParentQ(q)],  *)
(*                so the primary/fallback pair is one demand group with    *)
(*                two separately accounted lease tickets.  A fallback      *)
(*                changes the requested representation, not the demanded   *)
(*                object.                                                  *)
(*   dstate[d]    custody of the demand: DPending (scheduler backlog),     *)
(*                DActive0/DActive1 (held by R0/R1), DSatisfied            *)
(*                (published), or DSettled<reason> (explicit terminal      *)
(*                fixture boundary).  Custody is a partition of D.         *)
(*                                                                         *)
(* Atomic restoration: SettleClose(s) returns every demand held by a live  *)
(* tagged ticket of s from Active to DPending in the SAME edge that frees  *)
(* the tickets.  This matches the production operation retain_peer_        *)
(* assignments (crates/p2p/src/download_window.rs 1416-1447): removal of   *)
(* assignments, accounting adjustment, and cursor rewind are one           *)
(* exclusive mutation with no observable intermediate handoff, so the      *)
(* model has no separate return transition and no freed-but-unreturned    *)
(* window.  freed and requeues stay as bounded historical ticket           *)
(* monitors of that one edge: freed counts the released lease, requeues    *)
(* counts the restored-demand receipt, both 0 -> 1 together.  The          *)
(* duplicate sentinel value 2 stays representable in requeues so           *)
(* exactly-once remains falsifiable; Safety proves requeues <= 1.  Ticket  *)
(* receipts count leases, not distinct demands: a primary plus fallback    *)
(* closed together yields two receipts and ONE restored demand.            *)
(*                                                                         *)
(* DPending is the scheduler-custody abstraction, not "absent from the    *)
(* Rust pending map": the demanded hash is discoverable by the bounded     *)
(* scan from the rewound cursor (download_window.rs 1595-1650, which       *)
(* excludes pending, received, and already-selected hashes).               *)
(*                                                                         *)
(* Outcome boundaries: Publish -> DSatisfied.  Timeout -> DPending,        *)
(* matching expire_pending (download_window.rs 1993-2018), which releases  *)
(* the assignment and rewinds the cursor; this deliberately extends retry  *)
(* semantics beyond close-only restoration and is recorded as such.        *)
(* Invalid, NotFound, Cancel, and Unavailable map to explicit              *)
(* DSettled<reason> fixture boundaries, NOT to assertions that production  *)
(* never retries them; that classification belongs to the concrete owner.  *)
(* Done disposes any remaining DPending demand as DSettledShutdown         *)
(* without clearing history and without claiming satisfaction, because     *)
(* attempts or external credits may be exhausted.                          *)
(*                                                                         *)
(* Scope limits (reported, not guessed): two primary attempts bound this   *)
(* fixture.  It can witness (a) two distinct demands and, in a separate    *)
(* trace, (b) one demand lost on S0 and reissued on S1 with a late S0      *)
(* completion changing nothing.  It can NOT witness both distinct demands  *)
(* lost and reissued in one trace (no third primary ticket), three or      *)
(* more attempts at one demand, concurrent attempts at one demand,         *)
(* replacement sessions overlapping the S0-closed-before-S1 order, or      *)
(* hedged requests (ColdFrontState::Racing and PrefixProbe at              *)
(* download_window.rs 358-409, 1263-1289, 1762-1774).  Eventual reissue    *)
(* is NOT claimed: no fairness forces Reserve, and the original            *)
(* settlement consequent is unchanged.                                     *)
(*                                                                         *)
(* Trace inclusion: projecting any trace of this model onto the original   *)
(* variables (erasing demandOf/dstate and the receipt monitors) yields an   *)
(* original-behavior trace when original Reserve steps carry D0 then D1    *)
(* in allocation order.  The staged freed-but-not-requeued states of the   *)
(* superseded ghost extension no longer exist; that observation-boundary   *)
(* change is authorized by the amendment.  Fairness is otherwise           *)
(* unchanged: no fairness clause is added, and the four ghost Requeue      *)
(* clauses are removed together with the action they served.               *)
(***************************************************************************)

(***************************************************************************)
(* State.                                                                 *)
(***************************************************************************)

VARIABLES
  \* @type: Str -> Str;
  phase,          \* per session lifecycle position
  \* @type: Str -> Str;
  transport,      \* per session owned transport object
  \* @type: Str -> Bool;
  authFailed,     \* sticky per incarnation authentication failure
  \* @type: Str;
  current,        \* the one current session, "None" when absent
  \* @type: Int;
  nextSession,    \* allocation cursor, 2 means exhausted, never wraps
  \* @type: Bool;
  inputOpen,      \* external input accepted while true
  \* @type: Bool;
  done,           \* terminal flag, only stutter remains after it
  \* @type: Int;
  eventsLeft,     \* remaining external events, never replenished
  \* @type: <<Str, Str, Str>>;
  ctrl,           \* bounded control buffer: NoTok or one tagged token
  \* @type: <<Str, Str, Str>>;
  data,           \* bounded data buffer: NoTok or one tagged token
  \* @type: <<Str, Str, Str>>;
  partialIn,      \* bounded partial input buffer: NoTok or one tagged token
  \* @type: <<Str, Str, Str>>;
  partialOut,     \* bounded partial output buffer: NoTok or one tagged token
  \* @type: Bool;
  controlDebt,    \* a reserved control service opportunity is owed
  \* @type: Str -> Str;
  reqPhase,       \* per ticket lease phase
  \* @type: Str -> <<Str, Str>>;
  reqTag,         \* per ticket session and generation tag, set at allocation
  \* @type: Str -> Int;
  allocated,      \* per ticket allocation bit, monotone
  \* @type: Str -> Int;
  everIssued,     \* per ticket issuance bit, monotone
  \* @type: Str -> Int;
  releases,       \* per ticket release bit, set once at terminalization
  \* @type: Str -> Str;
  result,         \* per ticket terminal outcome
  \* @type: Str -> Str;
  body,           \* abstract owned body state per primary ticket
  \* @type: Str -> Str;
  demandOf,        \* per primary ticket: its immutable demand identity
  \* @type: Str -> Str;
  dstate,          \* per demand: scheduler custody state
  \* @type: Str -> Int;
  freed,           \* close settlement freed this ticket's lease
  \* @type: Str -> Int;
  requeues,        \* restored-demand receipt for this ticket's lease
  \* @type: Bool;
  stepOK          \* observer of the preceding edge, TRUE initially

vars == << phase, transport, authFailed, current, nextSession,
          inputOpen, done, eventsLeft,
          ctrl, data, partialIn, partialOut, controlDebt,
          reqPhase, reqTag, allocated, everIssued, releases, result,
          body, demandOf, dstate, freed, requeues, stepOK >>


(***************************************************************************)
(* Total helpers.                                                         *)
(* Why IF guarded access: Apalache evaluates both symbolic branches, so    *)
(* every lookup is written as a total function that never applies a        *)
(* function or a sequence outside its domain.                             *)
(***************************************************************************)

\* @type: (Str) => Str;
GenOfS(s) == IF s = S0 THEN G0 ELSE IF s = S1 THEN G1 ELSE "NoGen"
\* @type: (Str) => Int;
SessionIndex(s) == IF s = S0 THEN 0 ELSE 1
\* @type: (Str) => Str;
PartnerOf(q) ==
  IF q = R0 THEN F0
  ELSE IF q = R1 THEN F1
  ELSE IF q = F0 THEN R0
  ELSE R1
\* @type: (Str) => Str;
ParentQ(q) == IF q = F0 THEN R0 ELSE IF q = F1 THEN R1 ELSE q
\* @type: (Str) => Str;
ActiveOf(r) == IF r = R0 THEN DActive0 ELSE DActive1
\* Custody disposition of a terminal ticket outcome: Close and Timeout
\* return the demand to the scheduler, Success satisfies it, and the
\* remaining outcomes are explicit fixture settle boundaries.
\* @type: (Str) => Str;
CustodyOf(o) ==
  IF o \in {"Close", "Timeout"} THEN DPending
  ELSE IF o = "Success" THEN DSatisfied
  ELSE IF o = "Invalid" THEN DSettledInvalid
  ELSE IF o = "NotFound" THEN DSettledNotFound
  ELSE IF o = "Cancel" THEN DSettledCancel
  ELSE DSettledUnavailable

CurPhase == IF current = "None" THEN "NoPhase" ELSE phase[current]
CurTransport == IF current = "None" THEN "None" ELSE transport[current]

Estab == current # "None" /\ CurPhase = "Established"
\* @type: (Str, Str) => Bool;
TaggedTo(q, s) == reqTag[q] # NoTag /\ reqTag[q][1] = s
\* @type: (Str) => Bool;
MatchesCurrent(q) == reqTag[q] # NoTag /\ current # "None" /\ reqTag[q][1] = current

\* Close-transfer projections of the demand-custody extension: the
\* tickets whose lease this close settlement freed, the tickets whose
\* demand receipt was restored in the same edge, and their equality,
\* which the atomic restoration holds in every state, in particular at
\* the FinishClose settlement boundary.
\* @type: (Str) => Set(Str);
FreedOf(s) == {q \in Q : TaggedTo(q, s) /\ freed[q] = 1}
\* @type: (Str) => Set(Str);
RequeuedOf(s) == {q \in Q : TaggedTo(q, s) /\ requeues[q] >= 1}
\* @type: (Str) => Bool;
RequeueComplete(s) == FreedOf(s) = RequeuedOf(s)

\* @type: (<<Str, Str, Str>>, Str) => Bool;
HasTagged(tok, s) == tok # NoTok /\ tok[1] = s

\* @type: (<<Str, Str, Str>>, Str, Str) => <<Str, Str, Str>>;
DropIfIn(tok, q1, q2) ==
  IF tok = NoTok THEN tok
  ELSE IF tok[3] = q1 \/ tok[3] = q2 THEN NoTok ELSE tok

\* @type: (<<Str, Str, Str>>, Str) => <<Str, Str, Str>>;
DropIfTagged(tok, s) ==
  IF tok = NoTok THEN tok
  ELSE IF tok[1] = s THEN NoTok ELSE tok

\* @type: (Str, Str) => Bool;
KindOK(s, k) ==
  \/ k = "Fragment" /\ transport[s] \in {"Handshake", "CipherSession", "V1"}
  \/ k \in {"AuthOK", "AuthFail", "PolicyV1"} /\ transport[s] = "Handshake"
  \/ k = "Frame" /\ transport[s] \in {"CipherSession", "V1"}


(***************************************************************************)
(* Edge observer.                                                         *)
(*                                                                         *)
(* Why a computed stepOK: the appendix makes the edge obligations of       *)
(* TransitionSafety checkable as a state invariant.  Every nonstuttering   *)
(* action sets stepOK to EdgeOK of its old and new state, stutter leaves   *)
(* it unchanged, and TransitionSafety is exactly stepOK.                  *)
(***************************************************************************)

EdgeOK ==
  /\ \A q \in Q :
       /\ allocated'[q] >= allocated[q]
       /\ everIssued'[q] >= everIssued[q]
       /\ releases'[q] >= releases[q]
       /\ \/ reqTag'[q] = reqTag[q]
          \/ /\ reqTag[q] = NoTag
             /\ reqPhase[q] = "Unused"
             /\ reqTag'[q] # NoTag
             /\ reqPhase'[q] = "Reserved"
             /\ GenOfS(reqTag'[q][1]) = reqTag'[q][2]
             /\ allocated[q] = 0
             /\ allocated'[q] = 1
       /\ (releases'[q] # releases[q]) =>
            /\ releases[q] = 0
            /\ releases'[q] = 1
            /\ reqPhase[q] \in NT
            /\ reqPhase'[q] = "Terminal"
       /\ freed'[q] >= freed[q]
       /\ requeues'[q] \in {requeues[q], requeues[q] + 1}
       /\ (freed'[q] # freed[q]) =>
            /\ freed[q] = 0
            /\ freed'[q] = 1
            /\ reqPhase[q] \in NT
            /\ reqPhase'[q] = "Terminal"
            /\ result'[q] = "Close"
            /\ releases'[q] = 1
       /\ (requeues'[q] # requeues[q]) =>
            /\ requeues[q] = 0
            /\ requeues'[q] = 1
            /\ freed[q] = 0
            /\ freed'[q] = 1
  /\ \A r \in Primary :
       \/ demandOf'[r] = demandOf[r]
       \/ /\ demandOf[r] = NoDemand
          /\ demandOf'[r] \in D
          /\ allocated[r] = 0
          /\ allocated'[r] = 1
          /\ reqPhase[r] = "Unused"
          /\ reqPhase'[r] = "Reserved"
  /\ \A d \in D :
       \/ dstate'[d] = dstate[d]
       \/ /\ dstate[d] = DPending
          /\ dstate'[d] \in {DActive0, DActive1}
          /\ \E r \in Primary :
               /\ demandOf[r] = NoDemand
               /\ demandOf'[r] = d
               /\ reqPhase[r] = "Unused"
               /\ reqPhase'[r] = "Reserved"
               /\ dstate'[d] = ActiveOf(r)
       \/ /\ dstate[d] = DPending
          /\ dstate'[d] = DSettledShutdown
          /\ done'
       \/ /\ dstate[d] \in {DActive0, DActive1}
          /\ \E q \in Q :
               /\ reqPhase[q] \in NT
               /\ reqPhase'[q] = "Terminal"
               /\ demandOf[ParentQ(q)] = d
               /\ dstate'[d] = CustodyOf(result'[q])
  /\ nextSession' >= nextSession
  /\ eventsLeft' \in {eventsLeft, eventsLeft - 1}
  /\ \A r \in Primary :
       /\ (body'[r] = "Published") => (body[r] \in {"Validated", "Published"})
       /\ (body[r] = "Published") => (body'[r] = "Published")
  /\ \A s \in Sess :
       /\ (transport'[s] = "V1") => (~authFailed'[s])
       /\ (phase[s] = "Closed") => (phase'[s] = "Closed")
  /\ \A q \in Q : (reqPhase[q] = "Terminal") => (reqPhase'[q] = "Terminal")

(***************************************************************************)
(* Terminalization.                                                       *)
(*                                                                         *)
(* Why one operator: the appendix makes terminalization atomic, one        *)
(* nonterminal to Terminal edge per ticket that sets its release bit from  *)
(* 0 to exactly 1 and removes its queued and output work, and a terminal   *)
(* parent never leaves a live fallback child behind, nor the reverse.     *)
(***************************************************************************)

\* @type: (Str, Str) => Bool;
TerminalizeEffects(o, q) ==
  /\ reqPhase' = [t \in Q |->
       IF (t = q \/ t = PartnerOf(q)) /\ reqPhase[t] \in NT
       THEN "Terminal" ELSE reqPhase[t]]
  /\ result' = [t \in Q |->
       IF (t = q \/ t = PartnerOf(q)) /\ reqPhase[t] \in NT
       THEN o ELSE result[t]]
  /\ releases' = [t \in Q |->
       IF (t = q \/ t = PartnerOf(q)) /\ reqPhase[t] \in NT
       THEN 1 ELSE releases[t]]
  /\ data' = DropIfIn(data, q, PartnerOf(q))
  /\ partialOut' = DropIfIn(partialOut, q, PartnerOf(q))
  /\ demandOf' = demandOf
  /\ dstate' = [d \in D |->
       IF (reqPhase[q] \in NT \/ reqPhase[PartnerOf(q)] \in NT)
          /\ demandOf[ParentQ(q)] = d
          /\ dstate[d] \in {DActive0, DActive1}
       THEN CustodyOf(o) ELSE dstate[d]]

(***************************************************************************)
(* Initial state and settlement predicate.                                *)
(***************************************************************************)

Init ==
  /\ phase = [s \in Sess |-> "Absent"]
  /\ transport = [s \in Sess |-> "None"]
  /\ authFailed = [s \in Sess |-> FALSE]
  /\ current = "None"
  /\ nextSession = 0
  /\ inputOpen = TRUE
  /\ done = FALSE
  /\ eventsLeft = ExternalBudget
  /\ ctrl = NoTok
  /\ data = NoTok
  /\ partialIn = NoTok
  /\ partialOut = NoTok
  /\ controlDebt = FALSE
  /\ reqPhase = [q \in Q |-> "Unused"]
  /\ reqTag = [q \in Q |-> NoTag]
  /\ allocated = [q \in Q |-> 0]
  /\ everIssued = [q \in Q |-> 0]
  /\ releases = [q \in Q |-> 0]
  /\ result = [q \in Q |-> "None"]
  /\ body = [r \in Primary |-> "None"]
  /\ demandOf = [r \in Primary |-> NoDemand]
  /\ dstate = [d \in D |-> DPending]
  /\ freed = [q \in Q |-> 0]
  /\ requeues = [q \in Q |-> 0]
  /\ stepOK = TRUE

Settled ==
  /\ \A q \in Q : allocated[q] = 1 => reqPhase[q] = "Terminal"
  /\ \A s \in Sess : phase[s] \in {"Absent", "Closed"}
  /\ current = "None"
  /\ ctrl = NoTok /\ data = NoTok /\ partialIn = NoTok /\ partialOut = NoTok
  /\ controlDebt = FALSE

(***************************************************************************)
(* Actions of appendix A.4.                                               *)
(*                                                                         *)
(* Every action carries the implicit guard ~done.  External actions       *)
(* require open input and a positive budget and spend exactly one event,  *)
(* including stale and duplicate arrivals.  Seal is deliberately exempt   *)
(* so exhaustion can never prevent closing input.                        *)
(***************************************************************************)

\* A fresh incarnation replaces the previous one only after it is closed
\* and its tickets settled, and only this incarnation is initialized.
\* @type: (Str) => Bool;
PrecedingClosed(s) ==
  /\ (s = S1) => (phase[S0] = "Closed")
  /\ \A q \in Q : TaggedTo(q, s) => reqPhase[q] = "Terminal"

\* @type: (Str) => Bool;
Start(s) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ current = "None"
  /\ nextSession = SessionIndex(s)
  /\ phase[s] = "Absent"
  /\ PrecedingClosed(s)
  /\ phase' = [phase EXCEPT ![s] = "Handshaking"]
  /\ transport' = [transport EXCEPT ![s] = "Handshake"]
  /\ authFailed' = [authFailed EXCEPT ![s] = FALSE]
  /\ current' = s
  /\ nextSession' = nextSession + 1
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << inputOpen, done, ctrl, data, partialIn, partialOut,
                  controlDebt, reqPhase, reqTag, allocated, everIssued,
                  releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* One bounded input chunk or control verdict arrives.  The kind must fit
\* the transport that owns the session, so ciphertext never reaches V1.
\* @type: (Str, Str) => Bool;
ReadPartial(s, k) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ s = current
  /\ CurPhase \in {"Handshaking", "Established"}
  /\ partialIn = NoTok
  /\ KindOK(s, k)
  /\ partialIn' = <<s, GenOfS(s), k>>
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, ctrl, data, partialOut, controlDebt,
                  reqPhase, reqTag, allocated, everIssued, releases,
                  result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Bytes move into the abstract parser.  No authentication or body claim.
\* @type: (Str) => Bool;
ConsumeFragment(s) ==
  /\ ~done
  /\ s = current
  /\ partialIn = <<s, GenOfS(s), "Fragment">>
  /\ partialIn' = NoTok
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, data, partialOut,
                  controlDebt, reqPhase, reqTag, allocated, everIssued,
                  releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* The owned handshake produces bounded output while still handshaking.
\* @type: (Str) => Bool;
HandshakeOutput(s) ==
  /\ ~done
  /\ s = current /\ phase[s] = "Handshaking"
  /\ partialOut = NoTok
  /\ partialOut' = <<s, GenOfS(s), "Handshake">>
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, data, partialIn,
                  controlDebt, reqPhase, reqTag, allocated, everIssued,
                  releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Successful authenticated completion moves handshake ownership into the
\* cipher session and establishes the incarnation.
\* @type: (Str) => Bool;
Authenticate(s) ==
  /\ ~done
  /\ s = current /\ phase[s] = "Handshaking"
  /\ partialIn = <<s, GenOfS(s), "AuthOK">>
  /\ ~authFailed[s]
  /\ partialIn' = NoTok
  /\ transport' = [transport EXCEPT ![s] = "CipherSession"]
  /\ phase' = [phase EXCEPT ![s] = "Established"]
  /\ UNCHANGED << authFailed, current, nextSession, inputOpen, done,
                  eventsLeft, ctrl, data, partialOut, controlDebt,
                  reqPhase, reqTag, allocated, everIssued, releases,
                  result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* A policy recognized V1 compatibility outcome selects V1.  It never
\* reinterprets ciphertext, and an authentication failure bars it.
\* @type: (Str) => Bool;
SelectV1(s) ==
  /\ ~done
  /\ s = current /\ phase[s] = "Handshaking"
  /\ partialIn = <<s, GenOfS(s), "PolicyV1">>
  /\ ~authFailed[s]
  /\ partialIn' = NoTok
  /\ transport' = [transport EXCEPT ![s] = "V1"]
  /\ phase' = [phase EXCEPT ![s] = "Established"]
  /\ UNCHANGED << authFailed, current, nextSession, inputOpen, done,
                  eventsLeft, ctrl, data, partialOut, controlDebt,
                  reqPhase, reqTag, allocated, everIssued, releases,
                  result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Authentication failure is sticky, kills the transport, and closes.
\* @type: (Str) => Bool;
AuthenticationFault(s) ==
  /\ ~done
  /\ s = current /\ phase[s] = "Handshaking"
  /\ partialIn = <<s, GenOfS(s), "AuthFail">>
  /\ partialIn' = NoTok
  /\ authFailed' = [authFailed EXCEPT ![s] = TRUE]
  /\ phase' = [phase EXCEPT ![s] = "Closing"]
  /\ transport' = [transport EXCEPT ![s] = "Dead"]
  /\ UNCHANGED << current, nextSession, inputOpen, done, eventsLeft,
                  ctrl, data, partialOut, controlDebt, reqPhase, reqTag,
                  allocated, everIssued, releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* A fully framed authenticated message may be parsed and dispatched.
\* Framing is not validation success and publishes nothing.
\* @type: (Str) => Bool;
Frame(s) ==
  /\ ~done
  /\ s = current /\ phase[s] = "Established"
  /\ partialIn = <<s, GenOfS(s), "Frame">>
  /\ partialIn' = NoTok
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, data, partialOut,
                  controlDebt, reqPhase, reqTag, allocated, everIssued,
                  releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Control intake records the owed reserved service opportunity.
\* @type: (Str) => Bool;
EnqueueControl(s) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ s = current /\ phase[s] = "Established"
  /\ ctrl = NoTok
  /\ ctrl' = <<s, GenOfS(s), "Control">>
  /\ controlDebt' = TRUE
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, data, partialIn, partialOut,
                  reqPhase, reqTag, allocated, everIssued, releases,
                  result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Serving control pays the debt.  A stale tagged control is not service.
ServeControl ==
  /\ ~done
  /\ Estab
  /\ ctrl # NoTok
  /\ ctrl[1] = current
  /\ partialOut = NoTok
  /\ ctrl' = NoTok
  /\ partialOut' = ctrl
  /\ controlDebt' = FALSE
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, data, partialIn,
                  reqPhase, reqTag, allocated, everIssued, releases,
                  result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Reservation, the tag, and the demand lease are one atomic
\* allocation.  The two primary tickets are themselves the reservation
\* bound of this finite fixture, and only a pending demand can be
\* leased.
\* @type: (Str, Str) => Bool;
Reserve(r, d) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ Estab
  /\ reqPhase[r] = "Unused"
  /\ dstate[d] = DPending
  /\ reqPhase' = [reqPhase EXCEPT ![r] = "Reserved"]
  /\ reqTag' = [reqTag EXCEPT ![r] = <<current, GenOfS(current)>>]
  /\ allocated' = [allocated EXCEPT ![r] = 1]
  /\ demandOf' = [demandOf EXCEPT ![r] = d]
  /\ dstate' = [dstate EXCEPT ![d] = ActiveOf(r)]
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, ctrl, data, partialIn, partialOut,
                  controlDebt, everIssued, releases, result, body, freed, requeues >>
  /\ stepOK' = EdgeOK

\* A reserved ticket enters the data queue.  Queue admission is not
\* issuance, so the lease stays reserved until the issuance boundary.
\* @type: (Str) => Bool;
QueueData(q) ==
  /\ ~done
  /\ Estab
  /\ reqPhase[q] = "Reserved"
  /\ MatchesCurrent(q)
  /\ data = NoTok
  /\ data' = <<reqTag[q][1], reqTag[q][2], q>>
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, partialIn, partialOut,
                  controlDebt, reqPhase, reqTag, allocated, everIssued,
                  releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Data service is blocked while control debt is outstanding, so bulk
\* traffic can never consume the reserved control opportunity.
\* @type: (Str) => Bool;
ServeData(q) ==
  /\ ~done
  /\ Estab
  /\ reqPhase[q] = "Reserved"
  /\ data # NoTok
  /\ data[3] = q
  /\ data[1] = current
  /\ partialOut = NoTok
  /\ ~controlDebt
  /\ data' = NoTok
  /\ partialOut' = data
  /\ reqPhase' = [reqPhase EXCEPT ![q] = "Issued"]
  /\ everIssued' = [everIssued EXCEPT ![q] = 1]
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, partialIn, controlDebt,
                  reqTag, allocated, releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* One modeled output chunk leaves.  Concrete writers keep their remaining
\* bounded bytes, so this consumes exactly one modeled chunk.
WritePartial ==
  /\ ~done
  /\ partialOut # NoTok
  /\ current # "None"
  /\ CurTransport \in {"Handshake", "CipherSession", "V1"}
  /\ partialOut' = NoTok
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, data, partialIn,
                  controlDebt, reqPhase, reqTag, allocated, everIssued,
                  releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* A peer response for an issued or reconstructing ticket.  Partial data
\* only applies to a compact primary, a complete candidate belongs to the
\* parent of a fallback child, and an invalid response terminalizes.
\* @type: (Str, Str) => Bool;
Response(q, k) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ k \in {"Partial", "Complete", "Invalid"}
  /\ Estab
  /\ MatchesCurrent(q)
  /\ reqPhase[q] \in {"Issued", "Reconstructing"}
  /\ eventsLeft' = eventsLeft - 1
  /\ \/ /\ k = "Partial"
        /\ q \in Primary
        /\ reqPhase' = [reqPhase EXCEPT ![q] = "Reconstructing"]
        /\ result' = result
        /\ releases' = releases
        /\ body' = [body EXCEPT ![q] = "Partial"]
        /\ data' = data
        /\ partialOut' = partialOut
        /\ demandOf' = demandOf
        /\ dstate' = dstate
     \/ /\ k = "Complete"
        /\ reqPhase' = reqPhase
        /\ result' = result
        /\ releases' = releases
        /\ body' = [body EXCEPT ![ParentQ(q)] = "Complete"]
        /\ data' = data
        /\ partialOut' = partialOut
        /\ demandOf' = demandOf
        /\ dstate' = dstate
     \/ /\ k = "Invalid"
        /\ TerminalizeEffects("Invalid", q)
        /\ body' = body
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, ctrl, partialIn, controlDebt, reqTag,
                  allocated, everIssued, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Reconstruction either completes the body or keeps it partial without
\* publication.  The retain option is the stutter of this abstraction.
\* @type: (Str) => Bool;
Reconstruct(r) ==
  /\ ~done
  /\ reqPhase[r] = "Reconstructing"
  /\ body[r] = "Partial"
  /\ body' = [body EXCEPT ![r] = "Complete"]
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, data, partialIn,
                  partialOut, controlDebt, reqPhase, reqTag, allocated,
                  everIssued, releases, result, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* The full body fallback is separately owned work with its own ticket,
\* so it consumes one external allocation event and its own reservation.
\* @type: (Str) => Bool;
BeginFallback(r) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ reqPhase[r] = "Reconstructing"
  /\ Estab
  /\ MatchesCurrent(r)
  /\ reqPhase[PartnerOf(r)] = "Unused"
  /\ reqPhase' = [reqPhase EXCEPT ![r] = "Fallback", ![PartnerOf(r)] = "Reserved"]
  /\ reqTag' = [reqTag EXCEPT ![PartnerOf(r)] = reqTag[r]]
  /\ allocated' = [allocated EXCEPT ![PartnerOf(r)] = 1]
  /\ body' = [body EXCEPT ![r] = "None"]
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, ctrl, data, partialIn, partialOut,
                  controlDebt, everIssued, releases, result, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* When bounded allocation or policy cannot supply the fallback, the
\* parent settles as unavailable and no child is allocated.
\* @type: (Str) => Bool;
FallbackUnavailable(r) ==
  /\ ~done
  /\ reqPhase[r] = "Reconstructing"
  /\ TerminalizeEffects("Unavailable", r)
  /\ body' = [body EXCEPT ![r] = "None"]
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, partialIn, controlDebt,
                  reqTag, allocated, everIssued, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Every reconstructed candidate passes the ordinary validation owner.
\* Validation tokens abstract results that the real owner produces.
\* @type: (Str) => Bool;
Validate(r) ==
  /\ ~done
  /\ body[r] = "Complete"
  /\ Estab
  /\ MatchesCurrent(r)
  /\ \/ reqPhase[r] \in {"Issued", "Reconstructing"}
     \/ /\ reqPhase[r] = "Fallback"
        /\ reqPhase[PartnerOf(r)] = "Issued"
  /\ \/ /\ body' = [body EXCEPT ![r] = "Validated"]
        /\ reqPhase' = reqPhase
        /\ result' = result
        /\ releases' = releases
        /\ data' = data
        /\ partialOut' = partialOut
        /\ demandOf' = demandOf
        /\ dstate' = dstate
     \/ /\ TerminalizeEffects("Invalid", r)
        /\ body' = body
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, partialIn, controlDebt,
                  reqTag, allocated, everIssued, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Only a validated body of a live parent publishes, and a fallback
\* parent needs its child live.  Publication terminalizes with Success.
\* @type: (Str) => Bool;
Publish(r) ==
  /\ ~done
  /\ body[r] = "Validated"
  /\ Estab
  /\ MatchesCurrent(r)
  /\ reqPhase[r] \in NT
  /\ (reqPhase[r] = "Fallback") => (reqPhase[PartnerOf(r)] \in NT)
  /\ body' = [body EXCEPT ![r] = "Published"]
  /\ TerminalizeEffects("Success", r)
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, ctrl, partialIn, controlDebt,
                  reqTag, allocated, everIssued, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Expiry settles the ticket and its dependent work.
\* @type: (Str) => Bool;
Timeout(q) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ reqPhase[q] \in NT
  /\ TerminalizeEffects("Timeout", q)
  /\ body' = body
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, ctrl, partialIn, controlDebt, reqTag,
                  allocated, everIssued, freed, requeues >>
  /\ stepOK' = EdgeOK

\* A not found settles the ticket and dependent work.
\* @type: (Str) => Bool;
NotFound(q) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ reqPhase[q] \in NT
  /\ Estab
  /\ MatchesCurrent(q)
  /\ TerminalizeEffects("NotFound", q)
  /\ body' = body
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, ctrl, partialIn, controlDebt, reqTag,
                  allocated, everIssued, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Owner cancellation settles the ticket and dependent work.
\* @type: (Str) => Bool;
Cancel(q) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ allocated[q] = 1
  /\ reqPhase[q] \in NT
  /\ TerminalizeEffects("Cancel", q)
  /\ body' = body
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, ctrl, partialIn, controlDebt, reqTag,
                  allocated, everIssued, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Close needs either sealed input or the owner close condition.  The
\* owner condition is unconstrained environment choice here, which makes
\* close available for every live session and unconditionally available
\* once input is sealed.
\* @type: (Str) => Bool;
Close(s) ==
  /\ ~done
  /\ phase[s] \in {"Handshaking", "Established"}
  /\ phase' = [phase EXCEPT ![s] = "Closing"]
  /\ transport' = [transport EXCEPT ![s] = "Dead"]
  /\ UNCHANGED << authFailed, current, nextSession, inputOpen, done,
                  eventsLeft, ctrl, data, partialIn, partialOut, controlDebt,
                  reqPhase, reqTag, allocated, everIssued, releases, result,
                  body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* A transport fault closes without granting any downgrade permission.
\* @type: (Str) => Bool;
TransportFault(s) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ s = current
  /\ phase[s] \in {"Handshaking", "Established"}
  /\ phase' = [phase EXCEPT ![s] = "Closing"]
  /\ transport' = [transport EXCEPT ![s] = "Dead"]
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << authFailed, current, nextSession, inputOpen, done,
                  ctrl, data, partialIn, partialOut, controlDebt, reqPhase,
                  reqTag, allocated, everIssued, releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Why SettleCloseWork: an instance with nothing to settle is exactly a
\* stutter step, so excluding it preserves the transition graph while it
\* keeps every SettleClose instance genuinely state changing, which the
\* fairness expansion below relies on.
\* @type: (Str) => Bool;
SettleCloseWork(s) ==
  \/ \E q \in Q : TaggedTo(q, s) /\ reqPhase[q] \in NT
  \/ \E r \in Primary : TaggedTo(r, s) /\ body[r] \notin {"None", "Published"}
  \/ HasTagged(ctrl, s)
  \/ HasTagged(data, s)
  \/ HasTagged(partialIn, s)
  \/ HasTagged(partialOut, s)
  \/ controlDebt

\* Close settlement terminalizes every live tagged ticket with Close,
\* discards nonpublished bodies, drops queued and buffered work, and
\* clears the owed control service.
\* @type: (Str) => Bool;
SettleClose(s) ==
  /\ ~done
  /\ phase[s] = "Closing"
  /\ SettleCloseWork(s)
  /\ reqPhase' = [q \in Q |->
       IF TaggedTo(q, s) /\ reqPhase[q] \in NT
       THEN "Terminal" ELSE reqPhase[q]]
  /\ result' = [q \in Q |->
       IF TaggedTo(q, s) /\ reqPhase[q] \in NT
       THEN "Close" ELSE result[q]]
  /\ releases' = [q \in Q |->
       IF TaggedTo(q, s) /\ reqPhase[q] \in NT
       THEN 1 ELSE releases[q]]
  /\ freed' = [t \in Q |->
       IF TaggedTo(t, s) /\ reqPhase[t] \in NT
       THEN 1 ELSE freed[t]]
  /\ requeues' = [t \in Q |->
       IF TaggedTo(t, s) /\ reqPhase[t] \in NT
       THEN 1 ELSE requeues[t]]
  /\ dstate' = [d \in D |->
       IF (\E q \in Q :
             TaggedTo(q, s) /\ reqPhase[q] \in NT
             /\ demandOf[ParentQ(q)] = d)
          /\ dstate[d] \in {DActive0, DActive1}
       THEN CustodyOf("Close") ELSE dstate[d]]
  /\ body' = [r \in Primary |->
       IF TaggedTo(r, s) /\ body[r] # "Published"
       THEN "None" ELSE body[r]]
  /\ ctrl' = DropIfTagged(ctrl, s)
  /\ data' = DropIfTagged(data, s)
  /\ partialIn' = DropIfTagged(partialIn, s)
  /\ partialOut' = DropIfTagged(partialOut, s)
  /\ controlDebt' = FALSE
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, eventsLeft, reqTag, allocated,
                  everIssued, demandOf >>
  /\ stepOK' = EdgeOK

\* The incarnation finishes only with no live tagged tickets, no retained
\* tokens, no debt, and every lease freed by this close settlement
\* requeued exactly once: the settlement boundary at which requeued-set
\* equality with the freed set is required.  Between SettleClose and this
\* edge the requeues may still be staged, so equality is not demanded
\* prematurely.
\* @type: (Str) => Bool;
FinishClose(s) ==
  /\ ~done
  /\ phase[s] = "Closing"
  /\ \A q \in Q : TaggedTo(q, s) => reqPhase[q] \notin NT
  /\ ~HasTagged(ctrl, s)
  /\ ~HasTagged(data, s)
  /\ ~HasTagged(partialIn, s)
  /\ ~HasTagged(partialOut, s)
  /\ ~controlDebt
  /\ RequeueComplete(s)
  /\ phase' = [phase EXCEPT ![s] = "Closed"]
  /\ current' = IF current = s THEN "None" ELSE current
  /\ UNCHANGED << transport, authFailed, nextSession, inputOpen, done,
                  eventsLeft, ctrl, data, partialIn, partialOut, controlDebt,
                  reqPhase, reqTag, allocated, everIssued, releases, result,
                  body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* A late or duplicate completion is a typed rejection that changes only
\* the budget and the edge observer, never any lease state.
\* @type: (<<Str, Str>>, Str) => Bool;
IsLateArrival(tag, q) ==
  \/ tag = NoTag
  \/ allocated[q] = 0
  \/ reqPhase[q] = "Terminal"
  \/ tag # NoTag /\ GenOfS(tag[1]) # tag[2]
  \/ tag # NoTag /\ phase[tag[1]] # "Established"
  \/ tag # NoTag /\ current # tag[1]

\* @type: (<<Str, Str>>, Str) => Bool;
RejectLate(tag, q) ==
  /\ ~done
  /\ inputOpen /\ eventsLeft > 0
  /\ tag \in TagDom
  /\ IsLateArrival(tag, q)
  /\ eventsLeft' = eventsLeft - 1
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, done, ctrl, data, partialIn, partialOut,
                  controlDebt, reqPhase, reqTag, allocated, everIssued,
                  releases, result, body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Sealing closes external input without spending an event, so budget
\* exhaustion can never trap an open input.
Seal ==
  /\ ~done
  /\ inputOpen
  /\ inputOpen' = FALSE
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession, done,
                  eventsLeft, ctrl, data, partialIn, partialOut, controlDebt,
                  reqPhase, reqTag, allocated, everIssued, releases, result,
                  body, demandOf, dstate, freed, requeues >>
  /\ stepOK' = EdgeOK

\* Done requires sealed input and full settlement and permits stutter
\* only.  Every still-pending demand is disposed as DSettledShutdown:
\* settlement is recorded, never satisfaction.
Done ==
  /\ ~done
  /\ ~inputOpen
  /\ Settled
  /\ done' = TRUE
  /\ dstate' = [d \in D |->
       IF dstate[d] = DPending THEN DSettledShutdown ELSE dstate[d]]
  /\ UNCHANGED << phase, transport, authFailed, current, nextSession,
                  inputOpen, eventsLeft, ctrl, data, partialIn, partialOut,
                  controlDebt, reqPhase, reqTag, allocated, everIssued,
                  releases, result, body, demandOf, freed, requeues >>
  /\ stepOK' = EdgeOK

Stutter == UNCHANGED vars

(***************************************************************************)
(* Next is the unrestricted union of every action instance plus stutter.   *)
(* There is no priority, pruning, or fairness inside Next.                *)
(***************************************************************************)

Next ==
  \/ \E s \in Sess : Start(s)
  \/ \E s \in Sess, k \in InKind : ReadPartial(s, k)
  \/ \E s \in Sess : ConsumeFragment(s)
  \/ \E s \in Sess : HandshakeOutput(s)
  \/ \E s \in Sess : Authenticate(s)
  \/ \E s \in Sess : SelectV1(s)
  \/ \E s \in Sess : AuthenticationFault(s)
  \/ \E s \in Sess : Frame(s)
  \/ \E s \in Sess : EnqueueControl(s)
  \/ ServeControl
  \/ \E r \in Primary, d \in D : Reserve(r, d)
  \/ \E q \in Q : QueueData(q)
  \/ \E q \in Q : ServeData(q)
  \/ WritePartial
  \/ \E q \in Q, k \in {"Partial", "Complete", "Invalid"} : Response(q, k)
  \/ \E r \in Primary : Reconstruct(r)
  \/ \E r \in Primary : BeginFallback(r)
  \/ \E r \in Primary : FallbackUnavailable(r)
  \/ \E r \in Primary : Validate(r)
  \/ \E r \in Primary : Publish(r)
  \/ \E q \in Q : Timeout(q)
  \/ \E q \in Q : NotFound(q)
  \/ \E q \in Q : Cancel(q)
  \/ \E s \in Sess : Close(s)
  \/ \E s \in Sess : TransportFault(s)
  \/ \E s \in Sess : SettleClose(s)
  \/ \E s \in Sess : FinishClose(s)
  \/ \E tag \in TagDom, q \in Q : RejectLate(tag, q)
  \/ Seal
  \/ Done
  \/ Stutter

(***************************************************************************)
(* TypeOK: every variable stays inside its declared finite domain.        *)
(***************************************************************************)

TypeOK ==
  /\ phase \in [Sess -> PhaseDom]
  /\ transport \in [Sess -> TransportDom]
  /\ authFailed \in [Sess -> BOOLEAN]
  /\ current \in {"None"} \cup Sess
  /\ nextSession \in 0..2
  /\ inputOpen \in BOOLEAN
  /\ done \in BOOLEAN
  /\ stepOK \in BOOLEAN
  /\ eventsLeft \in 0..ExternalBudget
  /\ ctrl \in CtrlVal
  /\ data \in DataVal
  /\ partialIn \in InVal
  /\ partialOut \in OutVal
  /\ controlDebt \in BOOLEAN
  /\ reqPhase \in [Q -> ReqPhaseDom]
  /\ reqTag \in [Q -> TagDom]
  /\ allocated \in [Q -> {0, 1}]
  /\ everIssued \in [Q -> {0, 1}]
  /\ releases \in [Q -> {0, 1}]
  /\ result \in [Q -> OutcomeDom]
  /\ body \in [Primary -> BodyDom]
  /\ demandOf \in [Primary -> DemandVal]
  /\ dstate \in [D -> DState]
  /\ freed \in [Q -> {0, 1}]
  /\ requeues \in [Q -> {0, 1, 2}]

(***************************************************************************)
(* Safety: the state invariants of appendix A.5.                          *)
(***************************************************************************)

\* @type: (<<Str, Str, Str>>) => Bool;
TokenOK(tok) ==
  tok = NoTok
  \/ (tok[1] = current /\ tok[2] = GenOfS(tok[1]))

Safety ==
  /\ \A s \in Sess :
       /\ (current = s) => phase[s] \notin {"Closed", "Absent"}
       /\ phase[s] \in {"Handshaking", "Established", "Closing"} =>
            (current = s)
       /\ authFailed[s] => transport[s] # "V1"
       /\ (phase[s] = "Handshaking") => (transport[s] = "Handshake")
       /\ (phase[s] = "Established") =>
            (transport[s] \in {"CipherSession", "V1"})
       /\ (phase[s] \in {"Closing", "Closed"}) => (transport[s] = "Dead")
       /\ (phase[s] = "Absent") => (transport[s] = "None")
  /\ (nextSession >= 1) => (phase[S0] # "Absent")
  /\ (nextSession = 2) => (phase[S0] = "Closed")
  /\ phase[S1] \in {"Handshaking", "Established", "Closing"} =>
       (nextSession = 2)
  /\ TokenOK(ctrl)
  /\ TokenOK(data)
  /\ TokenOK(partialIn)
  /\ TokenOK(partialOut)
  /\ (controlDebt <=> (ctrl # NoTok))
  /\ \A q \in Q :
       /\ (reqPhase[q] \in NT) =>
            (reqTag[q] # NoTag /\ allocated[q] = 1 /\ releases[q] = 0)
       /\ (reqPhase[q] = "Unused") =>
            (reqTag[q] = NoTag /\ allocated[q] = 0 /\ releases[q] = 0
             /\ everIssued[q] = 0)
       /\ (releases[q] = 1) <=>
            (allocated[q] = 1 /\ reqPhase[q] = "Terminal")
       /\ everIssued[q] <= allocated[q]
       /\ (reqTag[q] # NoTag) =>
            (GenOfS(reqTag[q][1]) = reqTag[q][2]
             /\ reqPhase[q] # "Unused")
  /\ \A q \in Q :
       /\ requeues[q] <= 1
       /\ (freed[q] = 1) <=> (requeues[q] = 1)
       /\ (freed[q] = 1) =>
            (allocated[q] = 1 /\ releases[q] = 1 /\ result[q] = "Close")
       /\ (allocated[q] = 0) => (freed[q] = 0 /\ requeues[q] = 0)
  /\ \A d \in D :
       /\ (dstate[d] = DActive0) <=>
            (reqPhase[R0] \in NT /\ demandOf[R0] = d)
       /\ (dstate[d] = DActive1) <=>
            (reqPhase[R1] \in NT /\ demandOf[R1] = d)
  /\ \A r \in Primary :
       (demandOf[r] # NoDemand) <=> (allocated[r] = 1)
  /\ \A q \in Q :
       (reqPhase[q] \in NT) => (demandOf[ParentQ(q)] \in D)
  /\ \A s \in Sess : (phase[s] = "Closed") => RequeueComplete(s)
  /\ \A r \in Primary :
       /\ (reqPhase[r] = "Fallback") =>
            (reqTag[PartnerOf(r)] # NoTag
             /\ allocated[PartnerOf(r)] = 1
             /\ reqPhase[PartnerOf(r)] \in NT)
       /\ (reqPhase[r] = "Terminal") =>
            (reqPhase[PartnerOf(r)] \in {"Unused", "Terminal"})
       /\ (reqPhase[PartnerOf(r)] = "Terminal") =>
            (reqPhase[r] = "Terminal")
       /\ (body[r] = "Published") =>
            (reqPhase[r] = "Terminal" /\ result[r] = "Success")
  /\ done => (~inputOpen /\ Settled)
  /\ (done) => (\A q \in Q : (freed[q] = 1) => (requeues[q] = 1))
  /\ (done) => (\A d \in D : dstate[d] \notin {DPending, DActive0, DActive1})

(***************************************************************************)
(* TransitionSafety: the edge obligations, checkable as a state invariant  *)
(* through the stepOK observer.                                           *)
(***************************************************************************)

TransitionSafety == stepOK

(***************************************************************************)
(* ConditionalProgress.                                                   *)
(*                                                                         *)
(* Why explicit expansions: Apalache 0.62.2 supports no WF or SF macros   *)
(* and no ENABLED primitive inside temporal properties, so weak fairness  *)
(* of each concrete internal action instance is written per appendix A.5  *)
(* as ( <>[] EnabledA ) => ( []<> TakenA ), where EnabledA is the action  *)
(* guard evaluated as a state predicate and TakenA is the nonstuttering   *)
(* action relation <<A>>_vars.  Every listed action has a guard that      *)
(* forces a state change, so each action equals its own nonstuttering     *)
(* form.  External starts, choices, and faults carry no fairness          *)
(* requirement.                                                           *)
(***************************************************************************)

\* State-level enabledness guards: the guard of each action instance
\* evaluated on the current state, with no primed variables.
\* @type: (Str) => Bool;
EnClose(s) == ~done /\ phase[s] \in {"Handshaking", "Established"}
\* @type: (Str) => Bool;
EnSettleClose(s) ==
  ~done /\ phase[s] = "Closing" /\ SettleCloseWork(s)
\* @type: (Str) => Bool;
EnFinishClose(s) ==
  /\ ~done
  /\ phase[s] = "Closing"
  /\ \A q \in Q : TaggedTo(q, s) => reqPhase[q] \notin NT
  /\ ~HasTagged(ctrl, s)
  /\ ~HasTagged(data, s)
  /\ ~HasTagged(partialIn, s)
  /\ ~HasTagged(partialOut, s)
  /\ ~controlDebt
  /\ RequeueComplete(s)
EnDone == ~done /\ ~inputOpen /\ Settled
EnServeControl ==
  ~done /\ Estab /\ ctrl # NoTok /\ ctrl[1] = current
  /\ partialOut = NoTok
EnWritePartial ==
  ~done /\ partialOut # NoTok /\ current # "None"
  /\ CurTransport \in {"Handshake", "CipherSession", "V1"}

FairCloseS0 ==
  ((<>[] EnClose(S0)) => ([]<> <<Close(S0)>>_vars))
FairCloseS1 ==
  ((<>[] EnClose(S1)) => ([]<> <<Close(S1)>>_vars))
FairSettleCloseS0 ==
  ((<>[] EnSettleClose(S0)) => ([]<> <<SettleClose(S0)>>_vars))
FairSettleCloseS1 ==
  ((<>[] EnSettleClose(S1)) => ([]<> <<SettleClose(S1)>>_vars))
FairFinishCloseS0 ==
  ((<>[] EnFinishClose(S0)) => ([]<> <<FinishClose(S0)>>_vars))
FairFinishCloseS1 ==
  ((<>[] EnFinishClose(S1)) => ([]<> <<FinishClose(S1)>>_vars))
FairDone == ((<>[] EnDone) => ([]<> <<Done>>_vars))
FairServeControl ==
  ((<>[] EnServeControl) => ([]<> <<ServeControl>>_vars))
FairWritePartial ==
  ((<>[] EnWritePartial) => ([]<> <<WritePartial>>_vars))

ConditionalProgress ==
  ((<> ~inputOpen)
   /\ FairCloseS0
   /\ FairCloseS1
   /\ FairSettleCloseS0
   /\ FairSettleCloseS1
   /\ FairFinishCloseS0
   /\ FairFinishCloseS1
   /\ FairDone
   /\ FairServeControl
   /\ FairWritePartial)
  =>
  ((<> done)
   /\ [] ((everIssued[R0] = 1) =>
           <> (reqPhase[R0] = "Terminal" /\ releases[R0] = 1))
   /\ [] ((everIssued[R1] = 1) =>
           <> (reqPhase[R1] = "Terminal" /\ releases[R1] = 1))
   /\ [] ((everIssued[F0] = 1) =>
           <> (reqPhase[F0] = "Terminal" /\ releases[F0] = 1))
   /\ [] ((everIssued[F1] = 1) =>
           <> (reqPhase[F1] = "Terminal" /\ releases[F1] = 1)))

(***************************************************************************)
(* End of module.                                                         *)
(***************************************************************************)
=============================================================================
