---- MODULE ChainAdmission ----
(***************************************************************************)
(* ChainAdmission: coordinated chain transitions and transaction           *)
(* admission, per the plan appendix "Coordinated chain transitions and     *)
(* transaction admission" (sections A and B) and the FTL appendix.         *)
(*                                                                         *)
(* Sections A and B form one model.  The finite fixture is literal:        *)
(* blocks G -> A -> B and G -> X; transactions t1 (spends g1, creates      *)
(* t1out) and t2 (spends t1out, creates t2out); block A confirms t1, B     *)
(* confirms t2, X carries the conflicting spend of g1.  Every variable     *)
(* ranges over the appendix domains only: no hidden clocks, no             *)
(* unbounded integers, no growing histories.                               *)
(*                                                                         *)
(* Next is the unrestricted union of every listed action plus stutter.     *)
(* Stutter is supplied by [][Next]_vars at the use sites; no fairness or   *)
(* priority occurs inside Next.  Weak fairness appears only inside the     *)
(* antecedent of ConditionalProgress, written as explicit                  *)
(* (<>[] ENABLED <<A>>_vars) => ([]<> <<A>>_vars) clauses because          *)
(* Apalache 0.62.2 supports no WF_/SF_ macros.                             *)
(*                                                                         *)
(* Block, coin, transaction and edge identifiers are small integers.       *)
(* Enum values are integers; the comments name each code.                  *)
(***************************************************************************)
(* NOTE: every multi-key EXCEPT (two-level function update) in this      *)
(* module is written in nested single-key form.  Apalache 0.62.2         *)
(* desugars a two-key EXCEPT through nullary LET helpers whose applied   *)
(* names carry a mismatched operator type; the temporal lane's inliner   *)
(* then fails with "Unable to unify the signature (() => (F)) of t_N$M   *)
(* with the type $callSiteType".  The nested form is the defining        *)
(* equivalence of EXCEPT (Specifying Systems p. 304):                    *)
(*   [f EXCEPT ![a][b] = v] == [f EXCEPT ![a] = [f[a] EXCEPT ![b] = v]] *)
(* Value-preserving in both directions; no other desugaring route in     *)
(* this module mints these helpers.                                      *)

EXTENDS Integers, Naturals, Sequences, FiniteSets

(*************************************************************************)
(* Constants (mirrored in the root CONSTRAINTS.md register).             *)
(* K = 128 is a verification bound passed on the command line, not a     *)
(* production limit and not a constant of this module.                   *)
(*************************************************************************)
CONSTANTS
  \* @type: Int;
  EventBudget,      (* external event credits: 0..EventBudget, named 12   *)
  \* @type: Int;
  JobSlots,         (* fixed chain/admission job slots, named 12          *)
  \* @type: Int;
  MaxAttempts,      (* four-attempt retry convention                      *)
  \* @type: Int;
  CounterBound,     (* monotone publication counters 0..CounterBound      *)
  \* @type: Int;
  FrameBound,       (* body/undo frame arrays 0..FrameBound, named 72     *)
  \* @type: Int;
  FactBound,        (* committed reconciliation facts, named 36           *)
  \* @type: Int;
  ReqSlots          (* admission request slots 1..ReqSlots, named 12      *)

(*************************************************************************)
(* Finite fixture carriers.                                              *)
(* Blocks: G = 0, A = 1, B = 2, X = 3.  NULLT = -1 marks an absent root. *)
(* Coins: g0 = 0, g1 = 1, a0 = 2, t1out = 3, b0 = 4, t2out = 5,          *)
(*        x0 = 6, x1 = 7.  Transactions: t1 = 0, t2 = 1.                 *)
(*************************************************************************)
G == 0
BLKA == 1
BLKB == 2
BLKX == 3
NULLT == -1

COIN_G1 == 1
COIN_T1OUT == 3

T1 == 0
T2 == 1

BlockHeight == [b \in {G, BLKA, BLKB, BLKX} |->
                  CASE b = G -> 0
                  []  b = BLKA -> 1
                  []  b = BLKB -> 2
                  []  b = BLKX -> 1]

RootCoins == [b \in {G, BLKA, BLKB, BLKX} |->
                CASE b = G -> {0, 1}
                []  b = BLKA -> {0, 2, 3}
                []  b = BLKB -> {0, 2, 4, 5}
                []  b = BLKX -> {0, 6, 7}]

(* Directed edges.  Codes: 0 = G->A connect, 1 = A->B connect,           *)
(* 2 = G->X connect, 3 = A->G disconnect, 4 = B->A disconnect,           *)
(* 5 = X->G disconnect.                                                  *)
EdgeFrom == [e \in 0..5 |->
               CASE e = 0 -> G   [] e = 1 -> BLKA [] e = 2 -> G
               []  e = 3 -> BLKA [] e = 4 -> BLKB [] e = 5 -> BLKX]
EdgeTo == [e \in 0..5 |->
             CASE e = 0 -> BLKA [] e = 1 -> BLKB [] e = 2 -> BLKX
             []  e = 3 -> G    [] e = 4 -> BLKA [] e = 5 -> G]
EdgeIsConn == [e \in 0..5 |-> e <= 2]

(* Simple re-root plans over the fixture tree, at most three edges.      *)
(* Plan codes: 0 = empty; 1..6 = the single edges 0..5;                  *)
(* 7 = <0,1> (G->A->B); 8 = <4,3> (B->A->G); 9 = <3,2> (A->G->X);        *)
(* 10 = <5,0> (X->G->A); 11 = <4,3,2> (B->A->G->X);                      *)
(* 12 = <5,0,1> (X->G->A->B).                                            *)
PlanLen(p) == CASE p = 0 -> 0
              []  p <= 6 -> 1
              []  p <= 10 -> 2
              []  OTHER -> 3

PE(p, k) == CASE p = 1 -> 0
            []  p = 2 -> 1
            []  p = 3 -> 2
            []  p = 4 -> 3
            []  p = 5 -> 4
            []  p = 6 -> 5
            []  p = 7 -> IF k = 1 THEN 0 ELSE 1
            []  p = 8 -> IF k = 1 THEN 4 ELSE 3
            []  p = 9 -> IF k = 1 THEN 3 ELSE 2
            []  p = 10 -> IF k = 1 THEN 5 ELSE 0
            []  p = 11 -> CASE k = 1 -> 4 [] k = 2 -> 3 [] OTHER -> 2
            []  OTHER -> CASE k = 1 -> 5 [] k = 2 -> 0 [] OTHER -> 1

PlanStart(p) == IF p = 0 THEN NULLT ELSE EdgeFrom[PE(p, 1)]
PlanEnd(p) == IF p = 0 THEN NULLT ELSE EdgeTo[PE(p, PlanLen(p))]

(* Frame value codes: 0 = Empty, else 1 + 3*block + height.              *)
(* (G,0) -> 1, (A,1) -> 5, (B,2) -> 9, (X,1) -> 11.                      *)
FrameCode(b, h) == 1 + 3 * b + h

(*************************************************************************)
(* State.  Root records carry the durable semantic root                  *)
(* R = (tip, height, CommitId, coins_version, coins, body_extent,        *)
(* undo_extent, refs); coins_version = CommitId per the appendix.        *)
(* refs maps (height, block, body|undo) to 0 (None) or a frame slot      *)
(* 1..FrameBound, flattened into the eight fields gb gu ab au xb xu      *)
(* bb bu over the valid (height, block) pairs.                           *)
(*************************************************************************)
VARIABLES
  \* @type: Int;
  epoch,
  \* @type: Int;
  generation,
  \* @type: Int;
  poolSeq,
  \* @type: Int;
  policyEpoch,
  \* @type: { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } };
  diskRoot,
  \* @type: { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } };
  liveRoot,
  \* @type: { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } };
  priorRoot,
  \* @type: { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } };
  proposedRoot,
  \* @type: Int -> Int;
  bodyFrames,
  \* @type: Int -> Int;
  undoFrames,
  \* @type: Int;
  bodyPos,
  \* @type: Int;
  undoPos,
  \* @type: Int;
  syncBody,
  \* @type: Int;
  syncUndo,
  \* @type: Bool;
  fileSync,
  \* @type: Bool;
  dirSync,
  \* @type: Set(Int);
  diskCands,
  \* @type: Int;
  eventsLeft,
  \* @type: Bool;
  inputClosed,
  \* @type: Int -> Int;
  jobReq,
  \* @type: Int -> Int;
  jobMode,
  \* @type: Int -> Int;
  jobAtt,
  \* @type: Int -> Int;
  jobPlan,
  \* @type: Int -> Int;
  jobCur,
  \* @type: Int -> (Int -> Int);
  jobEv,
  \* @type: Int -> { se: Int, sg: Int, stip: Int, sseq: Int, spol: Int };
  jobStamp,
  \* @type: Int -> Int;
  jobOutcome,
  \* @type: { ce: Int, cj: Int, cc: Int };
  compId,
  \* @type: Int;
  compStatus,
  \* @type: Bool;
  unresComp,
  \* @type: Int;
  chainPhase,
  \* @type: Int;
  faultKind,
  \* @type: Int;
  lifePhase,
  \* @type: Set(Int);
  pool,
  \* @type: Set(Int);
  relay,
  \* @type: { n: Int, x: Int, y: Int };
  detached,
  \* @type: Int;
  poolTagE,
  \* @type: Int;
  poolTagC,
  \* @type: Set(Int);
  estAcct,
  \* @type: Int -> { c: Int, e: Int };
  reconFacts,
  \* @type: Int;
  factN,
  \* @type: Int;
  pubTip,
  \* @type: Int;
  pubHeight,
  \* @type: Int;
  pubVer,
  \* @type: Int;
  pubGen,
  \* @type: Bool;
  rootRec,
  \* @type: Bool;
  poolRec,
  \* @type: Bool;
  backend,
  \* @type: Bool;
  pendNotif,
  \* @type: Int -> { n: Int, x: Int, y: Int };
  reqTxs,
  \* @type: Int -> { n: Int, x: Int, y: Int };
  reqRes,
  \* @type: Int -> Bool;
  reqOcc,
  \* @type: Int -> Bool;
  reqFin,
  \* @type: Int -> Int;
  reqMode,
  \* @type: Int -> Int;
  reqStage,
  \* @type: Int -> Int;
  reqAtt,
  \* @type: Int -> Int;
  reqOrigin,
  \* @type: Int -> Int;
  reqFeeLim,
  \* @type: Int -> (Int -> Int);
  reqFacts,
  \* @type: Int -> (Int -> Int);
  bJob,
  \* @type: Int -> (Int -> Int);
  bJobAtt,
  \* @type: Int;
  lockOwner,
  \* @type: Int;
  chainRes,
  \* @type: Bool;
  writerHeld,
  \* @type: Bool;
  readerHeld,
  \* @type: Bool;
  subscribed,
  \* @type: Int;
  subId,
  \* @type: Int;
  obsQN,
  \* @type: Int;
  obsQRec,
  \* @type: Bool;
  obsDel,
  \* @type: Int;
  obsDelRec,
  \* @type: Bool;
  gap,
  \* @type: Bool;
  delReady,
  \* @type: Bool;
  deadlineExp,
  \* @type: Int;
  compCredits,
  \* @type: Bool;
  stepOK
(*************************************************************************)
(* Variable groups.  Each action assigns every variable it touches and   *)
(* lists every fully untouched group as UNCHANGED; a group with only     *)
(* some members touched gets explicit x' = x assignments for its         *)
(* untouched members, so every primed variable is determined in every    *)
(* transition.  chainPhase, faultKind, lifePhase and the lock flags      *)
(* have their own tuples because most actions touch only one of them.    *)
(* stepOK is assigned once, hoisted into Next over the action union.  *)
(*************************************************************************)
\* @type: <<Int, Int, Int, Int>>;
VCtr == <<epoch, generation, poolSeq, policyEpoch>>
\* @type: <<{ tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } }, { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } }, { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } }, { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } }>>;
VRoot == <<diskRoot, liveRoot, priorRoot, proposedRoot>>
\* @type: <<Int -> Int, Int -> Int, Int, Int, Int, Int, Bool, Bool, Set(Int)>>;
VFrm == <<bodyFrames, undoFrames, bodyPos, undoPos, syncBody, syncUndo,
          fileSync, dirSync, diskCands>>
\* @type: <<Int, Bool>>;
VEnv == <<eventsLeft, inputClosed>>
\* @type: <<Int -> Int, Int -> Int, Int -> Int, Int -> Int, Int -> Int, Int -> (Int -> Int), Int -> { se: Int, sg: Int, stip: Int, sseq: Int, spol: Int }, Int -> Int>>;
VJob == <<jobReq, jobMode, jobAtt, jobPlan, jobCur, jobEv, jobStamp,
          jobOutcome>>
\* @type: <<{ ce: Int, cj: Int, cc: Int }, Int, Bool>>;
VCmp == <<compId, compStatus, unresComp>>
\* @type: <<Int>>;
VCP == <<chainPhase>>
\* @type: <<Set(Int), Set(Int), { n: Int, x: Int, y: Int }, Int, Int, Set(Int), Int -> { c: Int, e: Int }, Int>>;
VPl == <<pool, relay, detached, poolTagE, poolTagC, estAcct, reconFacts,
         factN>>
\* @type: <<Int, Int, Int, Int>>;
VPub == <<pubTip, pubHeight, pubVer, pubGen>>
\* @type: <<Bool, Bool, Bool, Bool>>;
VFlg == <<rootRec, poolRec, backend, pendNotif>>
\* @type: <<Int -> { n: Int, x: Int, y: Int }, Int -> { n: Int, x: Int, y: Int }, Int -> Bool, Int -> Bool, Int -> Int, Int -> Int, Int -> Int, Int -> Int, Int -> Int, Int -> (Int -> Int), Int -> (Int -> Int), Int -> (Int -> Int)>>;
VReq == <<reqTxs, reqRes, reqOcc, reqFin, reqMode, reqStage, reqAtt,
          reqOrigin, reqFeeLim, reqFacts, bJob, bJobAtt>>
\* @type: <<Int>>;
VFk == <<faultKind>>
\* @type: <<Int>>;
VLP == <<lifePhase>>
\* @type: <<Int>>;
VCO == <<lockOwner>>
\* @type: <<Int>>;
VCR == <<chainRes>>
\* @type: <<Bool>>;
VWH == <<writerHeld>>
\* @type: <<Bool>>;
VRH == <<readerHeld>>
\* @type: <<Bool, Int, Int, Int, Bool, Int, Bool, Bool, Bool>>;
VObs == <<subscribed, subId, obsQN, obsQRec, obsDel, obsDelRec, gap,
          delReady, deadlineExp>>
\* @type: <<Int>>;
VCr == <<compCredits>>
(* This front end predates the %-modulo operator; Mod2 is x mod 2 for   *)
(* nonnegative x via integer division.                                  *)
\* @type: (Int) => Int;
Mod2(x) == x - 2 * (x \div 2)

(*************************************************************************)
(* Root and stamp helpers.                                               *)
(* jobReq codes: 0 = none; 1..4 = Chain(tip 0..3); 5 = Tx t1; 6 = Tx t2. *)
(* jobMode: 0 none, 1 Preview, 2 Commit.                                 *)
(* jobEv / bJob entry codes: 0 Absent, 1 Prepared/Pending, 2 Valid,      *)
(* 3 Invalid/Pass, 4 Stale/Fail.  bJob per-position: 2 = Running.        *)
(* jobOutcome: 0 Pending, 1 Success, 2 Invalid, 3 Busy, 4 Unavailable,   *)
(* 5 IoFailure.                                                          *)
(* compStatus: 0 unresolved, 1 success, 2 failure, 3 ambiguous,          *)
(* 4 consumed.                                                           *)
(* chainPhase: 1 Idle, 2 Reserved, 3 Closed, 4 Appended, 5 Synced,       *)
(* 6 Batch, 7 Received, 8 Reconciled, 9 Published, 10 Recovering,        *)
(* 11 Done.  lifePhase: 1 Running, 2 Settled, 3 Done.                    *)
(* faultKind: 0 None, 1 Crash, 2 Io, 3 CallbackLoss.                     *)
(* reqStage: 0 Idle, 1 Snapshot, 2 Verify, 3 RecheckAndCommit, 4 Retry,  *)
(* 5 Finish, 6 Finished.  reqRes row: 0 none, 1 accept, 2 reject,        *)
(* 3 orphan, 4 already known.                                            *)
(* reqFeeLim class: 0 Absent, 1 Below, 2 At, 3 Above.                    *)
(*************************************************************************)
NoRefs == [gb |-> 0, gu |-> 0, ab |-> 0, au |-> 0,
           xb |-> 0, xu |-> 0, bb |-> 0, bu |-> 0]

\* @type: (Int, Int, Int, Int, { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int }) => { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } };
MkRoot(t, c, be, ue, rf) ==
  [tip |-> t, height |-> IF t = NULLT THEN 0 ELSE BlockHeight[t],
   cid |-> c, ver |-> c,
   coins |-> IF t = NULLT THEN {} ELSE RootCoins[t],
   be |-> be, ue |-> ue, refs |-> rf]

RootG(c) == MkRoot(G, c, 0, 0, NoRefs)

NullRoot == MkRoot(NULLT, 0, 0, 0, NoRefs)

NoStamp == [se |-> -1, sg |-> 0, stip |-> 0, sseq |-> 0, spol |-> 0]

MkStamp == [se |-> epoch, sg |-> generation, stip |-> liveRoot.tip,
            sseq |-> poolSeq, spol |-> policyEpoch]

\* @type: ({ se: Int, sg: Int, stip: Int, sseq: Int, spol: Int }) => Bool;
StampOK(st) ==
  st.se = epoch /\ st.sg = generation /\ st.stip = liveRoot.tip
    /\ st.sseq = poolSeq /\ st.spol = policyEpoch

\* @type: ({ gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int }, Int, Int, Int) => { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int };
SetRef(rf, b, bv, uv) ==
  CASE b = 0 -> [rf EXCEPT !.gb = bv, !.gu = uv]
  []  b = 1 -> [rf EXCEPT !.ab = bv, !.au = uv]
  []  b = 2 -> [rf EXCEPT !.bb = bv, !.bu = uv]
  []  OTHER -> [rf EXCEPT !.xb = bv, !.xu = uv]

\* @type: ({ gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int }, Int) => Int;
RefBody(rf, b) == CASE b = 0 -> rf.gb
                  []  b = 1 -> rf.ab
                  []  b = 2 -> rf.bb
                  []  OTHER -> rf.xb

\* @type: ({ gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int }, Int) => Int;
RefUndo(rf, b) == CASE b = 0 -> rf.gu
                  []  b = 1 -> rf.au
                  []  b = 2 -> rf.bu
                  []  OTHER -> rf.xu

\* @type: ({ tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } }, Int, Int, Int) => { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } };
RootAfterConn(root, e, bp, up) ==
  [root EXCEPT !.tip = EdgeTo[e], !.height = BlockHeight[EdgeTo[e]],
   !.cid = root.cid + 1, !.ver = root.cid + 1,
   !.coins = RootCoins[EdgeTo[e]],
   !.be = root.be + 1, !.ue = root.ue + 1,
   !.refs = SetRef(root.refs, EdgeTo[e], bp, up)]

\* @type: ({ tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } }, Int) => { tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } };
RootAfterDisc(root, e) ==
  [root EXCEPT !.tip = EdgeTo[e], !.height = BlockHeight[EdgeTo[e]],
   !.cid = root.cid + 1, !.ver = root.cid + 1,
   !.coins = RootCoins[EdgeTo[e]],
   !.refs = SetRef(root.refs, EdgeFrom[e], 0, 0)]

(* A referenced frame counts as durable exactly when its slot lies       *)
(* within the synced bound and the stored frame matches the referenced   *)
(* (height, block) pair.  Orphan append tails beyond the synced bounds   *)
(* are never authoritative.                                              *)
\* @type: (Int, Int, Int, Int -> Int) => Bool;
RefOkBV(v, bound, code, fr) == v = 0 \/ (v <= bound /\ fr[v] = code)

\* @type: ({ tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } }, Int, Int, Int -> Int, Int -> Int) => Bool;
DurableRefs(root, sb, su, bf, uf) ==
  /\ RefOkBV(root.refs.gb, sb, 1, bf)
  /\ RefOkBV(root.refs.gu, su, 1, uf)
  /\ RefOkBV(root.refs.ab, sb, 5, bf)
  /\ RefOkBV(root.refs.au, su, 5, uf)
  /\ RefOkBV(root.refs.bb, sb, 9, bf)
  /\ RefOkBV(root.refs.bu, su, 9, uf)
  /\ RefOkBV(root.refs.xb, sb, 11, bf)
  /\ RefOkBV(root.refs.xu, su, 11, uf)

\* @type: ({ tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } }) => Bool;
ValidRootShape(r) ==
  \/ r.tip = NULLT
  \/ /\ r.tip \in {G, BLKA, BLKB, BLKX}
     /\ r.height = BlockHeight[r.tip]
     /\ r.coins = RootCoins[r.tip]
     /\ r.ver = r.cid
     /\ r.cid <= CounterBound
     /\ r.be <= FrameBound /\ r.ue <= FrameBound
     /\ \A v \in {r.refs.gb, r.refs.gu, r.refs.ab, r.refs.au,
                  r.refs.xb, r.refs.xu, r.refs.bb, r.refs.bu}:
          v \in 0..FrameBound

(*************************************************************************)
(* Detached re-admission queue: ordered, duplicate free, length <= 2.    *)
(* Encoded as [n, x, y]; -1 marks an empty slot.                         *)
(*************************************************************************)
DetEmpty == [n |-> 0, x |-> -1, y |-> -1]

\* @type: ({ n: Int, x: Int, y: Int }, Int) => Bool;
DetMem(d, t) == (d.n >= 1 /\ d.x = t) \/ (d.n = 2 /\ d.y = t)

\* @type: ({ n: Int, x: Int, y: Int }, Int) => { n: Int, x: Int, y: Int };
DetAdd(d, t) ==
  IF t < 0 THEN d
  ELSE IF d.n = 0 THEN [n |-> 1, x |-> t, y |-> -1]
  ELSE IF d.n = 1 /\ d.x # t THEN [n |-> 2, x |-> d.x, y |-> t]
  ELSE d

\* @type: ({ n: Int, x: Int, y: Int }) => { n: Int, x: Int, y: Int };
DetShift(d) == CASE d.n = 0 -> d
               []  d.n = 1 -> DetEmpty
               []  OTHER -> [n |-> 1, x |-> d.y, y |-> -1]

\* @type: ({ n: Int, x: Int, y: Int }, Int) => { n: Int, x: Int, y: Int };
DetDel(d, t) ==
  CASE d.n = 0 -> d
  []  d.n = 1 -> IF d.x = t THEN DetEmpty ELSE d
  []  OTHER -> IF d.x = t THEN [n |-> 1, x |-> d.y, y |-> -1]
               ELSE IF d.y = t THEN [n |-> 1, x |-> d.x, y |-> -1]
               ELSE d

(* |S| <= 2, so two unrolled deletions suffice; no recursion.            *)
\* @type: ({ n: Int, x: Int, y: Int }, Set(Int)) => { n: Int, x: Int, y: Int };
DetRemoveAll(d, S) ==
  LET d1 == IF S = {} THEN d ELSE DetDel(d, CHOOSE t \in S : TRUE)
      s1 == IF S = {} THEN {} ELSE S \ {CHOOSE t \in S : TRUE}
  IN IF s1 = {} THEN d1 ELSE DetDel(d1, CHOOSE t \in s1 : TRUE)

(*************************************************************************)
(* Admission fixture facts.  Spends(t1) = {g1}, Spends(t2) = {t1out};    *)
(* Created(t1) = {t1out}, Created(t2) = {t2out}.  ConfirmedBy names the  *)
(* pool transactions a connect edge confirms; SpendSet names the coins   *)
(* the tip's included transactions spend.                                *)
(*************************************************************************)
TxSpends(t) == IF t = T1 THEN {COIN_G1} ELSE {COIN_T1OUT}
TxCreated(t) == IF t = T1 THEN {COIN_T1OUT} ELSE {5}

ValidUnder(t, tip) == tip # NULLT /\ TxSpends(t) \subseteq RootCoins[tip]

ConfirmedBy(tip) == CASE tip = BLKA -> {T1}
                    []  tip = BLKB -> {T2}
                    []  OTHER -> {}

SpendSet(tip) == CASE tip = BLKA -> {COIN_G1}
                 []  tip = BLKB -> {COIN_T1OUT}
                 []  tip = BLKX -> {COIN_G1}
                 []  OTHER -> {}

(*************************************************************************)
(* Edge effect on (pool, detached) for one reconciliation edge, per the  *)
(* canonical named lifecycle: connects confirm and remove conflicts      *)
(* with their dependents; disconnects detach entries invalid under the   *)
(* parent and detach valid candidates absent from the pool.              *)
(*************************************************************************)
\* @type: (Int, { p: Set(Int), d: { n: Int, x: Int, y: Int } }) => { p: Set(Int), d: { n: Int, x: Int, y: Int } };
EdgeEff(e, pd) ==
  IF EdgeIsConn[e]
    THEN LET cf == pd.p \cap ConfirmedBy(EdgeTo[e])
             fl == {t \in (pd.p \ cf) :
                      TxSpends(t) \cap SpendSet(EdgeTo[e]) # {}}
             ds == {t \in (pd.p \ (cf \cup fl)) :
                      \E c \in fl : TxCreated(c) \cap TxSpends(t) # {}}
         IN [p |-> pd.p \ (cf \cup fl \cup ds), d |-> pd.d]
    ELSE LET bad == {t \in pd.p : ~ValidUnder(t, EdgeTo[e])}
             np == pd.p \ bad
             cands == {t \in {T1, T2} :
                         ValidUnder(t, EdgeTo[e]) /\ t \notin np}
         IN [p |-> np,
             d |-> DetAdd(DetAdd(pd.d, IF bad = {} THEN -1
                                       ELSE CHOOSE t \in bad : TRUE),
                          IF cands = {} THEN -1
                            ELSE CHOOSE t \in cands : TRUE)]

(*************************************************************************)
(* Sigop costs are owner-computed fixture facts (resolved prevouts):     *)
(* representatives from the appendix boundary set {0, 15999, 16000,      *)
(* 16001}.  The 16000 limit is enforced in RowVerdict.                   *)
(*************************************************************************)
SIGOP_LIMIT == 16000
SigopsOf(t) == IF t = T1 THEN 15999 ELSE 16000

\* @type: (Int, Int) => Int;
TxOf(r, q) == IF q = 1 THEN reqTxs[r].x ELSE reqTxs[r].y

(* Deterministic per-row verdict, shared by preview and commit so both   *)
(* quote the same classification: script failure, missing input, fee     *)
(* floor, max fee, sigops, already known, accept.                        *)
\* @type: (Int, Int) => Int;
RowVerdict(r, q) ==
  IF reqTxs[r].n = 2 /\ reqTxs[r].x = reqTxs[r].y THEN 2
  ELSE IF bJob[r][q] = 4 THEN 2
  ELSE IF reqFacts[r][q] < 0 THEN 3
  ELSE IF reqFeeLim[r] = 1 THEN 2
  ELSE IF reqFeeLim[r] = 3 THEN 2
  ELSE IF SigopsOf(TxOf(r, q)) > SIGOP_LIMIT THEN 2
  ELSE IF TxOf(r, q) \in pool THEN 4
  ELSE 1

(* Owner-computed fact for one input: resolved coin, or Missing.         *)
(* t1 needs g1 in the committed set; t2 needs t1out confirmed or         *)
(* created by an admitted pool transaction (the pool overlay).           *)
\* @type: (Int, Int) => Int;
FactFor(r, q) ==
  IF q > reqTxs[r].n THEN -2
  ELSE IF TxOf(r, q) = T1
    THEN IF COIN_G1 \in liveRoot.coins THEN COIN_G1 ELSE -2
    ELSE IF COIN_T1OUT \in liveRoot.coins \/ T1 \in pool THEN COIN_T1OUT
    ELSE -2

(* Reservation argument: before any allocating start, the counters      *)
(* reserve the worst remaining internal increments of the bounded path   *)
(* (three edges per event: three commits, six fence flips, one epoch,    *)
(* one pool sequence step, one policy step, three facts).                *)
Headroom ==
  /\ liveRoot.cid + 3 * eventsLeft <= CounterBound
  /\ generation + 6 * eventsLeft <= CounterBound
  /\ epoch + eventsLeft <= CounterBound
  /\ poolSeq + eventsLeft <= CounterBound
  /\ policyEpoch + eventsLeft <= CounterBound
  /\ factN + 3 * eventsLeft <= FactBound

(*************************************************************************)
(* Init: authoritative disk and live root at G with CommitId 0, no       *)
(* frames, even generation, empty pool, all slots unused, budget full.   *)
(*************************************************************************)
Init ==
  /\ epoch' = 0 /\ generation' = 0 /\ poolSeq' = 0 /\ policyEpoch' = 0
  /\ diskRoot' = RootG(0) /\ liveRoot' = RootG(0)
  /\ priorRoot' = NullRoot /\ proposedRoot' = NullRoot
  /\ bodyFrames' = [i \in 1..FrameBound |-> 0]
  /\ undoFrames' = [i \in 1..FrameBound |-> 0]
  /\ bodyPos' = 0 /\ undoPos' = 0
  /\ syncBody' = 0 /\ syncUndo' = 0
  /\ fileSync' = FALSE /\ dirSync' = FALSE
  /\ diskCands' = {}
  /\ eventsLeft' = EventBudget /\ inputClosed' = FALSE
  /\ jobReq' = [s \in 1..JobSlots |-> 0]
  /\ jobMode' = [s \in 1..JobSlots |-> 0]
  /\ jobAtt' = [s \in 1..JobSlots |-> 0]
  /\ jobPlan' = [s \in 1..JobSlots |-> 0]
  /\ jobCur' = [s \in 1..JobSlots |-> 0]
  /\ jobEv' = [s \in 1..JobSlots |-> [q \in 1..3 |-> 0]]
  /\ jobStamp' = [s \in 1..JobSlots |-> NoStamp]
  /\ jobOutcome' = [s \in 1..JobSlots |-> 0]
  /\ compId' = [ce |-> -1, cj |-> 0, cc |-> 0]
  /\ compStatus' = 0 /\ unresComp' = FALSE
  /\ chainPhase' = 1 /\ faultKind' = 0 /\ lifePhase' = 1
  /\ pool' = {} /\ relay' = {} /\ detached' = DetEmpty
  /\ poolTagE' = -1 /\ poolTagC' = 0
  /\ estAcct' = {}
  /\ reconFacts' = [i \in 1..FactBound |-> [c |-> 0, e |-> -1]]
  /\ factN' = 0
  /\ pubTip' = G /\ pubHeight' = 0 /\ pubVer' = 0 /\ pubGen' = 0
  /\ rootRec' = TRUE /\ poolRec' = TRUE /\ backend' = TRUE
  /\ pendNotif' = FALSE
  /\ reqTxs' = [r \in 1..ReqSlots |-> [n |-> 0, x |-> -1, y |-> -1]]
  /\ reqRes' = [r \in 1..ReqSlots |-> [n |-> 0, x |-> 0, y |-> 0]]
  /\ reqOcc' = [r \in 1..ReqSlots |-> FALSE]
  /\ reqFin' = [r \in 1..ReqSlots |-> FALSE]
  /\ reqMode' = [r \in 1..ReqSlots |-> 0]
  /\ reqStage' = [r \in 1..ReqSlots |-> 0]
  /\ reqAtt' = [r \in 1..ReqSlots |-> 0]
  /\ reqOrigin' = [r \in 1..ReqSlots |-> 0]
  /\ reqFeeLim' = [r \in 1..ReqSlots |-> 0]
  /\ reqFacts' = [r \in 1..ReqSlots |-> [q \in 1..2 |-> -2]]
  /\ bJob' = [r \in 1..ReqSlots |-> [q \in 1..2 |-> 0]]
  /\ bJobAtt' = [r \in 1..ReqSlots |-> [q \in 1..2 |-> 0]]
  /\ lockOwner' = 0 /\ chainRes' = 0
  /\ writerHeld' = FALSE /\ readerHeld' = FALSE
  /\ subscribed' = FALSE /\ subId' = 0
  /\ obsQN' = 0 /\ obsQRec' = 0
  /\ obsDel' = FALSE /\ obsDelRec' = 0
  /\ gap' = FALSE /\ delReady' = FALSE /\ deadlineExp' = FALSE
  /\ compCredits' = CounterBound
  /\ stepOK' = TRUE
(*************************************************************************)
(* TypeOK: every variable belongs to its appendix domain, slot vectors   *)
(* are consistent, allocation tags are valid, attempts are bounded, and  *)
(* reserved capacity stays nonnegative.                                  *)
(*************************************************************************)
\* @type: ({ n: Int, x: Int, y: Int }) => Bool;
DetOK(d) ==
  /\ d.n \in 0..2 /\ d.x \in {-1, T1, T2} /\ d.y \in {-1, T1, T2}
  /\ (d.n = 0 => (d.x = -1 /\ d.y = -1))
  /\ (d.n = 1 => d.y = -1)
  /\ (d.n = 2 => (d.x # d.y))

(* InitPred removed: Apalache explores only Init/Next behaviors, so the    *)
(* checker supplies both conjuncts by construction; carrying them inside    *)
(* ConditionalProgress duplicated the full Next relation under the         *)
(* loop-finding transformation without verifying anything additional.      *)
\* @type: ({ n: Int, x: Int, y: Int }) => Bool;
ReqSeqOK(q) ==
  /\ q.n \in 0..2 /\ q.x \in {-1, T1, T2} /\ q.y \in {-1, T1, T2}
  /\ (q.n = 0 => (q.x = -1 /\ q.y = -1))
  /\ (q.n = 1 => q.y = -1)
  /\ (q.n = 2 => (q.x # q.y \/ q.x = -1))

\* @type: ({ n: Int, x: Int, y: Int }) => Bool;
ResRowOK(q) == q.n \in 0..2 /\ q.x \in 0..4 /\ q.y \in 0..4
             /\ (q.n <= 1 => q.y = 0)

\* @type: ({ se: Int, sg: Int, stip: Int, sseq: Int, spol: Int }) => Bool;
StampOKShape(st) ==
  \/ st.se = -1
  \/ /\ st.se \in 0..CounterBound /\ st.sg \in 0..CounterBound
     /\ st.stip \in {G, BLKA, BLKB, BLKX}
     /\ st.sseq \in 0..CounterBound /\ st.spol \in 0..CounterBound

\* @type: ({ tip: Int, height: Int, cid: Int, ver: Int, coins: Set(Int), be: Int, ue: Int, refs: { gb: Int, gu: Int, ab: Int, au: Int, xb: Int, xu: Int, bb: Int, bu: Int } }) => Bool;
RootFieldsOK(r) ==
  \A v \in {r.refs.gb, r.refs.gu, r.refs.ab, r.refs.au,
            r.refs.xb, r.refs.xu, r.refs.bb, r.refs.bu}:
    v \in 0..FrameBound

TypeOK ==
  /\ epoch \in 0..CounterBound
  /\ generation \in 0..CounterBound
  /\ poolSeq \in 0..CounterBound
  /\ policyEpoch \in 0..CounterBound
  /\ ValidRootShape(diskRoot) /\ RootFieldsOK(diskRoot)
  /\ ValidRootShape(liveRoot) /\ RootFieldsOK(liveRoot)
  /\ ValidRootShape(priorRoot) /\ RootFieldsOK(priorRoot)
  /\ ValidRootShape(proposedRoot) /\ RootFieldsOK(proposedRoot)
  /\ \A v \in ({bodyFrames[i] : i \in 1..FrameBound} \cup
                 {undoFrames[i] : i \in 1..FrameBound}):
       v = 0 \/ v \in {1, 5, 9, 11}
  /\ bodyPos \in 0..FrameBound /\ undoPos \in 0..FrameBound
  /\ syncBody \in 0..FrameBound /\ syncUndo \in 0..FrameBound
  /\ syncBody <= bodyPos /\ syncUndo <= undoPos
  /\ fileSync \in BOOLEAN /\ dirSync \in BOOLEAN
  /\ diskCands \subseteq {1, 2}
  /\ eventsLeft \in 0..EventBudget
  /\ inputClosed \in BOOLEAN
  /\ \A s \in 1..JobSlots:
       /\ jobReq[s] \in 0..6
       /\ jobMode[s] \in 0..2
       /\ jobAtt[s] \in 0..MaxAttempts
       /\ jobPlan[s] \in 0..12
       /\ jobCur[s] \in 0..3
       /\ jobCur[s] <= PlanLen(jobPlan[s])
       /\ \A q \in 1..3: jobEv[s][q] \in 0..4
       /\ StampOKShape(jobStamp[s])
       /\ jobOutcome[s] \in 0..5
       /\ (jobReq[s] = 0 =>
             (jobAtt[s] = 0 /\ jobPlan[s] = 0 /\ jobCur[s] = 0
                /\ jobOutcome[s] = 0 /\ jobMode[s] = 0))
       /\ (jobReq[s] # 0 => jobAtt[s] >= 1)
  /\ compId.ce \in -1..CounterBound
  /\ compId.cj \in 0..JobSlots
  /\ compId.cc \in 0..CounterBound
  /\ (compId.ce = -1 => compId.cc = 0)
  /\ compStatus \in 0..4
  /\ unresComp \in BOOLEAN
  /\ chainPhase \in 1..11
  /\ faultKind \in 0..3
  /\ lifePhase \in 1..3
  /\ pool \subseteq {T1, T2}
  /\ relay \subseteq {T1, T2}
  /\ DetOK(detached)
  /\ poolTagE \in -1..CounterBound
  /\ poolTagC \in 0..CounterBound
  /\ (poolTagE = -1 => poolTagC = 0)
  /\ estAcct \subseteq 1..FactBound
  /\ factN \in 0..FactBound
  /\ \A i \in 1..FactBound:
       /\ reconFacts[i].c \in 0..CounterBound
       /\ reconFacts[i].e \in ({-1} \cup 0..5)
       /\ (i <= factN <=> reconFacts[i].e # -1)
  /\ pubTip \in {G, BLKA, BLKB, BLKX}
  /\ pubHeight = BlockHeight[pubTip]
  /\ pubVer \in 0..CounterBound /\ pubGen \in 0..CounterBound
  /\ Mod2(pubGen) = 0
  /\ rootRec \in BOOLEAN /\ poolRec \in BOOLEAN
  /\ backend \in BOOLEAN /\ pendNotif \in BOOLEAN
  /\ \A r \in 1..ReqSlots:
       /\ ReqSeqOK(reqTxs[r]) /\ ResRowOK(reqRes[r])
       /\ reqOcc[r] \in BOOLEAN /\ reqFin[r] \in BOOLEAN
       /\ reqMode[r] \in 0..2
       /\ reqStage[r] \in 0..6
       /\ reqAtt[r] \in 0..MaxAttempts
       /\ reqOrigin[r] \in 0..5
       /\ reqFeeLim[r] \in 0..3
       /\ \A q \in 1..2:
            /\ reqFacts[r][q] \in ({-2, -1} \cup 0..7)
            /\ bJob[r][q] \in 0..4
            /\ bJobAtt[r][q] \in 0..MaxAttempts
       /\ (reqTxs[r].n = 1 => reqFacts[r][2] = -2 /\ bJob[r][2] = 0)
       /\ (~reqOcc[r] =>
             (reqStage[r] = 0 /\ reqAtt[r] = 0 /\ ~reqFin[r]
                /\ reqMode[r] = 0 /\ reqTxs[r].n = 0))
  /\ lockOwner \in 0..3
  /\ chainRes \in 0..JobSlots
  /\ writerHeld \in BOOLEAN /\ readerHeld \in BOOLEAN
  /\ subscribed \in BOOLEAN
  /\ subId \in 0..ReqSlots
  /\ obsQN \in 0..1 /\ obsQRec \in 0..CounterBound
  /\ obsDel \in BOOLEAN /\ obsDelRec \in 0..CounterBound
  /\ gap \in BOOLEAN /\ delReady \in BOOLEAN /\ deadlineExp \in BOOLEAN
  /\ compCredits \in 0..CounterBound
  /\ stepOK \in BOOLEAN
  /\ (obsQN = 1 => subscribed)
  /\ (obsDel => subscribed)
  /\ (obsQN = 1 => ~obsDel)

(*************************************************************************)
(* Safety: durable-prefix, exact-undo, branch-identity, coherent         *)
(* publication, full-stamp provenance, no proof over unresolved inputs,  *)
(* accounting exactness, observer bounds, and honest terminal facts.     *)
(*************************************************************************)
Safety ==
  /\ (diskCands = {} => diskRoot = liveRoot)
  /\ (diskCands = {1} => diskRoot = priorRoot)
  /\ (diskCands = {1, 2} =>
        diskRoot = priorRoot \/ diskRoot = proposedRoot)
  /\ (diskRoot.tip # NULLT =>
       liveRoot = diskRoot \/ diskCands # {})
  /\ DurableRefs(diskRoot, syncBody, syncUndo, bodyFrames, undoFrames)
  /\ liveRoot.coins = RootCoins[liveRoot.tip]
  /\ diskRoot.coins = RootCoins[diskRoot.tip]
  /\ liveRoot.height = BlockHeight[liveRoot.tip]
  /\ liveRoot.ver = liveRoot.cid
  /\ pubHeight = BlockHeight[pubTip]
  /\ pubVer <= diskRoot.cid
  /\ \A s \in 1..JobSlots:
       (jobStamp[s].se # -1 =>
          jobStamp[s].se <= epoch /\ jobStamp[s].sg <= generation)
  /\ \A r \in 1..ReqSlots, q \in 1..2:
       (bJob[r][q] = 3 => reqFacts[r][q] >= 0)
  /\ \A i \in estAcct: reconFacts[i].e # -1
  /\ ~writerHeld /\ ~readerHeld
  /\ (chainPhase = 11 => inputClosed)
  /\ (lifePhase # 1 => inputClosed)
  /\ (Mod2(generation) = 1) => chainPhase \in {3, 4, 5, 6, 7, 8, 10}
  /\ (Mod2(generation) = 0) => chainPhase \in {1, 2, 9, 10, 11}
  /\ (chainPhase \in {2, 3, 4, 5, 6, 7} => chainRes # 0)
  /\ (chainRes # 0 => jobReq[chainRes] \in 1..4)
  /\ (compStatus = 3 => chainPhase = 10)
  /\ (unresComp => (compStatus = 0 \/ compStatus = 3))
  /\ (chainPhase = 10 => faultKind # 0)
  /\ (faultKind = 3 => chainPhase # 10)
  /\ (poolTagE # -1 => poolTagE <= epoch /\ poolTagC <= diskRoot.cid)
  /\ (pendNotif => obsQN = 1)

(*************************************************************************)
(* StepSafe: the edge observer behind TransitionSafety.  Next conjoins   *)
(* stepOK' = StepSafe once over the action union, so the invariant       *)
(* stepOK holds exactly when every edge taken so far satisfied the       *)
(* transition obligations: reservation before the fence, no reopening    *)
(* before durable recovery and reconciliation, no speculative            *)
(* publication,                                                          *)
(* full-stamp recheck before install, one sequence increment per         *)
(* mutation and none for preview or retry, discarded evidence on retry,  *)
(* committed-only observer offers, overflow records a gap, monotone      *)
(* counters without wrap, and terminal absorption.                       *)
(*************************************************************************)
StepSafe ==
  /\ \A j \in 1..JobSlots: (jobReq[j] # 0 => jobReq'[j] = jobReq[j])
  /\ epoch' >= epoch /\ epoch' <= CounterBound
  /\ generation' >= generation /\ generation' <= CounterBound
  /\ poolSeq' >= poolSeq /\ poolSeq' <= CounterBound
  /\ policyEpoch' >= policyEpoch /\ policyEpoch' <= CounterBound
  /\ liveRoot'.cid >= liveRoot.cid
  /\ liveRoot'.cid <= CounterBound
  /\ factN' >= factN
  /\ bodyPos' >= bodyPos /\ undoPos' >= undoPos
  /\ syncBody' >= syncBody /\ syncUndo' >= syncUndo
  /\ pubVer' >= pubVer /\ pubGen' >= pubGen
  /\ (generation' # generation => generation' = generation + 1)
  /\ (Mod2(generation') = 1 /\ Mod2(generation) = 0) =>
       chainPhase' \in {3, 10}
  /\ (Mod2(generation') = 0 /\ Mod2(generation) = 1) => chainPhase' = 9
  /\ (pubVer' # pubVer) =>
       (chainPhase' = 9 /\ chainPhase = 8 /\ diskRoot' = liveRoot'
          /\ diskCands' = {} /\ pubGen' = generation')
  /\ \A r \in 1..ReqSlots:
       /\ (reqStage[r] = 3 /\ reqStage'[r] = 5) => StampOK(jobStamp[r])
       /\ (reqMode[r] = 1 /\ reqFin'[r] /\ ~reqFin[r]) =>
            (pool' = pool /\ relay' = relay /\ poolSeq' = poolSeq
               /\ estAcct' = estAcct /\ detached' = detached)
       /\ (reqStage'[r] = 4 /\ reqStage[r] # 4) => jobStamp'[r].se = -1
  /\ (obsQN' = 1 /\ obsQN = 0) =>
       (pubVer' # pubVer /\ obsQRec' = pubGen' /\ Mod2(pubGen') = 0)
  /\ (obsQN = 1 /\ obsQN' = 1 /\ pubVer' # pubVer) => gap'
  /\ (relay' # relay /\ pool' = pool) =>
       (relay' \subseteq relay /\ relay' # relay)
  /\ (pendNotif' /\ ~pendNotif) => pubVer' # pubVer
  /\ (poolSeq' # poolSeq) => poolSeq' = poolSeq + 1
  /\ (factN' > factN) => chainPhase' = 7
  /\ (estAcct' # estAcct) => estAcct \subseteq estAcct'
  /\ (chainPhase = 11) => chainPhase' = 11
  /\ (lifePhase = 3) => lifePhase' = 3
  /\ (chainRes' # chainRes) => chainPhase' \in {1, 2, 10}
  /\ (lifePhase' = 2 => inputClosed)
  /\ (lifePhase' = 3 => inputClosed)
  /\ ~writerHeld'
  /\ (eventsLeft' # eventsLeft) => eventsLeft' = eventsLeft - 1
  /\ \A j \in 1..JobSlots:
       (jobOutcome[j] # 0 => jobOutcome'[j] = jobOutcome[j])
(*************************************************************************)
(* A.2 actions.  Each action assigns every variable it touches; fully    *)
(* untouched groups are listed as UNCHANGED and partially touched groups *)
(*************************************************************************)
(* have their untouched members assigned explicitly, so every primed     *)
(* variable is determined.  Every non-stutter action requires            *)
(* chainPhase # 11 and lifePhase # 3; stutter is supplied by             *)
(* [][Next]_vars.                                                        *)
(*************************************************************************)

(* TransitionSafety: exported as the state invariant asserting that      *)
(* every edge taken so far satisfied StepSafe; Next conjoins            *)
(* stepOK' = StepSafe once over the action union, so this checks        *)
(* every actual edge.                                                   *)
(*************************************************************************)
TransitionSafety == stepOK

(* Prepare: allocate one chain job with a simple re-root plan from the   *)
(* live tip, consume one event credit, reserve completion capacity, and  *)
(* mark every plan edge Prepared.  Publishes nothing.                    *)
Prepare ==
  \E s \in 1..JobSlots, p \in 1..12 :
    /\ ~inputClosed /\ eventsLeft > 0 /\ compCredits > 0
    /\ Mod2(generation) = 0
    /\ chainPhase # 10 /\ chainPhase # 11 /\ lifePhase # 3
    /\ Headroom
    /\ jobReq[s] = 0
    /\ PlanLen(p) >= 1 /\ PlanStart(p) = liveRoot.tip
    /\ jobReq' = [jobReq EXCEPT ![s] = 1 + PlanEnd(p)]
    /\ jobPlan' = [jobPlan EXCEPT ![s] = p]
    /\ jobCur' = [jobCur EXCEPT ![s] = 0]
    /\ jobEv' = [jobEv EXCEPT ![s] =
                   [q \in 1..3 |-> IF q <= PlanLen(p) THEN 1 ELSE 0]]
    /\ jobAtt' = [jobAtt EXCEPT ![s] = 1]
    /\ jobStamp' = [jobStamp EXCEPT ![s] = MkStamp]
    /\ eventsLeft' = eventsLeft - 1
    /\ compCredits' = compCredits - 1
    /\ jobMode' = jobMode /\ jobOutcome' = jobOutcome
    /\ inputClosed' = inputClosed
    /\ UNCHANGED <<VCtr, VRoot, VFrm, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs>>
   

(* CompleteProof: one prepared edge of one chain job finishes            *)
(* independently, out of order, writing only its own bounded slot.       *)
(* Completion never reserves, mutates coins or pool, or publishes.       *)
CompleteProofJ(j, q) ==
  /\ backend
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ jobReq[j] \in 1..4
  /\ q <= PlanLen(jobPlan[j])
  /\ jobEv[j][q] = 1
  /\ \E v \in {2, 3} : jobEv' = [jobEv EXCEPT ![j] =
                                  [jobEv[j] EXCEPT ![q] = v]]
  /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
  /\ jobPlan' = jobPlan /\ jobCur' = jobCur
  /\ jobStamp' = jobStamp /\ jobOutcome' = jobOutcome
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* InvalidateContext: retained evidence whose stamp no longer matches    *)
(* the current context becomes Stale; never reinterpreted as current.    *)
InvalidateCtx ==
  \E j \in 1..JobSlots, q \in 1..3 :
    /\ chainPhase # 11 /\ lifePhase # 3
    /\ jobReq[j] \in 1..4
    /\ q <= PlanLen(jobPlan[j])
    /\ jobEv[j][q] \in {1, 2}
    /\ jobStamp[j].se # -1 /\ ~StampOK(jobStamp[j])
    /\ jobEv' = [jobEv EXCEPT ![j] = [jobEv[j] EXCEPT ![q] = 4]]
    /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
    /\ jobPlan' = jobPlan /\ jobCur' = jobCur
    /\ jobStamp' = jobStamp /\ jobOutcome' = jobOutcome
    /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
   

(* PolicyChange: external policy/context change consumes one credit and  *)
(* advances the bounded policy epoch; affected evidence goes stale       *)
(* through InvalidateCtx.                                                *)
PolicyChange ==
  /\ ~inputClosed /\ eventsLeft > 0
  /\ policyEpoch < CounterBound
  /\ policyEpoch + eventsLeft <= CounterBound
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ policyEpoch' = policyEpoch + 1
  /\ eventsLeft' = eventsLeft - 1
  /\ epoch' = epoch /\ generation' = generation
  /\ poolSeq' = poolSeq /\ inputClosed' = inputClosed
  /\ UNCHANGED <<VRoot, VFrm, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Internal retry: an existing stale chain job with attempts below four  *)
(* re-prepares under a stable context with fresh facts and stamp.        *)
Reprepare ==
  \E j \in 1..JobSlots :
    /\ chainPhase = 1 /\ Mod2(generation) = 0
    /\ chainPhase # 11 /\ lifePhase # 3
    /\ jobReq[j] \in 1..4 /\ jobOutcome[j] = 0
    /\ jobAtt[j] < MaxAttempts
    /\ \E q \in {q2 \in 1..3 : q2 <= PlanLen(jobPlan[j])} : jobEv[j][q] = 4
    /\ jobEv' = [jobEv EXCEPT ![j] =
                   [q \in 1..3 |->
                     IF q <= PlanLen(jobPlan[j]) THEN 1 ELSE jobEv[j][q]]]
    /\ jobAtt' = [jobAtt EXCEPT ![j] = jobAtt[j] + 1]
    /\ jobStamp' = [jobStamp EXCEPT ![j] = MkStamp]
    /\ jobReq' = jobReq /\ jobMode' = jobMode
    /\ jobPlan' = jobPlan /\ jobCur' = jobCur
    /\ jobOutcome' = jobOutcome
    /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
   

(* SelectPrefixAndReserve: acquire the chain-transition reservation for  *)
(* a job whose next edge is proven and context current.  Selection       *)
(* grants no pool writer.                                                *)
SelectPrefix ==
  \E j \in 1..JobSlots :
    /\ chainRes = 0
    /\ Mod2(generation) = 0
    /\ chainPhase \in {1, 9}
    /\ lifePhase # 3
    /\ jobReq[j] \in 1..4 /\ jobOutcome[j] = 0
    /\ jobCur[j] < PlanLen(jobPlan[j])
    /\ \A q \in 1..3 : (q <= jobCur[j] + 1) => jobEv[j][q] = 2
    /\ jobStamp[j].se # -1 /\ StampOK(jobStamp[j])
    /\ chainRes' = j
    /\ chainPhase' = 2
    /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VWH, VRH, VObs, VCr>>
   

(* CloseFence: increment to the odd generation only under the            *)
(* reservation; errors and destructors cannot reopen it.                 *)
CloseFence ==
  /\ chainPhase = 2 /\ chainRes # 0
  /\ Mod2(generation) = 0 /\ generation < CounterBound
  /\ generation' = generation + 1
  /\ chainPhase' = 3
  /\ epoch' = epoch /\ poolSeq' = poolSeq
  /\ policyEpoch' = policyEpoch
  /\ UNCHANGED <<VRoot, VFrm, VEnv, VJob, VCmp, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Append body/undo, connect edge: append bounded framed body and undo   *)
(* data, record tentative positions and the proposed root.  Appended     *)
(* bytes are not authoritative references.                               *)
AppendConn ==
  /\ chainPhase = 3 /\ chainRes # 0
  /\ LET j == chainRes
         k == jobCur[j] + 1
         e == PE(jobPlan[j], k)
      IN
    /\ EdgeIsConn[e]
    /\ bodyPos < FrameBound /\ undoPos < FrameBound
    /\ bodyFrames' = [bodyFrames EXCEPT
                        ![bodyPos + 1] = FrameCode(EdgeTo[e],
                                                    BlockHeight[EdgeTo[e]])]
    /\ undoFrames' = [undoFrames EXCEPT
                        ![undoPos + 1] = FrameCode(EdgeTo[e],
                                                    BlockHeight[EdgeTo[e]])]
    /\ bodyPos' = bodyPos + 1 /\ undoPos' = undoPos + 1
    /\ priorRoot' = liveRoot
    /\ proposedRoot' = RootAfterConn(liveRoot, e, bodyPos + 1, undoPos + 1)
    /\ chainPhase' = 4
    /\ syncBody' = syncBody /\ syncUndo' = syncUndo
    /\ fileSync' = fileSync /\ dirSync' = dirSync
    /\ diskCands' = diskCands
    /\ diskRoot' = diskRoot /\ liveRoot' = liveRoot
    /\ UNCHANGED <<VCtr, VEnv, VJob, VCmp, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
   

(* Append body/undo, disconnect edge: reuse the already durable frames   *)
(* of the abandoned tip; no new append.                                  *)
AppendDisc ==
  /\ chainPhase = 3 /\ chainRes # 0
  /\ LET j == chainRes
         k == jobCur[j] + 1
         e == PE(jobPlan[j], k)
         t == EdgeFrom[e]
         pb == RefBody(liveRoot.refs, t)
         pu == RefUndo(liveRoot.refs, t)
      IN
    /\ ~EdgeIsConn[e]
    /\ pb # 0 /\ pu # 0
    /\ pb <= syncBody /\ bodyFrames[pb] = FrameCode(t, BlockHeight[t])
    /\ pu <= syncUndo /\ undoFrames[pu] = FrameCode(t, BlockHeight[t])
    /\ priorRoot' = liveRoot
    /\ proposedRoot' = RootAfterDisc(liveRoot, e)
    /\ chainPhase' = 4
    /\ diskRoot' = diskRoot /\ liveRoot' = liveRoot
    /\ UNCHANGED <<VCtr, VFrm, VEnv, VJob, VCmp, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
   

(* Sync files and directories: appended bytes and required directory     *)
(* entries become durable.                                               *)
SyncFiles ==
  /\ chainPhase = 4 /\ backend
  /\ syncBody' = bodyPos /\ syncUndo' = undoPos
  /\ fileSync' = TRUE /\ dirSync' = TRUE
  /\ chainPhase' = 5
  /\ bodyFrames' = bodyFrames /\ undoFrames' = undoFrames
  /\ bodyPos' = bodyPos /\ undoPos' = undoPos
  /\ diskCands' = diskCands
  /\ UNCHANGED <<VCtr, VRoot, VEnv, VJob, VCmp, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Sync failure: an I/O fault at the sync boundary consumes one credit,  *)
(* leaves the appended bytes beyond the durable bounds, closes the       *)
(* fence, and enters Recovering without fabricating success.             *)
SyncFail ==
  /\ chainPhase = 4
  /\ ~inputClosed /\ eventsLeft > 0
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ eventsLeft' = eventsLeft - 1
  /\ faultKind' = 2
  /\ chainPhase' = 10
  /\ rootRec' = FALSE
  /\ inputClosed' = inputClosed
  /\ poolRec' = poolRec /\ backend' = backend
  /\ pendNotif' = pendNotif
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VJob, VCmp, VPl, VPub, VReq, VCO, VCR, VWH, VRH, VObs, VCr, VLP>>
 
(* AtomicBatch: submit one atomic coins/head batch for the selected      *)
(* edge under the odd fence; the base must equal the authoritative root  *)
(* and referenced extents must be durable.  Completion stays unresolved. *)
AtomicBatch ==
  /\ chainPhase = 5 /\ chainRes # 0
  /\ LET j == chainRes
         k == jobCur[j] + 1
         e == PE(jobPlan[j], k)
      IN
    /\ priorRoot = liveRoot
    /\ Mod2(generation) = 1
    /\ proposedRoot.cid = liveRoot.cid + 1
    /\ DurableRefs(proposedRoot, syncBody, syncUndo, bodyFrames,
                   undoFrames)
    /\ compId' = [ce |-> epoch, cj |-> j, cc |-> proposedRoot.cid]
    /\ compStatus' = 0
    /\ unresComp' = TRUE
    /\ diskCands' = {1, 2}
    /\ chainPhase' = 6
    /\ bodyFrames' = bodyFrames /\ undoFrames' = undoFrames
    /\ bodyPos' = bodyPos /\ undoPos' = undoPos
    /\ syncBody' = syncBody /\ syncUndo' = syncUndo
    /\ fileSync' = fileSync /\ dirSync' = dirSync
    /\ UNCHANGED <<VCtr, VRoot, VEnv, VJob, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
   

(* ReceiveCompletion, durable success: install the whole proposed root,  *)
(* append one committed reconciliation fact, and advance the job cursor. *)
ReceiveSuccess ==
  /\ chainPhase = 6 /\ chainRes # 0
  /\ compStatus = 0 /\ unresComp
  /\ factN < FactBound
  /\ LET j == chainRes
         k == jobCur[j] + 1
      IN
    /\ diskRoot' = proposedRoot /\ liveRoot' = proposedRoot
    /\ reconFacts' = [reconFacts EXCEPT ![factN + 1] =
                        [c |-> proposedRoot.cid, e |-> PE(jobPlan[j], k)]]
    /\ factN' = factN + 1
    /\ diskCands' = {}
    /\ compStatus' = 4
    /\ unresComp' = FALSE
    /\ jobCur' = [jobCur EXCEPT ![j] = jobCur[j] + 1]
    /\ chainPhase' = 7
    /\ priorRoot' = priorRoot /\ proposedRoot' = proposedRoot
    /\ bodyFrames' = bodyFrames /\ undoFrames' = undoFrames
    /\ bodyPos' = bodyPos /\ undoPos' = undoPos
    /\ syncBody' = syncBody /\ syncUndo' = syncUndo
    /\ fileSync' = fileSync /\ dirSync' = dirSync
    /\ compId' = compId
    /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
    /\ jobPlan' = jobPlan /\ jobEv' = jobEv
    /\ jobStamp' = jobStamp /\ jobOutcome' = jobOutcome
    /\ pool' = pool /\ relay' = relay /\ detached' = detached
    /\ poolTagE' = poolTagE /\ poolTagC' = poolTagC
    /\ estAcct' = estAcct
    /\ UNCHANGED <<VCtr, VEnv, VFk, VLP, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
   

(* ReceiveCompletion, definite failure: retain the prior root, consume   *)
(* the identity, keep the fence closed, and type the job IoFailure.      *)
(* Success is never reported for a failed write.                         *)
ReceiveFailure ==
  /\ chainPhase = 6 /\ chainRes # 0
  /\ compStatus = 0 /\ unresComp
  /\ compStatus' = 4
  /\ unresComp' = FALSE
  /\ diskCands' = {}
  /\ jobOutcome' = [jobOutcome EXCEPT ![chainRes] = 5]
  /\ chainPhase' = 7
  /\ compId' = compId
  /\ bodyFrames' = bodyFrames /\ undoFrames' = undoFrames
  /\ bodyPos' = bodyPos /\ undoPos' = undoPos
  /\ syncBody' = syncBody /\ syncUndo' = syncUndo
  /\ fileSync' = fileSync /\ dirSync' = dirSync
  /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
  /\ jobPlan' = jobPlan /\ jobCur' = jobCur
  /\ jobEv' = jobEv /\ jobStamp' = jobStamp
  /\ UNCHANGED <<VCtr, VRoot, VEnv, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* ReceiveCompletion, ambiguity: retain the explicit prior/proposed      *)
(* uncertainty and enter Recovering; the fence stays closed.             *)
ReceiveAmbiguous ==
  /\ chainPhase = 6 /\ chainRes # 0
  /\ compStatus = 0 /\ unresComp
  /\ compStatus' = 3
  /\ unresComp' = TRUE
  /\ diskCands' = {1, 2}
  /\ rootRec' = FALSE
  /\ chainPhase' = 10
  /\ faultKind' = 2
  /\ compId' = compId
  /\ bodyFrames' = bodyFrames /\ undoFrames' = undoFrames
  /\ bodyPos' = bodyPos /\ undoPos' = undoPos
  /\ syncBody' = syncBody /\ syncUndo' = syncUndo
  /\ fileSync' = fileSync /\ dirSync' = dirSync
  /\ poolRec' = poolRec /\ backend' = backend
  /\ pendNotif' = pendNotif
  /\ UNCHANGED <<VCtr, VRoot, VEnv, VJob, VLP, VPl, VPub, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* ReceiveCompletion, late or duplicate arrival: a typed no-op that      *)
(* changes no state, including after recovery.                           *)
ReceiveDup ==
  /\ compStatus # 0
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Next selected edge: return to Closed for the next committed edge of   *)
(* the same publication when its proof is current.                       *)
NextEdge ==
  /\ chainPhase = 7 /\ compStatus = 4 /\ chainRes # 0
  /\ LET j == chainRes
      IN
    /\ jobCur[j] < PlanLen(jobPlan[j])
    /\ jobEv[j][jobCur[j] + 1] = 2
    /\ jobStamp[j].se # -1 /\ StampOK(jobStamp[j])
  /\ chainPhase' = 3
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* ReconcilePool: under the reservation and the odd fence, fold the      *)
(* canonical named lifecycle over the committed edges in commit order,   *)
(* account the estimator before removals with the reconciliation         *)
(* identity recorded exactly once, then tag the pool.  A stale or        *)
(* exhausted evidence suffix ends the publication at the committed       *)
(* prefix.                                                               *)
ReconcilePool ==
  /\ chainPhase = 7 /\ compStatus = 4 /\ chainRes # 0
  /\ Mod2(generation) = 1
  /\ factN >= 1 /\ factN \notin estAcct
  /\ poolSeq < CounterBound
  /\ LET j == chainRes
         k == jobCur[j]
         pl == jobPlan[j]
         done == \/ k = PlanLen(pl)
                 \/ /\ k < PlanLen(pl)
                    /\ jobEv[j][k + 1] \in {3, 4}
                 \/ /\ jobStamp[j].se # -1 /\ ~StampOK(jobStamp[j])
         pd0 == [p |-> pool, d |-> detached]
         pd1 == IF k >= 1 THEN EdgeEff(PE(pl, 1), pd0) ELSE pd0
         pd2 == IF k >= 2 THEN EdgeEff(PE(pl, 2), pd1) ELSE pd1
         pd3 == IF k >= 3 THEN EdgeEff(PE(pl, 3), pd2) ELSE pd2
      IN
    /\ done
    /\ pool' = pd3.p
    /\ detached' = pd3.d
    /\ estAcct' = estAcct \cup {factN}
    /\ poolTagE' = epoch /\ poolTagC' = liveRoot.cid
    /\ poolSeq' = poolSeq + 1
    /\ chainPhase' = 8
    /\ epoch' = epoch /\ generation' = generation
    /\ policyEpoch' = policyEpoch
    /\ relay' = relay /\ reconFacts' = reconFacts /\ factN' = factN
    /\ UNCHANGED <<VRoot, VFrm, VEnv, VJob, VCmp, VFk, VLP, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
   

(* Publish: one atomic publication of tip, height, coins version and the *)
(* next even generation after pool reconciliation under a matching       *)
(* reconciliation tag.  The committed record is offered to a subscribed  *)
(* observer as part of this transition; a full queue records a gap.      *)
Publish ==
  /\ chainPhase = 8 /\ compStatus # 3 /\ ~unresComp
  /\ diskCands = {} /\ diskRoot = liveRoot
  /\ poolTagE = epoch /\ poolTagC = liveRoot.cid
  /\ Mod2(generation) = 1 /\ generation < CounterBound
  /\ generation' = generation + 1
  /\ pubTip' = liveRoot.tip /\ pubHeight' = liveRoot.height
  /\ pubVer' = liveRoot.ver /\ pubGen' = generation + 1
  /\ pendNotif' = (subscribed /\ obsQN = 0 /\ liveRoot.ver # pubVer)
  /\ obsQN' = IF subscribed /\ obsQN = 0 /\ liveRoot.ver # pubVer
                THEN 1 ELSE obsQN
  /\ obsQRec' = IF subscribed /\ obsQN = 0 /\ liveRoot.ver # pubVer
                  THEN generation + 1 ELSE obsQRec
  /\ gap' = (gap \/ (subscribed /\ obsQN = 1 /\ liveRoot.ver # pubVer))
  /\ chainPhase' = 9
  /\ epoch' = epoch /\ poolSeq' = poolSeq
  /\ policyEpoch' = policyEpoch
  /\ rootRec' = rootRec /\ poolRec' = poolRec /\ backend' = backend
  /\ subscribed' = subscribed /\ subId' = subId
  /\ obsDel' = obsDel /\ obsDelRec' = obsDelRec
  /\ delReady' = delReady /\ deadlineExp' = deadlineExp
  /\ UNCHANGED <<VRoot, VFrm, VEnv, VJob, VCmp, VFk, VLP, VPl, VReq, VCO, VCR, VWH, VRH, VCr>>
 
(* Complete: settle the published transition; release the reservation    *)
(* only after coherent publication.  A committed partial prefix is not   *)
(* success for an uncommitted requested suffix.                          *)
CompletePub ==
  /\ chainPhase = 9 /\ compStatus # 3 /\ ~unresComp
  /\ LET j == chainRes
      IN jobOutcome' = IF chainRes # 0
           THEN [jobOutcome EXCEPT ![j] =
                  IF jobOutcome[j] # 0 THEN jobOutcome[j]
                  ELSE IF jobCur[j] = PlanLen(jobPlan[j]) THEN 1 ELSE 2]
           ELSE jobOutcome
  /\ chainRes' = 0
  /\ chainPhase' = 1
  /\ priorRoot' = NullRoot /\ proposedRoot' = NullRoot
  /\ diskCands' = {} /\ fileSync' = FALSE /\ dirSync' = FALSE
  /\ diskRoot' = diskRoot /\ liveRoot' = liveRoot
  /\ bodyFrames' = bodyFrames /\ undoFrames' = undoFrames
  /\ bodyPos' = bodyPos /\ undoPos' = undoPos
  /\ syncBody' = syncBody /\ syncUndo' = syncUndo
  /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
  /\ jobPlan' = jobPlan /\ jobCur' = jobCur
  /\ jobEv' = jobEv /\ jobStamp' = jobStamp
  /\ UNCHANGED <<VCtr, VEnv, VCmp, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VWH, VRH, VObs, VCr>>
 

(* Complete, typed rejection: a chain job whose evidence has no valid    *)
(* or refreshable continuation settles with Invalid, or Busy after the   *)
(* four-attempt bound.                                                   *)
CompleteTyped ==
  \E j \in 1..JobSlots :
    /\ chainPhase = 1 /\ lifePhase # 3
    /\ jobReq[j] \in 1..4 /\ jobOutcome[j] = 0
    /\ jobPlan[j] # 0
    /\ \A q \in 1..3 : (q <= PlanLen(jobPlan[j]) /\ jobPlan[j] # 0) => jobEv[j][q] \in {3, 4}
    /\ jobOutcome' = [jobOutcome EXCEPT ![j] =
           IF \E q \in {q2 \in 1..3 : q2 <= PlanLen(jobPlan[j])} : jobEv[j][q] = 4
             THEN 3 ELSE 2]
    /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
    /\ jobPlan' = jobPlan /\ jobCur' = jobCur
    /\ jobEv' = jobEv /\ jobStamp' = jobStamp
    /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
   

(* Crash/Fault, crash: consume one credit, discard volatile evidence,    *)
(* reservations, pool and pending delivery, advance the process epoch,   *)
(* close the fence in the new epoch, and enter Recovering.  Interrupted  *)
(* jobs settle as typed IoFailure; no success is fabricated.             *)
CrashFault ==
  /\ ~inputClosed /\ eventsLeft > 0
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ epoch < CounterBound
  /\ eventsLeft' = eventsLeft - 1
  /\ faultKind' = 1
  /\ epoch' = epoch + 1
  /\ generation' = generation + (1 - Mod2(generation))
  /\ pool' = {} /\ relay' = {} /\ detached' = DetEmpty
  /\ jobEv' = [j \in 1..JobSlots |-> [q \in 1..3 |-> 0]]
  /\ jobStamp' = [j \in 1..JobSlots |-> NoStamp]
  /\ jobOutcome' = [j \in 1..JobSlots |->
                      IF jobReq[j] # 0 /\ jobOutcome[j] = 0 THEN 5
                        ELSE jobOutcome[j]]
  /\ chainRes' = 0 /\ lockOwner' = 0
  /\ writerHeld' = FALSE /\ readerHeld' = FALSE
  /\ chainPhase' = 10
  /\ rootRec' = FALSE /\ poolRec' = FALSE /\ pendNotif' = FALSE
  /\ obsQN' = 0 /\ obsDel' = FALSE /\ delReady' = FALSE
  /\ gap' = (gap \/ subscribed)
  /\ reqFin' = [r \in 1..ReqSlots |-> reqOcc[r]]
  /\ reqStage' = [r \in 1..ReqSlots |->
                    IF reqOcc[r] THEN 6 ELSE reqStage[r]]
  /\ inputClosed' = inputClosed
  /\ poolSeq' = poolSeq /\ policyEpoch' = policyEpoch
  /\ jobReq' = jobReq /\ jobMode' = jobMode
  /\ jobAtt' = jobAtt /\ jobPlan' = jobPlan /\ jobCur' = jobCur
  /\ poolTagE' = poolTagE /\ poolTagC' = poolTagC
  /\ estAcct' = estAcct /\ reconFacts' = reconFacts /\ factN' = factN
  /\ backend' = backend
  /\ subscribed' = subscribed /\ subId' = subId
  /\ obsQRec' = obsQRec /\ obsDelRec' = obsDelRec
  /\ deadlineExp' = deadlineExp
  /\ reqTxs' = reqTxs /\ reqRes' = reqRes /\ reqOcc' = reqOcc
  /\ reqMode' = reqMode /\ reqAtt' = reqAtt
  /\ reqOrigin' = reqOrigin /\ reqFeeLim' = reqFeeLim
  /\ reqFacts' = reqFacts /\ bJob' = bJob /\ bJobAtt' = bJobAtt
  /\ UNCHANGED <<VPub, VCr, VFrm, VRoot, VLP, VCmp>>
 
(* Crash/Fault, I/O or lost completion: preserves outstanding            *)
(* identities, closes the fence, and enters Recovering.                  *)
IoFault ==
  /\ ~inputClosed /\ eventsLeft > 0
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ generation < CounterBound
  /\ eventsLeft' = eventsLeft - 1
  /\ faultKind' = 2
  /\ chainPhase' = 10
  /\ generation' = generation + (1 - Mod2(generation))
  /\ unresComp' = (unresComp \/ chainPhase = 6)
  /\ rootRec' = FALSE
  /\ inputClosed' = inputClosed
  /\ compId' = compId /\ compStatus' = compStatus
  /\ poolRec' = poolRec /\ backend' = backend
  /\ pendNotif' = pendNotif
  /\ epoch' = epoch /\ poolSeq' = poolSeq
  /\ policyEpoch' = policyEpoch
/\ UNCHANGED <<VRoot, VFrm, VJob, VPl, VPub, VReq, VCO, VCR, VWH, VRH, VObs, VCr, VLP>>


(* Crash/Fault, callback loss: the optional delivery is dropped with a   *)
(* sticky gap; canonical progress and the phase are unchanged.           *)
CallbackLoss ==
  /\ ~inputClosed /\ eventsLeft > 0
  /\ chainPhase # 11 /\ chainPhase # 10 /\ lifePhase # 3
  /\ eventsLeft' = eventsLeft - 1
  /\ faultKind' = 3
  /\ obsQN' = 0 /\ obsDel' = FALSE /\ delReady' = FALSE
  /\ gap' = TRUE
  /\ pendNotif' = FALSE
  /\ inputClosed' = inputClosed
  /\ rootRec' = rootRec /\ poolRec' = poolRec /\ backend' = backend
  /\ subscribed' = subscribed /\ subId' = subId
  /\ obsQRec' = obsQRec /\ obsDelRec' = obsDelRec
  /\ deadlineExp' = deadlineExp
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VJob, VCmp, VCP, VLP, VPl, VPub, VReq, VCO, VCR, VWH, VRH, VCr>>
 

(* RecoverRoot, no durable ambiguity: the authoritative record stands;   *)
(* mark root recovery complete and restore recovery availability.        *)
RecoverRootKeep ==
  /\ chainPhase = 10
  /\ ~unresComp /\ compStatus # 3
  /\ rootRec' = TRUE /\ backend' = TRUE
  /\ poolRec' = poolRec /\ pendNotif' = pendNotif
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* RecoverRoot, unresolved batch or ambiguous completion: resolve the    *)
(* atomic record by its identity to the prior or wholly proposed root;   *)
(* referenced extents must be durable.  Orphan append tails beyond the   *)
(* synced bounds are never authoritative.                                *)
RecoverRootResolve ==
  /\ chainPhase = 10
  /\ unresComp \/ compStatus = 3
  /\ \E ch \in {1, 2} :
       LET r == IF ch = 1 THEN priorRoot ELSE proposedRoot
       IN /\ DurableRefs(r, syncBody, syncUndo, bodyFrames, undoFrames)
          /\ diskRoot' = r /\ liveRoot' = r
          /\ diskCands' = {}
          /\ compStatus' = 4 /\ compId' = compId
          /\ unresComp' = FALSE
          /\ rootRec' = TRUE /\ backend' = TRUE
          /\ priorRoot' = priorRoot /\ proposedRoot' = proposedRoot
          /\ compId' = compId
          /\ bodyFrames' = bodyFrames /\ undoFrames' = undoFrames
          /\ bodyPos' = bodyPos /\ undoPos' = undoPos
          /\ syncBody' = syncBody /\ syncUndo' = syncUndo
          /\ fileSync' = fileSync /\ dirSync' = dirSync
          /\ poolRec' = poolRec /\ pendNotif' = pendNotif
          /\ UNCHANGED <<VCtr, VEnv, VJob, VFk, VLP, VPl, VPub, VReq, VCO, VCR, VWH, VRH, VObs, VCr, VCP>>
         

(* RecoverPool: rebuild the pool against the exact recovered root        *)
(* through normal re-admission rules; persisted entries are candidates,  *)
(* not proof.  Establish a fresh epoch-tagged reconciliation identity;   *)
(* the estimator's persisted state is recovered, not replayed.           *)
RecoverPool ==
  /\ chainPhase = 10 /\ rootRec /\ backend
  /\ Mod2(generation) = 1
  /\ poolSeq < CounterBound
  /\ pool' = {t \in {T1, T2} : ValidUnder(t, liveRoot.tip)}
  /\ relay' = {}
  /\ detached' = DetEmpty
  /\ poolTagE' = epoch /\ poolTagC' = liveRoot.cid
  /\ poolSeq' = poolSeq + 1
  /\ poolRec' = TRUE /\ backend' = TRUE
  /\ faultKind' = 0
  /\ chainPhase' = 8
  /\ epoch' = epoch /\ generation' = generation
  /\ policyEpoch' = policyEpoch
  /\ rootRec' = rootRec /\ pendNotif' = pendNotif
  /\ estAcct' = estAcct /\ reconFacts' = reconFacts /\ factN' = factN
  /\ UNCHANGED <<VRoot, VFrm, VEnv, VJob, VCmp, VLP, VPub, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* CloseInput: closing external input allocates no event; already        *)
(* accepted work remains accountable.                                    *)
CloseInput ==
  /\ ~inputClosed
  /\ inputClosed' = TRUE
  /\ eventsLeft' = eventsLeft
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Finish, chain machine: every job settled or typed-rejected and no     *)
(* unresolved batch, reservation, or detached work remains.              *)
ChainFinish ==
  /\ inputClosed /\ chainPhase = 1 /\ lifePhase # 3
  /\ (\A j \in 1..JobSlots : jobReq[j] # 0 => jobOutcome[j] # 0)
  /\ ~unresComp /\ compStatus # 3
  /\ chainRes = 0 /\ detached.n = 0
  /\ rootRec /\ poolRec
  /\ chainPhase' = 11
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Detached re-admission: after stability, the bounded queue re-enters   *)
(* through the ordinary admission rules; invalid candidates are dropped  *)
(* with a typed disposition.                                             *)
Reconsider ==
  /\ chainPhase = 1 /\ Mod2(generation) = 0
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ detached.n > 0
  /\ poolSeq < CounterBound
  /\ detached' = DetShift(detached)
  /\ pool' = IF ValidUnder(detached.x, liveRoot.tip)
               THEN pool \cup {detached.x} ELSE pool
  /\ relay' = IF ValidUnder(detached.x, liveRoot.tip)
                THEN relay \cup {detached.x} ELSE relay
  /\ epoch' = epoch /\ generation' = generation
  /\ policyEpoch' = policyEpoch
  /\ poolSeq' = IF ValidUnder(detached.x, liveRoot.tip)
                  THEN poolSeq + 1 ELSE poolSeq
  /\ poolTagE' = poolTagE /\ poolTagC' = poolTagC
  /\ estAcct' = estAcct /\ reconFacts' = reconFacts /\ factN' = factN
  /\ UNCHANGED <<VRoot, VFrm, VEnv, VJob, VCmp, VFk, VLP, VCP, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Settle: input closed and all chain, admission, recovery, observer and *)
(* response work drained or disposed; no reservation or lock remains.    *)
Settle ==
  /\ lifePhase = 1 /\ inputClosed
  /\ chainPhase \in {1, 11}
  /\ (\A r \in 1..ReqSlots : reqOcc[r] => reqFin[r])
  /\ (\A j \in 1..JobSlots : jobReq[j] # 0 => jobOutcome[j] # 0)
  /\ ~unresComp /\ compStatus # 3
  /\ chainRes = 0 /\ detached.n = 0
  /\ obsQN = 0 /\ ~obsDel /\ ~pendNotif
  /\ ~writerHeld
  /\ lifePhase' = 2
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Done: terminal; only stutter is enabled afterwards.                   *)
EnterDone ==
  /\ lifePhase = 2
  /\ lifePhase' = 3
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VObs, VCr>>
 
(*************************************************************************)
(* B. Transaction-admission machine.  A request occupies request slot r  *)
(* and, as its A-side summary, job slot r: jobReq 5/6, jobMode, jobAtt,  *)
(* jobStamp and jobOutcome mirror the pipeline.  Ingress supplies no     *)
(* trusted sigop evidence: SigopsOf is owner-computed from the resolved  *)
(* prevouts.                                                             *)
(*************************************************************************)

(* Start: retain the parsed transactions, named mode, origin and request *)
(* fee limits; one external event and one completion reservation.        *)
AdmStart(r) ==
  /\ ~inputClosed /\ eventsLeft > 0 /\ compCredits > 0
  /\ jobReq[r] = 0 /\ ~reqOcc[r]
  /\ Mod2(generation) = 0
  /\ chainPhase # 10 /\ chainPhase # 11 /\ lifePhase # 3
  /\ Headroom
  /\ \E m \in {1, 2}, o \in 0..5, fl \in 0..3, ntx \in {1, 2},
       t1st \in {T1, T2}, t2nd \in {T1, T2} : t2nd # t1st
       /\ reqOcc' = [reqOcc EXCEPT ![r] = TRUE]
       /\ reqFin' = [reqFin EXCEPT ![r] = FALSE]
       /\ reqMode' = [reqMode EXCEPT ![r] = m]
       /\ reqOrigin' = [reqOrigin EXCEPT ![r] = o]
       /\ reqFeeLim' = [reqFeeLim EXCEPT ![r] = fl]
       /\ reqTxs' = [reqTxs EXCEPT ![r] =
                       [n |-> ntx, x |-> t1st,
                        y |-> IF ntx = 2 THEN t2nd ELSE -1]]
       /\ reqStage' = [reqStage EXCEPT ![r] = 1]
       /\ reqAtt' = [reqAtt EXCEPT ![r] = 1]
       /\ jobReq' = [jobReq EXCEPT ![r] = 5 + t1st]
       /\ jobMode' = [jobMode EXCEPT ![r] = m]
       /\ jobAtt' = [jobAtt EXCEPT ![r] = 1]
       /\ jobStamp' = [jobStamp EXCEPT ![r] = NoStamp]
       /\ eventsLeft' = eventsLeft - 1
       /\ compCredits' = compCredits - 1
  /\ reqRes' = reqRes /\ reqFacts' = reqFacts
  /\ bJob' = bJob /\ bJobAtt' = bJobAtt
  /\ jobPlan' = jobPlan /\ jobCur' = jobCur
  /\ jobEv' = jobEv /\ jobOutcome' = jobOutcome
  /\ inputClosed' = inputClosed
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VCO, VCR, VWH, VRH, VObs>>
 

(* Snapshot: capture the complete coherent read stamp, resolve each      *)
(* input once from the committed coins plus the admitted-pool overlay,   *)
(* and select verification.  Missing inputs receive the owner's orphan   *)
(* disposition as a preparation failure, never a fabricated proof.       *)
AdmSnapshot(r) ==
  /\ reqStage[r] = 1 /\ reqOcc[r] /\ ~reqFin[r]
  /\ Mod2(generation) = 0
  /\ compCredits > 0
  /\ jobStamp' = [jobStamp EXCEPT ![r] = MkStamp]
  /\ reqFacts' = [reqFacts EXCEPT ![r] =
                    [q \in 1..2 |-> FactFor(r, q)]]
  /\ bJob' = [bJob EXCEPT ![r] =
                [q \in 1..2 |->
                  IF q <= reqTxs[r].n THEN
                    IF FactFor(r, q) >= 0 THEN 1 ELSE 4
                  ELSE 0]]
  /\ reqStage' = [reqStage EXCEPT ![r] = 2]
  /\ reqTxs' = reqTxs /\ reqRes' = reqRes /\ reqOcc' = reqOcc
  /\ reqFin' = reqFin /\ reqMode' = reqMode /\ reqAtt' = reqAtt
  /\ reqOrigin' = reqOrigin /\ reqFeeLim' = reqFeeLim
  /\ bJobAtt' = bJobAtt
  /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
  /\ jobPlan' = jobPlan /\ jobCur' = jobCur
  /\ jobEv' = jobEv /\ jobOutcome' = jobOutcome
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Snapshot at a closed fence selects Retry without retaining evidence.  *)
AdmSnapRetry(r) ==
  /\ reqStage[r] = 1 /\ reqOcc[r] /\ ~reqFin[r]
  /\ Mod2(generation) = 1
  /\ jobStamp' = [jobStamp EXCEPT ![r] = NoStamp]
  /\ reqStage' = [reqStage EXCEPT ![r] = 4]
  /\ reqTxs' = reqTxs /\ reqRes' = reqRes /\ reqOcc' = reqOcc
  /\ reqFin' = reqFin /\ reqMode' = reqMode /\ reqAtt' = reqAtt
  /\ reqOrigin' = reqOrigin /\ reqFeeLim' = reqFeeLim
  /\ reqFacts' = reqFacts /\ bJob' = bJob /\ bJobAtt' = bJobAtt
  /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
  /\ jobPlan' = jobPlan /\ jobCur' = jobCur
  /\ jobEv' = jobEv /\ jobOutcome' = jobOutcome
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* VerifyIndependently, take: one pending proof job starts without the   *)
(* pool writer; bounded worker capacity is reserved.                     *)
VerifyTakeRP(r, q) ==
  /\ reqStage[r] = 2 /\ reqOcc[r] /\ ~reqFin[r]
  /\ q <= reqTxs[r].n
  /\ bJob[r][q] = 1
  /\ compCredits > 0
  /\ bJob' = [bJob EXCEPT ![r] = [bJob[r] EXCEPT ![q] = 2]]
  /\ bJobAtt' = [bJobAtt EXCEPT ![r] =
                   [bJobAtt[r] EXCEPT ![q] = reqAtt[r]]]
  /\ compCredits' = compCredits - 1
  /\ reqTxs' = reqTxs /\ reqRes' = reqRes /\ reqOcc' = reqOcc
  /\ reqFin' = reqFin /\ reqMode' = reqMode /\ reqStage' = reqStage
  /\ reqAtt' = reqAtt /\ reqOrigin' = reqOrigin
  /\ reqFeeLim' = reqFeeLim /\ reqFacts' = reqFacts
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VCO, VCR, VWH, VRH, VObs>>
 

(* VerifyIndependently, settle: jobs finish out of order and write only  *)
(* their own bounded result slots.                                       *)
VerifyDoneRP(r, q) ==
  /\ reqStage[r] = 2 /\ reqOcc[r]
  /\ q <= reqTxs[r].n
  /\ bJob[r][q] = 2
  /\ \E v \in {3, 4} : bJob' = [bJob EXCEPT ![r] =
                                 [bJob[r] EXCEPT ![q] = v]]
  /\ reqTxs' = reqTxs /\ reqRes' = reqRes /\ reqOcc' = reqOcc
  /\ reqFin' = reqFin /\ reqMode' = reqMode /\ reqStage' = reqStage
  /\ reqAtt' = reqAtt /\ reqOrigin' = reqOrigin
  /\ reqFeeLim' = reqFeeLim /\ reqFacts' = reqFacts
  /\ bJobAtt' = bJobAtt
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* Assemble verdicts in original request order: Preview stops at Finish  *)
(* with no mutation; Commit proceeds to the single writer recheck.       *)
AssembleVerdicts(r) ==
  /\ reqStage[r] = 2 /\ reqOcc[r] /\ ~reqFin[r]
  /\ \A q \in {q2 \in 1..2 : q2 <= reqTxs[r].n} : bJob[r][q] \in {3, 4}
  /\ reqStage' = [reqStage EXCEPT ![r] =
                    IF reqMode[r] = 1 THEN 5 ELSE 3]
  /\ reqTxs' = reqTxs /\ reqRes' = reqRes /\ reqOcc' = reqOcc
  /\ reqFin' = reqFin /\ reqMode' = reqMode /\ reqAtt' = reqAtt
  /\ reqOrigin' = reqOrigin /\ reqFeeLim' = reqFeeLim
  /\ reqFacts' = reqFacts /\ bJob' = bJob /\ bJobAtt' = bJobAtt
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* RecheckAndCommit, stale: any stamp field moved under the writer;      *)
(* discard the evidence and select Retry with fresh facts.               *)
CommitStale(r) ==
  /\ reqStage[r] = 3 /\ reqOcc[r] /\ ~reqFin[r]
  /\ jobStamp[r].se # -1 /\ ~StampOK(jobStamp[r])
  /\ reqStage' = [reqStage EXCEPT ![r] = 4]
  /\ jobStamp' = [jobStamp EXCEPT ![r] = NoStamp]
  /\ reqTxs' = reqTxs /\ reqRes' = reqRes /\ reqOcc' = reqOcc
  /\ reqFin' = reqFin /\ reqMode' = reqMode /\ reqAtt' = reqAtt
  /\ reqOrigin' = reqOrigin /\ reqFeeLim' = reqFeeLim
  /\ reqFacts' = reqFacts /\ bJob' = bJob /\ bJobAtt' = bJobAtt
  /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
  /\ jobPlan' = jobPlan /\ jobCur' = jobCur
  /\ jobEv' = jobEv /\ jobOutcome' = jobOutcome
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VCO, VCR, VWH, VRH, VObs, VCr>>
 

(* RecheckAndCommit, current: the writer is acquired once for the        *)
(* complete recheck and the atomic install (model-atomic: the writer is  *)
(* never held across a step boundary), then released in the same step.   *)
CommitApply(r) ==
  /\ reqStage[r] = 3 /\ reqOcc[r] /\ ~reqFin[r]
  /\ StampOK(jobStamp[r])
  /\ Mod2(generation) = 0
  /\ poolSeq < CounterBound
  /\ LET acc == {q \in 1..2 : q <= reqTxs[r].n /\ RowVerdict(r, q) = 1}
         accT == {TxOf(r, q) : q \in acc}
      IN
    /\ pool' = pool \cup accT
    /\ relay' = relay \cup accT
    /\ detached' = DetRemoveAll(detached, accT)
    /\ poolSeq' = IF acc # {} THEN poolSeq + 1 ELSE poolSeq
    /\ reqStage' = [reqStage EXCEPT ![r] = 5]
    /\ epoch' = epoch /\ generation' = generation
    /\ policyEpoch' = policyEpoch
    /\ poolTagE' = poolTagE /\ poolTagC' = poolTagC
    /\ estAcct' = estAcct /\ reconFacts' = reconFacts
    /\ factN' = factN
    /\ reqTxs' = reqTxs /\ reqRes' = reqRes /\ reqOcc' = reqOcc
    /\ reqFin' = reqFin /\ reqMode' = reqMode /\ reqAtt' = reqAtt
    /\ reqOrigin' = reqOrigin /\ reqFeeLim' = reqFeeLim
    /\ reqFacts' = reqFacts /\ bJob' = bJob /\ bJobAtt' = bJobAtt
    /\ UNCHANGED <<VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPub, VFlg, VCO, VCR, VWH, VRH, VObs, VCr>>
   

(* Retry: discard stamp, resolved coins and proof results; a fresh       *)
(* attempt below the bound recaptures at Snapshot, otherwise the typed   *)
(* Busy outcome settles the request.  No canonical mutation occurs.      *)
AdmRetry(r) ==
  /\ reqStage[r] = 4 /\ reqOcc[r] /\ ~reqFin[r]
  /\ IF jobAtt[r] < MaxAttempts
       THEN /\ jobAtt' = [jobAtt EXCEPT ![r] = jobAtt[r] + 1]
            /\ reqAtt' = [reqAtt EXCEPT ![r] = jobAtt[r] + 1]
            /\ jobStamp' = [jobStamp EXCEPT ![r] = NoStamp]
            /\ reqStage' = [reqStage EXCEPT ![r] = 1]
            /\ reqFin' = reqFin
            /\ jobOutcome' = jobOutcome
            /\ compCredits' = compCredits
       ELSE /\ reqFin' = [reqFin EXCEPT ![r] = TRUE]
            /\ reqStage' = [reqStage EXCEPT ![r] = 6]
            /\ jobOutcome' = [jobOutcome EXCEPT ![r] = 3]
            /\ jobStamp' = [jobStamp EXCEPT ![r] = NoStamp]
            /\ compCredits' = compCredits + 1
            /\ jobAtt' = jobAtt /\ reqAtt' = reqAtt
  /\ reqTxs' = reqTxs /\ reqRes' = reqRes /\ reqOcc' = reqOcc
  /\ reqMode' = reqMode /\ reqOrigin' = reqOrigin
  /\ reqFeeLim' = reqFeeLim /\ reqFacts' = reqFacts
  /\ bJob' = bJob /\ bJobAtt' = bJobAtt
  /\ jobReq' = jobReq /\ jobMode' = jobMode
  /\ jobPlan' = jobPlan /\ jobCur' = jobCur /\ jobEv' = jobEv
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VCO, VCR, VWH, VRH, VObs>>
 

(* Finish: publish the bounded ordered response, release the completion  *)
(* reservation, and settle the job summary.  Only retained accepted      *)
(* transactions became relay candidates, at CommitApply.                 *)
AdmFinish(r) ==
  /\ reqStage[r] = 5 /\ reqOcc[r] /\ ~reqFin[r]
  /\ reqRes' = [reqRes EXCEPT ![r] =
                  [n |-> reqTxs[r].n, x |-> RowVerdict(r, 1),
                   y |-> IF reqTxs[r].n = 2 THEN RowVerdict(r, 2) ELSE 0]]
  /\ reqFin' = [reqFin EXCEPT ![r] = TRUE]
  /\ reqStage' = [reqStage EXCEPT ![r] = 6]
  /\ compCredits' = compCredits + 1
  /\ jobOutcome' = [jobOutcome EXCEPT ![r] =
         IF \A q \in {q2 \in 1..2 : q2 <= reqTxs[r].n} : RowVerdict(r, q) \in {2, 3}
           THEN 2 ELSE 1]
  /\ reqTxs' = reqTxs /\ reqOcc' = reqOcc /\ reqMode' = reqMode
  /\ reqAtt' = reqAtt /\ reqOrigin' = reqOrigin
  /\ reqFeeLim' = reqFeeLim /\ reqFacts' = reqFacts
  /\ bJob' = bJob /\ bJobAtt' = bJobAtt
  /\ jobReq' = jobReq /\ jobMode' = jobMode /\ jobAtt' = jobAtt
  /\ jobPlan' = jobPlan /\ jobCur' = jobCur
  /\ jobEv' = jobEv /\ jobStamp' = jobStamp
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VCO, VCR, VWH, VRH, VObs>>
 
(*************************************************************************)
(* Observers: one bounded subscription, queue capacity 1, sticky gap.    *)
(* OfferCommitted is folded into Publish as its atomic publication       *)
(* effect, per the appendix.  Delivery happens outside all domain locks. *)
(*************************************************************************)

(* Subscribe: a new session with no prior-session gap.                   *)
Subscribe ==
  /\ ~inputClosed /\ eventsLeft > 0
  /\ ~subscribed
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ eventsLeft' = eventsLeft - 1
  /\ subscribed' = TRUE
  /\ \E sid \in 0..ReqSlots : sid # subId /\ subId' = sid
  /\ gap' = FALSE
  /\ obsQN' = obsQN /\ obsQRec' = obsQRec
  /\ obsDel' = obsDel /\ obsDelRec' = obsDelRec
  /\ delReady' = delReady /\ deadlineExp' = deadlineExp
  /\ inputClosed' = inputClosed
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VCr>>
 

(* Unsubscribe: drop queued and in-flight delivery resources.  A later   *)
(* subscription is a new session, not evidence the gap was repaired.     *)
Unsubscribe ==
  /\ subscribed
  /\ subscribed' = FALSE
  /\ obsQN' = 0 /\ obsDel' = FALSE /\ delReady' = FALSE
  /\ subId' = subId /\ obsQRec' = obsQRec
  /\ obsDelRec' = obsDelRec /\ gap' = gap
  /\ deadlineExp' = deadlineExp
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VCr>>
 

(* Deliver: transfer the queued committed record to the bounded delivery *)
(* slot with no domain lock held; expose any sticky gap indication.      *)
Deliver ==
  /\ subscribed /\ obsQN = 1 /\ ~obsDel
  /\ ~writerHeld /\ chainRes = 0
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ obsDel' = TRUE /\ obsDelRec' = obsQRec
  /\ obsQN' = 0
  /\ delReady' = TRUE
  /\ pendNotif' = FALSE
  /\ subscribed' = subscribed /\ subId' = subId
  /\ obsQRec' = obsQRec /\ gap' = gap
  /\ deadlineExp' = deadlineExp
  /\ rootRec' = rootRec /\ poolRec' = poolRec /\ backend' = backend
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VReq, VCO, VCR, VWH, VRH, VCr>>
 

(* CompleteDelivery: release the delivery slot; the gap stays sticky.    *)
CompleteDelivery ==
  /\ obsDel /\ delReady
  /\ obsDel' = FALSE /\ delReady' = FALSE
  /\ subscribed' = subscribed /\ subId' = subId
  /\ obsQN' = obsQN /\ obsQRec' = obsQRec
  /\ obsDelRec' = obsDelRec /\ gap' = gap
  /\ deadlineExp' = deadlineExp
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VFlg, VReq, VCO, VCR, VWH, VRH, VCr>>
 

(* Timeout: the expired record is dropped, resources released, and a     *)
(* sticky gap recorded for a surviving subscription.                     *)
ObsTimeout ==
  /\ obsQN = 1 \/ obsDel
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ obsQN' = 0 /\ obsDel' = FALSE /\ delReady' = FALSE
  /\ deadlineExp' = TRUE /\ gap' = TRUE
  /\ pendNotif' = FALSE
  /\ subscribed' = subscribed /\ subId' = subId
  /\ obsQRec' = obsQRec /\ obsDelRec' = obsDelRec
  /\ rootRec' = rootRec /\ poolRec' = poolRec /\ backend' = backend
  /\ UNCHANGED <<VCtr, VRoot, VFrm, VEnv, VJob, VCmp, VCP, VFk, VLP, VPl, VPub, VReq, VCO, VCR, VWH, VRH, VCr>>
 

(*************************************************************************)
(* NextCore: the unrestricted union of every listed action.  The edge    *)
(* observer is hoisted out of the actions and conjoined once in Next    *)
(* below: conjunction distributes over this disjunction exactly, and    *)
(* Apalache inlines action bodies into the ~198 fairness conjuncts, so  *)
(* a per-action observer multiplied StepSafe's body by every action     *)
(* site and exhausted the translation heap under loop finding.          *)
(* Stutter arises from [][Next]_vars at the use sites; no fairness or   *)
(* priority occurs inside NextCore.                                     *)
(*************************************************************************)
NextCore ==
  \/ Prepare
  \/ (\E j \in 1..JobSlots, q \in 1..3 : CompleteProofJ(j, q))
  \/ InvalidateCtx
  \/ PolicyChange
  \/ Reprepare
  \/ SelectPrefix
  \/ CloseFence
  \/ AppendConn
  \/ AppendDisc
  \/ SyncFiles
  \/ SyncFail
  \/ AtomicBatch
  \/ ReceiveSuccess
  \/ ReceiveFailure
  \/ ReceiveAmbiguous
  \/ ReceiveDup
  \/ NextEdge
  \/ ReconcilePool
  \/ Publish
  \/ CompletePub
  \/ CompleteTyped
  \/ CrashFault
  \/ IoFault
  \/ CallbackLoss
  \/ RecoverRootKeep
  \/ RecoverRootResolve
  \/ RecoverPool
  \/ CloseInput
  \/ ChainFinish
  \/ Reconsider
  \/ (\E r \in 1..ReqSlots : AdmStart(r))
  \/ (\E r \in 1..ReqSlots : AdmSnapshot(r))
  \/ (\E r \in 1..ReqSlots : AdmSnapRetry(r))
  \/ (\E r \in 1..ReqSlots, q \in 1..2 : VerifyTakeRP(r, q))
  \/ (\E r \in 1..ReqSlots, q \in 1..2 : VerifyDoneRP(r, q))
  \/ (\E r \in 1..ReqSlots : AssembleVerdicts(r))
  \/ (\E r \in 1..ReqSlots : CommitStale(r))
  \/ (\E r \in 1..ReqSlots : CommitApply(r))
  \/ (\E r \in 1..ReqSlots : AdmRetry(r))
  \/ (\E r \in 1..ReqSlots : AdmFinish(r))
  \/ Subscribe
  \/ Unsubscribe
  \/ Deliver
  \/ CompleteDelivery
  \/ ObsTimeout
  \/ Settle
  \/ EnterDone

(*************************************************************************)
(* Next: one hoisted edge-observer conjunct over the whole union,       *)
(* equivalent to the former per-action form by distribution and         *)
(* identical on every [][Next]_vars behavior for each <<A>>_vars        *)
(* fairness occurrence.                                                 *)
(*************************************************************************)
Next == NextCore /\ stepOK' = StepSafe

(* The full state tuple, for <<A>>_vars and [][Next]_vars.               *)
vars == <<epoch, generation, poolSeq, policyEpoch, diskRoot, liveRoot,
          priorRoot, proposedRoot, bodyFrames, undoFrames, bodyPos,
          undoPos, syncBody, syncUndo, fileSync, dirSync, diskCands,
          eventsLeft, inputClosed, jobReq, jobMode, jobAtt, jobPlan,
          jobCur, jobEv, jobStamp, jobOutcome, compId, compStatus,
          unresComp, chainPhase, faultKind, lifePhase, pool, relay,
          detached, poolTagE, poolTagC, estAcct, reconFacts, factN,
          pubTip, pubHeight, pubVer, pubGen, rootRec, poolRec, backend,
          pendNotif, reqTxs, reqRes, reqOcc, reqFin, reqMode, reqStage,
          reqAtt, reqOrigin, reqFeeLim, reqFacts, bJob, bJobAtt,
          lockOwner, chainRes, writerHeld, readerHeld, subscribed,
          subId, obsQN, obsQRec, obsDel, obsDelRec, gap, delReady,
          deadlineExp, compCredits, stepOK>>

(*************************************************************************)
(* Conditional liveness.  Apalache 0.62.2 supports no WF_/SF_ macros and *)
(* no ENABLED primitive inside temporal properties, so weak fairness of  *)
(* each concrete internal settlement action instance is written as       *)
(*   ( <>[] EnA ) => ( []<> <<A>>_vars )                                 *)
(* where EnA is the action guard evaluated as a state predicate over the *)
(* finite request/job indices.  Fairness appears only in the antecedent; *)
(* the consequent promises only eventual settlement or typed rejection,  *)
(* never successful acceptance, readiness, or optimal packing.           *)
(*************************************************************************)
EnCompleteProofJ(j, q) ==
  /\ backend
  /\ chainPhase # 11 /\ lifePhase # 3
  /\ jobReq[j] \in 1..4
  /\ q <= PlanLen(jobPlan[j])
  /\ jobEv[j][q] = 1

EnInvalidateCtx ==
  \E j \in 1..JobSlots, q \in 1..3 :
    /\ jobReq[j] \in 1..4
    /\ q <= PlanLen(jobPlan[j])
    /\ jobEv[j][q] \in {1, 2}
    /\ jobStamp[j].se # -1 /\ ~StampOK(jobStamp[j])

EnReprepare ==
  \E j \in 1..JobSlots :
    /\ chainPhase = 1 /\ Mod2(generation) = 0
    /\ jobReq[j] \in 1..4 /\ jobOutcome[j] = 0
    /\ jobAtt[j] < MaxAttempts
    /\ \E q \in {q2 \in 1..3 : q2 <= PlanLen(jobPlan[j])} : jobEv[j][q] = 4

EnSelectPrefix ==
  /\ chainRes = 0 /\ Mod2(generation) = 0
  /\ chainPhase \in {1, 9} /\ lifePhase # 3
  /\ \E j \in 1..JobSlots :
       /\ jobReq[j] \in 1..4 /\ jobOutcome[j] = 0
       /\ jobCur[j] < PlanLen(jobPlan[j])
       /\ \A q \in 1..3 : (q <= jobCur[j] + 1) => jobEv[j][q] = 2
       /\ jobStamp[j].se # -1 /\ StampOK(jobStamp[j])

EnCloseFence ==
  chainPhase = 2 /\ chainRes # 0
    /\ Mod2(generation) = 0 /\ generation < CounterBound

EnAppendConn ==
  /\ chainPhase = 3 /\ chainRes # 0
  /\ jobCur[chainRes] < PlanLen(jobPlan[chainRes])
  /\ EdgeIsConn[PE(jobPlan[chainRes], jobCur[chainRes] + 1)]
  /\ bodyPos < FrameBound /\ undoPos < FrameBound

EnAppendDisc ==
  /\ chainPhase = 3 /\ chainRes # 0
  /\ jobCur[chainRes] < PlanLen(jobPlan[chainRes])
  /\ ~EdgeIsConn[PE(jobPlan[chainRes], jobCur[chainRes] + 1)]
  /\ LET t == EdgeFrom[PE(jobPlan[chainRes], jobCur[chainRes] + 1)]
         pb == RefBody(liveRoot.refs, t)
         pu == RefUndo(liveRoot.refs, t)
      IN /\ pb # 0 /\ pu # 0
         /\ pb <= syncBody
         /\ bodyFrames[pb] = FrameCode(t, BlockHeight[t])
         /\ pu <= syncUndo
         /\ undoFrames[pu] = FrameCode(t, BlockHeight[t])

EnSyncFiles == chainPhase = 4 /\ backend

EnAtomicBatch ==
  /\ chainPhase = 5 /\ chainRes # 0
  /\ priorRoot = liveRoot /\ Mod2(generation) = 1
  /\ proposedRoot.cid = liveRoot.cid + 1
  /\ DurableRefs(proposedRoot, syncBody, syncUndo, bodyFrames, undoFrames)

EnReceiveSuccess ==
  /\ chainPhase = 6 /\ chainRes # 0
  /\ compStatus = 0 /\ unresComp /\ factN < FactBound

EnReceiveFailure ==
  chainPhase = 6 /\ chainRes # 0 /\ compStatus = 0 /\ unresComp

EnNextEdge ==
  /\ chainPhase = 7 /\ compStatus = 4 /\ chainRes # 0
  /\ jobCur[chainRes] < PlanLen(jobPlan[chainRes])
  /\ jobEv[chainRes][jobCur[chainRes] + 1] = 2
  /\ jobStamp[chainRes].se # -1 /\ StampOK(jobStamp[chainRes])

EnReconcilePool ==
  /\ chainPhase = 7 /\ compStatus = 4 /\ chainRes # 0
  /\ Mod2(generation) = 1
  /\ factN >= 1 /\ factN \notin estAcct /\ poolSeq < CounterBound
  /\ LET j == chainRes
         k == jobCur[j]
         pl == jobPlan[j]
      IN \/ k = PlanLen(pl)
         \/ /\ k < PlanLen(pl) /\ jobEv[j][k + 1] \in {3, 4}
         \/ /\ jobStamp[j].se # -1 /\ ~StampOK(jobStamp[j])

EnPublish ==
  /\ chainPhase = 8 /\ compStatus # 3 /\ ~unresComp
  /\ diskCands = {} /\ diskRoot = liveRoot
  /\ poolTagE = epoch /\ poolTagC = liveRoot.cid
  /\ Mod2(generation) = 1 /\ generation < CounterBound

EnCompletePub == chainPhase = 9 /\ compStatus # 3 /\ ~unresComp

EnCompleteTyped ==
  /\ chainPhase = 1 /\ lifePhase # 3
  /\ \E j \in 1..JobSlots :
       /\ jobReq[j] \in 1..4 /\ jobOutcome[j] = 0
       /\ jobPlan[j] # 0
       /\ \A q \in 1..3 : (q <= PlanLen(jobPlan[j]) /\ jobPlan[j] # 0) => jobEv[j][q] \in {3, 4}

EnRecoverRootKeep == chainPhase = 10 /\ ~unresComp /\ compStatus # 3

EnRecoverRootResolve ==
  /\ chainPhase = 10
  /\ unresComp \/ compStatus = 3
  /\ \/ DurableRefs(priorRoot, syncBody, syncUndo, bodyFrames, undoFrames)
     \/ DurableRefs(proposedRoot, syncBody, syncUndo, bodyFrames,
                    undoFrames)

EnRecoverPool ==
  /\ chainPhase = 10 /\ rootRec /\ backend
  /\ Mod2(generation) = 1 /\ poolSeq < CounterBound

EnReconsider ==
  /\ chainPhase = 1 /\ Mod2(generation) = 0 /\ lifePhase # 3
  /\ detached.n > 0 /\ poolSeq < CounterBound

EnAdmSnapshot(r) ==
  /\ reqStage[r] = 1 /\ reqOcc[r] /\ ~reqFin[r]
  /\ Mod2(generation) = 0 /\ compCredits > 0

EnAdmSnapRetry(r) ==
  reqStage[r] = 1 /\ reqOcc[r] /\ ~reqFin[r] /\ Mod2(generation) = 1

EnVerifyTakeRP(r, q) ==
  /\ reqStage[r] = 2 /\ reqOcc[r] /\ ~reqFin[r]
  /\ q <= reqTxs[r].n /\ bJob[r][q] = 1 /\ compCredits > 0

EnVerifyDoneRP(r, q) ==
  reqStage[r] = 2 /\ reqOcc[r] /\ q <= reqTxs[r].n /\ bJob[r][q] = 2

EnAssembleVerdicts(r) ==
  /\ reqStage[r] = 2 /\ reqOcc[r] /\ ~reqFin[r]
  /\ \A q \in {q2 \in 1..2 : q2 <= reqTxs[r].n} : bJob[r][q] \in {3, 4}

EnCommitStale(r) ==
  /\ reqStage[r] = 3 /\ reqOcc[r] /\ ~reqFin[r]
  /\ jobStamp[r].se # -1 /\ ~StampOK(jobStamp[r])

EnCommitApply(r) ==
  /\ reqStage[r] = 3 /\ reqOcc[r] /\ ~reqFin[r]
  /\ StampOK(jobStamp[r]) /\ Mod2(generation) = 0
  /\ poolSeq < CounterBound

EnAdmRetry(r) == reqStage[r] = 4 /\ reqOcc[r] /\ ~reqFin[r]

EnAdmFinish(r) == reqStage[r] = 5 /\ reqOcc[r] /\ ~reqFin[r]

EnDeliver ==
  /\ subscribed /\ obsQN = 1 /\ ~obsDel
  /\ ~writerHeld /\ chainRes = 0
  /\ chainPhase # 11 /\ lifePhase # 3

EnCompleteDelivery == obsDel /\ delReady

EnObsTimeout ==
  (obsQN = 1 \/ obsDel) /\ chainPhase # 11 /\ lifePhase # 3

EnCloseInput == ~inputClosed

EnChainFinish ==
  /\ inputClosed /\ chainPhase = 1 /\ lifePhase # 3
  /\ (\A j \in 1..JobSlots : jobReq[j] # 0 => jobOutcome[j] # 0)
  /\ ~unresComp /\ compStatus # 3
  /\ chainRes = 0 /\ detached.n = 0
  /\ rootRec /\ poolRec

EnSettle ==
  /\ lifePhase = 1 /\ inputClosed
  /\ chainPhase \in {1, 11}
  /\ (\A r \in 1..ReqSlots : reqOcc[r] => reqFin[r])
  /\ (\A j \in 1..JobSlots : jobReq[j] # 0 => jobOutcome[j] # 0)
  /\ ~unresComp /\ compStatus # 3
  /\ chainRes = 0 /\ detached.n = 0
  /\ obsQN = 0 /\ ~obsDel /\ ~pendNotif
  /\ ~writerHeld

EnEnterDone == lifePhase = 2

FairInternal ==
  /\ \A j \in 1..JobSlots, q \in 1..3 :
       ( ( <>[] EnCompleteProofJ(j, q) ) =>
         ( []<> <<CompleteProofJ(j, q)>>_vars ) )
  /\ \A r \in 1..ReqSlots, q \in 1..2 :
       ( ( <>[] EnVerifyTakeRP(r, q) ) =>
         ( []<> <<VerifyTakeRP(r, q)>>_vars ) )
       /\ ( ( <>[] EnVerifyDoneRP(r, q) ) =>
         ( []<> <<VerifyDoneRP(r, q)>>_vars ) )
  /\ \A r \in 1..ReqSlots :
       ( ( <>[] EnAdmSnapshot(r) ) => ( []<> <<AdmSnapshot(r)>>_vars ) )
       /\ ( ( <>[] EnAdmSnapRetry(r) ) =>
         ( []<> <<AdmSnapRetry(r)>>_vars ) )
       /\ ( ( <>[] EnAssembleVerdicts(r) ) =>
         ( []<> <<AssembleVerdicts(r)>>_vars ) )
       /\ ( ( <>[] EnCommitStale(r) ) => ( []<> <<CommitStale(r)>>_vars ) )
       /\ ( ( <>[] EnCommitApply(r) ) => ( []<> <<CommitApply(r)>>_vars ) )
       /\ ( ( <>[] EnAdmRetry(r) ) => ( []<> <<AdmRetry(r)>>_vars ) )
       /\ ( ( <>[] EnAdmFinish(r) ) => ( []<> <<AdmFinish(r)>>_vars ) )
  /\ ( ( <>[] EnInvalidateCtx ) => ( []<> <<InvalidateCtx>>_vars ) )
  /\ ( ( <>[] EnReprepare ) => ( []<> <<Reprepare>>_vars ) )
  /\ ( ( <>[] EnSelectPrefix ) => ( []<> <<SelectPrefix>>_vars ) )
  /\ ( ( <>[] EnCloseFence ) => ( []<> <<CloseFence>>_vars ) )
  /\ ( ( <>[] EnAppendConn ) => ( []<> <<AppendConn>>_vars ) )
  /\ ( ( <>[] EnAppendDisc ) => ( []<> <<AppendDisc>>_vars ) )
  /\ ( ( <>[] EnSyncFiles ) => ( []<> <<SyncFiles>>_vars ) )
  /\ ( ( <>[] EnAtomicBatch ) => ( []<> <<AtomicBatch>>_vars ) )
  /\ ( ( <>[] EnReceiveSuccess ) => ( []<> <<ReceiveSuccess>>_vars ) )
  /\ ( ( <>[] EnReceiveFailure ) => ( []<> <<ReceiveFailure>>_vars ) )
  /\ ( ( <>[] EnNextEdge ) => ( []<> <<NextEdge>>_vars ) )
  /\ ( ( <>[] EnReconcilePool ) => ( []<> <<ReconcilePool>>_vars ) )
  /\ ( ( <>[] EnPublish ) => ( []<> <<Publish>>_vars ) )
  /\ ( ( <>[] EnCompletePub ) => ( []<> <<CompletePub>>_vars ) )
  /\ ( ( <>[] EnCompleteTyped ) => ( []<> <<CompleteTyped>>_vars ) )
  /\ ( ( <>[] EnRecoverRootKeep ) => ( []<> <<RecoverRootKeep>>_vars ) )
  /\ ( ( <>[] EnRecoverRootResolve ) =>
         ( []<> <<RecoverRootResolve>>_vars ) )
  /\ ( ( <>[] EnRecoverPool ) => ( []<> <<RecoverPool>>_vars ) )
  /\ ( ( <>[] EnReconsider ) => ( []<> <<Reconsider>>_vars ) )
  /\ ( ( <>[] EnDeliver ) => ( []<> <<Deliver>>_vars ) )
  /\ ( ( <>[] EnCompleteDelivery ) => ( []<> <<CompleteDelivery>>_vars ) )
  /\ ( ( <>[] EnObsTimeout ) => ( []<> <<ObsTimeout>>_vars ) )
  /\ ( ( <>[] EnCloseInput ) => ( []<> <<CloseInput>>_vars ) )
  /\ ( ( <>[] EnChainFinish ) => ( []<> <<ChainFinish>>_vars ) )
  /\ ( ( <>[] EnSettle ) => ( []<> <<Settle>>_vars ) )
  /\ ( ( <>[] EnEnterDone ) => ( []<> <<EnterDone>>_vars ) )

(* A chain job counts as accepted work from allocation; settlement is a  *)
(* committed prefix or a typed rejection.                                *)
AcceptedW(w) == jobReq[w] \in 1..4
SettledW(w) == jobOutcome[w] # 0

StartedR(r) == reqOcc[r]
VerdictR(r) == reqFin[r]

RecoveryRequired == chainPhase = 10 \/ unresComp \/ compStatus = 3
RecoverySettled == chainPhase # 10 /\ ~unresComp /\ compStatus # 3

ConditionalProgress ==
  (FairInternal
     /\ <> inputClosed
     /\ <>[] backend
     /\ <>[] (faultKind = 0))
  =>
    ( (\A w \in 1..JobSlots : [](AcceptedW(w) => <> SettledW(w)))
      /\ (\A r \in 1..ReqSlots : [](StartedR(r) => <> VerdictR(r)))
      /\ [](RecoveryRequired => <> RecoverySettled)
      /\ <> (lifePhase = 3) )

=============================================================================
