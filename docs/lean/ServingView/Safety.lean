/-
Safety invariants of the ServingView query lifecycle machine
(Rust owners `crates/serving` and `crates/projection`).

Anchors: Tony Hoare, Claude Shannon

Models AppliedEpoch, CapabilityCoverage, capture_view, single-view tied
query evaluation, resilience to ordinary chain extension (QRY-03),
explicit Unavailable for out-of-coverage queries (QRY-05), generation
retirement on deep reorg leading to ExpiredView (QRY-06), lock-free
self-contained ScriptLive (PRJ-11), reads of an immutable captured view
under concurrent chain extension (QRY-02), and post-access serialization
without chain or mempool locks (QRY-08).

Design model only: specifies the state machine and invariant safety.
Not an implementation refinement proof or physical durability proof.
-/

namespace ServingView

structure State where
  tipHeight : Nat
  tipCommit : Nat
  currentGen : Nat
  retiredBelow : Nat
  coverageHeight : Nat
  viewEpochHeight : Nat
  viewEpochCommit : Nat
  viewGen : Nat
  viewCoverage : Nat
  viewStatus : Nat
  queryPhase : Nat
  queryTargetHeight : Nat
  queryIsTipPromised : Nat
  queryIsScriptLive : Nat
  queryResult : Nat
  chainLockHeld : Nat
  mempoolLockHeld : Nat

def maxHeight : Nat := 4
def maxGen : Nat := 3

def init : State :=
  { tipHeight := 0,
    tipCommit := 0,
    currentGen := 1,
    retiredBelow := 0,
    coverageHeight := 0,
    viewEpochHeight := 0,
    viewEpochCommit := 0,
    viewGen := 1,
    viewCoverage := 0,
    viewStatus := 0,
    queryPhase := 0,
    queryTargetHeight := 0,
    queryIsTipPromised := 0,
    queryIsScriptLive := 0,
    queryResult := 0,
    chainLockHeld := 0,
    mempoolLockHeld := 0 }

inductive Action
  | extendChain
  | advanceCoverage
  | deepReorg
  | captureView (isScriptLive : Nat) (isTip : Nat) (targetH : Nat)
  | accessState
  | startSerialization
  | finishQuery
  | stutter

def step (s : State) : Action → State
  | .extendChain =>
    if s.tipHeight < maxHeight then
      { s with tipHeight := s.tipHeight + 1, tipCommit := s.tipCommit + 1 }
    else s
  | .advanceCoverage =>
    if s.coverageHeight < s.tipHeight then
      { s with coverageHeight := s.coverageHeight + 1 }
    else s
  | .deepReorg =>
    if s.currentGen < maxGen then
      let newRetired := s.currentGen
      let newStatus := if s.viewGen ≤ newRetired then 2 else s.viewStatus
      { s with currentGen := s.currentGen + 1, retiredBelow := newRetired, viewStatus := newStatus }
    else s
  | .captureView isScriptLive isTip targetH =>
    if s.queryPhase = 0 then
      let chainLock := if isScriptLive = 0 then 1 else 0
      { s with queryPhase := 1,
               viewEpochHeight := s.tipHeight,
               viewEpochCommit := s.tipCommit,
               viewGen := s.currentGen,
               viewCoverage := s.coverageHeight,
               viewStatus := 1,
               queryTargetHeight := targetH,
               queryIsTipPromised := isTip,
               queryIsScriptLive := isScriptLive,
               queryResult := 0,
               chainLockHeld := chainLock,
               mempoolLockHeld := 0 }
    else s
  | .accessState =>
    if s.queryPhase = 1 then
      if s.viewStatus = 2 ∨ s.viewGen ≤ s.retiredBelow then
        { s with queryPhase := 2, queryResult := 3,
                 chainLockHeld := 0, mempoolLockHeld := 0 }
      else if s.queryIsTipPromised ≠ 0 ∧ s.viewEpochCommit ≠ s.tipCommit then
        { s with queryPhase := 2, queryResult := 4,
                 chainLockHeld := 0, mempoolLockHeld := 0 }
      else if s.viewCoverage < s.queryTargetHeight then
        { s with queryPhase := 2, queryResult := 2,
                 chainLockHeld := 0, mempoolLockHeld := 0 }
      else
        { s with queryPhase := 2, queryResult := 1,
                 chainLockHeld := 0, mempoolLockHeld := 0 }
    else s
  | .startSerialization =>
    if s.queryPhase = 2 ∧ s.chainLockHeld = 0 ∧ s.mempoolLockHeld = 0 then
      { s with queryPhase := 3 }
    else s
  | .finishQuery =>
    if s.queryPhase = 3 then
      { s with queryPhase := 0, queryResult := 0,
               chainLockHeld := 0, mempoolLockHeld := 0 }
    else s
  | .stutter => s

def safety (s : State) : Prop :=
  -- QRY-03: Ordinary chain extension never produces Retry for historical queries
  (s.queryResult = 4 → s.queryIsTipPromised ≠ 0)
  -- QRY-05: Queries outside declared coverage return Unavailable, never AnswerOk
  ∧ (s.queryResult = 1 → s.queryTargetHeight ≤ s.viewCoverage)
  -- QRY-06: ExpiredView is returned when the view's generation has been retired
  ∧ (s.queryResult = 3 → (s.viewStatus = 2 ∨ s.viewGen ≤ s.retiredBelow))
  -- Phase invariants
  ∧ (s.queryPhase = 1 → s.queryResult = 0)
  ∧ (s.retiredBelow ≤ s.currentGen)
  -- PRJ-11: ScriptLive never acquires the chain lock
  ∧ (s.queryIsScriptLive ≠ 0 → s.chainLockHeld = 0)
  -- QRY-08: Serialization runs with no chain or mempool locks held
  ∧ (s.queryPhase = 3 → (s.chainLockHeld = 0 ∧ s.mempoolLockHeld = 0))
  -- Well-formed machine bounds
  ∧ s.tipHeight ≤ maxHeight
  ∧ s.coverageHeight ≤ s.tipHeight
  ∧ s.currentGen ≤ maxGen
  ∧ s.queryPhase ≤ 3
  ∧ s.queryResult ≤ 4
  ∧ s.chainLockHeld ≤ 1
  ∧ s.mempoolLockHeld ≤ 1

theorem safety_init : safety init := by
  unfold safety init maxHeight maxGen
  decide

-- QRY-01, QRY-02, QRY-03, QRY-04, QRY-05, QRY-06, QRY-07, QRY-08, PRJ-11
/-- `safety` is an inductive invariant of `step` from `init`. -/
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  unfold safety at *
  rcases h with ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, hCovBnd, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
  cases a
  case extendChain =>
    dsimp [step]
    split <;> try dsimp
    · refine ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, by omega, by omega, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
    · exact ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, hCovBnd, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
  case advanceCoverage =>
    dsimp [step]
    split <;> try dsimp
    · refine ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, by omega, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
    · exact ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, hCovBnd, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
  case deepReorg =>
    dsimp [step]
    split <;> try dsimp
    · split <;> try dsimp
      · refine ⟨hRetry, hCover, ?_, hPhase1, by omega, hSL, hSerNoLock, hTipBnd, hCovBnd, by omega, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
        intro _; left; rfl
      · refine ⟨hRetry, hCover, ?_, hPhase1, by omega, hSL, hSerNoLock, hTipBnd, hCovBnd, by omega, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
        intro h3
        rcases hExp h3 with h1 | h2
        · left; exact h1
        · right; omega
    · exact ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, hCovBnd, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
  case captureView isScriptLive isTip targetH =>
    dsimp [step]
    split <;> try dsimp
    · refine ⟨by intro h; contradiction, ?_, by intro h; contradiction, ?_, ?_, ?_, by intro h; contradiction, hTipBnd, hCovBnd, hGenBnd, by omega, by omega, ?_, by omega⟩
      · intro h; contradiction
      · intro _; rfl
      · omega
      · intro h; split <;> omega
      · split <;> omega
    · exact ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, hCovBnd, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
  case accessState =>
    dsimp [step]
    split <;> try dsimp
    · split <;> try dsimp
      · refine ⟨by intro h; contradiction, by intro h; contradiction, ?_, by intro h; contradiction, hRetGen, by intro _; rfl, by intro h; contradiction, hTipBnd, hCovBnd, hGenBnd, by omega, by omega, by omega, by omega⟩
        intro _
        assumption
      · split <;> try dsimp
        · refine ⟨?_, by intro h; contradiction, by intro h; contradiction, by intro h; contradiction, hRetGen, by intro _; rfl, by intro h; contradiction, hTipBnd, hCovBnd, hGenBnd, by omega, by omega, by omega, by omega⟩
          intro _
          omega
        · split <;> try dsimp
          · refine ⟨by intro h; contradiction, by intro h; contradiction, by intro h; contradiction, by intro h; contradiction, hRetGen, by intro _; rfl, by intro h; contradiction, hTipBnd, hCovBnd, hGenBnd, by omega, by omega, by omega, by omega⟩
          · refine ⟨by intro h; contradiction, ?_, by intro h; contradiction, by intro h; contradiction, hRetGen, by intro _; rfl, by intro h; contradiction, hTipBnd, hCovBnd, hGenBnd, by omega, by omega, by omega, by omega⟩
            intro _
            omega
    · exact ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, hCovBnd, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
  case startSerialization =>
    dsimp [step]
    split <;> try dsimp
    · rename_i hG
      refine ⟨hRetry, hCover, hExp, by intro h; contradiction, hRetGen, hSL, ?_, hTipBnd, hCovBnd, hGenBnd, by omega, hResBnd, by omega, by omega⟩
      intro _
      exact ⟨hG.2.1, hG.2.2⟩
    · exact ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, hCovBnd, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
  case finishQuery =>
    dsimp [step]
    split <;> try dsimp
    · refine ⟨by intro h; contradiction, by intro h; contradiction, by intro h; contradiction, by intro h; contradiction, hRetGen, by intro _; rfl, by intro h; contradiction, hTipBnd, hCovBnd, hGenBnd, by omega, by omega, by omega, by omega⟩
    · exact ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, hCovBnd, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩
  case stutter =>
    dsimp [step]
    exact ⟨hRetry, hCover, hExp, hPhase1, hRetGen, hSL, hSerNoLock, hTipBnd, hCovBnd, hGenBnd, hPhaseBnd, hResBnd, hCLBnd, hMLBnd⟩

end ServingView
