/-
Safety invariants of the CommittedFacts handoff queue and projection worker
(Rust owners `crates/storage/src/committed_facts.rs`, `crates/node/src/facts_queue.rs`,
and `crates/projection/src/runtime/catch_up.rs`).

Anchors: David Parnas, Claude Shannon

Models consensus commit creating CommittedFacts, bounded queue
admission, overflow dropping with gap signaling (PRJ-04), payload-free
wake notification (IDX-08), live fact consumption with zero body reads
(PRJ-01), fallback recovery loading (PRJ-02), and three independent
positions (PRJ-13).

Design model only: specifies the state machine and invariant safety.
Not an implementation refinement proof or physical durability proof.
-/

namespace ProjectionIndex.Handoff

structure State where
  appliedHeight : Nat
  verifiedHeight : Nat
  coverageHeight : Nat
  queueLen : Nat
  queueBytes : Nat
  gap : Bool
  wakePending : Bool
  liveBodyReads : Nat
  recoveryBodyReads : Nat
  reorgCount : Nat
deriving Repr, DecidableEq

def maxHeight : Nat := 3
def queueBudget : Nat := 2
def maxVerified : Nat := 2

def init : State :=
  { appliedHeight := 0,
    verifiedHeight := 0,
    coverageHeight := 0,
    queueLen := 0,
    queueBytes := 0,
    gap := false,
    wakePending := false,
    liveBodyReads := 0,
    recoveryBodyReads := 0,
    reorgCount := 0 }

inductive Action
  | commitBlock
  | verifyHistorical
  | workerLiveStep
  | workerRecoveryStep
  | reorganize (fork : Nat)
  | stutter

def step (s : State) : Action → State
  | .commitBlock =>
    if s.appliedHeight < maxHeight then
      if s.queueBytes + 1 ≤ queueBudget then
        { s with appliedHeight := s.appliedHeight + 1,
                 queueLen := s.queueLen + 1,
                 queueBytes := s.queueBytes + 1,
                 wakePending := true }
      else
        { s with appliedHeight := s.appliedHeight + 1,
                 gap := true,
                 wakePending := true }
    else s
  | .verifyHistorical =>
    if s.verifiedHeight < maxVerified then
      { s with verifiedHeight := s.verifiedHeight + 1 }
    else s
  | .workerLiveStep =>
    if s.gap = false ∧ s.queueLen > 0 then
      { s with queueLen := s.queueLen - 1,
               queueBytes := s.queueBytes - 1,
               coverageHeight := s.coverageHeight + 1,
               wakePending := false }
    else s
  | .workerRecoveryStep =>
    if s.gap = true ∧ s.coverageHeight < s.appliedHeight then
      let nextCoverage := s.coverageHeight + 1
      { s with queueLen := 0,
               queueBytes := 0,
               coverageHeight := nextCoverage,
               recoveryBodyReads := s.recoveryBodyReads + 1,
               gap := (nextCoverage ≠ s.appliedHeight),
               wakePending := false }
    else s
  | .reorganize fork =>
    if s.reorgCount < 1 ∧ s.appliedHeight > 1 ∧ 1 ≤ fork ∧ fork < s.appliedHeight then
      { s with appliedHeight := fork,
               coverageHeight := if s.coverageHeight > fork then fork else s.coverageHeight,
               queueLen := 0,
               queueBytes := 0,
               gap := true,
               wakePending := true,
               reorgCount := s.reorgCount + 1 }
    else s
  | .stutter => s

def safety (s : State) : Prop :=
  s.liveBodyReads = 0
  ∧ s.queueBytes ≤ queueBudget
  ∧ s.queueLen ≤ s.queueBytes
  ∧ s.coverageHeight + s.queueLen ≤ s.appliedHeight
  ∧ (s.gap = false → s.queueBytes = s.queueLen)
  ∧ s.verifiedHeight ≤ maxVerified

theorem safety_init : safety init := by
  unfold safety init queueBudget maxVerified
  decide

-- PRJ-01, PRJ-02, PRJ-04, PRJ-13, IDX-08
/-- `safety` is an inductive invariant of `step` from `init`. -/
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  unfold safety at *
  rcases h with ⟨hLive, hQBytes, hQLen, hCov, hGap, hVer⟩
  cases a <;> simp only [step] <;> (try split) <;> (try split)
  all_goals
    try dsimp only
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
  all_goals
    try exact hLive
    try exact hVer
    try (intro hg; contradiction)
    try (intro hg; rw [hGap hg])
    try (intro hg; rfl)
    try (intro hg; rename_i hCond; have := hCond.1; contradiction)
    try (intro hg; rename_i hCond1 hCond2; have := hCond2.1; contradiction)
    try (intro hg; rename_i h1 h2 h3; omega)
    try (simp only [queueBudget, maxHeight, maxVerified] at *; omega)
