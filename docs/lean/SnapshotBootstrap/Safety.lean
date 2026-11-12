/-
Safety invariants of the SnapshotBootstrap lifecycle machine
(Rust owners `crates/storage`, `crates/execution`, and `crates/projection`).

Anchors: Tony Hoare, Claude Shannon

Models SnapshotManifest artifact commitments, single-pass streaming of
coin store and ScriptLive base into an unpublished keyspace (SNP-06),
publication gating on UTXO verification (SNP-07), index generation
attachment only on verified commitment (SNP-05), index failure
isolation vs assumed chainstate closure (SNP-10), three independent
reported positions (SNP-09), and explicit historical body availability
separated from index locators (SNP-08, SNP-11).

Design model only: specifies the state machine and invariant safety.
Not an implementation refinement proof or physical durability proof.
-/

namespace SnapshotBootstrap

structure State where
  bootstrapPhase : Nat
  unpublishedStreamed : Nat
  coinsPublished : Nat
  scriptLivePublished : Nat
  utxoVerified : Nat
  indexVerified : Nat
  indexAttached : Nat
  indexInvalidated : Nat
  chainstateClosed : Nat
  unpublishedDiscarded : Nat
  activeTipHeight : Nat
  historicalValHeight : Nat
  projectionCoverage : Nat
  bodyQueryHeight : Nat
  bodyQueryResult : Nat

def hasHistoricalBodies : Nat := 0
def baseHeight : Nat := 2
def maxHeight : Nat := 4

def init : State :=
  { bootstrapPhase := 0,
    unpublishedStreamed := 0,
    coinsPublished := 0,
    scriptLivePublished := 0,
    utxoVerified := 0,
    indexVerified := 0,
    indexAttached := 0,
    indexInvalidated := 0,
    chainstateClosed := 0,
    unpublishedDiscarded := 0,
    activeTipHeight := 0,
    historicalValHeight := 0,
    projectionCoverage := 0,
    bodyQueryHeight := 0,
    bodyQueryResult := 0 }

inductive Action
  | streamSnapshot
  | verifyCommitments (utxoOk : Nat) (indexOk : Nat)
  | publishValidSnapshot
  | rejectInvalidUtxo
  | advanceActiveChain
  | advanceHistoricalValidation
  | advanceProjectionCoverage
  | queryHistoricalBody (h : Nat)
  | stutter

def step (s : State) : Action → State
  | .streamSnapshot =>
    if s.bootstrapPhase = 0 then
      { s with bootstrapPhase := 1, unpublishedStreamed := 1, coinsPublished := 0, scriptLivePublished := 0 }
    else s
  | .verifyCommitments utxoOk indexOk =>
    if s.bootstrapPhase = 1 then
      { s with bootstrapPhase := 2, utxoVerified := utxoOk, indexVerified := indexOk }
    else s
  | .publishValidSnapshot =>
    if s.bootstrapPhase = 2 ∧ s.utxoVerified = 1 then
      if s.indexVerified = 1 then
        { s with bootstrapPhase := 3, coinsPublished := 1, scriptLivePublished := 1,
                 indexAttached := 1, indexInvalidated := 0,
                 projectionCoverage := baseHeight, activeTipHeight := baseHeight }
      else
        { s with bootstrapPhase := 3, coinsPublished := 1, scriptLivePublished := 1,
                 indexAttached := 0, indexInvalidated := 1,
                 projectionCoverage := 0, activeTipHeight := baseHeight }
    else s
  | .rejectInvalidUtxo =>
    if s.bootstrapPhase = 2 ∧ s.utxoVerified = 0 then
      { s with bootstrapPhase := 4, unpublishedDiscarded := 1, chainstateClosed := 1,
               coinsPublished := 0, scriptLivePublished := 0, indexAttached := 0 }
    else s
  | .advanceActiveChain =>
    if s.bootstrapPhase = 3 ∧ s.chainstateClosed = 0 ∧ s.activeTipHeight < maxHeight then
      { s with activeTipHeight := s.activeTipHeight + 1 }
    else s
  | .advanceHistoricalValidation =>
    if s.bootstrapPhase = 3 ∧ s.historicalValHeight < baseHeight then
      { s with historicalValHeight := s.historicalValHeight + 1 }
    else s
  | .advanceProjectionCoverage =>
    if s.bootstrapPhase = 3 ∧ s.indexAttached = 1 ∧ s.projectionCoverage < s.activeTipHeight then
      { s with projectionCoverage := s.projectionCoverage + 1 }
    else s
  | .queryHistoricalBody h =>
    if s.bootstrapPhase = 3 then
      let res := if h ≤ baseHeight then
        (if hasHistoricalBodies = 1 then 1 else 2)
      else 1
      { s with bodyQueryHeight := h, bodyQueryResult := res }
    else s
  | .stutter => s
def safety (s : State) : Prop :=
  -- SNP-07: Publication requires verified UTXO commitment
  ((s.coinsPublished = 1 ∨ s.scriptLivePublished = 1) → s.utxoVerified = 1)
  -- SNP-07, SNP-10: Invalid UTXO never publishes coins or ScriptLive
  ∧ ((s.utxoVerified = 0 ∧ (s.bootstrapPhase = 2 ∨ s.bootstrapPhase = 4)) →
       (s.coinsPublished = 0 ∧ s.scriptLivePublished = 0))
  -- Phase bounds: no premature publication before phase 3
  ∧ (s.bootstrapPhase < 3 → (s.coinsPublished = 0 ∧ s.scriptLivePublished = 0 ∧ s.indexAttached = 0))
  -- Closed chainstate occurs only in phase 4
  ∧ (s.bootstrapPhase < 4 → s.chainstateClosed = 0)
  -- SNP-05: Index generation attaches only if index commitment is verified
  ∧ (s.indexAttached = 1 → s.indexVerified = 1)
  -- SNP-10: Failed index commitment is isolated: invalidates projection only, chainstate remains open
  ∧ ((s.utxoVerified = 1 ∧ s.indexVerified = 0 ∧ s.bootstrapPhase = 3) →
       (s.chainstateClosed = 0 ∧ s.indexInvalidated = 1 ∧ s.indexAttached = 0))
  -- SNP-10: Failed UTXO assumption closes the affected chainstate
  ∧ (s.bootstrapPhase = 4 → s.chainstateClosed = 1)
  -- SNP-11: Snapshot index locator does not imply raw transaction body when bodies are not retained
  ∧ ((hasHistoricalBodies = 0 ∧ s.bodyQueryHeight ≤ baseHeight ∧ s.bodyQueryResult ≠ 0) →
       s.bodyQueryResult = 2)
  -- SNP-09: Three positions exist and are bounded independently
  ∧ s.activeTipHeight ≤ maxHeight
  ∧ s.historicalValHeight ≤ baseHeight
  ∧ s.projectionCoverage ≤ maxHeight
  ∧ s.bootstrapPhase ≤ 4
theorem safety_init : safety init := by
  unfold safety init hasHistoricalBodies baseHeight maxHeight
  decide

-- SNP-01, SNP-02, SNP-03, SNP-04, SNP-05, SNP-06, SNP-07, SNP-08, SNP-09, SNP-10, SNP-11
/-- `safety` is an inductive invariant of `step` from `init`. -/
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  cases a
  case streamSnapshot =>
    dsimp [step]
    split
    · rename_i hG
      unfold safety at h ⊢
      rcases h with ⟨hPub, hInvPub, hPrePub, hPreCls, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
      have hPre := hPrePub (by omega)
      dsimp
      refine ⟨by intro h; rcases h with h1 | h2 <;> contradiction,
              by intro ⟨_, hOr⟩; rcases hOr with h1 | h2 <;> contradiction,
              by intro _; exact ⟨rfl, rfl, hPre.2.2⟩,
              by intro _; exact hPreCls (by omega),
              by intro h; have := hPre.2.2.symm.trans h; contradiction,
              by intro ⟨_, _, h3⟩; contradiction,
              by intro h; contradiction,
              hBody, hActBnd, hHistBnd, hCovBnd, by omega⟩
    · exact h
  case verifyCommitments utxoOk indexOk =>
    dsimp [step]
    split
    · rename_i hG
      unfold safety at h ⊢
      rcases h with ⟨hPub, hInvPub, hPrePub, hPreCls, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
      have hPre := hPrePub (by omega)
      dsimp
      refine ⟨by intro h; rcases h with h1 | h2 <;> omega,
              by intro _; exact ⟨hPre.1, hPre.2.1⟩,
              by intro _; exact ⟨hPre.1, hPre.2.1, hPre.2.2⟩,
              by intro _; exact hPreCls (by omega),
              by intro h; have := hPre.2.2.symm.trans h; contradiction,
              by intro ⟨_, _, h3⟩; contradiction,
              by intro h; contradiction,
              hBody, hActBnd, hHistBnd, hCovBnd, by omega⟩
    · exact h
  case publishValidSnapshot =>
    dsimp [step]
    split
    · rename_i hG
      unfold safety at h ⊢
      rcases h with ⟨hPub, hInvPub, hPrePub, hPreCls, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
      have hCls0 := hPreCls (by omega)
      split
      · dsimp
        refine ⟨by intro _; omega,
                by intro ⟨hU0, _⟩; omega,
                by intro h; omega,
                by intro _; exact hCls0,
                by intro _; omega,
                by intro ⟨_, hI0, _⟩; omega,
                by intro h; contradiction,
                hBody, by unfold baseHeight maxHeight; omega, hHistBnd, by unfold baseHeight maxHeight; omega, by omega⟩
      · dsimp
        refine ⟨by intro _; omega,
                by intro ⟨hU0, _⟩; omega,
                by intro h; omega,
                by intro _; exact hCls0,
                by intro h; contradiction,
                by intro _; refine ⟨hCls0, rfl, rfl⟩,
                by intro h; contradiction,
                hBody, by unfold baseHeight maxHeight; omega, hHistBnd, by unfold maxHeight; omega, by omega⟩
    · exact h
  case rejectInvalidUtxo =>
    dsimp [step]
    split
    · rename_i hG
      unfold safety at h ⊢
      rcases h with ⟨hPub, hInvPub, hPrePub, hPreCls, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
      dsimp
      refine ⟨by intro h; rcases h with h1 | h2 <;> contradiction,
              by intro _; refine ⟨rfl, rfl⟩,
              by intro h; omega,
              by intro h; omega,
              by intro h; contradiction,
              by intro ⟨_, _, h3⟩; contradiction,
              by intro _; rfl,
              hBody, hActBnd, hHistBnd, hCovBnd, by omega⟩
    · exact h
  case advanceActiveChain =>
    dsimp [step]
    split
    · rename_i hG
      unfold safety at h ⊢
      rcases h with ⟨hPub, hInvPub, hPrePub, hPreCls, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
      dsimp
      refine ⟨hPub, hInvPub, by intro h; omega, by intro h; omega, hIdxAtt, hIdxIso, hCls, hBody, by omega, hHistBnd, hCovBnd, hPhaseBnd⟩
    · exact h
  case advanceHistoricalValidation =>
    dsimp [step]
    split
    · rename_i hG
      unfold safety at h ⊢
      rcases h with ⟨hPub, hInvPub, hPrePub, hPreCls, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
      dsimp
      refine ⟨hPub, hInvPub, by intro h; omega, by intro h; omega, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, by omega, hCovBnd, hPhaseBnd⟩
    · exact h
  case advanceProjectionCoverage =>
    dsimp [step]
    split
    · rename_i hG
      unfold safety at h ⊢
      rcases h with ⟨hPub, hInvPub, hPrePub, hPreCls, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
      dsimp
      refine ⟨hPub, hInvPub, by intro h; omega, by intro h; omega, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, hHistBnd, by omega, hPhaseBnd⟩
    · exact h
  case queryHistoricalBody hQuery =>
    dsimp [step]
    split
    · rename_i hG
      unfold safety at h ⊢
      rcases h with ⟨hPub, hInvPub, hPrePub, hPreCls, hIdxAtt, hIdxIso, hCls, hBody, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
      dsimp
      split
      · split
        · refine ⟨hPub, hInvPub, by intro h; omega, by intro h; omega, hIdxAtt, hIdxIso, hCls, ?_, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
          intro ⟨h0, _, _⟩
          unfold hasHistoricalBodies at h0
          contradiction
        · refine ⟨hPub, hInvPub, by intro h; omega, by intro h; omega, hIdxAtt, hIdxIso, hCls, by intro _; rfl, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
      · refine ⟨hPub, hInvPub, by intro h; omega, by intro h; omega, hIdxAtt, hIdxIso, hCls, ?_, hActBnd, hHistBnd, hCovBnd, hPhaseBnd⟩
        intro ⟨_, hLe, _⟩
        omega
    · exact h
  case stutter =>
    dsimp [step]
    exact h

end SnapshotBootstrap
