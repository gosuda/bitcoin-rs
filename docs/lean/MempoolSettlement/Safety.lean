/-
Safety invariants of the MempoolSettlement and MiningControl pairing model.
Rust owners: crates/mempool/src/gateway.rs and crates/node/src/mining.rs.

Anchors: Claude Shannon, Tony Hoare, Herbert Simon.

Models orderly mempool settlement from committed facts (MPS-01), matched pairing
of AppliedEpoch and MempoolGeneration during template assembly (MPS-03), and
consistent unsettlement across chain reorganizations.

Design model only: specifies the state machine and invariant safety.
Not an implementation refinement proof or physical durability proof.
-/

namespace MempoolSettlement

structure State where
  appliedEpoch : Nat
  settledAtEpoch : Nat
  mempoolGen : Nat
  templateActive : Bool
  templateEpoch : Nat
  templateGen : Nat
  templateHasConfirmed : Bool
  unsettledConfirmedCount : Nat
  factsQueueLen : Nat

def init : State :=
  { appliedEpoch := 1,
    settledAtEpoch := 1,
    mempoolGen := 0,
    templateActive := false,
    templateEpoch := 0,
    templateGen := 0,
    templateHasConfirmed := false,
    unsettledConfirmedCount := 0,
    factsQueueLen := 0 }

inductive Action
  | admitTx
  | commitBlock
  | commitReorg
  | settleConnectFact (clearsConfirmed : Bool)
  | settleDisconnectFact
  | assembleTemplate (reqEpoch : Nat) (reqGen : Nat)
  | mineBlock
  | stutter

def step (s : State) : Action → State
  | .admitTx =>
    { s with mempoolGen := s.mempoolGen + 1 }
  | .commitBlock =>
    { s with appliedEpoch := s.appliedEpoch + 1,
             factsQueueLen := s.factsQueueLen + 1,
             unsettledConfirmedCount := s.unsettledConfirmedCount + 1,
             templateActive := false,
             templateHasConfirmed := false }
  | .commitReorg =>
    { s with appliedEpoch := s.appliedEpoch + 1,
             factsQueueLen := s.factsQueueLen + 2,
             templateActive := false,
             templateHasConfirmed := false }
  | .settleConnectFact clearsConfirmed =>
    if 0 < s.factsQueueLen then
      let newQueueLen := s.factsQueueLen - 1
      let newConfirmed := if clearsConfirmed ∧ 0 < s.unsettledConfirmedCount then s.unsettledConfirmedCount - 1 else s.unsettledConfirmedCount
      let newSettled := if newQueueLen = 0 then s.appliedEpoch else s.settledAtEpoch
      { s with factsQueueLen := newQueueLen,
               mempoolGen := s.mempoolGen + 1,
               unsettledConfirmedCount := if newQueueLen = 0 then 0 else newConfirmed,
               settledAtEpoch := newSettled }
    else s
  | .settleDisconnectFact =>
    if 0 < s.factsQueueLen then
      let newQueueLen := s.factsQueueLen - 1
      let newSettled := if newQueueLen = 0 then s.appliedEpoch else s.settledAtEpoch
      { s with factsQueueLen := newQueueLen,
               mempoolGen := s.mempoolGen + 1,
               unsettledConfirmedCount := if newQueueLen = 0 then 0 else s.unsettledConfirmedCount,
               settledAtEpoch := newSettled }
    else s
  | .assembleTemplate reqEpoch reqGen =>
    if reqEpoch = s.appliedEpoch ∧ reqGen = s.mempoolGen ∧ s.settledAtEpoch = s.appliedEpoch then
      { s with templateActive := true,
               templateEpoch := reqEpoch,
               templateGen := reqGen,
               templateHasConfirmed := (0 < s.unsettledConfirmedCount) }
    else s
  | .mineBlock =>
    if s.templateActive ∧ s.templateEpoch = s.appliedEpoch then
      { s with templateActive := false, templateHasConfirmed := false }
    else s
  | .stutter => s

def safety (s : State) : Prop :=
  s.settledAtEpoch ≤ s.appliedEpoch
  ∧ (s.factsQueueLen = 0 ↔ s.settledAtEpoch = s.appliedEpoch)
  ∧ (s.settledAtEpoch = s.appliedEpoch → s.unsettledConfirmedCount = 0)
  ∧ (s.templateActive →
       s.factsQueueLen = 0
       ∧ s.templateEpoch = s.appliedEpoch
       ∧ s.templateEpoch = s.settledAtEpoch
       ∧ ¬s.templateHasConfirmed)

-- MPS-01, MPS-03
theorem safety_init : safety init := by
  unfold safety init
  decide

-- MPS-01, MPS-03
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  rcases h with ⟨hSettledLe, hQueueIff, hSettledZero, hTemplate⟩
  cases a
  case admitTx =>
    dsimp [step, safety] at *
    refine ⟨hSettledLe, hQueueIff, hSettledZero, hTemplate⟩
  case commitBlock =>
    dsimp [step, safety] at *
    have hqpos : s.factsQueueLen + 1 ≠ 0 := by omega
    have hneq : s.settledAtEpoch ≠ s.appliedEpoch + 1 := by omega
    refine ⟨by omega, ⟨by intro hq; contradiction, by intro hs; contradiction⟩, by intro hs; contradiction, by intro ht; cases ht⟩
  case commitReorg =>
    dsimp [step, safety] at *
    have hqpos : s.factsQueueLen + 2 ≠ 0 := by omega
    have hneq : s.settledAtEpoch ≠ s.appliedEpoch + 1 := by omega
    refine ⟨by omega, ⟨by intro hq; contradiction, by intro hs; contradiction⟩, by intro hs; contradiction, by intro ht; cases ht⟩
  case settleConnectFact clearsConfirmed =>
    dsimp [step]
    split
    · rename_i hq
      have hNoTpl : s.templateActive = false := by
        cases hta : s.templateActive
        · rfl
        · exfalso; have h0 := (hTemplate hta).1; omega
      by_cases hzero : s.factsQueueLen - 1 = 0
      · simp only [hzero, ite_true]
        dsimp [safety]
        refine ⟨by omega, ⟨by intro _; rfl, by intro _; rfl⟩, by intro _; rfl, by intro ht; rw [hNoTpl] at ht; cases ht⟩
      · simp only [hzero, ite_false]
        dsimp [safety]
        have hnotEpoch : s.settledAtEpoch ≠ s.appliedEpoch := by
          intro heq
          have h0 := hQueueIff.2 heq
          omega
        refine ⟨hSettledLe, ⟨by intro hq1; contradiction, by intro heq; contradiction⟩, by intro heq; contradiction, by intro ht; rw [hNoTpl] at ht; cases ht⟩
    · exact ⟨hSettledLe, hQueueIff, hSettledZero, hTemplate⟩
  case settleDisconnectFact =>
    dsimp [step]
    split
    · rename_i hq
      have hNoTpl : s.templateActive = false := by
        cases hta : s.templateActive
        · rfl
        · exfalso; have h0 := (hTemplate hta).1; omega
      by_cases hzero : s.factsQueueLen - 1 = 0
      · simp only [hzero, ite_true]
        dsimp [safety]
        refine ⟨by omega, ⟨by intro _; rfl, by intro _; rfl⟩, by intro _; rfl, by intro ht; rw [hNoTpl] at ht; cases ht⟩
      · simp only [hzero, ite_false]
        dsimp [safety]
        have hnotEpoch : s.settledAtEpoch ≠ s.appliedEpoch := by
          intro heq
          have h0 := hQueueIff.2 heq
          omega
        refine ⟨hSettledLe, ⟨by intro hq1; contradiction, by intro heq; contradiction⟩, by intro heq; contradiction, by intro ht; rw [hNoTpl] at ht; cases ht⟩
    · exact ⟨hSettledLe, hQueueIff, hSettledZero, hTemplate⟩
  case assembleTemplate reqEpoch reqGen =>
    dsimp [step]
    split
    · rename_i heq
      rcases heq with ⟨hE, hG, hS⟩
      have hq0 : s.factsQueueLen = 0 := hQueueIff.2 hS
      have hu0 : s.unsettledConfirmedCount = 0 := hSettledZero hS
      dsimp [safety]
      refine ⟨by omega, ⟨by intro _; exact hS, by intro _; exact hq0⟩, by intro _; exact hu0, ?_⟩
      intro _
      refine ⟨hq0, hE, by omega, ?_⟩
      intro hc
      rw [hu0] at hc
      contradiction
    · exact ⟨hSettledLe, hQueueIff, hSettledZero, hTemplate⟩
  case mineBlock =>
    dsimp [step]
    split
    · dsimp [safety]
      refine ⟨hSettledLe, hQueueIff, hSettledZero, by intro ht; cases ht⟩
    · exact ⟨hSettledLe, hQueueIff, hSettledZero, hTemplate⟩
  case stutter =>
    dsimp [step]
    exact ⟨hSettledLe, hQueueIff, hSettledZero, hTemplate⟩

-- MPS-03
theorem template_never_has_confirmed_tx (s : State) (h : safety s) :
    s.templateActive → ¬s.templateHasConfirmed := by
  intro ht
  exact (h.2.2.2 ht).2.2.2

end MempoolSettlement
