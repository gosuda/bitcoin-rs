/-
Safety invariants of the NodeBudget accounting model.
Rust reference model: crates/node/src/budget_model.rs (all seven owners).
Rust implementation: crates/node/src/budget.rs.

Anchors: Tony Hoare, John Carmack, Dieter Rams.

Models single-budget accounting across all retained allocation owners,
reservation before allocation, foreground capacity reservation, ingress
refusal under exhaustion without consensus invalidation, release on completion,
and the MDBX zero-cache reporting exception.

Design model only: specifies the state machine and invariant safety.
Not an implementation refinement proof or physical durability proof.
-/

namespace NodeBudget

def totalBudget : Nat := 4
def foregroundReserve : Nat := 1

structure State where
  coinCache : Nat
  engineCache : Nat
  factsQueue : Nat
  indexBuilder : Nat
  stagedImages : Nat
  queryViews : Nat
  peerOutbound : Nat
  reservedCoinCache : Nat
  reservedEngineCache : Nat
  reservedFactsQueue : Nat
  reservedIndexBuilder : Nat
  reservedStagedImages : Nat
  reservedQueryViews : Nat
  reservedPeerOutbound : Nat
  ingressRefused : Bool
  consensusInvalid : Bool
  isMdbx : Bool

def totalCharges (s : State) : Nat :=
  s.coinCache + s.engineCache + s.factsQueue + s.indexBuilder + s.stagedImages + s.queryViews +
  s.peerOutbound

def totalReserved (s : State) : Nat :=
  s.reservedCoinCache + s.reservedEngineCache + s.reservedFactsQueue +
  s.reservedIndexBuilder + s.reservedStagedImages + s.reservedQueryViews +
  s.reservedPeerOutbound

def totalCommitted (s : State) : Nat :=
  totalCharges s + totalReserved s

def backgroundCommitted (s : State) : Nat :=
  s.factsQueue + s.indexBuilder + s.queryViews +
  s.reservedFactsQueue + s.reservedIndexBuilder + s.reservedQueryViews

def init (isMdbx : Bool) : State :=
  { coinCache := 0,
    engineCache := 0,
    factsQueue := 0,
    indexBuilder := 0,
    stagedImages := 0,
    queryViews := 0,
    peerOutbound := 0,
    reservedCoinCache := 0,
    reservedEngineCache := 0,
    reservedFactsQueue := 0,
    reservedIndexBuilder := 0,
    reservedStagedImages := 0,
    reservedQueryViews := 0,
    reservedPeerOutbound := 0,
    ingressRefused := false,
    consensusInvalid := false,
    isMdbx := isMdbx }

inductive Action
  | reserveIngress (amt : Nat)
  | refuseIngress (amt : Nat)
  | allocateIngress (amt : Nat)
  | applyBlock (amt : Nat)
  | reserveFactsQueue (amt : Nat)
  | allocateFactsQueue (amt : Nat)
  | releaseFactsQueue (amt : Nat)
  | reserveIndexBuilder (amt : Nat)
  | allocateIndexBuilder (amt : Nat)
  | releaseIndexBuilder (amt : Nat)
  | reserveQueryViews (amt : Nat)
  | allocateQueryViews (amt : Nat)
  | releaseQueryViews (amt : Nat)
  | reserveCoinCache (amt : Nat)
  | allocateCoinCache (amt : Nat)
  | releaseCoinCache (amt : Nat)
  | growEngineCache (amt : Nat)
  | shrinkEngineCache (amt : Nat)
  | reservePeerOutbound (amt : Nat)
  | allocatePeerOutbound (amt : Nat)
  | releasePeerOutbound (amt : Nat)
  | stutter

def step (s : State) : Action → State
  | .reserveIngress amt =>
    if totalCommitted s + amt ≤ totalBudget then
      { s with reservedStagedImages := s.reservedStagedImages + amt }
    else s
  | .refuseIngress amt =>
    if totalBudget < totalCommitted s + amt then
      { s with ingressRefused := true }
    else s
  | .allocateIngress amt =>
    if amt ≤ s.reservedStagedImages then
      { s with reservedStagedImages := s.reservedStagedImages - amt,
               stagedImages := s.stagedImages + amt }
    else s
  | .applyBlock amt =>
    if amt ≤ s.stagedImages then
      { s with stagedImages := s.stagedImages - amt }
    else s
  | .reserveFactsQueue amt =>
    if totalCommitted s + amt ≤ totalBudget - foregroundReserve then
      { s with reservedFactsQueue := s.reservedFactsQueue + amt }
    else s
  | .allocateFactsQueue amt =>
    if amt ≤ s.reservedFactsQueue then
      { s with reservedFactsQueue := s.reservedFactsQueue - amt,
               factsQueue := s.factsQueue + amt }
    else s
  | .releaseFactsQueue amt =>
    if amt ≤ s.factsQueue then
      { s with factsQueue := s.factsQueue - amt }
    else s
  | .reserveIndexBuilder amt =>
    if totalCommitted s + amt ≤ totalBudget - foregroundReserve then
      { s with reservedIndexBuilder := s.reservedIndexBuilder + amt }
    else s
  | .allocateIndexBuilder amt =>
    if amt ≤ s.reservedIndexBuilder then
      { s with reservedIndexBuilder := s.reservedIndexBuilder - amt,
               indexBuilder := s.indexBuilder + amt }
    else s
  | .releaseIndexBuilder amt =>
    if amt ≤ s.indexBuilder then
      { s with indexBuilder := s.indexBuilder - amt }
    else s
  | .reserveQueryViews amt =>
    if totalCommitted s + amt ≤ totalBudget - foregroundReserve then
      { s with reservedQueryViews := s.reservedQueryViews + amt }
    else s
  | .allocateQueryViews amt =>
    if amt ≤ s.reservedQueryViews then
      { s with reservedQueryViews := s.reservedQueryViews - amt,
               queryViews := s.queryViews + amt }
    else s
  | .releaseQueryViews amt =>
    if amt ≤ s.queryViews then
      { s with queryViews := s.queryViews - amt }
    else s
  | .reserveCoinCache amt =>
    if totalCommitted s + amt ≤ totalBudget then
      { s with reservedCoinCache := s.reservedCoinCache + amt }
    else s
  | .allocateCoinCache amt =>
    if amt ≤ s.reservedCoinCache then
      { s with reservedCoinCache := s.reservedCoinCache - amt,
               coinCache := s.coinCache + amt }
    else s
  | .releaseCoinCache amt =>
    if amt ≤ s.coinCache then
      { s with coinCache := s.coinCache - amt }
    else s
  | .growEngineCache amt =>
    if ¬s.isMdbx ∧ totalCommitted s + amt ≤ totalBudget then
      { s with engineCache := s.engineCache + amt }
    else s
  | .shrinkEngineCache amt =>
    if ¬s.isMdbx ∧ amt ≤ s.engineCache then
      { s with engineCache := s.engineCache - amt }
    else s
  | .reservePeerOutbound amt =>
    if totalCommitted s + amt ≤ totalBudget then
      { s with reservedPeerOutbound := s.reservedPeerOutbound + amt }
    else s
  | .allocatePeerOutbound amt =>
    if amt ≤ s.reservedPeerOutbound then
      { s with reservedPeerOutbound := s.reservedPeerOutbound - amt,
               peerOutbound := s.peerOutbound + amt }
    else s
  | .releasePeerOutbound amt =>
    if amt ≤ s.peerOutbound then
      { s with peerOutbound := s.peerOutbound - amt }
    else s
  | .stutter => s

def safety (s : State) : Prop :=
  totalCommitted s ≤ totalBudget
  ∧ backgroundCommitted s ≤ totalBudget - foregroundReserve
  ∧ ¬s.consensusInvalid
  ∧ (s.isMdbx → s.engineCache = 0 ∧ s.reservedEngineCache = 0)

-- BUD-01, BUD-02, BUD-03, BUD-05, BUD-06, BUD-07
theorem safety_init (isMdbx : Bool) : safety (init isMdbx) := by
  unfold safety init totalCommitted totalCharges totalReserved backgroundCommitted totalBudget foregroundReserve
  cases isMdbx <;> decide

-- BUD-01, BUD-02, BUD-03, BUD-05, BUD-06, BUD-07
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  rcases h with ⟨hTot, hBg, hInv, hMdbx⟩
  cases a
  all_goals
    dsimp only [step]
    try split
  all_goals
    dsimp [safety, totalCommitted, totalCharges, totalReserved, backgroundCommitted, totalBudget, foregroundReserve] at *
    refine ⟨by omega, by omega, hInv, ?_⟩
  all_goals
    first
      | exact hMdbx
      | (intro h1; exfalso; rename_i he; exact he.1 h1)

-- BUD-03
theorem refusal_preserves_consensus_validity (s : State) (h : safety s) :
    s.ingressRefused → ¬s.consensusInvalid := by
  intro _
  exact h.2.2.1

end NodeBudget
