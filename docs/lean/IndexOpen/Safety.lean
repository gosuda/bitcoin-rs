/-
Safety invariants of the index open helper ownership and lifecycle machine
(Rust owner `crates/index/src/runtime/startup/open_model.rs`).

Anchors: Tony Hoare, Edsger W. Dijkstra

Models derived-index worker and helper thread phases, joined cancellation,
store acquisition, error/panic diagnostics, startup timeouts, host teardown
deadlines, and checkpoint gating under EMB-01.

Design model only: specifies the state machine and invariant safety.
Not an implementation refinement proof or physical durability proof.
-/

namespace IndexOpen

structure State where
  workerPhase : Nat
  helperPhase : Nat
  shutdownRequested : Nat
  storeHeld : Nat
  resultKind : Nat
  poisoned : Nat
  hostOutcome : Nat
  checkpointPublished : Nat

def workerIdle : Nat := 0
def workerOpening : Nat := 1
def workerReady : Nat := 2
def workerServing : Nat := 3
def workerStopping : Nat := 4
def workerStopped : Nat := 5
def workerAbandoned : Nat := 6

def helperAbsent : Nat := 0
def helperRunning : Nat := 1
def helperExited : Nat := 2
def helperJoined : Nat := 3

def resultNone : Nat := 0
def resultOpened : Nat := 1
def resultFailed : Nat := 2
def resultPanicked : Nat := 3

def hostPending : Nat := 0
def hostClean : Nat := 1
def hostFailed : Nat := 2

def init : State :=
  { workerPhase := workerIdle,
    helperPhase := helperAbsent,
    shutdownRequested := 0,
    storeHeld := 0,
    resultKind := resultNone,
    poisoned := 0,
    hostOutcome := hostPending,
    checkpointPublished := 0 }

inductive Action
  | requestShutdown
  | preSpawnStop
  | spawnHelper
  | nativeStoreAcquire
  | helperPostSuccess
  | helperPostFailed
  | helperPostPanicked
  | helperExit
  | workerReceiveOpened
  | workerStartServing
  | workerHandleFailed
  | workerCancelDuringOpening
  | workerCancelFromReadyOrServing
  | workerJoinHelper
  | workerCleanStop
  | workerStartupTimeout
  | hostDeadlineExpire
  | hostReportsAbandonment
  | hostCleanCompletion
  | publishCheckpoint
  | stutter

def step (s : State) : Action → State
  | .requestShutdown =>
    if s.shutdownRequested = 0 then
      { s with shutdownRequested := 1 }
    else s
  | .preSpawnStop =>
    if s.workerPhase = workerIdle ∧ s.shutdownRequested = 1 ∧ s.helperPhase = helperAbsent then
      { s with workerPhase := workerStopped }
    else s
  | .spawnHelper =>
    if s.workerPhase = workerIdle ∧ s.shutdownRequested = 0 ∧ s.helperPhase = helperAbsent ∧ s.hostOutcome = hostPending then
      { s with workerPhase := workerOpening, helperPhase := helperRunning }
    else s
  | .nativeStoreAcquire =>
    if s.helperPhase = helperRunning ∧ s.storeHeld = 0 ∧ s.resultKind = resultNone then
      { s with storeHeld := 1 }
    else s
  | .helperPostSuccess =>
    if s.helperPhase = helperRunning ∧ s.storeHeld = 1 ∧ s.resultKind = resultNone then
      { s with resultKind := resultOpened }
    else s
  | .helperPostFailed =>
    if s.helperPhase = helperRunning ∧ s.resultKind = resultNone then
      { s with resultKind := resultFailed, storeHeld := 0 }
    else s
  | .helperPostPanicked =>
    if s.helperPhase = helperRunning ∧ s.resultKind = resultNone then
      { s with resultKind := resultPanicked, storeHeld := 0 }
    else s
  | .helperExit =>
    if s.helperPhase = helperRunning ∧
       ((s.workerPhase ≠ workerAbandoned ∧ s.resultKind ≠ resultNone) ∨ s.workerPhase = workerAbandoned) then
      { s with helperPhase := helperExited,
               storeHeld := if s.workerPhase = workerAbandoned then 0 else s.storeHeld }
    else s
  | .workerReceiveOpened =>
    if s.workerPhase = workerOpening ∧ s.resultKind = resultOpened ∧ s.shutdownRequested = 0 then
      { s with workerPhase := workerReady }
    else s
  | .workerStartServing =>
    if s.workerPhase = workerReady ∧ s.helperPhase = helperJoined ∧ s.shutdownRequested = 0 then
      { s with workerPhase := workerServing }
    else s
  | .workerHandleFailed =>
    if s.workerPhase = workerOpening ∧ (s.resultKind = resultFailed ∨ s.resultKind = resultPanicked) ∧ s.shutdownRequested = 0 then
      { s with workerPhase := workerStopping }
    else s
  | .workerCancelDuringOpening =>
    if s.workerPhase = workerOpening ∧ s.shutdownRequested = 1 then
      { s with workerPhase := workerStopping }
    else s
  | .workerCancelFromReadyOrServing =>
    if (s.workerPhase = workerReady ∨ s.workerPhase = workerServing) ∧ s.shutdownRequested = 1 then
      { s with workerPhase := workerStopping }
    else s
  | .workerJoinHelper =>
    if s.workerPhase ≠ workerAbandoned ∧ s.helperPhase = helperExited then
      { s with helperPhase := helperJoined }
    else s
  | .workerCleanStop =>
    if s.workerPhase = workerStopping ∧ (s.helperPhase = helperAbsent ∨ s.helperPhase = helperJoined) then
      { s with workerPhase := workerStopped, storeHeld := 0 }
    else s
  | .workerStartupTimeout =>
    if s.workerPhase = workerOpening ∧ s.shutdownRequested = 0 ∧ s.helperPhase = helperRunning ∧ s.resultKind = resultNone then
      { s with workerPhase := workerAbandoned, poisoned := 1 }
    else s
  | .hostDeadlineExpire =>
    if s.hostOutcome = hostPending ∧ s.shutdownRequested = 1 ∧ s.workerPhase ≠ workerStopped ∧ s.workerPhase ≠ workerAbandoned then
      { s with hostOutcome := hostFailed, poisoned := 1 }
    else s
  | .hostReportsAbandonment =>
    if s.hostOutcome = hostPending ∧ (s.workerPhase = workerAbandoned ∨ (s.workerPhase = workerStopped ∧ s.poisoned = 1)) then
      { s with hostOutcome := hostFailed, poisoned := 1 }
    else s
  | .hostCleanCompletion =>
    if s.hostOutcome = hostPending ∧ s.workerPhase = workerStopped ∧ s.poisoned = 0 then
      { s with hostOutcome := hostClean }
    else s
  | .publishCheckpoint =>
    if s.hostOutcome = hostClean ∧ s.checkpointPublished = 0 ∧ s.poisoned = 0 then
      { s with checkpointPublished := 1 }
    else s
  | .stutter => s

def safety (s : State) : Prop :=
  s.workerPhase ≤ workerAbandoned
  ∧ s.helperPhase ≤ helperJoined
  ∧ s.shutdownRequested ≤ 1
  ∧ s.storeHeld ≤ 1
  ∧ s.resultKind ≤ resultPanicked
  ∧ s.poisoned ≤ 1
  ∧ s.hostOutcome ≤ hostFailed
  ∧ s.checkpointPublished ≤ 1
  ∧ (s.workerPhase = workerStopped →
      (s.helperPhase = helperAbsent ∨ s.helperPhase = helperJoined) ∧ s.storeHeld = 0)
  ∧ (s.hostOutcome = hostClean → s.workerPhase = workerStopped)
  ∧ (s.workerPhase = workerServing → s.helperPhase = helperJoined)
  ∧ (s.checkpointPublished = 1 →
      s.hostOutcome = hostClean ∧ s.poisoned = 0 ∧ s.storeHeld = 0 ∧ (s.helperPhase = helperAbsent ∨ s.helperPhase = helperJoined))
  ∧ (s.workerPhase = workerStopped ∧ s.helperPhase = helperAbsent →
      s.storeHeld = 0 ∧ s.resultKind = resultNone)
  ∧ (s.poisoned = 1 ∨ s.workerPhase = workerAbandoned ∨ s.hostOutcome = hostFailed →
      s.hostOutcome ≠ hostClean ∧ s.checkpointPublished = 0)
  ∧ (s.workerPhase = workerAbandoned → s.poisoned = 1)
  ∧ (s.hostOutcome = hostFailed → s.poisoned = 1)
  ∧ (s.storeHeld = 1 →
      s.helperPhase = helperRunning ∨ s.helperPhase = helperExited ∨ s.helperPhase = helperJoined)
  ∧ (s.helperPhase = helperAbsent →
      s.resultKind = resultNone ∧ s.storeHeld = 0)

-- EMB-01
theorem safety_init : safety init := by
  dsimp [safety, init, workerIdle, helperAbsent, resultNone, hostPending,
         workerStopped, workerAbandoned, helperJoined, resultPanicked, hostFailed,
         workerServing, helperRunning, helperExited]
  decide

-- EMB-01
/-- `safety` is an inductive invariant of `step` from `init`. -/
theorem safety_inductive (s : State) (a : Action) (h : safety s) :
    safety (step s a) := by
  rcases h with ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  cases a
  case stutter =>
    dsimp only [step]
    exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case requestShutdown =>
    dsimp only [step]
    split
    · refine ⟨h1, h2, ?_, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
      show 1 ≤ 1
      decide
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case preSpawnStop =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, h2, h3, h4, h5, h6, h7, h8, ?_, ?_, ?_, h12, ?_, ?_, ?_, h16, h17, h18⟩
      · show workerStopped ≤ workerAbandoned
        decide
      · intro _
        exact ⟨Or.inl hguard.2.2, (h18 hguard.2.2).2⟩
      · intro _
        rfl
      · intro hw
        nomatch hw
      · intro hp2
        exact ⟨(h18 hp2.2).2, (h18 hp2.2).1⟩
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · exact h14 (Or.inl hp1)
        · nomatch hp2
        · exact h14 (Or.inr (Or.inr hp3))
      · intro hw
        nomatch hw
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case spawnHelper =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, ?_, h3, h4, h5, h6, h7, h8, ?_, ?_, ?_, ?_, ?_, ?_, ?_, h16, ?_, ?_⟩
      · show workerOpening ≤ workerAbandoned
        decide
      · show helperRunning ≤ helperJoined
        decide
      · intro hw
        nomatch hw
      · intro hc
        have hbad : 0 = 1 := hguard.2.2.2.symm.trans hc
        nomatch hbad
      · intro hw
        nomatch hw
      · intro hcp
        have hbad : 0 = 1 := hguard.2.2.2.symm.trans (h12 hcp).1
        nomatch hbad
      · intro hp2
        nomatch hp2.1
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · exact h14 (Or.inl hp1)
        · nomatch hp2
        · exact h14 (Or.inr (Or.inr hp3))
      · intro hw
        nomatch hw
      · intro _
        exact Or.inl rfl
      · intro hh
        nomatch hh
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case nativeStoreAcquire =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨h1, h2, h3, ?_, h5, h6, h7, h8, ?_, h10, h11, ?_, ?_, h14, h15, h16, ?_, ?_⟩
      · show 1 ≤ 1
        decide
      · intro hwp
        rcases (h9 hwp).1 with hh | hh
        · have hbad : 1 = 0 := hguard.1.symm.trans hh
          nomatch hbad
        · have hbad : 1 = 3 := hguard.1.symm.trans hh
          nomatch hbad
      · intro hcp
        rcases (h12 hcp).2.2.2 with hh | hh
        · have hbad : 1 = 0 := hguard.1.symm.trans hh
          nomatch hbad
        · have hbad : 1 = 3 := hguard.1.symm.trans hh
          nomatch hbad
      · intro hp2
        have hbad : 1 = 0 := hguard.1.symm.trans hp2.2
        nomatch hbad
      · intro _
        exact Or.inl hguard.1
      · intro hh
        have hbad : 1 = 0 := hguard.1.symm.trans hh
        nomatch hbad
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case helperPostSuccess =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨h1, h2, h3, h4, ?_, h6, h7, h8, h9, h10, h11, h12, ?_, h14, h15, h16, h17, ?_⟩
      · show resultOpened ≤ resultPanicked
        decide
      · intro hp2
        have hbad : 1 = 0 := hguard.1.symm.trans hp2.2
        nomatch hbad
      · intro hh
        have hbad : 1 = 0 := hguard.1.symm.trans hh
        nomatch hbad
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case helperPostFailed =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨h1, h2, h3, ?_, ?_, h6, h7, h8, ?_, h10, h11, ?_, ?_, h14, h15, h16, ?_, ?_⟩
      · show 0 ≤ 1
        decide
      · show resultFailed ≤ resultPanicked
        decide
      · intro hwp
        rcases (h9 hwp).1 with hh | hh
        · have hbad : 1 = 0 := hguard.1.symm.trans hh
          nomatch hbad
        · have hbad : 1 = 3 := hguard.1.symm.trans hh
          nomatch hbad
      · intro hcp
        rcases (h12 hcp).2.2.2 with hh | hh
        · have hbad : 1 = 0 := hguard.1.symm.trans hh
          nomatch hbad
        · have hbad : 1 = 3 := hguard.1.symm.trans hh
          nomatch hbad
      · intro hp2
        have hbad : 1 = 0 := hguard.1.symm.trans hp2.2
        nomatch hbad
      · intro hh
        nomatch hh
      · intro hh
        have hbad : 1 = 0 := hguard.1.symm.trans hh
        nomatch hbad
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case helperPostPanicked =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨h1, h2, h3, ?_, ?_, h6, h7, h8, ?_, h10, h11, ?_, ?_, h14, h15, h16, ?_, ?_⟩
      · show 0 ≤ 1
        decide
      · show resultPanicked ≤ resultPanicked
        decide
      · intro hwp
        rcases (h9 hwp).1 with hh | hh
        · have hbad : 1 = 0 := hguard.1.symm.trans hh
          nomatch hbad
        · have hbad : 1 = 3 := hguard.1.symm.trans hh
          nomatch hbad
      · intro hcp
        rcases (h12 hcp).2.2.2 with hh | hh
        · have hbad : 1 = 0 := hguard.1.symm.trans hh
          nomatch hbad
        · have hbad : 1 = 3 := hguard.1.symm.trans hh
          nomatch hbad
      · intro hp2
        have hbad : 1 = 0 := hguard.1.symm.trans hp2.2
        nomatch hbad
      · intro hh
        nomatch hh
      · intro hh
        have hbad : 1 = 0 := hguard.1.symm.trans hh
        nomatch hbad
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case helperExit =>
    dsimp only [step]
    split
    · rename_i hguard
      split
      · rename_i hab
        refine ⟨h1, ?_, h3, ?_, h5, h6, h7, h8, ?_, h10, ?_, ?_, ?_, h14, h15, h16, ?_, ?_⟩
        · show helperExited ≤ helperJoined
          decide
        · show 0 ≤ 1
          decide
        · intro hwp
          have hbad : 6 = 5 := hab.symm.trans hwp
          nomatch hbad
        · intro hw
          have hbad : 6 = 3 := hab.symm.trans hw
          nomatch hbad
        · intro hcp
          rcases (h12 hcp).2.2.2 with hh | hh
          · have hbad : 1 = 0 := hguard.1.symm.trans hh
            nomatch hbad
          · have hbad : 1 = 3 := hguard.1.symm.trans hh
            nomatch hbad
        · intro hp2
          nomatch hp2.2
        · intro hh
          nomatch hh
        · intro hh
          nomatch hh
      · refine ⟨h1, ?_, h3, h4, h5, h6, h7, h8, ?_, h10, ?_, ?_, ?_, h14, h15, h16, ?_, ?_⟩
        · show helperExited ≤ helperJoined
          decide
        · intro hwp
          rcases (h9 hwp).1 with hh | hh
          · have hbad : 1 = 0 := hguard.1.symm.trans hh
            nomatch hbad
          · have hbad : 1 = 3 := hguard.1.symm.trans hh
            nomatch hbad
        · intro hw
          have hbad : 1 = 3 := hguard.1.symm.trans (h11 hw)
          nomatch hbad
        · intro hcp
          rcases (h12 hcp).2.2.2 with hh | hh
          · have hbad : 1 = 0 := hguard.1.symm.trans hh
            nomatch hbad
          · have hbad : 1 = 3 := hguard.1.symm.trans hh
            nomatch hbad
        · intro hp2
          nomatch hp2.2
        · intro _
          exact Or.inr (Or.inl rfl)
        · intro hh
          nomatch hh
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case workerReceiveOpened =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, h2, h3, h4, h5, h6, h7, h8, ?_, ?_, ?_, h12, ?_, ?_, ?_, h16, h17, h18⟩
      · show workerReady ≤ workerAbandoned
        decide
      · intro hw
        nomatch hw
      · intro hc
        have hbad : 1 = 5 := hguard.1.symm.trans (h10 hc)
        nomatch hbad
      · intro hw
        nomatch hw
      · intro hp2
        nomatch hp2.1
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · exact h14 (Or.inl hp1)
        · nomatch hp2
        · exact h14 (Or.inr (Or.inr hp3))
      · intro hw
        nomatch hw
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case workerStartServing =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, h2, h3, h4, h5, h6, h7, h8, ?_, ?_, ?_, h12, ?_, ?_, ?_, h16, h17, h18⟩
      · show workerServing ≤ workerAbandoned
        decide
      · intro hw
        nomatch hw
      · intro hc
        have hbad : 2 = 5 := hguard.1.symm.trans (h10 hc)
        nomatch hbad
      · intro _
        exact hguard.2.1
      · intro hp2
        nomatch hp2.1
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · exact h14 (Or.inl hp1)
        · nomatch hp2
        · exact h14 (Or.inr (Or.inr hp3))
      · intro hw
        nomatch hw
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case workerHandleFailed =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, h2, h3, h4, h5, h6, h7, h8, ?_, ?_, ?_, h12, ?_, ?_, ?_, h16, h17, h18⟩
      · show workerStopping ≤ workerAbandoned
        decide
      · intro hw
        nomatch hw
      · intro hc
        have hbad : 1 = 5 := hguard.1.symm.trans (h10 hc)
        nomatch hbad
      · intro hw
        nomatch hw
      · intro hp2
        nomatch hp2.1
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · exact h14 (Or.inl hp1)
        · nomatch hp2
        · exact h14 (Or.inr (Or.inr hp3))
      · intro hw
        nomatch hw
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case workerCancelDuringOpening =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, h2, h3, h4, h5, h6, h7, h8, ?_, ?_, ?_, h12, ?_, ?_, ?_, h16, h17, h18⟩
      · show workerStopping ≤ workerAbandoned
        decide
      · intro hw
        nomatch hw
      · intro hc
        have hbad : 1 = 5 := hguard.1.symm.trans (h10 hc)
        nomatch hbad
      · intro hw
        nomatch hw
      · intro hp2
        nomatch hp2.1
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · exact h14 (Or.inl hp1)
        · nomatch hp2
        · exact h14 (Or.inr (Or.inr hp3))
      · intro hw
        nomatch hw
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case workerCancelFromReadyOrServing =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, h2, h3, h4, h5, h6, h7, h8, ?_, ?_, ?_, h12, ?_, ?_, ?_, h16, h17, h18⟩
      · show workerStopping ≤ workerAbandoned
        decide
      · intro hw
        nomatch hw
      · intro hc
        rcases hguard.1 with hr | hs
        · have hbad : 2 = 5 := hr.symm.trans (h10 hc)
          nomatch hbad
        · have hbad : 3 = 5 := hs.symm.trans (h10 hc)
          nomatch hbad
      · intro hw
        nomatch hw
      · intro hp2
        nomatch hp2.1
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · exact h14 (Or.inl hp1)
        · nomatch hp2
        · exact h14 (Or.inr (Or.inr hp3))
      · intro hw
        nomatch hw
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case workerJoinHelper =>
    dsimp only [step]
    split
    · refine ⟨h1, ?_, h3, h4, h5, h6, h7, h8, ?_, h10, ?_, ?_, ?_, h14, h15, h16, ?_, ?_⟩
      · show helperJoined ≤ helperJoined
        decide
      · intro hwp
        exact ⟨Or.inr rfl, (h9 hwp).2⟩
      · intro _
        rfl
      · intro hcp
        exact ⟨(h12 hcp).1, (h12 hcp).2.1, (h12 hcp).2.2.1, Or.inr rfl⟩
      · intro hp2
        nomatch hp2.2
      · intro _
        exact Or.inr (Or.inr rfl)
      · intro hh
        nomatch hh
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case workerCleanStop =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, h2, h3, ?_, h5, h6, h7, h8, ?_, ?_, ?_, ?_, ?_, ?_, ?_, h16, ?_, ?_⟩
      · show workerStopped ≤ workerAbandoned
        decide
      · show 0 ≤ 1
        decide
      · intro _
        exact ⟨hguard.2, rfl⟩
      · intro _
        rfl
      · intro hw
        nomatch hw
      · intro hcp
        exact ⟨(h12 hcp).1, (h12 hcp).2.1, rfl, hguard.2⟩
      · intro hp2
        exact ⟨rfl, (h18 hp2.2).1⟩
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · exact h14 (Or.inl hp1)
        · nomatch hp2
        · exact h14 (Or.inr (Or.inr hp3))
      · intro hw
        nomatch hw
      · intro hh
        nomatch hh
      · intro hh
        exact ⟨(h18 hh).1, rfl⟩
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case workerStartupTimeout =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, h2, h3, h4, h5, ?_, h7, h8, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, h17, h18⟩
      · show workerAbandoned ≤ workerAbandoned
        decide
      · show 1 ≤ 1
        decide
      · intro hw
        nomatch hw
      · intro hc
        have hbad : 1 = 5 := hguard.1.symm.trans (h10 hc)
        nomatch hbad
      · intro hw
        nomatch hw
      · intro hcp
        rcases (h12 hcp).2.2.2 with hh | hh
        · have hbad : 1 = 0 := hguard.2.2.1.symm.trans hh
          nomatch hbad
        · have hbad : 1 = 3 := hguard.2.2.1.symm.trans hh
          nomatch hbad
      · intro hp2
        nomatch hp2.1
      · intro _
        have hcp01 : s.checkpointPublished = 0 ∨ s.checkpointPublished = 1 := by omega
        refine ⟨?_, ?_⟩
        · intro hc
          have hbad : 1 = 5 := hguard.1.symm.trans (h10 hc)
          nomatch hbad
        · rcases hcp01 with h0 | h1
          · exact h0
          · have hbad : 1 = 5 := hguard.1.symm.trans (h10 (h12 h1).1)
            nomatch hbad
      · intro _
        rfl
      · intro _
        rfl
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case hostDeadlineExpire =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨h1, h2, h3, h4, h5, ?_, ?_, h8, h9, ?_, h11, ?_, h13, ?_, ?_, ?_, h17, h18⟩
      · show 1 ≤ 1
        decide
      · show hostFailed ≤ hostFailed
        decide
      · intro hc
        nomatch hc
      · intro hcp
        have hbad : 0 = 1 := hguard.1.symm.trans (h12 hcp).1
        nomatch hbad
      · intro _
        have hcp01 : s.checkpointPublished = 0 ∨ s.checkpointPublished = 1 := by omega
        refine ⟨?_, ?_⟩
        · intro hc
          nomatch hc
        · rcases hcp01 with h0 | h1
          · exact h0
          · have hbad : 0 = 1 := hguard.1.symm.trans (h12 h1).1
            nomatch hbad
      · intro _
        rfl
      · intro _
        rfl
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case hostReportsAbandonment =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨h1, h2, h3, h4, h5, ?_, ?_, h8, h9, ?_, h11, ?_, h13, ?_, ?_, ?_, h17, h18⟩
      · show 1 ≤ 1
        decide
      · show hostFailed ≤ hostFailed
        decide
      · intro hc
        nomatch hc
      · intro hcp
        have hbad : 0 = 1 := hguard.1.symm.trans (h12 hcp).1
        nomatch hbad
      · intro _
        have hcp01 : s.checkpointPublished = 0 ∨ s.checkpointPublished = 1 := by omega
        refine ⟨?_, ?_⟩
        · intro hc
          nomatch hc
        · rcases hcp01 with h0 | h1
          · exact h0
          · have hbad : 0 = 1 := hguard.1.symm.trans (h12 h1).1
            nomatch hbad
      · intro _
        rfl
      · intro _
        rfl
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case hostCleanCompletion =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨h1, h2, h3, h4, h5, h6, ?_, h8, h9, ?_, h11, ?_, h13, ?_, h15, ?_, h17, h18⟩
      · show hostClean ≤ hostFailed
        decide
      · intro _
        exact hguard.2.1
      · intro _
        exact ⟨rfl, hguard.2.2, (h9 hguard.2.1).2, (h9 hguard.2.1).1⟩
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · have hbad : 0 = 1 := hguard.2.2.symm.trans hp1
          nomatch hbad
        · have hbad : 5 = 6 := hguard.2.1.symm.trans hp2
          nomatch hbad
        · nomatch hp3
      · intro hf
        nomatch hf
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩
  case publishCheckpoint =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨h1, h2, h3, h4, h5, h6, h7, ?_, h9, h10, h11, ?_, h13, ?_, h15, h16, h17, h18⟩
      · show 1 ≤ 1
        decide
      · intro _
        have hw := h10 hguard.1
        exact ⟨hguard.1, hguard.2.2, (h9 hw).2, (h9 hw).1⟩
      · intro hord
        rcases hord with hp1 | hp2 | hp3
        · have hbad : 0 = 1 := hguard.2.2.symm.trans hp1
          nomatch hbad
        · have hw := h10 hguard.1
          have hbad : 5 = 6 := hw.symm.trans hp2
          nomatch hbad
        · have hbad : 1 = 2 := hguard.1.symm.trans hp3
          nomatch hbad
    · exact ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18⟩

-- EMB-01
/-- Poison and host failure are monotonic across single steps. -/
theorem poison_and_failure_monotonic (s : State) (a : Action) (_h : safety s) :
    (s.poisoned = 1 → (step s a).poisoned = 1) ∧
    (s.hostOutcome = hostFailed → (step s a).hostOutcome = hostFailed) := by
  cases a
  case stutter =>
    dsimp only [step]
    exact ⟨id, id⟩
  case requestShutdown =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case preSpawnStop =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case spawnHelper =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case nativeStoreAcquire =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case helperPostSuccess =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case helperPostFailed =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case helperPostPanicked =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case helperExit =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case workerReceiveOpened =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case workerStartServing =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case workerHandleFailed =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case workerCancelDuringOpening =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case workerCancelFromReadyOrServing =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case workerJoinHelper =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case workerCleanStop =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩
  case workerStartupTimeout =>
    dsimp only [step]
    split
    · refine ⟨?_, ?_⟩
      · intro _
        rfl
      · exact id
    · exact ⟨id, id⟩
  case hostDeadlineExpire =>
    dsimp only [step]
    split
    · refine ⟨?_, ?_⟩
      · intro _
        rfl
      · intro _
        rfl
    · exact ⟨id, id⟩
  case hostReportsAbandonment =>
    dsimp only [step]
    split
    · refine ⟨?_, ?_⟩
      · intro _
        rfl
      · intro _
        rfl
    · exact ⟨id, id⟩
  case hostCleanCompletion =>
    dsimp only [step]
    split
    · rename_i hguard
      refine ⟨?_, ?_⟩
      · exact id
      · intro hf
        have hbad : 0 = 2 := hguard.1.symm.trans hf
        nomatch hbad
    · exact ⟨id, id⟩
  case publishCheckpoint =>
    dsimp only [step]
    split <;> exact ⟨id, id⟩

end IndexOpen
