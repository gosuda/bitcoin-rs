/-
Safety invariants of the datadir schema lifecycle (target Epoch 3 design
governing planned node admission and planned offline converter `tools/storage-convert`).

Anchors: Tony Hoare, Edsger W. Dijkstra

Target Design Notice:
This module models the target Epoch 3 datadir schema lifecycle and the planned
offline converter (`tools/storage-convert`). These files specify epoch3
schema admission/conversion safety independently; they do not establish
implementation refinement or physical filesystem durability.

Two execution modes are modeled with disjoint phase domains:
1. Node admission:
   - exact-current marker (`current`, Epoch 3) opens without alteration.
   - absent marker with an empty datadir initializes `current` marker before opening.
   - malformed, retired (Epoch 2), future, or non-empty un-marked directory refuses
     admission and leaves marker and contents unchanged.
   - node initialization I/O failure pre-rename leaves marker absent and closed.
   - node initialization directory sync failure post-rename leaves a visible marker
     in state, but the engine remains closed (`initPublicationUnknown`).
   - node initialized-open records independent observed directory sync (`srcSyncObserved`),
     whereas opening an existing current marker requires no new sync.
2. Offline converter (`tools/storage-convert`, target design):
   - accepts retired or current epoch only, empty destination, and disjoint paths.
   - never opens or mutates source engine files; operates on copied scratch.
   - models sequential copy of 4 content cells (2 namespaces x 2 families).
   - supports corrupt-copy injection.
   - verification compares every destination cell against the original source cell;
     any mismatch fails before publication (`verificationFailed`).
   - only verified cells permit copying required engine-independent files,
     deleting scratch, and renaming the target marker.
   - final destination sync can fail after rename (`publicationUnknown`), leaving
     a visible marker and contents in the destination directory but withholding
     a success receipt, as physical durability across failure cannot be guaranteed
     without directory sync.
   - final destination sync success is independently recorded (`dstSyncObserved`);
     bypassing sync to directly claim success violates the invariant.
   - prepublication failures never publish destination marker.

Honest assumptions:
- Hash / Digest Abstraction: Four content identity bytes represent sorted logical
  rows across two namespaces by two families. Digest verification is modeled as
  exact comparison of identity bytes; collision resistance is an external property.
- Filesystem Atomicity: Rename of `CURRENT_SCHEMA.tmp` to `CURRENT_SCHEMA` is atomic
  in filesystem metadata.
- Implemented Epoch 3 Design: Models implemented live Epoch 3 lifecycle requirements under RCV-09.
  Live node implementation uses `CURRENT_SCHEMA_VERSION = 3`. The model is
  an independent design model, not an implementation refinement proof.
- Failure and Visibility Model: Pre-rename I/O errors abort without marker publication.
  Post-rename directory sync failures leave a visible marker in state, not a proven
  durable marker, and withhold a success receipt.
- Phase Constructor Ordering vs. State Facts: Lean phase constructors encode the
  sequential ordering of required-files copying and scratch deletion, while source
  contents immutability and final directory sync observation are independent state
  facts; the model does not assert direct physical observation of hardware durability
  inside Lean.
- Path Disjointness: Checked as a launch precondition; non-disjoint paths are refused
  before any destination or scratch writes occur.
- Independent Sync Observation: Terminal success outcome is distinct from the directory
  sync observation flag (`dstSyncObserved` / `srcSyncObserved`).
-/

namespace Storage.Schema

/-- Schema marker classification for a datadir. -/
inductive Marker where
  | absent
  | malformed
  | retired   -- Epoch 2 (Fjall / redb / rocksdb)
  | current   -- Epoch 3 (RocksDB default)
  | future
deriving DecidableEq, Repr

/-- Byte cell representing an abstract content identity. -/
abbrev Cell := UInt8

/-- Four cells representing two namespaces (e.g. chainstate, txindex) by two families. -/
structure Content where
  c0 : Cell
  c1 : Cell
  c2 : Cell
  c3 : Cell
deriving DecidableEq, Repr

/-- Four cells as an explicit list. -/
def Content.toList (c : Content) : List Cell :=
  [c.c0, c.c1, c.c2, c.c3]

theorem Content.toList_length (c : Content) : c.toList.length = 4 := rfl

/-- Immutable environment parameters captured at startup. -/
structure Env where
  srcMarker : Marker
  srcEmptyDir : Bool
  dstEmptyDir : Bool
  disjointPaths : Bool
  srcContents : Content
deriving DecidableEq, Repr

/-- Lifecycle phase for Node admission. -/
inductive NodePhase where
  | pending
  | opened
  | refused
  | initFailedPreRename
  | initPublicationUnknown
deriving DecidableEq, Repr

/-- Lifecycle phase for Offline Converter. -/
inductive CvtPhase where
  | unstarted
  | refused
  | scratchCopied
  | copyingCells (copied : List Cell)
  | cellsCopied (cells : List Cell)
  | verified (cells : List Cell)
  | requiredFilesCopied (cells : List Cell)
  | scratchDeleted (cells : List Cell)
  | publishedPendingSync (cells : List Cell)
  | success (cells : List Cell)
  | publicationUnknown (cells : List Cell)
  | verificationFailed
  | ioErrorPrePublish
deriving DecidableEq, Repr

/-- Combined mode-separated phase. -/
inductive Phase where
  | node (p : NodePhase)
  | converter (p : CvtPhase)
deriving DecidableEq, Repr

inductive Mode where
  | node
  | converter
deriving DecidableEq, Repr

structure State where
  env : Env
  srcMarker : Marker
  srcContents : Content
  dstSyncObserved : Bool
  srcSyncObserved : Bool
  phase : Phase
deriving DecidableEq, Repr

/-- Initial state for a given mode and environment. -/
def init (mode : Mode) (env : Env) : State :=
  match mode with
  | .node => {
      env := env,
      srcMarker := env.srcMarker,
      srcContents := env.srcContents,
      dstSyncObserved := false,
      srcSyncObserved := false,
      phase := .node .pending
    }
  | .converter => {
      env := env,
      srcMarker := env.srcMarker,
      srcContents := env.srcContents,
      dstSyncObserved := false,
      srcSyncObserved := false,
      phase := .converter .unstarted
    }

/-- Structural recursive comparison of cell lists without unchecked indexing. -/
def checkContent (expected actual : List Cell) : Bool :=
  match expected, actual with
  | [], [] => true
  | e :: es, a :: as => if e = a then checkContent es as else false
  | _, _ => false

theorem checkContent_eq : ∀ (expected actual : List Cell),
    checkContent expected actual = true → actual = expected
  | [], [], _ => rfl
  | [], _ :: _, h => by contradiction
  | _ :: _, [], h => by contradiction
  | e :: es, a :: as, h => by
    dsimp [checkContent] at h
    split at h
    · rename_i heq
      subst heq
      have ih := checkContent_eq es as h
      rw [ih]
    · contradiction

theorem checkContent_self : ∀ (l : List Cell), checkContent l l = true
  | [] => rfl
  | x :: xs => by
    dsimp [checkContent]
    simp [checkContent_self xs]
/-- Next cell from the source list to be copied given the current prefix. -/
def nextCell (src : List Cell) (copied : List Cell) : Option Cell :=
  match src, copied with
  | e :: _, [] => some e
  | _ :: es, _ :: cs => nextCell es cs
  | [], _ => none

theorem nextCell_isSome : ∀ (src copied : List Cell),
    copied.length < src.length → ∃ c, nextCell src copied = some c
  | [], _, h => by contradiction
  | e :: es, [], _ => ⟨e, rfl⟩
  | _ :: es, _ :: cs, h => by
    simp only [List.length_cons] at h
    have hlt : cs.length < es.length := by omega
    have ⟨c, hc⟩ := nextCell_isSome es cs hlt
    exact ⟨c, hc⟩

/-- Target destination marker derived from the state phase. -/
def dstMarker (s : State) : Option Marker :=
  match s.phase with
  | .converter (.publishedPendingSync _) => some .current
  | .converter (.success _) => some .current
  | .converter (.publicationUnknown _) => some .current
  | _ => none

/-- Target destination contents derived from the state phase. -/
def dstContents (s : State) : List Cell :=
  match s.phase with
  | .converter (.copyingCells copied) => copied
  | .converter (.cellsCopied cells) => cells
  | .converter (.verified cells) => cells
  | .converter (.requiredFilesCopied cells) => cells
  | .converter (.scratchDeleted cells) => cells
  | .converter (.publishedPendingSync cells) => cells
  | .converter (.success cells) => cells
  | .converter (.publicationUnknown cells) => cells
  | _ => []

def isNodeOpened (s : State) : Bool :=
  s.phase == .node .opened

def isNodeRefused (s : State) : Bool :=
  s.phase == .node .refused

def isCvtSuccess (s : State) : Bool :=
  match s.phase with
  | .converter (.success _) => true
  | _ => false

def isCvtRefused (s : State) : Bool :=
  s.phase == .converter .refused

def isRequiredFilesCopied (s : State) : Bool :=
  match s.phase with
  | .converter (.requiredFilesCopied _) => true
  | .converter (.scratchDeleted _) => true
  | .converter (.publishedPendingSync _) => true
  | .converter (.success _) => true
  | .converter (.publicationUnknown _) => true
  | _ => false

def isScratchDeleted (s : State) : Bool :=
  match s.phase with
  | .converter (.scratchDeleted _) => true
  | .converter (.publishedPendingSync _) => true
  | .converter (.success _) => true
  | .converter (.publicationUnknown _) => true
  | _ => false

inductive Action where
  -- Node actions
  | nodeOpenExactCurrent
  | nodeInitAndOpen
  | nodeRefuse
  | nodeInitErrorPreRename
  | nodeInitErrorPostRename
  -- Converter actions
  | cvtRefuse
  | cvtStartCopyScratch
  | cvtCopyCell
  | cvtCorruptCopy (corrupted : Cell)
  | cvtVerifyPass
  | cvtVerifyMismatch
  | cvtCopyRequiredFiles
  | cvtDeleteScratch
  | cvtPublishMarker
  | cvtSyncSuccess
  | cvtSyncFailure
  | cvtPrePublishIoError
  -- Stutter
  | stutter
deriving DecidableEq, Repr

def step (s : State) : Action → State
  -- Node actions
  | .nodeOpenExactCurrent =>
    match s.phase with
    | .node .pending =>
      if s.srcMarker = .current then
        { s with phase := .node .opened }
      else s
    | _ => s
  | .nodeInitAndOpen =>
    match s.phase with
    | .node .pending =>
      if s.srcMarker = .absent ∧ s.env.srcEmptyDir = true then
        { s with srcMarker := .current, srcSyncObserved := true, phase := .node .opened }
      else s
    | _ => s
  | .nodeRefuse =>
    match s.phase with
    | .node .pending =>
      if s.srcMarker = .malformed ∨ s.srcMarker = .retired ∨ s.srcMarker = .future ∨
         (s.srcMarker = .absent ∧ s.env.srcEmptyDir = false) then
        { s with phase := .node .refused }
      else s
    | _ => s
  | .nodeInitErrorPreRename =>
    match s.phase with
    | .node .pending =>
      if s.srcMarker = .absent ∧ s.env.srcEmptyDir = true then
        { s with phase := .node .initFailedPreRename }
      else s
    | _ => s
  | .nodeInitErrorPostRename =>
    match s.phase with
    | .node .pending =>
      if s.srcMarker = .absent ∧ s.env.srcEmptyDir = true then
        { s with srcMarker := .current, phase := .node .initPublicationUnknown }
      else s
    | _ => s
  -- Converter actions
  | .cvtRefuse =>
    match s.phase with
    | .converter .unstarted =>
      if ¬(s.srcMarker = .retired ∨ s.srcMarker = .current) ∨
         s.env.dstEmptyDir = false ∨ s.env.disjointPaths = false then
        { s with phase := .converter .refused }
      else s
    | _ => s
  | .cvtStartCopyScratch =>
    match s.phase with
    | .converter .unstarted =>
      if (s.srcMarker = .retired ∨ s.srcMarker = .current) ∧
         s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true then
        { s with phase := .converter .scratchCopied }
      else s
    | _ => s
  | .cvtCopyCell =>
    match s.phase with
    | .converter .scratchCopied =>
      match nextCell s.srcContents.toList [] with
      | some c => { s with phase := .converter (.copyingCells [c]) }
      | none => s
    | .converter (.copyingCells copied) =>
      if copied.length < 4 then
        match nextCell s.srcContents.toList copied with
        | some c =>
          let nextList := copied ++ [c]
          if nextList.length = 4 then
            { s with phase := .converter (.cellsCopied nextList) }
          else
            { s with phase := .converter (.copyingCells nextList) }
        | none => s
      else s
    | _ => s
  | .cvtCorruptCopy corrupted =>
    match s.phase with
    | .converter .scratchCopied =>
      { s with phase := .converter (.copyingCells [corrupted]) }
    | .converter (.copyingCells copied) =>
      if copied.length < 4 then
        let nextList := copied ++ [corrupted]
        if nextList.length = 4 then
          { s with phase := .converter (.cellsCopied nextList) }
        else
          { s with phase := .converter (.copyingCells nextList) }
      else s
    | _ => s
  | .cvtVerifyPass =>
    match s.phase with
    | .converter (.cellsCopied cells) =>
      if checkContent s.srcContents.toList cells = true then
        { s with phase := .converter (.verified cells) }
      else s
    | _ => s
  | .cvtVerifyMismatch =>
    match s.phase with
    | .converter (.cellsCopied cells) =>
      if checkContent s.srcContents.toList cells = false then
        { s with phase := .converter .verificationFailed }
      else s
    | _ => s
  | .cvtCopyRequiredFiles =>
    match s.phase with
    | .converter (.verified cells) =>
      { s with phase := .converter (.requiredFilesCopied cells) }
    | _ => s
  | .cvtDeleteScratch =>
    match s.phase with
    | .converter (.requiredFilesCopied cells) =>
      { s with phase := .converter (.scratchDeleted cells) }
    | _ => s
  | .cvtPublishMarker =>
    match s.phase with
    | .converter (.scratchDeleted cells) =>
      { s with phase := .converter (.publishedPendingSync cells) }
    | _ => s
  | .cvtSyncSuccess =>
    match s.phase with
    | .converter (.publishedPendingSync cells) =>
      { s with dstSyncObserved := true, phase := .converter (.success cells) }
    | _ => s
  | .cvtSyncFailure =>
    match s.phase with
    | .converter (.publishedPendingSync cells) =>
      { s with phase := .converter (.publicationUnknown cells) }
    | _ => s
  | .cvtPrePublishIoError =>
    match s.phase with
    | .converter .scratchCopied
    | .converter (.copyingCells _)
    | .converter (.cellsCopied _)
    | .converter (.verified _)
    | .converter (.requiredFilesCopied _)
    | .converter (.scratchDeleted _) =>
      { s with phase := .converter .ioErrorPrePublish }
    | _ => s
  | .stutter => s

/-- Closed inductive invariant of the lifecycle state machine. -/
def invariant (s : State) : Prop :=
  s.srcContents = s.env.srcContents
  ∧ match s.phase with
    | .node p =>
      s.dstSyncObserved = false
      ∧ match p with
      | .pending => s.srcMarker = s.env.srcMarker ∧ s.srcSyncObserved = false
      | .opened => s.srcMarker = .current ∧ (s.env.srcMarker = .absent → s.srcSyncObserved = true)
      | .refused => s.srcMarker = s.env.srcMarker ∧ s.srcSyncObserved = false
      | .initFailedPreRename => s.srcMarker = .absent ∧ s.srcMarker = s.env.srcMarker ∧ s.srcSyncObserved = false
      | .initPublicationUnknown => s.srcMarker = .current ∧ s.env.srcMarker = .absent ∧ s.env.srcEmptyDir = true ∧ s.srcSyncObserved = false
    | .converter p =>
      s.srcMarker = s.env.srcMarker
      ∧ s.srcSyncObserved = false
      ∧ match p with
        | .unstarted => s.dstSyncObserved = false
        | .refused => s.dstSyncObserved = false
        | .scratchCopied =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current)
        | .copyingCells copied =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current) ∧
          copied.length < 4
        | .cellsCopied cells =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current) ∧
          cells.length = 4
        | .verified cells =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current) ∧
          cells = s.env.srcContents.toList
        | .requiredFilesCopied cells =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current) ∧
          cells = s.env.srcContents.toList
        | .scratchDeleted cells =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current) ∧
          cells = s.env.srcContents.toList
        | .publishedPendingSync cells =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current) ∧
          cells = s.env.srcContents.toList
        | .success cells =>
          s.dstSyncObserved = true ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current) ∧
          cells = s.env.srcContents.toList
        | .publicationUnknown cells =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current) ∧
          cells = s.env.srcContents.toList
        | .verificationFailed =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current)
        | .ioErrorPrePublish =>
          s.dstSyncObserved = false ∧
          s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired ∨ s.env.srcMarker = .current)

-- RCV-09
theorem invariant_init (mode : Mode) (env : Env) : invariant (init mode env) := by
  cases mode with
  | node =>
    unfold invariant init
    dsimp
    exact ⟨rfl, rfl, rfl, rfl⟩
  | converter =>
    unfold invariant init
    dsimp
    exact ⟨rfl, rfl, rfl, rfl⟩

theorem step_srcContents (s : State) (a : Action) :
    (step s a).srcContents = s.srcContents := by
  cases a
  all_goals
    dsimp [step]
    repeat (first | split | rfl | cases s.phase)

-- RCV-09
theorem invariant_step (s : State) (a : Action) (h : invariant s) :
    invariant (step s a) := by
  cases a
  case nodeOpenExactCurrent =>
    cases hphase : s.phase with
    | converter cp =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | node np =>
      cases np
      case pending =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hguard
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hdst, hmarker, hsync⟩
          unfold invariant; dsimp
          refine ⟨hsrc, hdst, hguard, ?_⟩
          intro habs
          rw [hmarker] at hguard
          rw [habs] at hguard
          contradiction
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case nodeInitAndOpen =>
    cases hphase : s.phase with
    | converter cp =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | node np =>
      cases np
      case pending =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hguard
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hdst, hmarker, hsync⟩
          unfold invariant; dsimp
          exact ⟨hsrc, hdst, rfl, fun _ => rfl⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case nodeRefuse =>
    cases hphase : s.phase with
    | converter cp =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | node np =>
      cases np
      case pending =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hguard
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hdst, hmarker, hsync⟩
          unfold invariant; dsimp
          exact ⟨hsrc, hdst, hmarker, hsync⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case nodeInitErrorPreRename =>
    cases hphase : s.phase with
    | converter cp =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | node np =>
      cases np
      case pending =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hguard
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hdst, hmarker, hsync⟩
          unfold invariant; dsimp
          exact ⟨hsrc, hdst, hguard.1, hmarker, hsync⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case nodeInitErrorPostRename =>
    cases hphase : s.phase with
    | converter cp =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | node np =>
      cases np
      case pending =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hguard
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hdst, hmarker, hsync⟩
          have henv_abs : s.env.srcMarker = .absent := by
            rw [← hmarker]
            exact hguard.1
          unfold invariant; dsimp
          exact ⟨hsrc, hdst, rfl, henv_abs, hguard.2, hsync⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtRefuse =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case unstarted =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hmarker, hsync, hdst⟩
          unfold invariant; dsimp
          exact ⟨hsrc, hmarker, hsync, hdst⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtStartCopyScratch =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case unstarted =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hguard
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hmarker, hsync, hdst⟩
          rcases hguard with ⟨hmk, hdstEmpty, hdisj⟩
          have hmk_env : s.env.srcMarker = .retired ∨ s.env.srcMarker = .current := by
            rw [← hmarker]
            exact hmk
          unfold invariant; dsimp
          exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk_env⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtCopyCell =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case scratchCopied =>
        dsimp [step]; rw [hphase]; dsimp
        cases hnext : nextCell s.srcContents.toList [] with
        | none =>
          dsimp [hnext]; exact h
        | some c =>
          dsimp [hnext]
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
          have hlen : [c].length < 4 := (by decide : 1 < 4)
          unfold invariant; dsimp
          exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hlen⟩
      case copyingCells copied =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hlen
          cases hnext : nextCell s.srcContents.toList copied with
          | none =>
            dsimp [hnext]; exact h
          | some c =>
            dsimp [hnext]
            split
            · rename_i h4
              have hinv := h
              unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
              rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, _⟩
              unfold invariant; dsimp
              exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, h4⟩
            · rename_i hnot4
              have hinv := h
              unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
              rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, _⟩
              have hlen_app : (copied ++ [c]).length = copied.length + 1 := by
                simp [List.length_append]
              have hlen_lt : (copied ++ [c]).length < 4 := by
                omega
              unfold invariant; dsimp
              exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hlen_lt⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtCorruptCopy corrupted =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case scratchCopied =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
        have hlen : [corrupted].length < 4 := (by decide : 1 < 4)
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hlen⟩
      case copyingCells copied =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hlen
          split
          · rename_i h4
            have hinv := h
            unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
            rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, _⟩
            unfold invariant; dsimp
            exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, h4⟩
          · rename_i hnot4
            have hinv := h
            unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
            rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, _⟩
            have hlen_app : (copied ++ [corrupted]).length = copied.length + 1 := by
              simp [List.length_append]
            have hlen_lt : (copied ++ [corrupted]).length < 4 := by
              omega
            unfold invariant; dsimp
            exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hlen_lt⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtVerifyPass =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case cellsCopied cells =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hcheck
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hlen⟩
          have hceq := checkContent_eq s.srcContents.toList cells hcheck
          rw [hsrc] at hceq
          unfold invariant; dsimp
          exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hceq⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtVerifyMismatch =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case cellsCopied cells =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hcheck
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hlen⟩
          unfold invariant; dsimp
          exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtCopyRequiredFiles =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case verified cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hcells⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hcells⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtDeleteScratch =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case requiredFilesCopied cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hcells⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hcells⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtPublishMarker =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case scratchDeleted cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hcells⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hcells⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtSyncSuccess =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case publishedPendingSync cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hcells⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, rfl, hdstEmpty, hdisj, hmk, hcells⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtSyncFailure =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case publishedPendingSync cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hcells⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, hcells⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtPrePublishIoError =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case scratchCopied =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
      case copyingCells copied =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, _⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
      case cellsCopied cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, _⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
      case verified cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, _⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
      case requiredFilesCopied cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, _⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
      case scratchDeleted cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk, _⟩
        unfold invariant; dsimp
        exact ⟨hsrc, hmarker, hsync, hdst, hdstEmpty, hdisj, hmk⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case stutter =>
    exact h

/-- Inductive invariant holds across foldl execution over any trace list. -/
theorem invariant_foldl (tr : List Action) (s : State) (h : invariant s) :
    invariant (tr.foldl step s) := by
  induction tr generalizing s with
  | nil =>
    exact h
  | cons a rest ih =>
    dsimp [List.foldl]
    apply ih
    exact invariant_step s a h

-- RCV-09
/-- Inductive invariant holds across any finite trace from initialization. -/
theorem trace_invariant (mode : Mode) (env : Env) (tr : List Action) :
    invariant (tr.foldl step (init mode env)) :=
  invariant_foldl tr (init mode env) (invariant_init mode env)

-- RCV-09
/-- Source contents are strictly preserved across any trace. -/
theorem trace_srcContents (tr : List Action) (s : State) :
    (tr.foldl step s).srcContents = s.srcContents := by
  induction tr generalizing s with
  | nil => rfl
  | cons a rest ih =>
    dsimp [List.foldl]
    rw [ih (step s a), step_srcContents]
theorem step_env (s : State) (a : Action) :
    (step s a).env = s.env := by
  cases a <;> dsimp [step]
  all_goals
    repeat (first | split | rfl | cases s.phase)

theorem trace_env (tr : List Action) (s : State) :
    (tr.foldl step s).env = s.env := by
  induction tr generalizing s with
  | nil => rfl
  | cons a rest ih =>
    dsimp [List.foldl]
    rw [ih (step s a), step_env]

theorem converter_step_preserves_converter (s : State) (a : Action) (cp : CvtPhase)
    (h : s.phase = .converter cp) :
    ∃ cp', (step s a).phase = .converter cp' := by
  cases a <;> dsimp [step]
  all_goals
    rw [h]
    try dsimp
    repeat (first | split | rfl | exact ⟨_, rfl⟩ | exact ⟨_, h⟩)
theorem converter_phase_foldl (tr : List Action) (s : State) (cp : CvtPhase)
    (h : s.phase = .converter cp) :
    ∃ cp', (tr.foldl step s).phase = .converter cp' := by
  induction tr generalizing s cp with
  | nil =>
    exact ⟨cp, h⟩
  | cons a rest ih =>
    dsimp [List.foldl]
    have ⟨cp1, hcp1⟩ := converter_step_preserves_converter s a cp h
    exact ih (step s a) cp1 hcp1

theorem trace_converter_phase (env : Env) (tr : List Action) :
    ∃ cp, (tr.foldl step (init .converter env)).phase = .converter cp :=
  converter_phase_foldl tr (init .converter env) .unstarted rfl

-- RCV-09
/-- The converter mode never modifies the source marker under any execution trace. -/
theorem converter_trace_preserves_srcMarker (env : Env) (tr : List Action) :
    (tr.foldl step (init .converter env)).srcMarker = env.srcMarker := by
  have hinv := trace_invariant .converter env tr
  have ⟨cp, hcp⟩ := trace_converter_phase env tr
  unfold invariant at hinv
  rw [hcp] at hinv
  dsimp at hinv
  have henv : (tr.foldl step (init .converter env)).env = env := by
    rw [trace_env]
    rfl
  rw [henv] at hinv
  exact hinv.2.1

theorem node_step_preserves_node (s : State) (a : Action) (np : NodePhase)
    (h : s.phase = .node np) :
    ∃ np', (step s a).phase = .node np' := by
  cases a <;> dsimp [step]
  all_goals
    rw [h]
    try dsimp
    repeat (first | split | rfl | exact ⟨_, rfl⟩ | exact ⟨_, h⟩)
theorem node_phase_foldl (tr : List Action) (s : State) (np : NodePhase)
    (h : s.phase = .node np) :
    ∃ np', (tr.foldl step s).phase = .node np' := by
  induction tr generalizing s np with
  | nil =>
    exact ⟨np, h⟩
  | cons a rest ih =>
    dsimp [List.foldl]
    have ⟨np1, hnp1⟩ := node_step_preserves_node s a np h
    exact ih (step s a) np1 hnp1

theorem trace_node_phase (env : Env) (tr : List Action) :
    ∃ np, (tr.foldl step (init .node env)).phase = .node np :=
  node_phase_foldl tr (init .node env) .pending rfl

-- RCV-09
/-- Refusal transitions leave the source marker strictly unchanged. -/
theorem refusal_preserves_srcMarker (s : State) (a : Action) (_h : invariant s) :
    (step s a).phase = .node .refused ∨ (step s a).phase = .converter .refused →
    (step s a).srcMarker = s.srcMarker := by
  intro href
  cases a <;> dsimp [step] at *
  case nodeInitAndOpen =>
    cases hphase : s.phase with
    | node np =>
      cases np with
      | pending =>
        rw [hphase] at href
        by_cases hguard : s.srcMarker = .absent ∧ s.env.srcEmptyDir = true
        · simp [hguard] at href
        · simp [hguard]
      | _ => rfl
    | converter cp => rfl
  case nodeInitErrorPostRename =>
    cases hphase : s.phase with
    | node np =>
      cases np with
      | pending =>
        rw [hphase] at href
        by_cases hguard : s.srcMarker = .absent ∧ s.env.srcEmptyDir = true
        · simp [hguard] at href
        · simp [hguard]
      | _ => rfl
    | converter cp => rfl
  all_goals
    clear href
    repeat (first | split | rfl | cases s.phase)

-- RCV-09
/-- Output marker soundness: any published destination marker implies exact
verified cell contents, required engine-independent files durability, and scratch removed. -/
theorem output_marker_soundness (s : State) (h : invariant s) (m : Marker)
    (hm : dstMarker s = some m) :
    m = .current ∧ dstContents s = s.env.srcContents.toList ∧
    isRequiredFilesCopied s = true ∧ isScratchDeleted s = true := by
  unfold dstMarker at hm
  cases hphase : s.phase with
  | node p =>
    rw [hphase] at hm
    cases p <;> contradiction
  | converter cp =>
    rw [hphase] at hm
    cases cp with
    | publishedPendingSync cells =>
      injection hm with hm; subst hm
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨hsrc, hmarker, _, _, hdstEmpty, hdisj, hmk, hcells⟩
      unfold dstContents isRequiredFilesCopied isScratchDeleted
      rw [hphase]
      exact ⟨rfl, hcells, rfl, rfl⟩
    | success cells =>
      injection hm with hm; subst hm
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨hsrc, hmarker, _, _, hdstEmpty, hdisj, hmk, hcells⟩
      unfold dstContents isRequiredFilesCopied isScratchDeleted
      rw [hphase]
      exact ⟨rfl, hcells, rfl, rfl⟩
    | publicationUnknown cells =>
      injection hm with hm; subst hm
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨hsrc, hmarker, _, _, hdstEmpty, hdisj, hmk, hcells⟩
      unfold dstContents isRequiredFilesCopied isScratchDeleted
      rw [hphase]
      exact ⟨rfl, hcells, rfl, rfl⟩
    | _ => contradiction

-- RCV-09
/-- Node safety: the node engine is opened only under exact current marker,
and never opened under refusal or initialization failure. -/
theorem node_never_opens_wrong_marker (s : State) (h : invariant s)
    (hop : isNodeOpened s = true) :
    s.srcMarker = .current ∧
    ¬(s.phase = .node .refused ∨
      s.phase = .node .initFailedPreRename ∨
      s.phase = .node .initPublicationUnknown) := by
  unfold isNodeOpened at hop
  cases hphase : s.phase with
  | converter cp =>
    rw [hphase] at hop
    contradiction
  | node np =>
    rw [hphase] at hop
    cases np with
    | opened =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      refine ⟨h.2.2.1, ?_⟩
      intro hbad
      rcases hbad with h1 | h2 | h3 <;> contradiction
    | _ => contradiction

-- RCV-09
/-- Node initialized-open requires independent evidence of directory sync. -/
theorem node_init_open_implies_sync (s : State) (h : invariant s)
    (hop : isNodeOpened s = true) (habs : s.env.srcMarker = .absent) :
    s.srcSyncObserved = true := by
  unfold isNodeOpened at hop
  cases hphase : s.phase with
  | converter cp =>
    rw [hphase] at hop
    contradiction
  | node np =>
    rw [hphase] at hop
    cases np with
    | opened =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      exact h.2.2.2 habs
    | _ => contradiction

-- RCV-09
/-- Converter success implies independent observed final sync, a valid current marker,
and verified contents (distinguished from publication unknown). -/
theorem success_implies_final_sync (s : State) (h : invariant s)
    (hsucc : isCvtSuccess s = true) :
    s.dstSyncObserved = true ∧
    s.phase = .converter (.success s.env.srcContents.toList) ∧
    dstMarker s = some .current ∧
    dstContents s = s.env.srcContents.toList := by
  unfold isCvtSuccess at hsucc
  cases hphase : s.phase with
  | node np =>
    rw [hphase] at hsucc
    cases np <;> contradiction
  | converter cp =>
    rw [hphase] at hsucc
    cases cp with
    | success cells =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨hsrc, hmarker, _, hsync, hdstEmpty, hdisj, hmk, hcells⟩
      subst hcells
      unfold dstMarker dstContents
      rw [hphase]
      exact ⟨hsync, rfl, rfl, rfl⟩
    | _ => contradiction

-- RCV-09
/-- Post-rename directory sync failure yields a published valid marker,
but withholds a success receipt and leaves final sync unobserved. -/
theorem post_rename_unknown_distinguished_from_success (s : State) (h : invariant s)
    (cells : List Cell) (hp : s.phase = .converter (.publicationUnknown cells)) :
    isCvtSuccess s = false ∧ s.dstSyncObserved = false ∧ dstMarker s = some .current := by
  unfold isCvtSuccess dstMarker
  rw [hp]
  unfold invariant at h; rw [hp] at h; dsimp at h
  have hsync : s.dstSyncObserved = false := h.2.2.2.1
  exact ⟨rfl, hsync, rfl⟩

-- RCV-09
/-- Pre-condition enforcement: unsafe destination (non-empty destination, non-disjoint paths,
or unaccepted source epoch) is rejected before any scratch or destination writes occur. -/
theorem unsafe_destination_rejected_before_writes (s : State) (h : invariant s)
    (hunsafe : s.env.dstEmptyDir = false ∨ s.env.disjointPaths = false ∨
      (s.env.srcMarker ≠ .retired ∧ s.env.srcMarker ≠ .current)) :
    (∀ cp, s.phase = .converter cp → cp = .unstarted ∨ cp = .refused) ∧
    dstContents s = [] ∧ dstMarker s = none := by
  cases hphase : s.phase with
  | node np =>
    refine ⟨fun cp heq => by contradiction, ?_, ?_⟩
    · unfold dstContents; rw [hphase]
    · unfold dstMarker; rw [hphase]
  | converter cp =>
    unfold invariant at h; rw [hphase] at h; dsimp at h
    rcases h with ⟨hsrc, hmarker, _, hcp⟩
    cases cp with
    | unstarted =>
      refine ⟨fun cp' heq => by injection heq with heq; subst heq; exact Or.inl rfl, ?_, ?_⟩
      · unfold dstContents; rw [hphase]
      · unfold dstMarker; rw [hphase]
    | refused =>
      refine ⟨fun cp' heq => by injection heq with heq; subst heq; exact Or.inr rfl, ?_, ?_⟩
      · unfold dstContents; rw [hphase]
      · unfold dstMarker; rw [hphase]
    | scratchCopied =>
      rcases hcp with ⟨_, hdst, hdisj, hmk⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | copyingCells _ =>
      rcases hcp with ⟨_, hdst, hdisj, hmk, _⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | cellsCopied _ =>
      rcases hcp with ⟨_, hdst, hdisj, hmk, _⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | verified _ =>
      rcases hcp with ⟨_, hdst, hdisj, hmk, _⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | requiredFilesCopied _ =>
      rcases hcp with ⟨_, hdst, hdisj, hmk, _⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | scratchDeleted _ =>
      rcases hcp with ⟨_, hdst, hdisj, hmk, _⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | publishedPendingSync _ =>
      rcases hcp with ⟨_, hdst, hdisj, hmk, _⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | success _ =>
      rcases hcp with ⟨_, hdst, hdisj, hmk, _⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | publicationUnknown _ =>
      rcases hcp with ⟨_, hdst, hdisj, hmk, _⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | verificationFailed =>
      rcases hcp with ⟨_, hdst, hdisj, hmk⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
    | ioErrorPrePublish =>
      rcases hcp with ⟨_, hdst, hdisj, hmk⟩
      rcases hunsafe with h1 | h2 | h3
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmk with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)

/-
================================================================================
NEGATIVE CONTROLS AND MUTATION COUNTERPARTS
================================================================================
-/

/-- Negative-control mutant 1: verification step does NOT check content equality. -/
def step_unverified (s : State) : Action → State
  | .cvtVerifyPass =>
    match s.phase with
    | .converter (.cellsCopied cells) =>
      { s with phase := .converter (.verified cells) }
    | _ => s
  | a => step s a

/-- Initial environment with all-zero source content. -/
def sampleEnv : Env := {
  srcMarker := .retired,
  srcEmptyDir := true,
  dstEmptyDir := true,
  disjointPaths := true,
  srcContents := { c0 := 0, c1 := 0, c2 := 0, c3 := 0 }
}

/-- Concrete corrupt trace: injects 42 at cell 0, then publishes. -/
def corruptTrace : List Action := [
  .cvtStartCopyScratch,
  .cvtCorruptCopy 42,
  .cvtCopyCell,
  .cvtCopyCell,
  .cvtCopyCell,
  .cvtVerifyPass,
  .cvtCopyRequiredFiles,
  .cvtDeleteScratch,
  .cvtPublishMarker
]

/-- Negative Control 1: Omission of the verification guard permits corrupted
copied cells to reach the published destination marker. -/
theorem negative_control_unverified_publishes_corrupt_content :
    let finalState := corruptTrace.foldl step_unverified (init .converter sampleEnv)
    dstMarker finalState = some .current ∧ dstContents finalState ≠ sampleEnv.srcContents.toList := by
  dsimp [corruptTrace, sampleEnv, init, step_unverified, step, dstMarker, dstContents, Content.toList, nextCell]
  decide

/-- Soundness counterpart 1: under the true verified transition function,
the corrupt trace is blocked at verification and never publishes a destination marker. -/
theorem real_step_blocks_corrupt_trace_publication :
    let finalState := corruptTrace.foldl step (init .converter sampleEnv)
    dstMarker finalState = none := by
  dsimp [corruptTrace, sampleEnv, init, step, dstMarker, Content.toList, nextCell, checkContent]

/-- Negative Control 2: Bypassing the physical directory sync prerequisite and directly
claiming success violates the inductive invariant. -/
theorem negative_control_bypassing_sync_violates_invariant (s : State)
    (cells : List Cell) (hp : s.phase = .converter (.success cells))
    (hsync : s.dstSyncObserved = false) :
    ¬ invariant s := by
  intro hinv
  unfold invariant at hinv
  rw [hp] at hinv
  dsimp at hinv
  have hsyncObserved : s.dstSyncObserved = true := hinv.2.2.2.1
  rw [hsync] at hsyncObserved
  contradiction

end Storage.Schema
