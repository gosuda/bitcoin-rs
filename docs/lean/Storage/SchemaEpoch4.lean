/-
Safety invariants of the datadir schema lifecycle for schema epoch 4
(design model for node admission and converter step `3 -> 4` in
`tools/storage-convert`).

Anchors: Tony Hoare, Edsger W. Dijkstra

Target Design Notice:
This module models the Epoch 4 datadir schema lifecycle and the
converter step `3 -> 4`, after the stateful Phase 3 implementation.
The live node implementation
(`crates/storage/src/checkpoint/fs.rs`) sets
`CURRENT_SCHEMA_VERSION = 4`. This is an independent design model and
must not be reported as an implementation refinement proof.

Epoch 4 target facts modeled here:
1. Node admission refuses every marker epoch other than 4 and names
   `bitcoin-rs-storage-convert` in the refusal (message text is outside
   the state space).
2. Coins live in the engine `coins` keyspace; the converter derives coin
   content from the newest complete checkpoint UTXO snapshot image plus
   replay of heights `checkpoint + 1 .. durable head` from block bodies
   and undo rows. The checkpoint image is consumed, never retained as a
   resident authority.
3. The chainstate journal is deleted; no model action copies it and
   `journalCopied` can never rise.
4. `CURRENT_SCHEMA = 4` is written last, after verified cells, required
   files, checkpoint ingest, replay completion, and scratch deletion.
5. A missing complete checkpoint fails closed before any destination
   write; a missing block body or undo row aborts with
   `MissingBlockData{height}` before publication.
6. Success carries no final-head coin-count, amount, or hash statistic:
   no such independent commitment exists, and the model asserts none.

Honest assumptions:
- Hash / Digest Abstraction: four content identity bytes represent
  sorted logical rows across the copied keyspaces; one coin byte
  represents the coins keyspace. Digest verification is exact byte
  comparison; collision resistance is external.
- Height Bound: `durableHead <= 1` keeps the replay state finite; the
  replay loop is uniform in the head height.
- Sorted Ingest: external sorting before bulk ingest is an engine seam
  (`ingest_sorted`) property, outside this lifecycle model.
- Filesystem Atomicity: rename of `CURRENT_SCHEMA.tmp` is atomic.
- Failure and Visibility Model: pre-rename I/O errors abort without
  publication; post-rename directory sync failures leave a visible
  marker and withhold the success receipt.
-/

namespace Storage.SchemaEpoch4

/-- Schema marker classification for a datadir at epoch 4. -/
inductive Marker where
  | absent
  | malformed
  | retired3   -- Epoch 3 (RocksDB with journal and checkpoint coin image)
  | current4   -- Epoch 4 (coins in the engine `coins` keyspace)
  | future
deriving DecidableEq, Repr

abbrev Cell := Nat
abbrev CoinCell := Nat

/-- Four content cells for the copied keyspaces. -/
structure Content where
  c0 : Cell
  c1 : Cell
  c2 : Cell
  c3 : Cell
deriving DecidableEq, Repr

def Content.toList (c : Content) : List Cell :=
  [c.c0, c.c1, c.c2, c.c3]

theorem Content.toList_length (c : Content) : c.toList.length = 4 := rfl

/-- Immutable environment parameters captured at startup or tool invocation. -/
structure Env where
  srcMarker : Marker
  srcEmptyDir : Bool
  dstEmptyDir : Bool
  disjointPaths : Bool
  srcContents : Content
  checkpointHeight : Nat
  durableHead : Nat
  checkpointComplete : Bool
  blockDataPresent : Nat → Bool
  checkpointCoins : CoinCell
  blockUndoDelta : Nat → CoinCell

/-- The environment facts the converter and the node rely on. -/
def envWellFormed (env : Env) : Prop :=
  env.durableHead ≤ 1
  ∧ env.checkpointHeight ≤ env.durableHead
  ∧ ∀ h, h ≤ env.checkpointHeight →
      env.blockDataPresent h = true ∧ env.blockUndoDelta h = env.checkpointCoins

/-- Replay oracle: cumulative coin content attributed to height `h`. -/
def oracleCoins (env : Env) (h : Nat) : CoinCell :=
  if h ≤ env.checkpointHeight then env.checkpointCoins else env.blockUndoDelta h

/-- Lifecycle phase for Node admission. -/
inductive NodePhase where
  | pending
  | opened
  | refused
  | initFailedPreRename
  | initPublicationUnknown
deriving DecidableEq, Repr

/-- Lifecycle phase for the offline converter, epoch-4 pipeline. -/
inductive CvtPhase where
  | unstarted
  | refused
  | refusedNoCheckpoint
  | scratchCopied
  | copyingCells (copied : List Cell)
  | cellsCopied (cells : List Cell)
  | verified (cells : List Cell)
  | filesCopied (cells : List Cell)
  | ingested (cells : List Cell) (coins : CoinCell)
  | replaying (cells : List Cell) (coins : CoinCell) (applied : Nat)
  | replayDone (cells : List Cell) (coins : CoinCell)
  | scratchDeleted (cells : List Cell) (coins : CoinCell)
  | publishedPendingSync (cells : List Cell) (coins : CoinCell)
  | success (cells : List Cell) (coins : CoinCell)
  | publicationUnknown (cells : List Cell) (coins : CoinCell)
  | verificationFailed
  | missingBlockData (cells : List Cell) (coins : CoinCell) (applied : Nat)
  | ioErrorPrePublish
deriving DecidableEq, Repr

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
  journalCopied : Bool
  phase : Phase

def init (mode : Mode) (env : Env) : State :=
  match mode with
  | .node => {
      env := env,
      srcMarker := env.srcMarker,
      srcContents := env.srcContents,
      dstSyncObserved := false,
      srcSyncObserved := false,
      journalCopied := false,
      phase := .node .pending
    }
  | .converter => {
      env := env,
      srcMarker := env.srcMarker,
      srcContents := env.srcContents,
      dstSyncObserved := false,
      srcSyncObserved := false,
      journalCopied := false,
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

/-- Destination marker derived from the state phase. -/
def dstMarker (s : State) : Option Marker :=
  match s.phase with
  | .converter (.publishedPendingSync _ _) => some .current4
  | .converter (.success _ _) => some .current4
  | .converter (.publicationUnknown _ _) => some .current4
  | _ => none

/-- Destination keyspaces copied so far. -/
def dstCells (s : State) : List Cell :=
  match s.phase with
  | .converter (.copyingCells copied) => copied
  | .converter (.cellsCopied cells) => cells
  | .converter (.verified cells) => cells
  | .converter (.filesCopied cells) => cells
  | .converter (.ingested cells _) => cells
  | .converter (.replaying cells _ _) => cells
  | .converter (.replayDone cells _) => cells
  | .converter (.scratchDeleted cells _) => cells
  | .converter (.publishedPendingSync cells _) => cells
  | .converter (.success cells _) => cells
  | .converter (.publicationUnknown cells _) => cells
  | .converter (.missingBlockData cells _ _) => cells
  | _ => []

/-- Destination coins keyspace content. -/
def dstCoins (s : State) : CoinCell :=
  match s.phase with
  | .converter (.ingested _ coins) => coins
  | .converter (.replaying _ coins _) => coins
  | .converter (.replayDone _ coins) => coins
  | .converter (.scratchDeleted _ coins) => coins
  | .converter (.publishedPendingSync _ coins) => coins
  | .converter (.success _ coins) => coins
  | .converter (.publicationUnknown _ coins) => coins
  | .converter (.missingBlockData _ coins _) => coins
  | _ => 0

/-- Replay position attributed to the current phase. -/
def replayPos (s : State) : Nat :=
  match s.phase with
  | .converter (.ingested _ _) => s.env.checkpointHeight
  | .converter (.replaying _ _ k) => s.env.checkpointHeight + k
  | .converter (.replayDone _ _) => s.env.durableHead
  | .converter (.scratchDeleted _ _) => s.env.durableHead
  | .converter (.publishedPendingSync _ _) => s.env.durableHead
  | .converter (.success _ _) => s.env.durableHead
  | .converter (.publicationUnknown _ _) => s.env.durableHead
  | .converter (.missingBlockData _ _ k) => s.env.checkpointHeight + k
  | _ => 0

def isNodeOpened (s : State) : Bool :=
  s.phase == .node .opened

def isCvtSuccess (s : State) : Bool :=
  match s.phase with
  | .converter (.success _ _) => true
  | _ => false

inductive Action where
  | nodeOpenExactCurrent
  | nodeInitAndOpen
  | nodeRefuse
  | nodeInitErrorPreRename
  | nodeInitErrorPostRename
  | cvtRefuse
  | cvtRefuseNoCheckpoint
  | cvtStartCopyScratch
  | cvtCopyCell
  | cvtCorruptCopy (corrupted : Cell)
  | cvtVerifyPass
  | cvtVerifyMismatch
  | cvtCopyRequiredFiles
  | cvtLoadCheckpoint
  | cvtReplayBlock
  | cvtDeleteScratch
  | cvtPublishMarker
  | cvtSyncSuccess
  | cvtSyncFailure
  | cvtPrePublishIoError
  | stutter
deriving DecidableEq, Repr

def step (s : State) : Action → State
  | .nodeOpenExactCurrent =>
    match s.phase with
    | .node .pending =>
      if s.srcMarker = .current4 then { s with phase := .node .opened } else s
    | _ => s
  | .nodeInitAndOpen =>
    match s.phase with
    | .node .pending =>
      if s.srcMarker = .absent ∧ s.env.srcEmptyDir = true then
        { s with srcMarker := .current4, srcSyncObserved := true, phase := .node .opened }
      else s
    | _ => s
  | .nodeRefuse =>
    match s.phase with
    | .node .pending =>
      if s.srcMarker = .malformed ∨ s.srcMarker = .retired3 ∨ s.srcMarker = .future ∨
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
        { s with srcMarker := .current4, phase := .node .initPublicationUnknown }
      else s
    | _ => s
  | .cvtRefuse =>
    match s.phase with
    | .converter .unstarted =>
      if ¬(s.srcMarker = .retired3 ∨ s.srcMarker = .current4) ∨
         s.env.dstEmptyDir = false ∨ s.env.disjointPaths = false then
        { s with phase := .converter .refused }
      else s
    | _ => s
  | .cvtRefuseNoCheckpoint =>
    match s.phase with
    | .converter .unstarted =>
      if (s.srcMarker = .retired3 ∨ s.srcMarker = .current4) ∧
         s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
         s.env.checkpointComplete = false then
        { s with phase := .converter .refusedNoCheckpoint }
      else s
    | _ => s
  | .cvtStartCopyScratch =>
    match s.phase with
    | .converter .unstarted =>
      if (s.srcMarker = .retired3 ∨ s.srcMarker = .current4) ∧
         s.env.dstEmptyDir = true ∧ s.env.disjointPaths = true ∧
         s.env.checkpointComplete = true then
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
      { s with phase := .converter (.filesCopied cells) }
    | _ => s
  | .cvtLoadCheckpoint =>
    match s.phase with
    | .converter (.filesCopied cells) =>
      if s.env.checkpointHeight = s.env.durableHead then
        { s with phase := .converter (.replayDone cells s.env.checkpointCoins) }
      else
        { s with phase := .converter (.replaying cells s.env.checkpointCoins 0) }
    | _ => s
  | .cvtReplayBlock =>
    match s.phase with
    | .converter (.replaying cells coins k) =>
      if s.env.checkpointHeight + k < s.env.durableHead then
        if s.env.blockDataPresent (s.env.checkpointHeight + k + 1) then
          if s.env.checkpointHeight + k + 1 = s.env.durableHead then
            { s with phase :=
                .converter (.replayDone cells
                  (s.env.blockUndoDelta (s.env.checkpointHeight + k + 1))) }
          else
            { s with phase :=
                .converter (.replaying cells
                  (s.env.blockUndoDelta (s.env.checkpointHeight + k + 1)) (k + 1)) }
        else
          { s with phase := .converter (.missingBlockData cells coins k) }
      else s
    | _ => s
  | .cvtDeleteScratch =>
    match s.phase with
    | .converter (.replayDone cells coins) =>
      { s with phase := .converter (.scratchDeleted cells coins) }
    | _ => s
  | .cvtPublishMarker =>
    match s.phase with
    | .converter (.scratchDeleted cells coins) =>
      { s with phase := .converter (.publishedPendingSync cells coins) }
    | _ => s
  | .cvtSyncSuccess =>
    match s.phase with
    | .converter (.publishedPendingSync cells coins) =>
      { s with dstSyncObserved := true, phase := .converter (.success cells coins) }
    | _ => s
  | .cvtSyncFailure =>
    match s.phase with
    | .converter (.publishedPendingSync cells coins) =>
      { s with phase := .converter (.publicationUnknown cells coins) }
    | _ => s
  | .cvtPrePublishIoError =>
    match s.phase with
    | .converter .scratchCopied
    | .converter (.copyingCells _)
    | .converter (.cellsCopied _)
    | .converter (.verified _)
    | .converter (.filesCopied _)
    | .converter (.ingested _ _)
    | .converter (.replaying _ _ _)
    | .converter (.replayDone _ _)
    | .converter (.scratchDeleted _ _) =>
      { s with phase := .converter .ioErrorPrePublish }
    | _ => s
  | .stutter => s

/-- Closed inductive invariant of the epoch-4 lifecycle state machine. -/
def invariant (s : State) : Prop :=
  envWellFormed s.env
  ∧ s.srcContents = s.env.srcContents
  ∧ s.journalCopied = false
  ∧ match s.phase with
    | .node p =>
      s.dstSyncObserved = false
      ∧ match p with
        | .pending => s.srcMarker = s.env.srcMarker ∧ s.srcSyncObserved = false
        | .opened =>
          s.srcMarker = .current4 ∧ (s.env.srcMarker = .absent → s.srcSyncObserved = true)
        | .refused => s.srcMarker = s.env.srcMarker ∧ s.srcSyncObserved = false
        | .initFailedPreRename =>
          s.srcMarker = .absent ∧ s.srcMarker = s.env.srcMarker ∧ s.srcSyncObserved = false
        | .initPublicationUnknown =>
          s.srcMarker = .current4 ∧ s.env.srcMarker = .absent ∧
          s.env.srcEmptyDir = true ∧ s.srcSyncObserved = false
    | .converter p =>
      s.srcMarker = s.env.srcMarker
      ∧ s.srcSyncObserved = false
      ∧ match p with
        | .unstarted => s.dstSyncObserved = false
        | .refused => s.dstSyncObserved = false
        | .refusedNoCheckpoint =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = false
        | .scratchCopied =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true
        | .copyingCells copied =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ copied.length < 4
        | .cellsCopied cells =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells.length = 4
        | .verified cells =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList
        | .filesCopied cells =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList
        | .ingested cells coins =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList ∧
          coins = s.env.checkpointCoins
        | .replaying cells coins k =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList ∧
          coins = oracleCoins s.env (s.env.checkpointHeight + k) ∧
          s.env.checkpointHeight + k < s.env.durableHead
        | .replayDone cells coins =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList ∧
          coins = oracleCoins s.env s.env.durableHead
        | .scratchDeleted cells coins =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList ∧
          coins = oracleCoins s.env s.env.durableHead
        | .publishedPendingSync cells coins =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList ∧
          coins = oracleCoins s.env s.env.durableHead
        | .success cells coins =>
          s.dstSyncObserved = true ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList ∧
          coins = oracleCoins s.env s.env.durableHead
        | .publicationUnknown cells coins =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList ∧
          coins = oracleCoins s.env s.env.durableHead
        | .verificationFailed =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true
        | .missingBlockData cells coins k =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true ∧ cells = s.env.srcContents.toList ∧
          coins = oracleCoins s.env (s.env.checkpointHeight + k) ∧
          s.env.checkpointHeight + k < s.env.durableHead ∧
          s.env.blockDataPresent (s.env.checkpointHeight + k + 1) = false
        | .ioErrorPrePublish =>
          s.dstSyncObserved = false ∧ s.env.dstEmptyDir = true ∧
          s.env.disjointPaths = true ∧
          (s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4) ∧
          s.env.checkpointComplete = true

-- RCV-09
theorem invariant_init (mode : Mode) (env : Env) (hwf : envWellFormed env) :
    invariant (init mode env) := by
  cases mode with
  | node =>
    unfold invariant init envWellFormed
    dsimp
    exact ⟨hwf, rfl, rfl, rfl, rfl, rfl⟩
  | converter =>
    unfold invariant init envWellFormed
    dsimp
    exact ⟨hwf, rfl, rfl, rfl, rfl, rfl⟩

-- RCV-09
theorem step_srcContents (s : State) (a : Action) :
    (step s a).srcContents = s.srcContents := by
  cases a
  all_goals
    dsimp [step]
    repeat (first | split | rfl | cases s.phase)

-- RCV-09
theorem step_env (s : State) (a : Action) :
    (step s a).env = s.env := by
  cases a
  all_goals
    dsimp [step]
    repeat (first | split | rfl | cases s.phase)

-- RCV-09, RCV-10
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
          rcases hinv with ⟨hwf, hsrc, hj, hdst, hmarker, hsync⟩
          unfold invariant; dsimp
          refine ⟨hwf, hsrc, hj, hdst, hguard, ?_⟩
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
          rcases hinv with ⟨hwf, hsrc, hj, hdst, hmarker, hsync⟩
          have henv_abs : s.env.srcMarker = .absent := by
            rw [← hmarker]; exact hguard.1
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hdst, rfl, fun _ => rfl⟩
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
          rcases hinv with ⟨hwf, hsrc, hj, hdst, hmarker, hsync⟩
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hdst, hmarker, hsync⟩
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
          rcases hinv with ⟨hwf, hsrc, hj, hdst, hmarker, hsync⟩
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hdst, hguard.1, hmarker, hsync⟩
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
          rcases hinv with ⟨hwf, hsrc, hj, hdst, hmarker, hsync⟩
          have henv_abs : s.env.srcMarker = .absent := by
            rw [← hmarker]; exact hguard.1
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hdst, rfl, henv_abs, hguard.2, hsync⟩
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
          rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst⟩
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hmk, hsync, hdst⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtRefuseNoCheckpoint =>
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
          rcases hinv with ⟨hwf, hsrc, hj, hmkinv, hsync, hdst⟩
          rcases hguard with ⟨hmkg, hdstEmpty, hdisj, hcc⟩
          have hmk_env : s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4 := by
            rw [← hmkinv]; exact hmkg
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hmkinv, hsync, hdst, hdstEmpty, hdisj, hmk_env, hcc⟩
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
          rcases hinv with ⟨hwf, hsrc, hj, hmkinv, hsync, hdst⟩
          rcases hguard with ⟨hmkg, hdstEmpty, hdisj, hcc⟩
          have hmk_env : s.env.srcMarker = .retired3 ∨ s.env.srcMarker = .current4 := by
            rw [← hmkinv]; exact hmkg
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hmkinv, hsync, hdst, hdstEmpty, hdisj, hmk_env, hcc⟩
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
        | none => dsimp [hnext]; exact h
        | some c =>
          dsimp [hnext]
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
          have hlen : [c].length < 4 := (by decide : 1 < 4)
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hlen⟩
      case copyingCells copied =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hlen
          cases hnext : nextCell s.srcContents.toList copied with
          | none => dsimp [hnext]; exact h
          | some c =>
            dsimp [hnext]
            split
            · rename_i h4
              have hinv := h
              unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
              rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
              unfold invariant; dsimp
              exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, h4⟩
            · rename_i hnot4
              have hinv := h
              unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
              rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
              have hlen_app : (copied ++ [c]).length = copied.length + 1 := by
                simp [List.length_append]
              have hlen_lt : (copied ++ [c]).length < 4 := by omega
              unfold invariant; dsimp
              exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hlen_lt⟩
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
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
        have hlen : [corrupted].length < 4 := (by decide : 1 < 4)
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hlen⟩
      case copyingCells copied =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hlen
          split
          · rename_i h4
            have hinv := h
            unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
            rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
            unfold invariant; dsimp
            exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, h4⟩
          · rename_i hnot4
            have hinv := h
            unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
            rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
            have hlen_app : (copied ++ [corrupted]).length = copied.length + 1 := by
              simp [List.length_append]
            have hlen_lt : (copied ++ [corrupted]).length < 4 := by omega
            unfold invariant; dsimp
            exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hlen_lt⟩
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
          rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
          have hceq := checkContent_eq s.srcContents.toList cells hcheck
          rw [hsrc] at hceq
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hceq⟩
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
          rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
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
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hcells⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hcells⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtLoadCheckpoint =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case filesCopied cells =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hcphead
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hcells⟩
          have hle : s.env.durableHead ≤ s.env.checkpointHeight := by
            rw [hcphead]; exact Nat.le_refl _
          have hcoins : s.env.checkpointCoins = oracleCoins s.env s.env.durableHead := by
            unfold oracleCoins
            rw [ite_eq_left hle]
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hcells, hcoins⟩
        · rename_i hcplt
          have hinv := h
          unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
          rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, hcells⟩
          have hcoins : s.env.checkpointCoins =
              oracleCoins s.env (s.env.checkpointHeight + 0) := by
            unfold oracleCoins
            rw [ite_eq_left (by simp)]
          have hbound : s.env.checkpointHeight + 0 < s.env.durableHead := by
            rw [Nat.add_zero]; exact Nat.lt_of_le_of_ne hwf.2.1 hcplt
          have hne : s.env.checkpointHeight ≠ s.env.durableHead := hcplt
          unfold invariant; dsimp
          exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
            hcells, hcoins, hbound⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtReplayBlock =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case replaying cells coins k =>
        dsimp [step]; rw [hphase]; dsimp
        split
        · rename_i hlt
          split
          · rename_i hdata
            split
            · rename_i hpos
              have hinv := h
              unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
              rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj,
                hmkEnv, hcc, hcells, hcoins, hbound⟩
              have hnocp : ¬ (s.env.checkpointHeight + k + 1 ≤ s.env.checkpointHeight) := by
                omega
              have hcoins' : s.env.blockUndoDelta (s.env.checkpointHeight + k + 1) =
                  oracleCoins s.env s.env.durableHead := by
                unfold oracleCoins
                rw [ite_eq_right (by omega)]
                rw [hpos]
              unfold invariant; dsimp
              exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
                hcells, hcoins'⟩
            · rename_i hnotpos
              have hinv := h
              unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
              rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj,
                hmkEnv, hcc, hcells, hcoins, hbound⟩
              have hnocp : ¬ (s.env.checkpointHeight + (k + 1) ≤ s.env.checkpointHeight) := by
                omega
              have hbound' : s.env.checkpointHeight + (k + 1) < s.env.durableHead := by
                omega
              have hcoins' : s.env.blockUndoDelta (s.env.checkpointHeight + (k + 1)) =
                  oracleCoins s.env (s.env.checkpointHeight + (k + 1)) := by
                unfold oracleCoins
                rw [ite_eq_right hnocp]
              unfold invariant; dsimp
              exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
                hcells, hcoins', hbound'⟩
          · rename_i hnodata
            have hinv := h
            unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
            rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj,
              hmkEnv, hcc, hcells, hcoins, hbound⟩
            have hcoins' := hcoins
            unfold invariant; dsimp
            exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
              hcells, hcoins', hbound, Bool.eq_false_iff.mpr hnodata⟩
        · exact h
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtDeleteScratch =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case replayDone cells coins =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          hcells, hcoins⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          hcells, hcoins⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtPublishMarker =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case scratchDeleted cells coins =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          hcells, hcoins⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          hcells, hcoins⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtSyncSuccess =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case publishedPendingSync cells coins =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          hcells, hcoins⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, rfl, hdstEmpty, hdisj, hmkEnv, hcc,
          hcells, hcoins⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case cvtSyncFailure =>
    cases hphase : s.phase with
    | node np =>
      dsimp [step]; rw [hphase]; dsimp; exact h
    | converter cp =>
      cases cp
      case publishedPendingSync cells coins =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          hcells, hcoins⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          hcells, hcoins⟩
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
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
      case copyingCells copied =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
      case cellsCopied cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
      case verified cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
      case filesCopied cells =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc, _⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
      case ingested cells coins =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          _, _⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
      case replaying cells coins k =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          _, _, _⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
      case replayDone cells coins =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          _, _⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
      case scratchDeleted cells coins =>
        dsimp [step]; rw [hphase]; dsimp
        have hinv := h
        unfold invariant at hinv; rw [hphase] at hinv; dsimp at hinv
        rcases hinv with ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc,
          _, _⟩
        unfold invariant; dsimp
        exact ⟨hwf, hsrc, hj, hmk, hsync, hdst, hdstEmpty, hdisj, hmkEnv, hcc⟩
      all_goals
        dsimp [step]; rw [hphase]; dsimp; exact h
  case stutter =>
    exact h

-- RCV-09, RCV-10
theorem invariant_foldl (tr : List Action) (s : State) (h : invariant s) :
    invariant (tr.foldl step s) := by
  induction tr generalizing s with
  | nil => exact h
  | cons a rest ih =>
    dsimp [List.foldl]
    apply ih
    exact invariant_step s a h

-- RCV-09, RCV-10
theorem trace_invariant (mode : Mode) (env : Env) (hwf : envWellFormed env)
    (tr : List Action) :
    invariant (tr.foldl step (init mode env)) :=
  invariant_foldl tr (init mode env) (invariant_init mode env hwf)

-- RCV-09
theorem trace_srcContents (tr : List Action) (s : State) :
    (tr.foldl step s).srcContents = s.srcContents := by
  induction tr generalizing s with
  | nil => rfl
  | cons a rest ih =>
    dsimp [List.foldl]
    rw [ih (step s a), step_srcContents]

-- RCV-09
theorem trace_env (tr : List Action) (s : State) :
    (tr.foldl step s).env = s.env := by
  induction tr generalizing s with
  | nil => rfl
  | cons a rest ih =>
    dsimp [List.foldl]
    rw [ih (step s a), step_env]

-- RCV-09
theorem converter_step_preserves_converter (s : State) (a : Action) (cp : CvtPhase)
    (h : s.phase = .converter cp) :
    ∃ cp', (step s a).phase = .converter cp' := by
  cases a <;> dsimp [step]
  all_goals
    rw [h]
    try dsimp
    repeat (first | split | rfl | cases cp | exact ⟨_, rfl⟩ | exact ⟨_, h⟩)

-- RCV-09
theorem converter_phase_foldl (tr : List Action) (s : State) (cp : CvtPhase)
    (h : s.phase = .converter cp) :
    ∃ cp', (tr.foldl step s).phase = .converter cp' := by
  induction tr generalizing s cp with
  | nil => exact ⟨cp, h⟩
  | cons a rest ih =>
    dsimp [List.foldl]
    have ⟨cp1, hcp1⟩ := converter_step_preserves_converter s a cp h
    exact ih (step s a) cp1 hcp1

-- RCV-09
theorem trace_converter_phase (env : Env) (tr : List Action) :
    ∃ cp, (tr.foldl step (init .converter env)).phase = .converter cp :=
  converter_phase_foldl tr (init .converter env) .unstarted rfl

-- RCV-09
theorem converter_trace_preserves_srcMarker (env : Env) (tr : List Action)
    (hwf : envWellFormed env) :
    (tr.foldl step (init .converter env)).srcMarker = env.srcMarker := by
  have hinv := trace_invariant .converter env hwf tr
  have ⟨cp, hcp⟩ := trace_converter_phase env tr
  unfold invariant at hinv
  rw [hcp] at hinv
  dsimp at hinv
  have henv : (tr.foldl step (init .converter env)).env = env := by
    rw [trace_env]
    rfl
  rw [henv] at hinv
  exact hinv.2.2.2.1

-- RCV-09
theorem node_never_opens_wrong_marker (s : State) (h : invariant s)
    (hop : isNodeOpened s = true) :
    s.srcMarker = .current4 ∧
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
      rcases h with ⟨_, _, _, hdst, hmarker, hsyncImp⟩
      refine ⟨hmarker, ?_⟩
      intro hbad
      rcases hbad with h1 | h2 | h3 <;> contradiction
    | _ => contradiction

-- RCV-09, RCV-10
theorem unsafe_destination_rejected_before_writes (s : State) (h : invariant s)
    (hunsafe : s.env.dstEmptyDir = false ∨ s.env.disjointPaths = false ∨
      (s.env.srcMarker ≠ .retired3 ∧ s.env.srcMarker ≠ .current4) ∨
      s.env.checkpointComplete = false) :
    (∀ cp, s.phase = .converter cp →
      cp = .unstarted ∨ cp = .refused ∨ cp = .refusedNoCheckpoint) ∧
    dstCells s = [] ∧ dstCoins s = 0 ∧ dstMarker s = none := by
  cases hphase : s.phase with
  | node np =>
    refine ⟨fun cp heq => by contradiction, ?_, ?_, ?_⟩
    · unfold dstCells; rw [hphase]
    · unfold dstCoins; rw [hphase]
    · unfold dstMarker; rw [hphase]
  | converter cp =>
    unfold invariant at h; rw [hphase] at h; dsimp at h
    rcases h with ⟨_, _, _, hmk, _, hcp⟩
    cases cp with
    | unstarted =>
      refine ⟨fun cp' heq => by injection heq with heq; subst heq; exact Or.inl rfl, ?_, ?_, ?_⟩
      · unfold dstCells; rw [hphase]
      · unfold dstCoins; rw [hphase]
      · unfold dstMarker; rw [hphase]
    | refused =>
      refine ⟨fun cp' heq => by injection heq with heq; subst heq; exact Or.inr (Or.inl rfl),
        ?_, ?_, ?_⟩
      · unfold dstCells; rw [hphase]
      · unfold dstCoins; rw [hphase]
      · unfold dstMarker; rw [hphase]
    | refusedNoCheckpoint =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hccFalse⟩
      refine ⟨fun cp' heq => by injection heq with heq; subst heq; exact Or.inr (Or.inr rfl),
        ?_, ?_, ?_⟩
      · unfold dstCells; rw [hphase]
      · unfold dstCoins; rw [hphase]
      · unfold dstMarker; rw [hphase]
    | scratchCopied =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | copyingCells copied =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | cellsCopied cells =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | verified cells =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | filesCopied cells =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | ingested cells coins =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | replaying cells coins k =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _, _, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | replayDone cells coins =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | scratchDeleted cells coins =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | publishedPendingSync cells coins =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | success cells coins =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | publicationUnknown cells coins =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | verificationFailed =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | missingBlockData cells coins k =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc, _, _, _, _⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction
    | ioErrorPrePublish =>
      rcases hcp with ⟨_, hdst, hdisj, hmkEnv, hcc⟩
      rcases hunsafe with h1 | h2 | h3 | h4
      · rw [hdst] at h1; contradiction
      · rw [hdisj] at h2; contradiction
      · rcases hmkEnv with hm1 | hm2
        · exact False.elim (h3.1 hm1)
        · exact False.elim (h3.2 hm2)
      · rw [hcc] at h4; contradiction

-- RCV-10
theorem missing_block_data_fails_before_publication (s : State) (h : invariant s)
    (cells : List Cell) (coins : CoinCell) (k : Nat)
    (hp : s.phase = .converter (.missingBlockData cells coins k)) :
    dstMarker s = none ∧ s.dstSyncObserved = false ∧
    dstCoins s = oracleCoins s.env (s.env.checkpointHeight + k) ∧
    s.env.checkpointHeight + k < s.env.durableHead ∧
    s.env.blockDataPresent (s.env.checkpointHeight + k + 1) = false := by
  unfold dstMarker dstCoins
  rw [hp]
  unfold invariant at h; rw [hp] at h; dsimp at h
  rcases h with ⟨_, _, _, _, _, hdst, _, _, _, _, _, hcoins, hbound, hdata⟩
  exact ⟨rfl, hdst, hcoins, hbound, hdata⟩

-- RCV-10
theorem coins_replay_derived (s : State) (h : invariant s) :
    match s.phase with
    | .converter (.ingested _ _) => dstCoins s = oracleCoins s.env (replayPos s)
    | .converter (.replaying _ _ _) => dstCoins s = oracleCoins s.env (replayPos s)
    | .converter (.replayDone _ _) => dstCoins s = oracleCoins s.env (replayPos s)
    | .converter (.scratchDeleted _ _) => dstCoins s = oracleCoins s.env (replayPos s)
    | .converter (.publishedPendingSync _ _) => dstCoins s = oracleCoins s.env (replayPos s)
    | .converter (.success _ _) => dstCoins s = oracleCoins s.env (replayPos s)
    | .converter (.publicationUnknown _ _) => dstCoins s = oracleCoins s.env (replayPos s)
    | .converter (.missingBlockData _ _ _) => dstCoins s = oracleCoins s.env (replayPos s)
    | _ => dstCoins s = 0 := by
  cases hphase : s.phase with
  | node np =>
    simp only [dstCoins, hphase]
  | converter cp =>
    cases cp with
    | unstarted => simp only [dstCoins, hphase]
    | refused => simp only [dstCoins, hphase]
    | refusedNoCheckpoint => simp only [dstCoins, hphase]
    | scratchCopied => simp only [dstCoins, hphase]
    | copyingCells copied => simp only [dstCoins, hphase]
    | cellsCopied cells => simp only [dstCoins, hphase]
    | verified cells => simp only [dstCoins, hphase]
    | filesCopied cells => simp only [dstCoins, hphase]
    | ingested cells coins =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, hcoins⟩
      have hcoins' : coins = oracleCoins s.env s.env.checkpointHeight := by
        rw [hcoins]
        unfold oracleCoins
        rw [ite_eq_left (Nat.le_refl _)]
      simp only [dstCoins, replayPos, hphase]
      exact hcoins'
    | replaying cells coins k =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, hcoins, _⟩
      simp only [dstCoins, replayPos, hphase]
      exact hcoins
    | replayDone cells coins =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, hcoins⟩
      simp only [dstCoins, replayPos, hphase]
      exact hcoins
    | scratchDeleted cells coins =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, hcoins⟩
      simp only [dstCoins, replayPos, hphase]
      exact hcoins
    | publishedPendingSync cells coins =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, hcoins⟩
      simp only [dstCoins, replayPos, hphase]
      exact hcoins
    | success cells coins =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, hcoins⟩
      simp only [dstCoins, replayPos, hphase]
      exact hcoins
    | publicationUnknown cells coins =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, hcoins⟩
      simp only [dstCoins, replayPos, hphase]
      exact hcoins
    | verificationFailed => simp only [dstCoins, hphase]
    | missingBlockData cells coins k =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, _, hcoins, _⟩
      simp only [dstCoins, replayPos, hphase]
      exact hcoins
    | ioErrorPrePublish => simp only [dstCoins, hphase]

-- RCV-09, RCV-10
theorem output_marker_soundness (s : State) (h : invariant s) (m : Marker)
    (hm : dstMarker s = some m) :
    m = .current4 ∧ dstCells s = s.env.srcContents.toList ∧
    dstCoins s = oracleCoins s.env s.env.durableHead := by
  unfold dstMarker at hm
  cases hphase : s.phase with
  | node p =>
    rw [hphase] at hm
    cases p <;> contradiction
  | converter cp =>
    rw [hphase] at hm
    cases cp with
    | publishedPendingSync cells coins =>
      injection hm with hm; subst hm
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, hcells, hcoins⟩
      unfold dstCells dstCoins
      rw [hphase]
      exact ⟨rfl, hcells, hcoins⟩
    | success cells coins =>
      injection hm with hm; subst hm
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, hcells, hcoins⟩
      unfold dstCells dstCoins
      rw [hphase]
      exact ⟨rfl, hcells, hcoins⟩
    | publicationUnknown cells coins =>
      injection hm with hm; subst hm
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, _, _, _, _, _, hcells, hcoins⟩
      unfold dstCells dstCoins
      rw [hphase]
      exact ⟨rfl, hcells, hcoins⟩
    | _ => contradiction

-- RCV-09
theorem success_implies_final_sync (s : State) (h : invariant s)
    (hsucc : isCvtSuccess s = true) :
    s.dstSyncObserved = true ∧
    s.phase = .converter (.success s.env.srcContents.toList
      (oracleCoins s.env s.env.durableHead)) ∧
    dstMarker s = some .current4 ∧
    dstCells s = s.env.srcContents.toList ∧
    dstCoins s = oracleCoins s.env s.env.durableHead := by
  unfold isCvtSuccess at hsucc
  cases hphase : s.phase with
  | node np =>
    rw [hphase] at hsucc
    cases np <;> contradiction
  | converter cp =>
    rw [hphase] at hsucc
    cases cp with
    | success cells coins =>
      unfold invariant at h; rw [hphase] at h; dsimp at h
      rcases h with ⟨_, _, _, _, _, hsync, _, _, _, _, hcells, hcoins⟩
      subst hcells; subst hcoins
      unfold dstMarker dstCells dstCoins
      rw [hphase]
      exact ⟨hsync, rfl, rfl, rfl, rfl⟩
    | _ => contradiction

-- RCV-09
theorem post_rename_unknown_distinguished_from_success (s : State) (h : invariant s)
    (cells : List Cell) (coins : CoinCell)
    (hp : s.phase = .converter (.publicationUnknown cells coins)) :
    isCvtSuccess s = false ∧ s.dstSyncObserved = false ∧ dstMarker s = some .current4 := by
  unfold isCvtSuccess dstMarker
  rw [hp]
  unfold invariant at h; rw [hp] at h; dsimp at h
  have hsync : s.dstSyncObserved = false := h.2.2.2.2.2.1
  exact ⟨rfl, hsync, rfl⟩

-- RCV-10
theorem journal_absent (s : State) (h : invariant s) : s.journalCopied = false :=
  h.2.2.1

/-
NEGATIVE CONTROLS AND MUTATION COUNTERPARTS
-/

/-- Mutant 1: verification step does NOT check content equality. -/
def step_unverified (s : State) : Action → State
  | .cvtVerifyPass =>
    match s.phase with
    | .converter (.cellsCopied cells) =>
      { s with phase := .converter (.verified cells) }
    | _ => s
  | a => step s a

def sampleEnv : Env := {
  srcMarker := .retired3,
  srcEmptyDir := true,
  dstEmptyDir := true,
  disjointPaths := true,
  srcContents := { c0 := 0, c1 := 0, c2 := 0, c3 := 0 },
  checkpointHeight := 0,
  durableHead := 0,
  checkpointComplete := true,
  blockDataPresent := fun _ => true,
  checkpointCoins := 0,
  blockUndoDelta := fun _ => 0
}

theorem sampleEnv_wf : envWellFormed sampleEnv := by
  unfold envWellFormed
  refine ⟨by decide, by decide, ?_⟩
  intro h _
  exact ⟨rfl, rfl⟩

def corruptTrace : List Action := [
  .cvtStartCopyScratch,
  .cvtCorruptCopy 42,
  .cvtCopyCell,
  .cvtCopyCell,
  .cvtCopyCell,
  .cvtVerifyPass,
  .cvtCopyRequiredFiles,
  .cvtLoadCheckpoint,
  .cvtDeleteScratch,
  .cvtPublishMarker
]

theorem negative_control_unverified_publishes_corrupt_content :
    let finalState := corruptTrace.foldl step_unverified (init .converter sampleEnv)
    dstMarker finalState = some .current4 ∧
    dstCells finalState ≠ sampleEnv.srcContents.toList := by
  dsimp [corruptTrace, sampleEnv, init, step_unverified, step, dstMarker, dstCells,
    Content.toList, nextCell]
  decide

theorem real_step_blocks_corrupt_trace_publication :
    let finalState := corruptTrace.foldl step (init .converter sampleEnv)
    dstMarker finalState = none ∧ dstCoins finalState = 0 := by
  dsimp [corruptTrace, sampleEnv, init, step, dstMarker, dstCoins, Content.toList,
    nextCell, checkContent]
  decide

theorem negative_control_bypassing_sync_violates_invariant (s : State)
    (cells : List Cell) (coins : CoinCell)
    (hp : s.phase = .converter (.success cells coins))
    (hsync : s.dstSyncObserved = false) :
    ¬ invariant s := by
  intro hinv
  unfold invariant at hinv
  rw [hp] at hinv
  dsimp at hinv
  have hsyncObserved : s.dstSyncObserved = true := hinv.2.2.2.2.2.1
  rw [hsync] at hsyncObserved
  contradiction

end Storage.SchemaEpoch4
