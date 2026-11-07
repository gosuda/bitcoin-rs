\* RCV-09, RCV-10, RCV-04
----------------------------- MODULE MarkerEpoch4 -----------------------------
(***************************************************************************)
(* Datadir schema marker and migration lifecycle model for schema epoch 4. *)
(* Extends the epoch-3 lifecycle (DatadirSchema/Marker) to the epoch-4      *)
(* target: coins live in the engine `coins` keyspace, the chainstate        *)
(* journal is deleted, and the `utxo-v4.dat` checkpoint coin image is an    *)
(* input that is ingested, never retained. Node admission refuses every     *)
(* epoch other than 4 and names the offline converter                       *)
(* `bitcoin-rs-storage-convert` in the refusal (message text is outside     *)
(* the state space). The converter step `3 -> 4` copies an epoch-3 datadir  *)
(* into the same engine, loads the newest complete checkpoint               *)
(* `utxo-v4.dat`, bulk-ingests it sorted into `coins`, replays heights      *)
(* checkpoint+1..durable head from block bodies plus undo rows, and writes  *)
(* CURRENT_SCHEMA last. Verified over a finite cell abstraction (four KV    *)
(* content cells, one coin cell, two heights, bounded content bytes).       *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
  \* @type: Int;
  CellBound,
  \* @type: Int;
  ContentBound,
  \* @type: Int;
  HeightBound,
  \* @type: Int;
  CoinCellBound

Cell_Chainstate_Default == 0
Cell_Chainstate_Aux     == 1
Cell_Txindex_Default    == 2
Cell_Txindex_Aux        == 3

Cells == 0..(CellBound - 1)
ContentValues == 0..ContentBound

CoinCells == 0..(CoinCellBound - 1)
Heights == 0..HeightBound

CoinZero == [c \in CoinCells |-> 0]

MarkerAbsent    == 0
MarkerMalformed == 1
MarkerRetired   == 2
MarkerCurrent   == 3
MarkerFuture    == 4

\* MarkerRetired models schema epoch 3 (RocksDB with journal and
\* utxo-v4 checkpoint coin image); MarkerCurrent models schema epoch 4
\* (coins in the engine `coins` keyspace, journal and checkpoint coin
\* image removed). The distinction is a modeling comment; both markers
\* are distinct enum values in the state space.
MarkerClassification == {MarkerAbsent, MarkerMalformed, MarkerRetired, MarkerCurrent, MarkerFuture}

ModeNode    == 0
ModeConvert == 1

ModeDom == {ModeNode, ModeConvert}

PhaseNodeOpening          == 0
PhaseNodeInitPreRename    == 1
PhaseNodeInitPostRename   == 2
PhaseNodeOpened           == 3
PhaseNodeRefused          == 4
PhaseNodeInitFailed       == 5
PhaseNodeInitSyncFailed   == 6

PhaseConvertAdmitting           == 10
PhaseConvertCopyScratch         == 11
PhaseConvertCopyCells           == 12
PhaseConvertVerifyCells         == 13
PhaseConvertCopyFiles           == 14
PhaseConvertIngestCheckpoint    == 15
PhaseConvertReplaying           == 16
PhaseConvertReplayDone          == 17
PhaseConvertDeleteScratch       == 18
PhaseConvertPublishMarker       == 19
PhaseConvertPendingSync         == 20
PhaseConvertRefused             == 21
PhaseConvertRefusedNoCheckpoint == 22
PhaseConvertFailedPrepub        == 23
PhaseConvertMissingBlockData    == 24
PhaseConvertSuccess             == 25
PhaseConvertPubUnknown          == 26

PhaseDom == {
  PhaseNodeOpening,
  PhaseNodeInitPreRename,
  PhaseNodeInitPostRename,
  PhaseNodeOpened,
  PhaseNodeRefused,
  PhaseNodeInitFailed,
  PhaseNodeInitSyncFailed,
  PhaseConvertAdmitting,
  PhaseConvertCopyScratch,
  PhaseConvertCopyCells,
  PhaseConvertVerifyCells,
  PhaseConvertCopyFiles,
  PhaseConvertIngestCheckpoint,
  PhaseConvertReplaying,
  PhaseConvertReplayDone,
  PhaseConvertDeleteScratch,
  PhaseConvertPublishMarker,
  PhaseConvertPendingSync,
  PhaseConvertRefused,
  PhaseConvertRefusedNoCheckpoint,
  PhaseConvertFailedPrepub,
  PhaseConvertMissingBlockData,
  PhaseConvertSuccess,
  PhaseConvertPubUnknown
}

TerminalPhases == {
  PhaseNodeOpened,
  PhaseNodeRefused,
  PhaseNodeInitFailed,
  PhaseNodeInitSyncFailed,
  PhaseConvertRefused,
  PhaseConvertRefusedNoCheckpoint,
  PhaseConvertFailedPrepub,
  PhaseConvertMissingBlockData,
  PhaseConvertSuccess,
  PhaseConvertPubUnknown
}

\* Phases in which the coins keyspace has received the checkpoint ingest
\* (or later replay writes). Ordered late in the pipeline.
PostIngestPhases == {
  PhaseConvertReplaying,
  PhaseConvertReplayDone,
  PhaseConvertDeleteScratch,
  PhaseConvertPublishMarker,
  PhaseConvertPendingSync,
  PhaseConvertSuccess,
  PhaseConvertPubUnknown
}

MinInt(a, b) == IF a < b THEN a ELSE b

VARIABLES
  \* @type: Int;
  mode,
  \* @type: Int;
  initialSourceMarker,
  \* @type: Int -> Int;
  initialSourceContents,
  \* @type: Bool;
  sourceEmpty,
  \* @type: Bool;
  destEmpty,
  \* @type: Bool;
  pathsDisjoint,
  \* @type: Int;
  sourceMarker,
  \* @type: Int -> Int;
  sourceContents,
  \* @type: Int;
  destMarker,
  \* @type: Int -> Int;
  destContents,
  \* @type: Int;
  checkpointHeight,
  \* @type: Int;
  durableHead,
  \* @type: Bool;
  checkpointComplete,
  \* @type: Int -> Bool;
  blockDataPresent,
  \* @type: Int -> Int -> Int;
  blockUndoDelta,
  \* @type: Int -> Int;
  checkpointCoins,
  \* @type: Int -> Int;
  destCoins,
  \* @type: Int;
  replayCursor,
  \* @type: Bool;
  scratchPresent,
  \* @type: Bool;
  filesDurable,
  \* @type: Bool;
  journalCopied,
  \* @type: Int;
  copyCursor,
  \* @type: Int;
  verifyCursor,
  \* @type: Int;
  phase,
  \* @type: Bool;
  observedSync

\* @type: <<Int, Int, Int -> Int, Bool, Bool, Bool, Int, Int -> Int, Int, Int -> Int, Int, Int, Bool, Int -> Bool, Int -> Int -> Int, Int -> Int, Int -> Int, Int, Bool, Bool, Bool, Int, Int, Int, Bool>>;
vars == << mode, initialSourceMarker, initialSourceContents, sourceEmpty, destEmpty,
           pathsDisjoint, sourceMarker, sourceContents, destMarker, destContents,
           checkpointHeight, durableHead, checkpointComplete, blockDataPresent,
           blockUndoDelta, checkpointCoins, destCoins, replayCursor,
           scratchPresent, filesDurable, journalCopied, copyCursor, verifyCursor,
           phase, observedSync >>

NodeInputsUnchanged == << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                          destEmpty, pathsDisjoint, checkpointHeight, durableHead,
                          checkpointComplete, blockDataPresent, blockUndoDelta,
                          checkpointCoins >>

Init ==
  /\ mode \in ModeDom
  /\ initialSourceMarker \in MarkerClassification
  /\ initialSourceContents \in [Cells -> ContentValues]
  /\ sourceEmpty \in BOOLEAN
  /\ destEmpty \in BOOLEAN
  /\ pathsDisjoint \in BOOLEAN
  /\ checkpointHeight \in 0..HeightBound
  /\ durableHead \in checkpointHeight..HeightBound
  /\ checkpointComplete \in BOOLEAN
  /\ blockDataPresent \in [Heights -> BOOLEAN]
  /\ checkpointCoins \in [CoinCells -> ContentValues]
  /\ blockUndoDelta \in [Heights -> [CoinCells -> ContentValues]]
  /\ \A h \in 0..checkpointHeight : blockDataPresent[h]
  /\ \A h \in 0..checkpointHeight : blockUndoDelta[h] = checkpointCoins
  /\ sourceMarker = initialSourceMarker
  /\ sourceContents = initialSourceContents
  /\ destMarker = MarkerAbsent
  /\ destContents = [c \in Cells |-> 0]
  /\ destCoins = CoinZero
  /\ replayCursor = 0
  /\ scratchPresent = FALSE
  /\ filesDurable = FALSE
  /\ journalCopied = FALSE
  /\ copyCursor = 0
  /\ verifyCursor = 0
  /\ phase = IF mode = ModeNode THEN PhaseNodeOpening ELSE PhaseConvertAdmitting
  /\ observedSync = FALSE

OracleCoins(h) == IF h <= checkpointHeight THEN checkpointCoins ELSE blockUndoDelta[h]

NodeOpenDirect ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeOpening
  /\ sourceMarker = MarkerCurrent
  /\ phase' = PhaseNodeOpened
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

NodeInitStart ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeOpening
  /\ sourceMarker = MarkerAbsent
  /\ sourceEmpty = TRUE
  /\ phase' = PhaseNodeInitPreRename
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

NodeInitPreRenameIoError ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeInitPreRename
  /\ phase' = PhaseNodeInitFailed
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

NodeInitRename ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeInitPreRename
  /\ sourceMarker' = MarkerCurrent
  /\ phase' = PhaseNodeInitPostRename
  /\ UNCHANGED << NodeInputsUnchanged, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

NodeInitPostRenameSyncSuccess ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeInitPostRename
  /\ phase' = PhaseNodeOpened
  /\ observedSync' = TRUE
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor >>

NodeInitPostRenameSyncFailure ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeInitPostRename
  /\ phase' = PhaseNodeInitSyncFailed
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

\* Refusal names the converter: the refusal text names
\* `bitcoin-rs-storage-convert --from <old> --to <new>`; the model carries
\* the refusal as a terminal phase only.
NodeRefuse ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeOpening
  /\ \/ sourceMarker \in {MarkerMalformed, MarkerRetired, MarkerFuture}
     \/ (sourceMarker = MarkerAbsent /\ sourceEmpty = FALSE)
  /\ phase' = PhaseNodeRefused
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

ConvertRefuse ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertAdmitting
  /\ \/ pathsDisjoint = FALSE
     \/ destEmpty = FALSE
     \/ ~(sourceMarker \in {MarkerRetired, MarkerCurrent})
  /\ phase' = PhaseConvertRefused
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

\* Missing complete checkpoint fails closed with resync guidance before
\* any destination write (RCV-10).
ConvertRefuseNoCheckpoint ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertAdmitting
  /\ pathsDisjoint = TRUE
  /\ destEmpty = TRUE
  /\ sourceMarker \in {MarkerRetired, MarkerCurrent}
  /\ checkpointComplete = FALSE
  /\ phase' = PhaseConvertRefusedNoCheckpoint
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

ConvertAdmit ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertAdmitting
  /\ pathsDisjoint = TRUE
  /\ destEmpty = TRUE
  /\ sourceMarker \in {MarkerRetired, MarkerCurrent}
  /\ checkpointComplete = TRUE
  /\ scratchPresent' = TRUE
  /\ phase' = PhaseConvertCopyScratch
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

\* Any I/O failure before the marker rename aborts without publication
\* (RCV-04). Once the marker is renamed, only PhaseConvertPubUnknown is
\* reachable (ConvertFinalSyncFailure).
ConvertPrepubIoFailure ==
  /\ mode = ModeConvert
  /\ phase \in {PhaseConvertCopyScratch, PhaseConvertCopyCells, PhaseConvertVerifyCells,
                PhaseConvertCopyFiles, PhaseConvertIngestCheckpoint,
                PhaseConvertReplaying, PhaseConvertReplayDone,
                PhaseConvertDeleteScratch, PhaseConvertPublishMarker}
  /\ phase' = PhaseConvertFailedPrepub
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

ConvertStartCopyCells ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertCopyScratch
  /\ phase' = PhaseConvertCopyCells
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

ConvertCopyCell ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertCopyCells
  /\ copyCursor < CellBound
  /\ destContents' = [destContents EXCEPT ![copyCursor] = sourceContents[copyCursor]]
  /\ copyCursor' = copyCursor + 1
  /\ phase' = IF copyCursor + 1 = CellBound THEN PhaseConvertVerifyCells ELSE PhaseConvertCopyCells
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, verifyCursor, observedSync >>

ConvertCorruptCopyCell ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertCopyCells
  /\ copyCursor < CellBound
  /\ \E v \in ContentValues :
       /\ v # sourceContents[copyCursor]
       /\ destContents' = [destContents EXCEPT ![copyCursor] = v]
  /\ copyCursor' = copyCursor + 1
  /\ phase' = IF copyCursor + 1 = CellBound THEN PhaseConvertVerifyCells ELSE PhaseConvertCopyCells
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, verifyCursor, observedSync >>

ConvertVerifyStep ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertVerifyCells
  /\ verifyCursor < CellBound
  /\ destContents[verifyCursor] = sourceContents[verifyCursor]
  /\ verifyCursor' = verifyCursor + 1
  /\ phase' = IF verifyCursor + 1 = CellBound THEN PhaseConvertCopyFiles ELSE PhaseConvertVerifyCells
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, observedSync >>

ConvertVerifyMismatch ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertVerifyCells
  /\ verifyCursor < CellBound
  /\ destContents[verifyCursor] # sourceContents[verifyCursor]
  /\ phase' = PhaseConvertFailedPrepub
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

\* Engine-independent files are copied byte-for-byte. The chainstate
\* journal is deleted in epoch 4 and is not part of the copied set; no
\* journal action exists in this model and journalCopied stays FALSE
\* (JournalAbsent invariant).
ConvertCopyRequiredFiles ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertCopyFiles
  /\ filesDurable' = TRUE
  /\ journalCopied' = FALSE
  /\ phase' = PhaseConvertIngestCheckpoint
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent,
                  copyCursor, verifyCursor, observedSync >>

\* Load the newest complete checkpoint utxo-v4.dat from the scratch copy,
\* externally sort by coin key, and bulk-ingest into the unpublished
\* `coins` keyspace (RCV-10). Sorted ingest order is an engine-seam
\* (`ingest_sorted`) property outside this lifecycle model. The image is
\* consumed, never retained as a resident authority.
ConvertLoadCheckpoint ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertIngestCheckpoint
  /\ filesDurable = TRUE
  /\ destCoins' = checkpointCoins
  /\ replayCursor' = checkpointHeight + 1
  /\ phase' = IF checkpointHeight = durableHead THEN PhaseConvertReplayDone
              ELSE PhaseConvertReplaying
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

\* Replay height checkpointHeight + 1 .. durableHead: apply the derived
\* coin effects of each block body plus its undo row. A missing body or
\* undo row aborts with MissingBlockData{height}; the aborting height is
\* the current replayCursor (carried by the phase, not a separate
\* variable, so the message text stays outside the state space).
ConvertReplayHeight ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertReplaying
  /\ replayCursor <= durableHead
  /\ IF blockDataPresent[replayCursor]
       THEN /\ destCoins' = blockUndoDelta[replayCursor]
            /\ replayCursor' = replayCursor + 1
            /\ phase' = IF replayCursor = durableHead THEN PhaseConvertReplayDone
                        ELSE PhaseConvertReplaying
       ELSE /\ destCoins' = destCoins
            /\ replayCursor' = replayCursor
            /\ phase' = PhaseConvertMissingBlockData
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

ConvertDeleteScratch ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertReplayDone
  /\ scratchPresent' = FALSE
  /\ phase' = PhaseConvertPublishMarker
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

\* CURRENT_SCHEMA = 4 is written last: temp file, fsync, rename, dir
\* fsync (RCV-04).
ConvertRenameMarker ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertPublishMarker
  /\ destMarker' = MarkerCurrent
  /\ phase' = PhaseConvertPendingSync
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

ConvertFinalSyncSuccess ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertPendingSync
  /\ phase' = PhaseConvertSuccess
  /\ observedSync' = TRUE
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor >>

ConvertFinalSyncFailure ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertPendingSync
  /\ phase' = PhaseConvertPubUnknown
  /\ UNCHANGED << NodeInputsUnchanged, sourceMarker, sourceContents, destMarker,
                  destContents, destCoins, replayCursor, scratchPresent, filesDurable,
                  journalCopied, copyCursor, verifyCursor, observedSync >>

Stutter ==
  /\ phase \in TerminalPhases
  /\ UNCHANGED vars

Next ==
  \/ NodeOpenDirect
  \/ NodeInitStart
  \/ NodeInitPreRenameIoError
  \/ NodeInitRename
  \/ NodeInitPostRenameSyncSuccess
  \/ NodeInitPostRenameSyncFailure
  \/ NodeRefuse
  \/ ConvertRefuse
  \/ ConvertRefuseNoCheckpoint
  \/ ConvertAdmit
  \/ ConvertPrepubIoFailure
  \/ ConvertStartCopyCells
  \/ ConvertCopyCell
  \/ ConvertCorruptCopyCell
  \/ ConvertVerifyStep
  \/ ConvertVerifyMismatch
  \/ ConvertCopyRequiredFiles
  \/ ConvertLoadCheckpoint
  \/ ConvertReplayHeight
  \/ ConvertDeleteScratch
  \/ ConvertRenameMarker
  \/ ConvertFinalSyncSuccess
  \/ ConvertFinalSyncFailure
  \/ Stutter

TypeOK ==
  /\ mode \in ModeDom
  /\ initialSourceMarker \in MarkerClassification
  /\ initialSourceContents \in [Cells -> ContentValues]
  /\ sourceEmpty \in BOOLEAN
  /\ destEmpty \in BOOLEAN
  /\ pathsDisjoint \in BOOLEAN
  /\ sourceMarker \in MarkerClassification
  /\ sourceContents \in [Cells -> ContentValues]
  /\ destMarker \in MarkerClassification
  /\ destContents \in [Cells -> ContentValues]
  /\ checkpointHeight \in 0..HeightBound
  /\ durableHead \in checkpointHeight..HeightBound
  /\ checkpointComplete \in BOOLEAN
  /\ blockDataPresent \in [Heights -> BOOLEAN]
  /\ blockUndoDelta \in [Heights -> [CoinCells -> ContentValues]]
  /\ checkpointCoins \in [CoinCells -> ContentValues]
  /\ destCoins \in [CoinCells -> ContentValues]
  /\ replayCursor \in 0..(HeightBound + 1)
  /\ scratchPresent \in BOOLEAN
  /\ filesDurable \in BOOLEAN
  /\ journalCopied \in BOOLEAN
  /\ copyCursor \in 0..CellBound
  /\ verifyCursor \in 0..CellBound
  /\ phase \in PhaseDom
  /\ observedSync \in BOOLEAN

\* The source datadir is never mutated by conversion: contents are
\* strictly immutable, and the source marker changes only through node
\* initialization of an absent, empty datadir.
SourceImmutable ==
  /\ sourceContents = initialSourceContents
  /\ (mode = ModeConvert) => (sourceMarker = initialSourceMarker)
  /\ (phase \in {PhaseNodeRefused, PhaseConvertRefused, PhaseConvertRefusedNoCheckpoint}) =>
       (sourceMarker = initialSourceMarker)

\* A published destination marker implies verified cells, oracle-derived
\* coins at the durable head, copied files, deleted scratch, and a
\* completed replay (CURRENT_SCHEMA written last).
MarkerSound ==
  /\ (destMarker = MarkerCurrent) =>
       (/\ destContents = sourceContents
        /\ destCoins = OracleCoins(durableHead)
        /\ filesDurable = TRUE
        /\ scratchPresent = FALSE
        /\ verifyCursor = CellBound
        /\ replayCursor = durableHead + 1)

\* Refusals and pre-publication aborts never publish a marker, never
\* claim a final sync, and a missing-checkpoint refusal additionally
\* leaves the destination untouched.
RefusalAbortClean ==
  /\ (phase \in {PhaseConvertRefused, PhaseConvertRefusedNoCheckpoint,
                 PhaseConvertFailedPrepub, PhaseConvertMissingBlockData}) =>
       (/\ destMarker = MarkerAbsent
        /\ observedSync = FALSE)
  /\ (phase = PhaseConvertRefusedNoCheckpoint) =>
       (/\ destContents = [c \in Cells |-> 0]
        /\ destCoins = CoinZero
        /\ copyCursor = 0
        /\ verifyCursor = 0
        /\ scratchPresent = FALSE
        /\ filesDurable = FALSE
        /\ journalCopied = FALSE
        /\ replayCursor <= checkpointHeight)

\* Success implies an independently observed final directory sync plus
\* the full published soundness conjuncts. The model deliberately does
\* NOT relate success to any final-head coin-count, amount, or hash
\* statistic: no such independent commitment exists (the converter makes
\* no final-head coin statistics comparison).
SuccessImpliesSync ==
  /\ (phase = PhaseConvertSuccess) =>
       (/\ observedSync = TRUE
        /\ destMarker = MarkerCurrent
        /\ filesDurable = TRUE
        /\ scratchPresent = FALSE
        /\ destContents = sourceContents
        /\ destCoins = OracleCoins(durableHead)
        /\ replayCursor = durableHead + 1)

\* Coin content is always either untouched (pre-ingest zero) or exactly
\* the replay-oracle value for the replay position; no arbitrary bytes
\* ever enter the coins keyspace.
CoinsOracleDerived ==
  /\ (replayCursor > checkpointHeight) =>
       destCoins = OracleCoins(MinInt(replayCursor - 1, durableHead))
  /\ (replayCursor <= checkpointHeight) =>
       destCoins = CoinZero

\* The chainstate journal is deleted in epoch 4; no model action copies
\* it and the flag can never rise.
JournalAbsent == journalCopied = FALSE

Safety ==
  /\ SourceImmutable
  /\ MarkerSound
  /\ RefusalAbortClean
  /\ SuccessImpliesSync
  /\ CoinsOracleDerived
  /\ JournalAbsent

ConditionalProgress == TRUE

=============================================================================
