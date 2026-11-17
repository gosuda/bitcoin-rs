\* RCV-09
----------------------------- MODULE Marker -----------------------------
(***************************************************************************)
(* Datadir schema marker and migration lifecycle model.                    *)
(* Models Node admission and OfflineConversion modes over a finite cell    *)
(* abstraction (two namespaces, two families, bounded content bytes).     *)
(* Verifies marker publication, source immutability, crash/error safety,   *)
(* and independent observed directory sync before success.                 *)
(***************************************************************************)

EXTENDS Naturals

CONSTANTS
  \* @type: Int;
  CellBound,
  \* @type: Int;
  ContentBound

Cell_Chainstate_Default == 0
Cell_Chainstate_Aux     == 1
Cell_Txindex_Default    == 2
Cell_Txindex_Aux        == 3

Cells == 0..(CellBound - 1)
ContentValues == 0..ContentBound

MarkerAbsent    == 0
MarkerMalformed == 1
MarkerRetired   == 2
MarkerCurrent   == 3
MarkerFuture    == 4

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

PhaseConvertAdmitting     == 10
PhaseConvertCopyScratch    == 11
PhaseConvertCopyCells     == 12
PhaseConvertVerifyCells   == 13
PhaseConvertCopyFiles     == 14
PhaseConvertDeleteScratch == 15
PhaseConvertPublishMarker == 16
PhaseConvertPendingSync   == 17
PhaseConvertRefused       == 18
PhaseConvertFailedPrepub  == 19
PhaseConvertSuccess       == 20
PhaseConvertPubUnknown    == 21

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
  PhaseConvertDeleteScratch,
  PhaseConvertPublishMarker,
  PhaseConvertPendingSync,
  PhaseConvertRefused,
  PhaseConvertFailedPrepub,
  PhaseConvertSuccess,
  PhaseConvertPubUnknown
}

TerminalPhases == {
  PhaseNodeOpened,
  PhaseNodeRefused,
  PhaseNodeInitFailed,
  PhaseNodeInitSyncFailed,
  PhaseConvertRefused,
  PhaseConvertFailedPrepub,
  PhaseConvertSuccess,
  PhaseConvertPubUnknown
}

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
  \* @type: Bool;
  scratchPresent,
  \* @type: Bool;
  filesDurable,
  \* @type: Int;
  copyCursor,
  \* @type: Int;
  verifyCursor,
  \* @type: Int;
  phase,
  \* @type: Bool;
  observedSync

\* @type: <<Int, Int, Int -> Int, Bool, Bool, Bool, Int, Int -> Int, Int, Int -> Int, Bool, Bool, Int, Int, Int, Bool>>;
vars == << mode, initialSourceMarker, initialSourceContents, sourceEmpty, destEmpty,
           pathsDisjoint, sourceMarker, sourceContents, destMarker, destContents,
           scratchPresent, filesDurable, copyCursor, verifyCursor, phase, observedSync >>

Init ==
  /\ mode \in ModeDom
  /\ initialSourceMarker \in MarkerClassification
  /\ initialSourceContents \in [Cells -> ContentValues]
  /\ sourceEmpty \in BOOLEAN
  /\ destEmpty \in BOOLEAN
  /\ pathsDisjoint \in BOOLEAN
  /\ sourceMarker = initialSourceMarker
  /\ sourceContents = initialSourceContents
  /\ destMarker = MarkerAbsent
  /\ destContents = [c \in Cells |-> 0]
  /\ scratchPresent = FALSE
  /\ filesDurable = FALSE
  /\ copyCursor = 0
  /\ verifyCursor = 0
  /\ phase = IF mode = ModeNode THEN PhaseNodeOpening ELSE PhaseConvertAdmitting
  /\ observedSync = FALSE

NodeOpenDirect ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeOpening
  /\ sourceMarker = MarkerCurrent
  /\ phase' = PhaseNodeOpened
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

NodeInitStart ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeOpening
  /\ sourceMarker = MarkerAbsent
  /\ sourceEmpty = TRUE
  /\ phase' = PhaseNodeInitPreRename
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

NodeInitPreRenameIoError ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeInitPreRename
  /\ phase' = PhaseNodeInitFailed
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

NodeInitRename ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeInitPreRename
  /\ sourceMarker' = MarkerCurrent
  /\ phase' = PhaseNodeInitPostRename
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

NodeInitPostRenameSyncSuccess ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeInitPostRename
  /\ phase' = PhaseNodeOpened
  /\ observedSync' = TRUE
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor >>

NodeInitPostRenameSyncFailure ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeInitPostRename
  /\ phase' = PhaseNodeInitSyncFailed
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

NodeRefuse ==
  /\ mode = ModeNode
  /\ phase = PhaseNodeOpening
  /\ \/ sourceMarker \in {MarkerMalformed, MarkerRetired, MarkerFuture}
     \/ (sourceMarker = MarkerAbsent /\ sourceEmpty = FALSE)
  /\ phase' = PhaseNodeRefused
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

ConvertRefuse ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertAdmitting
  /\ \/ pathsDisjoint = FALSE
     \/ destEmpty = FALSE
     \/ ~(sourceMarker \in {MarkerRetired, MarkerCurrent})
  /\ phase' = PhaseConvertRefused
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

ConvertAdmit ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertAdmitting
  /\ pathsDisjoint = TRUE
  /\ destEmpty = TRUE
  /\ sourceMarker \in {MarkerRetired, MarkerCurrent}
  /\ scratchPresent' = TRUE
  /\ phase' = PhaseConvertCopyScratch
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, filesDurable, copyCursor, verifyCursor, observedSync >>

ConvertPrepubIoFailure ==
  /\ mode = ModeConvert
  /\ phase \in {PhaseConvertCopyScratch, PhaseConvertCopyCells, PhaseConvertVerifyCells,
                PhaseConvertCopyFiles, PhaseConvertDeleteScratch, PhaseConvertPublishMarker}
  /\ phase' = PhaseConvertFailedPrepub
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

ConvertStartCopyCells ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertCopyScratch
  /\ phase' = PhaseConvertCopyCells
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

ConvertCopyCell ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertCopyCells
  /\ copyCursor < CellBound
  /\ destContents' = [destContents EXCEPT ![copyCursor] = sourceContents[copyCursor]]
  /\ copyCursor' = copyCursor + 1
  /\ phase' = IF copyCursor + 1 = CellBound THEN PhaseConvertVerifyCells ELSE PhaseConvertCopyCells
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  scratchPresent, filesDurable, verifyCursor, observedSync >>

ConvertCorruptCopyCell ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertCopyCells
  /\ copyCursor < CellBound
  /\ \E v \in ContentValues :
       /\ v # sourceContents[copyCursor]
       /\ destContents' = [destContents EXCEPT ![copyCursor] = v]
  /\ copyCursor' = copyCursor + 1
  /\ phase' = IF copyCursor + 1 = CellBound THEN PhaseConvertVerifyCells ELSE PhaseConvertCopyCells
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  scratchPresent, filesDurable, verifyCursor, observedSync >>

ConvertVerifyStep ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertVerifyCells
  /\ verifyCursor < CellBound
  /\ destContents[verifyCursor] = sourceContents[verifyCursor]
  /\ verifyCursor' = verifyCursor + 1
  /\ phase' = IF verifyCursor + 1 = CellBound THEN PhaseConvertCopyFiles ELSE PhaseConvertVerifyCells
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, observedSync >>

ConvertVerifyMismatch ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertVerifyCells
  /\ verifyCursor < CellBound
  /\ destContents[verifyCursor] # sourceContents[verifyCursor]
  /\ phase' = PhaseConvertFailedPrepub
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

ConvertCopyRequiredFiles ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertCopyFiles
  /\ filesDurable' = TRUE
  /\ phase' = PhaseConvertDeleteScratch
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, copyCursor, verifyCursor, observedSync >>

ConvertDeleteScratch ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertDeleteScratch
  /\ scratchPresent' = FALSE
  /\ phase' = PhaseConvertPublishMarker
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, filesDurable, copyCursor, verifyCursor, observedSync >>

ConvertRenameMarker ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertPublishMarker
  /\ destMarker' = MarkerCurrent
  /\ phase' = PhaseConvertPendingSync
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

ConvertFinalSyncSuccess ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertPendingSync
  /\ phase' = PhaseConvertSuccess
  /\ observedSync' = TRUE
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor >>

ConvertFinalSyncFailure ==
  /\ mode = ModeConvert
  /\ phase = PhaseConvertPendingSync
  /\ phase' = PhaseConvertPubUnknown
  /\ UNCHANGED << mode, initialSourceMarker, initialSourceContents, sourceEmpty,
                  destEmpty, pathsDisjoint, sourceMarker, sourceContents, destMarker,
                  destContents, scratchPresent, filesDurable, copyCursor, verifyCursor,
                  observedSync >>

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
  \/ ConvertAdmit
  \/ ConvertPrepubIoFailure
  \/ ConvertStartCopyCells
  \/ ConvertCopyCell
  \/ ConvertCorruptCopyCell
  \/ ConvertVerifyStep
  \/ ConvertVerifyMismatch
  \/ ConvertCopyRequiredFiles
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
  /\ scratchPresent \in BOOLEAN
  /\ filesDurable \in BOOLEAN
  /\ copyCursor \in 0..CellBound
  /\ verifyCursor \in 0..CellBound
  /\ phase \in PhaseDom
  /\ observedSync \in BOOLEAN

Safety ==
  /\ sourceContents = initialSourceContents
  /\ (mode = ModeConvert) => (sourceMarker = initialSourceMarker)
  /\ (phase \in {PhaseNodeRefused, PhaseConvertRefused}) => (sourceMarker = initialSourceMarker)
  /\ (phase = PhaseNodeOpened) =>
       (/\ sourceMarker = MarkerCurrent
        /\ (initialSourceMarker = MarkerAbsent => observedSync = TRUE))
  /\ (phase = PhaseNodeInitSyncFailed) =>
       (/\ sourceMarker = MarkerCurrent
        /\ initialSourceMarker = MarkerAbsent
        /\ sourceEmpty = TRUE)
  /\ (mode = ModeConvert /\ (~pathsDisjoint \/ ~destEmpty \/ ~(initialSourceMarker \in {MarkerRetired, MarkerCurrent}))) =>
       (/\ destMarker = MarkerAbsent
        /\ copyCursor = 0
        /\ scratchPresent = FALSE
        /\ phase \in {PhaseConvertAdmitting, PhaseConvertRefused})
  /\ (phase = PhaseConvertFailedPrepub) => (destMarker = MarkerAbsent)
  /\ (destMarker = MarkerCurrent) =>
       (/\ \A c \in Cells : destContents[c] = sourceContents[c]
        /\ filesDurable = TRUE
        /\ scratchPresent = FALSE
        /\ verifyCursor = CellBound)
  /\ (phase = PhaseConvertSuccess) =>
       (/\ destMarker = MarkerCurrent
        /\ filesDurable = TRUE
        /\ scratchPresent = FALSE
        /\ observedSync = TRUE
        /\ \A c \in Cells : destContents[c] = sourceContents[c])

ConditionalProgress == TRUE

=============================================================================
