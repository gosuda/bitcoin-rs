//! Executable reference model for schema epoch 6 admission and offline conversion.
//!
//! Models the lifecycle of node datadir schema verification and the converter steps
//! `3 -> 6`, `4 -> 6` and `5 -> 6` targeting storage epoch 6 per RCV-09 and RCV-10. Epoch 5,
//! epoch 4 and epoch 3 are retired. Epoch 6 keeps coins in the engine `coins` keyspace,
//! deletes the journal, and publishes a snapshot-base checkpoint in place of the
//! retired snapshot archive. The model treats all retired epochs as the same
//! convertible source; archive verification of a retired epoch snapshot is not
//! modeled. Live storage (`checkpoint::fs`) is at schema epoch 6; this is a
//! standalone behavioral design model, not an implementation-refinement claim on
//! `fs.rs` or `tools/storage-convert`.

#[cfg(kani)]
mod proofs;

pub const NUM_CELLS: usize = 4;
pub const NUM_CELLS_U8: u8 = 4;
pub const NUM_HEIGHTS: usize = 2;
pub const HEIGHT_MAX: u8 = 1;

/// Classification of a CURRENT_SCHEMA marker file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerClassification {
    /// No CURRENT_SCHEMA file present in directory.
    Absent,
    /// Marker file is present but contains invalid data or corrupt formatting.
    Malformed,
    /// Datadir schema epoch 3 (retired epoch; journal and checkpoint coin image).
    RetiredEpoch3,
    /// Datadir schema epoch 4 (retired epoch; engine `coins` keyspace, snapshot archive).
    RetiredEpoch4,
    /// Datadir schema epoch 5 (retired epoch; engine `coins` keyspace, snapshot-base checkpoint, undo format version 1).
    RetiredEpoch5,
    /// Datadir schema epoch 6 (current epoch; engine `coins` keyspace, snapshot-base checkpoint, undo format version 2).
    CurrentEpoch6,
    /// Future schema epoch not recognized by this version.
    FutureEpoch,
}

impl MarkerClassification {
    #[must_use]
    pub const fn is_current(self) -> bool {
        matches!(self, Self::CurrentEpoch6)
    }

    #[must_use]
    pub const fn is_convertible(self) -> bool {
        matches!(
            self,
            Self::RetiredEpoch3 | Self::RetiredEpoch4 | Self::RetiredEpoch5 | Self::CurrentEpoch6
        )
    }

    #[must_use]
    pub const fn refusal_names_converter(self) -> bool {
        !self.is_current()
    }
}

/// Operational mode of the schema lifecycle machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    NodeAdmission,
    OfflineConversion,
}

/// Immutable inputs provided at startup or tool invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelInputs {
    pub mode: Mode,
    pub source_marker: MarkerClassification,
    pub source_dir_empty: bool,
    pub dest_initially_empty: bool,
    pub paths_disjoint: bool,
    pub initial_source_contents: [u8; NUM_CELLS],
    pub checkpoint_height: u8,
    pub durable_head: u8,
    pub checkpoint_complete: bool,
    pub block_data_present: [bool; NUM_HEIGHTS],
    pub checkpoint_coins: u8,
    pub block_undo_delta: [u8; NUM_HEIGHTS],
}

impl ModelInputs {
    /// Replay oracle: cumulative coin content attributed to a height.
    #[must_use]
    pub fn oracle_coins(&self, height: u8) -> u8 {
        if height <= self.checkpoint_height {
            self.checkpoint_coins
        } else {
            self.block_undo_delta[usize::from(height)]
        }
    }

    /// Environment facts the converter and the node rely on.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.durable_head <= HEIGHT_MAX
            && self.checkpoint_height <= self.durable_head
            && (0..=self.checkpoint_height).all(|h| {
                self.block_data_present[usize::from(h)]
                    && self.block_undo_delta[usize::from(h)] == self.checkpoint_coins
            })
    }
}

/// Lifecycle progression phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Admission,
    Copying,
    Verifying,
    CopyingRequiredFiles,
    IngestingCheckpoint,
    Replaying,
    ReplayDone,
    DeletingScratch,
    RenamingMarker,
    PublishedPendingSync,
    NodeInitWritingTemp,
    NodeInitRenaming,
    NodeInitPendingSync,
    Terminal,
}

/// High-level outcome of lifecycle execution.
#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Pending,
    Refused,
    RefusedNoCheckpoint,
    MissingData { height: u8 },
    PrepublicationFailure,
    PublicationUnknown,
    Success,
}
impl PartialEq for Outcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Pending, Self::Pending) => true,
            (Self::Refused, Self::Refused) => true,
            (Self::RefusedNoCheckpoint, Self::RefusedNoCheckpoint) => true,
            (Self::MissingData { height: h1 }, Self::MissingData { height: h2 }) => h1 == h2,
            (Self::PrepublicationFailure, Self::PrepublicationFailure) => true,
            (Self::PublicationUnknown, Self::PublicationUnknown) => true,
            (Self::Success, Self::Success) => true,
            _ => false,
        }
    }
}

impl Eq for Outcome {}

/// Discrete transition actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    RejectAdmission,
    RefuseMissingCheckpoint,
    ConvertAcceptAdmission,
    NodeOpenDirect,
    NodeInitStart,
    NodeInitWriteTempSuccess,
    NodeInitWriteTempFailure,
    NodeInitRenameSuccess,
    NodeInitRenameFailure,
    CopyCell,
    CorruptCopyCell(u8),
    VerifyCell,
    PrepubIoFailure,
    CopyRequiredFiles,
    LoadCheckpointCoins,
    ReplayBlock,
    MissingBlockDataAbort,
    DeleteScratchSuccess,
    PublishMarkerRename,
    FinalSyncSuccess,
    FinalSyncFailure,
    Stutter,
}

impl Action {
    pub const ALL: [Self; 22] = [
        Self::RejectAdmission,
        Self::RefuseMissingCheckpoint,
        Self::ConvertAcceptAdmission,
        Self::NodeOpenDirect,
        Self::NodeInitStart,
        Self::NodeInitWriteTempSuccess,
        Self::NodeInitWriteTempFailure,
        Self::NodeInitRenameSuccess,
        Self::NodeInitRenameFailure,
        Self::CopyCell,
        Self::CorruptCopyCell(0xFF),
        Self::VerifyCell,
        Self::PrepubIoFailure,
        Self::CopyRequiredFiles,
        Self::LoadCheckpointCoins,
        Self::ReplayBlock,
        Self::MissingBlockDataAbort,
        Self::DeleteScratchSuccess,
        Self::PublishMarkerRename,
        Self::FinalSyncSuccess,
        Self::FinalSyncFailure,
        Self::Stutter,
    ];
}

/// State of the lifecycle reference model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct State {
    pub inputs: ModelInputs,
    pub source_marker: MarkerClassification,
    pub source_contents: [u8; NUM_CELLS],
    pub dest_cells: [u8; NUM_CELLS],
    pub dest_coins: u8,
    pub dest_marker: Option<MarkerClassification>,
    pub phase: Phase,
    pub outcome: Outcome,
    pub copy_cursor: u8,
    pub verify_cursor: u8,
    pub replay_applied: u8,
    pub required_files_durable: bool,
    pub scratch_deleted: bool,
    pub journal_copied: bool,
    pub observed_final_sync: bool,
}

impl State {
    #[must_use]
    pub const fn init(inputs: ModelInputs) -> Self {
        Self {
            inputs,
            source_marker: inputs.source_marker,
            source_contents: inputs.initial_source_contents,
            dest_cells: [0; NUM_CELLS],
            dest_coins: 0,
            dest_marker: None,
            phase: Phase::Admission,
            outcome: Outcome::Pending,
            copy_cursor: 0,
            verify_cursor: 0,
            replay_applied: 0,
            required_files_durable: false,
            scratch_deleted: false,
            journal_copied: false,
            observed_final_sync: false,
        }
    }

    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !matches!(self.outcome, Outcome::Pending)
    }

    #[must_use]
    pub const fn engine_opened(&self) -> bool {
        matches!(self.outcome, Outcome::Success) && matches!(self.inputs.mode, Mode::NodeAdmission)
    }

    #[must_use]
    pub const fn has_success_receipt(&self) -> bool {
        matches!(self.outcome, Outcome::Success)
            && matches!(self.inputs.mode, Mode::OfflineConversion)
    }

    /// Replay position attributed to the current state.
    #[must_use]
    pub const fn replay_position(&self) -> u8 {
        self.inputs.checkpoint_height + self.replay_applied
    }
}

fn can_reject_admission(state: &State) -> bool {
    match state.inputs.mode {
        Mode::NodeAdmission => {
            !state.source_marker.is_current()
                && !(state.source_marker == MarkerClassification::Absent
                    && state.inputs.source_dir_empty)
        }
        Mode::OfflineConversion => {
            !state.source_marker.is_convertible()
                || !state.inputs.dest_initially_empty
                || !state.inputs.paths_disjoint
        }
    }
}

fn can_refuse_missing_checkpoint(state: &State) -> bool {
    matches!(state.inputs.mode, Mode::OfflineConversion)
        && state.source_marker.is_convertible()
        && state.inputs.dest_initially_empty
        && state.inputs.paths_disjoint
        && !state.inputs.checkpoint_complete
}

fn step_admission(state: &State, action: Action) -> Option<State> {
    if !matches!(state.phase, Phase::Admission) {
        return None;
    }

    match action {
        Action::RejectAdmission => {
            if !can_reject_admission(state) {
                return None;
            }
            let mut next = *state;
            next.phase = Phase::Terminal;
            next.outcome = Outcome::Refused;
            Some(next)
        }
        Action::RefuseMissingCheckpoint => {
            if !can_refuse_missing_checkpoint(state) {
                return None;
            }
            let mut next = *state;
            next.phase = Phase::Terminal;
            next.outcome = Outcome::RefusedNoCheckpoint;
            Some(next)
        }
        Action::ConvertAcceptAdmission => {
            if !matches!(state.inputs.mode, Mode::OfflineConversion)
                || !state.source_marker.is_convertible()
                || !state.inputs.dest_initially_empty
                || !state.inputs.paths_disjoint
                || !state.inputs.checkpoint_complete
            {
                return None;
            }
            let mut next = *state;
            next.phase = Phase::Copying;
            next.copy_cursor = 0;
            Some(next)
        }
        Action::NodeOpenDirect => {
            if !matches!(state.inputs.mode, Mode::NodeAdmission)
                || !state.source_marker.is_current()
            {
                return None;
            }
            let mut next = *state;
            next.observed_final_sync = false;
            next.outcome = Outcome::Success;
            next.phase = Phase::Terminal;
            Some(next)
        }
        _ => None,
    }
}

fn step_node_init(state: &State, action: Action) -> Option<State> {
    match action {
        Action::NodeInitStart => {
            if !matches!(state.phase, Phase::Admission)
                || !matches!(state.inputs.mode, Mode::NodeAdmission)
                || state.source_marker != MarkerClassification::Absent
                || !state.inputs.source_dir_empty
            {
                return None;
            }
            let mut next = *state;
            next.phase = Phase::NodeInitWritingTemp;
            Some(next)
        }
        Action::NodeInitWriteTempSuccess => {
            if !matches!(state.phase, Phase::NodeInitWritingTemp) {
                return None;
            }
            let mut next = *state;
            next.phase = Phase::NodeInitRenaming;
            Some(next)
        }
        Action::NodeInitWriteTempFailure => {
            if !matches!(state.phase, Phase::NodeInitWritingTemp) {
                return None;
            }
            let mut next = *state;
            next.phase = Phase::Terminal;
            next.outcome = Outcome::PrepublicationFailure;
            Some(next)
        }
        Action::NodeInitRenameSuccess => {
            if !matches!(state.phase, Phase::NodeInitRenaming) {
                return None;
            }
            let mut next = *state;
            next.source_marker = MarkerClassification::CurrentEpoch6;
            next.phase = Phase::NodeInitPendingSync;
            Some(next)
        }
        Action::NodeInitRenameFailure => {
            if !matches!(state.phase, Phase::NodeInitRenaming) {
                return None;
            }
            let mut next = *state;
            next.phase = Phase::Terminal;
            next.outcome = Outcome::PrepublicationFailure;
            Some(next)
        }
        _ => None,
    }
}

fn step_conversion_copy(state: &State, action: Action) -> Option<State> {
    if !matches!(state.phase, Phase::Copying) || state.copy_cursor >= NUM_CELLS_U8 {
        return None;
    }

    match action {
        Action::CopyCell => {
            let idx = usize::from(state.copy_cursor);
            let mut next = *state;
            next.dest_cells[idx] = state.source_contents[idx];
            next.copy_cursor += 1;
            if next.copy_cursor == NUM_CELLS_U8 {
                next.phase = Phase::Verifying;
            }
            Some(next)
        }
        Action::CorruptCopyCell(corrupt_byte) => {
            let idx = usize::from(state.copy_cursor);
            let mut next = *state;
            next.dest_cells[idx] = corrupt_byte;
            next.copy_cursor += 1;
            if next.copy_cursor == NUM_CELLS_U8 {
                next.phase = Phase::Verifying;
            }
            Some(next)
        }
        _ => None,
    }
}

fn step_conversion_verify(state: &State, action: Action) -> Option<State> {
    if !matches!(action, Action::VerifyCell)
        || !matches!(state.phase, Phase::Verifying)
        || state.verify_cursor >= NUM_CELLS_U8
    {
        return None;
    }

    let idx = usize::from(state.verify_cursor);
    let mut next = *state;
    if next.dest_cells[idx] == next.source_contents[idx] {
        next.verify_cursor += 1;
        if next.verify_cursor == NUM_CELLS_U8 {
            next.phase = Phase::CopyingRequiredFiles;
        }
    } else {
        next.phase = Phase::Terminal;
        next.outcome = Outcome::PrepublicationFailure;
    }
    Some(next)
}

fn step_conversion_ingest(state: &State, action: Action) -> Option<State> {
    match action {
        Action::PrepubIoFailure => {
            if !matches!(
                state.phase,
                Phase::Copying
                    | Phase::Verifying
                    | Phase::CopyingRequiredFiles
                    | Phase::IngestingCheckpoint
                    | Phase::Replaying
                    | Phase::ReplayDone
                    | Phase::DeletingScratch
                    | Phase::RenamingMarker
            ) {
                return None;
            }
            let mut next = *state;
            next.phase = Phase::Terminal;
            next.outcome = Outcome::PrepublicationFailure;
            Some(next)
        }
        Action::CopyRequiredFiles => {
            if !matches!(state.phase, Phase::CopyingRequiredFiles)
                || state.verify_cursor != NUM_CELLS_U8
            {
                return None;
            }
            let mut next = *state;
            next.required_files_durable = true;
            next.journal_copied = false;
            next.phase = Phase::IngestingCheckpoint;
            Some(next)
        }
        Action::LoadCheckpointCoins => {
            if !matches!(state.phase, Phase::IngestingCheckpoint) || !state.required_files_durable {
                return None;
            }
            let mut next = *state;
            next.dest_coins = state.inputs.checkpoint_coins;
            next.replay_applied = 0;
            if state.inputs.checkpoint_height == state.inputs.durable_head {
                next.phase = Phase::ReplayDone;
            } else {
                next.phase = Phase::Replaying;
            }
            Some(next)
        }
        _ => None,
    }
}

fn step_conversion_replay(state: &State, action: Action) -> Option<State> {
    if !matches!(action, Action::ReplayBlock | Action::MissingBlockDataAbort) {
        return None;
    }
    if !matches!(state.phase, Phase::Replaying)
        || state.inputs.checkpoint_height + state.replay_applied >= state.inputs.durable_head
    {
        return None;
    }

    let height = state.inputs.checkpoint_height + state.replay_applied + 1;
    match action {
        Action::ReplayBlock => {
            if !state.inputs.block_data_present[usize::from(height)] {
                return None;
            }
            let mut next = *state;
            next.dest_coins = state.inputs.oracle_coins(height);
            next.replay_applied += 1;
            next.phase = if height == state.inputs.durable_head {
                Phase::ReplayDone
            } else {
                Phase::Replaying
            };
            Some(next)
        }
        Action::MissingBlockDataAbort => {
            if state.inputs.block_data_present[usize::from(height)] {
                return None;
            }
            let mut next = *state;
            next.phase = Phase::Terminal;
            next.outcome = Outcome::MissingData { height };
            Some(next)
        }
        _ => None,
    }
}

fn step_conversion_publish(state: &State, action: Action) -> Option<State> {
    match action {
        Action::DeleteScratchSuccess => {
            if !matches!(state.phase, Phase::ReplayDone) || !state.required_files_durable {
                return None;
            }
            let mut next = *state;
            next.scratch_deleted = true;
            next.phase = Phase::RenamingMarker;
            Some(next)
        }
        Action::PublishMarkerRename => {
            if !matches!(state.phase, Phase::RenamingMarker)
                || state.verify_cursor != NUM_CELLS_U8
                || state.replay_position() != state.inputs.durable_head
                || !state.required_files_durable
                || !state.scratch_deleted
            {
                return None;
            }
            let mut next = *state;
            next.dest_marker = Some(MarkerClassification::CurrentEpoch6);
            next.phase = Phase::PublishedPendingSync;
            Some(next)
        }
        _ => None,
    }
}

fn step_final_sync(state: &State, action: Action) -> Option<State> {
    if !matches!(
        state.phase,
        Phase::PublishedPendingSync | Phase::NodeInitPendingSync
    ) {
        return None;
    }

    match action {
        Action::FinalSyncSuccess => {
            let mut next = *state;
            next.observed_final_sync = true;
            next.outcome = Outcome::Success;
            next.phase = Phase::Terminal;
            Some(next)
        }
        Action::FinalSyncFailure => {
            let mut next = *state;
            next.observed_final_sync = false;
            next.outcome = Outcome::PublicationUnknown;
            next.phase = Phase::Terminal;
            Some(next)
        }
        _ => None,
    }
}

// RCV-09
#[must_use]
pub fn step(state: &State, action: Action) -> State {
    if state.is_terminal() {
        return *state;
    }

    if let Some(next) = step_admission(state, action) {
        return next;
    }
    if let Some(next) = step_node_init(state, action) {
        return next;
    }
    if let Some(next) = step_conversion_copy(state, action) {
        return next;
    }
    if let Some(next) = step_conversion_verify(state, action) {
        return next;
    }
    if let Some(next) = step_conversion_ingest(state, action) {
        return next;
    }
    if let Some(next) = step_conversion_replay(state, action) {
        return next;
    }
    if let Some(next) = step_conversion_publish(state, action) {
        return next;
    }
    if let Some(next) = step_final_sync(state, action) {
        return next;
    }

    *state
}

fn is_source_contents_intact(state: &State) -> bool {
    state.source_contents == state.inputs.initial_source_contents
}

fn journal_is_never_copied(state: &State) -> bool {
    !state.journal_copied
}

fn is_terminal_coherent(state: &State) -> bool {
    (state.phase == Phase::Terminal) == !matches!(state.outcome, Outcome::Pending)
}

fn is_verified_prefix(dest: &[u8; NUM_CELLS], src: &[u8; NUM_CELLS], verify_cursor: u8) -> bool {
    match verify_cursor {
        0 => true,
        1 => dest[0] == src[0],
        2 => dest[0] == src[0] && dest[1] == src[1],
        3 => dest[0] == src[0] && dest[1] == src[1] && dest[2] == src[2],
        4 => dest == src,
        _ => false,
    }
}

fn is_node_admission_terminal_coherent(state: &State) -> bool {
    match state.outcome {
        Outcome::Refused => {
            state.inputs.source_marker != MarkerClassification::CurrentEpoch6
                && !(state.inputs.source_marker == MarkerClassification::Absent
                    && state.inputs.source_dir_empty)
                && state.source_marker == state.inputs.source_marker
                && !state.observed_final_sync
        }
        Outcome::PrepublicationFailure => {
            state.inputs.source_marker == MarkerClassification::Absent
                && state.inputs.source_dir_empty
                && state.source_marker == MarkerClassification::Absent
                && !state.observed_final_sync
        }
        Outcome::Success => {
            state.source_marker == MarkerClassification::CurrentEpoch6
                && if state.inputs.source_marker == MarkerClassification::CurrentEpoch6 {
                    !state.observed_final_sync
                } else if state.inputs.source_marker == MarkerClassification::Absent
                    && state.inputs.source_dir_empty
                {
                    state.observed_final_sync
                } else {
                    false
                }
        }
        Outcome::PublicationUnknown => {
            state.inputs.source_marker == MarkerClassification::Absent
                && state.inputs.source_dir_empty
                && state.source_marker == MarkerClassification::CurrentEpoch6
                && !state.observed_final_sync
        }
        Outcome::RefusedNoCheckpoint | Outcome::MissingData { .. } => false,
        Outcome::Pending => false,
    }
}

fn is_node_admission_coherent(state: &State) -> bool {
    if state.inputs.mode != Mode::NodeAdmission {
        return false;
    }

    if state.dest_marker.is_some()
        || state.dest_cells != [0; NUM_CELLS]
        || state.dest_coins != 0
        || state.copy_cursor != 0
        || state.verify_cursor != 0
        || state.replay_applied != 0
        || state.required_files_durable
        || state.scratch_deleted
        || state.journal_copied
    {
        return false;
    }

    match state.phase {
        Phase::Admission => {
            state.source_marker == state.inputs.source_marker && !state.observed_final_sync
        }
        Phase::NodeInitWritingTemp | Phase::NodeInitRenaming => {
            state.inputs.source_marker == MarkerClassification::Absent
                && state.inputs.source_dir_empty
                && state.source_marker == MarkerClassification::Absent
                && !state.observed_final_sync
        }
        Phase::NodeInitPendingSync => {
            state.inputs.source_marker == MarkerClassification::Absent
                && state.inputs.source_dir_empty
                && state.source_marker == MarkerClassification::CurrentEpoch6
                && !state.observed_final_sync
        }
        Phase::Terminal => is_node_admission_terminal_coherent(state),
        Phase::Copying
        | Phase::Verifying
        | Phase::CopyingRequiredFiles
        | Phase::IngestingCheckpoint
        | Phase::Replaying
        | Phase::ReplayDone
        | Phase::DeletingScratch
        | Phase::RenamingMarker
        | Phase::PublishedPendingSync => false,
    }
}

fn is_conversion_terminal_coherent(state: &State) -> bool {
    match state.outcome {
        Outcome::Refused => {
            state.dest_marker.is_none()
                && state.dest_cells == [0; NUM_CELLS]
                && state.dest_coins == 0
                && state.copy_cursor == 0
                && state.verify_cursor == 0
                && state.replay_applied == 0
                && !state.required_files_durable
                && !state.scratch_deleted
                && !state.journal_copied
                && !state.observed_final_sync
        }
        Outcome::RefusedNoCheckpoint => {
            !state.inputs.checkpoint_complete
                && state.source_marker.is_convertible()
                && state.inputs.dest_initially_empty
                && state.inputs.paths_disjoint
                && state.dest_marker.is_none()
                && state.dest_cells == [0; NUM_CELLS]
                && state.dest_coins == 0
                && state.copy_cursor == 0
                && state.verify_cursor == 0
                && state.replay_applied == 0
                && !state.required_files_durable
                && !state.scratch_deleted
                && !state.journal_copied
                && !state.observed_final_sync
        }
        Outcome::MissingData { height } => {
            let aborted_height = state.inputs.checkpoint_height + state.replay_applied + 1;
            state.inputs.checkpoint_height + state.replay_applied < state.inputs.durable_head
                && height == aborted_height
                && !state.inputs.block_data_present[usize::from(height)]
                && state.dest_marker.is_none()
                && !state.observed_final_sync
        }
        Outcome::PrepublicationFailure => {
            state.dest_marker.is_none()
                && !state.observed_final_sync
                && is_verified_prefix(
                    &state.dest_cells,
                    &state.source_contents,
                    state.verify_cursor,
                )
                && (!state.scratch_deleted || state.required_files_durable)
        }
        Outcome::PublicationUnknown => {
            state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_coins == state.inputs.oracle_coins(state.inputs.durable_head)
                && state.dest_marker == Some(MarkerClassification::CurrentEpoch6)
                && state.required_files_durable
                && state.scratch_deleted
                && state.replay_applied
                    == state.inputs.durable_head - state.inputs.checkpoint_height
                && !state.observed_final_sync
        }
        Outcome::Success => {
            state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_coins == state.inputs.oracle_coins(state.inputs.durable_head)
                && state.dest_marker == Some(MarkerClassification::CurrentEpoch6)
                && state.required_files_durable
                && state.scratch_deleted
                && state.replay_applied
                    == state.inputs.durable_head - state.inputs.checkpoint_height
                && state.observed_final_sync
        }
        Outcome::Pending => false,
    }
}

fn is_conversion_coherent(state: &State) -> bool {
    if state.inputs.mode != Mode::OfflineConversion {
        return false;
    }

    if state.source_marker != state.inputs.source_marker || !journal_is_never_copied(state) {
        return false;
    }

    match state.phase {
        Phase::NodeInitWritingTemp | Phase::NodeInitRenaming | Phase::NodeInitPendingSync => {
            return false;
        }
        _ => {}
    }

    if !state.inputs.is_well_formed() {
        return false;
    }

    let convertible_inputs = state.inputs.source_marker.is_convertible()
        && state.inputs.dest_initially_empty
        && state.inputs.paths_disjoint;
    if !convertible_inputs {
        let clean_dest = state.dest_marker.is_none()
            && state.dest_cells == [0; NUM_CELLS]
            && state.dest_coins == 0
            && state.copy_cursor == 0
            && state.verify_cursor == 0
            && state.replay_applied == 0
            && !state.required_files_durable
            && !state.scratch_deleted
            && !state.observed_final_sync;
        return clean_dest
            && match state.phase {
                Phase::Admission => matches!(state.outcome, Outcome::Pending),
                Phase::Terminal => matches!(state.outcome, Outcome::Refused),
                _ => false,
            };
    }

    if state.copy_cursor > NUM_CELLS_U8
        || state.verify_cursor > NUM_CELLS_U8
        || state.verify_cursor > state.copy_cursor
        || state.replay_applied > state.inputs.durable_head - state.inputs.checkpoint_height
    {
        return false;
    }

    let admitted_preconditions = state.inputs.dest_initially_empty
        && state.inputs.paths_disjoint
        && state.inputs.checkpoint_complete;
    let coins_verified = state.dest_coins == state.inputs.checkpoint_coins
        || state.dest_coins == state.inputs.oracle_coins(state.replay_position());

    match state.phase {
        Phase::Admission => {
            state.dest_marker.is_none()
                && state.dest_cells == [0; NUM_CELLS]
                && state.dest_coins == 0
                && state.copy_cursor == 0
                && state.verify_cursor == 0
                && state.replay_applied == 0
                && !state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::Copying => {
            admitted_preconditions
                && state.copy_cursor < NUM_CELLS_U8
                && state.verify_cursor == 0
                && state.dest_coins == 0
                && state.dest_marker.is_none()
                && !state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::Verifying => {
            admitted_preconditions
                && state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor < NUM_CELLS_U8
                && state.dest_coins == 0
                && is_verified_prefix(
                    &state.dest_cells,
                    &state.source_contents,
                    state.verify_cursor,
                )
                && state.dest_marker.is_none()
                && !state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::CopyingRequiredFiles => {
            admitted_preconditions
                && state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_coins == 0
                && state.dest_marker.is_none()
                && !state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::IngestingCheckpoint => {
            admitted_preconditions
                && state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_coins == 0
                && state.dest_marker.is_none()
                && state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::Replaying => {
            admitted_preconditions
                && coins_verified
                && state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_marker.is_none()
                && state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
                && state.inputs.checkpoint_height + state.replay_applied < state.inputs.durable_head
        }
        Phase::ReplayDone | Phase::DeletingScratch => {
            admitted_preconditions
                && state.dest_coins == state.inputs.oracle_coins(state.inputs.durable_head)
                && state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_marker.is_none()
                && state.required_files_durable
                && !state.observed_final_sync
                && state.replay_applied
                    == state.inputs.durable_head - state.inputs.checkpoint_height
                && (state.phase != Phase::DeletingScratch || state.scratch_deleted)
        }
        Phase::RenamingMarker => {
            admitted_preconditions
                && state.dest_coins == state.inputs.oracle_coins(state.inputs.durable_head)
                && state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_marker.is_none()
                && state.required_files_durable
                && state.scratch_deleted
                && !state.observed_final_sync
                && state.replay_applied
                    == state.inputs.durable_head - state.inputs.checkpoint_height
        }
        Phase::PublishedPendingSync => {
            admitted_preconditions
                && state.dest_coins == state.inputs.oracle_coins(state.inputs.durable_head)
                && state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_marker == Some(MarkerClassification::CurrentEpoch6)
                && state.required_files_durable
                && state.scratch_deleted
                && !state.observed_final_sync
                && state.replay_applied
                    == state.inputs.durable_head - state.inputs.checkpoint_height
        }
        Phase::Terminal => is_conversion_terminal_coherent(state),
        Phase::NodeInitWritingTemp | Phase::NodeInitRenaming | Phase::NodeInitPendingSync => false,
    }
}

// RCV-09, RCV-10
#[must_use]
pub fn safety(state: &State) -> bool {
    state.inputs.is_well_formed()
        && is_source_contents_intact(state)
        && journal_is_never_copied(state)
        && is_terminal_coherent(state)
        && match state.inputs.mode {
            Mode::NodeAdmission => is_node_admission_coherent(state),
            Mode::OfflineConversion => is_conversion_coherent(state),
        }
}

#[cfg(test)]
mod tests {
    use super::{
        Action, MarkerClassification, Mode, ModelInputs, NUM_CELLS, Outcome, Phase, State, safety,
        step,
    };

    fn converter_inputs(marker: MarkerClassification) -> ModelInputs {
        ModelInputs {
            mode: Mode::OfflineConversion,
            source_marker: marker,
            source_dir_empty: false,
            dest_initially_empty: true,
            paths_disjoint: true,
            initial_source_contents: [5, 6, 7, 8],
            checkpoint_height: 0,
            durable_head: 1,
            checkpoint_complete: true,
            block_data_present: [true, true],
            checkpoint_coins: 9,
            block_undo_delta: [9, 12],
        }
    }

    fn node_inputs(marker: MarkerClassification, dir_empty: bool) -> ModelInputs {
        ModelInputs {
            mode: Mode::NodeAdmission,
            source_marker: marker,
            source_dir_empty: dir_empty,
            dest_initially_empty: false,
            paths_disjoint: false,
            initial_source_contents: [10, 20, 30, 40],
            checkpoint_height: 0,
            durable_head: 1,
            checkpoint_complete: true,
            block_data_present: [true, true],
            checkpoint_coins: 9,
            block_undo_delta: [9, 12],
        }
    }

    fn copy_and_verify(mut s: State) -> State {
        for _ in 0..NUM_CELLS {
            s = step(&s, Action::CopyCell);
        }
        for _ in 0..NUM_CELLS {
            s = step(&s, Action::VerifyCell);
        }
        s
    }

    fn run_pipeline(mut s: State) -> State {
        s = step(&s, Action::ConvertAcceptAdmission);
        s = copy_and_verify(s);
        s = step(&s, Action::CopyRequiredFiles);
        s = step(&s, Action::LoadCheckpointCoins);
        s = step(&s, Action::ReplayBlock);
        s = step(&s, Action::DeleteScratchSuccess);
        s = step(&s, Action::PublishMarkerRename);
        s
    }

    fn state_at_stage(stage: Phase) -> State {
        let inputs = converter_inputs(MarkerClassification::RetiredEpoch3);
        let mut s = State::init(inputs);
        s = step(&s, Action::ConvertAcceptAdmission);
        if stage == Phase::Copying {
            return step(&s, Action::CopyCell);
        }
        for _ in 0..NUM_CELLS {
            s = step(&s, Action::CopyCell);
        }
        if stage == Phase::Verifying {
            return step(&s, Action::VerifyCell);
        }
        for _ in 0..NUM_CELLS {
            s = step(&s, Action::VerifyCell);
        }
        if stage == Phase::CopyingRequiredFiles {
            return s;
        }
        s = step(&s, Action::CopyRequiredFiles);
        if stage == Phase::IngestingCheckpoint {
            return s;
        }
        s = step(&s, Action::LoadCheckpointCoins);
        if stage == Phase::Replaying {
            return s;
        }
        s = step(&s, Action::ReplayBlock);
        if stage == Phase::ReplayDone {
            return s;
        }
        s = step(&s, Action::DeleteScratchSuccess);
        if stage == Phase::RenamingMarker {
            return s;
        }
        s = step(&s, Action::PublishMarkerRename);
        if stage == Phase::PublishedPendingSync {
            return s;
        }
        s
    }

    // RCV-09
    #[test]
    fn node_exact_current_opens_without_alteration() {
        let inputs = node_inputs(MarkerClassification::CurrentEpoch6, false);
        let s0 = State::init(inputs);
        assert!(safety(&s0));
        let s1 = step(&s0, Action::NodeOpenDirect);
        assert!(safety(&s1));
        assert_eq!(s1.outcome, Outcome::Success);
        assert!(s1.engine_opened());
        assert_eq!(s1.source_marker, MarkerClassification::CurrentEpoch6);
        assert_eq!(s1.source_contents, [10, 20, 30, 40]);
        assert_eq!(s1.dest_marker, None);
        assert!(!s1.observed_final_sync);
    }

    // RCV-09
    #[test]
    fn node_absent_empty_initializes_marker_and_opens() {
        let inputs = node_inputs(MarkerClassification::Absent, true);
        let s0 = State::init(inputs);
        assert!(safety(&s0));
        let s1 = step(&s0, Action::NodeInitStart);
        assert!(safety(&s1));
        assert_eq!(s1.phase, Phase::NodeInitWritingTemp);
        assert_eq!(s1.source_marker, MarkerClassification::Absent);

        let s2 = step(&s1, Action::NodeInitWriteTempSuccess);
        assert!(safety(&s2));
        assert_eq!(s2.phase, Phase::NodeInitRenaming);

        let s3 = step(&s2, Action::NodeInitRenameSuccess);
        assert!(safety(&s3));
        assert_eq!(s3.phase, Phase::NodeInitPendingSync);
        assert_eq!(s3.source_marker, MarkerClassification::CurrentEpoch6);
        assert!(!s3.engine_opened());

        let s4 = step(&s3, Action::FinalSyncSuccess);
        assert!(safety(&s4));
        assert_eq!(s4.outcome, Outcome::Success);
        assert!(s4.engine_opened());
        assert_eq!(s4.source_marker, MarkerClassification::CurrentEpoch6);
        assert_eq!(s4.source_contents, [10, 20, 30, 40]);
        assert!(s4.observed_final_sync);
    }

    // RCV-09
    #[test]
    fn node_absent_empty_init_fails_before_rename_prepublication_failure() {
        let inputs = node_inputs(MarkerClassification::Absent, true);
        let s0 = State::init(inputs);
        let s1 = step(&s0, Action::NodeInitStart);
        let s2 = step(&s1, Action::NodeInitWriteTempFailure);
        assert!(safety(&s2));
        assert_eq!(s2.outcome, Outcome::PrepublicationFailure);
        assert_eq!(s2.source_marker, MarkerClassification::Absent);
        assert!(!s2.engine_opened());
        assert!(!s2.observed_final_sync);
    }

    // RCV-09
    #[test]
    fn node_absent_empty_init_rename_failure_prepublication_failure() {
        let inputs = node_inputs(MarkerClassification::Absent, true);
        let s0 = State::init(inputs);
        let s1 = step(&s0, Action::NodeInitStart);
        let s2 = step(&s1, Action::NodeInitWriteTempSuccess);
        let s3 = step(&s2, Action::NodeInitRenameFailure);
        assert!(safety(&s3));
        assert_eq!(s3.outcome, Outcome::PrepublicationFailure);
        assert_eq!(s3.source_marker, MarkerClassification::Absent);
        assert!(!s3.engine_opened());
    }

    // RCV-09
    #[test]
    fn node_absent_empty_final_sync_fails_after_rename_publication_unknown() {
        let inputs = node_inputs(MarkerClassification::Absent, true);
        let s0 = State::init(inputs);
        let s1 = step(&s0, Action::NodeInitStart);
        let s2 = step(&s1, Action::NodeInitWriteTempSuccess);
        let s3 = step(&s2, Action::NodeInitRenameSuccess);
        let s4 = step(&s3, Action::FinalSyncFailure);
        assert!(safety(&s4));
        assert_eq!(s4.outcome, Outcome::PublicationUnknown);
        assert_eq!(s4.source_marker, MarkerClassification::CurrentEpoch6);
        assert!(!s4.engine_opened());
        assert!(!s4.observed_final_sync);
    }

    // RCV-09
    #[test]
    fn node_refuses_all_non_current_marker_classes() {
        let non_current_cases = [
            (MarkerClassification::Absent, false),
            (MarkerClassification::Malformed, true),
            (MarkerClassification::Malformed, false),
            (MarkerClassification::RetiredEpoch3, true),
            (MarkerClassification::RetiredEpoch3, false),
            (MarkerClassification::RetiredEpoch4, true),
            (MarkerClassification::RetiredEpoch4, false),
            (MarkerClassification::RetiredEpoch5, true),
            (MarkerClassification::RetiredEpoch5, false),
            (MarkerClassification::FutureEpoch, true),
            (MarkerClassification::FutureEpoch, false),
        ];

        for (marker, empty) in non_current_cases {
            assert!(marker.refusal_names_converter());
            let inputs = node_inputs(marker, empty);
            let s0 = State::init(inputs);
            assert!(safety(&s0));
            let s1 = step(&s0, Action::RejectAdmission);
            assert!(safety(&s1));
            assert_eq!(s1.outcome, Outcome::Refused);
            assert_eq!(s1.source_marker, marker);
            assert_eq!(s1.source_contents, [10, 20, 30, 40]);
            assert!(!s1.engine_opened());
            assert!(!marker.is_current());
        }

        assert!(MarkerClassification::CurrentEpoch6.is_current());
        assert!(!MarkerClassification::CurrentEpoch6.refusal_names_converter());
    }

    #[test]
    fn node_out_of_turn_actions_stutter() {
        let inputs = node_inputs(MarkerClassification::CurrentEpoch6, false);
        let s0 = State::init(inputs);
        let s1 = step(&s0, Action::ConvertAcceptAdmission);
        assert_eq!(s0, s1);
        let s2 = step(&s0, Action::CopyCell);
        assert_eq!(s0, s2);
        let s3 = step(&s0, Action::PublishMarkerRename);
        assert_eq!(s0, s3);
        let s4 = step(&s0, Action::RejectAdmission);
        assert_eq!(s0, s4);
        let s5 = step(&s0, Action::NodeInitStart);
        assert_eq!(s0, s5);
    }

    // RCV-09
    #[test]
    fn converter_refuses_path_collision() {
        let inputs = ModelInputs {
            paths_disjoint: false,
            ..converter_inputs(MarkerClassification::RetiredEpoch3)
        };
        let s0 = State::init(inputs);
        assert!(safety(&s0));
        let s1 = step(&s0, Action::RejectAdmission);
        assert!(safety(&s1));
        assert_eq!(s1.outcome, Outcome::Refused);
        assert_eq!(s1.dest_marker, None);
        assert_eq!(s1.dest_cells, [0; NUM_CELLS]);
        assert_eq!(s1.copy_cursor, 0);
    }

    // RCV-09
    #[test]
    fn converter_refuses_destination_nonempty() {
        let inputs = ModelInputs {
            dest_initially_empty: false,
            ..converter_inputs(MarkerClassification::RetiredEpoch3)
        };
        let s0 = State::init(inputs);
        assert!(safety(&s0));
        let s1 = step(&s0, Action::RejectAdmission);
        assert!(safety(&s1));
        assert_eq!(s1.outcome, Outcome::Refused);
        assert_eq!(s1.dest_marker, None);
        assert_eq!(s1.dest_cells, [0; NUM_CELLS]);
        assert_eq!(s1.copy_cursor, 0);
    }

    // RCV-09
    #[test]
    fn converter_refuses_non_convertible_markers() {
        let non_convertible = [
            MarkerClassification::Absent,
            MarkerClassification::Malformed,
            MarkerClassification::FutureEpoch,
        ];
        for marker in non_convertible {
            assert!(!marker.is_convertible());
            let inputs = converter_inputs(marker);
            let s0 = State::init(inputs);
            assert!(safety(&s0));
            let s1 = step(&s0, Action::RejectAdmission);
            assert!(safety(&s1));
            assert_eq!(s1.outcome, Outcome::Refused);
            assert_eq!(s1.dest_marker, None);
            assert_eq!(s1.dest_cells, [0; NUM_CELLS]);
        }

        assert!(MarkerClassification::RetiredEpoch3.is_convertible());
        assert!(MarkerClassification::RetiredEpoch4.is_convertible());
        assert!(MarkerClassification::RetiredEpoch5.is_convertible());
        assert!(MarkerClassification::CurrentEpoch6.is_convertible());
    }

    // RCV-09, RCV-10
    #[test]
    fn converter_refuses_missing_checkpoint_before_writes() {
        let inputs = ModelInputs {
            checkpoint_complete: false,
            ..converter_inputs(MarkerClassification::RetiredEpoch3)
        };
        let s0 = State::init(inputs);
        assert!(safety(&s0));
        let s1 = step(&s0, Action::RefuseMissingCheckpoint);
        assert!(safety(&s1));
        assert_eq!(s1.outcome, Outcome::RefusedNoCheckpoint);
        assert_eq!(s1.source_marker, MarkerClassification::RetiredEpoch3);
        assert_eq!(s1.dest_marker, None);
        assert_eq!(s1.dest_cells, [0; NUM_CELLS]);
        assert_eq!(s1.dest_coins, 0);
        assert_eq!(s1.copy_cursor, 0);
        assert_eq!(s1.verify_cursor, 0);
        assert!(!s1.required_files_durable);
        assert!(!s1.scratch_deleted);
        assert!(!s1.journal_copied);
        assert!(!s1.observed_final_sync);
        let s2 = step(&s1, Action::ConvertAcceptAdmission);
        assert_eq!(s1, s2);
    }

    // RCV-09
    #[test]
    fn converter_corruption_at_every_cell() {
        for corrupt_idx in 0..NUM_CELLS {
            let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
            assert!(safety(&s));
            s = step(&s, Action::ConvertAcceptAdmission);
            assert!(safety(&s));

            for cell in 0..NUM_CELLS {
                if cell == corrupt_idx {
                    s = step(&s, Action::CorruptCopyCell(99));
                } else {
                    s = step(&s, Action::CopyCell);
                }
                assert!(safety(&s));
            }
            assert_eq!(s.phase, Phase::Verifying);

            for _ in 0..corrupt_idx {
                s = step(&s, Action::VerifyCell);
                assert!(safety(&s));
                assert_eq!(s.phase, Phase::Verifying);
            }

            s = step(&s, Action::VerifyCell);
            assert!(safety(&s));
            assert_eq!(s.outcome, Outcome::PrepublicationFailure);
            assert_eq!(s.dest_marker, None);
            assert!(!s.has_success_receipt());
        }
    }

    // RCV-09
    #[test]
    fn converter_prepublication_io_failures() {
        let failure_stages = [
            Phase::Copying,
            Phase::Verifying,
            Phase::CopyingRequiredFiles,
            Phase::IngestingCheckpoint,
            Phase::Replaying,
            Phase::ReplayDone,
            Phase::RenamingMarker,
        ];

        for stage in failure_stages {
            let mut s = state_at_stage(stage);
            assert_eq!(s.phase, stage);
            s = step(&s, Action::PrepubIoFailure);
            assert!(safety(&s));
            assert_eq!(s.outcome, Outcome::PrepublicationFailure);
            assert_eq!(s.dest_marker, None);
            assert!(!s.has_success_receipt());
            assert!(!s.observed_final_sync);
        }
    }

    // RCV-09, RCV-10
    #[test]
    fn converter_final_sync_ambiguity() {
        let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
        s = run_pipeline(s);
        assert_eq!(s.phase, Phase::PublishedPendingSync);
        assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
        assert_eq!(s.dest_coins, 12);
        assert!(safety(&s));

        s = step(&s, Action::FinalSyncFailure);
        assert!(safety(&s));
        assert_eq!(s.outcome, Outcome::PublicationUnknown);
        assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
        assert_eq!(s.dest_cells, [5, 6, 7, 8]);
        assert_eq!(s.dest_coins, 12);
        assert!(s.required_files_durable);
        assert!(s.scratch_deleted);
        assert!(!s.has_success_receipt());
        assert!(!s.observed_final_sync);
    }

    // RCV-09, RCV-10
    #[test]
    fn converter_successful_current_epoch_copy() {
        let mut s = State::init(converter_inputs(MarkerClassification::CurrentEpoch6));
        assert!(safety(&s));
        s = run_pipeline(s);
        s = step(&s, Action::FinalSyncSuccess);

        assert!(safety(&s));
        assert_eq!(s.outcome, Outcome::Success);
        assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
        assert_eq!(s.dest_cells, [5, 6, 7, 8]);
        assert_eq!(s.dest_coins, 12);
        assert!(s.required_files_durable);
        assert!(s.scratch_deleted);
        assert!(!s.journal_copied);
        assert!(s.has_success_receipt());
        assert!(s.observed_final_sync);
        assert_eq!(s.source_contents, [5, 6, 7, 8]);
        assert_eq!(s.source_marker, MarkerClassification::CurrentEpoch6);
        assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.inputs.durable_head));
    }

    // RCV-09, RCV-10
    #[test]
    fn converter_successful_retired_epoch3_migration() {
        let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
        assert!(safety(&s));
        s = run_pipeline(s);
        s = step(&s, Action::FinalSyncSuccess);

        assert!(safety(&s));
        assert_eq!(s.outcome, Outcome::Success);
        assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
        assert_eq!(s.dest_cells, [5, 6, 7, 8]);
        assert!(s.required_files_durable);
        assert!(s.scratch_deleted);
        assert!(s.has_success_receipt());
        assert!(s.observed_final_sync);
        assert_eq!(s.source_marker, MarkerClassification::RetiredEpoch3);
        assert_eq!(s.source_contents, [5, 6, 7, 8]);
    }
    // RCV-09, RCV-10
    #[test]
    fn converter_successful_retired_epoch5_migration() {
        let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch5));
        assert!(safety(&s));
        s = run_pipeline(s);
        s = step(&s, Action::FinalSyncSuccess);
        assert!(safety(&s));
        assert_eq!(s.outcome, Outcome::Success);
        assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
        assert_eq!(s.dest_cells, [5, 6, 7, 8]);
        assert!(s.required_files_durable);
        assert!(s.scratch_deleted);
        assert!(s.has_success_receipt());
        assert!(s.observed_final_sync);
        assert_eq!(s.source_marker, MarkerClassification::RetiredEpoch5);
        assert_eq!(s.source_contents, [5, 6, 7, 8]);
    }

    // RCV-10
    #[test]
    fn replayed_coins_follow_the_oracle_from_ingest_through_publish() {
        let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
        s = step(&s, Action::ConvertAcceptAdmission);
        s = copy_and_verify(s);
        s = step(&s, Action::CopyRequiredFiles);

        s = step(&s, Action::LoadCheckpointCoins);
        assert!(safety(&s));
        assert_eq!(s.phase, Phase::Replaying);
        assert_eq!(s.dest_coins, s.inputs.checkpoint_coins);
        assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.replay_position()));
        assert_eq!(s.replay_applied, 0);

        s = step(&s, Action::ReplayBlock);
        assert!(safety(&s));
        assert_eq!(s.phase, Phase::ReplayDone);
        assert_eq!(s.dest_coins, s.inputs.oracle_coins(1));
        assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.replay_position()));

        s = step(&s, Action::DeleteScratchSuccess);
        s = step(&s, Action::PublishMarkerRename);
        assert!(safety(&s));
        assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.inputs.durable_head));
    }

    // RCV-10
    #[test]
    fn checkpoint_at_head_ingests_without_replay() {
        let inputs = ModelInputs {
            checkpoint_height: 1,
            durable_head: 1,
            block_data_present: [true, true],
            checkpoint_coins: 9,
            block_undo_delta: [9, 9],
            ..converter_inputs(MarkerClassification::RetiredEpoch3)
        };
        let mut s = State::init(inputs);
        assert!(safety(&s));
        assert_eq!(s.inputs.oracle_coins(1), 9);
        s = step(&s, Action::ConvertAcceptAdmission);
        s = copy_and_verify(s);
        s = step(&s, Action::CopyRequiredFiles);
        s = step(&s, Action::LoadCheckpointCoins);
        assert!(safety(&s));
        assert_eq!(s.phase, Phase::ReplayDone);
        assert_eq!(s.dest_coins, 9);
        assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.inputs.durable_head));
        assert_eq!(s.replay_applied, 0);

        let s_before = s;
        s = step(&s, Action::ReplayBlock);
        assert_eq!(s, s_before);
        s = step(&s, Action::DeleteScratchSuccess);
        s = step(&s, Action::PublishMarkerRename);
        s = step(&s, Action::FinalSyncSuccess);
        assert!(safety(&s));
        assert_eq!(s.outcome, Outcome::Success);
        assert_eq!(s.dest_coins, s.inputs.oracle_coins(s.inputs.durable_head));
    }

    // RCV-10
    #[test]
    fn missing_block_data_aborts_before_publication() {
        let inputs = ModelInputs {
            block_data_present: [true, false],
            ..converter_inputs(MarkerClassification::RetiredEpoch3)
        };
        let mut s = State::init(inputs);
        assert!(safety(&s));
        s = step(&s, Action::ConvertAcceptAdmission);
        s = copy_and_verify(s);
        s = step(&s, Action::CopyRequiredFiles);
        s = step(&s, Action::LoadCheckpointCoins);
        assert_eq!(s.phase, Phase::Replaying);

        let stutter = step(&s, Action::ReplayBlock);
        assert_eq!(s, stutter);

        s = step(&s, Action::MissingBlockDataAbort);
        assert!(safety(&s));
        assert_eq!(s.outcome, Outcome::MissingData { height: 1 });
        assert_eq!(s.dest_marker, None);
        assert!(!s.observed_final_sync);
        assert!(!s.has_success_receipt());
        assert_eq!(s.dest_cells, [5, 6, 7, 8]);
        for action in Action::ALL {
            assert_eq!(step(&s, action), s);
        }
    }

    // RCV-10
    #[test]
    fn journal_is_never_copied() {
        let mut s = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
        assert!(safety(&s));
        assert!(!s.journal_copied);
        s = step(&s, Action::ConvertAcceptAdmission);
        s = copy_and_verify(s);
        s = step(&s, Action::CopyRequiredFiles);
        assert!(s.required_files_durable);
        assert!(!s.journal_copied);
        assert!(safety(&s));
        s = step(&s, Action::LoadCheckpointCoins);
        s = step(&s, Action::ReplayBlock);
        s = step(&s, Action::DeleteScratchSuccess);
        s = step(&s, Action::PublishMarkerRename);
        s = step(&s, Action::FinalSyncSuccess);
        assert!(safety(&s));
        assert_eq!(s.outcome, Outcome::Success);
        assert!(!s.journal_copied);
        for action in Action::ALL {
            assert!(!step(&s, action).journal_copied);
        }
    }

    // RCV-09, RCV-10
    #[test]
    fn terminal_outcomes_absorb_all_actions() {
        let mut s = State::init(converter_inputs(MarkerClassification::CurrentEpoch6));
        s = run_pipeline(s);
        s = step(&s, Action::FinalSyncSuccess);
        assert!(s.is_terminal());

        for action in Action::ALL {
            let next = step(&s, action);
            assert_eq!(next, s);
        }
    }

    #[test]
    fn invalid_actions_stutter() {
        let s0 = State::init(converter_inputs(MarkerClassification::RetiredEpoch3));
        let s1 = step(&s0, Action::PublishMarkerRename);
        assert_eq!(s0, s1);
        let s2 = step(&s0, Action::DeleteScratchSuccess);
        assert_eq!(s0, s2);
        let s3 = step(&s0, Action::CopyRequiredFiles);
        assert_eq!(s0, s3);
        let s4 = step(&s0, Action::LoadCheckpointCoins);
        assert_eq!(s0, s4);
        let s5 = step(&s0, Action::ReplayBlock);
        assert_eq!(s0, s5);
        let s6 = step(&s0, Action::MissingBlockDataAbort);
        assert_eq!(s0, s6);
        let s7 = step(&s0, Action::FinalSyncSuccess);
        assert_eq!(s0, s7);
        let s8 = step(&s0, Action::FinalSyncFailure);
        assert_eq!(s0, s8);
        let s9 = step(&s0, Action::Stutter);
        assert_eq!(s0, s9);
    }

    // RCV-09
    #[test]
    fn empty_namespaces_representable_by_content_identity() {
        let inputs = ModelInputs {
            initial_source_contents: [0, 42, 0, 99],
            ..converter_inputs(MarkerClassification::CurrentEpoch6)
        };
        let mut s = State::init(inputs);
        s = run_pipeline(s);
        s = step(&s, Action::FinalSyncSuccess);

        assert_eq!(s.outcome, Outcome::Success);
        assert_eq!(s.dest_cells, [0, 42, 0, 99]);
        assert_eq!(s.dest_marker, Some(MarkerClassification::CurrentEpoch6));
    }
}
