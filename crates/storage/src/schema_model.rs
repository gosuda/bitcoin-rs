//! Executable reference model for schema epoch 4 admission and offline conversion.
//!
//! Models the lifecycle of node datadir schema verification and the converter step
//! `3 -> 4` targeting storage epoch 4 (with epoch 3 retired) per RCV-09 and RCV-10.
//! Epoch 4 places coins in the engine `coins` keyspace, deletes the
//! journal, and removes the utxo v4 checkpoint coin image as a resident
//! authority. Live storage (`checkpoint::fs`) remains at schema epoch 4; this is a
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
    /// Datadir schema epoch 4 (current epoch; engine `coins` keyspace).
    CurrentEpoch4,
    /// Future schema epoch not recognized by this version.
    FutureEpoch,
}

impl MarkerClassification {
    #[must_use]
    pub const fn is_current(self) -> bool {
        matches!(self, Self::CurrentEpoch4)
    }

    #[must_use]
    pub const fn is_convertible(self) -> bool {
        matches!(self, Self::RetiredEpoch3 | Self::CurrentEpoch4)
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
            next.source_marker = MarkerClassification::CurrentEpoch4;
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
            next.dest_marker = Some(MarkerClassification::CurrentEpoch4);
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
            state.inputs.source_marker != MarkerClassification::CurrentEpoch4
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
            state.source_marker == MarkerClassification::CurrentEpoch4
                && if state.inputs.source_marker == MarkerClassification::CurrentEpoch4 {
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
                && state.source_marker == MarkerClassification::CurrentEpoch4
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
                && state.source_marker == MarkerClassification::CurrentEpoch4
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
                && state.dest_marker == Some(MarkerClassification::CurrentEpoch4)
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
                && state.dest_marker == Some(MarkerClassification::CurrentEpoch4)
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
                && state.dest_marker == Some(MarkerClassification::CurrentEpoch4)
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
mod tests;
