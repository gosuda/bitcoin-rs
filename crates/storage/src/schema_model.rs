//! Executable reference model for schema admission and offline conversion.
//!
//! Models the lifecycle of node datadir schema verification and offline
//! conversion for implemented live storage epoch 3 (with epoch 2 retired) per RCV-09.
//! These files specify epoch3 schema admission/conversion safety independently;
//! they do not establish implementation refinement or physical filesystem durability.

#[cfg(kani)]
mod proofs;

pub const NUM_CELLS: usize = 4;
pub const NUM_CELLS_U8: u8 = 4;

/// Classification of a CURRENT_SCHEMA marker file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkerClassification {
    /// No CURRENT_SCHEMA file present in directory.
    Absent,
    /// Marker file is present but contains invalid data or corrupt formatting.
    Malformed,
    /// Datadir schema epoch 2 (retired epoch).
    RetiredEpoch2,
    /// Datadir schema epoch 3 (current epoch).
    CurrentEpoch3,
    /// Future schema epoch not recognized by this version.
    FutureEpoch,
}

impl MarkerClassification {
    #[must_use]
    pub const fn is_current(self) -> bool {
        matches!(self, Self::CurrentEpoch3)
    }

    #[must_use]
    pub const fn is_convertible(self) -> bool {
        matches!(self, Self::RetiredEpoch2 | Self::CurrentEpoch3)
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
}

/// Lifecycle progression phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Admission,
    Copying,
    Verifying,
    SyncingRequiredFiles,
    DeletingScratch,
    RenamingMarker,
    PublishedPendingSync,
    NodeInitWritingTemp,
    NodeInitRenaming,
    NodeInitPendingSync,
    Terminal,
}

/// High-level outcome of lifecycle execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pending,
    Refused,
    PrepublicationFailure,
    PublicationUnknown,
    Success,
}

/// Discrete transition actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    RejectAdmission,
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
    SyncRequiredFilesSuccess,
    DeleteScratchSuccess,
    PublishMarkerRename,
    FinalSyncSuccess,
    FinalSyncFailure,
    Stutter,
}

impl Action {
    pub const ALL: [Self; 18] = [
        Self::RejectAdmission,
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
        Self::SyncRequiredFilesSuccess,
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
    pub dest_marker: Option<MarkerClassification>,
    pub phase: Phase,
    pub outcome: Outcome,
    pub copy_cursor: u8,
    pub verify_cursor: u8,
    pub required_files_durable: bool,
    pub scratch_deleted: bool,
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
            dest_marker: None,
            phase: Phase::Admission,
            outcome: Outcome::Pending,
            copy_cursor: 0,
            verify_cursor: 0,
            required_files_durable: false,
            scratch_deleted: false,
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
        Action::ConvertAcceptAdmission => {
            if !matches!(state.inputs.mode, Mode::OfflineConversion)
                || !state.source_marker.is_convertible()
                || !state.inputs.dest_initially_empty
                || !state.inputs.paths_disjoint
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
            next.source_marker = MarkerClassification::CurrentEpoch3;
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
            next.phase = Phase::SyncingRequiredFiles;
        }
    } else {
        next.phase = Phase::Terminal;
        next.outcome = Outcome::PrepublicationFailure;
    }
    Some(next)
}

fn step_conversion_publish(state: &State, action: Action) -> Option<State> {
    match action {
        Action::PrepubIoFailure => {
            if !matches!(
                state.phase,
                Phase::Copying
                    | Phase::Verifying
                    | Phase::SyncingRequiredFiles
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
        Action::SyncRequiredFilesSuccess => {
            if !matches!(state.phase, Phase::SyncingRequiredFiles)
                || state.verify_cursor != NUM_CELLS_U8
            {
                return None;
            }
            let mut next = *state;
            next.required_files_durable = true;
            next.phase = Phase::DeletingScratch;
            Some(next)
        }
        Action::DeleteScratchSuccess => {
            if !matches!(state.phase, Phase::DeletingScratch) || !state.required_files_durable {
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
                || !state.required_files_durable
                || !state.scratch_deleted
            {
                return None;
            }
            let mut next = *state;
            next.dest_marker = Some(MarkerClassification::CurrentEpoch3);
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

fn is_terminal_coherent(state: &State) -> bool {
    (state.phase == Phase::Terminal) == (state.outcome != Outcome::Pending)
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
            state.inputs.source_marker != MarkerClassification::CurrentEpoch3
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
            state.source_marker == MarkerClassification::CurrentEpoch3
                && if state.inputs.source_marker == MarkerClassification::CurrentEpoch3 {
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
                && state.source_marker == MarkerClassification::CurrentEpoch3
                && !state.observed_final_sync
        }
        Outcome::Pending => false,
    }
}

fn is_node_admission_coherent(state: &State) -> bool {
    if state.inputs.mode != Mode::NodeAdmission {
        return false;
    }

    if state.dest_marker.is_some()
        || state.dest_cells != [0; NUM_CELLS]
        || state.copy_cursor != 0
        || state.verify_cursor != 0
        || state.required_files_durable
        || state.scratch_deleted
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
                && state.source_marker == MarkerClassification::CurrentEpoch3
                && !state.observed_final_sync
        }
        Phase::Terminal => is_node_admission_terminal_coherent(state),
        Phase::Copying
        | Phase::Verifying
        | Phase::SyncingRequiredFiles
        | Phase::DeletingScratch
        | Phase::RenamingMarker
        | Phase::PublishedPendingSync => false,
    }
}

fn is_conversion_terminal_coherent(state: &State) -> bool {
    match state.outcome {
        Outcome::Refused => false,
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
                && state.dest_marker == Some(MarkerClassification::CurrentEpoch3)
                && state.required_files_durable
                && state.scratch_deleted
                && !state.observed_final_sync
        }
        Outcome::Success => {
            state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_marker == Some(MarkerClassification::CurrentEpoch3)
                && state.required_files_durable
                && state.scratch_deleted
                && state.observed_final_sync
        }
        Outcome::Pending => false,
    }
}

fn is_conversion_coherent(state: &State) -> bool {
    if state.inputs.mode != Mode::OfflineConversion {
        return false;
    }

    if state.source_marker != state.inputs.source_marker {
        return false;
    }

    match state.phase {
        Phase::NodeInitWritingTemp | Phase::NodeInitRenaming | Phase::NodeInitPendingSync => {
            return false;
        }
        _ => {}
    }

    let convertible_inputs = state.inputs.source_marker.is_convertible()
        && state.inputs.dest_initially_empty
        && state.inputs.paths_disjoint;
    if !convertible_inputs {
        let clean_dest = state.dest_marker.is_none()
            && state.dest_cells == [0; NUM_CELLS]
            && state.copy_cursor == 0
            && state.verify_cursor == 0
            && !state.required_files_durable
            && !state.scratch_deleted
            && !state.observed_final_sync;
        return clean_dest
            && match state.phase {
                Phase::Admission => state.outcome == Outcome::Pending,
                Phase::Terminal => state.outcome == Outcome::Refused,
                _ => false,
            };
    }

    if state.copy_cursor > NUM_CELLS_U8
        || state.verify_cursor > NUM_CELLS_U8
        || state.verify_cursor > state.copy_cursor
    {
        return false;
    }

    match state.phase {
        Phase::Admission => {
            state.dest_marker.is_none()
                && state.dest_cells == [0; NUM_CELLS]
                && state.copy_cursor == 0
                && state.verify_cursor == 0
                && !state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::Copying => {
            state.copy_cursor < NUM_CELLS_U8
                && state.verify_cursor == 0
                && state.dest_marker.is_none()
                && !state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::Verifying => {
            state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor < NUM_CELLS_U8
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
        Phase::SyncingRequiredFiles => {
            state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_marker.is_none()
                && !state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::DeletingScratch => {
            state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_marker.is_none()
                && state.required_files_durable
                && !state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::RenamingMarker => {
            state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_marker.is_none()
                && state.required_files_durable
                && state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::PublishedPendingSync => {
            state.copy_cursor == NUM_CELLS_U8
                && state.verify_cursor == NUM_CELLS_U8
                && state.dest_cells == state.source_contents
                && state.dest_marker == Some(MarkerClassification::CurrentEpoch3)
                && state.required_files_durable
                && state.scratch_deleted
                && !state.observed_final_sync
        }
        Phase::Terminal => is_conversion_terminal_coherent(state),
        Phase::NodeInitWritingTemp | Phase::NodeInitRenaming | Phase::NodeInitPendingSync => false,
    }
}

// RCV-09
#[must_use]
pub fn safety(state: &State) -> bool {
    is_source_contents_intact(state)
        && is_terminal_coherent(state)
        && match state.inputs.mode {
            Mode::NodeAdmission => is_node_admission_coherent(state),
            Mode::OfflineConversion => is_conversion_coherent(state),
        }
}

#[cfg(test)]
mod tests;
