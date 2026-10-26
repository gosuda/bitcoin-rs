//! Node-owned bounded snapshot import, coherent export, and fenced consumer
//! reconciliation.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bitcoin_rs_chain::LatchReader;
use bitcoin_rs_chainstate::{
    ApplyError, AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager, Chainstate,
    ChainstateRole,
};
use bitcoin_rs_primitives::{Hash256, Network};
use bitcoin_rs_rpc::context::{
    ChainstateInfo, ChainstatesInfo, SnapshotControlError, SnapshotExport, SnapshotImport,
};
use bitcoin_rs_storage::checkpoint::fs::{HAS_ATOMIC_NOREPLACE_RENAME, rename_noreplace};
use bitcoin_rs_storage::checkpoint::{create_file, open_data_dir, sync_dir};
use bitcoin_rs_utxo::core_snapshot::{
    CoreV2WriteReport, SnapshotError, SnapshotLimits, read_verified, write_core_v2,
};
use bitcoin_rs_utxo::{SeedOfferCell, SeedProvenance, V4Witness, VerifiedSnapshotArtifact};
use parking_lot::Mutex;

use crate::chain_effects::ChainFollowers;

/// Bytes buffered between the encoder and the output file.
const EXPORT_BUFFER_BYTES: usize = 64 * 1024;

/// The import budget and activation effects shared by embedding and RPC.
pub(crate) struct SnapshotControl {
    pub(crate) manager: Arc<AssumeUtxoManager>,
    chainstate: Arc<Chainstate>,
    followers: ChainFollowers,
    data_dir: PathBuf,
    network: Network,
    // Post-start ScriptLive seed demand. `None` when ScriptLive is disabled at
    // composition time; the cell itself is worker-owned demand shared with the
    // publisher and the worker spec. This handle never mints, only offers.
    seed_offer: Option<SeedOfferCell>,
    // One imported UTXO set may be materialized at a time. This is a resource
    // permit, not a second lifecycle state. No chain write lock spans decoding.
    import: Mutex<()>,
    // One export may wait for chain-transition exclusion and hold it while it
    // encodes. A second request is refused rather than queued behind it.
    export: Mutex<()>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SnapshotExportError {
    #[error("another snapshot export is in progress")]
    ExportInProgress,
    #[error("Snapshot export interrupted")]
    Interrupted,
    #[error("snapshot output path needs a final UTF-8 file name")]
    OutputName,
    #[error("could not prepare snapshot output: {0}")]
    Output(std::io::Error),
    #[error(
        "{0} already exists. If you are sure this is what you want, move it out of the way first"
    )]
    Exists(String),
    #[error("snapshot output cannot be in the node's snapshot recovery namespace")]
    RecoveryOutput,
    #[error("this platform has no atomic no-replace rename, so a snapshot cannot be published")]
    NoAtomicPublish,
    #[error("chain is not accepting a snapshot export: {0}")]
    Admission(#[from] ApplyError),
    #[error("no applied tip to export")]
    NoAppliedTip,
    #[error("the applied tip has no established chain transaction count")]
    ChainTxCountUnknown,
    #[error("could not encode snapshot: {0}")]
    Codec(#[from] SnapshotError),
    #[error("could not write snapshot: {0}")]
    Write(std::io::Error),
    #[error("snapshot file holds {actual} bytes but the encoder wrote {expected}")]
    Length { expected: u64, actual: u64 },
    #[error("snapshot was published but its directory entry could not be made durable: {0}")]
    DirectorySync(std::io::Error),
}

impl From<SnapshotExportError> for SnapshotControlError {
    fn from(error: SnapshotExportError) -> Self {
        match error {
            SnapshotExportError::Interrupted
            | SnapshotExportError::Codec(SnapshotError::Interrupted) => Self::Interrupted,
            SnapshotExportError::OutputName
            | SnapshotExportError::Output(_)
            | SnapshotExportError::Exists(_)
            | SnapshotExportError::RecoveryOutput => Self::File(error.to_string()),
            SnapshotExportError::ExportInProgress
            | SnapshotExportError::NoAtomicPublish
            | SnapshotExportError::Admission(_)
            | SnapshotExportError::NoAppliedTip
            | SnapshotExportError::ChainTxCountUnknown => Self::Unavailable(error.to_string()),
            SnapshotExportError::Codec(_)
            | SnapshotExportError::Write(_)
            | SnapshotExportError::Length { .. }
            | SnapshotExportError::DirectorySync(_) => Self::Failed(error.to_string()),
        }
    }
}

/// A resolved output: the capability for its directory and the names in it.
struct ExportTarget {
    dir: cap_std::fs::Dir,
    name: String,
    temp: String,
    path: PathBuf,
}

/// Removes the staged file unless it was published, so every error,
/// interruption and panic path leaves no partial snapshot behind.
struct StagedFile<'a> {
    dir: &'a cap_std::fs::Dir,
    name: &'a str,
    published: bool,
}

impl<'a> StagedFile<'a> {
    fn create(
        dir: &'a cap_std::fs::Dir,
        name: &'a str,
    ) -> std::io::Result<(Self, cap_std::fs::File)> {
        let file = create_file(dir, name)?;
        Ok((
            Self {
                dir,
                name,
                published: false,
            },
            file,
        ))
    }

    fn published(mut self) {
        self.published = true;
    }
}

impl Drop for StagedFile<'_> {
    fn drop(&mut self) {
        if !self.published
            && let Err(error) = self.dir.remove_file(self.name)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(file = self.name, %error, "could not remove unpublished snapshot export");
        }
    }
}

/// What one locked encode certifies about the snapshot it wrote.
struct Encoded {
    report: CoreV2WriteReport,
    base_hash: Hash256,
    base_height: u32,
    nchaintx: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SnapshotImportError {
    #[error("could not read snapshot: {0}")]
    File(#[from] std::io::Error),
    #[error("snapshot input must be a regular file")]
    NotRegular,
    #[error("another snapshot import is in progress")]
    ImportInProgress,
    #[error("snapshot activation requires an empty mempool")]
    MempoolNotEmpty,
    #[error("snapshot input cannot be in the node's snapshot recovery namespace")]
    RecoveryInput,
    #[error("invalid Core snapshot: {0}")]
    Codec(#[from] bitcoin_rs_utxo::core_snapshot::SnapshotError),
    #[error("snapshot activation failed: {0}")]
    Activation(#[from] AssumeUtxoError),
    #[error("invalid native snapshot: {0}")]
    Native(#[from] bitcoin_rs_utxo::UtxoError),
    #[error("snapshot admission failed: {0}")]
    Admission(#[from] bitcoin_rs_chainstate::ApplyError),
    #[error("snapshot consumer reconciliation failed: {0}")]
    Settlement(#[from] bitcoin_rs_mempool::ChainChangeError),
    #[error("snapshot activation failed: {activation}; consumer settlement failed: {settlement}")]
    ActivationAndSettlement {
        activation: AssumeUtxoError,
        settlement: bitcoin_rs_mempool::ChainChangeError,
    },
}

impl From<SnapshotImportError> for SnapshotControlError {
    fn from(error: SnapshotImportError) -> Self {
        match error {
            SnapshotImportError::File(_)
            | SnapshotImportError::NotRegular
            | SnapshotImportError::RecoveryInput => Self::File(error.to_string()),
            SnapshotImportError::Codec(bitcoin_rs_utxo::core_snapshot::SnapshotError::Io(_)) => {
                Self::Failed(error.to_string())
            }
            SnapshotImportError::Codec(_) | SnapshotImportError::Native(_) => {
                Self::Invalid(error.to_string())
            }
            SnapshotImportError::ImportInProgress
            | SnapshotImportError::MempoolNotEmpty
            | SnapshotImportError::Activation(
                AssumeUtxoError::AlreadyActive
                | AssumeUtxoError::FullRevalidationRequired
                | AssumeUtxoError::SnapshotHeaderMissing(_)
                | AssumeUtxoError::SnapshotBaseNotOnBestHeaderChain { .. }
                | AssumeUtxoError::ActivationBehindTip,
            ) => Self::Unavailable(error.to_string()),
            _ => Self::Failed(error.to_string()),
        }
    }
}

/// Validate the held descriptor. `O_NONBLOCK` prevents a FIFO path replacement
/// from hanging between the path metadata check and opening the input.
fn open_regular_input(path: &Path) -> Result<File, SnapshotImportError> {
    #[cfg(not(unix))]
    if !path.metadata()?.is_file() {
        return Err(SnapshotImportError::NotRegular);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let flags =
            i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).map_err(std::io::Error::other)?;
        options.custom_flags(flags);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(SnapshotImportError::NotRegular);
    }
    Ok(file)
}

impl SnapshotControl {
    pub(crate) fn new(
        manager: Arc<AssumeUtxoManager>,
        chainstate: Arc<Chainstate>,
        followers: ChainFollowers,
        data_dir: PathBuf,
        network: Network,
        seed_offer: Option<SeedOfferCell>,
    ) -> Self {
        Self {
            manager,
            chainstate,
            followers,
            data_dir,
            network,
            seed_offer,
            import: Mutex::new(()),
            export: Mutex::new(()),
        }
    }

    /// Writes the UTXO set at the applied tip as a Core v2 snapshot.
    ///
    /// The request latch or the chainstate shutdown latch stops the encode
    /// within the writer's polling interval; either answers
    /// [`SnapshotExportError::Interrupted`] and leaves no file.
    pub(crate) fn export(
        &self,
        output: &Path,
        cancellation: &LatchReader,
    ) -> Result<SnapshotExport, SnapshotExportError> {
        let shutdown = self.chainstate.shutdown_reader();
        self.export_until(output, &|| {
            cancellation.is_triggered() || shutdown.is_triggered()
        })
    }

    fn export_until(
        &self,
        output: &Path,
        stop: &dyn Fn() -> bool,
    ) -> Result<SnapshotExport, SnapshotExportError> {
        // Refuse before any lock or byte: publication needs the no-replace
        // rename, and discovering its absence after the encode would have
        // blocked block commits for nothing.
        if !HAS_ATOMIC_NOREPLACE_RENAME {
            return Err(SnapshotExportError::NoAtomicPublish);
        }
        let _permit = self
            .export
            .try_lock()
            .ok_or(SnapshotExportError::ExportInProgress)?;
        let target = self.resolve_output(output)?;
        if stop() {
            return Err(SnapshotExportError::Interrupted);
        }
        let (staged, file) =
            StagedFile::create(&target.dir, &target.temp).map_err(SnapshotExportError::Output)?;
        let mut sink = BufWriter::with_capacity(EXPORT_BUFFER_BYTES, file);
        let encoded = self.encode_at_applied_tip(&mut sink, stop)?;
        sink.flush().map_err(SnapshotExportError::Write)?;
        let file = sink
            .into_inner()
            .map_err(|error| SnapshotExportError::Write(error.into_error()))?;
        file.sync_all().map_err(SnapshotExportError::Write)?;
        let actual = file.metadata().map_err(SnapshotExportError::Write)?.len();
        if actual != encoded.report.bytes {
            return Err(SnapshotExportError::Length {
                expected: encoded.report.bytes,
                actual,
            });
        }
        drop(file);
        if stop() {
            return Err(SnapshotExportError::Interrupted);
        }
        // A prior existence check cannot exclude another creator of the
        // destination, so publication is the filesystem's no-replace rename.
        match rename_noreplace(&target.dir, &target.temp, &target.name) {
            Ok(()) => staged.published(),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(SnapshotExportError::Exists(
                    target.path.to_string_lossy().into_owned(),
                ));
            }
            Err(error) => return Err(SnapshotExportError::Write(error)),
        }
        sync_dir(&target.dir).map_err(SnapshotExportError::DirectorySync)?;
        Ok(SnapshotExport {
            coins_written: encoded.report.coins,
            base_hash: encoded.base_hash.to_string_be(),
            base_height: encoded.base_height,
            // JSON cannot serialize arbitrary filesystem bytes; only this
            // display replaces them, never the path that was written.
            path: target.path.to_string_lossy().into_owned(),
            txoutset_hash: encoded.report.txoutset_hash.to_string_be(),
            nchaintx: encoded.nchaintx,
        })
    }

    /// Resolves `output` below the data directory when relative, refusing an
    /// existing entry and the node's snapshot recovery namespace.
    fn resolve_output(&self, output: &Path) -> Result<ExportTarget, SnapshotExportError> {
        let joined = if output.is_absolute() {
            output.to_path_buf()
        } else {
            self.data_dir.join(output)
        };
        let name = joined
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or(SnapshotExportError::OutputName)?
            .to_owned();
        let parent = joined
            .parent()
            .ok_or(SnapshotExportError::OutputName)?
            .canonicalize()
            .map_err(SnapshotExportError::Output)?;
        // Activation publishes native recovery files in this namespace and may
        // replace entries there, so an exported snapshot cannot live in it.
        let recovery = self
            .data_dir
            .canonicalize()
            .map_err(SnapshotExportError::Output)?
            .join("assumeutxo");
        if parent.starts_with(recovery) {
            return Err(SnapshotExportError::RecoveryOutput);
        }
        let dir = open_data_dir(&parent).map_err(SnapshotExportError::Output)?;
        let path = parent.join(&name);
        match dir.symlink_metadata(&name) {
            Ok(_) => {
                return Err(SnapshotExportError::Exists(
                    path.to_string_lossy().into_owned(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(SnapshotExportError::Output(error)),
        }
        Ok(ExportTarget {
            temp: format!("{name}.{}.incomplete", std::process::id()),
            dir,
            name,
            path,
        })
    }

    /// Encodes the applied tip's UTXO set into `sink`.
    ///
    /// The transition lock is taken before the stable view, matching block
    /// apply, and both are held across the whole encode because the set has no
    /// immutable capture: no commit can interleave between the tip read, the
    /// coin count and the last coin. Commit-blocking time, from the permit
    /// to its release, is logged for every outcome.
    fn encode_at_applied_tip<W: Write>(
        &self,
        sink: &mut W,
        stop: &dyn Fn() -> bool,
    ) -> Result<Encoded, SnapshotExportError> {
        let transition = self.chainstate.lock_transition()?;
        let permitted = quanta::Instant::now();
        let encoded = self.encode_under_view(sink, stop);
        drop(transition);
        let held_us = permitted.elapsed().as_micros();
        match &encoded {
            Ok(done) => tracing::info!(
                held_us,
                coins = done.report.coins,
                bytes = done.report.bytes,
                base_height = done.base_height,
                "snapshot export released the chain transition"
            ),
            Err(error) => tracing::warn!(
                held_us,
                %error,
                "snapshot export released the chain transition without a snapshot"
            ),
        }
        encoded
    }

    fn encode_under_view<W: Write>(
        &self,
        sink: &mut W,
        stop: &dyn Fn() -> bool,
    ) -> Result<Encoded, SnapshotExportError> {
        let utxo = self.chainstate.utxo_reader();
        let view = utxo.lock_stable_view();
        let snapshot = self.chainstate.snapshot();
        let tip = snapshot.applied.ok_or(SnapshotExportError::NoAppliedTip)?;
        let nchaintx = snapshot
            .chain_tx_count
            .get()
            .ok_or(SnapshotExportError::ChainTxCountUnknown)?;
        let coins = u64::try_from(view.len())
            .map_err(|error| SnapshotExportError::Write(std::io::Error::other(error)))?;
        let report = write_core_v2(&view, self.network, tip.hash, tip.height, coins, sink, stop)?;
        Ok(Encoded {
            report,
            base_hash: tip.hash,
            base_height: tip.height,
            nchaintx,
        })
    }

    // Both input formats claim the same resource permit and refuse a second
    // activation before resolving a path, reading input or reconstructing coins.
    fn claim_import(&self) -> Result<parking_lot::MutexGuard<'_, ()>, SnapshotImportError> {
        let permit = self
            .import
            .try_lock()
            .ok_or(SnapshotImportError::ImportInProgress)?;
        if !matches!(self.manager.status()?, AssumeUtxoDiskStatus::Uninitialized) {
            return Err(AssumeUtxoError::AlreadyActive.into());
        }
        Ok(permit)
    }

    pub(crate) fn import(&self, input: &Path) -> Result<SnapshotImport, SnapshotImportError> {
        let _permit = self.claim_import()?;
        let path = if input.is_absolute() {
            input.to_path_buf()
        } else {
            self.data_dir.join(input)
        };
        let path = path.canonicalize()?;
        if !path.metadata()?.is_file() {
            return Err(SnapshotImportError::NotRegular);
        }
        // Activation publishes native recovery files only in this namespace.
        // A portable source there must not be overwritten by that publication.
        let recovery = self.data_dir.canonicalize()?.join("assumeutxo");
        if path.starts_with(recovery) {
            return Err(SnapshotImportError::RecoveryInput);
        }
        let mut file = BufReader::new(open_regular_input(&path)?);
        // The reader seals the set with the commitment and statistics folded
        // from its authenticated records; activation consumes that proof and
        // does not traverse the set again.
        let read_started = Instant::now();
        let snapshot = read_verified(&mut file, self.network, SnapshotLimits::default())?;
        let read_verify = read_started.elapsed();
        let result = SnapshotImport {
            coins_loaded: snapshot.metadata.coins_count,
            tip_hash: snapshot.anchor.block_hash.to_string_be(),
            base_height: snapshot.anchor.height,
            // JSON cannot serialize arbitrary filesystem bytes. Render before
            // committing so a valid symlink target cannot turn success into a
            // post-commit response error.
            path: path.to_string_lossy().into_owned(),
        };
        let file_bytes = snapshot.bytes_read;
        let base_hash = snapshot.anchor.block_hash;
        let state = snapshot.into_state();
        let activate_started = Instant::now();
        self.activate(base_hash, |manager| {
            manager.activate_verified_snapshot(state)
        })?;
        // One structured record per successful import: the e2e resource proof
        // reads these phases from the node's stderr JSON. No other consumer.
        tracing::info!(
            target: "bitcoin_rs::snapshot_import",
            coins = result.coins_loaded,
            file_bytes,
            base_height = result.base_height,
            read_verify_micros = micros(read_verify),
            activate_micros = micros(activate_started.elapsed()),
            "snapshot import phases"
        );
        Ok(result)
    }

    /// Existing embedding contract: native v4 input and caller-relative paths.
    /// This entry shares the same resource permit and activation effects with RPC.
    pub(crate) fn import_native(&self, path: &Path) -> Result<(), SnapshotImportError> {
        let _permit = self.claim_import()?;
        let mut file = BufReader::new(open_regular_input(path)?);
        let snapshot = bitcoin_rs_utxo::read_snapshot_strict_v4(&mut file)?;
        // Native v4 input carries no proof; the manager verifies it once.
        let base_hash = snapshot.tip_hash;
        self.activate(base_hash, |manager| {
            manager.activate_snapshot_state(snapshot.set, snapshot.tip_hash, snapshot.height)
        })
    }

    fn activate(
        &self,
        base_hash: Hash256,
        activation: impl FnOnce(&AssumeUtxoManager) -> Result<(), AssumeUtxoError>,
    ) -> Result<(), SnapshotImportError> {
        // Take-and-drop on this early exit too: every return from `activate`
        // leaves no staged witness behind, so none can pair with a later call.
        let change = match self.followers.begin_mempool_change() {
            Ok(change) => change,
            Err(error) => {
                self.drop_activation_witness();
                return Err(SnapshotImportError::Admission(error));
            }
        };
        // The generation fence serializes with in-flight admission and prevents
        // new commits. Drop the pool read guard before costly activation work.
        if self
            .followers
            .mempool_gateway()
            .is_some_and(|gateway| !gateway.read().is_empty())
        {
            // A guard's Drop intentionally leaves admission closed. This is an
            // operational refusal, so settle without invoking any consumers.
            if let Some(change) = change
                && let Err(error) = change.finish()
            {
                self.chainstate.fail_closed_for_recovery();
                self.drop_activation_witness();
                return Err(SnapshotImportError::Settlement(error));
            }
            self.drop_activation_witness();
            return Err(SnapshotImportError::MempoolNotEmpty);
        }
        let result = activation(self.manager.as_ref());
        if result.is_ok() {
            self.followers.on_snapshot();
        }
        if !self.chainstate.is_closed_for_recovery()
            && let Some(change) = change
            && let Err(settlement) = change.finish()
        {
            self.chainstate.fail_closed_for_recovery();
            // Settlement failed after (or without) manager success: nothing may
            // be offered, and no staged witness may survive to a later call.
            self.drop_activation_witness();
            return match result {
                Err(activation) => Err(SnapshotImportError::ActivationAndSettlement {
                    activation,
                    settlement,
                }),
                Ok(()) => Err(SnapshotImportError::Settlement(settlement)),
            };
        }
        if let Err(activation) = result {
            self.drop_activation_witness();
            Err(SnapshotImportError::Activation(activation))
        } else {
            // Full success only: manager activation plus followers plus
            // settlement. A later restart mints from the durable Validating
            // state instead, so nothing is offered on any other path.
            self.offer_activation_seed(base_hash);
            Ok(())
        }
    }

    /// Takes and drops any staged activation witness. Every activation error,
    /// settlement, abort, and interruption path calls this so a stale witness
    /// can never pair with a later activation call.
    fn drop_activation_witness(&self) {
        let _ = self.manager.take_pending_activation_witness();
    }

    /// C4 offer: after full activation success, seals the committed archive
    /// `coins.dat` for `base_hash` with the staged witness and offers it into
    /// the shared seed cell. Skips without any file I/O when no cell is
    /// installed or the cell is not wanted; a length mismatch or I/O error
    /// drops the opened file and leaves the cell untouched.
    fn offer_activation_seed(&self, base_hash: bitcoin_rs_primitives::Hash256) {
        let Some(witness) = self.manager.take_pending_activation_witness() else {
            return;
        };
        Self::offer_witness_file(
            self.seed_offer.as_ref(),
            &self.data_dir,
            &witness,
            base_hash,
        );
    }

    /// Shared pre-check/open/check/seal/offer step. Pure pointer moves happen
    /// inside the cell; no lock is held across open, reads, or sealing.
    fn offer_witness_file(
        seed_offer: Option<&SeedOfferCell>,
        data_dir: &Path,
        witness: &V4Witness,
        base_hash: bitcoin_rs_primitives::Hash256,
    ) {
        let Some(cell) = seed_offer else {
            return;
        };
        if !cell.is_wanted() {
            return;
        }
        let path = data_dir
            .join("assumeutxo")
            .join(base_hash.to_string())
            .join("coins.dat");
        // Same hardened opener as snapshot inputs: O_NONBLOCK plus a
        // regular-file check, so a planted FIFO can neither hang activation
        // nor be seeded. Rejection drops the witness with the cell untouched.
        let file = match open_regular_input(&path) {
            Ok(file) => file,
            Err(_) => return,
        };
        let len = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(_) => return,
        };
        if len != witness.byte_len() {
            return;
        }
        let artifact = VerifiedSnapshotArtifact::seal(
            file,
            *witness,
            SeedProvenance::AssumeUtxoArchive {
                base: base_hash.to_le_bytes(),
            },
        );
        let _ = cell.offer(artifact);
    }

    pub(crate) fn chainstates(&self) -> Result<ChainstatesInfo, SnapshotControlError> {
        let report = self
            .manager
            .try_chainstates_report()
            .map_err(|error| SnapshotControlError::Failed(error.to_string()))?
            .ok_or_else(|| {
                SnapshotControlError::Unavailable("snapshot lifecycle update is in progress".into())
            })?;
        let summary = report.lifecycle;
        let mut chainstates = Vec::with_capacity(2);
        if let Some(historical) = summary.historical_chainstate {
            chainstates.push(ChainstateInfo {
                blocks: historical.current_height,
                bestblockhash: historical.current_hash.to_string_be(),
                verificationprogress: report.historical_verification_progress,
                snapshot_blockhash: None,
                validated: true,
            });
        }
        let active = summary.active_chainstate;
        let snapshot_blockhash = active_snapshot_base(active.role, &summary.status)
            .map(bitcoin_rs_primitives::Hash256::to_string_be);
        chainstates.push(ChainstateInfo {
            blocks: active.height.unwrap_or(0),
            bestblockhash: active
                .hash
                .unwrap_or_else(|| self.network.genesis_block_hash())
                .to_string_be(),
            verificationprogress: report.active_verification_progress,
            snapshot_blockhash,
            validated: active.validated,
        });
        Ok(ChainstatesInfo {
            headers: report.headers,
            chainstates,
        })
    }
}

fn micros(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

// Core v31.1 keeps m_from_snapshot_blockhash after marking the snapshot
// validated (validation.cpp:6104-6111). A failure likewise does not erase an
// active assumed role's origin merely because the disk status is Failed.
fn active_snapshot_base(
    role: ChainstateRole,
    status: &AssumeUtxoDiskStatus,
) -> Option<bitcoin_rs_primitives::Hash256> {
    match role {
        ChainstateRole::AssumedActive { base_hash, .. } => Some(base_hash),
        ChainstateRole::Ordinary => match status {
            AssumeUtxoDiskStatus::Finalized { base_hash, .. } => Some(*base_hash),
            _ => None,
        },
        ChainstateRole::Historical { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_rs_utxo::core_snapshot::{SnapshotError, read_and_verify};

    #[test]
    fn active_origin_survives_failure_and_validated_provenance_survives_finalization() {
        let base = bitcoin_rs_primitives::Hash256::from_le_bytes(&[7; 32]);
        let absent = bitcoin_rs_primitives::Hash256::default();
        let assumed = ChainstateRole::AssumedActive {
            base_height: 200,
            base_hash: base,
        };
        let failed = AssumeUtxoDiskStatus::Failed {
            base_height: 200,
            base_hash: base,
            expected_hash_serialized: absent,
            actual_hash_serialized: absent,
        };
        assert_eq!(active_snapshot_base(assumed, &failed), Some(base));
        let finalized = AssumeUtxoDiskStatus::Finalized {
            base_height: 200,
            base_hash: base,
            validated_hash_serialized: absent,
        };
        assert_eq!(
            active_snapshot_base(ChainstateRole::Ordinary, &finalized),
            Some(base)
        );
        assert_eq!(
            active_snapshot_base(
                ChainstateRole::Ordinary,
                &AssumeUtxoDiskStatus::Uninitialized
            ),
            None
        );
    }

    // `rustix::fs::mkfifoat` is not available on Apple platforms, so the
    // macOS test hosts gate this fixture the same way the epoch-lock FIFO
    // test in `tests/unit/state/tests/events.rs` does. The code under test
    // (`open_regular_input`) keeps its platform-independent coverage
    // elsewhere.
    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn input_fifo_is_rejected_without_waiting_for_a_writer() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("input.pipe");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let rejected = matches!(
                open_regular_input(&path),
                Err(SnapshotImportError::NotRegular)
            );
            let _ = sender.send(rejected);
        });
        assert!(
            receiver.recv_timeout(std::time::Duration::from_secs(1))?,
            "FIFO must be rejected as a non-regular input"
        );
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("input opener panicked"))?;
        Ok(())
    }

    fn node_config(dir: &Path) -> crate::NodeConfig {
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.join("node");
        config.p2p.listen.clear();
        config
    }

    fn core_headers() -> anyhow::Result<Vec<bitcoin_rs_primitives::Header>> {
        let raw: Vec<String> = serde_json::from_str(include_str!(
            "../../utxo/tests/fixtures/core-v2/blocks200.json"
        ))?;
        raw.iter()
            .map(|hex| {
                let block: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(hex)?;
                bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(&block.header))
                    .map_err(anyhow::Error::from)
            })
            .collect()
    }

    fn snapshot_inputs(dir: &Path) -> anyhow::Result<(crate::state::NodeState, PathBuf, PathBuf)> {
        let state = crate::state::NodeState::open(node_config(dir), None)?;
        state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            Network::Regtest.genesis_block(),
        ))?;
        state.chainstate().admit_headers(&core_headers()?)?;
        let core_bytes = include_bytes!("../../utxo/tests/fixtures/core-v2/core200.dat");
        let core_path = dir.join("core.dat");
        std::fs::write(&core_path, core_bytes)?;
        let snapshot = read_and_verify(
            &mut core_bytes.as_slice(),
            Network::Regtest,
            SnapshotLimits::default(),
        )?;
        let mut native = Vec::new();
        bitcoin_rs_utxo::write_snapshot_observed(
            &snapshot.set,
            &snapshot.anchor.block_hash,
            snapshot.anchor.height,
            &mut native,
            (),
        )?;
        let native_path = dir.join("native.dat");
        std::fs::write(&native_path, &native)?;
        Ok((state, core_path, native_path))
    }

    #[test]
    fn native_embedding_contract_and_shared_import_budget() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let (state, core_path, native_path) = snapshot_inputs(dir.path())?;
        let native = std::fs::read(&native_path)?;
        let core_bytes = std::fs::read(&core_path)?;
        {
            let _permit = state.snapshots.import.lock();
            assert!(matches!(
                state.snapshots.import(&core_path),
                Err(SnapshotImportError::ImportInProgress)
            ));
            assert!(matches!(
                state.snapshots.import_native(&native_path),
                Err(SnapshotImportError::ImportInProgress)
            ));
        }
        // The established embedding call still selects native v4 explicitly.
        assert!(state.activate_assumeutxo_snapshot_file(&core_path).is_err());
        state.activate_assumeutxo_snapshot_file(&native_path)?;
        assert!(matches!(
            state
                .snapshots
                .import_native(&dir.path().join("missing.dat")),
            Err(SnapshotImportError::Activation(
                AssumeUtxoError::AlreadyActive
            ))
        ));
        let view = state.chainstates_summary()?;
        assert_eq!(view.active_chainstate.height, Some(200));
        assert!(!view.active_chainstate.validated);
        assert!(view.historical_chainstate.is_some());
        assert_eq!(std::fs::read(native_path)?, native);
        assert_eq!(std::fs::read(core_path)?, core_bytes);
        Ok(())
    }

    #[test]
    fn successful_snapshot_import_preserves_nonresident_fee_prioritisation() -> anyhow::Result<()> {
        use bitcoin_rs_mempool::PrioritisedTransaction;
        use bitcoin_rs_primitives::{Hash256, Txid};

        // Core 31.1 AddChainstate transfers the existing empty CTxMemPool;
        // its mapDeltas entries for absent transactions survive that transfer.
        for native in [false, true] {
            let dir = tempfile::tempdir()?;
            let (state, core_path, native_path) = snapshot_inputs(dir.path())?;
            let gateway = state.mempool_gateway();
            let txid = Txid(Hash256::from_le_bytes(&[42; 32]));
            gateway.prioritise(txid, 123)?;
            let expected = vec![PrioritisedTransaction {
                txid,
                fee_delta: 123,
                in_mempool: false,
                modified_fee: None,
            }];
            assert_eq!(gateway.prioritised_transactions(), expected);
            assert!(gateway.read().is_empty());
            let sequence = gateway.read().sequence_number();
            if native {
                state.snapshots.import_native(&native_path)?;
            } else {
                state.snapshots.import(&core_path)?;
            }
            assert_eq!(
                gateway.prioritised_transactions(),
                expected,
                "successful import must preserve operator fee deltas (native={native})"
            );
            assert!(gateway.read().is_empty());
            assert_eq!(gateway.read().sequence_number(), sequence);
            assert!(gateway.stable_generation().is_some());
            assert_eq!(
                state
                    .chainstate()
                    .applied_tip_snapshot()
                    .map(|tip| tip.height),
                Some(200)
            );
            assert!(state.chainstate().role().is_assumed_active());
        }
        Ok(())
    }

    #[test]
    fn nonempty_mempool_refuses_both_formats_without_changing_state() -> anyhow::Result<()> {
        use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry};
        use bitcoin_rs_primitives::{
            Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
        };

        let dir = tempfile::tempdir()?;
        let (state, core_path, native_path) = snapshot_inputs(dir.path())?;
        let gateway = state.mempool_gateway();
        let transaction = Arc::new(Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Network::Regtest.genesis_block().txs[0].txid(), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: Script::from_bytes(vec![0x6a, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]),
            }],
            lock_time: LockTime::ZERO,
        });
        // Stage membership through the existing test seam. The independent
        // process case covers admission of a real spend on both implementations.
        gateway.insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::clone(&transaction), 100, 1_000, 0, 0, 0),
        )?;
        gateway.prioritise(transaction.txid(), 123)?;
        let before_tip = state.chainstate().applied_tip_snapshot();
        let before_stats = state.chainstate().coin_stats_handle().snapshot();
        let before_sequence = gateway.read().sequence_number();
        let before_fees = gateway.prioritised_transactions();
        let core_bytes = std::fs::read(&core_path)?;
        let native_bytes = std::fs::read(&native_path)?;
        for native in [false, true] {
            let result = if native {
                state.snapshots.import_native(&native_path)
            } else {
                state.snapshots.import(&core_path).map(|_| ())
            };
            assert!(
                matches!(result, Err(SnapshotImportError::MempoolNotEmpty)),
                "a populated mempool must refuse snapshot activation"
            );
            assert!(gateway.read().contains_txid(&transaction.txid()));
            assert_eq!(gateway.read().sequence_number(), before_sequence);
            assert_eq!(gateway.prioritised_transactions(), before_fees);
            assert!(
                gateway.stable_generation().is_some(),
                "refusal must settle its admission fence"
            );
            assert_eq!(state.chainstate().applied_tip_snapshot(), before_tip);
            assert_eq!(
                state.chainstate().coin_stats_handle().snapshot(),
                before_stats
            );
            assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
            assert!(matches!(
                state.snapshots.manager.status()?,
                AssumeUtxoDiskStatus::Uninitialized
            ));
            assert!(!state.chainstate().is_closed_for_recovery());
            assert!(!dir.path().join("node/assumeutxo").exists());
            assert_eq!(std::fs::read(&core_path)?, core_bytes);
            assert_eq!(std::fs::read(&native_path)?, native_bytes);
        }
        gateway.clear(AdmissionOrigin::Rpc);
        state.snapshots.import(&core_path)?;
        assert_eq!(
            state
                .chainstate()
                .applied_tip_snapshot()
                .map(|tip| tip.height),
            Some(200)
        );
        assert!(gateway.stable_generation().is_some());
        Ok(())
    }

    fn entry_names(dir: &Path) -> anyhow::Result<Vec<String>> {
        let mut names = std::fs::read_dir(dir)?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<anyhow::Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }

    #[test]
    fn export_reproduces_the_core_snapshot_and_never_replaces_an_entry() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let (state, core_path, _native_path) = snapshot_inputs(dir.path())?;
        state.snapshots.import(&core_path)?;
        let core_bytes = std::fs::read(&core_path)?;
        let pin = Network::Regtest
            .assume_utxo_for_height(200)
            .ok_or_else(|| anyhow::anyhow!("the regtest 200-height pin is compiled"))?;
        let coins = read_and_verify(
            &mut core_bytes.as_slice(),
            Network::Regtest,
            SnapshotLimits::default(),
        )?
        .metadata
        .coins_count;
        let never = LatchReader::fixture_never();
        let out = dir.path().join("out");
        std::fs::create_dir(&out)?;
        let output = out.join("export.dat");

        let exported = state.snapshots.export(&output, &never)?;
        assert_eq!(std::fs::read(&output)?, core_bytes);
        assert_eq!(exported.coins_written, coins);
        assert_eq!(exported.base_height, 200);
        assert_eq!(exported.base_hash, pin.block_hash.to_string_be());
        assert_eq!(exported.txoutset_hash, pin.hash_serialized.to_string_be());
        assert_eq!(exported.nchaintx, pin.chain_tx_count);
        assert_eq!(
            exported.path,
            output.canonicalize()?.to_string_lossy().into_owned()
        );
        assert_eq!(entry_names(&out)?, ["export.dat"]);

        // The published file and an operator's file both survive a second
        // export, and no temporary file is left beside them.
        assert!(matches!(
            state.snapshots.export(&output, &never),
            Err(SnapshotExportError::Exists(_))
        ));
        let operator = out.join("operator.dat");
        std::fs::write(&operator, b"operator")?;
        assert!(matches!(
            state.snapshots.export(&operator, &never),
            Err(SnapshotExportError::Exists(_))
        ));
        assert_eq!(std::fs::read(&operator)?, b"operator");
        assert_eq!(std::fs::read(&output)?, core_bytes);
        assert_eq!(entry_names(&out)?, ["export.dat", "operator.dat"]);

        // A relative path resolves below the data directory.
        let relative = state.snapshots.export(Path::new("relative.dat"), &never)?;
        assert_eq!(
            std::fs::read(dir.path().join("node/relative.dat"))?,
            core_bytes
        );
        assert_eq!(
            relative.path,
            dir.path()
                .join("node/relative.dat")
                .canonicalize()?
                .to_string_lossy()
        );

        // Activation may replace entries in the recovery namespace, so an
        // export cannot be placed there.
        let recovery = dir.path().join("node/assumeutxo/export.dat");
        assert!(matches!(
            state.snapshots.export(&recovery, &never),
            Err(SnapshotExportError::RecoveryOutput)
        ));
        assert!(!recovery.exists());
        Ok(())
    }

    #[test]
    fn interrupted_export_publishes_nothing_and_removes_its_staged_file() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let (state, core_path, _native_path) = snapshot_inputs(dir.path())?;
        state.snapshots.import(&core_path)?;
        let out = dir.path().join("out");
        std::fs::create_dir(&out)?;
        let output = out.join("interrupted.dat");

        let cancelled = LatchReader::new(Arc::new(std::sync::atomic::AtomicBool::new(true)));
        assert!(matches!(
            state.snapshots.export(&output, &cancelled),
            Err(SnapshotExportError::Interrupted)
        ));
        assert_eq!(entry_names(&out)?, Vec::<String>::new());

        // The second poll is the encoder's own, after the staged file exists
        // and the chain locks are held.
        let polls = std::cell::Cell::new(0_u32);
        let stop = || {
            polls.set(polls.get() + 1);
            polls.get() > 1
        };
        let error = state
            .snapshots
            .export_until(&output, &stop)
            .err()
            .ok_or_else(|| anyhow::anyhow!("an interrupted export must fail"))?;
        assert!(matches!(
            error,
            SnapshotExportError::Codec(SnapshotError::Interrupted)
        ));
        assert!(matches!(
            SnapshotControlError::from(error),
            SnapshotControlError::Interrupted
        ));
        assert_eq!(entry_names(&out)?, Vec::<String>::new());

        // The locks were released: a later export succeeds.
        state
            .snapshots
            .export(&output, &LatchReader::fixture_never())?;
        assert_eq!(entry_names(&out)?, ["interrupted.dat"]);

        // Node shutdown interrupts like the request latch does.
        state.chainstate().request_shutdown();
        assert!(matches!(
            state
                .snapshots
                .export(&out.join("shutdown.dat"), &LatchReader::fixture_never()),
            Err(SnapshotExportError::Interrupted)
        ));
        assert_eq!(entry_names(&out)?, ["interrupted.dat"]);
        Ok(())
    }

    #[test]
    fn concurrent_export_is_refused_while_the_permit_is_held() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let (state, core_path, _native_path) = snapshot_inputs(dir.path())?;
        state.snapshots.import(&core_path)?;
        let output = dir.path().join("busy.dat");
        {
            let _permit = state.snapshots.export.lock();
            let error = state
                .snapshots
                .export(&output, &LatchReader::fixture_never())
                .err()
                .ok_or_else(|| anyhow::anyhow!("a held permit must refuse the export"))?;
            assert!(matches!(error, SnapshotExportError::ExportInProgress));
            assert!(matches!(
                SnapshotControlError::from(error),
                SnapshotControlError::Unavailable(_)
            ));
        }
        assert!(!output.exists());
        Ok(())
    }

    fn regtest_pin() -> anyhow::Result<&'static bitcoin_rs_primitives::AssumeUtxoData> {
        Network::Regtest
            .assume_utxo_for_height(200)
            .ok_or_else(|| anyhow::anyhow!("regtest height-200 anchor missing"))
    }

    type ValidatingIdentity = (
        u32,
        bitcoin_rs_primitives::Hash256,
        bitcoin_rs_primitives::Hash256,
        u64,
    );

    fn validating_identity(status: &AssumeUtxoDiskStatus) -> anyhow::Result<ValidatingIdentity> {
        match status {
            AssumeUtxoDiskStatus::Validating {
                base_height,
                base_hash,
                expected_hash_serialized,
                chain_tx_count,
                ..
            } => Ok((
                *base_height,
                *base_hash,
                *expected_hash_serialized,
                *chain_tx_count,
            )),
            other => anyhow::bail!("expected a validating lifecycle, found {other:?}"),
        }
    }

    fn tip_identity(
        state: &crate::state::NodeState,
    ) -> Option<(u32, bitcoin_rs_primitives::Hash256)> {
        state
            .chainstate()
            .applied_tip_snapshot()
            .map(|tip| (tip.height, tip.hash))
    }

    // Activation is one linearizable writer: the lifecycle mutex plus the
    // durable-head compare-and-swap. The sealed state needs no further
    // consistency model because it has exactly one owner and no shared handle.
    // Both entries must install byte-identical statistics, and the restarted
    // node (which recomputes them from the archive) must agree.
    #[test]
    fn sealed_and_proofless_activation_install_identical_state_and_survive_restart()
    -> anyhow::Result<()> {
        let pinned = regtest_pin()?;
        let mut installed = Vec::new();
        for native in [false, true] {
            let dir = tempfile::tempdir()?;
            let (state, core_path, native_path) = snapshot_inputs(dir.path())?;
            if native {
                state.snapshots.import_native(&native_path)?;
            } else {
                state.snapshots.import(&core_path)?;
            }
            let stats = state.chainstate().coin_stats_handle().snapshot();
            let (commitment, mut scanned) = state.chainstate().utxo().with_stable_view(|view| {
                Ok::<_, bitcoin_rs_utxo::UtxoError>((
                    view.hash_serialized_3_at_height(pinned.height)?,
                    bitcoin_rs_utxo::stats::scan_coin_stats(view, pinned.height, true)?,
                ))
            })?;
            assert_eq!(commitment, pinned.hash_serialized, "native={native}");
            scanned.tx_count = pinned.chain_tx_count;
            assert_eq!(
                stats.to_bytes(),
                scanned.to_bytes(),
                "native={native}: installed statistics equal an independent scan"
            );
            assert_eq!(stats.utxo_count, 200);
            let identity = validating_identity(&state.snapshots.manager.status()?)?;
            assert_eq!(identity.1, pinned.block_hash);
            drop(state);

            let resumed = crate::state::NodeState::open(node_config(dir.path()), None)?;
            assert_eq!(
                resumed
                    .chainstate()
                    .coin_stats_handle()
                    .snapshot()
                    .to_bytes(),
                stats.to_bytes(),
                "native={native}: restart recomputation agrees with installed statistics"
            );
            assert_eq!(
                validating_identity(&resumed.snapshots.manager.status()?)?,
                identity
            );
            assert!(resumed.chainstate().role().is_assumed_active());
            assert_eq!(
                tip_identity(&resumed),
                Some((pinned.height, pinned.block_hash))
            );
            assert!(
                resumed
                    .chainstates_summary()?
                    .historical_chainstate
                    .is_some()
            );
            installed.push(stats.to_bytes());
        }
        assert_eq!(
            installed[0], installed[1],
            "typed and proofless activation must be indistinguishable"
        );
        Ok(())
    }

    #[test]
    fn wrong_commitment_changes_nothing_and_a_valid_retry_activates() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let (state, core_path, _) = snapshot_inputs(dir.path())?;
        let mut forged = std::fs::read(&core_path)?;
        *forged
            .last_mut()
            .ok_or_else(|| anyhow::anyhow!("empty fixture"))? ^= 1;
        let forged_path = dir.path().join("forged.dat");
        std::fs::write(&forged_path, &forged)?;
        let before_tip = state.chainstate().applied_tip_snapshot();
        let before_stats = state.chainstate().coin_stats_handle().snapshot();
        assert!(matches!(
            state.snapshots.import(&forged_path),
            Err(SnapshotImportError::Codec(
                SnapshotError::CommitmentMismatch { .. }
            ))
        ));
        assert_eq!(state.chainstate().applied_tip_snapshot(), before_tip);
        assert_eq!(
            state.chainstate().coin_stats_handle().snapshot(),
            before_stats
        );
        assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert!(!state.chainstate().is_closed_for_recovery());
        assert!(!dir.path().join("node/assumeutxo").exists());
        assert_eq!(std::fs::read(&forged_path)?, forged);
        state.snapshots.import(&core_path)?;
        assert_eq!(tip_identity(&state).map(|tip| tip.0), Some(200));
        Ok(())
    }

    // A set without proof is mutable through shared access (`replace_from`);
    // the sealed type exists to forbid exactly that. The proofless entry must
    // therefore recompute and refuse, leaving the node reusable.
    #[test]
    fn mutating_an_unproven_set_is_caught_by_the_single_verification() -> anyhow::Result<()> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path, _) = snapshot_inputs(dir.path())?;
        let bytes = std::fs::read(&core_path)?;
        let loaded = read_and_verify(
            &mut bytes.as_slice(),
            Network::Regtest,
            SnapshotLimits::default(),
        )?;
        loaded.set.replace_from(bitcoin_rs_utxo::UtxoSet::new());
        let before_tip = state.chainstate().applied_tip_snapshot();
        let before_stats = state.chainstate().coin_stats_handle().snapshot();
        let result = state.snapshots.manager.activate_snapshot_state(
            loaded.set,
            loaded.metadata.base_block_hash,
            loaded.anchor.height,
        );
        assert!(matches!(
            result,
            Err(AssumeUtxoError::SnapshotCommitmentMismatch { expected, .. })
                if expected == pinned.hash_serialized
        ));
        assert_eq!(state.chainstate().applied_tip_snapshot(), before_tip);
        assert_eq!(
            state.chainstate().coin_stats_handle().snapshot(),
            before_stats
        );
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert!(!state.chainstate().is_closed_for_recovery());
        assert!(!dir.path().join("node/assumeutxo").exists());
        state.snapshots.import(&core_path)?;
        assert_eq!(tip_identity(&state).map(|tip| tip.0), Some(200));
        Ok(())
    }

    // A directory at the final headers name makes archive publication fail
    // after coins.dat was published and before any durable head names either
    // file. The durable head is the sole authority, so the restarted node is
    // Uninitialized again and a retry overwrites the orphan coin archive.
    #[cfg(unix)]
    #[test]
    fn interrupted_activation_fails_closed_and_restart_retries_cleanly() -> anyhow::Result<()> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path, _) = snapshot_inputs(dir.path())?;
        let archive = dir
            .path()
            .join("node/assumeutxo")
            .join(pinned.block_hash.to_string());
        let obstruction = archive.join("headers.dat");
        std::fs::create_dir_all(&obstruction)?;
        let before_tip = tip_identity(&state);
        assert!(before_tip.is_some());
        assert!(matches!(
            state.snapshots.import(&core_path),
            Err(SnapshotImportError::Activation(AssumeUtxoError::Archive(_)))
        ));
        assert!(state.chainstate().is_closed_for_recovery());
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
        assert_eq!(tip_identity(&state), before_tip);
        assert!(archive.join("coins.dat").is_file(), "orphan coin archive");
        drop(state);

        std::fs::remove_dir(&obstruction)?;
        let resumed = crate::state::NodeState::open(node_config(dir.path()), None)?;
        assert!(!resumed.chainstate().is_closed_for_recovery());
        assert!(matches!(
            resumed.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert_eq!(resumed.chainstate().role(), ChainstateRole::Ordinary);
        assert_eq!(tip_identity(&resumed), before_tip);
        resumed.chainstate().admit_headers(&core_headers()?)?;
        resumed.snapshots.import(&core_path)?;
        assert_eq!(tip_identity(&resumed), Some((200, pinned.block_hash)));
        assert!(archive.join("headers.dat").is_file());
        let mut coins = BufReader::new(File::open(archive.join("coins.dat"))?);
        let archived = bitcoin_rs_utxo::read_snapshot_strict_v4(&mut coins)?;
        assert_eq!(
            (archived.height, archived.tip_hash, archived.set.len()),
            (pinned.height, pinned.block_hash, 200)
        );
        Ok(())
    }
}
