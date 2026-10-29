use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

const EXPORT_BUFFER_BYTES: usize = 64 * 1024;

static EXPORT_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn staged_temp_name(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let counter = EXPORT_TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!(
        "{name}.{pid}.{nanos:x}-{counter:x}.incomplete",
        pid = std::process::id()
    )
}

pub(crate) struct SnapshotControl {
    pub(crate) manager: Arc<AssumeUtxoManager>,
    chainstate: Arc<Chainstate>,
    followers: ChainFollowers,
    data_dir: PathBuf,
    network: Network,
    seed_offer: Option<SeedOfferCell>,
    import: Mutex<()>,
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

struct ExportTarget {
    dir: cap_std::fs::Dir,
    name: String,
    temp: String,
    path: PathBuf,
}

struct StagedFile<'a> {
    dir: &'a cap_std::fs::Dir,
    name: String,
    published: bool,
}

impl<'a> StagedFile<'a> {
    fn create(
        dir: &'a cap_std::fs::Dir,
        name: String,
    ) -> std::io::Result<(Self, cap_std::fs::File)> {
        let file = create_file(dir, &name)?;
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
            && let Err(error) = self.dir.remove_file(&self.name)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(file = &self.name, %error, "could not remove unpublished snapshot export");
        }
    }
}

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
        if !HAS_ATOMIC_NOREPLACE_RENAME {
            return Err(SnapshotExportError::NoAtomicPublish);
        }
        let _permit = self
            .export
            .try_lock()
            .ok_or(SnapshotExportError::ExportInProgress)?;
        let mut target = self.resolve_output(output)?;
        if stop() {
            return Err(SnapshotExportError::Interrupted);
        }
        let (staged, file) = {
            let mut attempts = 0_u32;
            let mut temp = target.temp.clone();
            loop {
                match StagedFile::create(&target.dir, temp.clone()) {
                    Ok(staged) => break staged,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::AlreadyExists && attempts < 32 =>
                    {
                        attempts += 1;
                        temp = staged_temp_name(&target.name);
                    }
                    Err(error) => return Err(SnapshotExportError::Output(error)),
                }
            }
        };
        target.temp = staged.name.clone();
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
            path: target.path.to_string_lossy().into_owned(),
            txoutset_hash: encoded.report.txoutset_hash.to_string_be(),
            nchaintx: encoded.nchaintx,
        })
    }

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
            temp: staged_temp_name(&name),
            dir,
            name,
            path,
        })
    }

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
        let recovery = self.data_dir.canonicalize()?.join("assumeutxo");
        if path.starts_with(recovery) {
            return Err(SnapshotImportError::RecoveryInput);
        }
        let mut file = BufReader::new(open_regular_input(&path)?);
        let read_started = Instant::now();
        let snapshot = read_verified(&mut file, self.network, SnapshotLimits::default())?;
        let read_verify = read_started.elapsed();
        let result = SnapshotImport {
            coins_loaded: snapshot.metadata.coins_count,
            tip_hash: snapshot.anchor.block_hash.to_string_be(),
            base_height: snapshot.anchor.height,
            path: path.to_string_lossy().into_owned(),
        };
        let file_bytes = snapshot.bytes_read;
        let base_hash = snapshot.anchor.block_hash;
        let state = snapshot.into_state();
        let activate_started = Instant::now();
        self.activate(base_hash, |manager| {
            manager.activate_verified_snapshot(state)
        })?;
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

    pub(crate) fn import_native(&self, path: &Path) -> Result<(), SnapshotImportError> {
        let _permit = self.claim_import()?;
        let mut file = BufReader::new(open_regular_input(path)?);
        let snapshot = bitcoin_rs_utxo::read_snapshot_strict_v4(&mut file)?;
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
        let change = match self.followers.begin_mempool_change() {
            Ok(change) => change,
            Err(error) => {
                self.drop_activation_witness();
                return Err(SnapshotImportError::Admission(error));
            }
        };
        if self
            .followers
            .mempool_gateway()
            .is_some_and(|gateway| !gateway.read().is_empty())
        {
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
            self.offer_activation_seed(base_hash);
            Ok(())
        }
    }

    fn drop_activation_witness(&self) {
        let _ = self.manager.take_pending_activation_witness();
    }

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
mod tests;
