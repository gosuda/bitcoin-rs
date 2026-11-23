use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read as _, Seek as _, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin_rs_chain::ActivatedSnapshot;
use bitcoin_rs_chain::{
    ApplyError, AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager, Chainstate,
    ChainstateRole,
};
use bitcoin_rs_consensus::latch::LatchReader;
use bitcoin_rs_consensus::primitives::{Hash256, Network};
use bitcoin_rs_index::IndexError;
use bitcoin_rs_index::IndexWatermark;
use bitcoin_rs_index::snapshot_seed::{ScriptLiveSeedObserver, ScriptLiveSeedSession};
use bitcoin_rs_storage::checkpoint::fs::{HAS_ATOMIC_NOREPLACE_RENAME, rename_noreplace};
use bitcoin_rs_storage::checkpoint::{create_file, open_data_dir, sync_dir};
#[cfg(test)]
use bitcoin_rs_storage::utxo::core_snapshot::SnapshotLimits;
use bitcoin_rs_storage::utxo::core_snapshot::{
    CoreV2Base, CoreV2WriteReport, SnapshotError, write_core_v2,
};
use bitcoin_rs_storage::utxo::record::UtxoRecord;
use bitcoin_rs_storage::utxo::{SnapshotCoin, SnapshotCoinObserver};
pub use bitcoin_rs_wire::context::SnapshotImport;
use bitcoin_rs_wire::context::{
    ChainstateInfo, ChainstatesInfo, SnapshotControlError, SnapshotExport,
};
use parking_lot::Mutex;

use crate::chain_effects::ChainFollowers;
use crate::facts_queue::FactsQueue;
use bitcoin_rs_storage::CommittedFacts;

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
    script_live_seed: Option<Arc<bitcoin_rs_index::snapshot_seed::ScriptLiveSeedState>>,
    derived_index_runtime: Option<Arc<bitcoin_rs_index::runtime::DerivedIndexRuntime>>,
    derived_index_status: Option<Arc<bitcoin_rs_index::runtime::DerivedIndexCapability>>,
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
    #[error("could not read snapshot coins: {0}")]
    Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
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
            | SnapshotExportError::Exists(_) => Self::File(error.to_string()),
            SnapshotExportError::ExportInProgress
            | SnapshotExportError::NoAtomicPublish
            | SnapshotExportError::Admission(_)
            | SnapshotExportError::NoAppliedTip
            | SnapshotExportError::ChainTxCountUnknown => Self::Unavailable(error.to_string()),
            SnapshotExportError::Codec(_)
            | SnapshotExportError::Utxo(_)
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
pub enum SnapshotImportError {
    #[error("could not read snapshot: {0}")]
    File(#[from] std::io::Error),
    #[error("snapshot input must be a regular file")]
    NotRegular,
    #[error("another snapshot import is in progress")]
    ImportInProgress,
    #[error("snapshot activation requires an empty mempool")]
    MempoolNotEmpty,
    #[error("invalid Core snapshot: {0}")]
    Codec(#[from] bitcoin_rs_storage::utxo::core_snapshot::SnapshotError),
    #[error("ScriptLive snapshot seed staging failed: {0}")]
    Seed(#[from] bitcoin_rs_index::IndexError),
    #[error("snapshot activation failed: {0}")]
    Activation(#[from] AssumeUtxoError),
    #[error("snapshot admission failed: {0}")]
    Admission(#[from] bitcoin_rs_chain::ApplyError),
    #[error("snapshot consumer reconciliation failed: {0}")]
    Settlement(#[from] bitcoin_rs_mempool::ChainChangeError),
    #[error("snapshot activation failed: {activation}; consumer settlement failed: {settlement}")]
    ActivationAndSettlement {
        activation: Box<AssumeUtxoError>,
        settlement: bitcoin_rs_mempool::ChainChangeError,
    },
    #[error("snapshot manifest invalid: {0}")]
    Manifest(#[from] bitcoin_rs_chain::manifest::ManifestError),
    #[error("index bundle error: {0}")]
    Bundle(#[from] bitcoin_rs_index::portable::IndexBundleError),
}

impl From<SnapshotImportError> for SnapshotControlError {
    fn from(error: SnapshotImportError) -> Self {
        match error {
            SnapshotImportError::File(_) | SnapshotImportError::NotRegular => {
                Self::File(error.to_string())
            }
            SnapshotImportError::Codec(
                bitcoin_rs_storage::utxo::core_snapshot::SnapshotError::Io(_),
            ) => Self::Failed(error.to_string()),
            SnapshotImportError::Codec(_) => Self::Invalid(error.to_string()),
            SnapshotImportError::ImportInProgress
            | SnapshotImportError::MempoolNotEmpty
            | SnapshotImportError::Activation(
                AssumeUtxoError::AlreadyActive
                | AssumeUtxoError::FullRevalidationRequired
                | AssumeUtxoError::SnapshotHeaderMissing(_)
                | AssumeUtxoError::SnapshotBaseNotOnBestHeaderChain { .. }
                | AssumeUtxoError::ActivationBehindTip,
            ) => Self::Unavailable(error.to_string()),
            SnapshotImportError::Manifest(_) => Self::Invalid(error.to_string()),
            SnapshotImportError::Bundle(_) => Self::Failed(error.to_string()),
            _ => Self::Failed(error.to_string()),
        }
    }
}

pub(crate) fn read_bounded_manifest(path: &Path) -> Result<Vec<u8>, SnapshotImportError> {
    const MAX_MANIFEST_BYTES: u64 = 1 << 20;
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_MANIFEST_BYTES) {
        return Err(SnapshotImportError::Manifest(
            bitcoin_rs_chain::manifest::ManifestError::Format("manifest is larger than 1 MiB"),
        ));
    }
    Ok(bytes)
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
        script_live_seed: Option<Arc<bitcoin_rs_index::snapshot_seed::ScriptLiveSeedState>>,
        derived_index_runtime: Option<Arc<bitcoin_rs_index::runtime::DerivedIndexRuntime>>,
        derived_index_status: Option<Arc<bitcoin_rs_index::runtime::DerivedIndexCapability>>,
    ) -> Self {
        Self {
            manager,
            chainstate,
            followers,
            data_dir,
            network,
            script_live_seed,
            derived_index_runtime,
            derived_index_status,
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
        let view = utxo.lock_stable_view()?;
        let snapshot = self.chainstate.snapshot();
        let tip = snapshot.applied.ok_or(SnapshotExportError::NoAppliedTip)?;
        let nchaintx = snapshot
            .chain_tx_count
            .get()
            .ok_or(SnapshotExportError::ChainTxCountUnknown)?;
        let coins = u64::try_from(view.len())
            .map_err(|error| SnapshotExportError::Write(std::io::Error::other(error)))?;
        let report = write_core_v2(
            &view,
            &CoreV2Base {
                network: self.network,
                base_hash: tip.hash,
                base_height: tip.height,
                coins_count: coins,
            },
            sink,
            stop,
        )?;
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
        let path = self.data_dir.join(input);
        let path = path.canonicalize()?;
        if !path.metadata()?.is_file() {
            return Err(SnapshotImportError::NotRegular);
        }
        let mut file = BufReader::new(open_regular_input(&path)?);
        let file_bytes = path.metadata()?.len();
        let session = self.begin_decode_seed()?;
        let seed = session.as_ref();
        let mut refused = None;
        let started = Instant::now();
        let outcome = self.activate(|manager| {
            let mut observer = seed.map(ScriptLiveSeedSession::observer);
            manager.activate_core_snapshot(
                &mut file,
                None,
                |txid, record| {
                    if let Some(observer) = observer.as_mut() {
                        observe_outputs(observer, txid, record);
                    }
                },
                || admit_seed(seed, &mut refused),
            )
        });
        let activated = settle_seed(seed, outcome, refused).map_err(codec_import_error)?;
        tracing::info!(
            target: "bitcoin_rs::snapshot_import",
            coins = activated.declared_coins,
            file_bytes,
            base_height = activated.height,
            activate_micros = micros(started.elapsed()),
            "snapshot import phases"
        );
        Ok(SnapshotImport {
            coins_loaded: activated.declared_coins,
            tip_hash: activated.base_hash.to_string_be(),
            base_height: activated.height,
            path: path.to_string_lossy().into_owned(),
        })
    }

    fn begin_decode_seed(
        &self,
    ) -> Result<Option<bitcoin_rs_index::snapshot_seed::ScriptLiveSeedSession>, SnapshotImportError>
    {
        match self.script_live_seed.as_ref() {
            Some(seed) => seed.begin_session().map(Some).map_err(|error| {
                tracing::warn!(%error, "ScriptLive decode seed session unavailable");
                SnapshotImportError::Seed(error)
            }),
            None => Ok(None),
        }
    }

    fn activate<T>(
        &self,
        activation: impl FnOnce(&AssumeUtxoManager) -> Result<T, AssumeUtxoError>,
    ) -> Result<T, SnapshotImportError> {
        let change = match self.followers.begin_mempool_change() {
            Ok(change) => change,
            Err(error) => {
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
                return Err(SnapshotImportError::Settlement(error));
            }
            return Err(SnapshotImportError::MempoolNotEmpty);
        }
        let result = activation(self.manager.as_ref());
        if result.is_ok()
            && let Err(settlement) = self.followers.on_snapshot(change.as_ref())
        {
            self.chainstate.fail_closed_for_recovery();
            return Err(SnapshotImportError::Settlement(settlement));
        }
        if !self.chainstate.is_closed_for_recovery()
            && let Some(change) = change
            && let Err(settlement) = change.finish()
        {
            self.chainstate.fail_closed_for_recovery();
            return match result {
                Err(activation) => Err(SnapshotImportError::ActivationAndSettlement {
                    activation: Box::new(activation),
                    settlement,
                }),
                Ok(_) => Err(SnapshotImportError::Settlement(settlement)),
            };
        }
        let activated = result.map_err(SnapshotImportError::Activation)?;
        self.sync_historical_window()
            .inspect_err(|_| self.chainstate.fail_closed_for_recovery())?;
        Ok(activated)
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
            .map(bitcoin_rs_consensus::primitives::Hash256::to_string_be);
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
    pub(crate) fn import_manifest(
        &self,
        path: &Path,
    ) -> Result<SnapshotImport, SnapshotImportError> {
        let _permit = self.claim_import()?;
        let path = self.data_dir.join(path);
        let path = path.canonicalize()?;
        if !path.metadata()?.is_file() {
            return Err(SnapshotImportError::NotRegular);
        }
        let bytes = read_bounded_manifest(&path)?;
        let manifest = bitcoin_rs_chain::manifest::SnapshotManifest::parse(&bytes)?;
        if manifest.schema != bitcoin_rs_index::index_format_version() {
            return Err(SnapshotImportError::Manifest(
                bitcoin_rs_chain::manifest::ManifestError::SchemaMismatch {
                    expected: bitcoin_rs_index::index_format_version(),
                    found: manifest.schema,
                },
            ));
        }
        let anchor = self
            .network
            .assume_utxo_for_height(manifest.base_height)
            .ok_or_else(
                || bitcoin_rs_chain::manifest::ManifestError::UnknownAnchor {
                    found: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                        &manifest.base_hash,
                    ),
                    height: manifest.base_height,
                },
            )?;
        let genesis = self.network.genesis_block_hash().to_le_bytes();
        let trust = manifest.verify_against_anchor(self.network, genesis, anchor)?;
        let dir = path.parent().unwrap_or(&path);

        let utxo_path = manifest.artifact_path(dir, bitcoin_rs_chain::manifest::UTXO_SLOT)?;
        let mut file = BufReader::new(open_regular_input(&utxo_path)?);
        let file_bytes = utxo_path.metadata()?.len();
        let session = self.begin_decode_seed()?;
        let seed = session.as_ref();
        let mut refused = None;
        let started = Instant::now();
        {
            let anchor = bitcoin_rs_storage::utxo::core_snapshot::CoreSnapshotStream::open(
                &mut file,
                self.network,
            )?
            .anchor();
            if anchor.height != manifest.base_height
                || anchor.block_hash.to_le_bytes() != manifest.base_hash
            {
                if let Some(session) = session.as_ref() {
                    session.abort();
                }
                return Err(SnapshotImportError::Manifest(
                    bitcoin_rs_chain::manifest::ManifestError::SnapshotBaseMismatch {
                        expected_height: manifest.base_height,
                        expected: Hash256::from_le_bytes(&manifest.base_hash),
                        found_height: anchor.height,
                        found: anchor.block_hash,
                    },
                ));
            }
            if anchor.hash_serialized.to_le_bytes() != manifest.utxo_commitment {
                if let Some(session) = session.as_ref() {
                    session.abort();
                }
                return Err(SnapshotImportError::Manifest(
                    bitcoin_rs_chain::manifest::ManifestError::SnapshotCommitmentMismatch {
                        expected: Hash256::from_le_bytes(&manifest.utxo_commitment),
                        found: anchor.hash_serialized,
                    },
                ));
            }
            file.seek(std::io::SeekFrom::Start(0))?;
        }
        let outcome = self.activate(|manager| {
            let mut observer = seed.map(ScriptLiveSeedSession::observer);
            manager.activate_core_snapshot(
                &mut file,
                Some(bitcoin_rs_chain::assumeutxo::FileAttestation {
                    sha256: manifest.utxo_sha256(),
                    size: manifest.utxo_size(),
                }),
                |txid, record| {
                    if let Some(observer) = observer.as_mut() {
                        observe_outputs(observer, txid, record);
                    }
                },
                || admit_seed(seed, &mut refused),
            )
        });
        let activated = settle_seed(seed, outcome, refused).map_err(ingest_error)?;
        let base_height = activated.height;
        let result = SnapshotImport {
            coins_loaded: activated.declared_coins,
            tip_hash: activated.base_hash.to_string_be(),
            base_height,
            path: path.to_string_lossy().into_owned(),
        };

        for (slot_idx, cap_trust) in trust.capability_trust.iter().enumerate() {
            let Some(cap) =
                bitcoin_rs_consensus::primitives::IndexArtifactCapability::from_index(slot_idx)
            else {
                continue;
            };
            if manifest.index_commitments[slot_idx].is_none() {
                continue;
            }
            let verified = match cap_trust {
                bitcoin_rs_chain::manifest::CapabilityTrust::Trusted(_) => {
                    manifest.verify_index_artifact(dir, slot_idx + 1)
                }
                bitcoin_rs_chain::manifest::CapabilityTrust::Untrusted => {
                    Err(bitcoin_rs_chain::manifest::ManifestError::Artifacts(
                        "the manifest index commitment is not compiled into this node",
                    ))
                }
            };
            match verified {
                Ok(()) => tracing::info!(
                    capability = %cap.name(),
                    base_height,
                    "index artifact verified against its compiled commitment"
                ),
                Err(error) => {
                    tracing::warn!(
                        capability = %cap.name(),
                        %error,
                        "index artifact unavailable; other capabilities continue"
                    );
                    self.fail_capability(cap, base_height, &error);
                }
            }
        }
        tracing::info!(
            target: "bitcoin_rs::snapshot_manifest_import",
            coins = result.coins_loaded,
            file_bytes,
            base_height = result.base_height,
            activate_micros = micros(started.elapsed()),
            "snapshot manifest import phases"
        );
        Ok(result)
    }

    pub(crate) fn admit_startup_manifest(&self, path: &Path) -> Result<(), SnapshotImportError> {
        match self.manager.status()? {
            AssumeUtxoDiskStatus::Uninitialized => self.import_manifest(path).map(|_| ()),
            AssumeUtxoDiskStatus::Validating {
                base_height,
                base_hash,
                ..
            }
            | AssumeUtxoDiskStatus::Finalized {
                base_height,
                base_hash,
                ..
            } => {
                let path = self.data_dir.join(path);
                let bytes = read_bounded_manifest(&path)?;
                let manifest = bitcoin_rs_chain::manifest::SnapshotManifest::parse(&bytes)?;
                if manifest.base_height == base_height
                    && manifest.base_hash == base_hash.to_le_bytes()
                {
                    Ok(())
                } else {
                    Err(AssumeUtxoError::AlreadyActive.into())
                }
            }
            AssumeUtxoDiskStatus::Failed {
                base_height,
                expected_hash_serialized,
                actual_hash_serialized,
                ..
            } => Err(SnapshotImportError::Activation(
                AssumeUtxoError::PreviouslyFailed {
                    base_height,
                    expected_hash_serialized,
                    actual_hash_serialized,
                },
            )),
        }
    }

    pub(crate) fn sync_historical_window(&self) -> Result<(), SnapshotImportError> {
        let Some(runtime) = self.derived_index_runtime.as_ref() else {
            return Ok(());
        };
        let (base, next) = match self.manager.status()? {
            AssumeUtxoDiskStatus::Validating { base_height, .. } => {
                let next = self
                    .manager
                    .next_historical_block()?
                    .map_or(base_height.saturating_add(1), |(height, _)| height);
                (base_height, next)
            }
            AssumeUtxoDiskStatus::Finalized { base_height, .. } => {
                (base_height, base_height.saturating_add(1))
            }
            AssumeUtxoDiskStatus::Uninitialized | AssumeUtxoDiskStatus::Failed { .. } => {
                return Ok(());
            }
        };
        runtime.set_historical_window(base, next);
        Ok(())
    }

    pub(crate) fn wire_historical_facts(&self, queue: Option<Arc<FactsQueue>>) {
        let Some(queue) = queue else {
            self.manager.clear_historical_facts_hook();
            return;
        };
        let runtime = self.derived_index_runtime.clone();
        self.manager
            .set_historical_facts_hook(Arc::new(move |facts: &Arc<CommittedFacts>| {
                queue.try_push(Arc::clone(facts));
                let Some(height) = facts.blocks.iter().map(|block| block.height).max() else {
                    return;
                };
                if let Some(runtime) = runtime.as_ref() {
                    runtime.note_historical_facts(height);
                }
            }));
    }

    /// SNP-10: an index artifact failure invalidates that projection only.
    fn fail_capability(
        &self,
        cap: bitcoin_rs_consensus::primitives::IndexArtifactCapability,
        base_height: u32,
        error: &bitcoin_rs_chain::manifest::ManifestError,
    ) {
        let Some(runtime) = self.derived_index_runtime.as_ref() else {
            return;
        };
        match cap {
            bitcoin_rs_consensus::primitives::IndexArtifactCapability::TxLookup => {
                runtime.fail_tx_lookup(
                    &bitcoin_rs_index::runtime::DerivedIndexWorkerError::ArtifactUnavailable(
                        error.to_string(),
                    ),
                );
            }
            bitcoin_rs_consensus::primitives::IndexArtifactCapability::ScriptHistory => {
                runtime.fail_script_history(
                    &bitcoin_rs_index::runtime::DerivedIndexWorkerError::HistoryUnavailable(
                        bitcoin_rs_storage::pruning::HistoryUnavailable::Pruned {
                            below: base_height,
                        },
                    ),
                );
            }
            bitcoin_rs_consensus::primitives::IndexArtifactCapability::ScriptLive => {
                runtime.fail_script_live(
                    &bitcoin_rs_index::runtime::DerivedIndexWorkerError::ScriptLiveHistoryPruned,
                );
            }
            bitcoin_rs_consensus::primitives::IndexArtifactCapability::CompactFilters => {
                runtime.fail_compact_filters(
                    &bitcoin_rs_index::runtime::DerivedIndexWorkerError::HistoryUnavailable(
                        bitcoin_rs_storage::pruning::HistoryUnavailable::Pruned {
                            below: base_height,
                        },
                    ),
                );
            }
        }
    }
    pub(crate) fn three_positions(&self) -> Result<ThreePositions, SnapshotControlError> {
        let active_chain_height = self
            .chainstate
            .applied_tip_snapshot()
            .map_or(0, |tip| tip.height);
        let status = self
            .manager
            .status()
            .map_err(|error| SnapshotControlError::Failed(error.to_string()))?;
        let historical_validation_height = match status {
            AssumeUtxoDiskStatus::Validating {
                historical_height, ..
            } => historical_height,
            AssumeUtxoDiskStatus::Finalized { base_height, .. } => base_height,
            _ => 0,
        };
        let projection_coverage = self
            .derived_index_status
            .as_ref()
            .map_or([None; 4], |status| status.capability_coverage());
        Ok(ThreePositions {
            active_chain_height,
            historical_validation_height,
            projection_coverage,
        })
    }
}

/// SNP-09: three independent reported positions: active-chain application,
/// historical verification progress, and projection coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreePositions {
    pub active_chain_height: u32,
    pub historical_validation_height: u32,
    /// Indexed by `IndexCapability::index`; `None` where no projection serves.
    pub projection_coverage: [Option<u32>; 4],
}

fn micros(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

fn active_snapshot_base(
    role: ChainstateRole,
    status: &AssumeUtxoDiskStatus,
) -> Option<bitcoin_rs_consensus::primitives::Hash256> {
    match role {
        ChainstateRole::AssumedActive { base_hash, .. } => Some(base_hash),
        ChainstateRole::Ordinary => match status {
            AssumeUtxoDiskStatus::Finalized { base_hash, .. } => Some(*base_hash),
            _ => None,
        },
        ChainstateRole::Historical { .. } => None,
    }
}

fn observe_outputs(observer: &mut ScriptLiveSeedObserver<'_>, txid: Hash256, record: &UtxoRecord) {
    for output in record.outputs() {
        observer.observe_coin(SnapshotCoin {
            txid,
            vout: output.vout,
            value: output.value,
            script_pubkey: output.script_pubkey,
            height: output.height,
            coinbase: output.coinbase,
        });
    }
}

fn admit_seed(seed: Option<&ScriptLiveSeedSession>, refused: &mut Option<IndexError>) -> bool {
    match seed.and_then(ScriptLiveSeedSession::take_error) {
        Some(error) => {
            *refused = Some(error);
            false
        }
        None => true,
    }
}

fn ingest_error(error: SnapshotImportError) -> SnapshotImportError {
    match error {
        SnapshotImportError::Activation(AssumeUtxoError::ArtifactDigestMismatch {
            expected_sha256,
            found_sha256,
            expected_size,
            found_size,
        }) => SnapshotImportError::Manifest(if expected_sha256 == found_sha256 {
            bitcoin_rs_chain::manifest::ManifestError::ArtifactSizeMismatch {
                slot: bitcoin_rs_chain::manifest::UTXO_SLOT,
                declared: expected_size,
                actual: found_size,
            }
        } else {
            bitcoin_rs_chain::manifest::ManifestError::ArtifactHashMismatch {
                slot: bitcoin_rs_chain::manifest::UTXO_SLOT,
                declared: expected_sha256,
                actual: found_sha256,
            }
        }),
        other => codec_import_error(other),
    }
}

fn codec_import_error(error: SnapshotImportError) -> SnapshotImportError {
    match error {
        SnapshotImportError::Activation(AssumeUtxoError::Codec(error)) => {
            SnapshotImportError::Codec(error)
        }
        other => other,
    }
}

fn settle_seed(
    seed: Option<&ScriptLiveSeedSession>,
    outcome: Result<ActivatedSnapshot, SnapshotImportError>,
    refused: Option<IndexError>,
) -> Result<ActivatedSnapshot, SnapshotImportError> {
    let Some(session) = seed else {
        return outcome;
    };
    match outcome {
        Ok(activated) => {
            session.publish(IndexWatermark {
                height: activated.height,
                hash: activated.base_hash.to_le_bytes(),
            });
            Ok(activated)
        }
        Err(error) => {
            session.abort();
            Err(match refused {
                Some(seed_error) => SnapshotImportError::Seed(seed_error),
                None => error,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestError;
    use bitcoin_rs_storage::utxo::core_snapshot::{SnapshotError, read_and_verify};
    impl From<SnapshotExportError> for TestError {
        fn from(error: SnapshotExportError) -> Self {
            match error {
                SnapshotExportError::Codec(inner) => Self::from(inner),
                SnapshotExportError::Utxo(inner) => Self::from(inner),
                SnapshotExportError::Admission(inner) => Self::from(inner),
                SnapshotExportError::Output(inner)
                | SnapshotExportError::Write(inner)
                | SnapshotExportError::DirectorySync(inner) => Self::from(inner),
                SnapshotExportError::Interrupted => {
                    Self::Timeout("snapshot export runs to completion")
                }
                SnapshotExportError::ExportInProgress => {
                    Self::ExpectationFailed("no snapshot export permit is held")
                }
                SnapshotExportError::Exists(_) => {
                    Self::ExpectationFailed("the export target is new")
                }
                SnapshotExportError::OutputName
                | SnapshotExportError::NoAtomicPublish
                | SnapshotExportError::NoAppliedTip
                | SnapshotExportError::ChainTxCountUnknown
                | SnapshotExportError::Length { .. } => {
                    Self::ExpectationFailed("the export target is publishable")
                }
            }
        }
    }

    impl From<SnapshotControlError> for TestError {
        fn from(error: SnapshotControlError) -> Self {
            Self::Io(std::io::Error::other(error))
        }
    }

    #[test]
    fn active_origin_survives_failure_and_validated_provenance_survives_finalization() {
        let base = bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(&[7; 32]);
        let absent = bitcoin_rs_consensus::primitives::Hash256::default();
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

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn input_fifo_is_rejected_without_waiting_for_a_writer() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("input.pipe");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(std::io::Error::from)?;
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
        worker.join().map_err(|_| TestError::ThreadPanicked)?;
        Ok(())
    }

    fn node_config(dir: &Path) -> crate::NodeConfig {
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.join("node");
        config.p2p.listen.clear();
        config
    }

    fn core_headers() -> Result<Vec<bitcoin_rs_consensus::primitives::Header>, TestError> {
        let raw: Vec<String> = sonic_rs::from_str(include_str!(
            "../../../testdata/storage/fixtures/core-v2/blocks200.json"
        ))?;
        raw.iter()
            .map(|hex| {
                let block: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(hex)?;
                bitcoin_rs_consensus::primitives::deserialize(&bitcoin::consensus::serialize(
                    &block.header,
                ))
                .map_err(TestError::from)
            })
            .collect()
    }

    fn snapshot_inputs(dir: &Path) -> Result<(crate::state::NodeState, PathBuf), TestError> {
        snapshot_inputs_with(dir, |_| {})
    }

    fn snapshot_inputs_with(
        dir: &Path,
        configure: impl FnOnce(&mut crate::NodeConfig),
    ) -> Result<(crate::state::NodeState, PathBuf), TestError> {
        let mut config = node_config(dir);
        configure(&mut config);
        let state = crate::state::NodeState::open(config, None)?;
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            Network::Regtest.genesis_block(),
        ))?;
        state.chainstate().admit_headers(&core_headers()?)?;
        let core_bytes = include_bytes!("../../../testdata/storage/fixtures/core-v2/core200.dat");
        let core_path = dir.join("core.dat");
        std::fs::write(&core_path, core_bytes)?;
        Ok((state, core_path))
    }

    struct TamperOnRewind {
        bytes: Vec<u8>,
        position: usize,
        rewound: bool,
        flip_at: usize,
    }

    impl std::io::Read for TamperOnRewind {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let available = self.bytes.len().saturating_sub(self.position);
            let count = buf.len().min(available);
            let start = self.position;
            buf[..count].copy_from_slice(&self.bytes[start..start + count]);
            if self.rewound && (start..start + count).contains(&self.flip_at) {
                buf[self.flip_at - start] ^= 1;
            }
            self.position += count;
            Ok(count)
        }
    }

    impl std::io::Seek for TamperOnRewind {
        fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
            match from {
                std::io::SeekFrom::Start(to) => {
                    self.position = usize::try_from(to).map_err(std::io::Error::other)?;
                    self.rewound = true;
                }
                std::io::SeekFrom::Current(0) => {}
                _ => {
                    return Err(std::io::Error::other(
                        "tamper reader supports Start and Current(0)",
                    ));
                }
            }
            u64::try_from(self.position).map_err(std::io::Error::other)
        }
    }

    #[test]
    fn core_embedding_contract_and_shared_import_budget() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        {
            let _permit = state.snapshots.import.lock();
            assert!(matches!(
                state.snapshots.import(&core_path),
                Err(SnapshotImportError::ImportInProgress)
            ));
        }
        state.snapshots.import(&core_path)?;
        assert!(matches!(
            state.snapshots.import(&dir.path().join("missing.dat")),
            Err(SnapshotImportError::Activation(
                AssumeUtxoError::AlreadyActive
            ))
        ));
        let view = state.chainstates_summary()?;
        assert_eq!(view.active_chainstate.height, Some(200));
        assert!(!view.active_chainstate.validated);
        assert!(view.historical_chainstate.is_some());
        assert_eq!(std::fs::read(&core_path)?, core_bytes);
        Ok(())
    }

    // MPL-04, MPS-03, SNP-07
    #[test]
    fn successful_snapshot_import_preserves_nonresident_fee_prioritisation() -> Result<(), TestError>
    {
        use bitcoin_rs_consensus::primitives::{Hash256, Txid};
        use bitcoin_rs_mempool::PrioritisedTransaction;

        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
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
        let fee_sequence = gateway.read().fee_delta_sequence_number();
        assert_ne!(gateway.read().settled_at_commit(), 0);
        state.snapshots.import(&core_path)?;
        assert_eq!(
            gateway.prioritised_transactions(),
            expected,
            "successful import must preserve operator fee deltas"
        );
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), sequence);
        assert_eq!(gateway.read().fee_delta_sequence_number(), fee_sequence);
        assert_eq!(gateway.read().settled_at_commit(), 0);
        assert!(gateway.stable_generation().is_some());
        assert_eq!(
            state
                .chainstate()
                .applied_tip_snapshot()
                .map(|tip| tip.height),
            Some(200)
        );
        assert!(state.chainstate().role().is_assumed_active());
        Ok(())
    }

    // API-11, API-30, MPS-03, SNP-07, SYNC-05
    #[test]
    fn mining_resumes_after_snapshot_replaces_a_settled_tip() -> Result<(), TestError> {
        use bitcoin_rs_wire::mining::{
            BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, GenerateRequest,
            GenerateSelection, MiningControl,
        };

        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let mining = crate::mining::MiningCoordinator::new(
            state.mempool_reader(),
            state.chainstate(),
            state.stable_read(),
            state.chain_followers(),
            vec![0x51],
            state.config().mining.coinbase_reserve,
        );
        assert_ne!(state.mempool_gateway().read().settled_at_commit(), 0);
        state.snapshots.import(&core_path)?;
        let template = mining.get_block_template(BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
            coinbase_budget: None,
        })?;
        let BlockTemplateResult::Template(template) = template else {
            return Err(TestError::ExpectationFailed("snapshot mining template"));
        };
        assert_eq!(template.candidate.height, 201);
        for submit in [false, true] {
            let generated = mining.generate(GenerateRequest {
                payout: vec![0x51],
                count: 1,
                max_tries: GenerateRequest::DEFAULT_MAX_TRIES,
                selection: GenerateSelection::Mempool,
                submit,
            })?;
            assert_eq!(generated.len(), 1);
            assert_eq!(
                state
                    .chainstate()
                    .applied_tip_snapshot()
                    .map(|tip| tip.height),
                Some(if submit { 201 } else { 200 })
            );
            assert!(state.mempool_gateway().stable_generation().is_some());
        }
        assert_ne!(state.mempool_gateway().read().settled_at_commit(), 0);
        Ok(())
    }

    // MPS-03, SNP-07, SYNC-04
    #[test]
    fn snapshot_settlement_refusal_after_durable_activation_keeps_admission_closed()
    -> Result<(), TestError> {
        use bitcoin_rs_consensus::primitives::{
            Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
        };
        use bitcoin_rs_mempool::{AdmissionOrigin, ChainChangeError, MempoolEntry, SubmitError};
        use bitcoin_rs_wire::context::ChainAdmissionView;

        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let pinned = regtest_pin()?;
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
        let before_commit = gateway.read().settled_at_commit();
        let before_sequence = gateway.read().sequence_number();
        assert_ne!(before_commit, 0);
        assert!(gateway.read().is_empty());
        assert!(gateway.stable_generation().is_some());
        assert_eq!(tip_identity(&state).map(|tip| tip.0), Some(0));
        let mut input = BufReader::new(std::fs::File::open(&core_path)?);
        let mut inserted = None;
        let result = state.snapshots.activate(|manager| {
            let activated =
                manager.activate_core_snapshot(&mut input, None, |_, _| {}, || true)?;
            assert_eq!(tip_identity(&state), Some((pinned.height, pinned.block_hash)));
            assert!(gateway.stable_generation().is_none());
            inserted = Some(gateway.insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::clone(&transaction), 100, 1_000, 0, 0, 0),
            ));
            Ok(activated)
        });
        inserted.ok_or(TestError::Missing("post-activation mempool mutation"))??;
        assert!(matches!(
            result,
            Err(SnapshotImportError::Settlement(
                ChainChangeError::SnapshotMempoolNotEmpty
            ))
        ));
        assert!(state.chainstate().is_closed_for_recovery());
        assert_eq!(gateway.stable_generation(), None);
        assert!(matches!(
            gateway.begin_chain_change(),
            Err(ChainChangeError::AlreadyActive)
        ));
        assert!(gateway.read().contains_txid(&transaction.txid()));
        assert_eq!(gateway.read().sequence_number(), before_sequence + 1);
        assert_eq!(gateway.read().settled_at_commit(), before_commit);
        let chainstate = state.chainstate();
        let admission = ChainAdmissionView::new(
            chainstate.utxo_reader(),
            chainstate.applied_tip_reader(),
            chainstate.block_tree_reader(),
            chainstate.network(),
        );
        assert_eq!(
            gateway.submit_transaction(
                Arc::clone(&transaction),
                AdmissionOrigin::Rpc,
                None,
                0,
                &admission,
            ),
            Err(SubmitError::RetryExhausted)
        );
        let identity = validating_identity(&state.snapshots.manager.status()?)?;
        assert_eq!(identity.1, pinned.block_hash);
        assert_eq!(tip_identity(&state), Some((pinned.height, pinned.block_hash)));
        assert!(state.chainstate().role().is_assumed_active());
        assert!(matches!(
            state.snapshots.import(&core_path),
            Err(SnapshotImportError::Activation(AssumeUtxoError::AlreadyActive))
        ));
        assert_eq!(gateway.stable_generation(), None);
        drop(admission);
        drop(chainstate);
        drop(gateway);
        drop(state);

        let resumed = crate::state::NodeState::open(node_config(dir.path()), None)?;
        assert_eq!(tip_identity(&resumed), Some((pinned.height, pinned.block_hash)));
        assert_eq!(
            validating_identity(&resumed.snapshots.manager.status()?)?,
            identity
        );
        assert!(!resumed.chainstate().is_closed_for_recovery());
        assert!(resumed.mempool_gateway().stable_generation().is_some());
        let coins = reconstruct_utxo_set(&resumed)?;
        assert_eq!(
            coins.with_stable_view(|view| view.hash_serialized_3_at_height(pinned.height))?,
            pinned.hash_serialized
        );
        Ok(())
    }

    #[test]
    fn nonempty_mempool_refuses_import_without_changing_state() -> Result<(), TestError> {
        use bitcoin_rs_consensus::primitives::{
            Amount, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
        };
        use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry};

        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
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
        let result = state.snapshots.import(&core_path).map(|_| ());
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
        gateway.clear(AdmissionOrigin::Rpc)?;
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

    fn entry_names(dir: &Path) -> Result<Vec<String>, TestError> {
        let mut names = std::fs::read_dir(dir)?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        names.sort();
        Ok(names)
    }

    #[test]
    fn export_reproduces_the_core_snapshot_and_never_replaces_an_entry() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        state.snapshots.import(&core_path)?;
        let core_bytes = std::fs::read(&core_path)?;
        let pin = Network::Regtest
            .assume_utxo_for_height(200)
            .ok_or(TestError::Missing("compiled regtest 200-height pin"))?;
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
        Ok(())
    }

    #[test]
    fn interrupted_export_publishes_nothing_and_removes_its_staged_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        state.snapshots.import(&core_path)?;
        let out = dir.path().join("out");
        std::fs::create_dir(&out)?;
        let output = out.join("interrupted.dat");

        let cancelled = {
            let trigger = bitcoin_rs_consensus::latch::LatchWriter::new();
            trigger.trigger();
            trigger.reader()
        };
        assert!(matches!(
            state.snapshots.export(&output, &cancelled),
            Err(SnapshotExportError::Interrupted)
        ));
        assert_eq!(entry_names(&out)?, Vec::<String>::new());

        let polls = std::cell::Cell::new(0_u32);
        let stop = || {
            polls.set(polls.get() + 1);
            polls.get() > 1
        };
        let error = state
            .snapshots
            .export_until(&output, &stop)
            .err()
            .ok_or(TestError::UnexpectedSuccess("interrupted export succeeded"))?;
        assert!(matches!(
            error,
            SnapshotExportError::Codec(SnapshotError::Interrupted)
        ));
        assert!(matches!(
            SnapshotControlError::from(error),
            SnapshotControlError::Interrupted
        ));
        assert_eq!(entry_names(&out)?, Vec::<String>::new());

        state
            .snapshots
            .export(&output, &LatchReader::fixture_never())?;
        assert_eq!(entry_names(&out)?, ["interrupted.dat"]);

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
    fn stale_same_pid_temp_does_not_block_a_new_export() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        state.snapshots.import(&core_path)?;
        let out = dir.path().join("out");
        std::fs::create_dir(&out)?;
        let stale = out.join(format!("export.dat.{}.incomplete", std::process::id()));
        std::fs::write(&stale, b"stale")?;
        let output = out.join("export.dat");

        let exported = state
            .snapshots
            .export(&output, &LatchReader::fixture_never())?;
        assert_eq!(
            exported.path,
            output.canonicalize()?.to_string_lossy().into_owned()
        );
        assert_eq!(std::fs::read(&stale)?, b"stale");
        assert!(output.is_file());
        let names = entry_names(&out)?;
        assert!(names.contains(&"export.dat".to_string()));
        assert!(
            names.contains(
                &stale
                    .file_name()
                    .ok_or(TestError::Missing("stale file name"))?
                    .to_string_lossy()
                    .into_owned()
            )
        );
        assert_eq!(
            names
                .iter()
                .filter(|name| name.ends_with(".incomplete"))
                .count(),
            1,
            "the new export publishes without leaving its own staged file"
        );
        Ok(())
    }

    #[test]
    fn concurrent_export_is_refused_while_the_permit_is_held() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        state.snapshots.import(&core_path)?;
        let output = dir.path().join("busy.dat");
        {
            let _permit = state.snapshots.export.lock();
            let error = state
                .snapshots
                .export(&output, &LatchReader::fixture_never())
                .err()
                .ok_or(TestError::UnexpectedSuccess("held permit allowed export"))?;
            assert!(matches!(error, SnapshotExportError::ExportInProgress));
            assert!(matches!(
                SnapshotControlError::from(error),
                SnapshotControlError::Unavailable(_)
            ));
        }
        assert!(!output.exists());
        Ok(())
    }

    fn regtest_pin() -> Result<&'static bitcoin_rs_consensus::primitives::AssumeUtxoData, TestError>
    {
        Network::Regtest
            .assume_utxo_for_height(200)
            .ok_or(TestError::Missing("regtest height-200 anchor"))
    }

    type ValidatingIdentity = (
        u32,
        bitcoin_rs_consensus::primitives::Hash256,
        bitcoin_rs_consensus::primitives::Hash256,
        u64,
    );

    fn validating_identity(status: &AssumeUtxoDiskStatus) -> Result<ValidatingIdentity, TestError> {
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
            _ => Err(TestError::ExpectationFailed(
                "validating assumeutxo lifecycle",
            )),
        }
    }

    fn tip_identity(
        state: &crate::state::NodeState,
    ) -> Option<(u32, bitcoin_rs_consensus::primitives::Hash256)> {
        state
            .chainstate()
            .applied_tip_snapshot()
            .map(|tip| (tip.height, tip.hash))
    }

    fn reconstruct_utxo_set(
        state: &crate::state::NodeState,
    ) -> Result<bitcoin_rs_storage::utxo::UtxoSet, TestError> {
        let coin_store = state.coins();
        let snapshot = coin_store.store().snapshot()?;
        let coins = bitcoin_rs_storage::utxo::UtxoSet::new();
        for row in snapshot.iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])? {
            let (_key, value) = row?;
            coins.insert_parsed_record(
                bitcoin_rs_storage::utxo::UtxoRecord::from_encoded(value.into_boxed_slice())
                    .map_err(TestError::Utxo)?,
            );
        }
        Ok(coins)
    }

    #[test]
    fn sealed_activation_installs_state_and_survives_restart() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        state.snapshots.import(&core_path)?;
        let stats = state.chainstate().coin_stats_handle().snapshot();
        let coins = reconstruct_utxo_set(&state)?;
        let (commitment, mut scanned) = coins.with_stable_view(|view| {
            Ok::<_, TestError>((
                view.hash_serialized_3_at_height(pinned.height)?,
                bitcoin_rs_storage::utxo::stats::scan_coin_stats(view, pinned.height, true)?,
            ))
        })?;
        assert_eq!(commitment, pinned.hash_serialized);
        scanned.tx_count = pinned.chain_tx_count;
        assert_eq!(
            stats.to_bytes(),
            scanned.to_bytes(),
            "installed statistics equal an independent scan"
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
            "restart recomputation agrees with installed statistics"
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
        Ok(())
    }

    #[test]
    fn wrong_commitment_changes_nothing_and_a_valid_retry_activates() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let mut forged = std::fs::read(&core_path)?;
        *forged
            .last_mut()
            .ok_or(TestError::Missing("snapshot fixture bytes"))? ^= 1;
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

    // SNP-07
    #[test]
    fn truncated_snapshot_installs_no_coins_and_stays_uninitialized() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let truncated_path = dir.path().join("truncated.dat");
        std::fs::write(&truncated_path, &core_bytes[..core_bytes.len() / 2])?;
        let before_tip = state.chainstate().applied_tip_snapshot();
        let before_stats = state.chainstate().coin_stats_handle().snapshot();
        let before_coverage = state.three_positions()?.projection_coverage;
        assert!(matches!(
            state.snapshots.import(&truncated_path),
            Err(SnapshotImportError::Codec(SnapshotError::Truncated { .. }))
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
        assert_eq!(
            state.three_positions()?.projection_coverage,
            before_coverage,
            "a failed snapshot import must not publish index coverage"
        );
        assert_eq!(
            state.three_positions()?.projection_coverage,
            [None, None, None, None],
            "no projection claims coverage without a verified commitment"
        );
        assert!(
            !dir.path().join("node/assumeutxo").exists(),
            "a failed snapshot import must leave no assumeutxo directory"
        );
        let staged = match state.snapshots.script_live_seed.as_ref() {
            Some(seed) => seed.staged_rows(),
            None => 0,
        };
        assert_eq!(
            staged, 0,
            "a failed snapshot import must leave no staged seed rows"
        );
        Ok(())
    }

    // SNP-07
    #[test]
    fn trailing_snapshot_bytes_install_no_coins_and_stay_uninitialized() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let mut trailing = std::fs::read(&core_path)?;
        trailing.push(0);
        let trailing_path = dir.path().join("trailing.dat");
        std::fs::write(&trailing_path, &trailing)?;
        let before_tip = state.chainstate().applied_tip_snapshot();
        let before_stats = state.chainstate().coin_stats_handle().snapshot();
        let before_coverage = state.three_positions()?.projection_coverage;
        assert!(matches!(
            state.snapshots.import(&trailing_path),
            Err(SnapshotImportError::Codec(SnapshotError::TrailingBytes))
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
        assert_eq!(
            state.three_positions()?.projection_coverage,
            before_coverage,
            "a failed snapshot import must not publish index coverage"
        );
        assert_eq!(
            state.three_positions()?.projection_coverage,
            [None, None, None, None],
            "no projection claims coverage without a verified commitment"
        );
        assert!(
            !dir.path().join("node/assumeutxo").exists(),
            "a failed snapshot import must leave no assumeutxo directory"
        );
        let staged = match state.snapshots.script_live_seed.as_ref() {
            Some(seed) => seed.staged_rows(),
            None => 0,
        };
        assert_eq!(
            staged, 0,
            "a failed snapshot import must leave no staged seed rows"
        );
        Ok(())
    }

    #[test]
    fn interrupted_activation_fails_closed_and_restart_retries_cleanly() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let checkpoints = dir.path().join("node/chainstate-checkpoints");
        std::fs::write(&checkpoints, b"obstruction")?;
        let before_tip = tip_identity(&state);
        assert!(before_tip.is_some());
        assert!(matches!(
            state.snapshots.import(&core_path),
            Err(SnapshotImportError::Activation(
                AssumeUtxoError::ActivationCheckpointPublish { .. }
            ))
        ));
        assert!(state.chainstate().is_closed_for_recovery());
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
        assert_eq!(tip_identity(&state), before_tip);
        assert!(!dir.path().join("node/assumeutxo").exists());
        assert!(
            !checkpoints.join("CURRENT").is_file(),
            "a failed checkpoint publication writes no CURRENT"
        );
        drop(state);

        std::fs::remove_file(&checkpoints)?;
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
        let current = dir.path().join("node/chainstate-checkpoints/CURRENT");
        assert!(current.is_file(), "activation publishes the checkpoint");
        let stats = resumed.chainstate().coin_stats_handle().snapshot();
        let coins = reconstruct_utxo_set(&resumed)?;
        let commitment =
            coins.with_stable_view(|view| view.hash_serialized_3_at_height(pinned.height))?;
        assert_eq!(commitment, pinned.hash_serialized);
        assert_eq!(stats.tx_count, pinned.chain_tx_count);
        drop(resumed);
        let restarted = crate::state::NodeState::open(node_config(dir.path()), None)?;
        assert_eq!(tip_identity(&restarted), Some((200, pinned.block_hash)));
        assert_eq!(
            restarted
                .chainstate()
                .coin_stats_handle()
                .snapshot()
                .to_bytes(),
            stats.to_bytes(),
            "restart resumes at the base from the published checkpoint"
        );
        Ok(())
    }

    struct SnapshotActivationKill {
        ready: PathBuf,
    }

    impl bitcoin_rs_storage::commit::CommitFault for SnapshotActivationKill {
        fn before_commit(
            &self,
            prefix: &bitcoin_rs_storage::commit::AcceptedPrefix,
        ) -> Result<(), bitcoin_rs_storage::CommitError> {
            if matches!(
                prefix.next_head.assumeutxo,
                AssumeUtxoDiskStatus::Validating { .. }
            ) {
                std::fs::write(&self.ready, b"ready").map_err(|error| {
                    bitcoin_rs_storage::CommitError::Storage(
                        bitcoin_rs_storage::StorageError::backend(error.to_string()),
                    )
                })?;
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        }
    }

    #[test]
    fn snapshot_activation_crash_worker() -> Result<(), TestError> {
        let Some(dir) = std::env::var_os("BITCOIN_RS_SNAPSHOT_KILL_DIR") else {
            return Ok(());
        };
        let dir = std::path::PathBuf::from(dir);
        let (state, core_path) = snapshot_inputs(&dir)?;
        state
            .chainstate()
            .set_commit_fault(std::sync::Arc::new(SnapshotActivationKill {
                ready: dir.join("kill-ready"),
            }));
        state.snapshots.import(&core_path)?;
        Err(TestError::UnexpectedSuccess(
            "activation kill fault was not reached",
        ))
    }

    #[test]
    fn process_kill_between_checkpoint_publish_and_head_commit_restarts_cold()
    -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "snapshot::tests::snapshot_activation_crash_worker",
                "--nocapture",
            ])
            .env("BITCOIN_RS_SNAPSHOT_KILL_DIR", dir.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !dir.path().join("kill-ready").exists() && std::time::Instant::now() < deadline {
            if let Some(status) = child.try_wait()? {
                return Err(TestError::message(format!(
                    "activation crash child exited before the head commit: {status}"
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !dir.path().join("kill-ready").exists() {
            child.kill()?;
            child.wait()?;
            return Err(TestError::Timeout(
                "activation crash child never reached the head commit",
            ));
        }
        child.kill()?;
        child.wait()?;
        let cs_store = bitcoin_rs_storage::RocksDbStore::open(dir.path().join("node/chainstate"))?;
        let raw = bitcoin_rs_storage::KvStore::get(
            &cs_store,
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            bitcoin_rs_storage::durable_head::DURABLE_HEAD_KEY,
        )?
        .ok_or(TestError::Missing("post-kill durable head missing"))?;
        let actual = bitcoin_rs_storage::durable_head::DurableHead::decode(&raw)
            .ok_or(TestError::Missing("post-kill durable head undecodable"))?;
        let marker_bytes = bitcoin_rs_storage::KvStore::get(
            &cs_store,
            bitcoin_rs_storage::ColumnFamily::UtxoMeta,
            bitcoin_rs_storage::SNAPSHOT_ACTIVATION_KEY,
        )?;
        let marker = marker_bytes
            .as_deref()
            .and_then(bitcoin_rs_storage::SnapshotActivationMarker::decode);
        drop(cs_store);
        assert_eq!(actual.height, 0);
        assert_eq!(actual.tip, Network::Regtest.genesis_block_hash());
        let prepared = bitcoin_rs_chain::recovery::prepare_initial_state_with_engine(
            &dir.path().join("node"),
            Network::Regtest,
            Some(&actual),
            marker.as_ref(),
        )
        .map_err(|error| TestError::Recovery(Box::new(error)))?;
        assert!(
            matches!(
                prepared.initial.resume_source,
                bitcoin_rs_chain::recovery::ResumeSource::Cold
            ),
            "a kill between checkpoint publish and head commit must restore cold"
        );
        let resumed = crate::state::NodeState::open(node_config(dir.path()), None)?;
        assert_eq!(
            tip_identity(&resumed),
            Some((0, Network::Regtest.genesis_block_hash()))
        );
        assert!(matches!(
            resumed.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert_eq!(resumed.chainstate().role(), ChainstateRole::Ordinary);
        assert!(
            !dir.path()
                .join("node/chainstate-checkpoints/CURRENT")
                .exists(),
            "the rollback removes the checkpoint no head names"
        );
        resumed.chainstate().admit_headers(&core_headers()?)?;
        let core_path = dir.path().join("core.dat");
        resumed.snapshots.import(&core_path)?;
        assert_eq!(tip_identity(&resumed), Some((200, pinned.block_hash)));
        let current = dir.path().join("node/chainstate-checkpoints/CURRENT");
        assert!(current.is_file(), "activation publishes the checkpoint");
        let stats = resumed.chainstate().coin_stats_handle().snapshot();
        let coins = reconstruct_utxo_set(&resumed)?;
        let commitment =
            coins.with_stable_view(|view| view.hash_serialized_3_at_height(pinned.height))?;
        assert_eq!(commitment, pinned.hash_serialized);
        assert_eq!(stats.tx_count, pinned.chain_tx_count);
        drop(resumed);
        let restarted = crate::state::NodeState::open(node_config(dir.path()), None)?;
        assert_eq!(tip_identity(&restarted), Some((200, pinned.block_hash)));
        assert_eq!(
            restarted
                .chainstate()
                .coin_stats_handle()
                .snapshot()
                .to_bytes(),
            stats.to_bytes(),
            "restart resumes at the base from the published checkpoint"
        );
        Ok(())
    }

    fn write_manifest_bytes(
        dir: &Path,
        base_height: u32,
        base_hash: [u8; 32],
        utxo_commitment: [u8; 32],
        core_bytes: &[u8],
    ) -> Result<PathBuf, TestError> {
        use bitcoin_rs_chain::manifest::{ARTIFACT_SLOTS, SnapshotManifest, UTXO_SLOT};
        use sha2::Digest;

        let mut sizes = [0_u64; ARTIFACT_SLOTS];
        let mut hashes = [[0_u8; 32]; ARTIFACT_SLOTS];
        sizes[UTXO_SLOT] =
            u64::try_from(core_bytes.len()).map_err(|e| TestError::Io(std::io::Error::other(e)))?;
        hashes[UTXO_SLOT] = sha2::Sha256::digest(core_bytes).into();

        let manifest = SnapshotManifest {
            manifest_version: 1,
            network: "regtest".to_string(),
            genesis: Network::Regtest.genesis_block_hash().to_le_bytes(),
            base_hash,
            base_height,
            schema: bitcoin_rs_index::index_format_version(),
            utxo_commitment,
            index_commitments: [None; 4],
            coverage: [None; 4],
            sizes,
            hashes,
            historical_verified_height: 0,
        };
        let manifest_path = dir.join("snapshot_manifest.json");
        std::fs::write(&manifest_path, sonic_rs::to_vec_pretty(&manifest)?)?;
        Ok(manifest_path)
    }

    fn write_manifest_with_utxo_digest(
        dir: &Path,
        pinned: &bitcoin_rs_consensus::primitives::AssumeUtxoData,
        core_bytes: &[u8],
        utxo_digest: [u8; 32],
    ) -> Result<PathBuf, TestError> {
        use bitcoin_rs_chain::manifest::{ARTIFACT_SLOTS, SnapshotManifest, UTXO_SLOT};

        let mut sizes = [0_u64; ARTIFACT_SLOTS];
        let mut hashes = [[0_u8; 32]; ARTIFACT_SLOTS];
        sizes[UTXO_SLOT] =
            u64::try_from(core_bytes.len()).map_err(|e| TestError::Io(std::io::Error::other(e)))?;
        hashes[UTXO_SLOT] = utxo_digest;

        let manifest = SnapshotManifest {
            manifest_version: 1,
            network: "regtest".to_string(),
            genesis: Network::Regtest.genesis_block_hash().to_le_bytes(),
            base_hash: pinned.block_hash.to_le_bytes(),
            base_height: pinned.height,
            schema: bitcoin_rs_index::index_format_version(),
            utxo_commitment: pinned.hash_serialized.to_le_bytes(),
            index_commitments: [None; 4],
            coverage: [None; 4],
            sizes,
            hashes,
            historical_verified_height: 0,
        };
        let manifest_path = dir.join("snapshot_manifest.json");
        std::fs::write(&manifest_path, sonic_rs::to_vec_pretty(&manifest)?)?;
        Ok(manifest_path)
    }

    fn write_valid_manifest(
        dir: &Path,
        pinned: &bitcoin_rs_consensus::primitives::AssumeUtxoData,
        core_bytes: &[u8],
    ) -> Result<PathBuf, TestError> {
        write_manifest_bytes(
            dir,
            pinned.height,
            pinned.block_hash.to_le_bytes(),
            pinned.hash_serialized.to_le_bytes(),
            core_bytes,
        )
    }

    fn write_manifest_with_mismatched_index_artifact(
        dir: &Path,
        pinned: &bitcoin_rs_consensus::primitives::AssumeUtxoData,
        core_bytes: &[u8],
    ) -> Result<PathBuf, TestError> {
        use bitcoin_rs_chain::manifest::{ARTIFACT_SLOTS, SnapshotManifest, UTXO_SLOT};
        use sha2::Digest;

        let mut sizes = [0_u64; ARTIFACT_SLOTS];
        let mut hashes = [[0_u8; 32]; ARTIFACT_SLOTS];
        sizes[UTXO_SLOT] =
            u64::try_from(core_bytes.len()).map_err(|e| TestError::Io(std::io::Error::other(e)))?;
        hashes[UTXO_SLOT] = sha2::Sha256::digest(core_bytes).into();

        let fake_bytes = b"invalid artifact bytes";
        std::fs::write(dir.join("txlookup.artifact"), fake_bytes)?;
        sizes[1] =
            u64::try_from(fake_bytes.len()).map_err(|e| TestError::Io(std::io::Error::other(e)))?;
        hashes[1] = [0xee; 32];

        let mut index_commitments = [None; 4];
        index_commitments[0] = Some(bitcoin_rs_chain::manifest::ManifestIndexCommitment {
            sha256: [0xee; 32],
            size_bytes: sizes[1],
        });

        let manifest = SnapshotManifest {
            manifest_version: 1,
            network: "regtest".to_string(),
            genesis: Network::Regtest.genesis_block_hash().to_le_bytes(),
            base_hash: pinned.block_hash.to_le_bytes(),
            base_height: pinned.height,
            schema: bitcoin_rs_index::index_format_version(),
            utxo_commitment: pinned.hash_serialized.to_le_bytes(),
            index_commitments,
            coverage: [None; 4],
            sizes,
            hashes,
            historical_verified_height: 0,
        };
        let json_bytes = sonic_rs::to_vec_pretty(&manifest)?;
        let manifest_path = dir.join("snapshot_manifest.json");
        std::fs::write(&manifest_path, json_bytes)?;
        Ok(manifest_path)
    }

    // SNP-01, SNP-05, SNP-08
    #[test]
    fn node_from_manifest_serves_covered_queries_before_historical_sync() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let manifest_path = write_valid_manifest(dir.path(), pinned, &core_bytes)?;

        let import = state.import_manifest(&manifest_path)?;
        assert_eq!(import.base_height, pinned.height);
        assert_eq!(import.tip_hash, pinned.block_hash.to_string_be());
        assert_eq!(import.coins_loaded, 200);

        assert_eq!(
            state.chainstate().role(),
            ChainstateRole::AssumedActive {
                base_height: pinned.height,
                base_hash: pinned.block_hash,
            }
        );
        assert_eq!(
            tip_identity(&state),
            Some((pinned.height, pinned.block_hash))
        );

        let status = state.snapshots.manager.status()?;
        assert!(matches!(
            status,
            AssumeUtxoDiskStatus::Validating {
                base_height: 200,
                historical_height: 0,
                ..
            }
        ));

        let mut coin_rows = 0_usize;
        for row in state
            .chainstate()
            .coins()
            .store()
            .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        {
            row?;
            coin_rows += 1;
        }
        assert_eq!(coin_rows, 200);

        let stats = state.chainstate().coin_stats_handle().snapshot();
        assert_eq!(stats.utxo_count, 200);
        assert_eq!(stats.total_amount, 872500000000);

        Ok(())
    }
    // SNP-10
    #[test]
    fn bad_index_artifact_keeps_the_coin_store_import() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let manifest_path =
            write_manifest_with_mismatched_index_artifact(dir.path(), pinned, &core_bytes)?;

        let result = state
            .import_manifest(&manifest_path)
            .map(|_| ())
            .map_err(|error| error.to_string());
        assert!(
            result.is_ok(),
            "an index artifact failure blocked the UTXO bootstrap: {result:?}"
        );
        assert_eq!(
            state.chainstates_summary()?.active_chainstate.height,
            Some(pinned.height)
        );
        let mut coin_rows = 0_usize;
        for row in state
            .chainstate()
            .coins()
            .store()
            .iter_prefix(bitcoin_rs_storage::ColumnFamily::Coins, &[])?
        {
            row?;
            coin_rows += 1;
        }
        assert_eq!(coin_rows, 200);
        Ok(())
    }

    // SNP-10
    #[test]
    fn failed_txlookup_artifact_leaves_the_chainstate_open_and_serving() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (mut state, core_path) = snapshot_inputs_with(dir.path(), |config| {
            config.indexes.txindex = true;
            config.indexes.script_index = crate::config::ScriptIndexMode::Utxo;
        })?;
        let core_bytes = std::fs::read(&core_path)?;
        let manifest_path =
            write_manifest_with_mismatched_index_artifact(dir.path(), pinned, &core_bytes)?;
        state.start_index_workers()?;
        let script_live =
            bitcoin_rs_consensus::primitives::IndexArtifactCapability::ScriptLive.index();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let claimed = state.three_positions()?.projection_coverage[script_live];
            if claimed.is_some() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the ScriptLive worker claimed no coverage within 120s"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let before = state.three_positions()?;
        assert!(
            before.projection_coverage[script_live].is_some(),
            "ScriptLive holds coverage before the TxLookup failure"
        );

        state.import_manifest(&manifest_path)?;

        assert!(
            !state.chainstate().is_closed_for_recovery(),
            "a failed index artifact must not close the chainstate"
        );
        assert_eq!(
            state.chainstates_summary()?.active_chainstate.height,
            Some(pinned.height)
        );
        assert_eq!(
            state
                .chainstate()
                .applied_tip_snapshot()
                .map(|tip| tip.height),
            Some(pinned.height),
            "the chainstate keeps serving its applied tip"
        );
        let after = state.three_positions()?;
        assert!(
            after.projection_coverage[script_live].is_some(),
            "ScriptLive still holds coverage after the TxLookup failure"
        );
        assert_eq!(
            after.projection_coverage[script_live], before.projection_coverage[script_live],
            "the ScriptLive capability keeps its coverage when TxLookup fails"
        );
        Ok(())
    }

    // SNP-09
    #[test]
    fn three_positions_move_independently() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let manifest_path = write_valid_manifest(dir.path(), pinned, &core_bytes)?;

        state.import_manifest(&manifest_path)?;
        let p0 = state.three_positions()?;
        assert_eq!(p0.active_chain_height, 200);
        assert_eq!(p0.historical_validation_height, 0);
        assert_ne!(p0.active_chain_height, p0.historical_validation_height);

        let child = bitcoin_rs_chain::chain::regtest_fixture::mined_regtest_child_at(
            bitcoin_rs_consensus::primitives::BlockHash::from(pinned.block_hash),
            201,
        )?;
        state.chainstate().admit_headers(&[child.header])?;
        state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
            child,
        ))?;

        let p1 = state.three_positions()?;
        assert_eq!(p1.active_chain_height, 201);
        assert_eq!(p1.historical_validation_height, 0);
        assert_ne!(p1.active_chain_height, p0.active_chain_height);
        assert_eq!(
            p1.historical_validation_height,
            p0.historical_validation_height
        );

        let genesis = bitcoin_rs_consensus::primitives::BlockImage::from_local(
            Network::Regtest.genesis_block(),
        );
        state.snapshots.manager.step_historical(&genesis)?;

        let raw: Vec<String> = sonic_rs::from_str(include_str!(
            "../../../testdata/storage/fixtures/core-v2/blocks200.json"
        ))?;
        let block1: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(&raw[0])?;
        let block1_image = bitcoin_rs_consensus::primitives::BlockImage::from_raw(
            bytes::Bytes::from(bitcoin::consensus::serialize(&block1)),
        )?;
        state.snapshots.manager.step_historical(&block1_image)?;

        let p2 = state.three_positions()?;
        assert_eq!(p2.active_chain_height, 201);
        assert_eq!(p2.historical_validation_height, 1);
        assert_eq!(p2.active_chain_height, p1.active_chain_height);
        assert_ne!(
            p2.historical_validation_height,
            p1.historical_validation_height
        );
        assert_eq!(
            p2.projection_coverage,
            [None, None, None, None],
            "no projection worker runs, so no projection claims coverage"
        );

        Ok(())
    }

    // SNP-02
    #[test]
    fn an_oversized_manifest_is_refused_before_activation() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let manifest_path = write_valid_manifest(dir.path(), pinned, &core_bytes)?;
        let mut json = std::fs::read(&manifest_path)?;
        let closing = json
            .pop()
            .ok_or(TestError::Missing("manifest closing brace"))?;
        if closing != b'}' {
            return Err(TestError::ExpectationFailed(
                "manifest JSON ends with a brace",
            ));
        }
        json.extend_from_slice(b",\"filler\":\"");
        json.extend(std::iter::repeat_n(b' ', 1 << 21));
        json.extend_from_slice(b"\"}");
        std::fs::write(&manifest_path, &json)?;

        let result = state.import_manifest(&manifest_path);
        assert!(matches!(
            result,
            Err(SnapshotImportError::Manifest(
                bitcoin_rs_chain::manifest::ManifestError::Format("manifest is larger than 1 MiB")
            ))
        ));
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
        Ok(())
    }

    // SNP-10
    #[test]
    fn manifest_utxo_digest_is_checked_in_the_ingest_pass() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let manifest_path =
            write_manifest_with_utxo_digest(dir.path(), pinned, &core_bytes, [0xab; 32])?;
        let before_tip = tip_identity(&state);
        assert!(matches!(
            state.import_manifest(&manifest_path),
            Err(SnapshotImportError::Manifest(
                bitcoin_rs_chain::manifest::ManifestError::ArtifactHashMismatch { slot: 0, .. }
            ))
        ));
        assert!(
            state.chainstate().is_closed_for_recovery(),
            "a digest mismatch found in the ingest pass fails closed"
        );
        assert_eq!(tip_identity(&state), before_tip);
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        Ok(())
    }

    #[test]
    fn ingest_pass_file_swap_after_the_verification_pass_fails_closed() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let attestation = bitcoin_rs_chain::assumeutxo::FileAttestation {
            sha256: {
                use sha2::Digest;
                sha2::Sha256::digest(&core_bytes).into()
            },
            size: u64::try_from(core_bytes.len())?,
        };
        let mut reader = TamperOnRewind {
            bytes: core_bytes.clone(),
            position: 0,
            rewound: false,
            flip_at: core_bytes.len() / 2,
        };
        assert!(
            state
                .snapshots
                .manager
                .activate_core_snapshot(&mut reader, Some(attestation), |_, _| {}, || true)
                .is_err()
        );
        assert!(state.chainstate().is_closed_for_recovery());
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        Ok(())
    }

    // SNP-02
    #[test]
    fn a_manifest_on_a_foreign_schema_is_refused_at_activation() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let manifest_path = write_valid_manifest(dir.path(), pinned, &core_bytes)?;
        let mut manifest: bitcoin_rs_chain::manifest::SnapshotManifest =
            sonic_rs::from_slice(&std::fs::read(&manifest_path)?)?;
        manifest.schema = 1;
        let foreign = dir.path().join("foreign_schema_manifest.json");
        std::fs::write(&foreign, sonic_rs::to_vec(&manifest)?)?;

        let result = state.import_manifest(&foreign);
        assert!(matches!(
            result,
            Err(SnapshotImportError::Manifest(
                bitcoin_rs_chain::manifest::ManifestError::SchemaMismatch { found: 1, .. }
            ))
        ));
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
        Ok(())
    }

    // SNP-03
    #[test]
    fn a_snapshot_file_from_another_base_is_refused_before_activation() -> Result<(), TestError> {
        let other = Network::Regtest
            .assume_utxo_for_height(110)
            .ok_or(TestError::Missing("regtest height-110 anchor"))?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let manifest_path = write_manifest_bytes(
            dir.path(),
            other.height,
            other.block_hash.to_le_bytes(),
            other.hash_serialized.to_le_bytes(),
            &core_bytes,
        )?;

        let result = state.import_manifest(&manifest_path);
        assert!(matches!(
            result,
            Err(SnapshotImportError::Manifest(
                bitcoin_rs_chain::manifest::ManifestError::SnapshotBaseMismatch {
                    expected_height: 110,
                    found_height: 200,
                    ..
                }
            ))
        ));
        assert!(matches!(
            state.snapshots.manager.status()?,
            AssumeUtxoDiskStatus::Uninitialized
        ));
        assert_eq!(state.chainstate().role(), ChainstateRole::Ordinary);
        Ok(())
    }

    // SNP-07
    #[test]
    fn reopening_with_the_manifest_configuration_succeeds() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let mut config = node_config(dir.path());
        let manifest_path = {
            let state = crate::state::NodeState::open(config.clone(), None)?;
            state.apply_block(&bitcoin_rs_consensus::primitives::BlockImage::from_local(
                Network::Regtest.genesis_block(),
            ))?;
            state.chainstate().admit_headers(&core_headers()?)?;
            let core_path = dir.path().join("core.dat");
            std::fs::write(
                &core_path,
                include_bytes!("../../../testdata/storage/fixtures/core-v2/core200.dat"),
            )?;
            let core_bytes = std::fs::read(&core_path)?;
            let manifest_path = write_valid_manifest(dir.path(), pinned, &core_bytes)?;
            state.import_manifest(&manifest_path)?;
            manifest_path
        };
        config.assumeutxo_manifest = Some(manifest_path);

        let state = crate::state::NodeState::open(config, None)?;
        assert_eq!(
            state.chainstates_summary()?.active_chainstate.height,
            Some(pinned.height)
        );
        assert!(
            matches!(
                state.snapshots.manager.status()?,
                AssumeUtxoDiskStatus::Validating { .. } | AssumeUtxoDiskStatus::Finalized { .. }
            ),
            "the restart must keep the imported base instead of failing on AlreadyActive"
        );
        Ok(())
    }

    #[test]
    fn checkpoint_published_before_head_commit_restarts_cold() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        state.snapshots.import(&core_path)?;
        drop(state);
        let data_dir = dir.path().join("node");
        let head_with = |assumeutxo| bitcoin_rs_storage::DurableHead {
            assumeutxo,
            commit_id: 1,
            height: pinned.height,
            tip: pinned.block_hash,
            chain_tx_count: pinned.chain_tx_count,
            body_extent: None,
            undo_extent: None,
        };
        let uncommitted = head_with(AssumeUtxoDiskStatus::Uninitialized);
        let in_flight = bitcoin_rs_storage::SnapshotActivationMarker {
            base_hash: pinned.block_hash,
            coin_count: 0,
            coin_digest: pinned.hash_serialized,
        };
        let cold = bitcoin_rs_chain::recovery::prepare_initial_state_with_engine(
            &data_dir,
            Network::Regtest,
            Some(&uncommitted),
            Some(&in_flight),
        )
        .map_err(|error| TestError::Recovery(Box::new(error)))?;
        assert!(
            matches!(
                cold.initial.resume_source,
                bitcoin_rs_chain::recovery::ResumeSource::Cold
            ),
            "a checkpoint at the base of an in-flight activation must not be restored"
        );
        let ordinary = bitcoin_rs_chain::recovery::prepare_initial_state_with_engine(
            &data_dir,
            Network::Regtest,
            Some(&uncommitted),
            None,
        )
        .map_err(|error| TestError::Recovery(Box::new(error)))?;
        assert!(
            matches!(
                ordinary.initial.resume_source,
                bitcoin_rs_chain::recovery::ResumeSource::Checkpoint
            ),
            "a checkpoint at a compiled base with no activation in flight must restore"
        );
        let committed = head_with(AssumeUtxoDiskStatus::Validating {
            base_height: pinned.height,
            base_hash: pinned.block_hash,
            expected_hash_serialized: pinned.hash_serialized,
            chain_tx_count: pinned.chain_tx_count,
            historical_height: 0,
            historical_hash: Network::Regtest.genesis_block_hash(),
            pending: None,
            checkpoint: None,
        });
        let warm = bitcoin_rs_chain::recovery::prepare_initial_state_with_engine(
            &data_dir,
            Network::Regtest,
            Some(&committed),
            None,
        )
        .map_err(|error| TestError::Recovery(Box::new(error)))?;
        assert!(
            matches!(
                warm.initial.resume_source,
                bitcoin_rs_chain::recovery::ResumeSource::Checkpoint
            ),
            "the head that names the base must restore the published checkpoint"
        );
        Ok(())
    }

    #[test]
    fn manifest_import_resolves_a_datadir_relative_path() -> Result<(), TestError> {
        let pinned = regtest_pin()?;
        let dir = tempfile::tempdir()?;
        let (state, core_path) = snapshot_inputs(dir.path())?;
        let core_bytes = std::fs::read(&core_path)?;
        let data_dir = dir.path().join("node");
        std::fs::create_dir_all(&data_dir)?;
        std::fs::write(data_dir.join("core.dat"), &core_bytes)?;
        let manifest_path = write_valid_manifest(&data_dir, pinned, &core_bytes)?;
        let relative_name = "relative_snapshot_manifest.json";
        std::fs::rename(&manifest_path, data_dir.join(relative_name))?;
        let import = state.import_manifest(std::path::Path::new(relative_name))?;
        assert_eq!(import.base_height, pinned.height);
        assert_eq!(import.tip_hash, pinned.block_hash.to_string_be());
        assert_eq!(import.coins_loaded, 200);
        assert_eq!(
            tip_identity(&state),
            Some((pinned.height, pinned.block_hash))
        );
        state
            .snapshots
            .admit_startup_manifest(std::path::Path::new(relative_name))?;
        let mismatched_name = "mismatched_snapshot_manifest.json";
        let mismatched_path = write_manifest_bytes(
            &data_dir,
            pinned.height.saturating_add(1),
            pinned.block_hash.to_le_bytes(),
            pinned.hash_serialized.to_le_bytes(),
            &core_bytes,
        )?;
        std::fs::rename(&mismatched_path, data_dir.join(mismatched_name))?;
        let mismatched = state
            .snapshots
            .admit_startup_manifest(std::path::Path::new(mismatched_name));
        assert!(matches!(
            mismatched,
            Err(SnapshotImportError::Activation(
                AssumeUtxoError::AlreadyActive
            ))
        ));
        Ok(())
    }
}
