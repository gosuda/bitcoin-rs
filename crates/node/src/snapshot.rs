use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read as _, Seek as _, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin_rs_consensus::latch::LatchReader;
use bitcoin_rs_consensus::primitives::{Hash256, Network};
use bitcoin_rs_execution::ActivatedSnapshot;
use bitcoin_rs_execution::{
    ApplyError, AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager, Chainstate,
    ChainstateRole,
};
use bitcoin_rs_projection::IndexError;
use bitcoin_rs_projection::IndexWatermark;
use bitcoin_rs_projection::snapshot_seed::{ScriptLiveSeedObserver, ScriptLiveSeedSession};
pub use bitcoin_rs_serving::context::SnapshotImport;
use bitcoin_rs_serving::context::{
    ChainstateInfo, ChainstatesInfo, SnapshotControlError, SnapshotExport,
};
use bitcoin_rs_storage::checkpoint::fs::{HAS_ATOMIC_NOREPLACE_RENAME, rename_noreplace};
use bitcoin_rs_storage::checkpoint::{create_file, open_data_dir, sync_dir};
#[cfg(test)]
use bitcoin_rs_storage::utxo::core_snapshot::SnapshotLimits;
use bitcoin_rs_storage::utxo::core_snapshot::{
    CoreV2Base, CoreV2WriteReport, SnapshotError, write_core_v2,
};
use bitcoin_rs_storage::utxo::record::UtxoRecord;
use bitcoin_rs_storage::utxo::{SnapshotCoin, SnapshotCoinObserver};
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
    script_live_seed: Option<Arc<bitcoin_rs_projection::snapshot_seed::ScriptLiveSeedState>>,
    pub(crate) derived_index_runtime:
        Option<Arc<bitcoin_rs_projection::runtime::DerivedIndexRuntime>>,
    pub(crate) derived_index_status:
        Option<Arc<bitcoin_rs_projection::runtime::DerivedIndexCapability>>,
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
    Seed(#[from] bitcoin_rs_projection::IndexError),
    #[error("snapshot activation failed: {0}")]
    Activation(#[from] AssumeUtxoError),
    #[error("snapshot admission failed: {0}")]
    Admission(#[from] bitcoin_rs_execution::ApplyError),
    #[error("snapshot consumer reconciliation failed: {0}")]
    Settlement(#[from] bitcoin_rs_mempool::ChainChangeError),
    #[error("snapshot activation failed: {activation}; consumer settlement failed: {settlement}")]
    ActivationAndSettlement {
        activation: Box<AssumeUtxoError>,
        settlement: bitcoin_rs_mempool::ChainChangeError,
    },
    #[error("snapshot manifest invalid: {0}")]
    Manifest(#[from] bitcoin_rs_execution::manifest::ManifestError),
    #[error("index bundle error: {0}")]
    Bundle(#[from] bitcoin_rs_projection::portable::IndexBundleError),
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

fn read_bounded_manifest(path: &Path) -> Result<Vec<u8>, SnapshotImportError> {
    const MAX_MANIFEST_BYTES: u64 = 1 << 20;
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_MANIFEST_BYTES) {
        return Err(SnapshotImportError::Manifest(
            bitcoin_rs_execution::manifest::ManifestError::Format("manifest is larger than 1 MiB"),
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
        script_live_seed: Option<Arc<bitcoin_rs_projection::snapshot_seed::ScriptLiveSeedState>>,
        derived_index_runtime: Option<Arc<bitcoin_rs_projection::runtime::DerivedIndexRuntime>>,
        derived_index_status: Option<Arc<bitcoin_rs_projection::runtime::DerivedIndexCapability>>,
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
        let path = if input.is_absolute() {
            input.to_path_buf()
        } else {
            self.data_dir.join(input)
        };
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
    ) -> Result<
        Option<bitcoin_rs_projection::snapshot_seed::ScriptLiveSeedSession>,
        SnapshotImportError,
    > {
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
        if result.is_ok() {
            self.followers.on_snapshot();
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
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.data_dir.join(path)
        };
        let path = path.canonicalize()?;
        if !path.metadata()?.is_file() {
            return Err(SnapshotImportError::NotRegular);
        }
        let bytes = read_bounded_manifest(&path)?;
        let manifest = bitcoin_rs_execution::manifest::SnapshotManifest::parse(&bytes)?;
        if manifest.schema != bitcoin_rs_projection::index_format_version() {
            return Err(SnapshotImportError::Manifest(
                bitcoin_rs_execution::manifest::ManifestError::SchemaMismatch {
                    expected: bitcoin_rs_projection::index_format_version(),
                    found: manifest.schema,
                },
            ));
        }
        let anchor = self
            .network
            .assume_utxo_for_height(manifest.base_height)
            .ok_or_else(
                || bitcoin_rs_execution::manifest::ManifestError::UnknownAnchor {
                    found: bitcoin_rs_consensus::primitives::Hash256::from_le_bytes(
                        &manifest.base_hash,
                    ),
                    height: manifest.base_height,
                },
            )?;
        let genesis = self.network.genesis_block_hash().to_le_bytes();
        let trust = manifest.verify_against_anchor(self.network, genesis, anchor)?;
        let dir = path.parent().unwrap_or(&path);

        let utxo_path = manifest.artifact_path(dir, bitcoin_rs_execution::manifest::UTXO_SLOT)?;
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
                    bitcoin_rs_execution::manifest::ManifestError::SnapshotBaseMismatch {
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
                    bitcoin_rs_execution::manifest::ManifestError::SnapshotCommitmentMismatch {
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
                Some(bitcoin_rs_execution::assumeutxo::FileAttestation {
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
                bitcoin_rs_execution::manifest::CapabilityTrust::Trusted(_) => {
                    manifest.verify_index_artifact(dir, slot_idx + 1)
                }
                bitcoin_rs_execution::manifest::CapabilityTrust::Untrusted => {
                    Err(bitcoin_rs_execution::manifest::ManifestError::Artifacts(
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
                let bytes = read_bounded_manifest(path)?;
                let manifest = bitcoin_rs_execution::manifest::SnapshotManifest::parse(&bytes)?;
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
        error: &bitcoin_rs_execution::manifest::ManifestError,
    ) {
        let Some(runtime) = self.derived_index_runtime.as_ref() else {
            return;
        };
        match cap {
            bitcoin_rs_consensus::primitives::IndexArtifactCapability::TxLookup => {
                runtime.fail_tx_lookup(
                    &bitcoin_rs_projection::runtime::DerivedIndexWorkerError::ArtifactUnavailable(
                        error.to_string(),
                    ),
                );
            }
            bitcoin_rs_consensus::primitives::IndexArtifactCapability::ScriptHistory => {
                runtime.fail_script_history(
                    &bitcoin_rs_projection::runtime::DerivedIndexWorkerError::HistoryUnavailable(
                        bitcoin_rs_storage::pruning::HistoryUnavailable::Pruned {
                            below: base_height,
                        },
                    ),
                );
            }
            bitcoin_rs_consensus::primitives::IndexArtifactCapability::ScriptLive => {
                runtime.fail_script_live(
                    &bitcoin_rs_projection::runtime::DerivedIndexWorkerError::ScriptLiveHistoryPruned,
                );
            }
            bitcoin_rs_consensus::primitives::IndexArtifactCapability::CompactFilters => {
                runtime.fail_compact_filters(
                    &bitcoin_rs_projection::runtime::DerivedIndexWorkerError::HistoryUnavailable(
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

#[cfg(test)]
mod tests;

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
            bitcoin_rs_execution::manifest::ManifestError::ArtifactSizeMismatch {
                slot: bitcoin_rs_execution::manifest::UTXO_SLOT,
                declared: expected_size,
                actual: found_size,
            }
        } else {
            bitcoin_rs_execution::manifest::ManifestError::ArtifactHashMismatch {
                slot: bitcoin_rs_execution::manifest::UTXO_SLOT,
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
