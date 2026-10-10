//! Node-owned bounded snapshot import and fenced consumer reconciliation.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitcoin_rs_chainstate::{AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager, Chainstate};
use bitcoin_rs_primitives::Network;
use bitcoin_rs_rpc::context::{
    ChainstateInfo, ChainstatesInfo, SnapshotControlError, SnapshotImport,
};
use bitcoin_rs_utxo::core_snapshot::{SnapshotLimits, read_and_verify};
use parking_lot::Mutex;

use crate::chain_effects::ChainFollowers;

/// The import budget and activation effects shared by embedding and RPC.
pub(crate) struct SnapshotControl {
    pub(crate) manager: Arc<AssumeUtxoManager>,
    chainstate: Arc<Chainstate>,
    followers: ChainFollowers,
    data_dir: PathBuf,
    network: Network,
    // One imported UTXO set may be materialized at a time. This is a resource
    // permit, not a second lifecycle state. No chain write lock spans decoding.
    import: Mutex<()>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SnapshotImportError {
    #[error("could not read snapshot: {0}")]
    File(#[from] std::io::Error),
    #[error("snapshot input must be a regular file")]
    NotRegular,
    #[error("another snapshot import is in progress")]
    ImportInProgress,
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
            | SnapshotImportError::Activation(
                AssumeUtxoError::AlreadyActive
                | AssumeUtxoError::FullRevalidationRequired
                | AssumeUtxoError::SnapshotHeaderMissing(_)
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
    ) -> Self {
        Self {
            manager,
            chainstate,
            followers,
            data_dir,
            network,
            import: Mutex::new(()),
        }
    }

    pub(crate) fn import(&self, input: &Path) -> Result<SnapshotImport, SnapshotImportError> {
        let _permit = self
            .import
            .try_lock()
            .ok_or(SnapshotImportError::ImportInProgress)?;
        if !matches!(self.manager.status()?, AssumeUtxoDiskStatus::Uninitialized) {
            return Err(AssumeUtxoError::AlreadyActive.into());
        }
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
        let snapshot = read_and_verify(&mut file, self.network, SnapshotLimits::default())?;
        let result = SnapshotImport {
            coins_loaded: snapshot.metadata.coins_count,
            tip_hash: snapshot.anchor.block_hash.to_string_be(),
            base_height: snapshot.anchor.height,
            path,
        };
        self.activate(
            snapshot.set,
            snapshot.metadata.base_block_hash,
            snapshot.anchor.height,
        )?;
        Ok(result)
    }

    /// Existing embedding contract: native v4 input and caller-relative paths.
    /// This entry shares the same resource permit and activation effects with RPC.
    pub(crate) fn import_native(&self, path: &Path) -> Result<(), SnapshotImportError> {
        let _permit = self
            .import
            .try_lock()
            .ok_or(SnapshotImportError::ImportInProgress)?;
        let mut file = BufReader::new(open_regular_input(path)?);
        let snapshot = bitcoin_rs_utxo::read_snapshot_strict_v4(&mut file)?;
        self.activate(snapshot.set, snapshot.tip_hash, snapshot.height)
    }

    fn activate(
        &self,
        set: bitcoin_rs_utxo::UtxoSet,
        base_hash: bitcoin_rs_primitives::Hash256,
        height: u32,
    ) -> Result<(), SnapshotImportError> {
        let change = self.followers.begin_mempool_change()?;
        let result = self.manager.activate_snapshot_state(set, base_hash, height);
        if result.is_ok()
            && let Err(error) = self.followers.on_snapshot(change.as_ref())
        {
            self.chainstate.fail_closed_for_recovery();
            return Err(SnapshotImportError::Settlement(error));
        }
        if !self.chainstate.is_closed_for_recovery()
            && let Some(change) = change
            && let Err(settlement) = change.finish()
        {
            self.chainstate.fail_closed_for_recovery();
            return match result {
                Err(activation) => Err(SnapshotImportError::ActivationAndSettlement {
                    activation,
                    settlement,
                }),
                Ok(()) => Err(SnapshotImportError::Settlement(settlement)),
            };
        }
        result.map_err(SnapshotImportError::Activation)
    }

    pub(crate) fn chainstates(&self) -> Result<ChainstatesInfo, SnapshotControlError> {
        let report = self
            .manager
            .chainstates_report()
            .map_err(|error| SnapshotControlError::Failed(error.to_string()))?;
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
        let snapshot_blockhash = match summary.status {
            AssumeUtxoDiskStatus::Validating { base_hash, .. }
            | AssumeUtxoDiskStatus::Finalized { base_hash, .. } => Some(base_hash.to_string_be()),
            AssumeUtxoDiskStatus::Uninitialized | AssumeUtxoDiskStatus::Failed { .. } => None,
        };
        let active = summary.active_chainstate;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
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

    #[test]
    fn native_embedding_contract_and_shared_import_budget() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p.listen.clear();
        let state = crate::state::NodeState::open(config, None)?;
        state.apply_block(&Network::Regtest.genesis_block())?;
        let raw: Vec<String> = serde_json::from_str(include_str!(
            "../../utxo/tests/fixtures/core-v2/blocks200.json"
        ))?;
        let headers = raw
            .iter()
            .map(|hex| {
                let block: bitcoin::Block = bitcoin::consensus::encode::deserialize_hex(hex)?;
                bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(&block.header))
                    .map_err(anyhow::Error::from)
            })
            .collect::<anyhow::Result<Vec<bitcoin_rs_primitives::Header>>>()?;
        state.chainstate().admit_headers(&headers)?;
        let core_bytes = include_bytes!("../../utxo/tests/fixtures/core-v2/core200.dat");
        let core_path = dir.path().join("core.dat");
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
        let native_path = dir.path().join("native.dat");
        std::fs::write(&native_path, &native)?;
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
        let view = state.chainstates_summary()?;
        assert_eq!(view.active_chainstate.height, Some(200));
        assert!(!view.active_chainstate.validated);
        assert!(view.historical_chainstate.is_some());
        assert_eq!(std::fs::read(native_path)?, native);
        assert_eq!(std::fs::read(core_path)?, core_bytes);
        Ok(())
    }
}
