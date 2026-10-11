//! Node-owned bounded snapshot import and fenced consumer reconciliation.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitcoin_rs_chainstate::{
    AssumeUtxoDiskStatus, AssumeUtxoError, AssumeUtxoManager, Chainstate, ChainstateRole,
};
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
        let snapshot = read_and_verify(&mut file, self.network, SnapshotLimits::default())?;
        let result = SnapshotImport {
            coins_loaded: snapshot.metadata.coins_count,
            tip_hash: snapshot.anchor.block_hash.to_string_be(),
            base_height: snapshot.anchor.height,
            // JSON cannot serialize arbitrary filesystem bytes. Render before
            // committing so a valid symlink target cannot turn success into a
            // post-commit response error.
            path: path.to_string_lossy().into_owned(),
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
        let _permit = self.claim_import()?;
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
                return Err(SnapshotImportError::Settlement(error));
            }
            return Err(SnapshotImportError::MempoolNotEmpty);
        }
        let result = self.manager.activate_snapshot_state(set, base_hash, height);
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

    fn snapshot_inputs(dir: &Path) -> anyhow::Result<(crate::state::NodeState, PathBuf, PathBuf)> {
        let mut config = crate::NodeConfig::default_for_network(Network::Regtest);
        config.data_dir = dir.join("node");
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
}
