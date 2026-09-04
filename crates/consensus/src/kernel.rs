#[cfg(feature = "kernel")]
mod enabled {
    use bitcoin_rs_primitives::{Hash256, Network, OutPoint, Tx, TxOut, Txid, consensus_bytes};
    use bitcoin_rs_script::VerifyFlags;

    use crate::ConsensusError;
    use crate::rust_path::UtxoView;

    /// Verifies every input script of `tx` through bitcoinkernel.
    ///
    /// Independent Core oracle: callers compare this verdict against the native
    /// interpreter. Production apply never routes here.
    ///
    /// `spent_outputs` pairs each input's outpoint with the output it spends, in
    /// input order — the shape the verify path already holds after prevout
    /// resolution. One transaction serialization/parse and one
    /// [`bitcoinkernel::PrecomputedTransactionData`] are shared across all inputs.
    ///
    /// Per-input verdict failures map to [`ConsensusError::Script`]; parse and
    /// precompute failures map to [`ConsensusError::Kernel`]. A `spent_outputs`
    /// length that disagrees with the input count is rejected outright: the loop
    /// below is driven by `spent_outputs`, so a short slice would otherwise
    /// leave trailing inputs silently unverified.
    pub fn verify_tx_scripts(
        tx: &Tx,
        spent_outputs: &[(OutPoint, TxOut)],
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        let tx_bytes = consensus_bytes(tx);
        let kernel_tx = bitcoinkernel::Transaction::new(&tx_bytes)
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        let prepared = prepare_kernel_tx(kernel_tx, tx.inputs.len(), spent_outputs)?;
        for (input_index, (_, prevout)) in spent_outputs.iter().enumerate() {
            verify_prepared_input(&prepared, prevout, input_index, flags)?;
        }
        Ok(())
    }

    /// A block parsed once by `libbitcoinkernel`.
    ///
    /// This is the independent Core parse used by `--verify-kernel` and by
    /// differential tests. Production apply hashes native `Tx` values and
    /// never feeds this handle into Rust state.
    pub struct KernelBlock {
        block: bitcoinkernel::Block,
    }

    impl KernelBlock {
        /// Parses `raw_block` once.
        pub fn parse(raw_block: &[u8]) -> Result<Self, ConsensusError> {
            bitcoinkernel::Block::new(raw_block)
                .map(|block| Self { block })
                .map_err(|error| ConsensusError::Kernel(error.to_string()))
        }

        /// Txids in block order, taken from the hashes the parse already
        /// computed. Verified byte-identical to native `Tx::txid` over mainnet
        /// `0..150_000` (1.7M transactions, zero mismatches).
        pub fn txids(&self) -> Result<Vec<Txid>, ConsensusError> {
            use bitcoinkernel::prelude::*;

            (0..self.block.transaction_count())
                .map(|index| {
                    let tx = self
                        .block
                        .transaction(index)
                        .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
                    Ok(Txid(Hash256::from_le_bytes(&tx.txid().to_bytes())))
                })
                .collect()
        }

        /// Transaction count as parsed.
        pub fn transaction_count(&self) -> usize {
            self.block.transaction_count()
        }
    }

    /// Kernel transaction plus sighash precompute retained across inputs.
    struct PreparedKernelTx<T: bitcoinkernel::prelude::TransactionExt> {
        kernel_tx: T,
        precomputed: bitcoinkernel::PrecomputedTransactionData,
    }

    /// Builds the shared [`bitcoinkernel::PrecomputedTransactionData`] over an
    /// already-parsed kernel transaction.
    fn prepare_kernel_tx<T: bitcoinkernel::prelude::TransactionExt>(
        kernel_tx: T,
        input_count: usize,
        spent_outputs: &[(OutPoint, TxOut)],
    ) -> Result<PreparedKernelTx<T>, ConsensusError> {
        if spent_outputs.len() != input_count {
            return Err(ConsensusError::Kernel(format!(
                "prevout count {} does not match input count {input_count}",
                spent_outputs.len(),
            )));
        }
        let kernel_prevouts = spent_outputs
            .iter()
            .map(|(_, prevout)| kernel_txout(prevout))
            .collect::<Result<Vec<_>, _>>()?;
        let precomputed =
            bitcoinkernel::PrecomputedTransactionData::new(&kernel_tx, kernel_prevouts.as_slice())
                .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        Ok(PreparedKernelTx {
            kernel_tx,
            precomputed,
        })
    }

    /// Verifies a single input against a previously prepared kernel transaction.
    fn verify_prepared_input<T: bitcoinkernel::prelude::TransactionExt>(
        prepared: &PreparedKernelTx<T>,
        prevout: &TxOut,
        input_index: usize,
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        let script = bitcoinkernel::ScriptPubkey::new(&prevout.script_pubkey)
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        let amount = i64::try_from(prevout.value)
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        bitcoinkernel::verify(
            &script,
            Some(amount),
            &prepared.kernel_tx,
            input_index,
            Some(flags.kernel_bits()),
            &prepared.precomputed,
        )
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: format!("kernel script verification failed: {error}"),
        })?;
        Ok(())
    }

    /// Context for Core's bitcoinkernel consensus engine.
    pub struct KernelContext {
        ctx: bitcoinkernel::Context,
    }

    impl KernelContext {
        /// Creates a kernel context for a network.
        pub fn new(network: Network) -> Result<Self, ConsensusError> {
            let chain_type = match network {
                Network::Mainnet => bitcoinkernel::ChainType::Mainnet,
                Network::Testnet3 => bitcoinkernel::ChainType::Testnet,
                Network::Testnet4 => bitcoinkernel::ChainType::Testnet4,
                Network::Signet => bitcoinkernel::ChainType::Signet,
                Network::Regtest => bitcoinkernel::ChainType::Regtest,
            };
            bitcoinkernel::ContextBuilder::new()
                .chain_type(chain_type)
                .build()
                .map(|ctx| Self { ctx })
                .map_err(|error| ConsensusError::Kernel(error.to_string()))
        }

        /// Verifies a transaction's inputs through bitcoinkernel script verification.
        pub fn verify_tx(
            &self,
            tx: &Tx,
            prevouts: &impl UtxoView,
            _height: u32,
            flags: VerifyFlags,
        ) -> Result<(), ConsensusError> {
            let _ = &self.ctx;
            let spent = collect_spent_outputs(tx, prevouts)?;
            verify_tx_scripts(tx, &spent, flags)
        }
    }

    fn collect_spent_outputs(
        tx: &Tx,
        prevouts: &impl UtxoView,
    ) -> Result<Vec<(OutPoint, TxOut)>, ConsensusError> {
        tx.inputs
            .iter()
            .enumerate()
            .map(|(input_index, input)| {
                prevouts
                    .lookup(&input.previous_output)
                    .map(|txout| (input.previous_output, txout))
                    .ok_or(ConsensusError::MissingPrevout { input_index })
            })
            .collect()
    }

    fn kernel_txout(prevout: &TxOut) -> Result<bitcoinkernel::TxOut, ConsensusError> {
        let script = bitcoinkernel::ScriptPubkey::new(&prevout.script_pubkey)
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        let amount = i64::try_from(prevout.value)
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        Ok(bitcoinkernel::TxOut::new(&script, amount))
    }

    /// Compares native accept/reject against Core. Agreement on reject is
    /// `Ok` so the caller can keep the native error; disagreement is
    /// [`ConsensusError::Kernel`].
    pub fn compare_script_verdicts(
        txs_and_spent: &[(&Tx, Vec<(OutPoint, TxOut)>)],
        flags: VerifyFlags,
        native_accepted: bool,
    ) -> Result<(), ConsensusError> {
        let mut kernel_error = None;
        for (tx, spent) in txs_and_spent {
            if spent.is_empty() {
                continue;
            }
            if let Err(error) = verify_tx_scripts(tx, spent, flags) {
                kernel_error = Some(error);
                break;
            }
        }
        let kernel_accepted = kernel_error.is_none();
        match (native_accepted, kernel_accepted) {
            (true, true) | (false, false) => Ok(()),
            (true, false) => Err(ConsensusError::Kernel(format!(
                "native accepted, kernel rejected: {}",
                kernel_error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "unknown kernel error".to_owned())
            ))),
            (false, true) => Err(ConsensusError::Kernel(
                "native rejected, kernel accepted".to_owned(),
            )),
        }
    }

    /// Compares native txids against Core's parse of the same wire bytes.
    ///
    /// Kernel-owned `KernelBlock` / txids never leave this call. Agreement is
    /// `Ok`; parse failure or a txid/count mismatch is [`ConsensusError::Kernel`].
    pub fn compare_block_parse(raw: &[u8], native_txids: &[Txid]) -> Result<(), ConsensusError> {
        let kernel_block = KernelBlock::parse(raw)?;
        if kernel_block.transaction_count() != native_txids.len() {
            return Err(ConsensusError::Kernel(format!(
                "native tx count {}, kernel tx count {}",
                native_txids.len(),
                kernel_block.transaction_count(),
            )));
        }
        let kernel_txids = kernel_block.txids()?;
        for (index, (native, kernel)) in native_txids.iter().zip(kernel_txids.iter()).enumerate() {
            if native != kernel {
                return Err(ConsensusError::Kernel(format!(
                    "txid mismatch at index {index}"
                )));
            }
        }
        Ok(())
    }
}

/// Returns whether this build compiled `libbitcoinkernel`.
///
/// The production apply path is always native. This flag only tells callers
/// whether the independent Core oracle is available for differential checks.
#[must_use]
pub const fn kernel_compiled() -> bool {
    cfg!(feature = "kernel")
}

#[cfg(feature = "kernel")]
pub use enabled::{
    KernelBlock, KernelContext, compare_block_parse, compare_script_verdicts, verify_tx_scripts,
};

#[cfg(not(feature = "kernel"))]
/// Stub kernel context available when the `kernel` feature is off.
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelContext;

#[cfg(not(feature = "kernel"))]
/// Runtime `--verify-kernel` requires a build that compiled `libbitcoinkernel`.
pub fn compare_script_verdicts(
    txs_and_spent: &[(
        &bitcoin_rs_primitives::Tx,
        Vec<(
            bitcoin_rs_primitives::OutPoint,
            bitcoin_rs_primitives::TxOut,
        )>,
    )],
    flags: bitcoin_rs_script::VerifyFlags,
    native_accepted: bool,
) -> Result<(), crate::ConsensusError> {
    let _ = (txs_and_spent, flags, native_accepted);
    Err(crate::ConsensusError::Kernel(
        "verify_kernel requires a build with --features kernel".to_owned(),
    ))
}

#[cfg(not(feature = "kernel"))]
/// Runtime `--verify-kernel` requires a build that compiled `libbitcoinkernel`.
pub fn compare_block_parse(
    raw: &[u8],
    native_txids: &[bitcoin_rs_primitives::Txid],
) -> Result<(), crate::ConsensusError> {
    let _ = (raw, native_txids);
    Err(crate::ConsensusError::Kernel(
        "verify_kernel requires a build with --features kernel".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    };

    use super::{compare_block_parse, kernel_compiled};

    fn coinbase_block() -> Block {
        let tx = Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), u32::MAX),
                script_sig: vec![1, 1],
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: vec![tx],
        }
    }

    // CONTRACT: docs/contracts/validation-default.md#VAL-03
    #[test]
    fn compare_block_parse_agrees_or_requires_kernel_feature() {
        let block = coinbase_block();
        let raw = consensus_bytes(&block);
        let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
        let result = compare_block_parse(&raw, &txids);
        if kernel_compiled() {
            if let Err(error) = result {
                panic!("Core parse must match native txids: {error}");
            }
        } else {
            match result {
                Err(crate::ConsensusError::Kernel(reason)) => {
                    assert!(
                        reason.contains("verify_kernel"),
                        "unexpected kernel error: {reason}"
                    );
                }
                other => panic!("expected Kernel compile-time error, got {other:?}"),
            }
        }
    }

    // CONTRACT: docs/contracts/validation-default.md#VAL-03
    #[test]
    fn compare_block_parse_rejects_txid_mismatch_when_compiled() {
        if !kernel_compiled() {
            return;
        }
        let block = coinbase_block();
        let raw = consensus_bytes(&block);
        let mut txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
        txids[0] = Txid::default();
        match compare_block_parse(&raw, &txids) {
            Err(crate::ConsensusError::Kernel(reason)) => {
                assert!(
                    reason.contains("txid mismatch"),
                    "unexpected kernel error: {reason}"
                );
            }
            other => panic!("expected txid mismatch, got {other:?}"),
        }
    }
}
