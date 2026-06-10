#[cfg(feature = "kernel")]
mod enabled {
    use bitcoin::consensus::encode;
    use bitcoin::{Network, OutPoint, TxOut};
    use bitcoin_rs_primitives::{Block, Tx};
    use bitcoin_rs_script::VerifyFlags;

    use crate::ConsensusError;
    use crate::rust_path::{BlockState, TipState, UtxoView};

    /// Verifies every input script of `tx` through bitcoinkernel.
    ///
    /// `spent_outputs` pairs each input's outpoint with the output it spends, in
    /// input order — the shape the verify path already holds after prevout
    /// resolution. One transaction serialization/parse and one
    /// [`bitcoinkernel::PrecomputedTransactionData`] are shared across all inputs.
    ///
    /// Per-input verdict failures map to [`ConsensusError::Script`] (preserving
    /// the verify entry's error contract); parse and precompute failures map to
    /// [`ConsensusError::Kernel`]. A `spent_outputs` length that disagrees with
    /// the input count is rejected outright: the loop below is driven by
    /// `spent_outputs`, so a short slice would otherwise leave trailing inputs
    /// silently unverified.
    pub fn verify_tx_scripts(
        tx: &bitcoin::Transaction,
        spent_outputs: &[(OutPoint, TxOut)],
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        if spent_outputs.len() != tx.input.len() {
            return Err(ConsensusError::Kernel(format!(
                "prevout count {} does not match input count {}",
                spent_outputs.len(),
                tx.input.len()
            )));
        }
        let tx_bytes = encode::serialize(tx);
        let kernel_tx = bitcoinkernel::Transaction::new(&tx_bytes)
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        let kernel_prevouts = spent_outputs
            .iter()
            .map(|(_, prevout)| kernel_txout(prevout))
            .collect::<Result<Vec<_>, _>>()?;
        let tx_data =
            bitcoinkernel::PrecomputedTransactionData::new(&kernel_tx, kernel_prevouts.as_slice())
                .map_err(|error| ConsensusError::Kernel(error.to_string()))?;

        for (input_index, (_, prevout)) in spent_outputs.iter().enumerate() {
            let script = bitcoinkernel::ScriptPubkey::new(prevout.script_pubkey.as_bytes())
                .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
            let amount = i64::try_from(prevout.value.to_sat())
                .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
            bitcoinkernel::verify(
                &script,
                Some(amount),
                &kernel_tx,
                input_index,
                Some(flags.kernel_bits()),
                &tx_data,
            )
            .map_err(|error| ConsensusError::Script {
                input_index,
                reason: format!("kernel script verification failed: {error}"),
            })?;
        }
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
                Network::Bitcoin => bitcoinkernel::ChainType::Mainnet,
                Network::Testnet => bitcoinkernel::ChainType::Testnet,
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
            verify_tx_scripts(&tx.0, &spent, flags)
        }

        /// Connects block-level rules through the kernel path shape.
        pub fn connect_block(
            &self,
            block: &Block,
            prev_tip: &TipState,
        ) -> Result<BlockState, ConsensusError> {
            let _ = &self.ctx;
            Ok(BlockState {
                height: prev_tip.next_height(),
                block_hash: block.0.block_hash(),
                tx_count: block.0.txdata.len(),
            })
        }
    }

    fn collect_spent_outputs(
        tx: &Tx,
        prevouts: &impl UtxoView,
    ) -> Result<Vec<(OutPoint, TxOut)>, ConsensusError> {
        tx.0.input
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
        let script = bitcoinkernel::ScriptPubkey::new(prevout.script_pubkey.as_bytes())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        let amount = i64::try_from(prevout.value.to_sat())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        Ok(bitcoinkernel::TxOut::new(&script, amount))
    }
}

#[cfg(feature = "kernel")]
pub use enabled::{KernelContext, verify_tx_scripts};

#[cfg(not(feature = "kernel"))]
/// Stub kernel context available when the `kernel` feature is off.
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelContext;
