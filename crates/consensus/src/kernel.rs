#[cfg(feature = "kernel")]
mod enabled {
    use bitcoin::consensus::encode;
    use bitcoin::{Network, TxOut};
    use bitcoin_rs_primitives::{Block, Tx};
    use bitcoin_rs_script::VerifyFlags;

    use crate::ConsensusError;
    use crate::rust_path::{BlockState, TipState, UtxoView};

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
            let tx_bytes = encode::serialize(&tx.0);
            let kernel_tx = bitcoinkernel::Transaction::new(&tx_bytes)
                .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
            let spent = collect_spent_outputs(tx, prevouts)?;
            let kernel_prevouts = spent
                .iter()
                .map(kernel_txout)
                .collect::<Result<Vec<_>, _>>()?;
            let tx_data = bitcoinkernel::PrecomputedTransactionData::new(
                &kernel_tx,
                kernel_prevouts.as_slice(),
            )
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;

            for (input_index, prevout) in spent.iter().enumerate() {
                let script = bitcoinkernel::ScriptPubkey::new(prevout.script_pubkey.as_bytes())
                    .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
                bitcoinkernel::verify(
                    &script,
                    Some(
                        i64::try_from(prevout.value.to_sat())
                            .map_err(|error| ConsensusError::Kernel(error.to_string()))?,
                    ),
                    &kernel_tx,
                    input_index,
                    Some(flags.kernel_bits()),
                    &tx_data,
                )
                .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
            }
            Ok(())
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
    ) -> Result<Vec<TxOut>, ConsensusError> {
        tx.0.input
            .iter()
            .enumerate()
            .map(|(input_index, input)| {
                prevouts
                    .lookup(&input.previous_output)
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
pub use enabled::KernelContext;

#[cfg(not(feature = "kernel"))]
/// Stub kernel context available when the `kernel` feature is off.
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelContext;
