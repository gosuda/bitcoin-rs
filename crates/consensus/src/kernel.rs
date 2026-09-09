#[cfg(feature = "kernel")]
mod enabled {
    use bitcoin_rs_primitives::{Hash256, Network, OutPoint, Tx, TxOut, Txid, consensus_bytes};
    use bitcoin_rs_script::VerifyFlags;

    use crate::ConsensusError;
    use crate::rust_path::UtxoView;

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
    /// Parsing here is worth far more than the parse itself. Core's
    /// `CTransaction` hashes itself while deserializing, using the SHA-256
    /// implementation Core selects at runtime (`avx2(8way)` on this host), so
    /// every txid comes out of this parse for free and the per-transaction
    /// serialization + `bitcoinkernel::Transaction::new` round-trip disappears
    /// with it.
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

        pub(crate) fn transaction(
            &self,
            index: usize,
        ) -> Result<bitcoinkernel::TransactionRef<'_>, ConsensusError> {
            self.block
                .transaction(index)
                .map_err(|error| ConsensusError::Kernel(error.to_string()))
        }

        /// Derives the shared block facts (weight, Merkle root, and mutation
        /// flag) by reducing the caller's already-surfaced transaction IDs
        /// in one pass over the decoded transactions — the same IDs the
        /// parse produced, without a second kernel FFI crossing. Byte
        /// positions are a native-layout fact and stay empty on this path.
        #[must_use]
        pub fn derive_facts(&self, txs: &[Tx], txids: &[Txid]) -> crate::block_view::BlockFacts {
            crate::block_view::BlockFacts::from_txids(txs, txids.to_vec())
        }
    }

    /// Kernel transaction plus sighash precompute retained for parallel
    /// per-input verification.
    ///
    /// Generic over the transaction handle so the block path can hold a
    /// borrowed [`bitcoinkernel::TransactionRef`] while the standalone
    /// [`verify_tx_scripts`] entry keeps an owned one.
    pub(crate) struct PreparedKernelTx<T: bitcoinkernel::prelude::TransactionExt> {
        kernel_tx: T,
        precomputed: bitcoinkernel::PrecomputedTransactionData,
    }

    /// Builds the shared [`bitcoinkernel::PrecomputedTransactionData`] over an
    /// already-parsed kernel transaction.
    pub(crate) fn prepare_kernel_tx<T: bitcoinkernel::prelude::TransactionExt>(
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
    pub(crate) fn verify_prepared_input<T: bitcoinkernel::prelude::TransactionExt>(
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
}

#[cfg(feature = "kernel")]
pub use enabled::{KernelBlock, KernelContext, verify_tx_scripts};
#[cfg(feature = "kernel")]
pub(crate) use enabled::{PreparedKernelTx, prepare_kernel_tx, verify_prepared_input};

#[cfg(not(feature = "kernel"))]
/// Stub kernel context available when the `kernel` feature is off.
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelContext;

#[cfg(not(feature = "kernel"))]
/// Portable-build stand-in for the kernel's one-shot block parse.
///
/// The native path parses the serialized block once through the checked
/// borrowed layout and keeps every fact derived from that single pass:
/// transaction IDs, witness IDs, weight, byte positions, and the Merkle
/// root with its mutation flag. Later stages consume those facts through
/// [`KernelBlock::derive_facts`] instead of re-walking or re-hashing the
/// decoded block, so the production native path decodes the transaction
/// tree exactly once.
#[derive(Debug, Clone)]
pub struct KernelBlock {
    facts: crate::block_view::BlockFacts,
}

#[cfg(not(feature = "kernel"))]
impl KernelBlock {
    /// Parses `raw_block` once through the checked layout and derives every
    /// fact the later stages share.
    ///
    /// # Errors
    /// Returns [`ConsensusError::Kernel`] if `raw_block` is not a valid block.
    pub fn parse(raw_block: &[u8]) -> Result<Self, crate::ConsensusError> {
        // `parse_exact` keeps the old owned decoder's contract: trailing
        // bytes are a typed error, and the whole pass validates shape
        // without materializing a transaction tree.
        let parsed = bitcoin_rs_primitives::layout::ParsedBlock::parse_exact(raw_block)
            .map_err(|error| crate::ConsensusError::Kernel(error.to_string()))?;
        Ok(Self {
            facts: crate::block_view::BlockFacts::from_parsed(&parsed),
        })
    }

    /// Transaction IDs derived in the single parse pass.
    #[must_use]
    pub fn txids(&self) -> &[bitcoin_rs_primitives::Txid] {
        self.facts.txids()
    }

    /// Transaction count as parsed.
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.facts.tx_count()
    }

    /// The facts derived in the one parse pass.
    #[must_use]
    pub const fn facts(&self) -> &crate::block_view::BlockFacts {
        &self.facts
    }

    /// The shared block facts for a view that owns them.
    ///
    /// The native parse already derived everything in one pass, so this
    /// clones the derived facts; the kernel build reduces the caller's
    /// already-surfaced transaction IDs through the production walker
    /// instead of re-crossing the kernel FFI per transaction. One call
    /// shape keeps the node uniform across backends; the arguments exist
    /// for that kernel shape and are unused here.
    #[must_use]
    pub fn derive_facts(
        &self,
        _txs: &[bitcoin_rs_primitives::Tx],
        _txids: &[bitcoin_rs_primitives::Txid],
    ) -> crate::block_view::BlockFacts {
        self.facts.clone()
    }
}
