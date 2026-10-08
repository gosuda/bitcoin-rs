//! Block parse backends and runtime-selected script preparation.

use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_script::VerifyFlags;

use crate::ConsensusError;
use crate::ValidationEngine;

/// Returns the unsupported-build error for a kernel request on a build without
/// `kernel` support.
#[cfg(not(feature = "kernel"))]
pub(crate) fn kernel_not_compiled() -> ConsensusError {
    ConsensusError::UnsupportedEngine {
        engine: ValidationEngine::Kernel,
    }
}

/// Rejects a prevout set that does not cover exactly `input_count` inputs.
pub(crate) fn ensure_prevout_count(
    spent_outputs: &[(OutPoint, TxOut)],
    input_count: usize,
) -> Result<(), ConsensusError> {
    if spent_outputs.len() != input_count {
        return Err(ConsensusError::PrevoutCount {
            input_count,
            prevout_count: spent_outputs.len(),
        });
    }
    Ok(())
}

/// The native one-shot block parse, compiled in every build.
mod native {
    use core::marker::PhantomData;

    use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid};
    use bitcoin_rs_script::VerifyFlags;

    use crate::ConsensusError;

    /// A block parsed once through the checked borrowed layout.
    #[derive(Debug, Clone)]
    pub struct NativeBlock {
        facts: crate::block_view::BlockFacts,
    }

    impl NativeBlock {
        /// Parses `raw_block` once and derives every fact the later stages share.
        pub fn parse(raw_block: &[u8]) -> Result<Self, ConsensusError> {
            // `parse_exact` keeps the old owned decoder's contract: trailing
            // bytes are a typed error, and the whole pass validates shape
            // without materializing a transaction tree.
            let parsed = bitcoin_rs_primitives::layout::ParsedBlock::parse_exact(raw_block)
                .map_err(|error| ConsensusError::Encoding(error.to_string()))?;
            Ok(Self {
                facts: crate::block_view::BlockFacts::from_parsed(&parsed),
            })
        }

        /// Transaction IDs derived in the single parse pass.
        #[expect(
            clippy::unnecessary_wraps,
            reason = "shape parity with the fallible kernel backend"
        )]
        pub fn txids(&self) -> Result<Vec<Txid>, ConsensusError> {
            Ok(self.facts.txids().to_vec())
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
        #[must_use]
        pub fn derive_facts(&self, _txs: &[Tx], _txids: &[Txid]) -> crate::block_view::BlockFacts {
            self.facts.clone()
        }

        /// The native backend has nothing to prepare per transaction.
        #[expect(
            clippy::unused_self,
            reason = "shape parity with the kernel backend's per-transaction prepare"
        )]
        #[expect(
            clippy::unnecessary_wraps,
            reason = "shape parity with the fallible kernel backend"
        )]
        pub(crate) fn prepare_tx<'b>(
            &self,
            _index: usize,
            _input_count: usize,
            _spent_outputs: &[(OutPoint, TxOut)],
        ) -> Result<super::PreparedTx<'b>, ConsensusError> {
            Ok(super::PreparedTx::Native(NativePreparedTx, PhantomData))
        }
    }

    /// The native backend retains nothing across prepared input checks.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct NativePreparedTx;

    /// The native per-input script verdict: the interpreter in `bitcoin-rs-script`
    /// covers every consensus spend class.
    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "shape parity with the kernel backend's prepared-state handle"
    )]
    pub(crate) fn verify_input(
        _prepared: &NativePreparedTx,
        input_index: usize,
        flags: VerifyFlags,
        spent_outputs: &[TxOut],
        tx: &Tx,
    ) -> Result<(), ConsensusError> {
        crate::verify_tx::verify_input_script_native(input_index, spent_outputs, tx, flags)
    }
}

/// The prefix every `bitcoinkernel` script rejection carries.
#[cfg(feature = "kernel")]
pub(crate) const KERNEL_SCRIPT_REJECT_PREFIX: &str = "kernel script verification failed: ";

/// The `libbitcoinkernel` block parse and script backend.
#[cfg(feature = "kernel")]
mod kernel_backend {
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxOut, Txid, consensus_bytes};
    use bitcoin_rs_script::VerifyFlags;

    use crate::{ConsensusError, ScriptEngine};

    /// Verifies every input script of `tx` through bitcoinkernel.
    pub(super) fn verify_tx_scripts(
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

    /// A block parsed by `libbitcoinkernel`.
    pub struct KernelBlock {
        block: bitcoinkernel::Block,
    }

    impl core::fmt::Debug for KernelBlock {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("KernelBlock")
        }
    }

    impl KernelBlock {
        /// Parses `raw_block` once.
        pub fn parse(raw_block: &[u8]) -> Result<Self, ConsensusError> {
            bitcoinkernel::Block::new(raw_block)
                .map(|block| Self { block })
                .map_err(|error| ConsensusError::Kernel(error.to_string()))
        }

        /// Txids in block order, taken from the hashes the parse already computed.
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

        /// Prepares this block's transaction `index` for parallel per-input kernel
        /// verification over its resolved prevouts.
        pub(crate) fn prepare_tx(
            &self,
            index: usize,
            input_count: usize,
            spent_outputs: &[(OutPoint, TxOut)],
        ) -> Result<super::PreparedTx<'_>, ConsensusError> {
            let kernel_tx = self.block.transaction(index).map_err(map_kernel_error)?;
            Ok(super::PreparedTx::Kernel(prepare_kernel_tx(
                kernel_tx,
                input_count,
                spent_outputs,
            )?))
        }

        /// Derives block facts from parsed IDs without another FFI crossing.
        #[expect(
            clippy::unused_self,
            reason = "shape parity with the native backend's derive_facts"
        )]
        #[must_use]
        pub fn derive_facts(&self, txs: &[Tx], txids: &[Txid]) -> crate::block_view::BlockFacts {
            crate::block_view::BlockFacts::from_txids(txs, txids.to_vec())
        }
    }

    fn map_kernel_error(error: impl core::fmt::Display) -> ConsensusError {
        ConsensusError::Kernel(error.to_string())
    }

    /// Kernel transaction and shared sighash precompute.
    pub(crate) struct PreparedKernelTx<T: bitcoinkernel::prelude::TransactionExt> {
        kernel_tx: T,
        precomputed: bitcoinkernel::PrecomputedTransactionData,
    }

    fn prepare_kernel_tx<T: bitcoinkernel::prelude::TransactionExt>(
        kernel_tx: T,
        input_count: usize,
        spent_outputs: &[(OutPoint, TxOut)],
    ) -> Result<PreparedKernelTx<T>, ConsensusError> {
        super::ensure_prevout_count(spent_outputs, input_count)?;
        let kernel_prevouts = spent_outputs
            .iter()
            .map(|(_, prevout)| kernel_txout(prevout))
            .collect::<Result<Vec<_>, _>>()?;
        let precomputed =
            bitcoinkernel::PrecomputedTransactionData::new(&kernel_tx, kernel_prevouts.as_slice())
                .map_err(map_kernel_error)?;
        Ok(PreparedKernelTx {
            kernel_tx,
            precomputed,
        })
    }

    pub(crate) fn verify_prepared_input<T: bitcoinkernel::prelude::TransactionExt>(
        prepared: &PreparedKernelTx<T>,
        prevout: &TxOut,
        input_index: usize,
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        let script =
            bitcoinkernel::ScriptPubkey::new(&prevout.script_pubkey).map_err(map_kernel_error)?;
        let amount = i64::try_from(prevout.value.to_sat())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        bitcoinkernel::verify(
            &script,
            Some(amount),
            &prepared.kernel_tx,
            input_index,
            // Fill implications before policy bits are stripped: CLEANSTACK
            // still activates WITNESS and P2SH in the native driver and counter.
            Some(flags.filled().kernel_bits()),
            &prepared.precomputed,
        )
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: format!("{}{error}", super::KERNEL_SCRIPT_REJECT_PREFIX),
            engine: ScriptEngine::Kernel,
        })?;
        Ok(())
    }

    fn kernel_txout(prevout: &TxOut) -> Result<bitcoinkernel::TxOut, ConsensusError> {
        let script =
            bitcoinkernel::ScriptPubkey::new(&prevout.script_pubkey).map_err(map_kernel_error)?;
        let amount = i64::try_from(prevout.value.to_sat())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        Ok(bitcoinkernel::TxOut::new(&script, amount))
    }
}

/// A one-shot block parse for the selected engine, carrying whichever backend
/// parsed `raw_block`.
#[derive(Debug)]
pub enum BlockParse {
    /// The checked borrowed layout parse.
    Native(native::NativeBlock),
    /// The `libbitcoinkernel` parse.
    #[cfg(feature = "kernel")]
    Kernel(kernel_backend::KernelBlock),
}

impl BlockParse {
    /// Parses `raw_block` once under `engine`.
    /// Parse errors map to `Kernel`; unavailable engines to `UnsupportedEngine`.
    pub fn parse(raw_block: &[u8], engine: ValidationEngine) -> Result<Self, ConsensusError> {
        match engine {
            ValidationEngine::Native => native::NativeBlock::parse(raw_block).map(Self::Native),
            ValidationEngine::Kernel => kernel_block_parse(raw_block),
        }
    }

    /// Transaction IDs in block order, parsed once.
    pub fn txids(&self) -> Result<Vec<Txid>, ConsensusError> {
        match self {
            Self::Native(block) => block.txids(),
            #[cfg(feature = "kernel")]
            Self::Kernel(block) => block.txids(),
        }
    }

    /// Transaction count as parsed.
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        match self {
            Self::Native(block) => block.transaction_count(),
            #[cfg(feature = "kernel")]
            Self::Kernel(block) => block.transaction_count(),
        }
    }

    /// The native one-pass facts, or `None` for a kernel parse (whose facts are
    /// derived on demand from the caller's transaction IDs).
    #[must_use]
    pub const fn native_facts(&self) -> Option<&crate::block_view::BlockFacts> {
        match self {
            Self::Native(block) => Some(block.facts()),
            #[cfg(feature = "kernel")]
            Self::Kernel(_) => None,
        }
    }

    pub(crate) fn prepare_tx<'b>(
        &'b self,
        index: usize,
        input_count: usize,
        spent_outputs: &[(OutPoint, TxOut)],
    ) -> Result<PreparedTx<'b>, ConsensusError> {
        ensure_prevout_count(spent_outputs, input_count)?;
        match self {
            Self::Native(block) => block.prepare_tx(index, input_count, spent_outputs),
            #[cfg(feature = "kernel")]
            Self::Kernel(block) => block.prepare_tx(index, input_count, spent_outputs),
        }
    }

    /// The shared block facts (weight, Merkle root, mutation flag) for `txs`.
    #[must_use]
    pub fn derive_facts(&self, txs: &[Tx], txids: &[Txid]) -> crate::block_view::BlockFacts {
        match self {
            Self::Native(block) => block.derive_facts(txs, txids),
            #[cfg(feature = "kernel")]
            Self::Kernel(block) => block.derive_facts(txs, txids),
        }
    }
}

#[cfg(feature = "kernel")]
fn kernel_block_parse(raw_block: &[u8]) -> Result<BlockParse, ConsensusError> {
    kernel_backend::KernelBlock::parse(raw_block).map(BlockParse::Kernel)
}

#[cfg(not(feature = "kernel"))]
fn kernel_block_parse(_raw_block: &[u8]) -> Result<BlockParse, ConsensusError> {
    Err(kernel_not_compiled())
}

pub(crate) enum PreparedTx<'b> {
    Native(native::NativePreparedTx, core::marker::PhantomData<&'b ()>),
    #[cfg(feature = "kernel")]
    Kernel(kernel_backend::PreparedKernelTx<bitcoinkernel::TransactionRef<'b>>),
}

pub(crate) fn verify_prepared_input(
    prepared: &PreparedTx<'_>,
    spent_outputs: &[TxOut],
    tx: &Tx,
    input_index: usize,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    match prepared {
        PreparedTx::Native(state, _) => {
            native::verify_input(state, input_index, flags, spent_outputs, tx)
        }
        #[cfg(feature = "kernel")]
        PreparedTx::Kernel(state) => kernel_backend::verify_prepared_input(
            state,
            &spent_outputs[input_index],
            input_index,
            flags,
        ),
    }
}

/// Verifies every input script of `tx` under `engine`.
/// `PrevoutCount` precedes execution; script/setup errors map to `Script`/`Kernel`.
pub fn verify_tx_scripts(
    tx: &Tx,
    spent_outputs: &[(OutPoint, TxOut)],
    flags: VerifyFlags,
    engine: ValidationEngine,
) -> Result<(), ConsensusError> {
    ensure_prevout_count(spent_outputs, tx.inputs.len())?;
    match engine {
        ValidationEngine::Native => {
            // One clone of the spent outputs per transaction, shared by every
            // input check; BIP341 sighashes commit to the full ordered set.
            let spent: Vec<TxOut> = spent_outputs
                .iter()
                .map(|(_, prevout)| prevout.clone())
                .collect();
            for (input_index, _) in spent_outputs.iter().enumerate() {
                crate::verify_tx::verify_input_script_native(input_index, &spent, tx, flags)?;
            }
            Ok(())
        }
        ValidationEngine::Kernel => verify_tx_scripts_kernel(tx, spent_outputs, flags),
    }
}

/// Runs every input script of `tx` through bitcoinkernel.
#[cfg(feature = "kernel")]
fn verify_tx_scripts_kernel(
    tx: &Tx,
    spent_outputs: &[(OutPoint, TxOut)],
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    kernel_backend::verify_tx_scripts(tx, spent_outputs, flags)
}

/// Fails closed: bitcoinkernel support is not compiled into this build.
#[cfg(not(feature = "kernel"))]
fn verify_tx_scripts_kernel(
    _tx: &Tx,
    _spent_outputs: &[(OutPoint, TxOut)],
    _flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    Err(kernel_not_compiled())
}
