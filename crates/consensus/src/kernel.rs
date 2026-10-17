//! Block parse backends and runtime-selected script preparation.

use bitcoin_rs_primitives::{OutPoint, Tx, TxOut};
use bitcoin_rs_script::VerifyFlags;

use crate::ConsensusError;
use crate::ValidationEngine;

impl From<bitcoin_rs_script::PrevoutError> for ConsensusError {
    fn from(error: bitcoin_rs_script::PrevoutError) -> Self {
        match error {
            bitcoin_rs_script::PrevoutError::Count {
                input_count,
                prevout_count,
            } => Self::PrevoutCount {
                input_count,
                prevout_count,
            },
            bitcoin_rs_script::PrevoutError::Mismatch { input_index } => {
                Self::PrevoutMismatch { input_index }
            }
        }
    }
}

/// Kernel selection fails closed when the backend is not compiled.
#[cfg(not(feature = "kernel"))]
fn kernel_not_compiled() -> ConsensusError {
    ConsensusError::UnsupportedEngine {
        engine: ValidationEngine::Kernel,
    }
}

#[cfg(feature = "kernel")]
pub(crate) const KERNEL_SCRIPT_REJECT_PREFIX: &str = "kernel script verification failed: ";

#[cfg(feature = "kernel")]
mod kernel_backend {
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxOut, Txid, consensus_bytes};
    use bitcoin_rs_script::VerifyFlags;

    use crate::{ConsensusError, ScriptEngine};

    pub(super) fn verify_tx_scripts(
        tx: &Tx,
        spent_outputs: &[(OutPoint, TxOut)],
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        let tx_bytes = consensus_bytes(tx);
        let kernel_tx = bitcoinkernel::Transaction::new(&tx_bytes)
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        let prepared = prepare_kernel_tx(kernel_tx, spent_outputs)?;
        for (input_index, (_, prevout)) in spent_outputs.iter().enumerate() {
            verify_prepared_input(&prepared, prevout, input_index, flags)?;
        }
        Ok(())
    }

    pub struct KernelBlock {
        block: bitcoinkernel::Block,
    }

    impl core::fmt::Debug for KernelBlock {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("KernelBlock")
        }
    }

    impl KernelBlock {
        pub fn parse(raw_block: &[u8]) -> Result<Self, ConsensusError> {
            bitcoinkernel::Block::new(raw_block)
                .map(|block| Self { block })
                .map_err(|error| ConsensusError::Kernel(error.to_string()))
        }

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

        pub fn transaction_count(&self) -> usize {
            self.block.transaction_count()
        }

        /// Retains the parsed transaction and resolved prevouts for parallel checks.
        pub(super) fn prepare_tx(
            &self,
            index: usize,
            spent_outputs: Vec<(OutPoint, TxOut)>,
        ) -> Result<super::PreparedTx<'_>, ConsensusError> {
            let kernel_tx = self.block.transaction(index).map_err(map_kernel_error)?;
            let state = prepare_kernel_tx(kernel_tx, &spent_outputs)?;
            let mut spent_outputs: Vec<TxOut> = spent_outputs
                .into_iter()
                .map(|(_, output)| output)
                .collect();
            // Collection may reuse tuple capacity; retain only the output set.
            spent_outputs.shrink_to_fit();
            Ok(super::PreparedTx::Kernel {
                state,
                spent_outputs,
            })
        }
    }

    fn map_kernel_error(error: impl core::fmt::Display) -> ConsensusError {
        ConsensusError::Kernel(error.to_string())
    }

    pub(crate) struct PreparedKernelTx<T: bitcoinkernel::prelude::TransactionExt> {
        kernel_tx: T,
        precomputed: bitcoinkernel::PrecomputedTransactionData,
    }

    pub(super) fn prepare_kernel_tx<T: bitcoinkernel::prelude::TransactionExt>(
        kernel_tx: T,
        spent_outputs: &[(OutPoint, TxOut)],
    ) -> Result<PreparedKernelTx<T>, ConsensusError> {
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

    pub(super) fn verify_prepared_input<T: bitcoinkernel::prelude::TransactionExt>(
        prepared: &PreparedKernelTx<T>,
        prevout: &TxOut,
        input_index: usize,
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        let script =
            bitcoinkernel::ScriptPubkey::new(&prevout.script_pubkey).map_err(map_kernel_error)?;
        let amount = i64::try_from(prevout.value.to_sat())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        match bitcoinkernel::verify(
            &script,
            Some(amount),
            &prepared.kernel_tx,
            input_index,
            // Fill implications before policy bits are stripped: CLEANSTACK
            // still activates WITNESS and P2SH in the native driver and counter.
            Some(flags.filled().kernel_bits()),
            &prepared.precomputed,
        ) {
            Ok(()) => Ok(()),
            Err(bitcoinkernel::KernelError::ScriptVerify(
                bitcoinkernel::ScriptVerifyError::Invalid,
            )) => Err(ConsensusError::Script {
                input_index,
                reason: format!(
                    "{}{}",
                    super::KERNEL_SCRIPT_REJECT_PREFIX,
                    bitcoinkernel::ScriptVerifyError::Invalid
                ),
                engine: ScriptEngine::Kernel,
            }),
            Err(error) => Err(ConsensusError::Kernel(error.to_string())),
        }
    }

    fn kernel_txout(prevout: &TxOut) -> Result<bitcoinkernel::TxOut, ConsensusError> {
        let script =
            bitcoinkernel::ScriptPubkey::new(&prevout.script_pubkey).map_err(map_kernel_error)?;
        let amount = i64::try_from(prevout.value.to_sat())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        Ok(bitcoinkernel::TxOut::new(&script, amount))
    }
}

/// A block parsed once by the selected engine.
#[derive(Debug)]
pub enum BlockParse {
    /// Checked borrowed layout, available in every build.
    Native(crate::block_view::BlockFacts),
    #[cfg(feature = "kernel")]
    /// Bitcoin Core's kernel parse.
    Kernel(kernel_backend::KernelBlock),
}

impl BlockParse {
    /// Parses `raw_block` once under `engine`.
    /// Native parse errors map to `Encoding`, kernel errors to `Kernel`.
    /// Unavailable engines return `UnsupportedEngine`.
    pub fn parse(raw_block: &[u8], engine: ValidationEngine) -> Result<Self, ConsensusError> {
        match engine {
            ValidationEngine::Native => {
                // Reject trailing bytes without materializing another tree.
                let parsed = bitcoin_rs_primitives::layout::ParsedBlock::parse_exact(raw_block)
                    .map_err(|error| ConsensusError::Encoding(error.to_string()))?;
                Ok(Self::Native(crate::block_view::BlockFacts::from_parsed(
                    &parsed,
                )))
            }
            ValidationEngine::Kernel => kernel_block_parse(raw_block),
        }
    }

    #[must_use]
    pub fn transaction_count(&self) -> usize {
        match self {
            Self::Native(facts) => facts.tx_count(),
            #[cfg(feature = "kernel")]
            Self::Kernel(block) => block.transaction_count(),
        }
    }

    /// Consumes the parse, transferring facts and retaining only script backend state.
    /// Callers must check the transaction count against `txs` before this handoff.
    /// Kernel transaction-ID extraction errors retain their original mapping.
    pub fn into_parts(
        self,
        #[cfg_attr(not(feature = "kernel"), expect(unused_variables))] txs: &[Tx],
    ) -> Result<(BlockScriptSource, crate::block_view::BlockFacts), ConsensusError> {
        match self {
            Self::Native(facts) => Ok((BlockScriptSource::Native, facts)),
            #[cfg(feature = "kernel")]
            Self::Kernel(block) => {
                let txids = block.txids()?;
                let facts = crate::block_view::BlockFacts::from_txids(txs, txids);
                Ok((BlockScriptSource::Kernel(block), facts))
            }
        }
    }
}

/// Backend state retained after block facts move into the validation view.
/// Native checks use the bound decoded transactions; kernel checks retain the parse.
#[derive(Debug)]
pub enum BlockScriptSource {
    /// Native checks need no second owner for parsed block facts.
    Native,
    #[cfg(feature = "kernel")]
    /// Kernel transactions borrow this independently parsed block.
    Kernel(kernel_backend::KernelBlock),
}

impl BlockScriptSource {
    /// Prepares resolved prevouts for this block's engine.
    /// `PrevoutCount`/`PrevoutMismatch` precede backend work; setup errors map to `Kernel`.
    pub(crate) fn prepare_tx<'b>(
        &'b self,
        #[cfg_attr(not(feature = "kernel"), expect(unused_variables))] index: usize,
        tx: &'b Tx,
        spent_outputs: Vec<(OutPoint, TxOut)>,
    ) -> Result<PreparedTx<'b>, ConsensusError> {
        match self {
            Self::Native => Ok(PreparedTx::Native(
                bitcoin_rs_script::PreparedTransaction::from_owned(tx, spent_outputs)?,
            )),
            #[cfg(feature = "kernel")]
            Self::Kernel(block) => {
                bitcoin_rs_script::validate_prevouts(tx, &spent_outputs)?;
                block.prepare_tx(index, spent_outputs)
            }
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

#[cfg_attr(
    feature = "kernel",
    expect(
        clippy::large_enum_variant,
        reason = "retain the fixed-size native aggregate cache inline instead of allocating for every transaction"
    )
)]
pub(crate) enum PreparedTx<'b> {
    Native(bitcoin_rs_script::PreparedTransaction<'b>),
    #[cfg(feature = "kernel")]
    Kernel {
        state: kernel_backend::PreparedKernelTx<bitcoinkernel::TransactionRef<'b>>,
        spent_outputs: Vec<TxOut>,
    },
}

/// Verifies an input under the engine and ordered prevouts retained at preparation.
pub(crate) fn verify_prepared_input(
    prepared: &PreparedTx<'_>,
    input_index: usize,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    match prepared {
        PreparedTx::Native(state) => {
            crate::verify_tx::verify_input_script_native(state, input_index, flags)
        }
        #[cfg(feature = "kernel")]
        PreparedTx::Kernel {
            state,
            spent_outputs,
        } => {
            let Some(prevout) = spent_outputs.get(input_index) else {
                return Err(ConsensusError::Kernel(format!(
                    "input index {input_index} out of range for {} spent outputs",
                    spent_outputs.len()
                )));
            };
            kernel_backend::verify_prepared_input(state, prevout, input_index, flags)
        }
    }
}

/// Verifies every input under `engine`, failing closed if unavailable.
///
/// `spent_outputs` must pair input outpoints and outputs in input order.
/// `PrevoutCount`/`PrevoutMismatch` precede backend work; script/setup failures
/// map to `Script`/`Kernel`.
pub fn verify_tx_scripts(
    tx: &Tx,
    spent_outputs: &[(OutPoint, TxOut)],
    flags: VerifyFlags,
    engine: ValidationEngine,
) -> Result<(), ConsensusError> {
    match engine {
        ValidationEngine::Native => {
            let prepared = bitcoin_rs_script::PreparedTransaction::new(tx, spent_outputs)?;
            for (input_index, _) in spent_outputs.iter().enumerate() {
                crate::verify_tx::verify_input_script_native(&prepared, input_index, flags)?;
            }
            Ok(())
        }
        ValidationEngine::Kernel => {
            bitcoin_rs_script::validate_prevouts(tx, spent_outputs)?;
            verify_tx_scripts_kernel(tx, spent_outputs, flags)
        }
    }
}

#[cfg(feature = "kernel")]
fn verify_tx_scripts_kernel(
    tx: &Tx,
    spent_outputs: &[(OutPoint, TxOut)],
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    kernel_backend::verify_tx_scripts(tx, spent_outputs, flags)
}

#[cfg(not(feature = "kernel"))]
fn verify_tx_scripts_kernel(
    _tx: &Tx,
    _spent_outputs: &[(OutPoint, TxOut)],
    _flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    Err(kernel_not_compiled())
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{Network, consensus_bytes};

    use super::*;

    #[test]
    fn block_preparation_rejects_misordered_prevout_identities() {
        let mut block = Network::Regtest.genesis_block();
        let mut second_input = block.txs[0].inputs[0].clone();
        second_input.previous_output.vout = 0;
        block.txs[0].inputs.push(second_input);
        let tx = &block.txs[0];
        let rows: Vec<_> = tx
            .inputs
            .iter()
            .map(|input| (input.previous_output, tx.outputs[0].clone()))
            .collect();
        let mut swapped = rows.clone();
        swapped.swap(0, 1);
        for engine in ValidationEngine::ALL
            .iter()
            .copied()
            .filter(|engine| engine.is_supported())
        {
            let parsed = BlockParse::parse(&consensus_bytes(&block), engine)
                .unwrap_or_else(|error| panic!("fixture parse: {error}"));
            let (parsed, _) = parsed
                .into_parts(&block.txs)
                .unwrap_or_else(|error| panic!("fixture facts: {error}"));
            assert!(parsed.prepare_tx(0, tx, rows.clone()).is_ok());
            assert!(matches!(
                parsed.prepare_tx(0, tx, swapped.clone()),
                Err(ConsensusError::PrevoutMismatch { input_index: 0 })
            ));
        }
    }

    #[cfg(feature = "kernel")]
    #[test]
    fn kernel_verify_api_error_propagates_as_kernel_error() {
        let block = Network::Regtest.genesis_block();
        let tx = &block.txs[0];
        let tx_bytes = consensus_bytes(tx);
        let kernel_tx = bitcoinkernel::Transaction::new(&tx_bytes)
            .unwrap_or_else(|error| panic!("genesis tx kernel parse: {error}"));
        let prevout = tx.outputs[0].clone();
        let prepared = kernel_backend::prepare_kernel_tx(
            kernel_tx,
            &[(tx.inputs[0].previous_output, prevout.clone())],
        )
        .unwrap_or_else(|error| panic!("prepare genesis tx: {error}"));
        // Passing an out-of-bounds input index causes bitcoinkernel::verify to return
        // KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex), a kernel API/setup error.
        let err =
            kernel_backend::verify_prepared_input(&prepared, &prevout, 999, VerifyFlags::NONE);
        assert!(
            matches!(err, Err(ConsensusError::Kernel(ref msg)) if msg.contains("input index")),
            "real kernel verification API error must map to ConsensusError::Kernel, got: {err:?}"
        );
        assert!(
            !matches!(err, Err(ConsensusError::Script { .. })),
            "real kernel verification API error must never masquerade as ConsensusError::Script"
        );
    }
}
