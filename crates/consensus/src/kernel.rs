//! Block parse backends and runtime-selected script preparation.
//!
//! The `kernel` Cargo feature is capability only ("bitcoinkernel support is
//! compiled in"); it never selects an engine. Selection is
//! [`crate::ValidationEngine`] alone: [`ValidationEngine::Kernel`] is refused
//! with the unsupported-build error on a build without this feature, and
//! [`ValidationEngine::Native`] reaches the Rust interpreter in every build —
//! including ones where the kernel backend below is compiled.
//!
//! The parse engine follows the selected validation engine ([`BlockParse::parse`])
//! so one run cannot mix a kernel parse with native script checks or the
//! reverse. Everything script-verification-specific dispatches through
//! [`BlockParse::prepare_tx`] and [`verify_prepared_input`]; the block/tx
//! validation pipeline around them is shared.

use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_script::VerifyFlags;

use crate::ConsensusError;
use crate::ValidationEngine;

/// Returns the unsupported-build error for a kernel request on a build
/// without `kernel` support. Selection fails closed here; it never falls back
/// to another engine. Only builds without the capability produce it.
#[cfg(not(feature = "kernel"))]
fn kernel_not_compiled() -> ConsensusError {
    ConsensusError::UnsupportedEngine {
        engine: ValidationEngine::Kernel,
    }
}

/// Rejects a prevout set that does not cover exactly `input_count` inputs.
///
/// Shared by every seam that hands resolved prevouts to a script backend, so
/// no engine can disagree about it. The dispatch loops are driven by the
/// prevout slice: a short slice would leave trailing inputs silently
/// unverified (fail-open) and a long one would index past the transaction's
/// inputs in the native interpreter.
///
/// # Errors
/// Returns [`ConsensusError::PrevoutCount`] when the counts disagree: the
/// mismatch is a caller wiring bug and is reported backend-neutrally, never
/// as a script failure.
fn ensure_prevout_count(
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
///
/// The native path parses the serialized block once through the checked
/// borrowed layout and keeps every fact derived from that single pass:
/// transaction IDs, witness IDs, weight, and the Merkle root
/// with its mutation flag. Later stages consume those facts through
/// [`NativeBlock::derive_facts`] instead of re-walking or re-hashing the
/// decoded block, so the production native path decodes the transaction tree
/// exactly once.
mod native {
    use bitcoin_rs_primitives::{Tx, Txid};

    use crate::ConsensusError;

    /// A block parsed once through the checked borrowed layout.
    #[derive(Debug, Clone)]
    pub struct NativeBlock {
        facts: crate::block_view::BlockFacts,
    }

    impl NativeBlock {
        /// Parses `raw_block` once and derives every fact the later stages
        /// share.
        ///
        /// # Errors
        /// Returns [`ConsensusError::Encoding`] if `raw_block` is not a valid
        /// block — a backend-neutral parse failure, so kernel-less builds do
        /// not report it as a kernel error.
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
        ///
        /// Infallible here; the `Result` keeps one call shape with the
        /// kernel backend, whose parse can fail per transaction.
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

        /// The shared block facts for a view that owns them.
        ///
        /// The parse already derived everything in one pass, so this clones
        /// the derived facts; the arguments exist for the kernel backend's
        /// call shape and are unused here.
        #[must_use]
        pub fn derive_facts(&self, _txs: &[Tx], _txids: &[Txid]) -> crate::block_view::BlockFacts {
            self.facts.clone()
        }
    }
}

/// The prefix every `bitcoinkernel` script rejection carries.
///
/// It reaches clients inside the BIP22 reject reason, so the bytes are a
/// boundary contract. Classification never reads it: a kernel rejection is
/// identified by [`crate::ScriptEngine::Kernel`].
#[cfg(feature = "kernel")]
pub(crate) const KERNEL_SCRIPT_REJECT_PREFIX: &str = "kernel script verification failed: ";

/// The `libbitcoinkernel` block parse and script backend.
#[cfg(feature = "kernel")]
mod kernel_backend {
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxOut, Txid, consensus_bytes};
    use bitcoin_rs_script::VerifyFlags;

    use crate::{ConsensusError, ScriptEngine};

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

        /// Prepares this block's transaction `index` for parallel per-input
        /// kernel verification over its resolved prevouts.
        pub(super) fn prepare_tx(
            &self,
            index: usize,
            input_count: usize,
            spent_outputs: &[(OutPoint, TxOut)],
        ) -> Result<super::PreparedTx<'_>, ConsensusError> {
            let kernel_tx = self.block.transaction(index).map_err(map_kernel_error)?;
            Ok(super::PreparedTx::Kernel {
                state: prepare_kernel_tx(kernel_tx, input_count, spent_outputs)?,
                spent_outputs: spent_outputs
                    .iter()
                    .map(|(_, output)| output.clone())
                    .collect(),
            })
        }

        /// Derives the shared block facts (weight, Merkle root, and mutation
        /// flag) by reducing the caller's already-surfaced transaction IDs
        /// in one pass over the decoded transactions — the same IDs the
        /// parse produced, without a second kernel FFI crossing.
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

    /// Kernel transaction plus sighash precompute retained for parallel
    /// per-input verification.
    ///
    /// Generic over the transaction handle so the block path can hold a
    /// borrowed [`bitcoinkernel::TransactionRef`] while the standalone
    /// `verify_tx_scripts` entry keeps an owned one.
    pub(crate) struct PreparedKernelTx<T: bitcoinkernel::prelude::TransactionExt> {
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

    /// Verifies a single input against a previously prepared kernel transaction.
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
///
/// The parse engine follows the selected validation engine so a run cannot mix
/// a kernel parse with native script checks or the reverse. Both arms share
/// one shape — parse once, count check, txids — so callers stay uniform
/// whichever engine produced the view, and every engine-specific decision
/// downstream is answered from this value.
#[derive(Debug)]
pub enum BlockParse {
    /// The checked borrowed layout parse. Compiled and supported in every build.
    Native(native::NativeBlock),
    /// The `libbitcoinkernel` parse.
    #[cfg(feature = "kernel")]
    Kernel(kernel_backend::KernelBlock),
}

impl BlockParse {
    /// Parses `raw_block` once under `engine`.
    ///
    /// # Errors
    /// The error variant follows the selected backend: [`ConsensusError::Encoding`]
    /// when the native layout parse rejects the bytes, [`ConsensusError::Kernel`]
    /// when the kernel backend cannot parse them, and
    /// [`ConsensusError::UnsupportedEngine`] when `engine` is
    /// [`ValidationEngine::Kernel`] on a build without kernel support.
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

    /// Prepares one parsed transaction for this parse's engine's parallel
    /// per-input script checks over its resolved prevouts.
    ///
    /// # Errors
    /// Returns [`ConsensusError::Kernel`] when the backend cannot prepare the
    /// transaction (a `spent_outputs` length that disagrees with the input
    /// count is rejected outright, before any backend runs).
    pub(crate) fn prepare_tx<'b>(
        &'b self,
        #[cfg_attr(not(feature = "kernel"), expect(unused_variables))] index: usize,
        tx: &'b Tx,
        spent_outputs: &[(OutPoint, TxOut)],
    ) -> Result<PreparedTx<'b>, ConsensusError> {
        ensure_prevout_count(spent_outputs, tx.inputs.len())?;
        match self {
            Self::Native(_) => Ok(PreparedTx::Native(
                bitcoin_rs_script::PreparedTransaction::new(
                    tx,
                    spent_outputs
                        .iter()
                        .map(|(_, output)| output.clone())
                        .collect(),
                ),
            )),
            #[cfg(feature = "kernel")]
            Self::Kernel(block) => block.prepare_tx(index, tx.inputs.len(), spent_outputs),
        }
    }

    /// The shared block facts (weight, Merkle root, mutation flag) for `txs`.
    ///
    /// The native parse already derived everything in one pass and clones its
    /// facts; the kernel backend reduces the caller's already-surfaced
    /// transaction IDs through the production walker instead of re-crossing
    /// the kernel FFI per transaction.
    #[must_use]
    pub fn derive_facts(&self, txs: &[Tx], txids: &[Txid]) -> crate::block_view::BlockFacts {
        match self {
            Self::Native(block) => block.derive_facts(txs, txids),
            #[cfg(feature = "kernel")]
            Self::Kernel(block) => block.derive_facts(txs, txids),
        }
    }
}

/// Parses one block with `libbitcoinkernel`.
#[cfg(feature = "kernel")]
fn kernel_block_parse(raw_block: &[u8]) -> Result<BlockParse, ConsensusError> {
    kernel_backend::KernelBlock::parse(raw_block).map(BlockParse::Kernel)
}

/// Fails closed: the kernel parse is unavailable in this build.
#[cfg(not(feature = "kernel"))]
fn kernel_block_parse(_raw_block: &[u8]) -> Result<BlockParse, ConsensusError> {
    Err(kernel_not_compiled())
}

/// One prepared transaction's backend state for the parse's engine.
#[cfg_attr(
    feature = "kernel",
    expect(
        clippy::large_enum_variant,
        reason = "retain the fixed-size native aggregate cache inline instead of allocating for every transaction"
    )
)]
pub(crate) enum PreparedTx<'b> {
    /// The native transaction, ordered prevouts and shared aggregate hashes.
    Native(bitcoin_rs_script::PreparedTransaction<'b>),
    /// The kernel transaction and its shared sighash precompute.
    #[cfg(feature = "kernel")]
    Kernel {
        state: kernel_backend::PreparedKernelTx<bitcoinkernel::TransactionRef<'b>>,
        spent_outputs: Vec<TxOut>,
    },
}

/// Verifies one input against its prepared transaction state under the
/// engine that prepared it.
///
/// Each backend retains the ordered spent outputs with its prepared state.
pub(crate) fn verify_prepared_input(
    prepared: &PreparedTx<'_>,
    input_index: usize,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    match prepared {
        // The native per-input script verdict: the interpreter in
        // `bitcoin-rs-script` covers every consensus spend class.
        PreparedTx::Native(state) => {
            crate::verify_tx::verify_input_script_native(state, input_index, flags)
        }
        #[cfg(feature = "kernel")]
        PreparedTx::Kernel {
            state,
            spent_outputs,
        } => kernel_backend::verify_prepared_input(
            state,
            &spent_outputs[input_index],
            input_index,
            flags,
        ),
    }
}

/// Verifies every input script of `tx` under `engine`.
///
/// `spent_outputs` pairs each input's outpoint with the output it spends, in
/// input order. [`ValidationEngine::Native`] runs the portable interpreter in
/// every build; [`ValidationEngine::Kernel`] runs bitcoinkernel where compiled
/// and otherwise fails closed with the unsupported-build error.
///
/// # Errors
/// Per-input verdict failures map to [`ConsensusError::Script`]; backend parse
/// and precompute failures map to [`ConsensusError::Kernel`]. A
/// `spent_outputs` length that disagrees with the input count is rejected
/// before any backend runs: the dispatch below is driven by `spent_outputs`,
/// so a short slice would otherwise leave trailing inputs silently unverified
/// (fail-open) and a long one would index past `tx.inputs` in the native
/// interpreter. The check is shared, not per-branch, so no engine can
/// disagree about it.
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
            let prepared = bitcoin_rs_script::PreparedTransaction::new(tx, spent);
            for (input_index, _) in spent_outputs.iter().enumerate() {
                crate::verify_tx::verify_input_script_native(&prepared, input_index, flags)?;
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
