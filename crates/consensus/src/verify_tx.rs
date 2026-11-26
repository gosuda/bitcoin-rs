use std::collections::HashSet;
use std::time::Instant;

use crate::primitives::{Amount, OutPoint, Sequence, Tx, TxOut, TxView, Wtxid};

use crate::block_view::{BlockView, BlockViewSource};
use crate::script::PreparedTransaction;
use crate::script::VerifyFlags;
use crate::sigops::transaction_sigop_cost_view;
use rayon::prelude::*;

use crate::ScriptEngine;
use crate::UtxoView;
use crate::{ConsensusError, MAX_BLOCK_SIGOPS_COST, ValidationEngine};

use crate::primitives::{LOCKTIME_THRESHOLD, SEQUENCE_FINAL};
const MIN_COINBASE_SCRIPT_SIG_SIZE: usize = 2;
const MAX_COINBASE_SCRIPT_SIG_SIZE: usize = 100;

pub(crate) const COINBASE_MATURITY: u32 = 100;

const MIN_PARALLEL_SCRIPT_CHECKS: usize = 32;

#[must_use]
pub fn is_final_tx_view(tx: TxView<'_>, block_height: u32, locktime_cutoff: u32) -> bool {
    let lock_time = tx.lock_time().to_consensus();
    if lock_time == 0 {
        return true;
    }

    let threshold = if lock_time < LOCKTIME_THRESHOLD {
        block_height
    } else {
        locktime_cutoff
    };
    if lock_time < threshold {
        return true;
    }

    for i in 0..tx.input_count() {
        if tx.input_sequence(i) != Sequence::from_consensus(SEQUENCE_FINAL) {
            return false;
        }
    }
    true
}

#[must_use]
pub fn is_final_tx(tx: &Tx, block_height: u32, locktime_cutoff: u32) -> bool {
    is_final_tx_view(tx.into(), block_height, locktime_cutoff)
}

pub fn verify_coinbase_script_sig_size_view(tx: TxView<'_>) -> Result<(), ConsensusError> {
    if tx.is_coinbase() && tx.input_count() > 0 {
        let len = tx.input_script_sig(0).len();
        if !(MIN_COINBASE_SCRIPT_SIG_SIZE..=MAX_COINBASE_SCRIPT_SIG_SIZE).contains(&len) {
            return Err(ConsensusError::CoinbaseScriptSigSize { len });
        }
    }
    Ok(())
}

pub fn verify_coinbase_script_sig_size(tx: &Tx) -> Result<(), ConsensusError> {
    verify_coinbase_script_sig_size_view(tx.into())
}

pub fn check_coinbase_maturity(
    coinbase: bool,
    created_height: u32,
    spend_height: u32,
) -> Result<(), ConsensusError> {
    let depth = spend_height.saturating_sub(created_height);
    if coinbase && depth < COINBASE_MATURITY {
        return Err(ConsensusError::Bip {
            bip: "COINBASE_MATURITY",
            reason: format!(
                "spent coinbase output created at height {created_height} cannot be spent at height {spend_height} (depth {depth} < {COINBASE_MATURITY})"
            ),
        });
    }
    Ok(())
}

pub fn verify_transaction(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    engine: ValidationEngine,
    signature_cache: Option<&crate::script::SignatureCache>,
) -> Result<(), ConsensusError> {
    verify_transaction_with_locktime_cutoff(
        tx.into(),
        prevouts,
        height,
        locktime_cutoff,
        flags,
        Some(engine),
        signature_cache,
    )
}

pub fn verify_transaction_non_script(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_with_locktime_cutoff(
        tx.into(),
        prevouts,
        height,
        locktime_cutoff,
        flags,
        None,
        None,
    )
}

pub fn verify_transaction_non_script_view(
    tx: TxView<'_>,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_with_locktime_cutoff(
        tx,
        prevouts,
        height,
        locktime_cutoff,
        flags,
        None,
        None,
    )
}

fn verify_transaction_with_locktime_cutoff(
    tx: TxView<'_>,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    engine: Option<ValidationEngine>,
    signature_cache: Option<&crate::script::SignatureCache>,
) -> Result<(), ConsensusError> {
    if let Some(engine) = engine
        && !engine.is_supported()
    {
        return Err(ConsensusError::UnsupportedEngine { engine });
    }
    let Some(prep) = prepare_tx_checks(tx, height, locktime_cutoff, |_, outpoint| {
        prevouts.lookup(outpoint)
    })?
    else {
        return Ok(());
    };

    if let Some(engine) = engine {
        crate::kernel::verify_tx_scripts_view(tx, &prep.prevouts, flags, engine, signature_cache)?;
    }

    finalize_tx_value_and_sigops(tx, &prep, flags)
}

struct TxPrep {
    prevouts: Vec<(OutPoint, TxOut)>,
    input_value: u64,
    output_value: u64,
}

pub fn verify_transaction_input_outpoints_view(tx: TxView<'_>) -> Result<(), ConsensusError> {
    if tx.is_coinbase() {
        return Ok(());
    }
    let mut seen = HashSet::with_capacity(tx.input_count());
    for input_index in 0..tx.input_count() {
        let outpoint = tx.input_outpoint(input_index);
        if outpoint.is_null() {
            return Err(ConsensusError::NullPrevout { input_index });
        }
        if !seen.insert(outpoint) {
            return Err(ConsensusError::DuplicateInput { input_index });
        }
    }
    Ok(())
}

pub fn verify_transaction_input_outpoints(tx: &Tx) -> Result<(), ConsensusError> {
    verify_transaction_input_outpoints_view(tx.into())
}

pub(crate) fn verify_transaction_structure_view(tx: TxView<'_>) -> Result<u64, ConsensusError> {
    if tx.input_count() == 0 {
        return Err(ConsensusError::EmptyInputs);
    }
    if tx.output_count() == 0 {
        return Err(ConsensusError::EmptyOutputs);
    }
    let output_value = total_output_value_view(tx)?;
    if tx.is_coinbase() {
        verify_coinbase_script_sig_size_view(tx)?;
    } else {
        verify_transaction_input_outpoints_view(tx)?;
    }
    Ok(output_value)
}

pub(crate) fn verify_transaction_structure(tx: &Tx) -> Result<u64, ConsensusError> {
    verify_transaction_structure_view(tx.into())
}

fn total_output_value_view(tx: TxView<'_>) -> Result<u64, ConsensusError> {
    let mut sum = 0u64;
    for i in 0..tx.output_count() {
        let next = sum
            .checked_add(tx.output_value(i).to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        if Amount::from_sat(next) > Amount::MAX_MONEY {
            return Err(ConsensusError::OutputValueOverflow);
        }
        sum = next;
    }
    Ok(sum)
}

fn prepare_tx_checks(
    tx: TxView<'_>,
    height: u32,
    locktime_cutoff: u32,
    mut lookup: impl FnMut(usize, &OutPoint) -> Option<TxOut>,
) -> Result<Option<TxPrep>, ConsensusError> {
    if !is_final_tx_view(tx, height, locktime_cutoff) {
        return Err(ConsensusError::Bip {
            bip: "BIP113",
            reason: format!(
                "non-final transaction at height {height} locktime cutoff \
                 {locktime_cutoff}: locktime {}",
                tx.lock_time()
            ),
        });
    }

    let output_value = verify_transaction_structure_view(tx)?;
    if tx.is_coinbase() {
        return Ok(None);
    }

    let mut input_value = 0u64;
    let mut prevouts = Vec::with_capacity(tx.input_count());
    for input_index in 0..tx.input_count() {
        let outpoint = tx.input_outpoint(input_index);
        let prevout =
            lookup(input_index, &outpoint).ok_or(ConsensusError::MissingPrevout { input_index })?;
        input_value = input_value
            .checked_add(prevout.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        prevouts.push((outpoint, prevout));
    }

    Ok(Some(TxPrep {
        prevouts,
        input_value,
        output_value,
    }))
}

fn finalize_tx_value_and_sigops(
    tx: TxView<'_>,
    prep: &TxPrep,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    if prep.input_value < prep.output_value {
        return Err(ConsensusError::InputsLessThanOutputs {
            input_value: prep.input_value,
            output_value: prep.output_value,
        });
    }

    let sigop_cost = transaction_sigop_cost_view(tx, &prep.prevouts, flags);
    if sigop_cost > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: MAX_BLOCK_SIGOPS_COST,
        });
    }
    Ok(())
}

pub(crate) fn verify_input_script_native(
    prepared: &PreparedTransaction<'_>,
    input_index: usize,
    flags: VerifyFlags,
    signature_cache: Option<&crate::script::SignatureCache>,
) -> Result<(), ConsensusError> {
    prepared
        .verify_input(input_index, flags, signature_cache)
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: error.to_string(),
            engine: ScriptEngine::Native,
        })?;
    Ok(())
}

struct PreparedTx<'b> {
    pre_error: Option<ConsensusError>,
    post_error: Option<ConsensusError>,
    checks_start: usize,
    checks_len: usize,
    script_state: Option<crate::kernel::PreparedTx<'b>>,
}

struct InputCheck {
    prepared_index: usize,
    input_index: usize,
}

#[derive(Clone, Copy, Default)]
pub struct ScriptStageTimings {
    pub prepare_seconds: f64,
    pub parallel_seconds: f64,
}

pub fn verify_block_input_scripts<'tx, 'checks>(
    view: &mut BlockView<'tx>,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    timings: &mut ScriptStageTimings,
    script_source: &'checks crate::kernel::BlockScriptSource,
    script_cache: Option<&crate::script_cache::ScriptExecutionCache>,
) -> Result<(), ConsensusError>
where
    'tx: 'checks,
{
    let prepare_started = Instant::now();
    let mut takes = script_cache.map(crate::script_cache::WindowCacheTakes::new);
    let unit = prepare_block_script_checks(
        view,
        height,
        locktime_cutoff,
        flags,
        script_source,
        takes.as_mut(),
    )?;
    timings.prepare_seconds = prepare_started.elapsed().as_secs_f64();

    let unit_slice = core::slice::from_ref(&unit);
    let parallel_started = Instant::now();
    let results = run_prepared_checks(unit_slice);
    timings.parallel_seconds = parallel_started.elapsed().as_secs_f64();
    first_unit_failure(unit_slice, &results).map_err(|failure| failure.error)
}

pub struct BlockScriptChecks<'b> {
    prepared: Vec<PreparedTx<'b>>,
    checks: Vec<InputCheck>,
    flags: VerifyFlags,
}

#[derive(Debug)]
pub struct BatchScriptFailure {
    pub unit: usize,
    pub error: ConsensusError,
}

pub fn prepare_block_script_checks<'tx, 'checks>(
    view: &mut BlockView<'tx>,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    script_source: &'checks crate::kernel::BlockScriptSource,
    takes: Option<&mut crate::script_cache::WindowCacheTakes<'_>>,
) -> Result<BlockScriptChecks<'checks>, ConsensusError>
where
    'tx: 'checks,
{
    let wtxids: Vec<Wtxid> = if takes.is_some() {
        match view.facts().wtxids().map(<[Wtxid]>::to_vec) {
            Some(wtxids) => wtxids,
            None if view.facts().has_witness() => view.witness_ids().to_vec(),
            None => view.txids().iter().map(|txid| Wtxid(txid.0)).collect(),
        }
    } else {
        Vec::new()
    };
    let (source, resolved) = view.parts_mut();
    let tx_count = match source {
        BlockViewSource::Txs(txs) => txs.len(),
        BlockViewSource::Image(img) => img.tx_count(),
    };
    if tx_count != resolved.len() {
        return Err(ConsensusError::PrevoutMatrixSize {
            expected: tx_count,
            actual: resolved.len(),
        });
    }
    if takes.is_some() && tx_count != wtxids.len() {
        return Err(ConsensusError::PrevoutMatrixSize {
            expected: tx_count,
            actual: wtxids.len(),
        });
    }
    let (prepared, checks) = prepare_block_input_checks(
        source,
        resolved,
        &wtxids,
        height,
        locktime_cutoff,
        flags,
        script_source,
        takes,
    );
    Ok(BlockScriptChecks {
        prepared,
        checks,
        flags,
    })
}

fn run_prepared_checks(units: &[BlockScriptChecks<'_>]) -> Vec<Result<(), ConsensusError>> {
    let run = |(unit_index, check): &(usize, &InputCheck)| check_input(&units[*unit_index], check);
    let flat: Vec<(usize, &InputCheck)> = units
        .iter()
        .enumerate()
        .flat_map(|(index, unit)| unit.checks.iter().map(move |check| (index, check)))
        .collect();
    if flat.len() < MIN_PARALLEL_SCRIPT_CHECKS {
        flat.iter().map(run).collect()
    } else {
        flat.par_iter().map(run).collect()
    }
}

fn first_unit_failure(
    units: &[BlockScriptChecks<'_>],
    results: &[Result<(), ConsensusError>],
) -> Result<(), BatchScriptFailure> {
    let mut offsets = Vec::with_capacity(units.len());
    let mut total = 0_usize;
    for unit in units {
        offsets.push(total);
        let Some(next) = total.checked_add(unit.checks.len()) else {
            return Err(layout_failure(0));
        };
        total = next;
    }

    for (unit_index, unit) in units.iter().enumerate() {
        let from = offsets[unit_index];
        let Some(to) = from.checked_add(unit.checks.len()) else {
            return Err(layout_failure(unit_index));
        };
        let Some(slice) = results.get(from..to) else {
            return Err(layout_failure(unit_index));
        };
        match first_prepared_error(&unit.prepared, slice) {
            Ok(Some(error)) => {
                return Err(BatchScriptFailure {
                    unit: unit_index,
                    error,
                });
            }
            Ok(None) => {}
            Err(()) => return Err(layout_failure(unit_index)),
        }
    }
    Ok(())
}

pub fn verify_prepared_units(units: &[BlockScriptChecks<'_>]) -> Result<(), BatchScriptFailure> {
    let results = run_prepared_checks(units);
    first_unit_failure(units, &results)
}

fn layout_failure(unit: usize) -> BatchScriptFailure {
    BatchScriptFailure {
        unit,
        error: ConsensusError::Kernel(
            "internal: prepared script-check layout does not match its results".to_owned(),
        ),
    }
}

fn first_prepared_error(
    prepared: &[PreparedTx<'_>],
    results: &[Result<(), ConsensusError>],
) -> Result<Option<ConsensusError>, ()> {
    for prep in prepared {
        if let Some(error) = &prep.pre_error {
            return Ok(Some(error.clone()));
        }
        let Some(to) = prep.checks_start.checked_add(prep.checks_len) else {
            return Err(());
        };
        let Some(slice) = results.get(prep.checks_start..to) else {
            return Err(());
        };
        for result in slice {
            if let Err(error) = result {
                return Ok(Some(error.clone()));
            }
        }
        if let Some(error) = &prep.post_error {
            return Ok(Some(error.clone()));
        }
    }
    Ok(None)
}

fn prepare_block_input_checks<'b>(
    source: BlockViewSource<'b>,
    resolved: &mut [Vec<Option<TxOut>>],
    wtxids: &[Wtxid],
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    script_source: &'b crate::kernel::BlockScriptSource,
    mut takes: Option<&mut crate::script_cache::WindowCacheTakes<'_>>,
) -> (Vec<PreparedTx<'b>>, Vec<InputCheck>) {
    let tx_count = match source {
        BlockViewSource::Txs(txs) => txs.len(),
        BlockViewSource::Image(img) => img.tx_count(),
    };
    let mut prepared = Vec::with_capacity(tx_count);
    let mut checks = Vec::new();
    for tx_index in 0..tx_count {
        let tx = match source {
            BlockViewSource::Txs(txs) => TxView::Owned(&txs[tx_index]),
            BlockViewSource::Image(img) => TxView::View(img.tx(tx_index)),
        };
        let resolved_inputs = &mut resolved[tx_index];
        let prep = match prepare_tx_checks(tx, height, locktime_cutoff, |input_index, _| {
            resolved_inputs.get_mut(input_index).and_then(Option::take)
        }) {
            Ok(Some(prep)) => prep,
            Ok(None) => {
                prepared.push(PreparedTx {
                    pre_error: None,
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    script_state: None,
                });
                continue;
            }
            Err(pre_error) => {
                prepared.push(PreparedTx {
                    pre_error: Some(pre_error),
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    script_state: None,
                });
                break;
            }
        };

        if takes
            .as_mut()
            .is_some_and(|takes| takes.take(wtxids[tx_index], flags))
        {
            let post_error = finalize_tx_value_and_sigops(tx, &prep, flags).err();
            let stop_after_tx = post_error.is_some();
            prepared.push(PreparedTx {
                pre_error: None,
                post_error,
                checks_start: checks.len(),
                checks_len: 0,
                script_state: None,
            });
            if stop_after_tx {
                break;
            }
            continue;
        }

        let post_error = finalize_tx_value_and_sigops(tx, &prep, flags).err();
        let script_state = match script_source.prepare_tx(tx_index, tx, prep.prevouts) {
            Ok(state) => state,
            Err(setup_error) => {
                prepared.push(PreparedTx {
                    pre_error: Some(setup_error),
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    script_state: None,
                });
                break;
            }
        };

        let prepared_index = prepared.len();
        let checks_start = checks.len();
        for input_index in 0..tx.input_count() {
            checks.push(InputCheck {
                prepared_index,
                input_index,
            });
        }
        let checks_len = tx.input_count();

        let stop_after_tx = post_error.is_some();
        prepared.push(PreparedTx {
            pre_error: None,
            post_error,
            checks_start,
            checks_len,
            script_state: Some(script_state),
        });
        if stop_after_tx {
            break;
        }
    }
    (prepared, checks)
}

fn check_input(unit: &BlockScriptChecks<'_>, check: &InputCheck) -> Result<(), ConsensusError> {
    let prep = &unit.prepared[check.prepared_index];
    let script_state = prep.script_state.as_ref().ok_or_else(|| {
        ConsensusError::Kernel("clean non-coinbase tx lost prepared script state".to_owned())
    })?;
    crate::kernel::verify_prepared_input(script_state, check.input_index, unit.flags)
}

#[cfg(test)]
mod tests {
    use crate::primitives::{
        Amount, Block, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence, Tx,
        TxIn, TxOut, Txid, Witness, Wtxid, consensus_bytes, deserialize,
    };
    #[cfg(not(feature = "kernel"))]
    use crate::primitives::{Sighash, SighashCache};
    use crate::script::opcode::{OP_EQUAL, OP_HASH160};
    use crate::script::push_data;
    use crate::script::{VerifyFlags, push_int};
    use bitcoin::hashes::Hash as _;

    use super::{
        ScriptStageTimings, is_final_tx, verify_coinbase_script_sig_size, verify_transaction,
    };
    use crate::ValidationEngine;

    use crate::test_error::TestError;

    fn parsed_block_for(txs: &[Tx], engine: ValidationEngine) -> crate::kernel::BlockScriptSource {
        let block = Block {
            header: Header {
                version: 1,
                bits: CompactTarget::from_consensus(0x2000_ffff),
                ..Header::default()
            },
            txs: txs.to_vec(),
        };
        crate::kernel::BlockParse::parse(&consensus_bytes(&block), engine)
            .unwrap_or_else(|error| panic!("synthetic block must parse: {error}"))
            .into_parts(txs)
            .unwrap_or_else(|error| panic!("synthetic facts: {error}"))
            .0
    }

    #[cfg(feature = "kernel")]
    const TEST_ENGINE: ValidationEngine = ValidationEngine::Kernel;
    #[cfg(not(feature = "kernel"))]
    const TEST_ENGINE: ValidationEngine = ValidationEngine::Native;

    fn test_block_parse(txs: &[Tx]) -> crate::kernel::BlockScriptSource {
        parsed_block_for(txs, TEST_ENGINE)
    }

    fn block_view_for(
        txs: &[Tx],
        resolved: Vec<Vec<Option<TxOut>>>,
    ) -> crate::block_view::BlockView<'_> {
        let mut view = crate::block_view::BlockView::from_facts(
            txs,
            crate::block_view::BlockFacts::from_txids(txs, txs.iter().map(Tx::txid).collect()),
        );
        view.set_resolved(resolved);
        view
    }
    use crate::{ConsensusError, ScriptEngine, UtxoView};

    impl UtxoView for hashbrown::HashMap<OutPoint, TxOut> {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.get(outpoint).cloned()
        }
    }

    #[test]
    fn assume_valid_and_prepared_sigop_checks_follow_witness_activation() -> Result<(), TestError> {
        let cost = crate::MAX_BLOCK_SIGOPS_COST + 1;
        let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[9; 32])), 0);
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: outpoint,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0xac; usize::try_from(cost)?]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::ZERO,
        };
        let prevouts = hashbrown::HashMap::from([(
            outpoint,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Script::from_bytes([vec![0x00, 0x20], vec![1; 32]].concat()),
            },
        )]);
        assert_eq!(
            super::verify_transaction_non_script(&tx, &prevouts, 0, 0, VerifyFlags::P2SH),
            Ok(()),
        );
        assert_eq!(
            super::verify_transaction_non_script(&tx, &prevouts, 0, 0, VerifyFlags::MANDATORY),
            Err(ConsensusError::SigopsLimit {
                cost,
                max: crate::MAX_BLOCK_SIGOPS_COST
            }),
        );
        let txs = vec![tx];
        let block = test_block_parse(&txs);
        let resolved = vec![vec![prevouts.get(&outpoint).cloned()]];
        let inactive = super::prepare_block_script_checks(
            &mut block_view_for(&txs, resolved.clone()),
            0,
            0,
            VerifyFlags::P2SH,
            &block,
            None,
        )?;
        assert!(inactive.prepared[0].post_error.is_none());
        assert!(super::verify_prepared_units(core::slice::from_ref(&inactive)).is_ok());
        let active = super::prepare_block_script_checks(
            &mut block_view_for(&txs, resolved),
            0,
            0,
            VerifyFlags::MANDATORY,
            &block,
            None,
        )?;
        assert_eq!(
            active.prepared[0].post_error,
            Some(ConsensusError::SigopsLimit {
                cost,
                max: crate::MAX_BLOCK_SIGOPS_COST,
            })
        );
        Ok(())
    }

    #[test]
    fn coinbase_script_sig_size_bounds_are_enforced_without_prevout_lookup() {
        let utxos = hashbrown::HashMap::new();
        for len in [0usize, 1, 2, 50, 100, 101] {
            let tx = coinbase_transaction_with_script_sig_len(len);
            let expected = if (2..=100).contains(&len) {
                Ok(())
            } else {
                Err(ConsensusError::CoinbaseScriptSigSize { len })
            };
            assert_eq!(verify_coinbase_script_sig_size(&tx), expected, "len {len}");
            assert_eq!(
                verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE, None),
                expected,
                "len {len}"
            );
        }
    }

    #[test]
    fn duplicate_non_coinbase_input_is_rejected() {
        let spent = outpoint(1);
        let tx = spend_tx(vec![spending_input(spent), spending_input(spent)], 50);
        assert_eq!(
            verify_transaction(
                &tx,
                &utxo_set([(spent, op1_txout(100))]),
                0,
                0,
                VerifyFlags::NONE,
                TEST_ENGINE,
                None
            ),
            Err(ConsensusError::DuplicateInput { input_index: 1 })
        );
    }

    #[test]
    #[cfg(not(feature = "kernel"))]
    fn verify_transaction_routes_taproot_spends_to_interpreter() {
        let tx = spend_tx(
            vec![
                true_spending_input(outpoint(5)),
                true_spending_input(outpoint(6)),
            ],
            50,
        );
        let taproot = TxOut {
            value: Amount::from_sat(50),
            script_pubkey: [vec![0x51, 0x20], vec![7; 32]].concat().into(),
        };
        assert_eq!(
            verify_transaction(
                &tx,
                &utxo_set([(outpoint(5), taproot), (outpoint(6), op1_txout(50))]),
                0,
                0,
                VerifyFlags::MANDATORY,
                TEST_ENGINE,
                None
            ),
            Err(ConsensusError::Script {
                input_index: 0,
                reason: "script failed: WITNESS_PROGRAM_WITNESS_EMPTY".to_owned(),
                engine: ScriptEngine::Native,
            })
        );
    }

    #[test]
    #[cfg(not(feature = "kernel"))]
    fn verify_transaction_accepts_valid_multi_input_taproot_keypath() {
        use secp256k1::{Keypair, Scalar, SecretKey, XOnlyPublicKey};
        use sha2::{Digest, Sha256};

        let seeds = [1u8, 2u8];
        let mut keypairs = Vec::new();
        let mut prevouts = Vec::new();
        let mut outpoints = Vec::new();
        for (index, seed) in seeds.into_iter().enumerate() {
            let secret =
                SecretKey::from_secret_bytes([seed; 32]).unwrap_or_else(|_| panic!("secret key"));
            let keypair = Keypair::from_secret_key(&secret);
            let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
            let tag = {
                let mut h = Sha256::new();
                h.update(b"TapTweak");
                h.finalize()
            };
            let mut tweak_hash = Sha256::new();
            tweak_hash.update(tag);
            tweak_hash.update(tag);
            tweak_hash.update(xonly.to_byte_array());
            tweak_hash.update([0u8; 32]);
            let tweak_arr: [u8; 32] = tweak_hash.finalize().into();
            let tweak = Scalar::from_be_bytes(tweak_arr).unwrap_or_else(|_| panic!("tweak scalar"));
            let tweaked_keypair = keypair
                .add_xonly_tweak(&tweak)
                .unwrap_or_else(|e| panic!("tweak: {e}"));
            let (output_key, _) = XOnlyPublicKey::from_keypair(&tweaked_keypair);
            let outpoint = OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[seed; 32])),
                vout: u32::try_from(index).unwrap_or_else(|_| panic!("vout")),
            };
            outpoints.push(outpoint);
            let mut script_pubkey = Vec::with_capacity(34);
            script_pubkey.push(0x51);
            script_pubkey.push(0x20);
            script_pubkey.extend_from_slice(&output_key.to_byte_array());
            prevouts.push(TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: script_pubkey.into(),
            });
            keypairs.push(tweaked_keypair);
        }

        let mut tx = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: outpoints
                .iter()
                .copied()
                .map(|previous_output| TxIn {
                    previous_output,
                    sequence: Sequence::MAX,
                    ..TxIn::default()
                })
                .collect(),
            outputs: vec![TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: push_int(1).into(),
            }],
        };

        for (input_idx, keypair) in keypairs.iter().enumerate() {
            let cache = SighashCache::new(&tx);
            let sighash = cache
                .taproot_signature_hash(input_idx, &prevouts, None, None, Sighash::Default)
                .unwrap_or_else(|_| panic!("taproot sighash"));
            let signature = secp256k1::schnorr::sign(sighash.as_byte_array(), keypair);
            tx.inputs[input_idx].witness = vec![signature.to_byte_array().to_vec()].into();
        }

        let mut utxos = hashbrown::HashMap::new();
        for (outpoint, prevout) in outpoints.into_iter().zip(prevouts) {
            utxos.insert(outpoint, prevout);
        }

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE, None),
            Ok(())
        );
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_scripts_preserve_verdicts_and_non_script_bypass() {
        for (seed, rhs, accepted) in [(7, 7, true), (8, 8, false), (9, 8, false)] {
            let outpoint = outpoint(seed);
            let mut input = spending_input(outpoint);
            input.script_sig = [push_int(7), push_int(rhs)].concat().into();
            let mut tx = spend_tx(vec![input], 50);
            tx.version = 1;
            let utxos = utxo_set([(outpoint, op_equal_txout(100))]);
            assert_eq!(
                super::verify_transaction_non_script(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY),
                Ok(()),
                "non-script seed {seed}"
            );
            let verdict =
                verify_transaction(&tx, &utxos, 0, 0, VerifyFlags::MANDATORY, TEST_ENGINE, None);
            if accepted {
                assert_eq!(verdict, Ok(()), "seed {seed}");
            } else {
                let Err(ConsensusError::Script {
                    input_index,
                    reason,
                    engine,
                }) = verdict
                else {
                    panic!("seed {seed}: expected a kernel script rejection");
                };
                assert_eq!(input_index, 0, "seed {seed}");
                assert_eq!(engine, ScriptEngine::Kernel, "seed {seed}");
                assert!(
                    reason
                        .strip_prefix("kernel script verification failed: ")
                        .is_some_and(|verdict| !verdict.is_empty()),
                    "seed {seed}: {reason}"
                );
            }
        }
    }

    #[test]
    fn locktime_finality_uses_the_height_and_the_caller_supplied_cutoff() {
        const TIMESTAMP: u32 = 500_000_100;
        let cases: [(u32, u32, u32, bool); 8] = [
            (0, 0, 0, true),
            (200, 100, 0, false),
            (200, 200, 0, false),
            (200, 201, 0, true),
            (TIMESTAMP, 1, TIMESTAMP - 1, false),
            (TIMESTAMP, 1, TIMESTAMP, false),
            (TIMESTAMP, 1, TIMESTAMP + 1, true),
            (TIMESTAMP, u32::MAX, 0, false),
        ];
        let utxos = hashbrown::HashMap::new();
        for (lock_time, height, cutoff, is_final) in cases {
            let mut tx = spend_tx(vec![spending_input(outpoint(1))], 1_000);
            tx.lock_time = LockTime::from_consensus(lock_time);
            tx.inputs[0].sequence = Sequence::from_consensus(0);
            let label = format!("locktime {lock_time} height {height} cutoff {cutoff}");
            assert_eq!(is_final_tx(&tx, height, cutoff), is_final, "{label}");

            let verdict = verify_transaction(
                &tx,
                &utxos,
                height,
                cutoff,
                VerifyFlags::MANDATORY,
                TEST_ENGINE,
                None,
            );
            if is_final {
                assert_eq!(
                    verdict,
                    Err(ConsensusError::MissingPrevout { input_index: 0 }),
                    "{label}"
                );
            } else {
                assert!(
                    matches!(verdict, Err(ConsensusError::Bip { bip: "BIP113", .. })),
                    "{label}: {verdict:?}"
                );
            }

            tx.inputs[0].sequence = Sequence::MAX;
            assert!(is_final_tx(&tx, height, cutoff), "{label} final sequence");
        }
    }

    fn spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: push_int(1).into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    #[test]
    fn prepared_units_keep_block_order_slices_and_flags() {
        let clean_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![true_spending_input(outpoint(11))], 50),
            spend_tx(vec![true_spending_input(outpoint(12))], 50),
        ];
        let clean_block = test_block_parse(&clean_txs);
        let clean_resolved = vec![
            Vec::new(),
            vec![Some(op1_txout(50))],
            vec![Some(op1_txout(50))],
        ];
        let late_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![true_spending_input(outpoint(1))], 50),
            spend_tx(vec![mismatch_input(outpoint(2))], 50),
        ];
        let late_block = test_block_parse(&late_txs);
        let late_resolved = vec![
            Vec::new(),
            vec![Some(op1_txout(50))],
            vec![Some(op_equal_txout(50))],
        ];
        let early_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![mismatch_input(outpoint(3))], 50),
        ];
        let early_block = test_block_parse(&early_txs);
        let early_resolved = vec![Vec::new(), vec![Some(op_equal_txout(50))]];

        let redeem_script = [0_u8];
        let redeem_hash = bitcoin::hashes::hash160::Hash::hash(&redeem_script);
        let p2sh_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(
                vec![TxIn {
                    previous_output: outpoint(10),
                    script_sig: push_data(&redeem_script).into(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                50,
            ),
        ];
        let p2sh_block = test_block_parse(&p2sh_txs);
        let p2sh_resolved = vec![
            Vec::new(),
            vec![Some(TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::from_bytes(
                    [
                        vec![OP_HASH160],
                        push_data(&redeem_hash.to_byte_array()),
                        vec![OP_EQUAL],
                    ]
                    .concat(),
                ),
            })],
        ];

        let clean = |flags| prepared_unit(&clean_txs, clean_resolved.clone(), &clean_block, flags);
        let late = |flags| prepared_unit(&late_txs, late_resolved.clone(), &late_block, flags);
        let early = |flags| prepared_unit(&early_txs, early_resolved.clone(), &early_block, flags);
        let p2sh = |flags| prepared_unit(&p2sh_txs, p2sh_resolved.clone(), &p2sh_block, flags);
        let failing_unit = |units: &[super::BlockScriptChecks<'_>]| {
            super::verify_prepared_units(units)
                .err()
                .map(|failure| failure.unit)
        };

        let mandatory = VerifyFlags::MANDATORY;
        assert_eq!(
            failing_unit(&[late(mandatory), clean(mandatory), early(mandatory)]),
            Some(0),
            "block order must beat position within a block"
        );
        assert_eq!(
            failing_unit(&[clean(mandatory), clean(mandatory), early(mandatory)]),
            Some(2),
            "misaligned result offsets would blame a clean unit"
        );
        assert_eq!(
            failing_unit(&[p2sh(mandatory)]),
            Some(0),
            "the P2SH fixture must fail under the strict flag set"
        );
        assert_eq!(
            failing_unit(&[clean(mandatory), p2sh(VerifyFlags::NONE)]),
            None,
            "each unit must be checked under the flags bound to it"
        );
    }

    #[test]
    fn a_batched_unit_matches_the_single_block_path() {
        let txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![mismatch_input(outpoint(7))], 50),
        ];
        let block = test_block_parse(&txs);
        let resolved = vec![Vec::new(), vec![Some(op_equal_txout(50))]];

        let single = super::verify_block_input_scripts(
            &mut block_view_for(&txs, resolved.clone()),
            0,
            0,
            VerifyFlags::MANDATORY,
            &mut ScriptStageTimings::default(),
            &block,
            None,
        );
        let units = [prepared_unit(
            &txs,
            resolved,
            &block,
            VerifyFlags::MANDATORY,
        )];
        let batched = super::verify_prepared_units(&units);

        match (single, batched) {
            (Err(single_error), Err(failure)) => assert_eq!(
                format!("{single_error}"),
                format!("{}", failure.error),
                "batched and single-block verdicts must be identical"
            ),
            (single, batched) => panic!(
                "both paths must reject this block: single={:?} batched_ok={}",
                single.err(),
                batched.is_ok()
            ),
        }
    }

    fn prepared_unit<'b>(
        txs: &'b [Tx],
        resolved: Vec<Vec<Option<TxOut>>>,
        block: &'b crate::kernel::BlockScriptSource,
        flags: VerifyFlags,
    ) -> super::BlockScriptChecks<'b> {
        let mut view = block_view_for(txs, resolved);
        match super::prepare_block_script_checks(&mut view, 0, 0, flags, block, None) {
            Ok(unit) => unit,
            Err(error) => panic!("test fixture prevout matrix is malformed: {error}"),
        }
    }

    fn true_spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            sequence: Sequence::MAX,
            ..TxIn::default()
        }
    }

    fn utxo_set<const N: usize>(
        entries: [(OutPoint, TxOut); N],
    ) -> hashbrown::HashMap<OutPoint, TxOut> {
        entries.into_iter().collect()
    }

    fn coinbase_transaction_with_script_sig_len(len: usize) -> Tx {
        Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![1; len].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        }
    }

    fn op1_txout(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: push_int(1).into(),
        }
    }

    fn op_equal_txout(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![OP_EQUAL].into(),
        }
    }

    // SCR-06
    #[test]
    fn script_cache_hit_skips_scripts_for_exact_flags_only() -> Result<(), TestError> {
        use crate::script_cache::{ScriptExecutionCache, WindowCacheTakes};

        let txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![mismatch_input(outpoint(3))], 50),
        ];
        let resolved = vec![vec![], vec![Some(op_equal_txout(50))]];
        let flags = VerifyFlags::MANDATORY;
        let wtxid = txs[1].wtxid();

        let parsed = test_block_parse(&txs);
        let mut view = block_view_for(&txs, resolved.clone());
        let miss = super::prepare_block_script_checks(&mut view, 0, 0, flags, &parsed, None)?;
        assert!(super::verify_prepared_units(core::slice::from_ref(&miss)).is_err());

        let cache = ScriptExecutionCache::new();
        cache.insert(wtxid, flags);
        let parsed = test_block_parse(&txs);
        let mut view = block_view_for(&txs, resolved.clone());
        let _ = view.witness_ids();
        let mut takes = WindowCacheTakes::new(&cache);
        let hit =
            super::prepare_block_script_checks(&mut view, 0, 0, flags, &parsed, Some(&mut takes))?;
        assert!(super::verify_prepared_units(core::slice::from_ref(&hit)).is_ok());

        let parsed = test_block_parse(&txs);
        let mut view = block_view_for(&txs, resolved.clone());
        let replay =
            super::prepare_block_script_checks(&mut view, 0, 0, flags, &parsed, Some(&mut takes))?;
        assert!(super::verify_prepared_units(core::slice::from_ref(&replay)).is_err());

        let other = ScriptExecutionCache::new();
        other.insert(wtxid, VerifyFlags::P2SH);
        let mut other_takes = WindowCacheTakes::new(&other);
        let parsed = test_block_parse(&txs);
        let mut view = block_view_for(&txs, resolved);
        let wrong = super::prepare_block_script_checks(
            &mut view,
            0,
            0,
            flags,
            &parsed,
            Some(&mut other_takes),
        )?;
        assert!(super::verify_prepared_units(core::slice::from_ref(&wrong)).is_err());
        Ok(())
    }

    #[test]
    fn prepared_error_selection_keeps_pre_script_post_order() {
        let resolved = vec![vec![], vec![Some(op1_txout(50))]];
        let balanced_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![true_spending_input(outpoint(1))], 50),
        ];
        let overdraft_txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![true_spending_input(outpoint(1))], 60),
        ];
        let parsed = test_block_parse(&overdraft_txs);

        let mut view = block_view_for(&overdraft_txs, resolved.clone());
        let overdraft =
            super::prepare_block_script_checks(&mut view, 0, 0, VerifyFlags::NONE, &parsed, None)
                .unwrap_or_else(|error| panic!("fixture prevouts resolve: {error}"));
        assert!(overdraft.prepared[1].script_state.is_some());
        let verdict = super::verify_prepared_units(core::slice::from_ref(&overdraft));
        assert!(
            matches!(
                verdict,
                Err(super::BatchScriptFailure {
                    unit: 0,
                    error: ConsensusError::InputsLessThanOutputs {
                        input_value: 50,
                        output_value: 60,
                    },
                })
            ),
            "actual: {verdict:?}"
        );

        let balanced_parsed = test_block_parse(&balanced_txs);
        let mut view = block_view_for(&balanced_txs, resolved);
        let balanced = super::prepare_block_script_checks(
            &mut view,
            0,
            0,
            VerifyFlags::NONE,
            &balanced_parsed,
            None,
        )
        .unwrap_or_else(|error| panic!("fixture prevouts resolve: {error}"));
        assert!(super::verify_prepared_units(core::slice::from_ref(&balanced)).is_ok());
    }

    fn mismatch_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: [push_int(7), push_int(8)].concat().into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    fn witnessed_mismatch_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            witness: Witness::from_stack(vec![vec![0x51]]),
            ..mismatch_input(outpoint)
        }
    }

    // SCR-06
    #[test]
    fn script_cache_hit_uses_derived_witness_ids_for_witness_bearing_bodies()
    -> Result<(), TestError> {
        use crate::script_cache::{ScriptExecutionCache, WindowCacheTakes};

        let txs = vec![
            coinbase_transaction_with_script_sig_len(2),
            spend_tx(vec![witnessed_mismatch_input(outpoint(3))], 50),
        ];
        let resolved = vec![vec![], vec![Some(op_equal_txout(50))]];
        let flags = VerifyFlags::MANDATORY;
        let wtxid = txs[1].wtxid();
        assert_ne!(
            wtxid,
            Wtxid(txs[1].txid().0),
            "the fixture must separate wtxid from txid"
        );

        let cache = ScriptExecutionCache::new();
        cache.insert(wtxid, flags);
        let parsed = test_block_parse(&txs);
        let mut view = block_view_for(&txs, resolved);
        assert!(
            view.facts().wtxids().is_none(),
            "the fixture must carry no precomputed witness ids"
        );
        let mut takes = WindowCacheTakes::new(&cache);
        let hit =
            super::prepare_block_script_checks(&mut view, 0, 0, flags, &parsed, Some(&mut takes))?;
        assert!(super::verify_prepared_units(core::slice::from_ref(&hit)).is_ok());
        Ok(())
    }

    // BLK-04
    #[test]
    fn block_script_checks_borrow_the_image_without_a_second_object_graph() -> Result<(), TestError>
    {
        use crate::block_view::{BlockFacts, BlockView};
        use crate::kernel::BlockScriptSource;
        use crate::primitives::block::{
            BlockImage, block_image_materialize_call_count,
            transaction_view_materialize_call_count, unwatch_materializations,
            watch_materializations,
        };

        let witness_script = vec![crate::script::opcode::OP_PUSHNUM_1];
        let witness_program = {
            use bitcoin::hashes::sha256;
            let mut program = vec![0x00, 0x20];
            program.extend_from_slice(sha256::Hash::hash(&witness_script).as_byte_array());
            program
        };
        let prevout = TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::from_bytes(witness_program),
        };
        let coinbase = coinbase_transaction_with_script_sig_len(2);
        let spend = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: outpoint(9),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![witness_script]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::from_bytes(vec![crate::script::opcode::OP_PUSHNUM_1]),
            }],
        };
        let block = Block {
            header: Header {
                version: 1,
                bits: CompactTarget::from_consensus(0x2000_ffff),
                ..Header::default()
            },
            txs: vec![coinbase.clone(), spend.clone()],
        };
        let image = BlockImage::from_local(block);
        let expected_txids = [coinbase.txid(), spend.txid()];
        let mut view = BlockView::from_image(&image, BlockFacts::from_image(&image));
        assert_eq!(view.facts().txids(), &expected_txids[..]);
        view.set_resolved(vec![Vec::new(), vec![Some(prevout)]]);

        watch_materializations(&image);
        let checks = super::prepare_block_script_checks(
            &mut view,
            0,
            0,
            VerifyFlags::MANDATORY,
            &BlockScriptSource::Native,
            None,
        )?;
        assert!(
            super::verify_prepared_units(core::slice::from_ref(&checks)).is_ok(),
            "the fixture spend must verify through views over the image"
        );
        let image_copies = block_image_materialize_call_count(&image);
        let view_copies = transaction_view_materialize_call_count(&image);
        unwatch_materializations(&image);
        assert_eq!(
            image_copies, 0,
            "validation must not build a second owned transaction object graph"
        );
        assert_eq!(
            view_copies, 0,
            "validation must read through transaction views over the image"
        );
        Ok(())
    }

    fn spend_tx(inputs: Vec<TxIn>, output_value: u64) -> Tx {
        Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs,
            outputs: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: push_int(1).into(),
            }],
        }
    }

    type OrderingCase = (&'static str, Vec<Tx>, Vec<Vec<Option<TxOut>>>, Expect);

    enum Expect {
        Accepted,
        ScriptAtFirstInput,
        Exact(ConsensusError),
    }

    fn outpoint(seed: u8) -> OutPoint {
        OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[seed; 32])),
            vout: 0,
        }
    }

    #[test]
    fn block_script_verification_reports_the_earliest_block_ordered_error() {
        let coinbase = coinbase_transaction_with_script_sig_len(2);

        let mut parallel_txs = vec![
            coinbase.clone(),
            spend_tx(vec![mismatch_input(outpoint(1))], 50),
        ];
        let mut parallel_resolved = vec![Vec::new(), vec![Some(op_equal_txout(100))]];
        for seed in 2..=u8::try_from(super::MIN_PARALLEL_SCRIPT_CHECKS).unwrap_or(u8::MAX) {
            parallel_txs.push(spend_tx(vec![mismatch_input(outpoint(seed))], 50));
            parallel_resolved.push(vec![Some(op_equal_txout(100))]);
        }

        let produced = spend_tx(vec![true_spending_input(outpoint(1))], 100);
        let produced_out = OutPoint {
            txid: produced.txid(),
            vout: 0,
        };
        let produced_output = produced.outputs[0].clone();
        let bad_producer = spend_tx(vec![mismatch_input(outpoint(1))], 100);
        let bad_producer_out = OutPoint {
            txid: bad_producer.txid(),
            vout: 0,
        };
        let bad_producer_output = bad_producer.outputs[0].clone();

        let cases: [OrderingCase; 7] = [
            (
                "a prevout matrix that does not cover the block",
                vec![coinbase.clone()],
                Vec::new(),
                Expect::Exact(ConsensusError::PrevoutMatrixSize {
                    expected: 1,
                    actual: 0,
                }),
            ),
            (
                "an earlier script error beats a later missing prevout",
                vec![
                    coinbase.clone(),
                    spend_tx(vec![mismatch_input(outpoint(1))], 50),
                    spend_tx(vec![true_spending_input(outpoint(2))], 50),
                ],
                vec![Vec::new(), vec![Some(op_equal_txout(100))], vec![None]],
                Expect::ScriptAtFirstInput,
            ),
            (
                "a script error beats the same transaction's value error",
                vec![
                    coinbase.clone(),
                    spend_tx(vec![mismatch_input(outpoint(1))], 100),
                ],
                vec![Vec::new(), vec![Some(op_equal_txout(50))]],
                Expect::ScriptAtFirstInput,
            ),
            (
                "a later pre-error does not outrank an earlier post-error",
                vec![
                    coinbase.clone(),
                    spend_tx(vec![true_spending_input(outpoint(1))], 100),
                    spend_tx(
                        vec![
                            true_spending_input(outpoint(2)),
                            true_spending_input(outpoint(2)),
                        ],
                        50,
                    ),
                ],
                vec![
                    Vec::new(),
                    vec![Some(op1_txout(50))],
                    vec![Some(op1_txout(50)), Some(op1_txout(50))],
                ],
                Expect::Exact(ConsensusError::InputsLessThanOutputs {
                    input_value: 50,
                    output_value: 100,
                }),
            ),
            (
                "the parallel fan-out still reports the first failure",
                parallel_txs,
                parallel_resolved,
                Expect::ScriptAtFirstInput,
            ),
            (
                "a same-block spend of a valid producing transaction",
                vec![
                    coinbase.clone(),
                    produced,
                    spend_tx(vec![true_spending_input(produced_out)], 90),
                ],
                vec![
                    Vec::new(),
                    vec![Some(op1_txout(100))],
                    vec![Some(produced_output)],
                ],
                Expect::Accepted,
            ),
            (
                "a same-block spend surfaces the producing transaction's error",
                vec![
                    coinbase,
                    bad_producer,
                    spend_tx(vec![true_spending_input(bad_producer_out)], 90),
                ],
                vec![
                    Vec::new(),
                    vec![Some(op_equal_txout(100))],
                    vec![Some(bad_producer_output)],
                ],
                Expect::ScriptAtFirstInput,
            ),
        ];

        for (label, txs, resolved, expect) in cases {
            let result = super::verify_block_input_scripts(
                &mut block_view_for(&txs, resolved),
                0,
                0,
                VerifyFlags::MANDATORY,
                &mut ScriptStageTimings::default(),
                &test_block_parse(&txs),
                None,
            );
            match expect {
                Expect::Accepted => assert_eq!(result, Ok(()), "{label}"),
                Expect::ScriptAtFirstInput => assert!(
                    matches!(result, Err(ConsensusError::Script { input_index: 0, .. })),
                    "{label}: {result:?}"
                ),
                Expect::Exact(error) => assert_eq!(result, Err(error), "{label}"),
            }
        }
    }

    struct TaprootScriptPathFixture {
        tx: Tx,
        prevouts: Vec<TxOut>,
        flags: VerifyFlags,
        height: u32,
    }

    #[derive(serde::Deserialize)]
    struct TaprootScriptPathFile {
        tx_hex: String,
        prevouts: Vec<TaprootScriptPathPrevout>,
        flags: String,
        height: u32,
    }

    #[derive(serde::Deserialize)]
    struct TaprootScriptPathPrevout {
        script_hex: String,
        amount_sat: u64,
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        bitcoin::hex::FromHex::from_hex(hex).unwrap_or_else(|error| panic!("bad hex: {error}"))
    }

    fn load_taproot_scriptpath_fixture() -> TaprootScriptPathFixture {
        let json = include_str!(
            "../../../testdata/consensus/vectors/scripts/taproot_scriptpath_spend.json"
        );
        let file: TaprootScriptPathFile = sonic_rs::from_str(json)
            .unwrap_or_else(|error| panic!("taproot scriptpath fixture parses: {error}"));
        let tx: Tx = deserialize(&decode_hex(&file.tx_hex))
            .unwrap_or_else(|error| panic!("taproot scriptpath tx hex decodes: {error}"));
        assert_eq!(
            file.prevouts.len(),
            tx.inputs.len(),
            "taproot scriptpath fixture: prevout count must match input count"
        );
        let prevouts = file
            .prevouts
            .iter()
            .map(|prevout| TxOut {
                value: Amount::from_sat(prevout.amount_sat),
                script_pubkey: decode_hex(&prevout.script_hex).into(),
            })
            .collect::<Vec<_>>();
        let flags = VerifyFlags::from_core_names(&file.flags)
            .unwrap_or_else(|error| panic!("taproot scriptpath flags parse: {error}"));
        TaprootScriptPathFixture {
            tx,
            prevouts,
            flags,
            height: file.height,
        }
    }

    #[test]
    fn verify_transaction_accepts_the_mainnet_taproot_scriptpath_spend() {
        let fixture = load_taproot_scriptpath_fixture();
        let mut utxos = hashbrown::HashMap::new();
        for (index, prevout) in fixture.prevouts.iter().enumerate() {
            utxos.insert(fixture.tx.inputs[index].previous_output, prevout.clone());
        }
        assert_eq!(
            verify_transaction(
                &fixture.tx,
                &utxos,
                fixture.height,
                0,
                fixture.flags,
                TEST_ENGINE,
                None
            ),
            Ok(())
        );
    }

    #[test]
    fn coinbase_maturity_boundaries() {
        let error = match super::check_coinbase_maturity(true, 10, 109) {
            Ok(()) => panic!("depth 99 must reject"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ConsensusError::Bip {
                bip: "COINBASE_MATURITY",
                ..
            }
        ));
        assert_eq!(super::check_coinbase_maturity(true, 10, 110), Ok(()));
        assert_eq!(super::check_coinbase_maturity(false, 10, 10), Ok(()));
    }
}
