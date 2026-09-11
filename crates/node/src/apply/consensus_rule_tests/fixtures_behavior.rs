//! Shared contract-test fixture construction.

use super::super::*;
use super::apply_handles_without_tx_index;
use super::fixtures_validation::coinbase_transaction_with_height;
use super::fixtures_validation::op_true_script;
use super::fixtures_validation::spending_transaction_to_script;
use super::fixtures_validation::txids_merkle_root;
use bitcoin_rs_chain::node::ChainWork;
use bitcoin_rs_chain::node::NodeStatus;
use bitcoin_rs_primitives::BlockHash;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::TxIn;
use bitcoin_rs_script::script::push_data;
use bitcoin_rs_script::script::push_int;
use bitcoin_rs_utxo::BlockChanges;
use bitcoin_rs_utxo::UtxoAdd;
use bitcoin_rs_utxo::UtxoSet;
use std::sync::Arc;

/// Parses `block` the way production does, so tests exercise the real
/// one-shot kernel parse rather than a stand-in.
pub(super) fn kernel_block_of(block: &Block) -> bitcoin_rs_consensus::kernel::KernelBlock {
    bitcoin_rs_consensus::kernel::KernelBlock::parse(&consensus_bytes(block))
        .unwrap_or_else(|error| panic!("test block must parse: {error}"))
}

pub(super) fn tx_plan(block: &Block) -> BlockTxPlan {
    plan_block_transactions(block, &block_txids(block))
}

pub(super) fn validation_context(
    block: &Block,
    height: u32,
    locktime_cutoff: u32,
    flags: bitcoin_rs_script::VerifyFlags,
) -> BlockValidationContext {
    BlockValidationContext {
        hash: block.block_hash().0,
        parent: block.header.prev_blockhash.0,
        height,
        flags,
        locktime_cutoff,
    }
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn apply_height_one_block(
    extra: Vec<Tx>,
    coinbase_value: u64,
) -> Result<TipSnapshot, ApplyError> {
    let (handles, block) = height_one_prepared(extra, coinbase_value)?;
    handles.apply_block(&block).map(|outcome| outcome.tip)
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn height_one_prepared(
    extra: Vec<Tx>,
    coinbase_value: u64,
) -> Result<(Chainstate, Block), ApplyError> {
    let funded = OutPoint::new(fixture_txid(0x71), 0);
    // Height 0 so the seeded coin is mature, and non-coinbase so maturity
    // does not apply to it at all.
    let Ok(utxo) = utxo_with_output(funded, 0) else {
        panic!("seeding the fixture UTXO must succeed");
    };
    let genesis = Network::Regtest.genesis_block();
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let mut coinbase = coinbase_transaction_with_height(1);
    // The BIP34 height push alone is one byte, and consensus requires a
    // coinbase scriptSig of at least two.
    let mut script_sig = push_int(1);
    script_sig.extend_from_slice(&push_data(&[0_u8; 4]));
    coinbase.inputs[0].script_sig = Script::from_bytes(script_sig);
    coinbase.outputs = vec![TxOut {
        value: Amount::from_sat(coinbase_value),
        script_pubkey: Script::from_bytes(op_true_script()),
    }];
    let mut txdata = vec![coinbase];
    txdata.extend(extra);

    let mut block = block_with_prev_hash_and_transactions(genesis.block_hash(), txdata);
    while !compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    Ok((handles, block))
}

pub(super) fn wait_until(
    deadline: std::time::Instant,
    mut condition: impl FnMut() -> bool,
) -> bool {
    while std::time::Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::yield_now();
    }
    condition()
}

pub(super) fn transaction(seed: u8) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(fixture_txid(seed), u32::from(seed)),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn utxo_with_output(
    previous_output: OutPoint,
    height: u32,
) -> Result<Arc<UtxoSet>, bitcoin_rs_utxo::UtxoError> {
    utxo_with_outputs_at_height(&[previous_output], height)
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn utxo_with_outputs_at_height(
    previous_outputs: &[OutPoint],
    height: u32,
) -> Result<Arc<UtxoSet>, bitcoin_rs_utxo::UtxoError> {
    let utxo = Arc::new(UtxoSet::new());
    let mut changes = BlockChanges::default();
    for previous_output in previous_outputs {
        changes.add(UtxoAdd::new(
            *previous_output,
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::from_bytes(op_true_script()),
            },
            false,
            height,
        ));
    }
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;
    Ok(utxo)
}

pub(super) fn block_with_transaction(tx: Tx) -> Block {
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: vec![tx],
    }
}

pub(super) fn block_with_transactions(txdata: Vec<Tx>) -> Block {
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: txdata,
    }
}

pub(super) fn block_with_prev_hash_and_transactions(
    prev_blockhash: BlockHash,
    txdata: Vec<Tx>,
) -> Block {
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: next_fixture_time(),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: txdata,
    };
    block.header.merkle_root = txids_merkle_root(&block).unwrap_or_default();
    block
}

/// A timestamp strictly after every fixture block built before it.
///
/// The fixtures used to hard-code `1`, which is before the regtest genesis
/// timestamp and therefore below its median-time-past. That went unnoticed
/// while only header sync checked timestamps; now that the apply path does
/// too, a fixture block has to carry a timestamp a real one could have.
/// Strictly increasing also keeps deep chains valid, where a constant would
/// fall to the median once enough blocks shared it.
pub(super) fn next_fixture_time() -> u32 {
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering;

    // Just past the regtest genesis timestamp.
    static NEXT: AtomicU32 = AtomicU32::new(1_296_688_603);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub(super) fn interpolated_time(
    anchor_time: u32,
    tip_time: u32,
    height: u32,
    tip_height: u32,
) -> u32 {
    if height == 0 || tip_height == 0 {
        return anchor_time;
    }
    let span = u64::from(tip_time.saturating_sub(anchor_time));
    let offset = span.saturating_mul(u64::from(height)) / u64::from(tip_height);
    anchor_time.saturating_add(u32::try_from(offset).unwrap_or(u32::MAX))
}

/// Fixture txid with every consensus byte set to `seed`.
pub(super) fn fixture_txid(seed: u8) -> Txid {
    Txid(Hash256::from_le_bytes(&[seed; 32]))
}

/// Compact target encoding of a 256-bit target: mirrors Bitcoin Core's
/// `GetCompact` and `bitcoin_rs_chain`'s crate-private
/// `pow::target_to_compact` (lossy past three bytes, sign bit never set).
pub(super) fn target_to_compact_lossy(target: ChainWork) -> u32 {
    if target == ChainWork::ZERO {
        return 0;
    }
    let mut size = target.bit_len().div_ceil(8);
    let mut compact = if size <= 3 {
        u32::try_from(target.as_limbs()[0] << (8 * (3 - size))).unwrap_or(0)
    } else {
        u32::try_from((target >> (8 * (size - 3))).as_limbs()[0]).unwrap_or(0)
    };
    if compact & 0x0080_0000 != 0 {
        compact >>= 8;
        size += 1;
    }
    compact | (u32::try_from(size).unwrap_or(0) << 24)
}

pub(super) fn retarget_bits_for_test(
    handles: &Chainstate,
    previous_bits: u32,
    actual_timespan: u32,
    expected_timespan: u32,
) -> u32 {
    let min_timespan = expected_timespan / 4;
    let max_timespan = expected_timespan * 4;
    let actual_clamped = actual_timespan.clamp(min_timespan, max_timespan);
    let previous_target = compact_to_target(previous_bits);
    let actual = ChainWork::from(actual_clamped);
    let expected = ChainWork::from(expected_timespan);
    let target = ((previous_target / expected) * actual)
        + (((previous_target % expected) * actual) / expected);
    let target = target.min(handles.network.max_target());
    target_to_compact_lossy(target)
}

pub(super) fn assert_nbits_error(error: &ApplyError, actual: u32, expected: u32, height: u32) {
    assert!(matches!(
        error,
        ApplyError::NbitsNonRetargetMismatch {
            actual: got_actual,
            expected: got_expected,
            height: got_height,
        } if *got_actual == actual && *got_expected == expected && *got_height == height
    ));
}

pub(super) fn spending_transaction(previous_output: OutPoint, sequence: u32) -> Tx {
    spending_transaction_to_script(previous_output, sequence, Vec::new())
}

pub(super) fn spending_transaction_with_version(
    previous_output: OutPoint,
    sequence: u32,
    version: i32,
) -> Tx {
    let mut transaction = spending_transaction(previous_output, sequence);
    transaction.version = version;
    transaction
}

pub(super) fn softfork_state(csv_active: bool) -> bitcoin_rs_chain::SoftforkState {
    bitcoin_rs_chain::SoftforkState {
        csv_active,
        segwit_active: false,
    }
}

pub(super) fn seed_block_tree_with_times(
    handles: &Chainstate,
    times: &[u32],
) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
    let mut tree = handles.block_tree.write();
    let mut parent = None;
    let mut tip = None;
    for (height, time) in times.iter().copied().enumerate() {
        let header = Header {
            version: 1,
            prev_blockhash: parent
                .and_then(|id| tree.node(id).ok().map(|node| BlockHash::from(node.hash)))
                .unwrap_or_else(BlockHash::default),
            merkle_root: Hash256::default(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: u32::try_from(height).map_err(|_| ApplyError::HeightOverflow(u32::MAX))?,
        };
        let id = tree.insert_node(parent, header, NodeStatus::Active)?;
        parent = Some(id);
        tip = Some(id);
    }
    match tip {
        Some(tip) => Ok(tip),
        None => Err(ApplyError::HeightOverflow(0)),
    }
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn empty_apply_handles_for_network(network: Network) -> Chainstate {
    apply_handles_for_network(network, Arc::new(UtxoSet::new()))
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn apply_handles(utxo: Arc<UtxoSet>) -> Chainstate {
    apply_handles_for_network(Network::Mainnet, utxo)
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn apply_handles_with_assume_valid(
    utxo: Arc<UtxoSet>,
    assume_valid_height: u32,
) -> Chainstate {
    let mut handles = apply_handles(utxo);
    handles.assume_valid_height = assume_valid_height;
    handles
}

/// Builds a block whose single non-coinbase tx spends a P2SH-template output with a
/// scriptSig that is VALID as a bare script but INVALID as P2SH.
///
/// redeemScript = `OP_0` (single byte `0x00`), which executes to FALSE.
/// - prevout scriptPubKey = `OP_HASH160 <hash160(redeem)> OP_EQUAL` (P2SH template).
/// - scriptSig = push-only, pushing the redeem bytes `[0x00]` as the only item.
///
/// BARE eval (P2SH OFF): scriptSig pushes `[0x00]`; scriptPubKey HASH160s it to `h`,
/// pushes `h`, `OP_EQUAL` -> TRUE. ACCEPTED.
/// P2SH eval (P2SH ON): the last scriptSig push `[0x00]` is deserialized as the
/// redeemScript `OP_0`, run with an empty stack -> pushes FALSE -> FAIL at input 0.
///
/// Gated to a real script backend: the acceptance arm asserts `Ok`, which only
/// holds when scripts actually execute. With no backend the verifier returns a
/// `Script { .. "backend disabled" }` error, so the helper would be dead code.
#[cfg(feature = "kernel")]
pub(super) fn p2sh_template_bare_spend_block()
-> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
    // hash160([0x00]): the bare-eval arm only accepts when the redeem script
    // pushed by the scriptSig hashes to the value in the template output.
    const REDEEM_HASH160: [u8; 20] = [
        0x9f, 0x7f, 0xd0, 0x96, 0xd3, 0x7e, 0xd2, 0xc0, 0xe3, 0xf7, 0xf0, 0xcf, 0xc9, 0x24, 0xbe,
        0xef, 0x4f, 0xfc, 0xeb, 0x68,
    ];

    let redeem: [u8; 1] = [0x00];
    let mut p2sh_output_script = vec![0xa9_u8];
    p2sh_output_script.extend_from_slice(&push_data(&REDEEM_HASH160));
    p2sh_output_script.push(0x87);

    let base_prevout = OutPoint::new(fixture_txid(0x67), 0);
    let utxo = Arc::new(UtxoSet::new());
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        base_prevout,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(p2sh_output_script),
        },
        false,
        1,
    ));
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[10; 32]))?;

    let spend = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: base_prevout,
            script_sig: Script::from_bytes(push_data(&redeem)),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(op_true_script()),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let block = block_with_transaction(spend);
    let plan = tx_plan(&block);
    Ok((block, plan, utxo))
}

pub(super) fn excess_value_spend_block()
-> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
    // `utxo_with_output` funds the prevout with 1_000 sats (its second arg `1` is
    // the coinbase height, not a value); the spend creates 2_000 sats of outputs,
    // so outputs exceed inputs — a NON-script consensus violation that must be
    // caught even when script checks are skipped.
    let base_prevout = OutPoint::new(fixture_txid(0x66), 0);
    let utxo = utxo_with_output(base_prevout, 1)?;
    let spend = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: base_prevout,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(2_000),
            script_pubkey: Script::from_bytes(op_true_script()),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let block = block_with_transaction(spend);
    let plan = tx_plan(&block);
    Ok((block, plan, utxo))
}

pub(super) fn apply_handles_for_network(network: Network, utxo: Arc<UtxoSet>) -> Chainstate {
    apply_handles_without_tx_index(network, utxo)
}

pub(super) fn apply_followed(
    handles: &Chainstate,
    followers: &crate::chain_effects::ChainFollowers,
    block: &Block,
) -> core::result::Result<TipSnapshot, ApplyError> {
    Ok(followers.apply_connect(handles, block)?.tip)
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn empty_utxo() -> Arc<UtxoSet> {
    Arc::new(UtxoSet::new())
}
