use super::super::*;
use super::BIP68_TEST_PREVOUT_MTP;
use super::MapBodyStore;
use super::ReorgBodyLoadingFixture;
use super::apply_handles_without_tx_index;
use super::coinbase_transaction;
use super::mined_block_with_prev_hash_and_transactions;
use bitcoin_rs_chain::node::NodeStatus;
use bitcoin_rs_mining::MiningControlError;
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
use compact_str::CompactString;
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

/// Fixture txid with every consensus byte set to `seed`.
pub(super) fn fixture_txid(seed: u8) -> Txid {
    Txid(Hash256::from_le_bytes(&[seed; 32]))
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

pub(super) fn zmq_followers(
    publisher: Arc<dyn crate::ZmqPublisher>,
) -> crate::chain_effects::ChainFollowers {
    crate::chain_effects::ChainFollowers::new(
        crate::chain_effects::ChainEffects::noop().with_zmq_publisher(publisher),
        Arc::new(crate::mining::MiningGenerationSignal::new()),
        None,
    )
}

#[allow(clippy::arc_with_non_send_sync)]
pub(super) fn one_block_window_fixture(
    utxo: Arc<UtxoSet>,
    txdata: Vec<Tx>,
    assume_valid_height: u32,
) -> Result<(Chainstate, Block, bytes::Bytes), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut handles = apply_handles_for_network(Network::Regtest, utxo);
    handles.assume_valid_height = assume_valid_height;
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let block = mined_block_with_prev_hash_and_transactions(genesis.block_hash(), txdata)?;
    let block_hash = Hash256::from(block.block_hash());
    applied_header_tip(&handles, block_hash, &block, 1)?;
    let raw = bytes::Bytes::from(consensus_bytes(&block));
    Ok((handles, block, raw))
}

pub(super) fn reorg_body_loading_fixture()
-> Result<ReorgBodyLoadingFixture, Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let bodies = Arc::new(MapBodyStore::default());
    let body_arc = Arc::clone(&bodies);
    let body_handle: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore> = body_arc;
    handles.block_body_store = Some(body_handle);

    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let losing = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let raw = bytes::Bytes::from(consensus_bytes(&losing));
    let applied = handles
        .apply_block_with_serialized(&losing, raw.clone())?
        .tip;
    bodies
        .bodies
        .write()
        .insert((applied.height, applied.hash), raw.to_vec());

    let win_one = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    let win_two = mined_block_with_prev_hash_and_transactions(
        win_one.block_hash(),
        vec![coinbase_transaction(3)],
    )?;
    let target = {
        let mut tree = handles.block_tree.write();
        let mut last = None;
        for (height, block) in [(1_u32, &win_one), (2_u32, &win_two)] {
            let hash = Hash256::from(block.block_hash());
            last = Some(tree.insert_header(block.header, NodeStatus::HeaderValid)?);
            bodies
                .bodies
                .write()
                .insert((height, hash), consensus_bytes(block));
        }
        last.ok_or_else(|| anyhow::anyhow!("no winning branch built"))?
    };

    Ok(ReorgBodyLoadingFixture {
        handles,
        utxo,
        bodies,
        target,
        losing,
        applied,
    })
}

pub(super) fn assert_reorg_load_failure_preserved_state(
    handles: &Chainstate,
    utxo: &UtxoSet,
    losing: &Block,
    applied: &TipSnapshot,
    tree_tip_before: Option<(bitcoin_rs_chain::NodeId, u32, Hash256)>,
    utxo_len_before: usize,
) {
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .map(|tip| (tip.tip_id, tip.height, tip.hash)),
        Some((applied.tip_id, applied.height, applied.hash)),
        "body loading failure must not move the applied tip"
    );
    assert_eq!(
        handles
            .block_tree
            .read()
            .tip()
            .map(|tip| (tip.tip_id, tip.height, tip.hash)),
        tree_tip_before,
        "body loading failure must not change the active header index"
    );
    assert_eq!(
        utxo.len(),
        utxo_len_before,
        "body loading failure must not change UTXO cardinality"
    );
    assert!(
        utxo.has_live_outputs_for_txid(&Hash256::from(losing.txs[0].txid())),
        "body loading failure must leave the applied branch coin live"
    );
}

pub(super) fn disconnect_followed(
    handles: &Chainstate,
    followers: &crate::chain_effects::ChainFollowers,
    block: &Block,
) -> core::result::Result<TipSnapshot, crate::DisconnectError> {
    Ok(followers.apply_disconnect(handles, block)?.parent_tip)
}

pub(super) fn generation_unavailable() -> MiningControlError {
    MiningControlError::Unavailable(CompactString::from("not wired in this test"))
}

pub(super) fn coinbase_transaction_with_height(height: u32) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(push_int(i64::from(height))),
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

pub(super) fn pow_header(prev_blockhash: BlockHash, bits: u32, time: u32, nonce: u32) -> Header {
    Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(bits),
        nonce,
    }
}

pub(super) fn seed_pow_chain_with_headers(
    handles: &Chainstate,
    headers: &[(u32, u32)],
) -> Result<BlockHash, Box<dyn std::error::Error>> {
    let mut tree = handles.block_tree.write();
    let mut parent = None;
    let mut prev_hash = BlockHash::default();
    for (height, &(bits, time)) in headers.iter().enumerate() {
        let height = u32::try_from(height)?;
        let header = pow_header(prev_hash, bits, time, height);
        prev_hash = header.compute_hash();
        parent = Some(tree.insert_node(parent, header, NodeStatus::Active)?);
    }
    handles.chain_tip.store(tree.tip());
    Ok(prev_hash)
}

/// `OP_RETURN <data>` output script.
pub(super) fn op_return_script(data: &[u8]) -> Vec<u8> {
    let mut script = vec![0x6a_u8];
    script.extend_from_slice(&push_data(data));
    script
}

/// Merkle root over the block's txids: pairwise double-SHA256 over the
/// little-endian id bytes, duplicating the last leaf on odd widths.
pub(super) fn txids_merkle_root(block: &Block) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    merkle_root_bytes(&mut leaves).map(|bytes| Hash256::from_le_bytes(&bytes))
}

pub(super) fn spending_transaction_to_script(
    previous_output: OutPoint,
    sequence: u32,
    script_pubkey: Vec<u8>,
) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(script_pubkey),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

pub(super) fn op_true_script() -> Vec<u8> {
    vec![0x51]
}

pub(super) fn seed_block_tree_for_bip68_time_at_height(
    handles: &Chainstate,
    tip_height: u32,
) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
    let mut tree = handles.block_tree.write();
    let mut parent = None;
    let mut tip = None;
    for height in 0..=tip_height {
        let header = Header {
            version: 1,
            prev_blockhash: parent
                .and_then(|id| tree.node(id).ok().map(|node| BlockHash::from(node.hash)))
                .unwrap_or_else(BlockHash::default),
            merkle_root: Hash256::default(),
            time: BIP68_TEST_PREVOUT_MTP,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
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

pub(super) fn assert_bip_error(error: &ApplyError, bip: &str) {
    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: actual, .. }) if *actual == bip
    ));
}

pub(super) fn assert_bip_error_reason_contains(error: &ApplyError, bip: &str, needle: &str) {
    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: actual, reason })
            if *actual == bip && reason.contains(needle)
    ));
}

pub(super) fn duplicate_spend_block()
-> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
    let base_prevout = OutPoint::new(fixture_txid(0x64), 0);
    let utxo = utxo_with_output(base_prevout, 1)?;
    let first_spend = spending_transaction_to_script(base_prevout, u32::MAX, op_true_script());
    let second_spend = spending_transaction_to_script(base_prevout, u32::MAX - 1, op_true_script());
    let block = block_with_transactions(vec![first_spend, second_spend]);
    let plan = tx_plan(&block);
    Ok((block, plan, utxo))
}

pub(super) fn bad_script_spend_block()
-> Result<(Block, BlockTxPlan, Arc<UtxoSet>), Box<dyn std::error::Error>> {
    let base_prevout = OutPoint::new(fixture_txid(0x65), 0);
    let utxo = Arc::new(UtxoSet::new());
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        base_prevout,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x87]),
        },
        false,
        1,
    ));
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

    let mut script_sig = push_int(7);
    script_sig.extend_from_slice(&push_int(8));
    let spend = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: base_prevout,
            script_sig: Script::from_bytes(script_sig),
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
