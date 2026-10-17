use std::fmt::Write as _;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use bitcoin::hex::FromHex;
use bitcoin_rs_chain::regtest_fixture::{self, REGTEST_BITS};
use bitcoin_rs_mempool::{AdmissionOrigin, MempoolEntry, SubmitOutcome};
use bitcoin_rs_mining::{
    BlockTemplate, BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult,
    BlockValidationResult, MempoolSequenceWake, MiningControl, MiningGenerationSignal, solve_block,
};
use bitcoin_rs_node::{MiningCoordinator, Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, deserialize as native_deserialize, encode::double_sha256,
};
use bitcoin_rs_rpc::{
    Handler,
    context::{
        ChainAdmissionView, ChainHandles, Context, ContextHandles, IndexHandles, MempoolHandles,
        MiningHandles, NetworkHandles,
    },
};
use bitcoin_rs_script::push_int;
use bitcoin_rs_utxo::UtxoSet;
use compact_str::CompactString;
use crossbeam_channel::{Receiver, bounded};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

pub(crate) const SEED_BLOCKS: u32 = 100;
pub(crate) const SEED_BASE_TIME: u32 = 1_296_688_603;
pub(crate) const SEED_BLOCK_INTERVAL: u32 = 600;
pub(crate) const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
pub(crate) const MEMPOOL_TX_FEE_SATS: u64 = 10_000;
pub(crate) const WITNESS_RESERVED: [u8; 32] = [0_u8; 32];
pub(crate) const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

pub(crate) struct NodeFixture {
    pub(crate) state: NodeState,
    _dir: tempfile::TempDir,
}

impl std::ops::Deref for NodeFixture {
    type Target = NodeState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

pub(crate) fn open_network(network: Network) -> Result<NodeFixture> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(network);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok(NodeFixture { state, _dir: dir })
}

pub(crate) fn open_at_genesis(network: Network) -> Result<NodeFixture> {
    let fixture = open_network(network)?;
    let _ = fixture.state.apply_block(&network.genesis_block())?;
    Ok(fixture)
}

/// Regtest node at its applied genesis tip plus the coordinator over it.
pub(crate) fn regtest_mining() -> Result<(NodeFixture, MiningCoordinator)> {
    let fixture = open_at_genesis(Network::Regtest)?;
    let mining = coordinator(&fixture.state);
    Ok((fixture, mining))
}

pub(crate) fn coordinator(state: &NodeState) -> MiningCoordinator {
    // Empty template coinbase script matches transport-only GBT wiring.
    MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
    )
}

pub(crate) fn advance_mempool_sequence(state: &NodeState) -> Result<()> {
    let mempool = state.mempool();
    let mut guard = mempool.write();
    guard
        .insert_entry(MempoolEntry::new(
            Arc::new(mempool_sequence_tx()),
            100,
            10_000,
            1,
            7,
            0,
        ))
        .map_err(|error| anyhow::anyhow!("seed insert failed: {error}"))?;
    guard.clear();
    Ok(())
}

pub(crate) fn template_request(long_poll_id: Option<CompactString>) -> BlockTemplateRequest {
    BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id,
    }
}

pub(crate) fn expect_template(result: BlockTemplateResult) -> BlockTemplate {
    match result {
        BlockTemplateResult::Template(template) => template,
        other @ BlockTemplateResult::Proposal(_) => {
            panic!("expected template, got {other:?}")
        }
    }
}

pub(crate) fn to_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(crate) fn is_witness_commitment(script_pubkey: &[u8]) -> bool {
    script_pubkey.len() >= 38 && script_pubkey.starts_with(&WITNESS_COMMITMENT_PREFIX)
}

pub(crate) fn solved_template_block(mining: &MiningCoordinator) -> Result<Block> {
    let template = expect_template(mining.get_block_template(template_request(None))?);
    let mut block = template
        .candidate
        .into_unsolved_block()
        .map_err(|error| anyhow::anyhow!("assemble template candidate: {error}"))?;
    solve_block(&mut block, 1_000_000)
        .map_err(|error| anyhow::anyhow!("solve template candidate: {error}"))?;
    Ok(block)
}

pub(crate) fn mined_child(prev: BlockHash) -> Result<Block> {
    mined_child_labeled(prev, 1)
}

pub(crate) fn mined_child_labeled(prev: BlockHash, label: i64) -> Result<Block> {
    let script_opcode = u8::try_from(label + 0x50)?;
    let coinbase = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![script_opcode, 0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50 * 100_000_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: 0x2000_0000,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time: 1_296_688_603 + 600,
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = block.txs[0].txid().into();
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

pub(crate) fn mined_regtest_header(prev: BlockHash, time: u32, version: i32) -> Header {
    let mut header = Header {
        version,
        prev_blockhash: prev,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
        nonce: 0,
    };
    regtest_fixture::mine_header_to_declared_target(&mut header)
        .unwrap_or_else(|error| panic!("regtest fixture header: {error}"));
    header
}

pub(crate) fn excess_coinbase_child(prev: BlockHash) -> Result<Block> {
    let mut block = mined_child(prev)?;
    let Some(output) = block.txs.first_mut().and_then(|tx| tx.outputs.first_mut()) else {
        panic!("coinbase has no output");
    };
    output.value = output.value.saturating_add(Amount::from_sat(1));
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("test block has no merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

pub(crate) fn mempool_sequence_tx() -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    }
}

pub(crate) fn propose_block(
    mining: &MiningCoordinator,
    block: Block,
) -> Result<BlockValidationResult> {
    match mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Proposal(block),
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: None,
    })? {
        BlockTemplateResult::Proposal(result) => Ok(result),
        other @ BlockTemplateResult::Template(_) => {
            panic!("expected a proposal result, got {other:?}")
        }
    }
}

pub(crate) fn disconnect_applied(state: &NodeState, block: &Block) -> Result<()> {
    use bitcoin_rs_primitives::consensus_bytes;
    let genesis = Network::Regtest.genesis_block();
    let target = state
        .chainstate()
        .block_tree_reader()
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or_else(|| anyhow::anyhow!("missing genesis node"))?;
    let block_hash = Hash256::from(block.block_hash());
    let body = block.clone();
    bitcoin_rs_node::reorg::switch_to_branch(
        &state.chainstate(),
        &state.chain_followers(),
        target,
        |hash| (hash == block_hash).then(|| (body.clone(), consensus_bytes(&body).into())),
        |_| {},
    )
    .map_err(|error| anyhow::anyhow!("{error}"))
}

pub(crate) fn open_regtest() -> Result<(NodeState, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}

pub(crate) fn apply_genesis(state: &NodeState) -> Result<()> {
    let genesis = Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    Ok(())
}

pub(crate) fn seed_chain(state: &NodeState, count: u32) -> Result<Hash256> {
    let mut tip = current_tip(state)?;
    for height in 1..=count {
        let coinbase = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        };
        let mut block = Block {
            header: Header {
                version: 0x2000_0000,
                prev_blockhash: BlockHash::from(tip.hash),
                merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                bits: CompactTarget::from_consensus(REGTEST_BITS),
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| anyhow::anyhow!("seed block must have a merkle root"))?;
        regtest_fixture::mine_block_to_declared_target(&mut block)?;
        state.apply_block(&block)?;
        tip = current_tip(state)?;
        assert_eq!(tip.height, height, "seed block must become the tip");
    }
    Ok(tip.hash)
}

pub(crate) fn current_tip(state: &NodeState) -> Result<bitcoin_rs_chain::TipSnapshot> {
    let Some(tip) = state.chainstate().applied_tip_snapshot() else {
        bail!("applied tip must exist");
    };
    Ok((*tip).clone())
}

pub(crate) fn assemble_from_template(
    template: &sonic_rs::Value,
    template_txs: &[sonic_rs::Value],
) -> Result<Block> {
    let prev_hex = required_str(template, "previousblockhash")?;
    let height = required_u64(template, "height")?;
    let coinbase_value = required_u64(template, "coinbasevalue")?;
    let bits = u32::from_str_radix(&required_str(template, "bits")?, 16)?;
    let curtime = u32::try_from(required_u64(template, "curtime")?).unwrap_or(u32::MAX);
    let version = i32::try_from(required_u64(template, "version")?).unwrap_or(0);
    let commitment_script =
        Vec::<u8>::from_hex(&required_str(template, "default_witness_commitment")?)?;
    assert!(
        commitment_script.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        "default_witness_commitment must be the BIP141 commitment script"
    );

    let mut txs = Vec::with_capacity(template_txs.len());
    for entry in template_txs {
        let data = entry
            .get("data")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("template transaction missing data hex"))?;
        txs.push(native_deserialize::<Tx>(&Vec::<u8>::from_hex(data)?)?);
    }

    assemble_block(
        prev_hex.as_str(),
        u32::try_from(height).unwrap_or(u32::MAX),
        version,
        bits,
        curtime,
        coinbase_value,
        commitment_script,
        txs,
    )
}

pub(crate) fn seed_coinbase_spend() -> Tx {
    seed_coinbase_spend_with_fee(MEMPOOL_TX_FEE_SATS)
}

pub(crate) fn seed_coinbase_spend_with_fee(fee_sats: u64) -> Tx {
    seed_coinbase_spend_at(1, fee_sats)
}

/// Spend of the coinbase `seed_chain` mines at `height`, paying `fee_sats`.
/// The coinbase is mature for the next block once the tip is `height + 99`.
pub(crate) fn seed_coinbase_spend_at(height: u32, fee_sats: u64) -> Tx {
    let seed_coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(seed_coinbase.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - fee_sats),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::ZERO,
    }
}

pub(crate) fn p2sh_true_output() -> Script {
    let redeem = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    Script::from_bytes(redeem.to_p2sh().into_bytes())
}

pub(crate) fn p2sh_true_spend_script_sig() -> Script {
    Script::from_bytes(vec![0x01, 0x51])
}

pub(crate) fn assemble_regtest_block(prev: Hash256, height: u32, txs: Vec<Tx>) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    let mut block = Block {
        header: Header {
            version: 0x2000_0000,
            prev_blockhash: BlockHash::from(prev),
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txs: std::iter::once(coinbase).chain(txs).collect(),
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("regtest block must have a merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

#[expect(clippy::unnecessary_wraps)]
pub(crate) fn admit_to_mempool(state: &NodeState, tx: &Tx) -> Result<()> {
    let utxo = state.chainstate().utxo_reader();
    let applied_tip = state.chainstate().applied_tip_reader();
    let block_tree = state.chainstate().block_tree_reader();
    let view = ChainAdmissionView::new(utxo, applied_tip, block_tree, Network::Regtest);
    let outcome = state.mempool_gateway().submit_transaction(
        Arc::new(tx.clone()),
        AdmissionOrigin::Rpc,
        None,
        bitcoin_rs_primitives::unix_time_secs(),
        &view,
    );
    assert!(
        matches!(outcome, Ok(SubmitOutcome::Committed(_))),
        "gateway admission must commit the spend, got: {outcome:?}"
    );
    Ok(())
}

pub(crate) fn mine_regtest_block(
    state: &NodeState,
    prev: Hash256,
    height: u32,
    txs: Vec<Tx>,
) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    let mut block = Block {
        header: Header {
            version: 0x2000_0000,
            prev_blockhash: BlockHash::from(prev),
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txs: std::iter::once(coinbase).chain(txs).collect(),
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("mined block must have a merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    state.apply_block(&block)?;
    Ok(block)
}

pub(crate) fn mining_handler(state: &NodeState) -> Handler {
    rpc_handler(state, Arc::new(coordinator(state)))
}

/// RPC handler over `state` whose mining methods run on `mining_control`.
pub(crate) fn rpc_handler(state: &NodeState, mining_control: Arc<dyn MiningControl>) -> Handler {
    let ctx = Context::from_handles(ContextHandles {
        chain: ChainHandles {
            chain_tip: state.chainstate().header_tip_reader(),
            applied_tip: state.chainstate().applied_tip_reader(),
            active_tip_wait: Some(state.chainstate()),
            progress: state.chainstate().chain_progress_reader(),
            blocks: state.block_log_reader(),
            utxo: bitcoin_rs_utxo::UtxoReader::new(Arc::new(UtxoSet::new())),
            coin_stats: state.chainstate().coin_stats_handle(),
            block_tree: state.chainstate().block_tree_reader(),
            chain_network: state.config().network,
            chain_transition: state.stable_read(),
            closed_for_recovery: state.chainstate().closed_for_recovery_reader(),
            ..ChainHandles::default()
        },
        mempool: MempoolHandles {
            gateway: state.mempool_gateway(),
        },
        indexes: IndexHandles::default(),
        network: NetworkHandles {
            peer_table: state.peer_table(),
            p2p: state.p2p(),
            local_services: state.p2p().local_services().to_u64(),
        },
        mining: MiningHandles {
            mining_control: Some(mining_control),
        },
        ..ContextHandles::default()
    })
    .with_chain_transition(state.stable_read());
    Handler::new(Arc::new(ctx))
}

pub(crate) fn assemble_block(
    prev_hex: &str,
    height: u32,
    version: i32,
    bits: u32,
    curtime: u32,
    coinbase_value: u64,
    commitment_script: Vec<u8>,
    txs: Vec<Tx>,
) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(push_int(i64::from(height))),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![WITNESS_RESERVED.to_vec()]),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(coinbase_value),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::from_bytes(commitment_script),
            },
        ],
        lock_time: LockTime::ZERO,
    };

    let mut block_txs = Vec::with_capacity(txs.len() + 1);
    block_txs.push(coinbase);
    block_txs.extend(txs);

    let mut block = Block {
        header: Header {
            version,
            prev_blockhash: prev_hex
                .parse::<BlockHash>()
                .map_err(|err| anyhow::anyhow!("invalid previousblockhash: {err}"))?,
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: curtime,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        },
        txs: block_txs,
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("block must have a merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

pub(crate) fn required_str(value: &sonic_rs::Value, key: &str) -> Result<String> {
    let text = value
        .get(key)
        .and_then(|text| text.as_str())
        .ok_or_else(|| anyhow::anyhow!("template field {key} missing or not a string"))?;
    Ok(text.to_owned())
}

pub(crate) fn required_u64(value: &sonic_rs::Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(sonic_rs::JsonValueTrait::as_i64)
        .and_then(|number| u64::try_from(number).ok())
        .ok_or_else(|| anyhow::anyhow!("template field {key} missing or not a number"))
}

/// Native BIP141 witness merkle fold with the odd-leaf duplication rule.
/// The coinbase wtxid is replaced by all-zeroes before folding.
pub(crate) fn compute_witness_merkle_root(txs: &[Tx]) -> Option<Hash256> {
    if txs.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(txs.len().saturating_add(1));
    level.push([0_u8; 32]);
    for tx in txs {
        level.push(*tx.wtxid().as_bytes());
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pos in 0..level.len().div_ceil(2) {
            let left = level[2 * pos];
            let right = level[(2 * pos + 1).min(level.len() - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        level = next;
    }
    Some(Hash256::from_le_bytes(&level[0]))
}

/// Seed blocks after which the height-1, height-2, and height-3 coinbases are
/// mature for the next block.
pub(crate) const PRIORITY_SEED_BLOCKS: u32 = SEED_BLOCKS + 2;
/// Fee of the pooled spend that starts out ranked last.
pub(crate) const LOW_FEE_SATS: u64 = 10_000;
/// Fee of the pooled spend that starts out ranked first.
pub(crate) const HIGH_FEE_SATS: u64 = 20_000;
/// Fee of the spend admitted after a prioritisation.
pub(crate) const LATE_FEE_SATS: u64 = 15_000;
/// Large enough that the prioritised spend outranks every other fee here.
pub(crate) const PRIORITY_DELTA_SATS: i64 = 50_000;
/// Ceiling for calls that must answer, above the coordinator's 1 s wait slice.
pub(crate) const PROMPT: Duration = Duration::from_secs(5);
/// Longest a long poll may take to register as a waiter before the test fails.
const PARK_DEADLINE: Duration = Duration::from_secs(10);

/// The public `longpollid` format:
/// `{tip_be_hex}{mempool_sequence}` at fee revision zero, otherwise
/// `{tip_be_hex}{mempool_sequence}:{fee_delta_sequence}`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LongPollId {
    pub(crate) tip: String,
    pub(crate) mempool_sequence: u64,
    pub(crate) fee_delta_sequence: u64,
}

impl LongPollId {
    /// Decodes `id` by the public format and nothing else. Ids without the
    /// fee suffix imply fee revision zero.
    pub(crate) fn parse(id: &str) -> Result<Self> {
        let (tip, counters) = id
            .split_at_checked(64)
            .ok_or_else(|| anyhow!("longpollid {id:?} is shorter than a tip hash"))?;
        if !tip.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("longpollid {id:?} does not start with a hex tip hash");
        }
        let (mempool, fee_delta_sequence) = match counters.split_once(':') {
            Some((mempool, fee)) => (mempool.parse()?, fee.parse()?),
            None => (counters.parse()?, 0),
        };
        Ok(Self {
            tip: tip.to_owned(),
            mempool_sequence: mempool,
            fee_delta_sequence,
        })
    }
}

/// The id the public format assigns to the node's live generation, built from
/// the applied tip and the pool's own counters rather than from the
/// coordinator.
pub(crate) fn live_long_poll_id(state: &NodeState) -> Result<String> {
    let tip = current_tip(state)?;
    let mempool = state.mempool();
    let pool = mempool.read();
    let mut id = format!("{}{}", tip.hash.to_string_be(), pool.sequence_number());
    let fee = pool.fee_delta_sequence_number();
    if fee != 0 {
        id.push(':');
        id.push_str(&fee.to_string());
    }
    Ok(id)
}

/// What a miner reads from one `getblocktemplate` reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TemplateView {
    pub(crate) long_poll_id: String,
    /// Transaction ids in template order.
    pub(crate) txids: Vec<String>,
    /// Actual fees, parallel to `txids`; prioritisation never changes them.
    pub(crate) fees: Vec<u64>,
    pub(crate) coinbase_value: u64,
}

impl TemplateView {
    pub(crate) fn id(&self) -> Result<LongPollId> {
        LongPollId::parse(&self.long_poll_id)
    }
}

pub(crate) fn template_view(template: &sonic_rs::Value) -> Result<TemplateView> {
    let entries = template
        .get("transactions")
        .and_then(|value| value.as_array())
        .ok_or_else(|| anyhow!("template has no transactions array"))?
        .as_slice();
    let mut txids = Vec::with_capacity(entries.len());
    let mut fees = Vec::with_capacity(entries.len());
    for entry in entries {
        txids.push(required_str(entry, "txid")?);
        fees.push(required_u64(entry, "fee")?);
    }
    Ok(TemplateView {
        long_poll_id: required_str(template, "longpollid")?,
        txids,
        fees,
        coinbase_value: required_u64(template, "coinbasevalue")?,
    })
}

/// One `getblocktemplate` call through the real RPC dispatcher; a
/// `long_poll_id` makes it a long poll.
pub(crate) fn gbt_view(handler: &Handler, long_poll_id: Option<&str>) -> Result<TemplateView> {
    let params = if let Some(id) = long_poll_id {
        json!([{"rules": ["segwit"], "longpollid": id}])
    } else {
        json!([{"rules": ["segwit"]}])
    };
    template_view(&handler.dispatch("getblocktemplate", &params)?)
}

/// One call running on its own thread, with a single owner.
///
/// Dropping the handle before the result is collected releases the thread
/// through the node shutdown latch, which every long-poll wait slice (1 s)
/// observes, and joins it. A failing test therefore never leaves a parked
/// poll behind. The result channel holds one slot, so the thread never blocks
/// sending it.
pub(crate) struct PendingPoll<T> {
    done: Receiver<T>,
    thread: Option<JoinHandle<()>>,
    release: Arc<AtomicBool>,
}

impl<T> PendingPoll<T> {
    pub(crate) fn spawn(release: Arc<AtomicBool>, call: impl FnOnce() -> T + Send + 'static) -> Self
    where
        T: Send + 'static,
    {
        let (done_tx, done) = bounded(1);
        let thread = thread::spawn(move || {
            let _ = done_tx.send(call());
        });
        Self {
            done,
            thread: Some(thread),
            release,
        }
    }

    /// Whether the call has returned or panicked.
    pub(crate) fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Collects the call's result; fails when it does not return in `within`.
    pub(crate) fn collect(mut self, within: Duration) -> Result<T> {
        let value = self
            .done
            .recv_timeout(within)
            .map_err(|error| anyhow!("the call did not return within {within:?}: {error}"))?;
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| anyhow!("the call's thread panicked"))?;
        }
        Ok(value)
    }
}

impl<T> Drop for PendingPoll<T> {
    fn drop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.release.store(true, Ordering::Release);
        let _ = thread.join();
    }
}

/// Blocks until `mining` reports a long-poll waiter registered on its wake
/// condvar.
///
/// The proof is causal, not timed. The coordinator counts a waiter under its
/// state mutex immediately before the condvar wait that releases that mutex,
/// and `parked_long_poll_waiters` reads the count under the same mutex. A
/// count of at least one therefore means the poll has read the live
/// generation, found it equal to the id it waits on, and is registered to
/// receive every later publication; nothing that follows can be missed by
/// starting late. It does not prove a notification fires: every wait slice
/// re-derives the live generation, so a lost notify only delays the reply.
/// The loop only bounds how long a regression takes to fail: it sleeps 1 ms
/// between reads, gives up after `PARK_DEADLINE`, and fails early when the
/// call returned without ever waiting.
pub(crate) fn await_parked<T>(mining: &MiningCoordinator, poll: &PendingPoll<T>) -> Result<()> {
    let deadline = Instant::now() + PARK_DEADLINE;
    loop {
        if mining.parked_long_poll_waiters() >= 1 {
            return Ok(());
        }
        if poll.is_finished() {
            bail!("the long poll returned without ever waiting");
        }
        if Instant::now() >= deadline {
            bail!("the long poll did not register as a waiter within {PARK_DEADLINE:?}");
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// One coordinator wired the way `lifecycle` wires production: gateway
/// mutations reach it through a `MiningGenerationSignal` observer leg, and the
/// RPC handler runs its mining methods on the same coordinator.
pub(crate) struct WiredMining {
    pub(crate) mining: Arc<MiningCoordinator>,
    pub(crate) handler: Arc<Handler>,
}

pub(crate) fn wire_mining(state: &NodeState) -> Result<WiredMining> {
    let mining = Arc::new(coordinator(state));
    let signal = Arc::new(MiningGenerationSignal::new());
    let control: Arc<dyn MiningControl> = mining.clone();
    let wake: Arc<dyn MempoolSequenceWake> = mining.clone();
    signal.attach(&control);
    signal.attach_sequence_wake(&wake);
    state
        .mempool_gateway()
        .attach_observer_leg("mining-test", signal)
        .map_err(anyhow::Error::msg)?;
    let handler = Arc::new(rpc_handler(state, control));
    Ok(WiredMining { mining, handler })
}

/// Transaction ids as the template renders them, in the given order.
pub(crate) fn txid_strings(txs: &[&Tx]) -> Vec<String> {
    txs.iter().map(|tx| tx.txid().to_string()).collect()
}

/// A long-poll `getblocktemplate` running on its own thread.
pub(crate) type Poll = PendingPoll<Result<TemplateView>>;

/// Regtest node with a wired coordinator and two independent pooled spends of
/// matured seed coinbases, so prioritising one reorders the template.
pub(crate) struct PriorityFixture {
    pub(crate) wired: WiredMining,
    pub(crate) state: NodeState,
    _dir: tempfile::TempDir,
    /// Pays `LOW_FEE_SATS`; ranks below `high` until prioritised.
    pub(crate) low: Tx,
    /// Pays `HIGH_FEE_SATS`.
    pub(crate) high: Tx,
}

pub(crate) fn priority_fixture() -> Result<PriorityFixture> {
    let (state, dir) = open_regtest()?;
    apply_genesis(&state)?;
    seed_chain(&state, PRIORITY_SEED_BLOCKS)?;
    let wired = wire_mining(&state)?;
    let low = seed_coinbase_spend_at(1, LOW_FEE_SATS);
    let high = seed_coinbase_spend_at(2, HIGH_FEE_SATS);
    admit_to_mempool(&state, &low)?;
    admit_to_mempool(&state, &high)?;
    Ok(PriorityFixture {
        wired,
        state,
        _dir: dir,
        low,
        high,
    })
}

impl PriorityFixture {
    pub(crate) fn mining(&self) -> &MiningCoordinator {
        &self.wired.mining
    }

    /// `getblocktemplate` through the real RPC dispatcher.
    pub(crate) fn template(&self) -> Result<TemplateView> {
        gbt_view(&self.wired.handler, None)
    }

    /// Real RPC `prioritisetransaction`: the handler mutates the pool through
    /// the gateway and publishes the fee generation.
    pub(crate) fn prioritise(&self, tx: &Tx, delta: i64) -> Result<()> {
        let accepted = self.wired.handler.dispatch(
            "prioritisetransaction",
            &json!([tx.txid().to_string(), 0, delta]),
        )?;
        if accepted.as_bool() != Some(true) {
            bail!("prioritisetransaction answered {accepted}");
        }
        Ok(())
    }

    /// Admits a third spend through the real gateway; the observer leg wakes
    /// the coordinator with the admission's sequence.
    pub(crate) fn admit_late(&self) -> Result<Tx> {
        let late = seed_coinbase_spend_at(3, LATE_FEE_SATS);
        admit_to_mempool(&self.state, &late)?;
        Ok(late)
    }

    /// Starts a long poll on the live template's id and returns only once the
    /// coordinator reports it parked (see [`await_parked`]). Nothing has been
    /// published since the template was read, so a poll that has returned by
    /// then did not wait and the proof is void; that fails here.
    pub(crate) fn park_long_poll(&self) -> Result<(TemplateView, Poll)> {
        let current = self.template()?;
        let poll = self.poll(&current.long_poll_id);
        await_parked(self.mining(), &poll)?;
        if poll.is_finished() {
            bail!("the long poll returned before anything was published");
        }
        Ok((current, poll))
    }

    /// A long-poll `getblocktemplate` on its own thread, waiting on `id`.
    pub(crate) fn poll(&self, id: &str) -> Poll {
        let handler = Arc::clone(&self.wired.handler);
        let id = id.to_owned();
        PendingPoll::spawn(self.state.shutdown(), move || gbt_view(&handler, Some(&id)))
    }
}
