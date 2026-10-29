
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use bitcoin_rs_mining::pool::ledger::*;
use std::sync::Arc;
use bitcoin_rs_storage::{ColumnFamily, FjallStore, KvStore, RedbStore};
use tempfile::TempDir;

trait FixtureValue<T> {
    #[track_caller]
    fn fixture(self, context: &str) -> T;
}

impl<T, E: std::fmt::Debug> FixtureValue<T> for Result<T, E> {
    #[track_caller]
    fn fixture(self, context: &str) -> T {
        self.unwrap_or_else(|error| panic!("{context}: {error:?}"))
    }
}

impl<T> FixtureValue<T> for Option<T> {
    #[track_caller]
    fn fixture(self, context: &str) -> T {
        self.unwrap_or_else(|| panic!("{context}"))
    }
}


fn hash(tag: u8) -> Hash32 {
    [tag; 32]
}

fn script(tag: u8) -> Vec<u8> {
    let mut script = vec![0x00, 0x14];
    script.extend_from_slice(&[tag; 20]);
    script
}

fn pool_script() -> Vec<u8> {
    script(0xA0)
}

fn change_script() -> Vec<u8> {
    script(0xC0)
}

fn account_script(account: u64) -> Vec<u8> {
    script(0x10 + u8::try_from(account).fixture("small account"))
}

fn config(window: u128, fee_bps: u16) -> PoolConfig {
    let mut config = PoolConfig::new(window, pool_script());
    config.pool_fee_bps = fee_bps;
    config.coinbase_maturity = 3;
    config.payout_confirmations = 2;
    config.abandon_confirmations = 2;
    config.reorg_watch_depth = 10;
    config.change_scripts = vec![change_script()];
    config
}

fn share(job: u64, account: u64, nonce: u32, work: u128) -> ShareCredit {
    share_vnt(job, account, nonce, 1, 1_700_000_000, work)
}

fn share_vnt(job: u64, account: u64, nonce: u32, version: i32, ntime: u32, work: u128) -> ShareCredit {
    let mut seed = Vec::new();
    seed.extend_from_slice(&job.to_be_bytes());
    seed.extend_from_slice(&account.to_be_bytes());
    seed.extend_from_slice(&nonce.to_be_bytes());
    seed.extend_from_slice(&version.to_be_bytes());
    seed.extend_from_slice(&ntime.to_be_bytes());
    seed.extend_from_slice(&work.to_be_bytes());
    ShareCredit {
        header_hash: sha256(&seed),
        job,
        account: MinerId(account),
        extranonce: vec![u8::try_from(account).fixture("small account"), 1, 2, 3],
        nonce,
        version,
        ntime,
        work,
    }
}

fn found(share: ShareCredit, height: u32, claimed: u64) -> BlockFound {
    let coinbase_txid = sha256(&[b"coinbase".as_slice(), share.header_hash.as_slice()].concat());
    BlockFound {
        share,
        height,
        coinbase_txid,
        claimed_coinbase_value_sat: claimed,
    }
}

fn coinbase_for(block: &BlockFound, pool_value: u64) -> ObservedCoinbase {
    ObservedCoinbase {
        txid: block.coinbase_txid,
        outputs: vec![
            TxOut {
                value_sat: pool_value,
                script_pubkey: pool_script(),
            },
            TxOut {
                value_sat: 0,
                script_pubkey: vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
            },
        ],
    }
}

fn idem(tag: u8) -> Hash32 {
    [tag; 32]
}

fn policy() -> PayoutPolicy {
    PayoutPolicy {
        min_payout_sat: 546,
        max_outputs: 100,
    }
}

fn outpoint(tag: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: hash(tag),
        vout,
    }
}

fn miner_amounts(list: &[(u64, u64)]) -> Vec<(MinerId, u64)> {
    list.iter()
        .map(|(id, amount)| (MinerId(*id), *amount))
        .collect()
}


#[derive(Default)]
struct ChainState {
    tip: u32,
    blocks: BTreeMap<u32, Hash32>,
    displaced: BTreeSet<Hash32>,
    coinbases: HashMap<Hash32, ObservedCoinbase>,
    txs: HashMap<Hash32, TxStatus>,
    spends: HashMap<OutPoint, ConfirmedSpend>,
    down: bool,
}

#[derive(Default)]
struct FakeChain {
    state: RefCell<ChainState>,
}

impl FakeChain {
    fn set_tip(&self, tip: u32) {
        let mut state = self.state.borrow_mut();
        let displaced: Vec<Hash32> = state.blocks.iter()
            .filter(|(height, _)| **height > tip && **height <= state.tip)
            .map(|(_, hash)| *hash).collect();
        state.displaced.extend(displaced);
        state.tip = tip;
    }

    fn set_block(&self, height: u32, block: Hash32) {
        let mut state = self.state.borrow_mut();
        if let Some(previous) = state.blocks.insert(height, block) {
            if previous != block && height <= state.tip {
                state.displaced.insert(previous);
            }
        }
    }

    fn set_coinbase(&self, block: Hash32, coinbase: ObservedCoinbase) {
        self.state.borrow_mut().coinbases.insert(block, coinbase);
    }

    fn set_tx(&self, txid: Hash32, status: TxStatus) {
        self.state.borrow_mut().txs.insert(txid, status);
    }

    fn set_spend(&self, outpoint: OutPoint, spend: ConfirmedSpend) {
        self.state.borrow_mut().spends.insert(outpoint, spend);
    }

    fn take_down(&self) {
        self.state.borrow_mut().down = true;
    }

    fn bring_up(&self) {
        self.state.borrow_mut().down = false;
    }

    fn check(&self) -> Result<(), ChainViewError> {
        if self.state.borrow().down {
            Err(ChainViewError("observer down".into()))
        } else {
            Ok(())
        }
    }
}

impl ChainView for FakeChain {
    fn tip_height(&self) -> Result<u32, ChainViewError> {
        self.check()?;
        Ok(self.state.borrow().tip)
    }

    fn block_location(&self, block_hash: &Hash32, height: u32) -> Result<BlockLocation, ChainViewError> {
        self.check()?;
        let state = self.state.borrow();
        if let Some((&observed, _)) = state.blocks.iter().find(|(h, hash)| **h <= state.tip && *hash == block_hash) {
            return Ok(BlockLocation::Canonical { height: observed });
        }
        if state.displaced.contains(block_hash) || (state.blocks.contains_key(&height) && height <= state.tip) {
            return Ok(BlockLocation::Side);
        }
        Ok(BlockLocation::Unknown)
    }

    fn coinbase_of(&self, block_hash: &Hash32) -> Result<Option<ObservedCoinbase>, ChainViewError> {
        self.check()?;
        Ok(self.state.borrow().coinbases.get(block_hash).cloned())
    }

    fn tx_status(&self, txid: &Hash32) -> Result<TxStatus, ChainViewError> {
        self.check()?;
        Ok(self
            .state
            .borrow()
            .txs
            .get(txid)
            .copied()
            .unwrap_or(TxStatus::Unknown))
    }

    fn confirmed_spender(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<ConfirmedSpend>, ChainViewError> {
        self.check()?;
        Ok(self.state.borrow().spends.get(outpoint).copied())
    }
}


fn varint(value: u64) -> Vec<u8> {
    match value {
        0..=0xfc => vec![u8::try_from(value).fixture("fits")],
        0xfd..=0xffff => {
            let mut out = vec![0xfd];
            out.extend_from_slice(&u16::try_from(value).fixture("fits").to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&u32::try_from(value).fixture("fits").to_le_bytes());
            out
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Witness {
    None,
    Items,
    Empty,
}

struct BuiltTx {
    raw: Vec<u8>,
    txid: Hash32,
}

fn build_tx(inputs: &[OutPoint], outputs: &[(u64, Vec<u8>)], witness: Witness) -> BuiltTx {
    let version = 2i32.to_le_bytes();
    let lock_time = 0u32.to_le_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(&varint(u64::try_from(inputs.len()).fixture("fits")));
    for input in inputs {
        body.extend_from_slice(&input.txid);
        body.extend_from_slice(&input.vout.to_le_bytes());
        body.extend_from_slice(&varint(0));
        body.extend_from_slice(&0xffff_fffdu32.to_le_bytes());
    }
    body.extend_from_slice(&varint(u64::try_from(outputs.len()).fixture("fits")));
    for (value, script) in outputs {
        body.extend_from_slice(&value.to_le_bytes());
        body.extend_from_slice(&varint(u64::try_from(script.len()).fixture("fits")));
        body.extend_from_slice(script);
    }
    let mut stripped = Vec::new();
    stripped.extend_from_slice(&version);
    stripped.extend_from_slice(&body);
    stripped.extend_from_slice(&lock_time);
    let txid = sha256d(&stripped);
    let raw = match witness {
        Witness::None => stripped,
        Witness::Items | Witness::Empty => {
            let mut raw = Vec::new();
            raw.extend_from_slice(&version);
            raw.extend_from_slice(&[0x00, 0x01]);
            raw.extend_from_slice(&body);
            for _ in inputs {
                if witness == Witness::Items {
                    raw.extend_from_slice(&varint(2));
                    raw.extend_from_slice(&varint(3));
                    raw.extend_from_slice(&[1, 2, 3]);
                    raw.extend_from_slice(&varint(2));
                    raw.extend_from_slice(&[4, 5]);
                } else {
                    raw.extend_from_slice(&varint(0));
                }
            }
            raw.extend_from_slice(&lock_time);
            raw
        }
    };
    BuiltTx { raw, txid }
}

fn pay_tx(batch: &PayoutBatch, inputs: &[OutPoint], change: Option<u64>) -> BuiltTx {
    let mut outputs: Vec<(u64, Vec<u8>)> = batch
        .outputs
        .iter()
        .rev()
        .map(|output| (output.amount_sat, output.script_pubkey.clone()))
        .collect();
    if let Some(change) = change {
        outputs.push((change, change_script()));
    }
    build_tx(inputs, &outputs, Witness::Items)
}

fn receipt(batch: &PayoutBatch, tx: &BuiltTx) -> PayoutReceipt {
    PayoutReceipt {
        batch_id: batch.id,
        txid: tx.txid,
        raw_tx: tx.raw.clone(),
    }
}

struct TestSigner {
    inputs: Vec<OutPoint>,
    refuse: bool,
}

impl ExternalSigner for TestSigner {
    fn sign(&self, request: &PayoutRequest) -> Result<PayoutReceipt, SignerError> {
        if self.refuse {
            return Err(SignerError("operator refused".into()));
        }
        let outputs: Vec<(u64, Vec<u8>)> = request
            .outputs
            .iter()
            .map(|output| (output.amount_sat, output.script_pubkey.clone()))
            .collect();
        let tx = build_tx(&self.inputs, &outputs, Witness::Items);
        Ok(PayoutReceipt {
            batch_id: request.batch_id,
            txid: tx.txid,
            raw_tx: tx.raw,
        })
    }
}


struct Fund {
    _dir: TempDir,
    path: PathBuf,
    ledger: Ledger,
    chain: FakeChain,
    block: BlockFound,
}

fn backend(path: impl AsRef<Path>) -> Arc<dyn KvStore> {
    if BACKEND == "fjall" {
        Arc::new(FjallStore::open(path).fixture("open fjall"))
    } else {
        Arc::new(RedbStore::open(path).fixture("open redb"))
    }
}

fn create(path: impl AsRef<Path>, config: PoolConfig) -> Result<Ledger, LedgerError> {
    Ledger::create(backend(path), config)
}

fn open(path: impl AsRef<Path>, config: PoolConfig) -> Result<Ledger, LedgerError> {
    Ledger::open(backend(path), config)
}

fn ledger_path(dir: &TempDir) -> PathBuf {
    dir.path().join("pool.redb")
}

fn staged_at(
    path: &Path,
    fee_bps: u16,
    claimed: u64,
    pool_value: u64,
) -> (Ledger, FakeChain, BlockFound) {
    let ledger = create(path, config(100, fee_bps)).fixture("create");
    ledger.record_share(&share(1, 1, 1, 50)).fixture("share 1");
    ledger.record_share(&share(1, 2, 1, 30)).fixture("share 2");
    let block = found(share(1, 3, 1, 20), 100, claimed);
    let recorded = ledger.record_found_block(&block).fixture("block");
    assert!(recorded.newly_recorded);
    let chain = FakeChain::default();
    chain.set_block(100, block.share.header_hash);
    chain.set_coinbase(block.share.header_hash, coinbase_for(&block, pool_value));
    chain.set_tip(99);
    for account in 1..=3 {
        ledger
            .set_payout_script(MinerId(account), &account_script(account))
            .fixture("script");
    }
    (ledger, chain, block)
}

fn staged(fee_bps: u16, claimed: u64) -> Fund {
    let dir = tempfile::tempdir().fixture("tempdir");
    let path = ledger_path(&dir);
    let (ledger, chain, block) = staged_at(&path, fee_bps, claimed, claimed);
    Fund {
        _dir: dir,
        path,
        ledger,
        chain,
        block,
    }
}

fn mature(fund: &Fund) {
    fund.chain.set_tip(102);
    let report = fund
        .ledger
        .reconcile_rounds(&fund.chain)
        .fixture("reconcile");
    assert_eq!(report.anomalies, Vec::new());
    let round = fund
        .ledger
        .round_for_block(&fund.block.share.header_hash)
        .fixture("round")
        .fixture("exists");
    assert_eq!(round.state, RoundState::Matured);
}

fn funded(fee_bps: u16, claimed: u64) -> Fund {
    let fund = staged(fee_bps, claimed);
    mature(&fund);
    fund
}

fn prepared(fund: &Fund) -> PayoutBatch {
    fund.ledger
        .prepare_payout_batch(idem(1), policy())
        .fixture("prepare")
        .fixture("a batch")
}

fn confirm_tx(fund: &Fund, txid: Hash32, block_tag: u8, height: u32, tip: u32) {
    fund.chain.set_block(height, hash(block_tag));
    fund.chain.set_tx(
        txid,
        TxStatus::Confirmed {
            block_hash: hash(block_tag),
            height,
        },
    );
    fund.chain.set_tip(tip);
}


#[test]
fn equal_height_fork_reverses_matured_credits() {
    let fund = funded(0, 1_000_001);
    fund.chain.set_block(100, hash(0xF0));
    fund.chain.set_tip(102);
    let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("reconcile equal-height fork");
    assert_eq!(report.transitions.len(), 1);
    assert_eq!(report.transitions[0].to, RoundState::Orphaned);
    assert_eq!(fund.ledger.balance(MinerId(1)).fixture("balance").available_sat, 0);
    fund.ledger.check_invariants().fixture("conservation");
}

#[test]
fn lower_height_fork_reverses_matured_credits() {
    let fund = funded(0, 1_000_001);
    fund.chain.set_block(100, hash(0xF1));
    fund.chain.set_tip(99);
    let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("reconcile shorter fork");
    assert_eq!(report.transitions.len(), 1);
    assert_eq!(report.transitions[0].to, RoundState::Orphaned);
    assert_eq!(fund.ledger.balance(MinerId(1)).fixture("balance").available_sat, 0);
    fund.ledger.check_invariants().fixture("conservation");
}

#[test]
fn independent_ledger_handles_share_the_revision_and_restart_state() {
    let dir = tempfile::tempdir().fixture("tempdir");
    let store = backend(ledger_path(&dir));
    let first = Ledger::create(Arc::clone(&store), config(100, 0)).fixture("create");
    let second = Ledger::open(Arc::clone(&store), config(100, 0)).fixture("second handle");
    first.record_share(&share(1, 1, 1, 10)).fixture("first write");
    second.record_share(&share(1, 2, 1, 20)).fixture("second write");
    assert_eq!(first.share_count().fixture("count"), 2);
    assert_eq!(second.share_count().fixture("count"), 2);
    first.check_invariants().fixture("first invariants");
    second.check_invariants().fixture("second invariants");
    drop(first);
    drop(second);
    let reopened = Ledger::open(store, config(100, 0)).fixture("reopen");
    assert_eq!(reopened.share_count().fixture("restart count"), 2);
}

#[test]
fn audit_tail_pages_the_latest_records_in_sequence_order() {
    let fund = funded(0, 1_000_001);
    let all = fund.ledger.audit_records(0, usize::MAX).fixture("audit");
    let tail = fund.ledger.audit_tail(2).fixture("tail");
    assert_eq!(tail, all[all.len().saturating_sub(2)..]);
    assert_eq!(fund.ledger.audit_tail(usize::MAX).fixture("all"), all);
    assert_eq!(fund.ledger.audit_tail(0).fixture("empty tail"), Vec::new());
    let (_dir, empty) = plain_ledger(100);
    assert_eq!(empty.audit_tail(20).fixture("empty ledger"), Vec::new());
}

#[test]
fn runtime_epochs_are_durable_and_shared_between_ledger_handles() {
    let dir = tempfile::tempdir().fixture("tempdir");
    let path = ledger_path(&dir);
    let store = backend(&path);
    let first = Ledger::create(Arc::clone(&store), config(100, 0)).fixture("create");
    let second = Ledger::open(Arc::clone(&store), config(100, 0)).fixture("second handle");
    assert_eq!(first.allocate_run_epoch().fixture("first epoch"), 1);
    assert_eq!(second.allocate_run_epoch().fixture("second epoch"), 2);
    drop(first);
    drop(second);
    drop(store);
    let reopened = open(&path, config(100, 0)).fixture("restart backend");
    assert_eq!(reopened.allocate_run_epoch().fixture("restart epoch"), 3);
}

fn wide_mul(a: u128, b: u128) -> (u128, u128) {
    let mask = u128::from(u64::MAX);
    let (a0, a1) = (a & mask, a >> 64);
    let (b0, b1) = (b & mask, b >> 64);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & mask) + (p10 & mask);
    let low = (p00 & mask) | ((mid & mask) << 64);
    let high = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (high, low)
}

#[test]
fn mul_div_rem_is_exact_across_the_192_bit_range() {
    let cases: [(u64, u128, u128); 7] = [
        (0, 0, 1),
        (7, 3, 9),
        (u64::MAX, u128::MAX, u128::MAX),
        (u64::MAX, 1 << 127, (1 << 127) + 12_345),
        (123_456_789, 1 << 100, (1 << 100) + (1 << 64) + 7),
        (
            2_100_000_000_000_000,
            123_456_789_012_345_678_901_234_567_890,
            987_654_321_098_765_432_109_876_543_210_987_654,
        ),
        (1, 1, 1),
    ];
    for (a, b, d) in cases {
        let (quotient, remainder) = mul_div_rem(a, b, d).fixture("valid");
        assert!(remainder < d, "remainder below divisor for {a} {b} {d}");
        let (q_high, q_low) = wide_mul(quotient, d);
        let (q_low, carry) = q_low.overflowing_add(remainder);
        let q_high = q_high + u128::from(carry);
        assert_eq!(
            (q_high, q_low),
            wide_mul(u128::from(a), b),
            "q*d+r == a*b for {a} {b} {d}"
        );
        assert!(quotient <= u128::from(a));
    }
    assert!(matches!(
        mul_div_rem(1, 1, 0),
        Err(LedgerError::InvalidInput(_))
    ));
    assert!(matches!(
        mul_div_rem(1, 2, 1),
        Err(LedgerError::InvalidInput(_))
    ));
}

#[test]
fn split_reward_rounds_deterministically_and_conserves_the_total() {
    let thirds = [(MinerId(1), 1u128), (MinerId(2), 1), (MinerId(3), 1)];
    assert_eq!(
        split_reward(100, &thirds).fixture("split"),
        miner_amounts(&[(1, 34), (2, 33), (3, 33)]),
        "equal remainders: the lowest account takes the residual satoshi"
    );
    let quarter = [(MinerId(1), 1u128), (MinerId(2), 3)];
    assert_eq!(
        split_reward(10, &quarter).fixture("split"),
        miner_amounts(&[(1, 3), (2, 7)])
    );
    assert_eq!(split_reward(0, &thirds).fixture("zero net"), Vec::new());
    assert!(matches!(
        split_reward(5, &[]),
        Err(LedgerError::EmptyWindow)
    ));
    assert!(matches!(
        split_reward(5, &[(MinerId(2), 1), (MinerId(1), 1)]),
        Err(LedgerError::InvalidInput(_))
    ));
    assert!(matches!(
        split_reward(5, &[(MinerId(1), 0)]),
        Err(LedgerError::InvalidInput(_))
    ));
    assert!(matches!(
        split_reward(5, &[(MinerId(1), u128::MAX), (MinerId(2), 1)]),
        Err(LedgerError::Overflow(_))
    ));
}

#[test]
fn split_reward_property_sum_equals_net_and_each_share_is_floor_or_ceil() {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..300 {
        let accounts = usize::try_from(next() % 12).fixture("small") + 1;
        let weights: Vec<(MinerId, u128)> = (0..accounts)
            .map(|index| {
                (
                    MinerId(u64::try_from(index).fixture("small") + 1),
                    u128::from(next() % 1_000_000) + 1,
                )
            })
            .collect();
        let net = next() % 2_100_000_000_000_000;
        let total: u128 = weights.iter().map(|(_, weight)| *weight).sum();
        let result = split_reward(net, &weights).fixture("split");
        let sum: u64 = result.iter().map(|(_, amount)| *amount).sum();
        assert_eq!(sum, net, "allocation sum equals net exactly");
        for (miner, weight) in &weights {
            let floor = u128::from(net) * weight / total;
            let got = result
                .iter()
                .find(|(candidate, _)| candidate == miner)
                .map_or(0, |(_, amount)| u128::from(*amount));
            assert!(
                got == floor || got == floor + 1,
                "within one satoshi of the exact share"
            );
        }
    }
}

#[test]
fn split_reward_handles_network_scale_work_without_loss() {
    let weights = [
        (MinerId(1), 300_000_000_000_000_000_000_000u128),
        (MinerId(2), 100_000_000_000_000_000_000_000),
        (MinerId(3), 7),
    ];
    let net = 2_100_000_000_000_000;
    let result = split_reward(net, &weights).fixture("split");
    let sum: u64 = result.iter().map(|(_, amount)| *amount).sum();
    assert_eq!(sum, net);
    assert_eq!(result[0].1, 1_575_000_000_000_000);
    assert_eq!(result[1].1, 525_000_000_000_000);
}

#[test]
fn pool_fee_rounds_down_and_never_exceeds_gross() {
    assert_eq!(
        split_pool_fee(1_000_001, 250).fixture("fee"),
        (25_000, 975_001)
    );
    assert_eq!(
        split_pool_fee(u64::MAX, 10_000).fixture("fee"),
        (u64::MAX, 0)
    );
    assert_eq!(split_pool_fee(0, 500).fixture("fee"), (0, 0));
    assert!(matches!(
        split_pool_fee(1, 10_001),
        Err(LedgerError::InvalidInput(_))
    ));
}

#[test]
fn window_accumulator_truncates_the_boundary_share() {
    let mut window = WindowAccumulator::new(10);
    window.push_older(MinerId(1), 6).fixture("push");
    assert!(!window.is_full());
    window.push_older(MinerId(2), 6).fixture("push");
    assert!(window.is_full());
    window
        .push_older(MinerId(3), 6)
        .fixture("push beyond a full window");
    assert_eq!(window.total(), 10);
    assert_eq!(
        window.into_weights(),
        vec![(MinerId(1), 6), (MinerId(2), 4)]
    );
}

#[test]
fn share_work_converts_exactly_from_le_bytes() {
    let mut le = [0u8; 32];
    le[..16].copy_from_slice(&u128::MAX.to_le_bytes());
    assert_eq!(work_from_le_bytes(le).fixture("fits"), u128::MAX);
    le[16] = 1;
    assert!(matches!(
        work_from_le_bytes(le),
        Err(LedgerError::Overflow(_))
    ));
}


#[test]
fn legacy_and_segwit_serializations_share_one_txid() {
    let inputs = [outpoint(1, 3)];
    let outputs = vec![(1_000u64, script(1)), (2_000, script(2))];
    let legacy = build_tx(&inputs, &outputs, Witness::None);
    let segwit = build_tx(&inputs, &outputs, Witness::Items);
    assert_eq!(legacy.txid, segwit.txid);
    let parsed_legacy = parse_transaction(&legacy.raw).fixture("legacy");
    let parsed_segwit = parse_transaction(&segwit.raw).fixture("segwit");
    assert_eq!(parsed_legacy.txid, legacy.txid);
    assert_eq!(parsed_segwit.txid, legacy.txid);
    assert!(!parsed_legacy.has_witness);
    assert!(parsed_segwit.has_witness);
    assert_eq!(parsed_segwit.inputs, inputs.to_vec());
    assert_eq!(parsed_segwit.outputs.len(), 2);
    assert_eq!(parsed_segwit.outputs[1].value_sat, 2_000);
    assert_eq!(parsed_segwit.version, 2);
}

#[test]
fn parser_rejects_malformed_encodings() {
    let inputs = [outpoint(1, 0)];
    let outputs = vec![(1_000u64, script(1))];
    let good = build_tx(&inputs, &outputs, Witness::Items);
    assert_eq!(
        parse_transaction(&good.raw[..good.raw.len() - 1]),
        Err(TxParseError::Truncated)
    );
    let mut trailing = good.raw;
    trailing.push(0);
    assert_eq!(
        parse_transaction(&trailing),
        Err(TxParseError::TrailingBytes)
    );
    let empty_witness = build_tx(&inputs, &outputs, Witness::Empty);
    assert_eq!(
        parse_transaction(&empty_witness.raw),
        Err(TxParseError::SuperfluousWitness)
    );
    let too_rich = build_tx(&inputs, &[(MAX_MONEY_SAT + 1, script(1))], Witness::None);
    assert_eq!(
        parse_transaction(&too_rich.raw),
        Err(TxParseError::ValueOutOfRange)
    );
    let mut non_canonical = vec![2, 0, 0, 0, 0xfd, 0x01, 0x00];
    non_canonical.extend_from_slice(&[0u8; 60]);
    assert_eq!(
        parse_transaction(&non_canonical),
        Err(TxParseError::NonCanonicalVarint)
    );
    let bad_flag = vec![2, 0, 0, 0, 0x00, 0x02, 0, 0, 0, 0];
    assert_eq!(
        parse_transaction(&bad_flag),
        Err(TxParseError::BadWitnessFlag)
    );
    let huge_count = [
        vec![2, 0, 0, 0, 0xfe],
        0x00ff_ffffu32.to_le_bytes().to_vec(),
    ]
    .concat();
    assert_eq!(
        parse_transaction(&huge_count),
        Err(TxParseError::CountTooLarge)
    );
    let no_outputs = build_tx(&inputs, &[], Witness::None);
    assert_eq!(
        parse_transaction(&no_outputs.raw),
        Err(TxParseError::NoOutputs)
    );
}


#[test]
fn payout_request_and_receipt_round_trip_and_reject_corruption() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let request = fund.ledger.request_for(&batch.id).fixture("request");
    assert_eq!(request.allowed_change_scripts, vec![change_script()]);
    let encoded = request.encode().fixture("encode");
    assert_eq!(&encoded[..4], b"BRPR");
    assert_eq!(PayoutRequest::decode(&encoded).fixture("decode"), request);
    assert_eq!(request.digest().fixture("digest"), sha256(&encoded));
    let mut bad_magic = encoded.clone();
    bad_magic[0] = b'X';
    assert!(matches!(
        PayoutRequest::decode(&bad_magic),
        Err(LedgerError::Codec(_))
    ));
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(matches!(
        PayoutRequest::decode(&trailing),
        Err(LedgerError::Codec(_))
    ));
    assert!(matches!(
        PayoutRequest::decode(&encoded[..encoded.len() - 3]),
        Err(LedgerError::Codec(_))
    ));
    let mut wrong_total = request;
    wrong_total.total_sat += 1;
    assert!(matches!(
        wrong_total.encode(),
        Err(LedgerError::InvalidInput(_))
    ));

    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], Some(50_000));
    let signed = receipt(&batch, &tx);
    let wire = signed.encode().fixture("encode receipt");
    assert_eq!(&wire[..4], b"BRPT");
    assert_eq!(
        PayoutReceipt::decode(&wire).fixture("decode receipt"),
        signed
    );
    assert!(matches!(
        PayoutReceipt::decode(&wire[..wire.len() - 1]),
        Err(LedgerError::Codec(_))
    ));
}

#[test]
fn payout_request_encode_rejects_invalid_change_scripts_before_emitting_bytes() {
    fn request(change: Vec<Vec<u8>>) -> PayoutRequest {
        PayoutRequest {
            batch_id: hash(0xAB),
            outputs: vec![PayoutOutput {
                account: MinerId(1),
                script_pubkey: account_script(1),
                amount_sat: 1_000,
            }],
            total_sat: 1_000,
            allowed_change_scripts: change,
        }
    }

    let valid = request(vec![change_script(), script(0xD0)]);
    let encoded = valid.encode().fixture("encode valid change scripts");
    assert_eq!(PayoutRequest::decode(&encoded).fixture("decode"), valid);
    let empty_list = request(Vec::new());
    let encoded_empty = empty_list.encode().fixture("encode empty change list");
    assert_eq!(
        PayoutRequest::decode(&encoded_empty).fixture("decode empty change list"),
        empty_list
    );

    let too_many = request(vec![change_script(); MAX_CHANGE_SCRIPTS + 1]);
    assert!(matches!(
        too_many.encode(),
        Err(LedgerError::InvalidInput(_))
    ));
    assert!(matches!(
        request(vec![Vec::new()]).encode(),
        Err(LedgerError::InvalidInput(_))
    ));
    assert!(matches!(
        request(vec![vec![0x51; MAX_SCRIPT_LEN + 1]]).encode(),
        Err(LedgerError::InvalidInput(_))
    ));
    assert!(matches!(
        request(vec![vec![0x6a, 0x01]]).encode(),
        Err(LedgerError::InvalidInput(_))
    ));
}


#[test]
fn create_refuses_existing_paths_and_open_demands_the_same_config() {
    let dir = tempfile::tempdir().fixture("tempdir");
    let path = ledger_path(&dir);
    assert!(matches!(
        open(&path, config(100, 0)).err(),
        Some(LedgerError::NotALedger)
    ));
    let ledger = create(&path, config(100, 0)).fixture("create");
    drop(ledger);
    assert!(matches!(
        create(&path, config(100, 0)).err(),
        Some(LedgerError::PathExists)
    ));
    assert!(matches!(
        open(&path, config(101, 0)).err(),
        Some(LedgerError::ConfigMismatch)
    ));
    assert!(matches!(
        open(&path, config(100, 1)).err(),
        Some(LedgerError::ConfigMismatch)
    ));
    let reopened = open(&path, config(100, 0)).fixture("same config reopens");
    assert_eq!(reopened.config(), &config(100, 0));
}

#[test]
fn open_refuses_a_foreign_store_without_writing_to_it() {
    let dir = tempfile::tempdir().fixture("tempdir");
    let store = backend(ledger_path(&dir));
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::PoolLedger, b"foreign-owner", b"untouched");
    store.write_durable(batch).fixture("seed");
    assert!(matches!(
        Ledger::open(Arc::clone(&store), config(100, 0)).err(),
        Some(LedgerError::NotALedger)
    ));
    assert_eq!(store.get(ColumnFamily::PoolLedger, b"foreign-owner").fixture("read"), Some(b"untouched".to_vec()));
    assert!(store.iter_prefix(ColumnFamily::PoolLedger, b"pool-ledger/v1/").fixture("scan").next().is_none());
}

#[test]
fn config_validation_rejects_every_unsafe_value() {
    let ok = config(100, 0);
    assert!(ok.validate().is_ok());
    let mut bad = ok.clone();
    bad.window_work = 0;
    assert!(matches!(bad.validate(), Err(LedgerError::InvalidConfig(_))));
    let mut bad = ok.clone();
    bad.pool_fee_bps = 10_001;
    assert!(matches!(bad.validate(), Err(LedgerError::InvalidConfig(_))));
    let mut bad = ok.clone();
    bad.coinbase_maturity = 0;
    assert!(matches!(bad.validate(), Err(LedgerError::InvalidConfig(_))));
    let mut bad = ok.clone();
    bad.reorg_watch_depth = 2;
    assert!(matches!(bad.validate(), Err(LedgerError::InvalidConfig(_))));
    let mut bad = ok.clone();
    bad.dust_limit_sat = 0;
    assert!(matches!(bad.validate(), Err(LedgerError::InvalidConfig(_))));
    let mut bad = ok.clone();
    bad.pool_coinbase_script = vec![0x6a, 0x01];
    assert!(matches!(bad.validate(), Err(LedgerError::InvalidConfig(_))));
    let mut bad = ok;
    bad.change_scripts = vec![Vec::new()];
    assert!(matches!(bad.validate(), Err(LedgerError::InvalidConfig(_))));
    let dir = tempfile::tempdir().fixture("tempdir");
    assert!(matches!(
        create(ledger_path(&dir), config(0, 0)).err(),
        Some(LedgerError::InvalidConfig(_))
    ));
}


fn plain_ledger(window: u128) -> (TempDir, Ledger) {
    let dir = tempfile::tempdir().fixture("tempdir");
    let ledger = create(ledger_path(&dir), config(window, 0)).fixture("create");
    (dir, ledger)
}

#[test]
fn shares_are_idempotent_by_header_hash_and_unique_by_identity() {
    let (_dir, ledger) = plain_ledger(100);
    let first = share(1, 1, 1, 10);
    assert_eq!(
        ledger.record_share(&first).fixture("credit"),
        ShareReceipt::Credited { seq: 0 }
    );
    assert_eq!(
        ledger.record_share(&first).fixture("replay"),
        ShareReceipt::Duplicate { seq: 0 }
    );
    assert_eq!(ledger.share_count().fixture("count"), 1);
    assert_eq!(
        ledger.share_by_hash(&first.header_hash).fixture("lookup"),
        Some((0, 10))
    );

    let mut other_work = first.clone();
    other_work.work = 11;
    assert!(matches!(
        ledger.record_share(&other_work).err(),
        Some(LedgerError::ShareConflict { seq: 0 })
    ));

    let mut same_identity = first;
    same_identity.header_hash = hash(0xEE);
    assert!(matches!(
        ledger.record_share(&same_identity).err(),
        Some(LedgerError::ShareIdentityConflict { seq: 0 })
    ));

    let mut zero = share(1, 1, 2, 1);
    zero.work = 0;
    assert!(matches!(
        ledger.record_share(&zero).err(),
        Some(LedgerError::InvalidInput(_))
    ));
    let mut long = share(1, 1, 3, 1);
    long.extranonce = vec![0; MAX_EXTRANONCE_LEN + 1];
    assert!(matches!(
        ledger.record_share(&long).err(),
        Some(LedgerError::InvalidInput(_))
    ));
    assert_eq!(
        ledger.share_count().fixture("count"),
        1,
        "rejected shares credit nothing"
    );
    ledger.check_invariants().fixture("invariants");
}

#[test]
fn maximum_length_extranonce_shares_stay_readable() {
    let (_dir, ledger) = plain_ledger(100);
    let mut longest = share(1, 1, 1, 10);
    longest.extranonce = vec![0xAB; MAX_EXTRANONCE_LEN];
    assert_eq!(
        ledger.record_share(&longest).fixture("credit"),
        ShareReceipt::Credited { seq: 0 }
    );
    assert_eq!(
        ledger.share_by_hash(&longest.header_hash).fixture("lookup"),
        Some((0, 10))
    );
    assert_eq!(
        ledger.record_share(&longest).fixture("replay"),
        ShareReceipt::Duplicate { seq: 0 }
    );
    let mut same_identity = longest.clone();
    same_identity.header_hash = hash(0xEE);
    assert!(matches!(
        ledger.record_share(&same_identity).err(),
        Some(LedgerError::ShareIdentityConflict { seq: 0 })
    ));
    ledger.check_invariants().fixture("invariants");
}

#[test]
fn window_boundaries_are_exact_in_work_units() {
    for (window, expected) in [
        (100u128, vec![(2u64, 40u128), (3, 60)]),
        (120, vec![(2, 60), (3, 60)]),
        (121, vec![(1, 1), (2, 60), (3, 60)]),
        (1_000, vec![(1, 60), (2, 60), (3, 60)]),
        (1, vec![(3, 1)]),
    ] {
        let (_dir, ledger) = plain_ledger(window);
        for account in 1..=3 {
            ledger
                .record_share(&share(1, account, 1, 60))
                .fixture("share");
        }
        let weights: Vec<(MinerId, u128)> =
            expected.iter().map(|(a, w)| (MinerId(*a), *w)).collect();
        assert_eq!(
            ledger.current_window().fixture("window"),
            weights,
            "window {window}"
        );
    }
}

#[test]
fn one_account_can_hold_several_shares_in_the_window() {
    let (_dir, ledger) = plain_ledger(100);
    ledger.record_share(&share(1, 1, 1, 30)).fixture("a");
    ledger.record_share(&share(1, 2, 1, 30)).fixture("b");
    ledger.record_share(&share(1, 1, 2, 30)).fixture("c");
    assert_eq!(
        ledger.current_window().fixture("window"),
        vec![(MinerId(1), 60), (MinerId(2), 30)]
    );
}

#[test]
fn the_window_slides_across_blocks_and_snapshots_are_frozen() {
    let (_dir, ledger) = plain_ledger(100);
    ledger.record_share(&share(1, 1, 1, 50)).fixture("a1");
    let first = found(share(1, 2, 1, 50), 10, 1_000);
    let first_round = ledger.record_found_block(&first).fixture("block 1").round;
    let second = found(share(1, 3, 1, 100), 11, 1_000);
    let second_round = ledger.record_found_block(&second).fixture("block 2").round;
    assert_eq!(
        ledger.round_weights(first_round.id).fixture("weights"),
        vec![(MinerId(1), 50), (MinerId(2), 50)]
    );
    assert_eq!(
        ledger.round_weights(second_round.id).fixture("weights"),
        vec![(MinerId(3), 100)]
    );
    assert_eq!(first_round.window_work_total, 100);
    ledger
        .record_share(&share(2, 4, 1, 100))
        .fixture("later share");
    assert_eq!(
        ledger.round_weights(first_round.id).fixture("weights"),
        vec![(MinerId(1), 50), (MinerId(2), 50)],
        "later shares never change a snapshot"
    );
}

#[test]
fn pruning_streams_bounded_batches() {
    let (_dir, ledger) = plain_ledger(100);
    for nonce in 0..1200u32 {
        ledger.record_share(&share(1, 1, nonce, 1)).fixture("share");
    }
    assert_eq!(ledger.share_count().fixture("count"), 1200);
    assert_eq!(ledger.prune_shares(100).fixture("prune"), 1100);
    assert_eq!(ledger.share_count().fixture("count"), 100);
    assert_eq!(
        ledger.current_window().fixture("window"),
        vec![(MinerId(1), 100)]
    );
    assert_eq!(ledger.prune_shares(100).fixture("nothing left"), 0);
}

#[test]
fn pruning_many_batches_applies_the_limit_before_materialization() {
    let (_dir, ledger) = plain_ledger(100);
    for nonce in 0..3500u32 {
        ledger.record_share(&share(1, 1, nonce, 1)).fixture("share");
    }
    assert_eq!(ledger.share_count().fixture("count"), 3500);
    assert_eq!(ledger.prune_shares(100).fixture("prune"), 3400);
    assert_eq!(ledger.share_count().fixture("count"), 100);
    assert_eq!(
        ledger.current_window().fixture("window"),
        vec![(MinerId(1), 100)]
    );
    let audits = ledger.audit_records(0, 10_000).fixture("audit");
    let batches: Vec<u64> = audits
        .iter()
        .filter(|record| record.kind == AuditKind::SharesPruned)
        .map(|record| record.values[1])
        .collect();
    assert_eq!(batches.len(), 4, "3400 doomed in 1024-sized batches");
    assert!(
        batches.iter().all(|batch| *batch <= 1024),
        "every batch applies the 1024 limit: {batches:?}"
    );
    assert_eq!(batches.iter().sum::<u64>(), 3400);
    assert_eq!(ledger.prune_shares(100).fixture("nothing left"), 0);
    ledger.check_invariants().fixture("invariants");
}

#[test]
fn share_count_comes_from_sequence_metadata_not_a_table_scan() {
    let (_dir, ledger) = plain_ledger(5);
    assert_eq!(ledger.share_count().fixture("empty"), 0);
    for nonce in 0..10u32 {
        ledger.record_share(&share(1, 1, nonce, 1)).fixture("share");
    }
    assert_eq!(ledger.share_count().fixture("ten"), 10);
    assert_eq!(ledger.retire_job(1).fixture("retire"), 10);
    assert_eq!(ledger.share_count().fixture("retire keeps shares"), 10);
    assert_eq!(ledger.prune_shares(5).fixture("prune"), 5);
    assert_eq!(ledger.share_count().fixture("five left"), 5);
    ledger.check_invariants().fixture("invariants");
}

#[test]
fn short_history_uses_all_work_and_pruning_protects_old_windows() {
    let (_dir, ledger) = plain_ledger(100);
    for account in 1..=6 {
        ledger
            .record_share(&share(1, account, 1, 50))
            .fixture("share");
    }
    assert!(matches!(
        ledger.prune_shares(99).err(),
        Some(LedgerError::InvalidInput(_))
    ));
    assert_eq!(ledger.prune_shares(100).fixture("prune"), 4);
    assert_eq!(ledger.share_count().fixture("count"), 2);
    assert_eq!(
        ledger.current_window().fixture("window"),
        vec![(MinerId(5), 50), (MinerId(6), 50)]
    );
    assert_eq!(ledger.prune_shares(100).fixture("nothing left to prune"), 0);
    let old = found(share(1, 3, 1, 50), 5, 1_000);
    assert!(matches!(
        ledger.record_found_block(&old).err(),
        Some(LedgerError::WindowPruned)
    ));
    let recent = found(share(1, 6, 1, 50), 6, 1_000);
    let recorded = ledger.record_found_block(&recent).fixture("recent block");
    assert_eq!(recorded.share, ShareReceipt::Duplicate { seq: 5 });
    assert_eq!(recorded.round.window_work_total, 100);
    ledger.check_invariants().fixture("invariants");
}

#[test]
fn retiring_a_job_bounds_the_index_and_refuses_late_shares() {
    let (_dir, ledger) = plain_ledger(100);
    let old = share(7, 1, 1, 10);
    ledger.record_share(&old).fixture("credit");
    ledger.record_share(&share(8, 2, 1, 10)).fixture("other job");
    assert_eq!(ledger.retire_job(7).fixture("retire"), 1);
    assert_eq!(ledger.retire_job(7).fixture("again"), 0);
    assert_eq!(
        ledger.share_by_hash(&old.header_hash).fixture("lookup"),
        Some((0, 10)),
        "retired header hashes stay reserved as tombstones"
    );
    assert!(matches!(
        ledger.record_share(&old).err(),
        Some(LedgerError::JobRetired(7))
    ));
    assert_eq!(
        ledger.current_window().fixture("window"),
        vec![(MinerId(1), 10), (MinerId(2), 10)],
        "retired job work stays in the window"
    );
    ledger
        .record_share(&share(8, 3, 1, 10))
        .fixture("live job still credits");
}

#[test]
fn version_and_ntime_rolls_are_distinct_shares_not_conflicts() {
    let (_dir, ledger) = plain_ledger(100);
    let base = share_vnt(1, 1, 7, 0x20000000, 1_700_000_000, 10);
    assert_eq!(
        ledger.record_share(&base).fixture("base"),
        ShareReceipt::Credited { seq: 0 }
    );
    let rolled_version = share_vnt(1, 1, 7, 0x20000001, 1_700_000_000, 10);
    assert_ne!(rolled_version.header_hash, base.header_hash);
    assert_eq!(
        ledger.record_share(&rolled_version).fixture("version roll"),
        ShareReceipt::Credited { seq: 1 }
    );
    let rolled_time = share_vnt(1, 1, 7, 0x20000000, 1_700_000_001, 10);
    assert_ne!(rolled_time.header_hash, base.header_hash);
    assert_eq!(
        ledger.record_share(&rolled_time).fixture("ntime roll"),
        ShareReceipt::Credited { seq: 2 }
    );
    assert_eq!(ledger.share_count().fixture("count"), 3);
    ledger.check_invariants().fixture("invariants");
}

#[test]
fn a_retired_header_hash_is_never_credited_again() {
    let (_dir, ledger) = plain_ledger(100);
    let old = share(7, 1, 1, 10);
    assert_eq!(
        ledger.record_share(&old).fixture("credit"),
        ShareReceipt::Credited { seq: 0 }
    );
    assert_eq!(ledger.retire_job(7).fixture("retire"), 1);
    assert!(matches!(
        ledger.record_share(&old).err(),
        Some(LedgerError::JobRetired(7))
    ));
    let mut cross_job = old.clone();
    cross_job.job = 8;
    assert!(matches!(
        ledger.record_share(&cross_job).err(),
        Some(LedgerError::ShareConflict { seq: 0 })
    ));
    assert_eq!(ledger.share_count().fixture("count"), 1);
    ledger.check_invariants().fixture("invariants");
}

#[test]
fn permanent_share_conflicts_are_classified_for_rejection() {
    assert!(LedgerError::JobRetired(7).is_permanent_share_conflict());
    assert!(LedgerError::ShareConflict { seq: 0 }.is_permanent_share_conflict());
    assert!(
        LedgerError::ShareIdentityConflict { seq: 0 }.is_permanent_share_conflict()
    );
    assert!(LedgerError::BlockConflict.is_permanent_share_conflict());
    assert!(!LedgerError::Conflict.is_permanent_share_conflict());
    assert!(!LedgerError::WindowPruned.is_permanent_share_conflict());
    assert!(!LedgerError::InvalidInput("x").is_permanent_share_conflict());
}

#[test]
fn config_encode_validates_change_scripts_before_encoding() {
    let ok = config(100, 0);
    assert!(ok.encode().is_ok());
    let mut too_many = ok.clone();
    too_many.change_scripts = vec![change_script(); MAX_CHANGE_SCRIPTS + 1];
    assert!(matches!(
        too_many.encode().err(),
        Some(LedgerError::InvalidConfig(_))
    ));
    let mut empty = ok.clone();
    empty.change_scripts = vec![Vec::new()];
    assert!(matches!(
        empty.encode().err(),
        Some(LedgerError::InvalidConfig(_))
    ));
    let mut unspendable = ok.clone();
    unspendable.change_scripts = vec![vec![0x6a, 0x01]];
    assert!(matches!(
        unspendable.encode().err(),
        Some(LedgerError::InvalidConfig(_))
    ));
}


#[test]
fn a_found_block_is_recorded_once_and_pays_nothing_until_the_chain_shows_it() {
    let fund = staged(0, 1_000_001);
    let again = fund.ledger.record_found_block(&fund.block).fixture("replay");
    assert!(!again.newly_recorded);
    assert_eq!(again.round.state, RoundState::Pending);
    assert_eq!(
        again.share,
        ShareReceipt::Duplicate {
            seq: again.round.solving_seq
        }
    );
    assert!(!again.round.reward_fixed);

    let mut moved = fund.block.clone();
    moved.height = 101;
    assert!(matches!(
        fund.ledger.record_found_block(&moved).err(),
        Some(LedgerError::BlockConflict)
    ));
    let mut other_value = fund.block.clone();
    other_value.claimed_coinbase_value_sat += 1;
    assert!(matches!(
        fund.ledger.record_found_block(&other_value).err(),
        Some(LedgerError::BlockConflict)
    ));

    let report = fund
        .ledger
        .reconcile_rounds(&fund.chain)
        .fixture("reconcile");
    assert_eq!(report.transitions, Vec::new(), "block above the tip");
    assert_eq!(report.anomalies, Vec::new(), "block above the tip");
    for account in 1..=3 {
        assert_eq!(
            fund.ledger.balance(MinerId(account)).fixture("balance"),
            Balance::default()
        );
    }
    assert_eq!(
        fund.ledger.round_allocations(1).fixture("allocs"),
        Vec::new()
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn rounds_mature_only_after_the_configured_confirmations_on_the_active_chain() {
    let fund = staged(0, 1_000_001);
    fund.chain.set_tip(100);
    let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("tip 100");
    assert_eq!(
        report.transitions,
        vec![RoundTransition {
            round: 1,
            from: RoundState::Pending,
            to: RoundState::Immature,
            credited_sat: 0,
            reversed_sat: 0,
            deficit_created_sat: 0,
        }]
    );
    let round = fund.ledger.round(1).fixture("round").fixture("exists");
    assert!(round.reward_fixed);
    assert_eq!(
        (round.gross_sat, round.pool_fee_sat, round.net_sat),
        (1_000_001, 0, 1_000_001)
    );
    assert_eq!(
        fund.ledger.round_allocations(1).fixture("allocs"),
        miner_amounts(&[(1, 500_001), (2, 300_000), (3, 200_000)]),
        "largest remainder takes the residual satoshi"
    );
    assert_eq!(
        fund.ledger.balance(MinerId(1)).fixture("balance"),
        Balance::default()
    );

    fund.chain.set_tip(101);
    assert_eq!(fund.ledger
            .reconcile_rounds(&fund.chain)
            .fixture("tip 101")
            .transitions
            , Vec::new());
    assert_eq!(
        fund.ledger.balance(MinerId(1)).fixture("balance"),
        Balance::default()
    );

    fund.chain.set_tip(102);
    let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("tip 102");
    assert_eq!(report.transitions.len(), 1);
    assert_eq!(report.transitions[0].from, RoundState::Immature);
    assert_eq!(report.transitions[0].to, RoundState::Matured);
    assert_eq!(report.transitions[0].credited_sat, 1_000_001);
    assert_eq!(
        fund.ledger
            .balance(MinerId(1))
            .fixture("balance")
            .available_sat,
        500_001
    );
    assert_eq!(
        fund.ledger
            .balance(MinerId(2))
            .fixture("balance")
            .available_sat,
        300_000
    );
    assert_eq!(
        fund.ledger
            .balance(MinerId(3))
            .fixture("balance")
            .available_sat,
        200_000
    );
    let invariants = fund.ledger.check_invariants().fixture("invariants");
    assert_eq!(invariants.credited_sat, 1_000_001);
    assert_eq!(invariants.available_sat, 1_000_001);
}

#[test]
fn the_pool_fee_comes_from_the_observed_reward_and_allocations_sum_to_net() {
    let fund = funded(250, 1_000_001);
    let round = fund.ledger.round(1).fixture("round").fixture("exists");
    assert_eq!(
        (round.gross_sat, round.pool_fee_sat, round.net_sat),
        (1_000_001, 25_000, 975_001)
    );
    let allocations = fund.ledger.round_allocations(1).fixture("allocs");
    assert_eq!(
        allocations,
        miner_amounts(&[(1, 487_501), (2, 292_500), (3, 195_000)])
    );
    let sum: u64 = allocations.iter().map(|(_, amount)| *amount).sum();
    assert_eq!(sum, round.net_sat);
    assert_eq!(sum + round.pool_fee_sat, round.gross_sat);
}

#[test]
fn reconciliation_is_idempotent_and_writes_no_audit_noise() {
    let fund = funded(0, 1_000_001);
    let before = fund.ledger.audit_records(0, 1_000).fixture("audit");
    for _ in 0..3 {
        let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("again");
        assert_eq!(report.transitions, Vec::new());
        assert_eq!(report.anomalies, Vec::new());
    }
    assert_eq!(fund.ledger.audit_records(0, 1_000).fixture("audit"), before);
}

#[test]
fn a_reorg_before_maturity_orphans_the_round_with_nothing_to_reverse_and_can_revive() {
    let fund = staged(0, 1_000_001);
    fund.chain.set_tip(100);
    fund.ledger.reconcile_rounds(&fund.chain).fixture("immature");
    fund.chain.set_block(100, hash(0xDD));
    fund.chain.set_tip(101);
    let report = fund
        .ledger
        .reconcile_rounds(&fund.chain)
        .fixture("displaced");
    assert_eq!(report.transitions.len(), 1);
    assert_eq!(report.transitions[0].to, RoundState::Orphaned);
    assert_eq!(report.transitions[0].reversed_sat, 0);
    assert_eq!(
        fund.ledger.balance(MinerId(1)).fixture("balance"),
        Balance::default()
    );
    fund.ledger.check_invariants().fixture("invariants");

    fund.chain.set_block(100, fund.block.share.header_hash);
    let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("revived");
    assert_eq!(report.transitions[0].from, RoundState::Orphaned);
    assert_eq!(report.transitions[0].to, RoundState::Immature);
    fund.chain.set_tip(102);
    fund.ledger.reconcile_rounds(&fund.chain).fixture("matured");
    assert_eq!(
        fund.ledger
            .balance(MinerId(1))
            .fixture("balance")
            .available_sat,
        500_001
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn a_reorg_after_maturity_reverses_the_credits_and_re_credits_when_the_block_returns() {
    let fund = funded(0, 1_000_001);
    fund.chain.set_block(100, hash(0xDD));
    let report = fund
        .ledger
        .reconcile_rounds(&fund.chain)
        .fixture("displaced");
    assert_eq!(report.transitions.len(), 1);
    let transition = report.transitions[0];
    assert_eq!(
        (transition.from, transition.to),
        (RoundState::Matured, RoundState::Orphaned)
    );
    assert_eq!(
        (transition.reversed_sat, transition.deficit_created_sat),
        (1_000_001, 0)
    );
    for account in 1..=3 {
        assert_eq!(
            fund.ledger.balance(MinerId(account)).fixture("balance"),
            Balance::default()
        );
    }
    fund.ledger
        .check_invariants()
        .fixture("invariants after reversal");

    fund.chain.set_block(100, fund.block.share.header_hash);
    let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("returned");
    assert_eq!(report.transitions[0].to, RoundState::Matured);
    assert_eq!(report.transitions[0].credited_sat, 1_000_001);
    assert_eq!(
        fund.ledger
            .balance(MinerId(1))
            .fixture("balance")
            .available_sat,
        500_001
    );
    fund.ledger
        .check_invariants()
        .fixture("invariants after re-credit");
}

#[test]
fn canonical_depth_loss_below_maturity_demotes_to_immature() {
    let fund = funded(0, 1_000_001);
    assert_eq!(
        fund.ledger
            .round_for_block(&fund.block.share.header_hash)
            .fixture("round")
            .fixture("exists")
            .state,
        RoundState::Matured
    );
    fund.chain.set_tip(101);
    let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("shorter tip");
    assert_eq!(report.transitions.len(), 1);
    let transition = report.transitions[0];
    assert_eq!(
        (transition.from, transition.to),
        (RoundState::Matured, RoundState::Immature)
    );
    assert_eq!(
        (transition.reversed_sat, transition.deficit_created_sat),
        (1_000_001, 0)
    );
    for account in 1..=3 {
        assert_eq!(
            fund.ledger.balance(MinerId(account)).fixture("balance"),
            Balance::default(),
            "demoted credits leave nothing payable"
        );
    }
    fund.ledger
        .check_invariants()
        .fixture("invariants after demotion");

    fund.chain.set_tip(102);
    let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("deeper tip");
    assert_eq!(report.transitions.len(), 1);
    assert_eq!(report.transitions[0].from, RoundState::Immature);
    assert_eq!(report.transitions[0].to, RoundState::Matured);
    assert_eq!(report.transitions[0].credited_sat, 1_000_001);
    assert_eq!(
        fund.ledger
            .balance(MinerId(1))
            .fixture("balance")
            .available_sat,
        500_001
    );
    fund.ledger.check_invariants().fixture("invariants after re-mature");
}

#[test]
fn reversing_credits_that_were_already_reserved_creates_an_explicit_deficit() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    assert_eq!(batch.total_sat, 1_000_001);
    fund.chain.set_block(100, hash(0xDD));
    let report = fund
        .ledger
        .reconcile_rounds(&fund.chain)
        .fixture("displaced");
    assert_eq!(report.transitions[0].reversed_sat, 1_000_001);
    assert_eq!(report.transitions[0].deficit_created_sat, 1_000_001);
    let balance = fund.ledger.balance(MinerId(1)).fixture("balance");
    assert_eq!(
        (
            balance.available_sat,
            balance.reserved_sat,
            balance.deficit_sat
        ),
        (0, 500_001, 500_001)
    );
    fund.ledger
        .check_invariants()
        .fixture("deficit keeps the equation balanced");

    fund.chain.set_block(100, fund.block.share.header_hash);
    fund.ledger.reconcile_rounds(&fund.chain).fixture("returned");
    let balance = fund.ledger.balance(MinerId(1)).fixture("balance");
    assert_eq!(
        (
            balance.available_sat,
            balance.reserved_sat,
            balance.deficit_sat
        ),
        (0, 500_001, 0),
        "re-credit first clears the deficit, never double-credits"
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn cancelling_a_batch_of_reversed_credits_repays_the_deficit_first() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    fund.chain.set_block(100, hash(0xDD));
    fund.ledger
        .reconcile_rounds(&fund.chain)
        .fixture("displaced");
    fund.ledger
        .cancel_prepared(&batch.id, CancelBasis::NeverHandedToSigner)
        .fixture("cancel");
    let balance = fund.ledger.balance(MinerId(1)).fixture("balance");
    assert_eq!(
        (
            balance.available_sat,
            balance.reserved_sat,
            balance.deficit_sat
        ),
        (0, 0, 0),
        "a reversed reward never becomes payable again"
    );
    assert_eq!(
        fund.ledger
            .prepare_payout_batch(idem(2), policy())
            .fixture("prepare again"),
        None
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn unseen_rounds_stop_being_monitored_after_the_watch_depth() {
    let fund = staged(0, 1_000_001);
    fund.chain.set_block(100, hash(0xDD));
    fund.chain.set_tip(110);
    let report = fund.ledger.reconcile_rounds(&fund.chain).fixture("settle");
    assert_eq!(report.transitions.len(), 1);
    assert_eq!(report.transitions[0].to, RoundState::Orphaned);
    fund.chain.set_block(100, fund.block.share.header_hash);
    assert_eq!(fund.ledger
            .reconcile_rounds(&fund.chain)
            .fixture("no longer watched")
            .transitions
            , Vec::new());
    assert_eq!(
        fund.ledger.round(1).fixture("round").fixture("exists").state,
        RoundState::Orphaned
    );
}

#[test]
fn a_claim_the_chain_contradicts_is_surfaced_and_never_applied() {
    let fund = staged(0, 1_000_001);
    fund.chain.set_tip(102);
    let mut wrong_txid = coinbase_for(&fund.block, 1_000_001);
    wrong_txid.txid = hash(0x99);
    fund.chain
        .set_coinbase(fund.block.share.header_hash, wrong_txid);
    let report = fund
        .ledger
        .reconcile_rounds(&fund.chain)
        .fixture("reconcile");
    assert_eq!(report.transitions, Vec::new());
    assert_eq!(report.anomalies.len(), 1);
    assert_eq!(report.anomalies[0].round, 1);

    fund.chain.set_coinbase(
        fund.block.share.header_hash,
        coinbase_for(&fund.block, 1_000_000),
    );
    let report = fund
        .ledger
        .reconcile_rounds(&fund.chain)
        .fixture("reconcile");
    assert_eq!(
        report.anomalies.len(),
        1,
        "claimed total differs from the observed total"
    );
    assert_eq!(
        fund.ledger.round(1).fixture("round").fixture("exists").state,
        RoundState::Pending
    );
    assert_eq!(
        fund.ledger.balance(MinerId(1)).fixture("balance"),
        Balance::default()
    );

    fund.chain.set_coinbase(
        fund.block.share.header_hash,
        coinbase_for(&fund.block, 1_000_001),
    );
    let report = fund
        .ledger
        .reconcile_rounds(&fund.chain)
        .fixture("reconcile");
    assert_eq!(report.anomalies, Vec::new());
    assert_eq!(report.transitions[0].to, RoundState::Matured);
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn a_coinbase_that_pays_miners_directly_matures_with_a_zero_pool_reward() {
    let dir = tempfile::tempdir().fixture("tempdir");
    let path = ledger_path(&dir);
    let (ledger, chain, block) = staged_at(&path, 0, 5_000_000, 0);
    chain.set_coinbase(
        block.share.header_hash,
        ObservedCoinbase {
            txid: block.coinbase_txid,
            outputs: vec![TxOut {
                value_sat: 5_000_000,
                script_pubkey: script(0x55),
            }],
        },
    );
    chain.set_tip(102);
    let report = ledger.reconcile_rounds(&chain).fixture("reconcile");
    assert_eq!(report.transitions[0].to, RoundState::Matured);
    assert_eq!(report.transitions[0].credited_sat, 0);
    let round = ledger.round(1).fixture("round").fixture("exists");
    assert_eq!((round.gross_sat, round.net_sat), (0, 0));
    assert!(
        ledger
            .prepare_payout_batch(idem(1), policy())
            .fixture("prepare")
            .is_none()
    );
    ledger.check_invariants().fixture("invariants");
}

#[test]
fn an_unavailable_observer_changes_nothing() {
    let fund = staged(0, 1_000_001);
    fund.chain.set_tip(102);
    let audit_before = fund.ledger.audit_records(0, 100).fixture("audit");
    fund.chain.take_down();
    assert!(matches!(
        fund.ledger.reconcile_rounds(&fund.chain).err(),
        Some(LedgerError::Chain(_))
    ));
    assert_eq!(
        fund.ledger.audit_records(0, 100).fixture("audit"),
        audit_before
    );
    assert_eq!(
        fund.ledger.round(1).fixture("round").fixture("exists").state,
        RoundState::Pending
    );
    fund.chain.bring_up();
    fund.ledger.reconcile_rounds(&fund.chain).fixture("recovers");
    assert_eq!(
        fund.ledger.round(1).fixture("round").fixture("exists").state,
        RoundState::Matured
    );
}


#[test]
fn payout_scripts_are_validated_and_batches_skip_accounts_without_one() {
    let fund = funded(0, 1_000_001);
    assert!(matches!(
        fund.ledger.set_payout_script(MinerId(9), &[]).err(),
        Some(LedgerError::InvalidInput(_))
    ));
    assert!(matches!(
        fund.ledger
            .set_payout_script(MinerId(9), &[0x6a, 0x01, 0x02])
            .err(),
        Some(LedgerError::InvalidInput(_))
    ));
    assert!(matches!(
        fund.ledger
            .set_payout_script(MinerId(9), &vec![0x51; MAX_SCRIPT_LEN + 1])
            .err(),
        Some(LedgerError::InvalidInput(_))
    ));
    assert_eq!(fund.ledger.payout_script(MinerId(9)).fixture("script"), None);
    assert_eq!(
        fund.ledger.payout_script(MinerId(1)).fixture("script"),
        Some(account_script(1))
    );
    fund.ledger
        .set_payout_script(MinerId(1), &account_script(1))
        .fixture("setting the same script is a no-op");
}

#[test]
fn preparing_a_batch_reserves_balances_atomically_and_never_double_allocates() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    assert_eq!(batch.state, BatchState::Prepared);
    assert_eq!(batch.total_sat, 1_000_001);
    assert_eq!(
        batch.outputs,
        vec![
            PayoutOutput {
                account: MinerId(1),
                script_pubkey: account_script(1),
                amount_sat: 500_001
            },
            PayoutOutput {
                account: MinerId(2),
                script_pubkey: account_script(2),
                amount_sat: 300_000
            },
            PayoutOutput {
                account: MinerId(3),
                script_pubkey: account_script(3),
                amount_sat: 200_000
            },
        ]
    );
    assert_eq!(
        batch.id,
        compute_batch_id(&idem(1), &batch.outputs).fixture("id")
    );
    let balance = fund.ledger.balance(MinerId(1)).fixture("balance");
    assert_eq!((balance.available_sat, balance.reserved_sat), (0, 500_001));

    let replay = fund
        .ledger
        .prepare_payout_batch(idem(1), policy())
        .fixture("replay")
        .fixture("same batch");
    assert_eq!(
        replay, batch,
        "same idempotency key returns the immutable batch"
    );
    assert!(
        fund.ledger
            .prepare_payout_batch(idem(2), policy())
            .fixture("second")
            .is_none(),
        "reserved funds are not available to a second batch"
    );
    assert_eq!(
        fund.ledger
            .balance(MinerId(1))
            .fixture("balance")
            .reserved_sat,
        500_001
    );
    assert_eq!(
        fund.ledger
            .batch_for_idempotency_key(&idem(1))
            .fixture("lookup"),
        Some(batch.clone())
    );
    assert_eq!(fund.ledger.active_batches().fixture("active"), vec![batch]);
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn payout_policy_is_bounded_by_dust_and_output_limits() {
    let fund = funded(0, 1_000_001);
    assert!(matches!(
        fund.ledger
            .prepare_payout_batch(
                idem(1),
                PayoutPolicy {
                    min_payout_sat: 545,
                    max_outputs: 10
                }
            )
            .err(),
        Some(LedgerError::InvalidInput(_))
    ));
    assert!(matches!(
        fund.ledger
            .prepare_payout_batch(
                idem(1),
                PayoutPolicy {
                    min_payout_sat: 546,
                    max_outputs: 0
                }
            )
            .err(),
        Some(LedgerError::InvalidInput(_))
    ));
    let small = fund
        .ledger
        .prepare_payout_batch(
            idem(3),
            PayoutPolicy {
                min_payout_sat: 546,
                max_outputs: 2,
            },
        )
        .fixture("prepare")
        .fixture("batch");
    assert_eq!(
        small.outputs.len(),
        2,
        "lowest accounts first, capped at max_outputs"
    );
    assert_eq!(
        fund.ledger
            .balance(MinerId(3))
            .fixture("balance")
            .available_sat,
        200_000
    );
    let high = fund
        .ledger
        .prepare_payout_batch(
            idem(4),
            PayoutPolicy {
                min_payout_sat: 250_000,
                max_outputs: 10,
            },
        )
        .fixture("prepare");
    assert!(
        high.is_none(),
        "account 3 holds 200000 < 250000 and the others are reserved"
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn a_payout_walks_prepared_signed_broadcast_confirmed_with_exact_accounting() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], Some(50_000));

    let signed = fund
        .ledger
        .record_signed(&receipt(&batch, &tx))
        .fixture("signed");
    assert_eq!(signed.state, BatchState::ExternallySigned);
    assert_eq!(signed.transactions.len(), 1);
    assert_eq!(signed.transactions[0].txid, tx.txid);
    let replay = fund
        .ledger
        .record_signed(&receipt(&batch, &tx))
        .fixture("replay");
    assert_eq!(replay, signed, "duplicate receipt changes nothing");

    assert!(matches!(
        fund.ledger
            .record_broadcast(&batch.id, &tx.txid, &fund.chain)
            .err(),
        Some(LedgerError::NotObserved(_))
    ));
    fund.chain.set_tx(tx.txid, TxStatus::InMempool);
    let broadcast = fund
        .ledger
        .record_broadcast(&batch.id, &tx.txid, &fund.chain)
        .fixture("broadcast");
    assert_eq!(broadcast.state, BatchState::Broadcast);
    assert_eq!(broadcast.broadcast_txid, Some(tx.txid));
    assert_eq!(
        fund.ledger
            .record_broadcast(&batch.id, &tx.txid, &fund.chain)
            .fixture("replay"),
        broadcast
    );
    assert_eq!(fund.ledger
            .reconcile_payouts(&fund.chain)
            .fixture("mempool only")
            , Vec::new());

    confirm_tx(&fund, tx.txid, 0xB1, 102, 102);
    assert_eq!(fund.ledger
            .reconcile_payouts(&fund.chain)
            .fixture("one confirmation")
            , Vec::new(),
        "payout_confirmations is 2"
    );
    assert_eq!(
        fund.ledger.balance(MinerId(1)).fixture("balance").paid_sat,
        0
    );

    fund.chain.set_tip(103);
    let transitions = fund
        .ledger
        .reconcile_payouts(&fund.chain)
        .fixture("two confirmations");
    assert_eq!(
        transitions,
        vec![BatchTransition {
            batch_id: batch.id,
            from: BatchState::Broadcast,
            to: BatchState::Confirmed
        }]
    );
    assert_confirmed_accounting(&fund, &batch, &tx);
}

fn assert_confirmed_accounting(fund: &Fund, batch: &PayoutBatch, tx: &BuiltTx) {
    let confirmed = fund
        .ledger
        .batch(&batch.id)
        .fixture("batch")
        .fixture("exists");
    assert_eq!(
        confirmed.confirmation,
        Some(Confirmation {
            txid: tx.txid,
            block_hash: hash(0xB1),
            height: 102,
        })
    );
    for (account, paid) in [(1u64, 500_001u64), (2, 300_000), (3, 200_000)] {
        let balance = fund.ledger.balance(MinerId(account)).fixture("balance");
        assert_eq!(
            (
                balance.available_sat,
                balance.reserved_sat,
                balance.paid_sat,
            ),
            (0, 0, paid)
        );
    }
    let invariants = fund.ledger.check_invariants().fixture("invariants");
    assert_eq!(
        (invariants.paid_sat, invariants.reserved_sat),
        (1_000_001, 0)
    );
    assert_eq!(
        fund.ledger.reconcile_payouts(&fund.chain).fixture("again"),
        Vec::new()
    );
    assert!(matches!(
        fund.ledger.request_for(&batch.id).err(),
        Some(LedgerError::IllegalTransition { .. })
    ));
    assert!(matches!(
        fund.ledger
            .cancel_prepared(&batch.id, CancelBasis::NeverHandedToSigner)
            .err(),
        Some(LedgerError::IllegalTransition { .. })
    ));
}

fn assert_invalid_receipts(
    fund: &Fund,
    batch: &PayoutBatch,
    input: &[OutPoint],
    paid: &[(u64, Vec<u8>)],
) {
    let mut short_amount = paid.to_vec();
    short_amount[0].0 -= 1;
    let tx = build_tx(input, &short_amount, Witness::Items);
    assert!(matches!(
        fund.ledger.record_signed(&receipt(batch, &tx)).err(),
        Some(LedgerError::Receipt(ReceiptError::MissingOutput { index: 0 }))
    ));
    let tx = build_tx(input, &paid[..2], Witness::Items);
    assert!(matches!(
        fund.ledger.record_signed(&receipt(batch, &tx)).err(),
        Some(LedgerError::Receipt(ReceiptError::MissingOutput { index: 2 }))
    ));
    let mut stray = paid.to_vec();
    stray.push((10_000, script(0x77)));
    let tx = build_tx(input, &stray, Witness::Items);
    assert!(matches!(
        fund.ledger.record_signed(&receipt(batch, &tx)).err(),
        Some(LedgerError::Receipt(ReceiptError::UnexpectedOutput { index: 3 }))
    ));
    let mut two_change = paid.to_vec();
    two_change.push((10_000, change_script()));
    two_change.push((10_001, change_script()));
    let tx = build_tx(input, &two_change, Witness::Items);
    assert!(matches!(
        fund.ledger.record_signed(&receipt(batch, &tx)).err(),
        Some(LedgerError::Receipt(ReceiptError::TooManyExtraOutputs))
    ));
    let tx = build_tx(input, paid, Witness::Items);
    let mut wrong_txid = receipt(batch, &tx);
    wrong_txid.txid = hash(0x99);
    assert!(matches!(
        fund.ledger.record_signed(&wrong_txid).err(),
        Some(LedgerError::Receipt(ReceiptError::TxidMismatch))
    ));
    let tx = build_tx(
        &[OutPoint {
            txid: [0; 32],
            vout: u32::MAX,
        }],
        paid,
        Witness::Items,
    );
    assert!(matches!(
        fund.ledger.record_signed(&receipt(batch, &tx)).err(),
        Some(LedgerError::Receipt(ReceiptError::NullPrevout))
    ));
    let tx = build_tx(&[outpoint(1, 0), outpoint(1, 0)], paid, Witness::Items);
    assert!(matches!(
        fund.ledger.record_signed(&receipt(batch, &tx)).err(),
        Some(LedgerError::Receipt(ReceiptError::DuplicateInput))
    ));
    let garbage = PayoutReceipt {
        batch_id: batch.id,
        txid: hash(1),
        raw_tx: vec![1, 2, 3],
    };
    assert!(matches!(
        fund.ledger.record_signed(&garbage).err(),
        Some(LedgerError::Receipt(ReceiptError::Parse(_)))
    ));
    let unknown = PayoutReceipt {
        batch_id: hash(0x42),
        txid: tx.txid,
        raw_tx: tx.raw,
    };
    assert!(matches!(
        fund.ledger.record_signed(&unknown).err(),
        Some(LedgerError::UnknownBatch(_))
    ));
}

#[test]
fn a_signed_transaction_must_pay_exactly_the_batch_and_prove_its_own_txid() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let input = [outpoint(0xA1, 0)];
    let paid: Vec<(u64, Vec<u8>)> = batch
        .outputs
        .iter()
        .map(|output| (output.amount_sat, output.script_pubkey.clone()))
        .collect();

    assert_invalid_receipts(&fund, &batch, &input, &paid);

    assert_eq!(
        fund.ledger
            .batch(&batch.id)
            .fixture("batch")
            .fixture("exists")
            .state,
        BatchState::Prepared,
        "every refusal left the batch untouched"
    );
    let good = build_tx(&input, &paid, Witness::Items);
    assert_eq!(
        fund.ledger
            .record_signed(&receipt(&batch, &good))
            .fixture("exact payment")
            .state,
        BatchState::ExternallySigned
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn replacements_must_conflict_with_every_earlier_signed_transaction() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let first = pay_tx(
        &batch,
        &[outpoint(0xA1, 0), outpoint(0xA2, 0)],
        Some(40_000),
    );
    fund.ledger
        .record_signed(&receipt(&batch, &first))
        .fixture("first");
    let disjoint = pay_tx(&batch, &[outpoint(0xA3, 0)], Some(40_000));
    assert!(matches!(
        fund.ledger.record_signed(&receipt(&batch, &disjoint)).err(),
        Some(LedgerError::Receipt(ReceiptError::NotConflicting { existing_txid })) if existing_txid == first.txid
    ));
    let replacement = pay_tx(
        &batch,
        &[outpoint(0xA2, 0), outpoint(0xA4, 0)],
        Some(30_000),
    );
    let batch_now = fund
        .ledger
        .record_signed(&receipt(&batch, &replacement))
        .fixture("replacement");
    assert_eq!(batch_now.transactions.len(), 2);
    assert_eq!(batch_now.state, BatchState::ExternallySigned);

    fund.chain.set_tx(replacement.txid, TxStatus::InMempool);
    fund.ledger
        .record_broadcast(&batch.id, &replacement.txid, &fund.chain)
        .fixture("broadcast replacement");
    confirm_tx(&fund, replacement.txid, 0xB2, 102, 103);
    fund.ledger.reconcile_payouts(&fund.chain).fixture("confirm");
    let confirmed = fund
        .ledger
        .batch(&batch.id)
        .fixture("batch")
        .fixture("exists");
    assert_eq!(confirmed.state, BatchState::Confirmed);
    assert_eq!(
        confirmed.confirmation.fixture("confirmation").txid,
        replacement.txid
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn a_reorged_out_confirmation_reverts_the_payout_and_a_new_block_reconfirms_it() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], None);
    fund.ledger
        .record_signed(&receipt(&batch, &tx))
        .fixture("signed");
    confirm_tx(&fund, tx.txid, 0xB1, 102, 103);
    fund.ledger.reconcile_payouts(&fund.chain).fixture("confirm");
    assert_eq!(
        fund.ledger.balance(MinerId(1)).fixture("balance").paid_sat,
        500_001
    );

    fund.chain.set_block(102, hash(0xB9));
    fund.chain.set_tx(tx.txid, TxStatus::InMempool);
    let transitions = fund.ledger.reconcile_payouts(&fund.chain).fixture("reorg");
    assert_eq!(
        transitions,
        vec![BatchTransition {
            batch_id: batch.id,
            from: BatchState::Confirmed,
            to: BatchState::Broadcast
        }]
    );
    let balance = fund.ledger.balance(MinerId(1)).fixture("balance");
    assert_eq!((balance.reserved_sat, balance.paid_sat), (500_001, 0));
    assert!(
        fund.ledger
            .batch(&batch.id)
            .fixture("batch")
            .fixture("exists")
            .confirmation
            .is_none()
    );
    fund.ledger
        .check_invariants()
        .fixture("invariants while reverted");

    confirm_tx(&fund, tx.txid, 0xB3, 103, 104);
    let transitions = fund
        .ledger
        .reconcile_payouts(&fund.chain)
        .fixture("reconfirm");
    assert_eq!(transitions[0].to, BatchState::Confirmed);
    assert_eq!(
        fund.ledger.balance(MinerId(1)).fixture("balance").paid_sat,
        500_001
    );

    confirm_tx(&fund, tx.txid, 0xB4, 104, 105);
    let transitions = fund
        .ledger
        .reconcile_payouts(&fund.chain)
        .fixture("moved block");
    assert_eq!(
        (transitions[0].from, transitions[0].to),
        (BatchState::Confirmed, BatchState::Confirmed),
        "the same payment confirmed in a different block moves the record, not the money"
    );
    assert_eq!(
        fund.ledger
            .batch(&batch.id)
            .fixture("batch")
            .fixture("exists")
            .confirmation
            .fixture("c")
            .height,
        104
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn a_batch_fails_only_when_every_signed_transaction_is_conclusively_double_spent() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let first = pay_tx(
        &batch,
        &[outpoint(0xA1, 0), outpoint(0xA2, 0)],
        Some(40_000),
    );
    let second = pay_tx(
        &batch,
        &[outpoint(0xA2, 0), outpoint(0xA3, 0)],
        Some(30_000),
    );
    fund.ledger
        .record_signed(&receipt(&batch, &first))
        .fixture("first");
    fund.ledger
        .record_signed(&receipt(&batch, &second))
        .fixture("second");

    let thief = hash(0xEE);
    fund.chain.set_block(104, hash(0xC1));
    fund.chain.set_spend(
        outpoint(0xA1, 0),
        ConfirmedSpend {
            spender_txid: thief,
            block_hash: hash(0xC1),
            height: 104,
        },
    );
    fund.chain.set_tip(105);
    assert_eq!(fund.ledger
            .reconcile_payouts(&fund.chain)
            .fixture("one dead")
            , Vec::new(),
        "only the first transaction lost an input"
    );
    fund.chain.set_spend(
        outpoint(0xA3, 0),
        ConfirmedSpend {
            spender_txid: thief,
            block_hash: hash(0xC1),
            height: 104,
        },
    );
    fund.chain.set_tip(104);
    assert_eq!(fund.ledger
            .reconcile_payouts(&fund.chain)
            .fixture("too shallow")
            , Vec::new(),
        "depth 1 is below abandon_confirmations"
    );
    fund.chain.set_tip(105);
    let transitions = fund
        .ledger
        .reconcile_payouts(&fund.chain)
        .fixture("both dead");
    assert_eq!(
        transitions,
        vec![BatchTransition {
            batch_id: batch.id,
            from: BatchState::ExternallySigned,
            to: BatchState::Failed
        }]
    );
    let failed = fund
        .ledger
        .batch(&batch.id)
        .fixture("batch")
        .fixture("exists");
    assert_eq!(
        failed.closure,
        Some(Closure::Failed {
            conflicting_txid: thief
        })
    );
    let balance = fund.ledger.balance(MinerId(1)).fixture("balance");
    assert_eq!((balance.available_sat, balance.reserved_sat), (500_001, 0));
    assert_eq!(fund.ledger.active_batches().fixture("active"), Vec::new());
    fund.ledger.check_invariants().fixture("invariants");

    let retry = fund
        .ledger
        .prepare_payout_batch(idem(2), policy())
        .fixture("retry")
        .fixture("a fresh batch");
    assert_ne!(retry.id, batch.id);
    assert_eq!(retry.outputs, batch.outputs);
    assert!(
        matches!(
            fund.ledger.record_signed(&receipt(&retry, &first)).err(),
            Some(LedgerError::Receipt(ReceiptError::TxidInOtherBatch))
        ),
        "a stale transaction of the failed batch can never be attached to its replacement"
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn a_mid_reconcile_chain_transition_defers_a_permanent_fail() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let first = pay_tx(
        &batch,
        &[outpoint(0xA1, 0), outpoint(0xA2, 0)],
        Some(40_000),
    );
    let second = pay_tx(
        &batch,
        &[outpoint(0xA2, 0), outpoint(0xA3, 0)],
        Some(30_000),
    );
    fund.ledger
        .record_signed(&receipt(&batch, &first))
        .fixture("first");
    fund.ledger
        .record_signed(&receipt(&batch, &second))
        .fixture("second");
    let thief = hash(0xEE);
    fund.chain.set_block(104, hash(0xC1));
    for outpoint in [outpoint(0xA1, 0), outpoint(0xA3, 0)] {
        fund.chain.set_spend(
            outpoint,
            ConfirmedSpend {
                spender_txid: thief,
                block_hash: hash(0xC1),
                height: 104,
            },
        );
    }
    fund.chain.set_tip(105);
    assert_eq!(
        fund.ledger
            .reconcile_payouts_checked(&fund.chain, &|| true)
            .fixture("deferred"),
        Vec::new()
    );
    let still = fund.ledger.batch(&batch.id).fixture("batch").fixture("exists");
    assert_eq!(still.state, BatchState::ExternallySigned);
    let transitions = fund
        .ledger
        .reconcile_payouts_checked(&fund.chain, &|| false)
        .fixture("failed");
    assert_eq!(
        transitions,
        vec![BatchTransition {
            batch_id: batch.id,
            from: BatchState::ExternallySigned,
            to: BatchState::Failed
        }]
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn cancelling_a_prepared_batch_releases_the_reservation_but_never_after_signing() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let cancelled = fund
        .ledger
        .cancel_prepared(&batch.id, CancelBasis::NeverHandedToSigner)
        .fixture("cancel");
    assert_eq!(cancelled.state, BatchState::Cancelled);
    assert_eq!(
        cancelled.closure,
        Some(Closure::Cancelled(CancelBasis::NeverHandedToSigner))
    );
    let balance = fund.ledger.balance(MinerId(1)).fixture("balance");
    assert_eq!((balance.available_sat, balance.reserved_sat), (500_001, 0));
    assert_eq!(
        fund.ledger
            .cancel_prepared(&batch.id, CancelBasis::NeverHandedToSigner)
            .fixture("idempotent"),
        cancelled
    );
    assert!(matches!(
        fund.ledger
            .cancel_prepared(&batch.id, CancelBasis::SignerRevoked)
            .err(),
        Some(LedgerError::IllegalTransition { .. })
    ));
    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], None);
    assert!(matches!(
        fund.ledger.record_signed(&receipt(&batch, &tx)).err(),
        Some(LedgerError::IllegalTransition { .. })
    ));
    fund.ledger.check_invariants().fixture("invariants");

    let second = fund
        .ledger
        .prepare_payout_batch(idem(2), policy())
        .fixture("prepare")
        .fixture("batch");
    let tx = pay_tx(&second, &[outpoint(0xA1, 1)], None);
    fund.ledger
        .record_signed(&receipt(&second, &tx))
        .fixture("signed");
    assert!(matches!(
        fund.ledger
            .cancel_prepared(&second.id, CancelBasis::SignerRevoked)
            .err(),
        Some(LedgerError::IllegalTransition { .. })
    ));
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn the_external_signer_seam_signs_the_canonical_request_and_failures_change_nothing() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let refuser = TestSigner {
        inputs: vec![outpoint(0xA1, 0)],
        refuse: true,
    };
    assert!(matches!(
        fund.ledger.sign_via(&batch.id, &refuser).err(),
        Some(LedgerError::Signer(_))
    ));
    assert_eq!(
        fund.ledger
            .batch(&batch.id)
            .fixture("batch")
            .fixture("exists")
            .state,
        BatchState::Prepared
    );
    let signer = TestSigner {
        inputs: vec![outpoint(0xA1, 0)],
        refuse: false,
    };
    let signed = fund.ledger.sign_via(&batch.id, &signer).fixture("signed");
    assert_eq!(signed.state, BatchState::ExternallySigned);
    fund.ledger.check_invariants().fixture("invariants");
}


#[test]
fn state_survives_a_restart_byte_for_byte() {
    let fund = funded(250, 1_000_001);
    let batch = prepared(&fund);
    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], Some(1_000));
    fund.ledger
        .record_signed(&receipt(&batch, &tx))
        .fixture("signed");
    let balances: Vec<Balance> = (1..=3)
        .map(|account| fund.ledger.balance(MinerId(account)).fixture("balance"))
        .collect();
    let audit = fund.ledger.audit_records(0, 1_000).fixture("audit");
    let round = fund.ledger.round(1).fixture("round");
    let window = fund.ledger.current_window().fixture("window");
    let path = fund.path.clone();
    let Fund { ledger, _dir: retained_dir, .. } = fund;
    drop(ledger);

    let reopened = open(&path, config(100, 250)).fixture("reopen");
    let after: Vec<Balance> = (1..=3)
        .map(|account| reopened.balance(MinerId(account)).fixture("balance"))
        .collect();
    assert_eq!(after, balances);
    assert_eq!(reopened.audit_records(0, 1_000).fixture("audit"), audit);
    assert_eq!(reopened.round(1).fixture("round"), round);
    assert_eq!(reopened.current_window().fixture("window"), window);
    let again = reopened.batch(&batch.id).fixture("batch").fixture("exists");
    assert_eq!(again.state, BatchState::ExternallySigned);
    assert_eq!(again.transactions[0].txid, tx.txid);
    assert_eq!(
        reopened
            .record_signed(&receipt(&batch, &tx))
            .fixture("replay after restart"),
        again
    );
    reopened.check_invariants().fixture("invariants");
    drop(retained_dir);
}

fn snapshot(ledger: &Ledger) -> (Vec<Balance>, Vec<AuditRecord>, u64, usize) {
    let balances = (1..=3)
        .map(|account| ledger.balance(MinerId(account)).fixture("balance"))
        .collect();
    let audit = ledger.audit_records(0, 10_000).fixture("audit");
    let shares = ledger.share_count().fixture("count");
    let batches = ledger.active_batches().fixture("batches").len();
    (balances, audit, shares, batches)
}

fn fail(op: &'static str, point: FailPoint) -> FailPlan {
    FailPlan {
        op,
        point,
        action: FailAction::ReturnError,
    }
}

fn prepare_after_interrupted_operations() -> (Fund, PayoutBatch) {
    let (_dir, ledger) = plain_ledger(100);
    let one = share(1, 1, 1, 10);
    ledger.arm_fail_plan(fail(OP_RECORD_SHARE, FailPoint::BeforeCommit));
    assert!(matches!(
        ledger.record_share(&one).err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(ledger.share_count().fixture("count"), 0);
    assert_eq!(ledger.share_by_hash(&one.header_hash).fixture("lookup"), None);
    assert_eq!(
        ledger.record_share(&one).fixture("retry"),
        ShareReceipt::Credited { seq: 0 }
    );

    let fund = staged(0, 1_000_001);
    let before = snapshot(&fund.ledger);
    let other = found(share(1, 3, 2, 20), 101, 1_000);
    fund.ledger
        .arm_fail_plan(fail(OP_RECORD_BLOCK, FailPoint::BeforeCommit));
    assert!(matches!(
        fund.ledger.record_found_block(&other).err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(snapshot(&fund.ledger), before);
    assert!(
        fund.ledger
            .round_for_block(&other.share.header_hash)
            .fixture("round")
            .is_none()
    );
    assert!(
        fund.ledger
            .record_found_block(&other)
            .fixture("retry")
            .newly_recorded
    );

    fund.chain.set_tip(102);
    let before = snapshot(&fund.ledger);
    fund.ledger
        .arm_fail_plan(fail(OP_RECONCILE_ROUNDS, FailPoint::BeforeCommit));
    assert!(matches!(
        fund.ledger.reconcile_rounds(&fund.chain).err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(snapshot(&fund.ledger), before);
    assert_eq!(
        fund.ledger
            .reconcile_rounds(&fund.chain)
            .fixture("retry")
            .transitions
            .len(),
        1
    );
    fund.ledger.check_invariants().fixture("invariants");

    let before = snapshot(&fund.ledger);
    fund.ledger
        .arm_fail_plan(fail(OP_PREPARE_PAYOUT, FailPoint::BeforeCommit));
    assert!(matches!(
        fund.ledger.prepare_payout_batch(idem(1), policy()).err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(snapshot(&fund.ledger), before);
    assert_eq!(
        fund.ledger
            .balance(MinerId(1))
            .fixture("balance")
            .reserved_sat,
        0
    );
    let batch = prepared(&fund);
    (fund, batch)
}

#[test]
fn an_interrupted_commit_loses_the_whole_operation_and_the_retry_succeeds() {
    let (fund, batch) = prepare_after_interrupted_operations();

    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], None);
    let before = snapshot(&fund.ledger);
    fund.ledger
        .arm_fail_plan(fail(OP_RECORD_SIGNED, FailPoint::BeforeCommit));
    assert!(matches!(
        fund.ledger.record_signed(&receipt(&batch, &tx)).err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(snapshot(&fund.ledger), before);
    fund.ledger
        .record_signed(&receipt(&batch, &tx))
        .fixture("retry");

    fund.chain.set_tx(tx.txid, TxStatus::InMempool);
    fund.ledger
        .arm_fail_plan(fail(OP_RECORD_BROADCAST, FailPoint::BeforeCommit));
    assert!(matches!(
        fund.ledger
            .record_broadcast(&batch.id, &tx.txid, &fund.chain)
            .err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(
        fund.ledger
            .batch(&batch.id)
            .fixture("batch")
            .fixture("exists")
            .state,
        BatchState::ExternallySigned
    );
    fund.ledger
        .record_broadcast(&batch.id, &tx.txid, &fund.chain)
        .fixture("retry");

    confirm_tx(&fund, tx.txid, 0xB1, 102, 103);
    let before = snapshot(&fund.ledger);
    fund.ledger
        .arm_fail_plan(fail(OP_RECONCILE_PAYOUTS, FailPoint::BeforeCommit));
    assert!(matches!(
        fund.ledger.reconcile_payouts(&fund.chain).err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(snapshot(&fund.ledger), before);
    assert_eq!(
        fund.ledger.balance(MinerId(1)).fixture("balance").paid_sat,
        0
    );
    assert_eq!(
        fund.ledger
            .reconcile_payouts(&fund.chain)
            .fixture("retry")
            .len(),
        1
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn a_commit_whose_reply_was_lost_is_durable_and_the_replay_changes_nothing() {
    let fund = funded(0, 1_000_001);
    fund.ledger
        .arm_fail_plan(fail(OP_PREPARE_PAYOUT, FailPoint::AfterCommit));
    assert!(matches!(
        fund.ledger.prepare_payout_batch(idem(1), policy()).err(),
        Some(LedgerError::Injected(_))
    ));
    let batch = fund
        .ledger
        .batch_for_idempotency_key(&idem(1))
        .fixture("lookup")
        .fixture("the batch committed");
    let replay = prepared(&fund);
    assert_eq!(replay, batch);
    assert_eq!(
        fund.ledger
            .balance(MinerId(1))
            .fixture("balance")
            .reserved_sat,
        500_001,
        "no double reservation"
    );

    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], None);
    fund.ledger
        .arm_fail_plan(fail(OP_RECORD_SIGNED, FailPoint::AfterCommit));
    assert!(matches!(
        fund.ledger.record_signed(&receipt(&batch, &tx)).err(),
        Some(LedgerError::Injected(_))
    ));
    let signed = fund
        .ledger
        .record_signed(&receipt(&batch, &tx))
        .fixture("replay");
    assert_eq!(signed.transactions.len(), 1);

    confirm_tx(&fund, tx.txid, 0xB1, 102, 103);
    fund.ledger
        .arm_fail_plan(fail(OP_RECONCILE_PAYOUTS, FailPoint::AfterCommit));
    assert!(matches!(
        fund.ledger.reconcile_payouts(&fund.chain).err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(
        fund.ledger
            .batch(&batch.id)
            .fixture("batch")
            .fixture("exists")
            .state,
        BatchState::Confirmed
    );
    assert_eq!(fund.ledger
            .reconcile_payouts(&fund.chain)
            .fixture("replay")
            , Vec::new());
    assert_eq!(
        fund.ledger.balance(MinerId(1)).fixture("balance").paid_sat,
        500_001,
        "paid exactly once"
    );

    let (_dir, ledger) = plain_ledger(100);
    let one = share(1, 1, 1, 10);
    ledger.arm_fail_plan(fail(OP_RECORD_SHARE, FailPoint::AfterCommit));
    assert!(matches!(
        ledger.record_share(&one).err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(
        ledger.record_share(&one).fixture("replay"),
        ShareReceipt::Duplicate { seq: 0 }
    );
    assert_eq!(ledger.share_count().fixture("count"), 1);
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn a_fail_plan_fires_once_and_only_for_its_operation() {
    let (_dir, ledger) = plain_ledger(100);
    ledger.arm_fail_plan(fail(OP_RETIRE_JOB, FailPoint::BeforeCommit));
    ledger
        .record_share(&share(1, 1, 1, 10))
        .fixture("other operations are unaffected");
    assert!(matches!(
        ledger.retire_job(1).err(),
        Some(LedgerError::Injected(_))
    ));
    assert_eq!(ledger.retire_job(1).fixture("fires once"), 1);
    ledger.arm_fail_plan(fail(OP_RECORD_SHARE, FailPoint::BeforeCommit));
    ledger.disarm_fail_plan();
    ledger.record_share(&share(2, 1, 1, 10)).fixture("disarmed");
}

#[cfg(unix)]
mod process_death {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, ExitStatus, Stdio};

    const SIGABRT: i32 = 6;

    fn run_child(dir: &Path, mode: &str) -> ExitStatus {
        let exe = std::env::current_exe().fixture("test binary path");
        Command::new(exe)
            .arg(format!("{BACKEND}::process_death::crash_child_entry"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("POOL_CRASH_DIR", dir)
            .env("POOL_CRASH_MODE", mode)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .fixture("spawn the child test binary")
    }

    fn crash_chain(txid: Hash32) -> FakeChain {
        let chain = FakeChain::default();
        chain.set_block(102, hash(0xB1));
        chain.set_tx(
            txid,
            TxStatus::Confirmed {
                block_hash: hash(0xB1),
                height: 102,
            },
        );
        chain.set_tip(103);
        chain
    }

    #[test]
    fn crash_child_entry() {
        let Ok(dir) = std::env::var("POOL_CRASH_DIR") else {
            return;
        };
        let mode = std::env::var("POOL_CRASH_MODE").unwrap_or_default();
        let ledger =
            open(PathBuf::from(dir).join("pool.redb"), config(100, 0)).fixture("open");
        let abort = |op: &'static str, point: FailPoint| FailPlan {
            op,
            point,
            action: FailAction::AbortProcess,
        };
        match mode.as_str() {
            "prepare_before_commit" => {
                ledger.arm_fail_plan(abort(OP_PREPARE_PAYOUT, FailPoint::BeforeCommit));
                let _ = ledger.prepare_payout_batch(idem(1), policy());
            }
            "prepare_after_commit" => {
                ledger.arm_fail_plan(abort(OP_PREPARE_PAYOUT, FailPoint::AfterCommit));
                let _ = ledger.prepare_payout_batch(idem(1), policy());
            }
            "reconcile_after_commit" => {
                let batch = ledger
                    .batch_for_idempotency_key(&idem(1))
                    .fixture("lookup")
                    .fixture("seeded batch");
                let chain = crash_chain(batch.transactions[0].txid);
                ledger.arm_fail_plan(abort(OP_RECONCILE_PAYOUTS, FailPoint::AfterCommit));
                let _ = ledger.reconcile_payouts(&chain);
            }
            other => panic!("unknown crash mode {other}"),
        }
        std::process::exit(3);
    }

    fn seed(path: &Path) {
        let (ledger, chain, _block) = staged_at(path, 0, 1_000_001, 1_000_001);
        chain.set_tip(102);
        ledger.reconcile_rounds(&chain).fixture("mature");
    }

    #[test]
    fn process_death_before_commit_leaves_the_ledger_exactly_as_it_was() {
        let dir = tempfile::tempdir().fixture("tempdir");
        let path = ledger_path(&dir);
        seed(&path);
        let status = run_child(dir.path(), "prepare_before_commit");
        assert_eq!(
            status.signal(),
            Some(SIGABRT),
            "the child died by SIGABRT mid-operation"
        );

        let ledger = open(&path, config(100, 0)).fixture("recovers after the unclean exit");
        assert!(
            ledger
                .batch_for_idempotency_key(&idem(1))
                .fixture("lookup")
                .is_none()
        );
        assert_eq!(ledger.active_batches().fixture("active"), Vec::new());
        let balance = ledger.balance(MinerId(1)).fixture("balance");
        assert_eq!((balance.available_sat, balance.reserved_sat), (500_001, 0));
        ledger
            .check_invariants()
            .fixture("invariants after the crash");
        let batch = ledger
            .prepare_payout_batch(idem(1), policy())
            .fixture("retry")
            .fixture("batch");
        assert_eq!(batch.total_sat, 1_000_001);
        ledger
            .check_invariants()
            .fixture("invariants after the retry");
    }

    #[test]
    fn process_death_after_commit_keeps_the_batch_and_the_retry_never_double_reserves() {
        let dir = tempfile::tempdir().fixture("tempdir");
        let path = ledger_path(&dir);
        seed(&path);
        let status = run_child(dir.path(), "prepare_after_commit");
        assert_eq!(status.signal(), Some(SIGABRT));

        let ledger = open(&path, config(100, 0)).fixture("recovers");
        let batch = ledger
            .batch_for_idempotency_key(&idem(1))
            .fixture("lookup")
            .fixture("the commit was durable");
        assert_eq!(batch.state, BatchState::Prepared);
        let balance = ledger.balance(MinerId(1)).fixture("balance");
        assert_eq!((balance.available_sat, balance.reserved_sat), (0, 500_001));
        let replay = ledger
            .prepare_payout_batch(idem(1), policy())
            .fixture("replay")
            .fixture("same batch");
        assert_eq!(replay, batch);
        assert_eq!(
            ledger.balance(MinerId(1)).fixture("balance").reserved_sat,
            500_001
        );
        ledger.check_invariants().fixture("invariants");
    }

    #[test]
    fn process_death_after_a_confirmation_commit_pays_exactly_once() {
        let dir = tempfile::tempdir().fixture("tempdir");
        let path = ledger_path(&dir);
        let txid = {
            let (ledger, chain, _block) = staged_at(&path, 0, 1_000_001, 1_000_001);
            chain.set_tip(102);
            ledger.reconcile_rounds(&chain).fixture("mature");
            let batch = ledger
                .prepare_payout_batch(idem(1), policy())
                .fixture("prepare")
                .fixture("batch");
            let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], Some(1_000));
            ledger.record_signed(&receipt(&batch, &tx)).fixture("signed");
            tx.txid
        };
        let status = run_child(dir.path(), "reconcile_after_commit");
        assert_eq!(status.signal(), Some(SIGABRT));

        let ledger = open(&path, config(100, 0)).fixture("recovers");
        let batch = ledger
            .batch_for_idempotency_key(&idem(1))
            .fixture("lookup")
            .fixture("batch");
        assert_eq!(
            batch.state,
            BatchState::Confirmed,
            "the confirmation commit was durable"
        );
        let chain = crash_chain(txid);
        assert_eq!(ledger.reconcile_payouts(&chain).fixture("replay"), Vec::new());
        let balance = ledger.balance(MinerId(1)).fixture("balance");
        assert_eq!((balance.reserved_sat, balance.paid_sat), (0, 500_001));
        let invariants = ledger.check_invariants().fixture("invariants");
        assert_eq!(invariants.paid_sat, 1_000_001);
    }
}


#[test]
fn the_audit_chain_is_deterministic_and_detects_tampering() {
    let first = funded(0, 1_000_001);
    let second = funded(0, 1_000_001);
    let chain_of = |fund: &Fund| -> Vec<(AuditKind, u64, Hash32)> {
        fund.ledger
            .audit_records(0, 1_000)
            .fixture("audit")
            .into_iter()
            .map(|record| (record.kind, record.subject, record.chain))
            .collect()
    };
    assert_eq!(
        chain_of(&first),
        chain_of(&second),
        "same inputs give the same hash chain"
    );
    let records = first.ledger.audit_records(0, 1_000).fixture("audit");
    assert!(
        records
            .iter()
            .any(|record| record.kind == AuditKind::RoundRecorded)
    );
    assert!(
        records
            .iter()
            .any(|record| record.kind == AuditKind::RewardFixed)
    );
    assert!(
        records
            .iter()
            .any(|record| record.kind == AuditKind::RoundMatured)
    );
    assert!(
        records
            .iter()
            .any(|record| record.kind == AuditKind::PayoutScriptSet)
    );
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record.seq, u64::try_from(index).fixture("small"));
    }
    assert_eq!(
        first.ledger.audit_records(2, 1).fixture("page").len(),
        1,
        "audit records page by sequence"
    );
    assert_eq!(
        first.ledger.verify_audit_chain().fixture("verify"),
        u64::try_from(records.len()).fixture("small")
    );

    let path = first.path.clone();
    let Fund { ledger, _dir: retained_dir, .. } = first;
    drop(ledger);
    {
        let db = backend(&path);
        let mut key = b"pool-ledger/v1/".to_vec();
        key.push(18);
        key.extend_from_slice(&1u64.to_be_bytes());
        let mut bytes = db.get(ColumnFamily::PoolLedger, &key).fixture("get").fixture("record 1");
        bytes[9] ^= 0xff;
        let mut batch = db.new_batch();
        batch.put(ColumnFamily::PoolLedger, &key, &bytes);
        db.write_durable(batch).fixture("tamper");
    }
    let tampered = open(&path, config(100, 0)).fixture("reopens");
    assert!(matches!(
        tampered.verify_audit_chain().err(),
        Some(LedgerError::Invariant(_))
    ));
    assert!(matches!(
        tampered.check_invariants().err(),
        Some(LedgerError::Invariant(_))
    ));
    drop(tampered);
    drop(retained_dir);
}

#[test]
fn bounded_reconcile_units_are_bounded_and_generation_guarded() {
    let fund = staged(0, 1_000_001);
    let second = found(share(1, 4, 1, 20), 101, 1_000_001);
    fund.ledger.record_found_block(&second).fixture("second block");
    fund.chain.set_block(101, second.share.header_hash);
    fund.chain
        .set_coinbase(second.share.header_hash, coinbase_for(&second, 1_000_001));
    let (empty, more_empty, _) = fund
        .ledger
        .reconcile_rounds_checked_limit(&fund.chain, &|| false, 0, None)
        .fixture("rounds limit 0");
    assert!(empty.transitions.is_empty() && empty.anomalies.is_empty());
    assert!(more_empty, "limit 0 must report more open rounds");
    let (_, more_first, next_first) = fund
        .ledger
        .reconcile_rounds_checked_limit(&fund.chain, &|| false, 1, None)
        .fixture("rounds first page");
    assert!(more_first, "two open rounds need a second page");
    let (_, more_second, _) = fund
        .ledger
        .reconcile_rounds_checked_limit(&fund.chain, &|| false, 1, next_first)
        .fixture("rounds second page");
    assert!(!more_second, "cursor reaches the tail");

    fund.chain.set_tip(100);
    let (aborted, _, _) = fund
        .ledger
        .reconcile_rounds_checked_limit(&fund.chain, &|| true, 10, None)
        .fixture("rounds aborted");
    assert!(aborted.transitions.is_empty() && aborted.anomalies.is_empty());
    let pending = fund
        .ledger
        .round_for_block(&fund.block.share.header_hash)
        .fixture("round")
        .fixture("exists");
    assert_eq!(pending.state, RoundState::Pending);

    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], Some(50_000));
    fund.ledger
        .record_signed(&receipt(&batch, &tx))
        .fixture("signed");
    let (none, more_none, _) = fund
        .ledger
        .reconcile_payouts_checked_limit(&fund.chain, &|| false, 0, None)
        .fixture("payouts limit 0");
    assert!(none.is_empty());
    assert!(more_none, "limit 0 must report more observable batches");
    let (_, more_one, _) = fund
        .ledger
        .reconcile_payouts_checked_limit(&fund.chain, &|| false, 1, None)
        .fixture("payouts limit 1");
    assert!(!more_one, "single observable batch fits in limit 1");

    fund.chain.set_tx(tx.txid, TxStatus::InMempool);
    fund.ledger
        .record_broadcast(&batch.id, &tx.txid, &fund.chain)
        .fixture("broadcast");
    confirm_tx(&fund, tx.txid, 0xB1, 102, 102);
    fund.chain.set_tip(103);
    let (held, _, _) = fund
        .ledger
        .reconcile_payouts_checked_limit(&fund.chain, &|| true, 10, None)
        .fixture("payouts aborted");
    assert!(held.is_empty());
    let still = fund.ledger.batch(&batch.id).fixture("batch").fixture("exists");
    assert_eq!(still.state, BatchState::Broadcast);
}

#[test]
fn bounded_pages_advance_via_cursor_without_rescanning_head() {
    let fund = staged(0, 1_000_001);
    let mut hashes = vec![fund.block.share.header_hash];
    for tag in [7u8, 8, 9, 10] {
        let block = found(share(1, 4, u32::from(tag), 20), 101, 1_000_001);
        fund.ledger.record_found_block(&block).fixture("extra block");
        fund.chain.set_block(101, block.share.header_hash);
        hashes.push(block.share.header_hash);
    }
    let mut ids: Vec<u64> = hashes
        .iter()
        .map(|hash| {
            fund.ledger
                .round_for_block(hash)
                .fixture("round")
                .fixture("exists")
                .id
        })
        .collect();
    ids.sort_unstable();
    assert_eq!(ids.len(), 5);
    let mut after: Option<u64> = None;
    let mut seen: Vec<u64> = Vec::new();
    let mut pages = 0usize;
    loop {
        let (report, more, next) = fund
            .ledger
            .reconcile_rounds_checked_limit(&fund.chain, &|| false, 2, after)
            .fixture("page");
        assert!(
            report.transitions.len() <= 2 && report.anomalies.is_empty(),
            "each page bounds work"
        );
        if let Some(cursor) = next {
            if let Some(previous) = after {
                assert!(cursor > previous, "cursor must advance");
            }
            assert!(!seen.contains(&cursor), "no repeats across pages");
            seen.push(cursor);
        }
        pages += 1;
        assert!(pages <= 4, "five rows with limit 2 converge in three pages");
        if !more {
            break;
        }
        after = next;
    }
    assert_eq!(seen.len(), 3, "three pages advance cursors without rescan");
    assert_eq!(
        seen,
        vec![ids[1], ids[3], ids[4]],
        "raw cursors must be [1,3,4] for five rows at limit 2"
    );

}

#[test]
fn payout_lifecycle_events_are_audited_in_order() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], None);
    fund.ledger
        .record_signed(&receipt(&batch, &tx))
        .fixture("signed");
    fund.chain.set_tx(tx.txid, TxStatus::InMempool);
    fund.ledger
        .record_broadcast(&batch.id, &tx.txid, &fund.chain)
        .fixture("broadcast");
    confirm_tx(&fund, tx.txid, 0xB1, 102, 103);
    fund.ledger.reconcile_payouts(&fund.chain).fixture("confirm");
    let kinds: Vec<AuditKind> = fund
        .ledger
        .audit_records(0, 1_000)
        .fixture("audit")
        .into_iter()
        .map(|record| record.kind)
        .filter(|kind| {
            matches!(
                kind,
                AuditKind::BatchPrepared
                    | AuditKind::BatchSigned
                    | AuditKind::BatchBroadcast
                    | AuditKind::BatchConfirmed
            )
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            AuditKind::BatchPrepared,
            AuditKind::BatchSigned,
            AuditKind::BatchBroadcast,
            AuditKind::BatchConfirmed
        ]
    );
    let confirmed = fund
        .ledger
        .audit_records(0, 1_000)
        .fixture("audit")
        .into_iter()
        .find(|record| record.kind == AuditKind::BatchConfirmed)
        .fixture("confirmed record");
    assert_eq!(confirmed.hash, batch.id);
    assert_eq!(confirmed.hash2, tx.txid);
    assert_eq!(confirmed.values[0], 102);
}

#[test]
fn confirmed_payout_with_shallow_depth_reverts_and_restores_reservation() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let total = batch.total_sat;
    let tx = pay_tx(&batch, &[outpoint(0xA1, 0)], None);
    fund.ledger
        .record_signed(&receipt(&batch, &tx))
        .fixture("signed");
    fund.chain.set_tx(tx.txid, TxStatus::InMempool);
    fund.ledger
        .record_broadcast(&batch.id, &tx.txid, &fund.chain)
        .fixture("broadcast");
    confirm_tx(&fund, tx.txid, 0xB1, 102, 103);
    let confirmed = fund.ledger.reconcile_payouts(&fund.chain).fixture("confirm");
    assert_eq!(confirmed.len(), 1);
    assert_eq!(confirmed[0].to, BatchState::Confirmed);
    let after_confirm = fund.ledger.batch(&batch.id).fixture("batch").fixture("exists");
    assert_eq!(after_confirm.state, BatchState::Confirmed);
    assert!(after_confirm.confirmation.is_some());

    fund.chain.set_tip(102);
    let reverted = fund.ledger.reconcile_payouts(&fund.chain).fixture("shallow");
    assert_eq!(reverted.len(), 1, "shallow Confirmed must transition");
    assert_eq!(reverted[0].from, BatchState::Confirmed);
    assert_eq!(reverted[0].to, BatchState::Broadcast);
    let after_revert = fund.ledger.batch(&batch.id).fixture("batch").fixture("exists");
    assert_eq!(after_revert.state, BatchState::Broadcast);
    assert!(after_revert.confirmation.is_none());
    for output in &after_revert.outputs {
        let balance = fund.ledger.balance(output.account).fixture("balance");
        assert_eq!(balance.paid_sat, 0, "revert must unsettle paid");
    }
    let mut reserved_total = 0u64;
    for output in &after_revert.outputs {
        let balance = fund.ledger.balance(output.account).fixture("balance");
        reserved_total += balance.reserved_sat;
    }
    assert_eq!(reserved_total, total, "revert must restore the reservation");
    fund.ledger.check_invariants().fixture("conservation");
}

struct TxOnlyChain<'a> {
    inner: &'a FakeChain,
}

impl ChainView for TxOnlyChain<'_> {
    fn tip_height(&self) -> Result<u32, ChainViewError> {
        self.inner.tip_height()
    }
    fn block_location(
        &self,
        block_hash: &Hash32,
        claimed_height: u32,
    ) -> Result<BlockLocation, ChainViewError> {
        self.inner.block_location(block_hash, claimed_height)
    }
    fn coinbase_of(
        &self,
        block_hash: &Hash32,
    ) -> Result<Option<ObservedCoinbase>, ChainViewError> {
        self.inner.coinbase_of(block_hash)
    }
    fn tx_status(&self, txid: &Hash32) -> Result<TxStatus, ChainViewError> {
        self.inner.tx_status(txid)
    }
    fn confirmed_spender(
        &self,
        _outpoint: &OutPoint,
    ) -> Result<Option<ConfirmedSpend>, ChainViewError> {
        Err(ChainViewError(
            "payout spend observation requires script index".into(),
        ))
    }
}

#[test]
fn confirmed_replacement_confirms_without_spend_index() {
    let fund = funded(0, 1_000_001);
    let batch = prepared(&fund);
    let first = pay_tx(
        &batch,
        &[outpoint(0xA1, 0), outpoint(0xA2, 0)],
        Some(40_000),
    );
    fund.ledger
        .record_signed(&receipt(&batch, &first))
        .fixture("first");
    let replacement = pay_tx(
        &batch,
        &[outpoint(0xA2, 0), outpoint(0xA4, 0)],
        Some(30_000),
    );
    fund.ledger
        .record_signed(&receipt(&batch, &replacement))
        .fixture("replacement");
    fund.chain.set_tx(replacement.txid, TxStatus::InMempool);
    fund.ledger
        .record_broadcast(&batch.id, &replacement.txid, &fund.chain)
        .fixture("broadcast replacement");
    confirm_tx(&fund, replacement.txid, 0xB2, 102, 103);
    let tx_only = TxOnlyChain { inner: &fund.chain };
    let transitions = fund.ledger.reconcile_payouts(&tx_only).fixture("confirm");
    assert_eq!(
        transitions,
        vec![BatchTransition {
            batch_id: batch.id,
            from: BatchState::Broadcast,
            to: BatchState::Confirmed,
        }],
        "authoritative confirmation must win over missing abandonment evidence"
    );
    let confirmed = fund
        .ledger
        .batch(&batch.id)
        .fixture("batch")
        .fixture("exists");
    assert_eq!(confirmed.state, BatchState::Confirmed);
    assert_eq!(
        confirmed.confirmation.fixture("confirmation").txid,
        replacement.txid
    );
    fund.ledger.check_invariants().fixture("invariants");
}

#[test]
fn prepare_caps_outputs_by_serialized_weight_before_count() {
    assert_eq!(
        payout_output_weight_wu(34),
        172,
        "a P2TR/P2WSH output weighs 43 bytes * 4"
    );
    assert!(
        2_500u64.saturating_mul(172) > MAX_PAYOUT_OUTPUT_WEIGHT_WU,
        "the count cap alone would exceed the output weight budget"
    );
    let dir = tempfile::tempdir().fixture("tempdir");
    let path = ledger_path(&dir);
    let mut cfg = config(1_000_000, 0);
    cfg.payout_confirmations = 2;
    cfg.abandon_confirmations = 2;
    cfg.reorg_watch_depth = 10;
    let ledger = create(&path, cfg).fixture("create");
    const ACCOUNTS: u64 = 2_400;
    for account in 1..=ACCOUNTS {
        let mut seed = Vec::new();
        seed.extend_from_slice(&1u64.to_be_bytes());
        seed.extend_from_slice(&account.to_be_bytes());
        seed.extend_from_slice(&1u32.to_be_bytes());
        let credit = ShareCredit {
            header_hash: sha256(&seed),
            job: 1,
            account: MinerId(account),
            extranonce: account.to_le_bytes().to_vec(),
            nonce: u32::try_from(account).fixture("small nonce"),
            version: 1,
            ntime: 1_700_000_000,
            work: 1,
        };
        ledger.record_share(&credit).fixture("share");
    }
    let solving = ShareCredit {
        header_hash: sha256(b"solve"),
        job: 1,
        account: MinerId(ACCOUNTS + 1),
        extranonce: b"solve".to_vec(),
        nonce: 0,
        version: 1,
        ntime: 1_700_000_000,
        work: 1,
    };
    let block = BlockFound {
        share: solving,
        height: 100,
        coinbase_txid: sha256(b"coinbase"),
        claimed_coinbase_value_sat: 5_000_000,
    };
    ledger.record_found_block(&block).fixture("block");
    let chain = FakeChain::default();
    chain.set_block(100, block.share.header_hash);
    chain.set_coinbase(
        block.share.header_hash,
        ObservedCoinbase {
            txid: block.coinbase_txid,
            outputs: vec![TxOut {
                value_sat: 5_000_000,
                script_pubkey: pool_script(),
            }],
        },
    );
    chain.set_tip(99);
    for account in 1..=ACCOUNTS {
        let mut script = vec![0x51u8, 0x20];
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&account.to_le_bytes());
        script.extend_from_slice(&key);
        assert_eq!(script.len(), 34);
        ledger
            .set_payout_script(MinerId(account), &script)
            .fixture("script");
    }
    chain.set_tip(102);
    ledger.reconcile_rounds(&chain).fixture("mature");
    let batch = ledger
        .prepare_payout_batch(
            idem(1),
            PayoutPolicy {
                min_payout_sat: 546,
                max_outputs: MAX_BATCH_OUTPUTS,
            },
        )
        .fixture("prepare")
        .fixture("a batch");
    let weight: u64 = batch
        .outputs
        .iter()
        .map(|output| payout_output_weight_wu(output.script_pubkey.len()))
        .sum();
    assert!(
        batch.outputs.len() < MAX_BATCH_OUTPUTS,
        "weight budget must bind before the 2,500-output count cap"
    );
    assert!(
        weight <= MAX_PAYOUT_OUTPUT_WEIGHT_WU,
        "reserved outputs must leave funding headroom: {weight} > {}",
        MAX_PAYOUT_OUTPUT_WEIGHT_WU
    );
    assert!(
        weight.saturating_add(payout_output_weight_wu(34)) > MAX_PAYOUT_OUTPUT_WEIGHT_WU,
        "the next 34-byte output must not fit the budget"
    );
    ledger.check_invariants().fixture("invariants");
}
