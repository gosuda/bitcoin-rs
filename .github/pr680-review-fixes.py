from pathlib import Path
import subprocess

root = Path.cwd()
preimages = {
    'crates/consensus/src/verify_tx.rs': '92ab1f3c0240afcc4a1e6d1904362c98f8be1a62',
    'crates/mempool/src/accounting.rs': '2925ea8e72f50735bcf1d87c39a11a61ca063c39',
    'crates/node/README.md': '903586f4311626b4dd9f5d8316b0f112afbce296',
    'crates/node/src/run.rs': 'ab8ab5385085a4232b4f33ec4ed2e3c16e6c4fc1',
    'crates/node/src/tx_ingress.rs': 'd71556131655b462831b39ff659aba9d2c6b892d',
    'crates/node/tests/tx_ingress_e2e.rs': '31b64d54db8a97cc9287e128f9e5ab7fd5894b29',
    'crates/p2p/README.md': 'e484e3d8183e6bee9e8425a1da8f13de21f0808c',
    'crates/script/src/sigops.rs': '5e461bd00e6dd7d2305c47beb91c9d7308c388fc',
    'docs/contracts/mempool-mutations.md': 'b0d4d6731be00d0080c774c2cafa42d17ef18a82',
    'docs/policies/mempool-policy.md': '019420fa5b6a3f05cbca1ab990f677d248b972a5',
}
for path, expected in preimages.items():
    actual = subprocess.check_output(['git', 'hash-object', path], text=True).strip()
    assert actual == expected, (path, expected, actual)

p=root/'crates/node/src/tx_ingress.rs'
s=p.read_text()
s=s.replace('use bitcoin_rs_mining::MiningControl;\n','').replace('    mining_control: Arc<dyn MiningControl>,\n','').replace('        mining_control,\n','').replace('                    self.mining_control.publish_generation();\n','')
s=s.replace('    use bitcoin_rs_p2p::DEFAULT_TX_RELAY_QUEUE_CAPACITY;','    use crate::mining::{MempoolSequenceWake, MiningGenerationSignal};\n    use bitcoin_rs_p2p::{DEFAULT_TX_RELAY_QUEUE_CAPACITY, RelayRequest};')
s=s.replace('use bitcoin_rs_primitives::{Block, OutPoint, TxIn, TxOut};','use bitcoin_rs_primitives::{OutPoint, TxIn, TxOut};')
s=s.replace('    /// A recording mining control that counts `publish_generation` calls.','    /// Records the production gateway observer\'s sequence-aware mining wake.')
a=s.index('    impl MiningControl for RecordingMining {')
b=s.index('    /// Builds a valid coinbase tx',a)
s=s[:a]+'''    impl MempoolSequenceWake for RecordingMining {
        fn publish_generation_from(&self, _sequence: u64) {
            self.publishes.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn recording_gateway(limits: MempoolLimits) -> (Arc<MempoolGateway>, Arc<RecordingMining>) {
        let mining = Arc::new(RecordingMining::new());
        let wake: Arc<dyn MempoolSequenceWake> = mining.clone();
        let signal = Arc::new(MiningGenerationSignal::new());
        signal.attach_sequence_wake(&wake);
        let gateway = MempoolGateway::shared_with(
            Arc::new(RwLock::new(Mempool::new(limits))),
            signal,
        );
        (gateway, mining)
    }

'''+s[b:]
s=s.replace('    /// Builds a valid coinbase tx for testing (no inputs, one output).','    /// Builds a transaction with an unavailable input for rejection fixtures.')
a=s.index('    fn make_consumer_with_utxo(')
b=s.index('    /// Builds a `PeerSource`',a)
s=s[:a]+'''    fn make_consumer_with_utxo(
        gateway: &Arc<MempoolGateway>,
    ) -> (TxIngressConsumer, Receiver<RelayRequest>) {
        use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
        let (consumer, relay_rx) = make_consumer(gateway);
        let mut changes = BlockChanges::with_capacity(1, 0);
        changes.add(UtxoAdd::new(
            spending_tx().inputs[0].previous_output,
            TxOut {
                value: 50_000,
                script_pubkey: vec![0x51],
            },
            false,
            100,
        ));
        consumer.utxo.commit_block(&changes, &Hash256::from_le_bytes(&[0xBB; 32]))
            .expect("utxo commit must succeed");
        (consumer, relay_rx)
    }

'''+s[b:]
a=s.index('    fn make_consumer(')
b=s.index('    /// Test: the consumer carries',a)
s=s[:a]+'''    fn make_consumer(gateway: &Arc<MempoolGateway>) -> (TxIngressConsumer, Receiver<RelayRequest>) {
        let (relay, relay_rx) = TxRelayQueue::new(DEFAULT_TX_RELAY_QUEUE_CAPACITY);
        let consumer = TxIngressConsumer {
            utxo: Arc::new(UtxoSet::new()),
            transactions: Arc::new(RwLock::new(hashbrown::HashMap::new())),
            peer_table: Arc::new(bitcoin_rs_p2p::PeerTable::new()),
            mempool_gateway: Arc::clone(gateway),
            relay,
            applied_tip: Arc::new(ArcSwapOption::empty()),
            block_tree: Arc::new(RwLock::new(BlockTree::new())),
        };
        (consumer, relay_rx)
    }

'''+s[b:]
s=s.replace('        let mining = Arc::new(RecordingMining::new());\n        let consumer = make_consumer_with_utxo(&gateway, mining);','        let (consumer, _relay_rx) = make_consumer_with_utxo(&gateway);')
s=s.replace('        let mining = Arc::new(RecordingMining::new());\n        let consumer = make_consumer(&gateway, mining);','        let (consumer, _relay_rx) = make_consumer(&gateway);')
a=s.index('    /// Test: a rejected transaction does not relay')
b=s.index('    #[test]\n    fn coinbase_is_rejected_not_orphaned',a)
s=s[:a]+'''    /// MPL-01: rejected admission publishes neither a mutation wake nor relay work.
    #[test]
    fn rejected_tx_does_not_relay_or_wake_mining() {
        let (gateway, mining) = recording_gateway(MempoolLimits::default());
        let (consumer, relay_rx) = make_consumer(&gateway);
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(coinbase_tx(50_000), test_source()));
        assert_eq!(mining.publish_count(), 0);
        assert!(relay_rx.try_recv().is_err());
    }

    /// MPL-01: an already-present body publishes no second mutation or relay.
    #[test]
    fn duplicate_tx_does_not_relay_or_wake_mining() {
        let (gateway, mining) = recording_gateway(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let tx = coinbase_tx(50_000);
        let txid = tx.txid();
        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 0, 1, 0);
        gateway.insert_entry(AdmissionOrigin::Rpc, entry).unwrap();
        assert_eq!(mining.publish_count(), 1, "fixture insertion wakes the observer");

        let (consumer, relay_rx) = make_consumer(&gateway);
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, test_source()));
        assert_eq!(mining.publish_count(), 1, "duplicate must not wake again");
        assert!(relay_rx.try_recv().is_err());
        assert!(gateway.read().contains_txid(&txid));
    }

    /// MPL-01 / ARCH-05: the gateway wakes mining once; ingress queues relay once.
    #[test]
    fn accepted_tx_relays_and_wakes_mining() {
        let (gateway, mining) = recording_gateway(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        });
        let (consumer, relay_rx) = make_consumer_with_utxo(&gateway);
        let source = test_source();
        let tx = spending_tx();
        let txid = tx.txid();
        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, source));

        assert_eq!(mining.publish_count(), 1, "one authoritative mutation wake");
        let request = relay_rx.try_recv().expect("committed transaction queues relay");
        assert_eq!(request.txid, txid);
        assert_eq!(request.source, Some(source.connection_id().get()));
        assert!(relay_rx.try_recv().is_err());
    }

'''+s[b:]
a=s.index('    fn oversized_missing_input_tx_is_rejected_not_orphaned')
tail=s[a:]
tail=tail.replace('        let txid = tx.txid();','        let txid = tx.txid();\n        let wtxid = tx.wtxid();')
tail=tail.replace('consumer.mempool_gateway.is_rejected(Hash256::from(txid)),','consumer.mempool_gateway.is_rejected(Hash256::from(wtxid)),')
tail=tail.replace('"a non-standard missing-input body must enter recent-rejects"','"the exact non-standard missing-input body must enter recent-rejects"')
tail=tail.replace('        );\n    }\n}', '        );\n        assert!(!consumer.mempool_gateway.is_rejected(Hash256::from(txid)));\n    }\n}')
s=s[:a]+tail
p.write_text(s)
p=root/'crates/node/src/run.rs';s=p.read_text(); needle='''        Arc::clone(&gateway),
        Arc::clone(&mining_control),
        Arc::clone(&shutdown),''';assert s.count(needle)==1;s=s.replace(needle,'''        Arc::clone(&gateway),
        Arc::clone(&shutdown),''');p.write_text(s)
p=root/'crates/node/tests/tx_ingress_e2e.rs';s=p.read_text()
a=s.index('use bitcoin_rs_mining::{');b=s.index('use bitcoin_rs_node::state::NodeState;',a)
s=s[:a]+'use bitcoin_rs_node::mining::MempoolSequenceWake;\n'+s[b:]
s=s.replace('use bitcoin_rs_primitives::{Block, Hash256,','use bitcoin_rs_primitives::{Hash256,')
s=s.replace('/// Recording `MiningControl` counting accepted-path template wakes.','/// Records wakes from the same gateway observer installed in production.')
a=s.index('impl MiningControl for RecordingMining {');b=s.index('/// Returns `Some(reason)`',a)
s=s[:a]+'''impl MempoolSequenceWake for RecordingMining {
    fn publish_generation_from(&self, _sequence: u64) {
        self.publishes.fetch_add(1, Ordering::Relaxed);
    }
}

'''+s[b:]
s=s.replace('let mining_control: Arc<dyn MiningControl> = Arc::<RecordingMining>::clone(&mining);','let wake: Arc<dyn MempoolSequenceWake> = mining.clone();\n        state.mining_generation_signal().attach_sequence_wake(&wake);')
s=s.replace('            mining_control,\n','').replace('        mining_control,\n','')
s=s.replace('    assert_eq!(relay.dropped(), 1);','    assert_eq!(relay.dropped(), 1);\n    assert_eq!(mining.publish_count(), 1);')
s=s.replace('''    assert!(
        harness.mining.publish_count() >= 1,
        "accepted tx must wake the mining control"
    );''','''    assert_eq!(harness.mining.publish_count(), 1, "one authoritative mutation wake");''')
p.write_text(s)

p=root/'crates/script/src/sigops.rs';s=p.read_text();s=s.replace('use bitcoin_rs_primitives::{Block, Tx};','use bitcoin_rs_primitives::{Block, OutPoint, Tx, TxOut};');s=s.replace('use crate::script::{EarlyEndOfScript, Instruction, instructions, is_p2wpkh, is_p2wsh, opcode};','''use crate::script::{
    EarlyEndOfScript, Instruction, instructions, is_p2sh, is_p2wpkh, is_p2wsh, is_push_only,
    is_witness_program, opcode,
};''')
m=root/'crates/mempool/src/accounting.rs';mem=m.read_text();a=mem.index('/// Returns BIP141 sigop cost');b=mem.index('#[cfg(test)]',a);counter=mem[a:b]
counter=counter.replace('pub fn sigop_cost(tx: &Tx, prevouts: &[(OutPoint, TxOut)]) -> u32 {\n    let by_outpoint: HashMap<_, _> = prevouts\n        .iter()\n        .map(|(outpoint, output)| (*outpoint, output))\n        .collect();','''pub fn count_tx_cost<'a>(
    tx: &Tx,
    mut lookup: impl FnMut(&OutPoint) -> Option<&'a TxOut>,
) -> u32 {''').replace('by_outpoint.get(&input.previous_output)','lookup(&input.previous_output)')
counter=counter.replace('/// `CountWitnessSigOps`. Missing prevouts contribute no contextual cost.','''/// `CountWitnessSigOps`. Missing prevouts contribute no contextual cost.
/// The caller supplies its existing coin lookup; counting neither builds a
/// second input index nor validates scripts or activation flags.''')
a=s.index('/// Counts the legacy sigop cost of a whole block');s=s[:a]+counter+s[a:];p.write_text(s)
a=mem.index('use bitcoin_rs_script::script::{');b=mem.index('use hashbrown::HashMap;',a);mem=mem[:a]+'use bitcoin_rs_script::sigops::count_tx_cost;\n'+mem[b:]
a=mem.index('/// Returns BIP141 sigop cost');b=mem.index('#[cfg(test)]',a);mem=mem[:a]+mem[b:]
mem=mem.replace('    PackageTxContext {','''    let by_outpoint: HashMap<_, _> = prevouts
        .iter()
        .map(|(outpoint, output)| (*outpoint, output))
        .collect();
    PackageTxContext {''',1)
mem=mem.replace('sigop_cost: sigop_cost(tx, prevouts),','sigop_cost: count_tx_cost(tx, |outpoint| by_outpoint.get(outpoint).copied()),')
mem=mem.replace('        assert_eq!(sigop_cost(tx, &prevouts), expected);\n','')
mem=mem.replace('assert_eq!(sigop_cost(&tx, &prevouts), 0);','assert_eq!(prepared_context(&tx, &prevouts, false).sigop_cost, 0);')
m.write_text(mem)
p=root/'crates/consensus/src/verify_tx.rs';s=p.read_text();a=s.index('use bitcoin_rs_script::script::instructions;');b=s.index('use rayon::prelude::*;',a);s=s[:a]+'use bitcoin_rs_script::VerifyFlags;\nuse bitcoin_rs_script::sigops::count_tx_cost;\n'+s[b:]
s=s.replace('    let _ = 0usize;\n    let sigop_cost = total_sigop_cost(tx, &prep.prevouts);','''    let mut cursor = 0;
    let sigop_cost = count_tx_cost(tx, |outpoint| {
        cached_prevout_lookup(&prep.prevouts, &mut cursor, outpoint)
    });''')
s=s.replace('fn cached_prevout_lookup(\n    prevouts: &[(OutPoint, TxOut)],','fn cached_prevout_lookup<\'a>(\n    prevouts: &\'a [(OutPoint, TxOut)],').replace(') -> Option<TxOut> {\n    if prevouts.is_empty()',') -> Option<&\'a TxOut> {\n    if prevouts.is_empty()').replace('return Some(txout.clone());','return Some(txout);').replace('    Some(txout.clone())\n}', '    Some(txout)\n}')
a=s.index('fn total_sigop_cost(');b=s.index('#[cfg(test)]',a);s=s[:a]+s[b:];p.write_text(s)
p=root/'crates/node/README.md';s=p.read_text();a=s.index('For transactions, node supplies');b=s.index('Crash recovery uses',a);s=s[:a]+'''The transaction lifecycle ownership boundary is defined by
[ARCH-05](../../docs/contracts/architecture.md#arch-05-node-composition-and-orchestration-boundary).

'''+s[b:];p.write_text(s)
p=root/'crates/p2p/README.md';s=p.read_text();a=s.index('Transaction inventory reads');b=s.index('`PeerManager` owns',a);s=s[:a]+'''The transaction lifecycle ownership boundary is defined by
[ARCH-05](../../docs/contracts/architecture.md#arch-05-node-composition-and-orchestration-boundary).
Supported inventory forms and outbound relay limitations are defined in
[P2P compatibility](../../docs/policies/p2p-compatibility.md).

'''+s[b:];p.write_text(s)
p=root/'docs/contracts/mempool-mutations.md';s=p.read_text();s=s.replace('''  retain both hash forms in a bounded FIFO. These private defaults and
  indexes have one owner in `orphan.rs`; RPC missing-input rejections do
  not populate peer orphan state.''','''  retain exact-body wtxids in a bounded FIFO. A rejected witness variant
  neither suppresses admission of another body with the same txid nor
  retires that body's resident orphan or ready work. An input naming a
  nonexistent output of a resident parent is rejected, not parked as an
  orphan. These private defaults and indexes have one owner in `orphan.rs`;
  RPC missing-input rejections do not populate peer orphan state.''')
s=s.replace('candidate pricing and earlier offered outputs; node supplies ordered','candidate accounting and earlier offered outputs; node supplies ordered');p.write_text(s)
p=root/'docs/policies/mempool-policy.md';s=p.read_text().replace('Retention and retry ordering follow `MPL-04`','Retention and retry semantics follow `MPL-04`');p.write_text(s)
