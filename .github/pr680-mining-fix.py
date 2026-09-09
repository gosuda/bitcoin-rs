from pathlib import Path
import subprocess

root = Path.cwd()
source = root / '.review-source'
preimages = {
    'crates/node/src/tx_ingress.rs': '42b95586dcf7849957c39ac0be1b8c4e641bb293',
    'crates/node/src/run.rs': '0f8876ace829257797cc29fcb951e736f0324d57',
    'crates/node/tests/tx_ingress_e2e.rs': '00894a8bac613d08d77c28f26662a4f51de23888',
}
for path, expected in preimages.items():
    actual = subprocess.check_output(['git', 'hash-object', path], text=True).strip()
    assert actual == expected, (path, expected, actual)

p = root / 'crates/node/src/tx_ingress.rs'
s = p.read_text()
production = s[:s.index('#[cfg(test)]')]
production = production.replace('use bitcoin_rs_mining::MiningControl;\n', '').replace('    mining_control: Arc<dyn MiningControl>,\n', '').replace('        mining_control,\n', '').replace('                    self.mining_control.publish_generation();\n', '')
tests = (source / 'crates/node/src/tx_ingress.rs').read_text().split('#[cfg(test)]', 1)[1]
tests = tests.replace('        let txid = tx.txid();\n        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, source));', '        let txid = tx.txid();\n        let wtxid = tx.wtxid();\n        consumer.process_one(bitcoin_rs_p2p::InboundTx::new(tx, source));')
tests = tests.replace('        assert_eq!(request.txid, txid);', '        assert_eq!(request.txid, txid);\n        assert_eq!(request.wtxid, wtxid);')
tests = tests.replace('        assert!(!consumer.mempool_gateway.is_rejected(Hash256::from(txid)));', '        assert!(!consumer.mempool_gateway.have_tx(Hash256::from(txid), false));')
p.write_text(production + '#[cfg(test)]' + tests)

p = root / 'crates/node/src/run.rs'
s = p.read_text()
needle = '        Arc::clone(&gateway),\n        Arc::clone(&mining_control),\n        Arc::clone(&shutdown),'
assert s.count(needle) == 1
s = s.replace(needle, '        Arc::clone(&gateway),\n        Arc::clone(&shutdown),')
p.write_text(s)

p = root / 'crates/node/tests/tx_ingress_e2e.rs'
s = p.read_text()
a = s.index('use bitcoin_rs_mining::{')
b = s.index('use bitcoin_rs_node::state::NodeState;', a)
s = s[:a] + 'use bitcoin_rs_node::mining::MempoolSequenceWake;\n' + s[b:]
s = s.replace('use bitcoin_rs_primitives::{Block, Hash256,', 'use bitcoin_rs_primitives::{Hash256,')
s = s.replace('/// Recording `MiningControl` counting accepted-path template wakes.', '/// Records the production gateway observer\'s sequence-aware mining wake.')
a = s.index('impl MiningControl for RecordingMining {')
b = s.index('/// Returns `Some(reason)`', a)
s = s[:a] + '''impl MempoolSequenceWake for RecordingMining {
    fn publish_generation_from(&self, _sequence: u64) {
        self.publishes.fetch_add(1, Ordering::Relaxed);
    }
}

''' + s[b:]
s = s.replace('let mining_control: Arc<dyn MiningControl> = Arc::<RecordingMining>::clone(&mining);', 'let wake: Arc<dyn MempoolSequenceWake> = mining.clone();\n        state.mining_generation_signal().attach_sequence_wake(&wake);')
s = s.replace('            mining_control,\n', '').replace('        mining_control,\n', '')
s = s.replace('    assert_eq!(relay.dropped(), 1);', '    assert_eq!(relay.dropped(), 1);\n    assert_eq!(mining.publish_count(), 1);')
s = s.replace('''    assert!(
        harness.mining.publish_count() >= 1,
        "accepted tx must wake the mining control"
    );''', '''    assert_eq!(
        harness.mining.publish_count(),
        1,
        "one authoritative mutation wake"
    );''')
p.write_text(s)
