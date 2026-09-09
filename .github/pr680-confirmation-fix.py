from pathlib import Path
import subprocess

root = Path.cwd()
p = root / 'crates/rpc/src/context.rs'
assert subprocess.check_output(['git', 'hash-object', str(p)], text=True).strip() == 'c9f41c05b3fe13ac99c8c2b6ac5b9752b8f37a6a'
s = p.read_text()
a = s.index('pub struct ChainAdmissionView')
b = s.index('/// Mempool capability handles.', a)
view = s[a:b]
view = view.replace("        transactions: &'a RwLock<HashMap<Txid, Tx>>,\n", '').replace("    transactions: &'a RwLock<HashMap<Txid, Tx>>,\n", '').replace('            transactions,\n', '')
old = '''        // This preserves the existing peer-side confirmed lookup. RPC ignores
        // this hint: its transaction lookup cache is not mempool membership.
        let confirmed = self.transactions.read().contains_key(&tx.txid());'''
assert old in view
view = view.replace(old, '''        // Only applied-chain coins prove this positive confirmation hint.
        // A lookup-cache body is not proof, and a fully spent transaction may
        // simply proceed through ordinary input validation instead.
        let confirmed = self.utxo.has_live_outputs_for_txid(&Hash256::from(tx.txid()));''')
s = s[:a] + view + s[b:]
a = s.index('    pub fn admission_chain(&self)')
b = s.index('    /// Admits one transaction', a)
section = s[a:b]
assert section.count('            &self.transactions,\n') == 1
s = s[:a] + section.replace('            &self.transactions,\n', '') + s[b:]
s = s.replace('        assert!(snapshot.confirmed);', '        assert!(!snapshot.confirmed, "the RPC lookup cache is not confirmation proof");')
a = s.rindex('\n}')
s = s[:a] + '''

    /// MPL-04: confirmation hints follow applied coins, never RPC body-cache membership.
    #[test]
    fn admission_chain_uses_live_coins_not_rpc_lookup_cache() -> anyhow::Result<()> {
        let ctx = Context::new();
        let tx = spending(OutPoint::new(Txid::from(Hash256::from_le_bytes(&[8; 32])), 0));
        ctx.add_transaction(tx.clone());
        assert!(!ctx.admission_chain().snapshot(&tx).context("cached body")?.confirmed);

        let outpoint = OutPoint::new(tx.txid(), 0);
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(outpoint, tx.outputs[0].clone(), false, 1));
        ctx.utxo.commit_block(&changes, &Hash256::default())?;
        assert!(ctx.admission_chain().snapshot(&tx).context("live coin")?.confirmed);

        let mut changes = BlockChanges::default();
        changes.remove(outpoint);
        ctx.utxo.commit_block(&changes, &Hash256::default())?;
        assert!(!ctx.admission_chain().snapshot(&tx).context("retired coin")?.confirmed);
        assert!(ctx.transactions.read().contains_key(&tx.txid()));
        Ok(())
    }
''' + s[a:]
p.write_text(s)

p = root / 'crates/node/src/tx_ingress.rs'
s = p.read_text()
s = s.replace('        transactions: state.transactions(),\n', '').replace('    transactions: Arc<RwLock<hashbrown::HashMap<Txid, Tx>>>,\n', '').replace('            &self.transactions,\n', '').replace('            transactions: Arc::new(RwLock::new(hashbrown::HashMap::new())),\n', '')
s = s.replace('use bitcoin_rs_primitives::{Hash256, Tx, Txid};', 'use bitcoin_rs_primitives::{Hash256, Txid};').replace('use bitcoin_rs_primitives::{OutPoint, TxIn, TxOut};', 'use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut};')
p.write_text(s)

p = root / 'docs/contracts/mempool-mutations.md'
s = p.read_text().replace('  model. A provider may return no snapshot to request a transient retry.', '''  model. Positive peer confirmation hints come from applied live coins,
  never RPC transaction-cache membership. A provider may return no snapshot
  to request a transient retry.''').replace('''  and ready IDs as one ownership unit. Retention is count-bounded FIFO
  without expiry; witness refresh preserves FIFO position. Recent rejects''', '''  and ready IDs as one ownership unit. Retention is FIFO bounded by both
  count and aggregate transaction weight, without expiry; witness refresh
  preserves FIFO position. Recent rejects''')
p.write_text(s)
