//! Prevout lookups for a window of consecutive blocks, before any of them commit.

use bitcoin_rs_primitives::{Block, OutPoint, Txid};
use hashbrown::{HashMap, HashSet};

use crate::connect::is_coinbase_tx;
use crate::{UtxoSet, shard::LiveOutput};

/// Where a block's prevouts are read from: the committed set, or a
/// [`WindowOverlay`] over blocks prepared but not yet committed.
pub trait OutputSource {
    /// The live output an outpoint refers to, or `None` if unspendable here.
    fn get_entry(&self, outpoint: &OutPoint) -> Option<LiveOutput>;
}

impl OutputSource for UtxoSet {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<LiveOutput> {
        Self::get_entry(self, outpoint)
    }
}

/// The committed UTXO set plus the net effect of window blocks already prepared.
/// Spends are tombstoned rather than removed so a later window block can
/// recreate an outpoint.
pub struct WindowOverlay<'u> {
    base: &'u UtxoSet,
    max_script_size: usize,
    /// `Some` created and live, `None` spent, absent means ask `base`.
    changed: HashMap<OutPoint, Option<LiveOutput>>,
}

impl<'u> WindowOverlay<'u> {
    /// `max_script_size` is the limit the committed set applies when it skips
    /// oversized outputs.
    pub fn new(base: &'u UtxoSet, max_script_size: usize) -> Self {
        Self {
            base,
            max_script_size,
            changed: HashMap::new(),
        }
    }

    /// Folds one block's net effect into the view. `same_block_spent`
    /// outpoints are skipped on both sides, as in
    /// [`build_block_changes`](crate::connect::build_block_changes). Genesis is
    /// a no-op, as in the apply path.
    ///
    /// # Errors
    ///
    /// A `txids` slice that does not cover every transaction; zipping would
    /// silently drop the trailing ones.
    pub fn advance(
        &mut self,
        block: &Block,
        txids: &[Txid],
        height: u32,
        same_block_spent: &HashSet<OutPoint>,
    ) -> Result<(), WindowOverlayError> {
        if block.txs.len() != txids.len() {
            return Err(WindowOverlayError::TxidCountMismatch {
                transactions: block.txs.len(),
                txids: txids.len(),
            });
        }
        if height == 0 {
            return Ok(());
        }
        for (tx, &txid) in block.txs.iter().zip(txids) {
            let coinbase = is_coinbase_tx(tx);
            for (vout, txout) in (0u32..).zip(&tx.outputs) {
                let script = &txout.script_pubkey;
                let outpoint = OutPoint::new(txid, vout);
                if script.first() == Some(&0x6a)
                    || script.len() > self.max_script_size
                    || same_block_spent.contains(&outpoint)
                {
                    continue;
                }
                let txout = txout.clone();
                self.changed.insert(
                    outpoint,
                    Some(LiveOutput {
                        txout,
                        coinbase,
                        height,
                    }),
                );
            }
            if coinbase {
                continue;
            }
            for input in &tx.inputs {
                if !same_block_spent.contains(&input.previous_output) {
                    self.changed.insert(input.previous_output, None);
                }
            }
        }
        Ok(())
    }
}

/// Why the view refused to fold in a block.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[allow(missing_docs)]
pub enum WindowOverlayError {
    #[error("block has {transactions} transactions but {txids} txids were supplied")]
    TxidCountMismatch { transactions: usize, txids: usize },
}

impl OutputSource for WindowOverlay<'_> {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<LiveOutput> {
        self.changed
            .get(outpoint)
            .map_or_else(|| self.base.get_entry(outpoint), Clone::clone)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::{
        Amount, Block, CompactTarget, Hash256, Header, LockTime, OutPoint, Sequence, Tx, TxIn,
        TxOut, Txid, Witness,
    };
    use hashbrown::HashSet;

    use super::{OutputSource, WindowOverlay, WindowOverlayError};
    use crate::{UndoBatch, UtxoAdd, UtxoSet};

    /// Opaque test bound; the apply path supplies the consensus value.
    const MAX_SCRIPT_SIZE: usize = 64;
    const HEIGHT: u32 = 7;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn tx(previous_output: OutPoint, script_pubkey: Vec<u8>, value: u64) -> Tx {
        Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output,
                script_sig: vec![0x00, 0x01].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script_pubkey.into(),
            }],
        }
    }

    /// A coinbase paying one output, so `advance` sees a creation.
    fn paying(script_pubkey: Vec<u8>, value: u64) -> Tx {
        tx(
            OutPoint::new(Txid::default(), u32::MAX),
            script_pubkey,
            value,
        )
    }

    fn spending(previous_output: OutPoint) -> Tx {
        let mut tx = tx(previous_output, vec![0x51], 1);
        tx.version = 2;
        tx
    }

    fn block(txs: Vec<Tx>) -> Block {
        Block {
            header: Header {
                version: 1,
                prev_blockhash: bitcoin_rs_primitives::BlockHash(Hash256::default()),
                merkle_root: Hash256::default(),
                time: 0,
                bits: CompactTarget::from_consensus(0x2100_ffff),
                nonce: 0,
            },
            txs,
        }
    }

    /// Folds `txs` in at `height` with no same-block netting.
    fn advance(overlay: &mut WindowOverlay<'_>, txs: Vec<Tx>, height: u32) -> TestResult {
        let txids: Vec<Txid> = txs.iter().map(Tx::txid).collect();
        overlay.advance(&block(txs), &txids, height, &HashSet::new())?;
        Ok(())
    }

    #[test]
    fn create_spend_and_recreate_shadow_the_committed_set() -> TestResult {
        let utxo = UtxoSet::new();
        let funded = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x31; 32])), 0);
        let mut seed = UndoBatch::default();
        seed.restore(UtxoAdd::new(
            funded,
            paying(vec![0x51], 900).outputs.remove(0),
            false,
            1,
        ));
        utxo.undo_block(&seed)?;
        let mut overlay = WindowOverlay::new(&utxo, MAX_SCRIPT_SIZE);
        let tx = paying(vec![0x51], 500);
        let created = OutPoint::new(tx.txid(), 0);
        assert!(overlay.get_entry(&funded).is_some());
        assert!(overlay.get_entry(&created).is_none());

        advance(&mut overlay, vec![tx.clone(), spending(funded)], HEIGHT)?;
        assert!(overlay.get_entry(&funded).is_none());
        assert_eq!(
            overlay
                .get_entry(&created)
                .map(|e| (e.height, e.coinbase, e.txout.value)),
            Some((HEIGHT, true, Amount::from_sat(500)))
        );

        advance(
            &mut overlay,
            vec![paying(vec![0x51], 1), spending(created)],
            HEIGHT + 1,
        )?;
        assert!(overlay.get_entry(&created).is_none());

        advance(&mut overlay, vec![tx], HEIGHT + 2)?;
        assert_eq!(
            overlay.get_entry(&created).map(|e| e.height),
            Some(HEIGHT + 2)
        );
        Ok(())
    }

    #[test]
    fn unspendable_genesis_and_same_block_outputs_never_enter_the_view() -> TestResult {
        let utxo = UtxoSet::new();
        let mut overlay = WindowOverlay::new(&utxo, MAX_SCRIPT_SIZE);
        let op_return = paying(vec![0x6a], 0);
        let at_limit = paying(vec![0x51; MAX_SCRIPT_SIZE], 1);
        let over_limit = paying(vec![0x51; MAX_SCRIPT_SIZE + 1], 1);
        let genesis = paying(vec![0x51], 5_000_000_000);
        let netted = paying(vec![0x51], 400);
        let netted_out = OutPoint::new(netted.txid(), 0);
        let spend = spending(netted_out);
        let ids = [
            op_return.txid(),
            at_limit.txid(),
            over_limit.txid(),
            genesis.txid(),
        ];

        advance(&mut overlay, vec![genesis], 0)?;
        advance(&mut overlay, vec![op_return, at_limit, over_limit], HEIGHT)?;
        overlay.advance(
            &block(vec![netted.clone(), spend.clone()]),
            &[netted.txid(), spend.txid()],
            HEIGHT + 1,
            &HashSet::from([netted_out]),
        )?;

        assert!(overlay.get_entry(&OutPoint::new(ids[0], 0)).is_none());
        assert!(overlay.get_entry(&OutPoint::new(ids[1], 0)).is_some());
        assert!(overlay.get_entry(&OutPoint::new(ids[2], 0)).is_none());
        assert!(overlay.get_entry(&OutPoint::new(ids[3], 0)).is_none());
        assert!(!overlay.changed.contains_key(&netted_out));
        Ok(())
    }

    #[test]
    fn a_short_txid_list_is_refused_untouched() {
        let utxo = UtxoSet::new();
        let mut overlay = WindowOverlay::new(&utxo, MAX_SCRIPT_SIZE);
        let txs = vec![paying(vec![0x51], 1), paying(vec![0x52], 2)];

        let outcome = overlay.advance(&block(txs), &[Txid::default()], HEIGHT, &HashSet::new());

        assert_eq!(
            outcome,
            Err(WindowOverlayError::TxidCountMismatch {
                transactions: 2,
                txids: 1,
            })
        );
        assert!(overlay.changed.is_empty());
    }
}
