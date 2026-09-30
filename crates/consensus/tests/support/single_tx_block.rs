//! Single-transaction block fixture shared by the BIP141 block-rule suites.
//! These blocks are not mined or UTXO-valid chain fixtures.

use bitcoin_rs_primitives::{Block, BlockHash, CompactTarget, Header, Tx};

/// Wraps `tx` as the only transaction of a block whose header commits to it:
/// a one-leaf Merkle root is that leaf's txid. Every other header field is
/// zero apart from version 1.
pub(crate) fn block(tx: Tx) -> Block {
    let merkle_root = tx.txid().into();
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root,
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: vec![tx],
    }
}
