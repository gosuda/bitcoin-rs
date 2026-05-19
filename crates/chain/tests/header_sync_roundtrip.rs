//! Header synchronization integration tests.
use bitcoin::{
    BlockHash, TxMerkleNode,
    block::{Header as BlockHeader, Version},
    hashes::Hash as _,
    pow::CompactTarget,
};
use bitcoin_rs_chain::{BlockTree, ChainError, Network, accept_headers};

#[test]
fn accepts_valid_headers_across_batches_and_rejects_bad_bits()
-> Result<(), Box<dyn std::error::Error>> {
    let headers = mine_headers(100);
    let mut tree = BlockTree::new();

    let first = accept_headers(&mut tree, &headers[..40], Network::Regtest)?;
    let second = accept_headers(&mut tree, &headers[40..], Network::Regtest)?;

    assert_eq!(first.len(), 40);
    assert_eq!(second.len(), 60);
    let tip = tree.tip().ok_or("missing tip")?;
    assert_eq!(tip.height, 99);
    assert_eq!(
        tip.hash,
        tree.node(*second.last().ok_or("missing id")?)?.hash
    );

    let mut tampered = headers[0];
    tampered.bits = CompactTarget::from_consensus(0x2200_ffff);
    let err = match accept_headers(&mut BlockTree::new(), &[tampered], Network::Regtest) {
        Ok(_) => panic!("oversized target must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(err, ChainError::TargetExceedsLimit { .. }));

    Ok(())
}

fn mine_headers(count: u32) -> Vec<BlockHeader> {
    let mut headers = Vec::new();
    let mut prev = BlockHash::all_zeros();
    for height in 0..count {
        let header = mine_header(prev, height);
        prev = header.block_hash();
        headers.push(header);
    }
    headers
}

fn mine_header(prev_blockhash: BlockHash, height: u32) -> BlockHeader {
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    let mut header = BlockHeader {
        version: Version::ONE,
        prev_blockhash,
        merkle_root: TxMerkleNode::from_byte_array(merkle),
        time: height,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    while !header.target().is_met_by(header.block_hash()) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}
