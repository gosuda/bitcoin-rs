#![expect(
    clippy::expect_used,
    reason = "independent-oracle fixture construction"
)]

use bitcoin_rs_primitives::{BlockHash, CompactTarget, Hash256, Network};

use crate::{ChainError, ChainWork, NodeStatus, node::BlockHeader, validate_pow};

use super::compact_to_target;

fn header_with_bits(bits: u32) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 0,
        bits: CompactTarget::from_consensus(bits),
        nonce: 0,
    }
}

#[test]
fn compact_overflow_bits_are_rejected_like_core_derive_target() {
    let header = header_with_bits(0x2200_0101);
    let hash = Hash256::default();
    let network = Network::Regtest;

    assert!(
        compact_to_target(header.bits) <= network.max_target(),
        "the wrapped target must sit inside the regtest limit, so only Core's overflow rule can \
         reject this encoding"
    );

    assert_eq!(
        validate_pow(&header, hash, network),
        Err(ChainError::TargetExceedsLimit {
            hash,
            target: ChainWork::MAX,
            max_target: network.max_target(),
        }),
        "Bitcoin Core's SetCompact marks nBits 0x22000101 as overflowed (nSize 34 and nWord \
         0x0101 > 0xff) and CheckProofOfWork rejects every overflowed encoding as bad-diffbits; \
         an all-zero hash below the wrapped target must not pass validation"
    );
}

#[test]
fn overflow_bits_carry_no_chainwork() {
    let header = header_with_bits(0x2200_0101);
    assert_eq!(
        crate::block_work(&header),
        ChainWork::ZERO,
        "Bitcoin Core's GetBlockProof returns zero for an overflowed compact encoding \
         (fOverflow makes it return 0); the truncated target must not earn chainwork"
    );
}

#[test]
fn regtest_min_difficulty_bits_still_pass_and_insert() {
    let header = header_with_bits(0x207f_ffff);
    let hash = Hash256::default();
    assert_eq!(validate_pow(&header, hash, Network::Regtest), Ok(()));

    let mut chain = crate::BlockTree::new();
    let id = chain
        .insert_header(header, NodeStatus::HeaderValid)
        .expect("genesis header inserts");
    assert_eq!(chain.node(id).expect("inserted node").height, 0);
}
