#![expect(
    clippy::expect_used,
    reason = "independent-oracle fixture construction"
)]

use bitcoin_rs_consensus::primitives::{BlockHash, CompactTarget, Hash256, Network};

use crate::chain::{ChainError, NodeStatus, validate_pow};
use bitcoin_rs_consensus::header_rules::{BlockHeader, ChainWork};

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
        Err(ChainError::TargetBitsOverflow {
            bits: header.bits.to_consensus(),
        }),
        "Bitcoin Core's SetCompact marks nBits 0x22000101 as overflowed (nSize 34 and nWord \
         0x0101 > 0xff) and CheckProofOfWork rejects every overflowed encoding as high-hash; \
         an all-zero hash below the wrapped target must not pass validation"
    );
}

#[test]
fn overflow_bits_are_reported_with_the_offending_nbits() {
    for bits in [0x2300_0001_u32, 0x2101_0000] {
        let header = header_with_bits(bits);
        assert_eq!(
            validate_pow(&header, Hash256::default(), Network::Regtest),
            Err(ChainError::TargetBitsOverflow { bits }),
            "Bitcoin Core v31.1 SetCompact (src/arith_uint256.cpp) sets fOverflow for nBits \
             {bits:08x} and CheckProofOfWork (src/pow.cpp) refuses every overflowed encoding \
             before the powLimit comparison, so the refusal must carry the offending nBits \
             instead of a placeholder target"
        );
    }
}

#[test]
fn core_set_compact_overflow_boundary_is_typed_not_placeholder() {
    use super::pow::compact_overflows;

    let near_boundary = header_with_bits(0x2100_ffff);
    assert!(
        !compact_overflows(near_boundary.bits),
        "nBits 0x2100ffff stays inside the 256-bit target at nSize 33 with nWord 0xffff, so \
         Core's SetCompact does not mark it overflowed"
    );
    let overflowing = header_with_bits(0x2101_0000);
    assert!(
        compact_overflows(overflowing.bits),
        "nBits 0x21010000 pushes nWord 0x10000 past 256 bits at nSize 33, as Core's SetCompact \
         marks it overflowed"
    );
}

#[test]
fn overflow_bits_carry_no_chainwork() {
    let header = header_with_bits(0x2200_0101);
    assert_eq!(
        crate::chain::block_work(&header),
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

    let mut chain = crate::chain::BlockTree::new();
    let id = chain
        .insert_header(header, NodeStatus::HeaderValid)
        .expect("genesis header inserts");
    assert_eq!(chain.node(id).expect("inserted node").height, 0);
}

#[test]
fn every_core_overflow_clause_and_its_boundary_matches_set_compact() {
    use super::pow::compact_overflows;

    let overflow = |bits| compact_overflows(CompactTarget::from_consensus(bits));
    for (bits, clause) in [
        (0x2300_0001_u32, "nSize > 34"),
        (0x2200_0100, "nWord > 0xff and nSize > 33"),
        (0x2101_0000, "nWord > 0xffff and nSize > 32"),
    ] {
        assert!(overflow(bits), "nBits {bits:08x} overflows: {clause}");
        let network = Network::Regtest;
        let header = header_with_bits(bits);
        let hash = Hash256::default();
        assert_eq!(
            validate_pow(&header, hash, network),
            Err(ChainError::TargetBitsOverflow {
                bits: header.bits.to_consensus(),
            }),
            "Bitcoin Core v31.1 SetCompact (src/arith_uint256.cpp) marks nBits {bits:08x} as \
             overflowed under {clause}, so CheckProofOfWork answers high-hash"
        );
    }
    for (bits, boundary) in [
        (0x2200_00ff_u32, "nSize 34 with nWord 0xff"),
        (0x2100_ffff, "nSize 33 with nWord 0xffff"),
        (0x2001_0000, "nSize 32 with nWord 0x10000"),
    ] {
        assert!(
            !overflow(bits),
            "nBits {bits:08x} stays inside the 256-bit target at {boundary}"
        );
    }
}
