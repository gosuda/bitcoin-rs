//! Contract tests for the shared regtest fixture: declared-target mining,
//! merkle binding, determinism, and the script-num encoding the coinbases
//! rely on. Deterministic, no wire.

use bitcoin::Target;
use bitcoin::hashes::Hash;
use bitcoin::script::Builder;
use bitcoin_rs_chain::regtest_fixture::{self, REGTEST_BITS};
use bitcoin_rs_chain::validate_pow;
use bitcoin_rs_primitives::{BlockHash, Hash256, Network};

fn genesis_parent() -> BlockHash {
    BlockHash::from(Network::Regtest.genesis_block_hash())
}

#[test]
fn mined_child_meets_declared_target() -> Result<(), Box<dyn std::error::Error>> {
    let child = regtest_fixture::mined_regtest_child_at(genesis_parent(), 1)?;
    assert_eq!(
        child.header.version, 4,
        "fixture headers carry a version the shared contextual header gate accepts past the BIP34 height"
    );
    assert_eq!(child.header.bits.to_consensus(), REGTEST_BITS);
    let hash = child.block_hash();
    // Differential: the `bitcoin` crate's own target check, independent of
    // the `compact_is_met_by` path the fixture grinds with.
    let target = Target::from_compact(bitcoin::CompactTarget::from_consensus(
        child.header.bits.to_consensus(),
    ));
    assert!(
        target.is_met_by(bitcoin::BlockHash::from_byte_array(*hash.as_bytes())),
        "the bitcoin target oracle rejects the fixture proof of work"
    );
    validate_pow(&child.header, Hash256::from(hash), Network::Regtest)?;
    let script_sig = &child.txs[0].inputs[0].script_sig;
    let height_push = regtest_fixture::script_num_push(1);
    assert!(
        script_sig.as_bytes().starts_with(height_push.as_slice())
            && (2..=100).contains(&script_sig.as_bytes().len()),
        "the coinbase scriptSig must carry the height push inside the consensus 2..=100 range"
    );
    Ok(())
}

#[test]
fn mined_child_merkle_root_binds() -> Result<(), Box<dyn std::error::Error>> {
    let child = regtest_fixture::mined_regtest_child_at(genesis_parent(), 2)?;
    assert_eq!(
        Some(child.header.merkle_root),
        regtest_fixture::merkle_root(&child.txs),
        "the header merkle root must equal the fixture fold over the block's transactions"
    );
    let txids = child
        .txs
        .iter()
        .map(|tx| bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
    let root =
        bitcoin::merkle_tree::calculate_root(txids).ok_or("fixture block has transactions")?;
    assert_eq!(
        child.header.merkle_root,
        Hash256::from_le_bytes(root.as_byte_array()),
        "the fixture fold must agree with the bitcoin crate's merkle computation"
    );
    Ok(())
}

#[test]
fn grind_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let first = regtest_fixture::mined_regtest_child_at(genesis_parent(), 3)?;
    let second = regtest_fixture::mined_regtest_child_at(genesis_parent(), 3)?;
    assert_eq!(
        first.header, second.header,
        "grinding the same parent twice must produce byte-identical headers"
    );
    assert_eq!(first.block_hash(), second.block_hash());
    Ok(())
}

#[test]
fn script_num_push_matches_cscriptnum() {
    let cases: [(i64, &[u8]); 6] = [
        (0, &[0x00]),               // OP_0
        (1, &[0x51]),               // OP_1
        (16, &[0x60]),              // OP_16
        (127, &[0x01, 0x7f]),       // explicit one-byte push
        (128, &[0x02, 0x80, 0x00]), // sign byte keeps the magnitude positive
        (-1, &[0x4f]),              // OP_1NEGATE
    ];
    for (value, expected) in cases {
        assert_eq!(
            regtest_fixture::script_num_push(value).as_slice(),
            expected,
            "script-num push for {value}"
        );
    }
    // Differential: the `bitcoin` crate's own CScriptNum builder (the same
    // encoding `bitcoin_rs_script::push_int` and the BIP34 checker use).
    for (value, expected) in cases {
        let script = Builder::new().push_int(value).into_script();
        assert_eq!(
            script.as_bytes(),
            expected,
            "bitcoin Builder::push_int disagrees with the pinned encoding for {value}"
        );
        assert_eq!(
            regtest_fixture::script_num_push(value).as_slice(),
            script.as_bytes(),
            "bitcoin Builder::push_int disagrees with the fixture encoding for {value}"
        );
    }
}
