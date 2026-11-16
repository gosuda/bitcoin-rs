use super::Block;
use super::BlockImage;
use crate::primitives::deserialize;
use crate::primitives::encode::DecodeError;

use crate::primitives::{BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid};

use crate::primitives::test_error::TestError;

type Result<T, E = TestError> = std::result::Result<T, E>;

#[test]
fn genesis_block_hash_matches_known_value() -> Result<()> {
    let bytes = std::fs::read("tests/testdata/0.bin")?;
    let block = deserialize::<Block>(&bytes)?;

    assert_eq!(
        block.block_hash(),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".parse::<BlockHash>()?
    );
    Ok(())
}

#[test]
fn fixture_block_reencodes_and_hashes_to_published_id() -> Result<()> {
    let bytes = std::fs::read("tests/testdata/363731.bin")?;
    let block = deserialize::<Block>(&bytes)?;

    assert_eq!(crate::primitives::encode::consensus_bytes(&block), bytes);
    assert_eq!(
        block.block_hash(),
        "00000000000000000c28e23330c29046f19e817fe8fe039f4044b2b2882aef53".parse::<BlockHash>()?
    );
    Ok(())
}

#[test]
fn size_and_weight_match_serialized_bytes_and_pinned_weights() -> Result<()> {
    let cases: &[(&str, usize, usize, u64)] = &[
        ("tests/testdata/0.bin", 285, 285, 1140),
        ("tests/testdata/363731.bin", 749_141, 749_141, 2_996_564),
    ];
    for (fixture, total, stripped, weight) in cases {
        let bytes = std::fs::read(fixture)?;
        let block = deserialize::<Block>(&bytes)?;

        assert_eq!(block.total_size(), bytes.len(), "{fixture}");
        assert_eq!(
            crate::primitives::encode::consensus_bytes(&block).len(),
            bytes.len(),
            "{fixture}"
        );
        assert_eq!(block.total_size(), *total, "{fixture}");
        assert_eq!(block.stripped_size(), *stripped, "{fixture}");
        assert_eq!(block.weight(), *weight, "{fixture}");
        assert_eq!(
            block.weight(),
            u64::try_from(block.stripped_size())?
                .saturating_mul(3)
                .saturating_add(u64::try_from(block.total_size())?),
            "{fixture}"
        );
    }
    Ok(())
}

fn witness_tx(witness: crate::primitives::Witness) -> Tx {
    Tx {
        version: 2,
        lock_time: crate::primitives::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0_u8; 32])), 0),
            script_sig: crate::primitives::Script::new(),
            sequence: crate::primitives::Sequence::MAX,
            witness,
        }],
        outputs: vec![TxOut {
            value: crate::primitives::Amount::from_sat(50_000),
            script_pubkey: vec![0x51].into(),
        }],
    }
}

fn block_with_tx(tx: Tx) -> Block {
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_700_000_000,
            bits: crate::primitives::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: vec![tx],
    }
}

#[test]
fn stripped_size_drops_witness_and_matches_header_plus_base_transactions() {
    let block = block_with_tx(witness_tx(
        vec![vec![0x21_u8; 64], vec![0x03_u8; 33]].into(),
    ));
    let total = crate::primitives::encode::consensus_bytes(&block).len();
    let stripped = block.stripped_size();
    assert!(
        stripped < total,
        "the witness discount must be visible: {stripped} vs {total}"
    );
    let manual: usize = 80 + 1 + block.txs.iter().map(Tx::base_size).sum::<usize>();
    assert_eq!(stripped, manual);
}

#[test]
fn stripped_size_equals_total_size_without_witness() {
    let block = block_with_tx(witness_tx(crate::primitives::Witness::new()));
    assert_eq!(
        block.stripped_size(),
        crate::primitives::encode::consensus_bytes(&block).len()
    );
    assert_eq!(block.stripped_size(), block.total_size());
}

#[test]
fn block_decode_rejects_trailing_bytes() -> Result<()> {
    let mut bytes = std::fs::read("tests/testdata/0.bin")?;
    assert!(deserialize::<Block>(&bytes).is_ok());
    bytes.push(0xFF);

    assert_eq!(
        deserialize::<Block>(&bytes),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
    Ok(())
}

fn read_test_fixture(name: &str) -> Result<Vec<u8>> {
    let local = format!("tests/testdata/{name}");
    if let Ok(bytes) = std::fs::read(&local) {
        return Ok(bytes);
    }
    let manifest = format!("{}/tests/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    Ok(std::fs::read(manifest)?)
}

#[test]
fn retained_heap_bytes_empty_and_excess_txs_capacity() {
    assert_eq!(Block::default().retained_heap_bytes(), 0);

    let mut block = Block::default();
    block.txs.reserve_exact(10);
    assert_eq!(block.retained_heap_bytes(), 10 * core::mem::size_of::<Tx>());
}

#[test]
fn retained_heap_bytes_genesis_fixture_matches_independent_calculation() -> Result<()> {
    let bytes = read_test_fixture("0.bin")?;
    let block = deserialize::<Block>(&bytes)?;

    let independent = block.txs.capacity() * core::mem::size_of::<Tx>()
        + block
            .txs
            .iter()
            .map(|tx| {
                let in_caps = tx.inputs.capacity() * core::mem::size_of::<TxIn>();
                let out_caps = tx.outputs.capacity() * core::mem::size_of::<TxOut>();
                let in_payloads: usize = tx
                    .inputs
                    .iter()
                    .map(|input| {
                        input.script_sig.capacity()
                            + input.witness.len() * core::mem::size_of::<u32>()
                            + input.witness.iter().map(<[u8]>::len).sum::<usize>()
                    })
                    .sum();
                let out_payloads: usize = tx
                    .outputs
                    .iter()
                    .map(|output| output.script_pubkey.capacity())
                    .sum();
                in_caps + out_caps + in_payloads + out_payloads
            })
            .sum::<usize>();

    assert_eq!(block.retained_heap_bytes(), independent);

    let expected_literal = core::mem::size_of::<Tx>()
        + core::mem::size_of::<TxIn>()
        + core::mem::size_of::<TxOut>()
        + 77
        + 67;
    assert_eq!(block.retained_heap_bytes(), expected_literal);
    Ok(())
}

#[test]
fn retained_heap_bytes_fixture_363731_matches_independent_calculation() -> Result<()> {
    let bytes = read_test_fixture("363731.bin")?;
    let block = deserialize::<Block>(&bytes)?;

    let independent = block.txs.capacity() * core::mem::size_of::<Tx>()
        + block
            .txs
            .iter()
            .map(|tx| {
                let in_caps = tx.inputs.capacity() * core::mem::size_of::<TxIn>();
                let out_caps = tx.outputs.capacity() * core::mem::size_of::<TxOut>();
                let in_payloads: usize = tx
                    .inputs
                    .iter()
                    .map(|input| {
                        input.script_sig.capacity()
                            + input.witness.len() * core::mem::size_of::<u32>()
                            + input.witness.iter().map(<[u8]>::len).sum::<usize>()
                    })
                    .sum();
                let out_payloads: usize = tx
                    .outputs
                    .iter()
                    .map(|output| output.script_pubkey.capacity())
                    .sum();
                in_caps + out_caps + in_payloads + out_payloads
            })
            .sum::<usize>();

    assert_eq!(block.retained_heap_bytes(), independent);

    Ok(())
}

#[test]
fn retained_heap_bytes_synthetic_witness_heavy_capacity_variations() {
    let mut script_sig_0 = Vec::with_capacity(60);
    script_sig_0.extend_from_slice(&[0xaa; 10]);

    let mut witness_0 = crate::primitives::Witness::with_capacity(4, 300);
    witness_0.push(&[0x01; 32]);
    witness_0.push(&[0x02; 64]);

    let mut witness_1 = crate::primitives::Witness::with_capacity(3, 80);
    witness_1.push(&[0x03; 33]);

    let mut inputs = Vec::with_capacity(5);
    inputs.push(TxIn {
        previous_output: OutPoint::default(),
        script_sig: crate::primitives::Script::from_bytes(script_sig_0),
        sequence: crate::primitives::Sequence::MAX,
        witness: witness_0,
    });
    inputs.push(TxIn {
        previous_output: OutPoint::default(),
        script_sig: crate::primitives::Script::new(),
        sequence: crate::primitives::Sequence::MAX,
        witness: witness_1,
    });

    let mut spk_0 = Vec::with_capacity(75);
    spk_0.extend_from_slice(&[0x51; 34]);
    let mut spk_1 = Vec::with_capacity(110);
    spk_1.extend_from_slice(&[0x00; 22]);
    let mut outputs = Vec::with_capacity(4);
    outputs.push(TxOut {
        value: crate::primitives::Amount::from_sat(50_000),
        script_pubkey: crate::primitives::Script::from_bytes(spk_0),
    });
    outputs.push(TxOut {
        value: crate::primitives::Amount::from_sat(60_000),
        script_pubkey: crate::primitives::Script::from_bytes(spk_1),
    });

    let tx = Tx {
        version: 2,
        inputs,
        outputs,
        lock_time: crate::primitives::LockTime::ZERO,
    };

    let mut txs = Vec::with_capacity(3);
    txs.push(tx);

    let mut block = Block {
        header: Header::default(),
        txs,
    };

    let expected_txs_buf = 3 * core::mem::size_of::<Tx>();
    let expected_inputs_buf = 5 * core::mem::size_of::<TxIn>();
    let expected_outputs_buf = 4 * core::mem::size_of::<TxOut>();
    let expected_input_0_scripts = 60 + 4 * core::mem::size_of::<u32>() + 300;
    let expected_input_1_scripts = 3 * core::mem::size_of::<u32>() + 80;
    let expected_output_scripts = 75 + 110;

    let expected_tx = expected_inputs_buf
        + expected_outputs_buf
        + expected_input_0_scripts
        + expected_input_1_scripts
        + expected_output_scripts;
    let expected_block = expected_txs_buf + expected_tx;

    assert_eq!(block.txs[0].retained_heap_bytes(), expected_tx);
    assert_eq!(block.retained_heap_bytes(), expected_block);

    block.txs.reserve_exact(7);
    let extra_txs_cap = block.txs.capacity() - 3;
    let expected_after_reserve = expected_block + extra_txs_cap * core::mem::size_of::<Tx>();
    assert_eq!(block.retained_heap_bytes(), expected_after_reserve);
}

#[test]
fn image_from_raw_retains_exact_fixture_bytes() -> Result<()> {
    use super::BlockImage;

    let bytes = read_test_fixture("363731.bin")?;
    let payload = BlockImage::from_raw(bytes::Bytes::from(bytes.clone()))?;

    assert_eq!(payload.bytes().as_ref(), bytes.as_slice());
    assert_eq!(payload.materialize(), deserialize::<Block>(&bytes)?);
    assert_eq!(
        crate::primitives::encode::consensus_bytes(&payload.materialize()),
        bytes
    );
    assert_eq!(payload.into_block(), deserialize::<Block>(&bytes)?);
    Ok(())
}

#[test]
fn image_from_raw_rejects_trailing_bytes() -> Result<()> {
    use super::BlockImage;

    let mut bytes = read_test_fixture("0.bin")?;
    assert!(BlockImage::from_raw(bytes::Bytes::from(bytes.clone())).is_ok());
    bytes.push(0xFF);

    assert!(
        matches!(
            BlockImage::from_raw(bytes::Bytes::from(bytes)),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        ),
        "exactly one trailing byte must be rejected"
    );
    Ok(())
}

#[test]
fn image_from_raw_rejects_malformed_bytes() {
    use super::BlockImage;

    assert!(
        matches!(
            BlockImage::from_raw(bytes::Bytes::new()),
            Err(DecodeError::EndOfData { .. })
        ),
        "empty input must fail, not decode to a default block"
    );
    assert!(
        matches!(
            BlockImage::from_raw(bytes::Bytes::from(vec![0x01_u8; 100])),
            Err(DecodeError::EndOfData { .. })
        ),
        "truncated body must fail instead of materializing a short block"
    );
}

#[test]
fn image_from_prefix_returns_consumed_and_discards_remainder() -> Result<()> {
    use super::BlockImage;

    let mut bytes = read_test_fixture("0.bin")?;
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE]);

    let (payload, consumed) = BlockImage::from_prefix(bytes::Bytes::from(bytes.clone()))?;

    assert_eq!(consumed, bytes.len() - 3);
    assert_eq!(payload.bytes().as_ref(), &bytes[..consumed]);
    assert_eq!(consumed, 285, "the pinned genesis fixture length");
    assert_eq!(payload.bytes().len(), consumed);

    let mut padded = read_test_fixture("0.bin")?;
    padded.extend_from_slice(&vec![0xA5; 1 << 20]);
    let (payload, consumed) = BlockImage::from_prefix(bytes::Bytes::from(padded.clone()))?;
    assert_eq!(consumed, padded.len() - (1 << 20));
    assert_eq!(payload.bytes().len(), consumed);
    assert_eq!(payload.bytes().as_ref(), &padded[..consumed]);

    let exact = read_test_fixture("363731.bin")?;
    let exact_len = exact.len();
    let (payload, consumed) = BlockImage::from_prefix(bytes::Bytes::from(exact.clone()))?;
    assert_eq!(consumed, exact_len);
    assert_eq!(payload.bytes().as_ref(), exact.as_slice());
    Ok(())
}

#[test]
fn image_from_local_encodes_witness_block_exactly() -> Result<()> {
    use super::BlockImage;

    const GOLDEN: &str = concat!(
        "01000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "00f15365",
        "ffff7f20",
        "00000000",
        "01",
        "02000000",
        "0001",
        "01",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000",
        "00",
        "ffffffff",
        "01",
        "50c3000000000000",
        "0151",
        "02",
        "40",
        "2121212121212121212121212121212121212121212121212121212121212121",
        "2121212121212121212121212121212121212121212121212121212121212121",
        "21",
        "0303030303030303030303030303030303030303030303030303030303030303",
        "03",
        "00000000",
    );

    let block = block_with_tx(witness_tx(
        vec![vec![0x21_u8; 64], vec![0x03_u8; 33]].into(),
    ));
    let payload = BlockImage::from_local(block.clone());

    let expected: Vec<u8> = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(GOLDEN)
        .unwrap_or_else(|error| panic!("golden fixture hex: {error}"));
    assert_eq!(payload.bytes().as_ref(), expected.as_slice());
    assert_eq!(payload.materialize(), block);
    assert!(
        payload.bytes().windows(64).any(|w| w == [0x21_u8; 64]),
        "retained bytes must carry the full witness item"
    );
    let roundtrip = BlockImage::from_raw(payload.bytes().clone())?;
    assert_eq!(roundtrip.materialize(), block);
    assert_eq!(roundtrip.bytes(), payload.bytes());
    Ok(())
}

#[test]
fn image_witness_identity_is_byte_exact_not_txid_only() {
    use super::BlockImage;

    let left = block_with_tx(witness_tx(vec![vec![0x11_u8; 32]].into()));
    let right = block_with_tx(witness_tx(vec![vec![0x22_u8; 32]].into()));
    assert_eq!(left.txs[0].txid(), right.txs[0].txid());

    let left_payload = BlockImage::from_local(left.clone());
    let right_payload = BlockImage::from_local(right.clone());
    assert_ne!(
        left_payload.bytes().as_ref(),
        right_payload.bytes().as_ref()
    );
    assert_ne!(left_payload.materialize(), right_payload.materialize());
    assert_eq!(left_payload.materialize(), left);
    assert_eq!(right_payload.materialize(), right);
}

// BLK-02, BLK-03
#[test]
fn block_image_from_raw_rejects_malformed_and_truncated_bytes() -> Result<()> {
    use super::BlockImage;

    assert!(matches!(
        BlockImage::from_raw(bytes::Bytes::new()),
        Err(DecodeError::EndOfData { .. })
    ));

    assert!(matches!(
        BlockImage::from_raw(bytes::Bytes::from(vec![0u8; 79])),
        Err(DecodeError::EndOfData { .. })
    ));

    let mut trailing = read_test_fixture("0.bin")?;
    trailing.push(0xEE);
    assert!(matches!(
        BlockImage::from_raw(bytes::Bytes::from(trailing)),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    ));

    let golden = read_test_fixture("481824.bin")?;
    let mut corrupted_flag = golden.clone();
    let mut replaced = false;
    let mut cursor = 81;
    while cursor + 1 < corrupted_flag.len() {
        if corrupted_flag[cursor] == 0x00 && corrupted_flag[cursor + 1] == 0x01 {
            corrupted_flag[cursor + 1] = 0x02;
            replaced = true;
            break;
        }
        cursor += 1;
    }
    assert!(replaced);
    assert!(matches!(
        BlockImage::from_raw(bytes::Bytes::from(corrupted_flag)),
        Err(DecodeError::InvalidSegwitFlag { got: 2 })
    ));

    Ok(())
}

// BLK-02, BLK-03
#[test]
fn block_image_from_prefix_consumes_exact_prefix() -> Result<()> {
    use super::BlockImage;

    let mut bytes = read_test_fixture("0.bin")?;
    let expected_len = bytes.len();
    bytes.extend_from_slice(&[0x11, 0x22, 0x33]);

    let (image, consumed) = BlockImage::from_prefix(bytes::Bytes::from(bytes.clone()))?;
    assert_eq!(consumed, expected_len);
    assert_eq!(image.bytes().len(), expected_len);
    assert_eq!(image.bytes().as_ref(), &bytes[..expected_len]);
    Ok(())
}

// BLK-02, BLK-05
#[test]
fn block_image_from_local_roundtrips_cleanly() -> Result<()> {
    use super::BlockImage;

    let block = block_with_tx(witness_tx(
        vec![vec![0x21_u8; 64], vec![0x03_u8; 33]].into(),
    ));
    let image = BlockImage::from_local(block.clone());

    let expected_bytes = crate::primitives::encode::consensus_bytes(&block);
    assert_eq!(image.bytes().as_ref(), expected_bytes.as_slice());
    assert_eq!(image.block_hash(), block.block_hash());
    assert_eq!(image.tx_count(), 1);
    assert_eq!(image.materialize(), block);
    assert!(image.has_witness());
    Ok(())
}

// BLK-05, BLK-06
#[test]
fn block_image_identities_and_views_distinct_domains() -> Result<()> {
    use super::BlockImage;

    let legacy_block = block_with_tx(witness_tx(crate::primitives::Witness::new()));
    let legacy_image = BlockImage::from_local(legacy_block.clone());
    assert!(!legacy_image.has_witness());
    assert_eq!(legacy_image.identity(0).wtxid(), None);
    assert_eq!(legacy_image.tx(0).wtxid().0, legacy_image.tx(0).txid().0);

    let segwit_block = block_with_tx(witness_tx(vec![vec![0xaa_u8; 32]].into()));
    let segwit_image = BlockImage::from_local(segwit_block.clone());
    assert!(segwit_image.has_witness());
    assert!(segwit_image.identity(0).wtxid().is_some());
    assert_eq!(
        segwit_image.identity(0).wtxid(),
        Some(segwit_image.tx(0).wtxid())
    );
    assert_ne!(segwit_image.tx(0).wtxid().0, segwit_image.tx(0).txid().0);
    Ok(())
}

fn rewrite_witness_items_in_place(
    image: &BlockImage,
    bytes: &mut [u8],
    mask: &mut [bool],
) -> Result<()> {
    for tx_layout in image.layout().txs() {
        for input_layout in tx_layout.inputs() {
            for item_layout in input_layout.witness_items() {
                let span = item_layout.item();
                let start = usize::try_from(span.start())?;
                let end = usize::try_from(span.end())?;
                mask[start..end].fill(true);
                for byte in &mut bytes[start..end] {
                    *byte = 0x5A;
                }
            }
        }
    }
    Ok(())
}

fn assert_transaction_views_match_except_witness(left: &BlockImage, right: &BlockImage) {
    assert_eq!(left.tx_count(), right.tx_count());
    for index in 0..left.tx_count() {
        let left_tx = left.tx(index);
        let right_tx = right.tx(index);
        assert_eq!(left_tx.identity().txid(), right_tx.identity().txid());
        assert_inputs_match_except_witness(&left_tx, &right_tx);
        assert_eq!(left_tx.output_count(), right_tx.output_count());
        for i in 0..left_tx.output_count() {
            assert_eq!(left_tx.output_value(i), right_tx.output_value(i));
            assert_eq!(left_tx.output_script(i), right_tx.output_script(i));
        }
    }
}

fn assert_inputs_match_except_witness(
    left: &crate::primitives::TransactionView<'_>,
    right: &crate::primitives::TransactionView<'_>,
) {
    assert_eq!(left.input_count(), right.input_count());
    for i in 0..left.input_count() {
        assert_eq!(left.input_outpoint(i), right.input_outpoint(i));
    }
}

// BLK-07
#[test]
fn utxo_and_fact_inputs_ignore_witness_bytes() -> Result<()> {
    use crate::block_view::BlockFacts;

    let golden = read_test_fixture("481824.bin")?;
    let witness_image = BlockImage::from_raw(bytes::Bytes::from(golden.clone()))?;

    let mut witness_mask = vec![false; witness_image.bytes().len()];
    let mut rewritten = golden;
    rewrite_witness_items_in_place(&witness_image, &mut rewritten, &mut witness_mask)?;
    let rewritten_image = BlockImage::from_raw(bytes::Bytes::from(rewritten))?;

    let witness_facts = BlockFacts::from_image(&witness_image);
    let rewritten_facts = BlockFacts::from_image(&rewritten_image);
    assert_transaction_views_match_except_witness(&witness_image, &rewritten_image);
    assert_eq!(witness_facts.txids(), rewritten_facts.txids());
    assert_eq!(witness_facts.weight(), rewritten_facts.weight());
    assert_eq!(witness_facts.merkle_root(), rewritten_facts.merkle_root());
    assert_eq!(witness_facts.has_witness(), rewritten_facts.has_witness());
    assert_ne!(witness_facts.wtxids(), rewritten_facts.wtxids());
    assert_ne!(
        witness_image.bytes().as_ref(),
        rewritten_image.bytes().as_ref()
    );
    let differing = witness_image
        .bytes()
        .iter()
        .zip(rewritten_image.bytes().iter())
        .enumerate()
        .filter(|(_, (left, right))| left != right)
        .map(|(index, _)| index);
    for index in differing {
        assert!(
            witness_mask[index],
            "a byte outside witness spans changed under witness-only rewriting"
        );
    }
    Ok(())
}

// BLK-08
#[test]
fn long_lived_records_own_their_bytes_and_outlive_the_image() -> Result<()> {
    use crate::block_view::BlockFacts;
    use crate::primitives::layout::TxIdentity;

    const fn assert_unborrowed<T: 'static>() {}
    assert_unborrowed::<TxIdentity>();
    assert_unborrowed::<BlockFacts>();

    let golden = read_test_fixture("481824.bin")?;
    let facts;
    let identities: Vec<TxIdentity>;
    {
        let image = BlockImage::from_raw(bytes::Bytes::from(golden))?;
        facts = BlockFacts::from_image(&image);
        identities = image.identities().to_vec();
    }
    assert_eq!(facts.txids().len(), identities.len());
    let wtxids = facts.wtxids().ok_or("fixture block must carry witness")?;
    assert_eq!(wtxids.len(), identities.len());
    for (index, (identity, txid)) in identities.iter().zip(facts.txids()).enumerate() {
        assert_eq!(identity.txid(), *txid);
        match identity.wtxid() {
            Some(wtxid) => assert_eq!(wtxid, wtxids[index]),
            None => assert_eq!(wtxids[index].0, txid.0),
        }
    }
    Ok(())
}
