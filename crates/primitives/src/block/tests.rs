use super::Block;
use crate::deserialize;
use crate::encode::DecodeError;

use crate::{BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid};

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

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

    assert_eq!(crate::encode::consensus_bytes(&block), bytes);
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
            crate::encode::consensus_bytes(&block).len(),
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

fn witness_tx(witness: crate::Witness) -> Tx {
    Tx {
        version: 2,
        lock_time: crate::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0_u8; 32])), 0),
            script_sig: crate::Script::new(),
            sequence: crate::Sequence::MAX,
            witness,
        }],
        outputs: vec![TxOut {
            value: crate::Amount::from_sat(50_000),
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
            bits: crate::CompactTarget::from_consensus(0x207f_ffff),
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
    let total = crate::encode::consensus_bytes(&block).len();
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
    let block = block_with_tx(witness_tx(crate::Witness::new()));
    assert_eq!(
        block.stripped_size(),
        crate::encode::consensus_bytes(&block).len()
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
                            + input.witness.capacity() * core::mem::size_of::<Vec<u8>>()
                            + input.witness.iter().map(Vec::capacity).sum::<usize>()
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
                            + input.witness.capacity() * core::mem::size_of::<Vec<u8>>()
                            + input.witness.iter().map(Vec::capacity).sum::<usize>()
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

    if core::mem::size_of::<usize>() == 8 {
        assert_eq!(block.retained_heap_bytes(), 1_109_823);
    }
    Ok(())
}

#[test]
fn retained_heap_bytes_synthetic_witness_heavy_capacity_variations() {
    let mut script_sig_0 = Vec::with_capacity(60);
    script_sig_0.extend_from_slice(&[0xaa; 10]);

    let mut wit_item_0 = Vec::with_capacity(128);
    wit_item_0.extend_from_slice(&[0x01; 32]);
    let mut wit_item_1 = Vec::with_capacity(256);
    wit_item_1.extend_from_slice(&[0x02; 64]);
    let mut witness_stack_0 = Vec::with_capacity(4);
    witness_stack_0.push(wit_item_0);
    witness_stack_0.push(wit_item_1);

    let mut wit_item_2 = Vec::with_capacity(80);
    wit_item_2.extend_from_slice(&[0x03; 33]);
    let mut witness_stack_1 = Vec::with_capacity(3);
    witness_stack_1.push(wit_item_2);

    let mut inputs = Vec::with_capacity(5);
    inputs.push(TxIn {
        previous_output: OutPoint::default(),
        script_sig: crate::Script::from_bytes(script_sig_0),
        sequence: crate::Sequence::MAX,
        witness: crate::Witness::from_stack(witness_stack_0),
    });
    inputs.push(TxIn {
        previous_output: OutPoint::default(),
        script_sig: crate::Script::new(),
        sequence: crate::Sequence::MAX,
        witness: crate::Witness::from_stack(witness_stack_1),
    });

    let mut spk_0 = Vec::with_capacity(75);
    spk_0.extend_from_slice(&[0x51; 34]);
    let mut spk_1 = Vec::with_capacity(110);
    spk_1.extend_from_slice(&[0x00; 22]);
    let mut outputs = Vec::with_capacity(4);
    outputs.push(TxOut {
        value: crate::Amount::from_sat(50_000),
        script_pubkey: crate::Script::from_bytes(spk_0),
    });
    outputs.push(TxOut {
        value: crate::Amount::from_sat(60_000),
        script_pubkey: crate::Script::from_bytes(spk_1),
    });

    let tx = Tx {
        version: 2,
        inputs,
        outputs,
        lock_time: crate::LockTime::ZERO,
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
    let expected_input_0_scripts = 60 + 4 * core::mem::size_of::<Vec<u8>>() + 128 + 256;
    let expected_input_1_scripts = 3 * core::mem::size_of::<Vec<u8>>() + 80;
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
fn payload_from_raw_retains_exact_fixture_bytes() -> Result<()> {
    use super::BlockPayload;

    let bytes = read_test_fixture("363731.bin")?;
    let payload = BlockPayload::from_raw(bytes::Bytes::from(bytes.clone()))?;

    assert_eq!(payload.bytes().as_ref(), bytes.as_slice());
    assert_eq!(payload.block(), &deserialize::<Block>(&bytes)?);
    assert_eq!(crate::encode::consensus_bytes(payload.block()), bytes);
    assert_eq!(payload.into_block(), deserialize::<Block>(&bytes)?);
    Ok(())
}

#[test]
fn payload_from_raw_rejects_trailing_bytes() -> Result<()> {
    use super::BlockPayload;

    let mut bytes = read_test_fixture("0.bin")?;
    assert!(BlockPayload::from_raw(bytes::Bytes::from(bytes.clone())).is_ok());
    bytes.push(0xFF);

    assert!(
        matches!(
            BlockPayload::from_raw(bytes::Bytes::from(bytes)),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        ),
        "exactly one trailing byte must be rejected"
    );
    Ok(())
}

#[test]
fn payload_from_raw_rejects_malformed_bytes() {
    use super::BlockPayload;

    assert!(
        matches!(
            BlockPayload::from_raw(bytes::Bytes::new()),
            Err(DecodeError::EndOfData { .. })
        ),
        "empty input must fail, not decode to a default block"
    );
    assert!(
        matches!(
            BlockPayload::from_raw(bytes::Bytes::from(vec![0x01_u8; 100])),
            Err(DecodeError::EndOfData { .. })
        ),
        "truncated body must fail instead of materializing a short block"
    );
}

#[test]
fn payload_from_prefix_returns_consumed_and_discards_remainder() -> Result<()> {
    use super::BlockPayload;

    let mut bytes = read_test_fixture("0.bin")?;
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE]);

    let (payload, consumed) = BlockPayload::from_prefix(bytes::Bytes::from(bytes.clone()))?;

    assert_eq!(consumed, bytes.len() - 3);
    assert_eq!(payload.bytes().as_ref(), &bytes[..consumed]);
    assert_eq!(payload.block(), &deserialize::<Block>(&bytes[..consumed])?);
    assert_eq!(payload.bytes().len(), consumed);

    let mut padded = read_test_fixture("0.bin")?;
    padded.extend_from_slice(&vec![0xA5; 1 << 20]);
    let (payload, consumed) = BlockPayload::from_prefix(bytes::Bytes::from(padded.clone()))?;
    assert_eq!(consumed, padded.len() - (1 << 20));
    assert_eq!(payload.bytes().len(), consumed);
    assert_eq!(payload.bytes().as_ref(), &padded[..consumed]);

    let exact = read_test_fixture("363731.bin")?;
    let exact_len = exact.len();
    let (payload, consumed) = BlockPayload::from_prefix(bytes::Bytes::from(exact.clone()))?;
    assert_eq!(consumed, exact_len);
    assert_eq!(payload.bytes().as_ref(), exact.as_slice());
    Ok(())
}

#[test]
fn payload_from_local_encodes_witness_block_exactly() -> Result<()> {
    use super::BlockPayload;

    let block = block_with_tx(witness_tx(
        vec![vec![0x21_u8; 64], vec![0x03_u8; 33]].into(),
    ));
    let payload = BlockPayload::from_local(block.clone());

    let expected = crate::encode::consensus_bytes(&block);
    assert_eq!(payload.bytes().as_ref(), expected.as_slice());
    assert_eq!(payload.block(), &block);
    assert!(
        payload.bytes().windows(64).any(|w| w == [0x21_u8; 64]),
        "retained bytes must carry the full witness item"
    );
    let roundtrip = BlockPayload::from_raw(payload.bytes().clone())?;
    assert_eq!(roundtrip.block(), &block);
    assert_eq!(roundtrip.bytes(), payload.bytes());
    Ok(())
}

#[test]
fn payload_witness_identity_is_byte_exact_not_txid_only() {
    use super::BlockPayload;

    let left = block_with_tx(witness_tx(vec![vec![0x11_u8; 32]].into()));
    let right = block_with_tx(witness_tx(vec![vec![0x22_u8; 32]].into()));
    assert_eq!(left.txs[0].txid(), right.txs[0].txid());

    let left_payload = BlockPayload::from_local(left.clone());
    let right_payload = BlockPayload::from_local(right.clone());
    assert_ne!(
        left_payload.bytes().as_ref(),
        right_payload.bytes().as_ref()
    );
    assert_ne!(left_payload.block(), right_payload.block());
    assert_eq!(left_payload.block(), &left);
    assert_eq!(right_payload.block(), &right);
}
