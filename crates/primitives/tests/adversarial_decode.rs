use bitcoin_rs_primitives::layout::ParsedTransaction;
use bitcoin_rs_primitives::varint::{self, VarintError};
use bitcoin_rs_primitives::{
    Amount, Block, ConsensusDecode, DecodeError, Header, LockTime, OutPoint, Sequence, Tx, TxIn,
    TxOut, Txid, Witness, consensus_bytes, deserialize,
};

fn dummy_tx() -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), 0),
            script_sig: vec![0x51].into(),
            sequence: Sequence::from_consensus(0xffff_fffe),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: vec![0x51].into(),
        }],
        lock_time: LockTime::from_consensus(100),
    }
}

#[test]
fn rejects_noncanonical_varint_prefix_fd_boundaries() {
    assert_eq!(
        varint::decode(&[0xfd, 0x00, 0x00]),
        Err(VarintError::NonCanonical { value: 0 })
    );
    assert_eq!(
        varint::decode(&[0xfd, 0x01, 0x00]),
        Err(VarintError::NonCanonical { value: 1 })
    );
    assert_eq!(
        varint::decode(&[0xfd, 0xfc, 0x00]),
        Err(VarintError::NonCanonical { value: 0xfc })
    );
    assert_eq!(varint::decode(&[0xfd, 0xfd, 0x00]), Ok((0xfd, 3)));
}

#[test]
fn rejects_noncanonical_varint_prefix_fe_boundaries() {
    assert_eq!(
        varint::decode(&[0xfe, 0x00, 0x00, 0x00, 0x00]),
        Err(VarintError::NonCanonical { value: 0 })
    );
    assert_eq!(
        varint::decode(&[0xfe, 0xff, 0xff, 0x00, 0x00]),
        Err(VarintError::NonCanonical { value: 0xffff })
    );
    assert_eq!(
        varint::decode(&[0xfe, 0x00, 0x00, 0x01, 0x00]),
        Ok((0x1_0000, 5))
    );
}

#[test]
fn rejects_noncanonical_varint_prefix_ff_boundaries() {
    assert_eq!(
        varint::decode(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        Err(VarintError::NonCanonical { value: 0 })
    );
    assert_eq!(
        varint::decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]),
        Err(VarintError::NonCanonical { value: 0xffff_ffff })
    );
    assert_eq!(
        varint::decode(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
        Ok((0x1_0000_0000, 9))
    );
}

#[test]
fn rejects_truncated_varints_at_all_lengths() {
    assert_eq!(
        varint::decode(&[]),
        Err(VarintError::Truncated {
            prefix: 0,
            needed: 1,
            available: 0,
        })
    );
    assert_eq!(
        varint::decode(&[0xfd]),
        Err(VarintError::Truncated {
            prefix: 0xfd,
            needed: 3,
            available: 1,
        })
    );
    assert_eq!(
        varint::decode(&[0xfe, 0x01, 0x02]),
        Err(VarintError::Truncated {
            prefix: 0xfe,
            needed: 5,
            available: 3,
        })
    );
    assert_eq!(
        varint::decode(&[0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
        Err(VarintError::Truncated {
            prefix: 0xff,
            needed: 9,
            available: 7,
        })
    );
}

#[test]
fn rejects_noncanonical_varint_in_tx_input_count() {
    let mut raw = 1_i32.to_le_bytes().to_vec();
    raw.extend_from_slice(&[0xfd, 0x01, 0x00]);
    assert!(matches!(
        deserialize::<Tx>(&raw),
        Err(DecodeError::Varint(VarintError::NonCanonical { value: 1 }))
    ));
}

#[test]
fn rejects_noncanonical_varint_in_tx_output_count() {
    let tx = dummy_tx();
    let valid_bytes = consensus_bytes(&tx);
    let mut corrupted = valid_bytes[..47].to_vec();
    corrupted.extend_from_slice(&[0xfd, 0x01, 0x00]);
    assert!(matches!(
        deserialize::<Tx>(&corrupted),
        Err(DecodeError::Varint(VarintError::NonCanonical { value: 1 }))
    ));
}

#[test]
fn rejects_noncanonical_varint_in_script_len() {
    let mut out_bytes = 100_u64.to_le_bytes().to_vec();
    out_bytes.extend_from_slice(&[0xfd, 0x02, 0x00, 0x51, 0x51]);
    let mut reader = out_bytes.as_slice();
    assert!(matches!(
        TxOut::consensus_decode(&mut reader),
        Err(DecodeError::Varint(VarintError::NonCanonical { value: 2 }))
    ));
}

#[test]
fn rejects_oversized_counts_without_allocation() {
    let mut raw = 1_i32.to_le_bytes().to_vec();
    raw.extend_from_slice(&[0xfe, 0x00, 0x00, 0x10, 0x00]);
    raw.extend_from_slice(&[0u8; 10]);
    assert!(matches!(
        deserialize::<Tx>(&raw),
        Err(DecodeError::EndOfData { .. })
    ));

    let mut block_raw = vec![0u8; 80];
    block_raw.extend_from_slice(&[0xfe, 0x00, 0x00, 0x10, 0x00]);
    block_raw.extend_from_slice(&[0u8; 10]);
    assert!(matches!(
        deserialize::<Block>(&block_raw),
        Err(DecodeError::EndOfData { .. })
    ));
}

#[test]
fn rejects_max_u64_count_without_panic() {
    let mut raw = 1_i32.to_le_bytes().to_vec();
    raw.extend_from_slice(&[0xff; 9]);
    raw.extend_from_slice(&[0u8; 10]);
    assert!(matches!(
        deserialize::<Tx>(&raw),
        Err(DecodeError::EndOfData { .. })
    ));
}

#[test]
fn rejects_trailing_bytes_on_all_primitives() {
    let header_bytes = [0x55_u8; 80];
    let mut with_trailing = header_bytes.to_vec();
    with_trailing.push(0xab);
    assert_eq!(
        deserialize::<Header>(&with_trailing),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );

    let mut outpoint_bytes = [0x11_u8; 32].to_vec();
    outpoint_bytes.extend_from_slice(&0_u32.to_le_bytes());
    outpoint_bytes.push(0xab);
    assert_eq!(
        deserialize::<OutPoint>(&outpoint_bytes),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );

    let tx = dummy_tx();
    let mut tx_bytes = consensus_bytes(&tx);
    tx_bytes.extend_from_slice(&[0xaa, 0xbb]);
    assert_eq!(
        deserialize::<Tx>(&tx_bytes),
        Err(DecodeError::TrailingBytes { remaining: 2 })
    );

    let block = Block {
        header: Header::default(),
        txs: vec![tx],
    };
    let mut block_bytes = consensus_bytes(&block);
    block_bytes.push(0xff);
    assert_eq!(
        deserialize::<Block>(&block_bytes),
        Err(DecodeError::TrailingBytes { remaining: 1 })
    );
}

#[test]
fn rejects_invalid_segwit_flags() {
    let base = 2_i32.to_le_bytes().to_vec();
    for bad_flag in [0x02_u8, 0x03, 0x7f, 0x80, 0xff] {
        let mut raw = base.clone();
        raw.extend_from_slice(&[0x00, bad_flag]);
        assert_eq!(
            deserialize::<Tx>(&raw),
            Err(DecodeError::InvalidSegwitFlag { got: bad_flag })
        );
    }
}

#[test]
fn rejects_superfluous_witness_with_empty_witnesses() {
    let mut raw = 2_i32.to_le_bytes().to_vec();
    raw.extend_from_slice(&[0x00, 0x01]);
    raw.push(0x01);
    raw.extend_from_slice(&[0xaa; 32]);
    raw.extend_from_slice(&0_u32.to_le_bytes());
    raw.push(0x00);
    raw.extend_from_slice(&0xffff_ffff_u32.to_le_bytes());
    raw.push(0x00);
    raw.push(0x00);
    raw.extend_from_slice(&0_u32.to_le_bytes());

    assert_eq!(
        deserialize::<Tx>(&raw),
        Err(DecodeError::SuperfluousWitness)
    );
}

#[test]
fn accepts_segwit_tx_with_single_empty_witness_item() {
    let mut raw = 2_i32.to_le_bytes().to_vec();
    raw.extend_from_slice(&[0x00, 0x01]);
    raw.push(0x01);
    raw.extend_from_slice(&[0xaa; 32]);
    raw.extend_from_slice(&0_u32.to_le_bytes());
    raw.push(0x00);
    raw.extend_from_slice(&0xffff_ffff_u32.to_le_bytes());
    raw.push(0x00);
    raw.push(0x01);
    raw.push(0x00);
    raw.extend_from_slice(&0_u32.to_le_bytes());

    let parsed = ParsedTransaction::parse_exact(&raw);
    assert!(parsed.is_ok());
    let Ok(tx) = deserialize::<Tx>(&raw) else {
        panic!("must decode");
    };
    assert!(tx.has_witness());
    assert_eq!(tx.inputs[0].witness.len(), 1);
    assert_eq!(tx.inputs[0].witness[0].len(), 0);
}

#[test]
fn amount_constants_and_arithmetic_boundaries() {
    assert_eq!(Amount::ZERO.to_sat(), 0);
    assert_eq!(Amount::SAT.to_sat(), 1);
    assert_eq!(Amount::COIN.to_sat(), 100_000_000);
    assert_eq!(Amount::MAX_MONEY.to_sat(), 2_100_000_000_000_000);

    let limit = Amount::MAX_MONEY;
    let below = Amount::from_sat(limit.to_sat() - 1);
    let above = Amount::from_sat(limit.to_sat() + 1);

    assert!(below < limit);
    assert!(above > limit);
    assert_eq!(limit.saturating_add(Amount::SAT), above);
    assert_eq!(
        Amount::from_sat(u64::MAX).saturating_add(Amount::SAT),
        Amount::from_sat(u64::MAX)
    );
}

#[test]
fn locktime_and_sequence_constants_and_boundaries() {
    assert_eq!(bitcoin_rs_primitives::LOCKTIME_THRESHOLD, 500_000_000);
    assert_eq!(bitcoin_rs_primitives::SEQUENCE_FINAL, 0xffff_ffff);

    let height_bound = LockTime::from_consensus(499_999_999);
    let time_bound = LockTime::from_consensus(500_000_000);
    assert!(height_bound.to_consensus() < bitcoin_rs_primitives::LOCKTIME_THRESHOLD);
    assert!(time_bound.to_consensus() >= bitcoin_rs_primitives::LOCKTIME_THRESHOLD);

    let final_seq = Sequence::from_consensus(bitcoin_rs_primitives::SEQUENCE_FINAL);
    assert_eq!(final_seq, bitcoin_rs_primitives::SEQUENCE_FINAL);

    let disabled_seq =
        Sequence::from_consensus(bitcoin_rs_primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG | 0x0a);
    assert_ne!(
        disabled_seq & bitcoin_rs_primitives::SEQUENCE_LOCKTIME_DISABLE_FLAG,
        0
    );
}
