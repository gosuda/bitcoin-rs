use super::*;

#[test]
fn decode_reservation_covers_live_parser_and_materialized_trees() -> Result<(), DecodeError> {
    let genesis = crate::Network::Regtest.genesis_block();
    for (transactions, inputs, outputs, witness_items) in [
        (1, 1, 1, 1),
        (100, 1, 1, 0),
        (1, 200, 300, 10),
        (1, 1, 1, 100_000),
    ] {
        let mut block = genesis.clone();
        let mut tx = block.txs[0].clone();
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0; 1]; witness_items]);
        tx.inputs = vec![tx.inputs[0].clone(); inputs];
        tx.outputs = vec![tx.outputs[0].clone(); outputs];
        block.txs = vec![tx; transactions];
        let raw = crate::consensus_bytes(&block);
        let parsed = ParsedBlock::parse_exact(&raw)?;
        let decoded = parsed.materialize();
        let heap = raw.len() + decoded.retained_heap_bytes() + parsed.scratch_heap_bytes();
        assert!(heap <= decode_reservation(raw.len()), "{heap}");
        assert_eq!(crate::consensus_bytes(&decoded), raw);
    }
    assert_eq!(decode_reservation(usize::MAX), usize::MAX);
    Ok(())
}
