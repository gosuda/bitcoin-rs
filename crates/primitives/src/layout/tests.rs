use super::*;

#[test]
fn decode_heap_bound_covers_live_parser_and_materialized_trees() -> Result<(), DecodeError> {
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
        let mut heap = raw.len()
            + decoded.retained_heap_bytes()
            + parsed.txs.capacity() * core::mem::size_of::<ParsedTransaction<'_>>()
            + parsed.tx_spans.capacity() * core::mem::size_of::<ByteSpan>();
        for tx in &parsed.txs {
            heap += tx.inputs.capacity() * core::mem::size_of::<InputLayout>()
                + tx.outputs.capacity() * core::mem::size_of::<OutputLayout>()
                + tx.witness_spans.capacity() * core::mem::size_of::<ByteSpan>();
        }
        assert!(heap <= ParsedBlock::decode_heap_bound(raw.len()), "{heap}");
        assert_eq!(crate::consensus_bytes(&decoded), raw);
    }
    assert_eq!(ParsedBlock::decode_heap_bound(usize::MAX), usize::MAX);
    Ok(())
}
