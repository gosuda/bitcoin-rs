use super::*;

#[test]
fn reader_rejects_mutated_linkage_and_invalid_pow_or_nbits()
-> Result<(), Box<dyn std::error::Error>> {
    let (tree, best_tip_id, applied) = chain_with_applied_height(2, 1)?;
    let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

    let mut bad_prev = bytes.clone();
    bad_prev[headers::HEADER_PREFIX_LEN + 80 + 4] ^= 1;
    assert!(headers::read_headers(&mut Cursor::new(bad_prev), config(), written.metadata).is_err());

    let mut bad_pow = bytes.clone();
    let header_offset = headers::HEADER_PREFIX_LEN + 80;
    let mut invalid = header_from_row(&bad_pow[header_offset..header_offset + 80])?;
    while compact_is_met_by(invalid.bits, invalid.compute_hash().0) {
        invalid.nonce = invalid.nonce.checked_add(1).ok_or("nonce exhausted")?;
    }
    bad_pow[header_offset..header_offset + 80].copy_from_slice(&headers::encode_header(&invalid)?);
    assert!(headers::read_headers(&mut Cursor::new(bad_pow), config(), written.metadata).is_err());

    let mut bad_nbits = bytes;
    let previous = header_from_row(&bad_nbits[header_offset..header_offset + 80])?;
    let mut nbits_mismatch = Header {
        bits: CompactTarget::from_consensus(0x207f_fffe),
        ..previous
    };
    mine_header_to_declared_target(&mut nbits_mismatch)?;
    bad_nbits[header_offset..header_offset + 80]
        .copy_from_slice(&headers::encode_header(&nbits_mismatch)?);
    assert!(
        headers::read_headers(&mut Cursor::new(bad_nbits), config(), written.metadata).is_err()
    );
    Ok(())
}
