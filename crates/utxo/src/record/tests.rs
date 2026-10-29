use super::*;

fn output(vout: u32, script: &[u8], value: u64) -> OwnedUtxoOut {
    OwnedUtxoOut::new(vout, value, script.to_vec(), false, 1)
}

#[test]
fn codec_accepts_exact_script_length_limit() -> Result<(), UtxoError> {
    let script = vec![0xA5; usize::from(u16::MAX)];
    let record = UtxoRecord::from_owned_outputs(
        Hash256::default(),
        &[OwnedUtxoOut::new(64, 42, script.clone(), false, u32::MAX)],
    )?;
    let output = record.outputs().next().ok_or(UtxoError::CorruptRecord)?;
    assert_eq!(output.script_pubkey, script.as_slice());
    assert_eq!(record.output_count(), 1);
    Ok(())
}

#[test]
fn codec_keeps_canonical_metadata_and_zero_copy_script() -> Result<(), UtxoError> {
    let record = UtxoRecord::from_owned_outputs(
        Hash256::default(),
        &[OwnedUtxoOut::new(
            u32::MAX,
            42,
            vec![0x51, 0xAC],
            true,
            u32::MAX,
        )],
    )?;
    assert_eq!(
        record.payload_bytes(),
        RECORD_HEADER_LEN + 15,
        "v5 output layout changed"
    );
    let output = record.outputs().next().ok_or(UtxoError::CorruptRecord)?;
    assert_eq!(output.vout, u32::MAX);
    assert_eq!(output.value, 42);
    assert_eq!(output.height, u32::MAX);
    assert!(output.coinbase);
    assert_eq!(output.script_pubkey, &[0x51, 0xAC]);
    Ok(())
}

#[test]
fn encoded_len_matches_the_bytes_written() -> Result<(), UtxoError> {
    let script = vec![0x51; 300];
    let cases = [
        OwnedUtxoOut::new(0, 0, Vec::new(), false, 0),
        OwnedUtxoOut::new(1, 1, vec![0x51], false, 1),
        OwnedUtxoOut::new(127, 100_000_000, vec![0x00; 22], true, 840_000),
        OwnedUtxoOut::new(128, 2_099_999_999_999_999, script.clone(), false, 1_048_576),
        OwnedUtxoOut::new(u32::MAX, u64::MAX, script, true, u32::MAX),
    ];
    for case in cases {
        let payload = OutputParts::from_owned(&case).payload_len()?;
        let vout_width = width_for(u64::from(case.vout));
        let len_width = width_for(u64::try_from(payload).unwrap_or(u64::MAX));
        let expected = RECORD_HEADER_LEN + 1 + vout_width + len_width + payload;
        let record = UtxoRecord::from_owned_outputs(Hash256::default(), &[case])?;
        assert_eq!(
            record.payload_bytes(),
            expected,
            "payload_len disagreed with write_payload"
        );
    }
    Ok(())
}

#[test]
fn an_amount_above_the_money_supply_survives_the_escape() -> Result<(), UtxoError> {
    for value in [
        crate::compress::MAX_COMPRESSIBLE_AMOUNT + 1,
        u64::MAX / 2,
        u64::MAX,
    ] {
        let record = UtxoRecord::from_owned_outputs(
            Hash256::default(),
            &[OwnedUtxoOut::new(3, value, vec![0x51], false, 7)],
        )?;
        let output = record.outputs().next().ok_or(UtxoError::CorruptRecord)?;
        assert_eq!(output.value, value, "escaped amount did not round trip");
        assert_eq!(output.vout, 3);
        assert_eq!(output.height, 7);
    }
    Ok(())
}

#[test]
fn a_corrupt_encoded_record_is_refused() -> Result<(), UtxoError> {
    type Corrupt = fn(&mut Vec<u8>, usize);
    let record = UtxoRecord::from_owned_outputs(
        Hash256::default(),
        &[output(0, &[0x51], 1), output(1, &[0x52, 0xac], 2)],
    )?;
    let len_dir = record.layout()?.len_dir;
    let encoded = record.bytes().to_vec();

    let cases: [(&str, Corrupt); 10] = [
        ("metadata truncated", |bytes, _| {
            bytes.truncate(RECORD_HEADER_LEN + 2);
        }),
        ("script truncated", |bytes, _| {
            bytes.pop();
        }),
        ("trailing byte", |bytes, _| bytes.push(0)),
        ("output count above the outputs present", |bytes, _| {
            bytes[OUTPUT_COUNT_OFFSET..INLINE_LEN_OFFSET].copy_from_slice(&3_u32.to_le_bytes());
        }),
        ("zero width nibble", |bytes, _| bytes[WIDTHS_OFFSET] = 0x00),
        ("over-wide vout nibble", |bytes, _| {
            bytes[WIDTHS_OFFSET] = 0x05;
        }),
        ("over-wide length nibble", |bytes, _| {
            bytes[WIDTHS_OFFSET] = 0x50;
        }),
        ("both nibbles over-wide", |bytes, _| {
            bytes[WIDTHS_OFFSET] = 0xff;
        }),
        ("inline_len above the output count", |bytes, _| {
            bytes[INLINE_LEN_OFFSET] = 3;
        }),
        ("inline_len above INLINE_CAPACITY", |bytes, _| {
            bytes[INLINE_LEN_OFFSET] = 9;
        }),
    ];

    for (label, corrupt) in cases {
        let mut mutant = encoded.clone();
        corrupt(&mut mutant, len_dir);
        assert!(
            matches!(
                UtxoRecord::from_encoded(mutant.into_boxed_slice()),
                Err(UtxoError::CorruptRecord)
            ),
            "{label} was accepted"
        );
    }

    let mut lying_length = encoded;
    lying_length[len_dir] = 0xf0;
    assert!(matches!(
        UtxoRecord::from_encoded(lying_length.into_boxed_slice()),
        Err(UtxoError::CorruptRecord)
    ));
    Ok(())
}

#[test]
fn an_absurd_compressed_amount_is_rejected_rather_than_overflowing() {
    let mut payload = vec![0xFE_u8];
    payload.extend_from_slice(&[0xFF; 8]);
    payload.push(0x01);
    payload.extend_from_slice(&[0x02, 0x51, 0xAC]);

    let mut bytes = Hash256::default().to_le_bytes().to_vec();
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.push(1);
    bytes.push(0x11);
    bytes.push(0x00);
    bytes.push(u8::try_from(payload.len()).unwrap_or(0));
    bytes.extend_from_slice(&payload);

    assert!(matches!(
        UtxoRecord::from_encoded(bytes.clone().into_boxed_slice()),
        Err(UtxoError::CorruptRecord)
    ));
}

#[test]
fn non_canonical_v5_spellings_are_rejected() {
    fn record(vout_width: usize, len_width: usize, vout: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Hash256::default().to_le_bytes().to_vec();
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(1);
        let widths =
            (u8::try_from(len_width).unwrap_or(1) << 4) | u8::try_from(vout_width).unwrap_or(1);
        bytes.push(widths);
        bytes.extend_from_slice(&vout.to_le_bytes()[..vout_width]);
        let len = u64::try_from(payload.len()).unwrap_or(0);
        bytes.extend_from_slice(&len.to_le_bytes()[..len_width]);
        bytes.extend_from_slice(payload);
        bytes
    }

    let canonical = record(1, 1, 0, &[0x01, 0x02, 0x51, 0xAC]);
    assert!(
        UtxoRecord::from_encoded(canonical.into_boxed_slice()).is_ok(),
        "the canonical spelling must decode"
    );

    let non_minimal = record(1, 1, 0, &[0x81, 0x00, 0x02, 0x51, 0xAC]);
    assert!(matches!(
        UtxoRecord::from_encoded(non_minimal.into_boxed_slice()),
        Err(UtxoError::CorruptRecord)
    ));

    let mut escaped = [0xFF_u8; 9].to_vec();
    escaped.push(0x01);
    escaped.extend_from_slice(&1_u64.to_le_bytes());
    escaped.extend_from_slice(&[0x02, 0x51, 0xAC]);
    assert!(matches!(
        UtxoRecord::from_encoded(record(1, 1, 0, &escaped).into_boxed_slice()),
        Err(UtxoError::CorruptRecord)
    ));

    for (vout_width, len_width) in [(2, 1), (1, 2), (4, 4)] {
        let wide = record(vout_width, len_width, 0, &[0x01, 0x02, 0x51, 0xAC]);
        assert!(
            matches!(
                UtxoRecord::from_encoded(wide.clone().into_boxed_slice()),
                Err(UtxoError::CorruptRecord)
            ),
            "an over-wide {vout_width}/{len_width} directory was accepted"
        );
    }

    let mut oversize = vec![0x01, 0x02];
    oversize.extend_from_slice(&vec![0x51; 65_536]);
    assert!(matches!(
        UtxoRecord::from_encoded(record(1, 4, 0, &oversize).into_boxed_slice()),
        Err(UtxoError::CorruptRecord)
    ));
}

#[test]
fn rejected_staged_add_leaves_source_record_unchanged() -> Result<(), UtxoError> {
    let record = UtxoRecord::from_owned_outputs(Hash256::default(), &[output(0, &[0x51], 1)])?;
    let original = record.clone();
    let too_large = OwnedUtxoOut::new(1, 2, vec![0_u8; usize::from(u16::MAX) + 1], false, 1);
    let additions = [OutputParts::from_owned(&too_large)];
    for mut overwritten in [None, Some(Vec::new())] {
        assert!(matches!(
            UtxoRecord::add_run_replacement(
                Some(&record),
                record.txid(),
                &additions,
                true,
                overwritten.as_mut(),
            ),
            Err(UtxoError::ScriptTooLarge { .. })
        ));
    }
    assert_eq!(record, original);
    Ok(())
}

#[test]
fn deep_clone_is_independent_and_byte_equal() -> Result<(), UtxoError> {
    let record = UtxoRecord::from_owned_outputs(
        Hash256::from_le_bytes(&[0x11; TXID_LEN]),
        &[output(0, &[0x51], 1), output(1, &[0x6A, 0xAC], 2)],
    )?;
    let clone = record.clone();
    assert_eq!(clone, record);
    assert_eq!(clone.payload_bytes(), record.payload_bytes());
    drop(record);
    assert_eq!(clone.output_count(), 2);
    assert!(clone.find_output(1).is_some());
    Ok(())
}

#[test]
fn an_outputless_record_decodes_and_reports_empty() -> Result<(), UtxoError> {
    let record = UtxoRecord::from_owned_outputs(Hash256::default(), &[])?;
    assert!(record.is_empty());
    assert_eq!(record.output_count(), 0);
    assert_eq!(record.max_vout(), None);
    assert!(record.find_output(0).is_none());
    assert_eq!(record.outputs().len(), 0);
    let decoded = UtxoRecord::from_encoded(record.buf.clone())?;
    assert_eq!(decoded, record);
    let mut removed = Vec::new();
    assert!(matches!(
        record.remove_run_replacement(&[], Some(&mut removed))?,
        RemovedRecord::Emptied
    ));
    assert_eq!(removed, []);
    Ok(())
}

#[test]
fn removal_outcome_and_materialization_follow_the_request() -> Result<(), UtxoError> {
    type Case = (&'static [u32], Outcome, &'static [Option<u32>]);
    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Unchanged,
        Replaced(Vec<u32>),
        Emptied,
    }
    let record = UtxoRecord::from_owned_outputs(
        Hash256::default(),
        &[
            output(0, &[0x50], 10),
            output(1, &[0x51], 11),
            output(2, &[0x52], 12),
        ],
    )?;
    let cases: [Case; 8] = [
        (&[], Outcome::Unchanged, &[]),
        (&[9], Outcome::Unchanged, &[None]),
        (&[9, 8], Outcome::Unchanged, &[None, None]),
        (&[0, 9], Outcome::Replaced(vec![1, 2]), &[Some(0), None]),
        (
            &[0, 1, 9],
            Outcome::Replaced(vec![2]),
            &[Some(0), Some(1), None],
        ),
        (
            &[0, 0, 1],
            Outcome::Replaced(vec![2]),
            &[Some(0), None, Some(1)],
        ),
        (&[2, 0, 1], Outcome::Emptied, &[Some(2), Some(0), Some(1)]),
        (
            &[0, 1, 2, 9],
            Outcome::Emptied,
            &[Some(0), Some(1), Some(2), None],
        ),
    ];
    for (request, expected, materialized) in cases {
        let mut removed = Vec::new();
        let outcome = match record.remove_run_replacement(request, Some(&mut removed))? {
            RemovedRecord::Unchanged => Outcome::Unchanged,
            RemovedRecord::Replaced(replacement) => {
                let mut survivors: Vec<u32> = replacement.outputs().map(|out| out.vout).collect();
                survivors.sort_unstable();
                Outcome::Replaced(survivors)
            }
            RemovedRecord::Emptied => Outcome::Emptied,
        };
        assert_eq!(outcome, expected, "outcome for {request:?}");
        assert_eq!(
            removed
                .iter()
                .map(|out| out.as_ref().map(|kept| kept.vout))
                .collect::<Vec<_>>(),
            materialized,
            "materialized vouts for {request:?}"
        );
        for kept in removed.iter().flatten() {
            assert_eq!(
                kept.value,
                10 + u64::from(kept.vout),
                "materialized payload for {request:?}"
            );
        }
        let without_sink = record.remove_run_replacement(request, None)?;
        assert_eq!(
            matches!(without_sink, RemovedRecord::Emptied),
            matches!(expected, Outcome::Emptied),
            "sinkless outcome for {request:?}"
        );
    }
    Ok(())
}

#[test]
fn edit_replacement_fuses_removals_and_additions() -> Result<(), UtxoError> {
    type Addition = (u32, u64, &'static [u8], bool);
    type Case = (
        &'static str,
        &'static [u32],
        &'static [u32],
        Addition,
        &'static [(u32, u64)],
    );
    let cases: [Case; 4] = [
        (
            "an addition below the pre-removal max",
            &[0, 5],
            &[5],
            (3, 33, &[0x33], false),
            &[(0, 0), (3, 33)],
        ),
        (
            "an edit past full removal",
            &[0, 1],
            &[0, 1],
            (4, 44, &[0x44], true),
            &[(4, 44)],
        ),
        (
            "a duplicated remove request is not a full removal",
            &[0, 1, 2],
            &[0, 0, 1],
            (5, 55, &[0x55], false),
            &[(2, 2), (5, 55)],
        ),
        (
            "a re-add of a removed vout",
            &[0, 1],
            &[1],
            (1, 66, &[0x66, 0xac], false),
            &[(0, 0), (1, 66)],
        ),
    ];
    for (name, initial, removes, (vout, value, script, coinbase), survivors) in cases {
        let outputs: Vec<OwnedUtxoOut> = initial
            .iter()
            .map(|live| output(*live, &[0x50], u64::from(*live)))
            .collect();
        let record = UtxoRecord::from_owned_outputs(Hash256::default(), &outputs)?;
        let additions = [OutputParts::new(vout, value, script, coinbase, 1)];
        let RemovedRecord::Replaced(replacement) = record.edit_replacement(removes, &additions)?
        else {
            panic!("{name}: an edit with additions must be Replaced");
        };
        assert_eq!(
            replacement
                .outputs()
                .map(|out| (out.vout, out.value))
                .collect::<Vec<_>>(),
            survivors,
            "{name}: survivors"
        );
        let added = replacement
            .find_output(vout)
            .ok_or(UtxoError::CorruptRecord)?;
        assert_eq!(added.script_pubkey, script, "{name}: script");
        assert_eq!(added.coinbase, coinbase, "{name}: coinbase");
    }

    let record = UtxoRecord::from_owned_outputs(
        Hash256::default(),
        &[output(0, &[0x50], 5), output(1, &[0x51], 6)],
    )?;
    let additions = [OutputParts::new(7, 77, &[0x77], false, 3)];
    let RemovedRecord::Replaced(edited) = record.edit_replacement(&[], &additions)? else {
        panic!("an add-only edit must produce a replacement");
    };
    assert_eq!(
        edited,
        UtxoRecord::add_run_replacement(Some(&record), record.txid(), &additions, false, None)?
    );
    Ok(())
}

#[test]
fn add_with_an_unsaturated_inline_partition_falls_back_to_rebuild() -> Result<(), UtxoError> {
    let nine: Vec<OwnedUtxoOut> = (0..9)
        .map(|vout| output(vout, &[0x51], u64::from(vout)))
        .collect();
    let record = UtxoRecord::from_owned_outputs(Hash256::default(), &nine)?;
    let shrunk = match record.remove_run_replacement(&[0], None)? {
        RemovedRecord::Replaced(record) => record,
        _ => panic!("a partial removal must produce a replacement"),
    };
    assert_eq!(shrunk.output_count(), 8);
    assert_eq!(shrunk.header().inline_len, 7);
    let grown = UtxoRecord::add_run_replacement(
        Some(&shrunk),
        shrunk.txid(),
        &[OutputParts::new(9, 99, &[0x59], false, 2)],
        true,
        None,
    )?;
    assert_eq!(grown.output_count(), 9);
    for vout in 1..=9 {
        assert!(grown.find_output(vout).is_some(), "vout {vout} was lost");
    }
    assert!(grown.find_output(0).is_none());
    Ok(())
}

#[test]
fn the_unique_add_guard_rejects_equal_and_decreasing_vouts() {
    assert!(vouts_are_strictly_increasing(None, [0]));
    assert!(vouts_are_strictly_increasing(Some(0), [1, 2]));
    assert!(vouts_are_strictly_increasing(Some(9), []));
    assert!(!vouts_are_strictly_increasing(Some(2), [2]));
    assert!(!vouts_are_strictly_increasing(None, [3, 3]));
    assert!(!vouts_are_strictly_increasing(None, [3, 1]));
}

#[test]
fn a_record_moved_across_threads_stays_decodable() -> Result<(), UtxoError> {
    let record = UtxoRecord::from_owned_outputs(
        Hash256::default(),
        &[output(0, &[0x51], 1), output(3, &[0x53], 3)],
    )?;
    let txid = record.txid();
    let record = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                assert_eq!(record.output_count(), 2);
                assert!(record.find_output(3).is_some());
                record
            })
            .join()
            .unwrap_or_else(|_| panic!("record moved across threads must not panic"))
    });
    assert_eq!(record.txid(), txid);
    Ok(())
}

#[test]
fn records_at_the_inline_partition_boundary_iterate_exactly() -> Result<(), UtxoError> {
    for count in [7_u32, 8, 9] {
        let outputs: Vec<OwnedUtxoOut> = (0..count)
            .map(|vout| {
                output(
                    vout,
                    &[0x51, u8::try_from(vout).unwrap_or(0)],
                    u64::from(vout) * 10,
                )
            })
            .collect();
        let record = UtxoRecord::from_owned_outputs(Hash256::default(), &outputs)?;
        assert_eq!(record.output_count(), usize::try_from(count).unwrap_or(0));
        let mut iter = record.outputs();
        assert_eq!(iter.len(), usize::try_from(count).unwrap_or(0));
        let decoded: Vec<u32> = iter.by_ref().map(|out| out.vout).collect();
        assert_eq!(decoded, (0..count).collect::<Vec<u32>>());
        assert_eq!(iter.len(), 0);
        assert!(iter.next().is_none());
        for vout in [0, count - 1, count] {
            assert_eq!(
                record.find_output(vout).is_some(),
                vout < count,
                "boundary vout {vout} on a {count}-output record"
            );
        }
    }
    Ok(())
}

#[test]
fn failed_non_unique_add_leaves_the_overwrite_sink_untouched() -> Result<(), UtxoError> {
    let existing = output(0, &[0x51], 10);
    let record =
        UtxoRecord::from_owned_outputs(Hash256::default(), std::slice::from_ref(&existing))?;
    let oversized = vec![0x51; usize::from(u16::MAX) + 1];
    let addition = OutputParts::new(0, 20, &oversized, false, 0);
    let mut overwritten = Vec::new();
    let result = UtxoRecord::add_run_replacement(
        Some(&record),
        Hash256::default(),
        &[addition],
        false,
        Some(&mut overwritten),
    );
    assert!(
        matches!(result, Err(UtxoError::ScriptTooLarge { .. })),
        "the oversized script must fail the encode"
    );
    assert!(
        overwritten.is_empty(),
        "a failed add must leave the overwrite sink untouched"
    );
    Ok(())
}
