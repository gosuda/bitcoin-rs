#![no_main]

use std::io::Cursor;

use bitcoin::hashes::{Hash as _, sha256d};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    let payload = payload
        .get(..bitcoin_rs_wire::wire::MAX_MESSAGE_PAYLOAD)
        .unwrap_or(payload);
    let Some(spec) =
        bitcoin_rs_wire::COMMANDS.get(usize::from(*selector) % bitcoin_rs_wire::COMMANDS.len())
    else {
        return;
    };
    let command = *spec;

    let magic = bitcoin::p2p::Magic::REGTEST;
    let mut framed = Vec::with_capacity(24usize.saturating_add(payload.len()));
    framed.extend_from_slice(&magic.to_bytes());
    let mut command_bytes = [0_u8; 12];
    command_bytes
        .get_mut(..command.len())
        .map(|slot| slot.copy_from_slice(command.as_bytes()));
    framed.extend_from_slice(&command_bytes);
    let Ok(len) = u32::try_from(payload.len()) else {
        return;
    };
    framed.extend_from_slice(&len.to_le_bytes());
    let digest = sha256d::Hash::hash(payload);
    framed.extend_from_slice(digest.as_byte_array().get(..4).unwrap_or(&[0; 4]));
    framed.extend_from_slice(payload);

    let r1 = bitcoin_rs_wire::wire::read_message(&mut Cursor::new(framed.as_slice()), magic);
    let r2 = bitcoin_rs_wire::wire::read_message(&mut Cursor::new(framed.as_slice()), magic);
    match (&r1, &r2) {
        (Ok((m1, raw1)), Ok((m2, raw2))) => {
            assert_eq!(m1, m2, "p2p determinism mismatch for {command}");
            assert_eq!(raw1, raw2, "p2p raw determinism mismatch for {command}");
        }
        (Err(e1), Err(e2)) => {
            assert_eq!(
                format!("{e1:?}"),
                format!("{e2:?}"),
                "p2p error determinism mismatch for {command}"
            );
        }
        _ => panic!("p2p read_message non-deterministic outcome for {command}"),
    }

    if let Ok((message, _raw)) = r1 {
        match &message {
            bitcoin_rs_wire::Message::Block(payload_block) => {
                let decoded = payload_block.block().retained_heap_bytes();
                assert!(
                    payload.len() + decoded
                        <= bitcoin_rs_consensus::primitives::layout::decode_reservation(payload.len()),
                    "{command} decoded beyond its decode reservation"
                );
            }
            bitcoin_rs_wire::Message::Tx(tx) => {
                let decoded = tx.retained_heap_bytes();
                assert!(
                    payload.len() + decoded
                        <= bitcoin_rs_consensus::primitives::layout::decode_reservation(payload.len()),
                    "{command} decoded beyond its decode reservation"
                );
            }
            bitcoin_rs_wire::Message::Headers(headers) => {
                let heap = headers.capacity() * core::mem::size_of::<bitcoin_rs_consensus::primitives::Header>();
                assert!(
                    heap <= bitcoin_rs_consensus::primitives::layout::decode_reservation(payload.len()) + 1024,
                    "{command} headers heap beyond reservation"
                );
            }
            bitcoin_rs_wire::Message::Addr(addrs) => {
                let heap = addrs.capacity() * 32;
                assert!(
                    heap <= bitcoin_rs_consensus::primitives::layout::decode_reservation(payload.len()) + 1024,
                    "{command} addr heap beyond reservation"
                );
            }
            bitcoin_rs_wire::Message::Inv(inv)
            | bitcoin_rs_wire::Message::GetData(inv)
            | bitcoin_rs_wire::Message::NotFound(inv) => {
                let heap = inv.capacity() * 36;
                assert!(
                    heap <= bitcoin_rs_consensus::primitives::layout::decode_reservation(payload.len()) + 1024,
                    "{command} inv heap beyond reservation"
                );
            }
            _ => {}
        }

        let mut reencoded = Vec::new();
        let written = bitcoin_rs_wire::wire::write_message(&mut reencoded, magic, &message)
            .expect("p2p write_message must succeed on decoded message");
        assert_eq!(written, reencoded.len());
        let (re_decoded, _) =
            bitcoin_rs_wire::wire::read_message(&mut Cursor::new(&reencoded), magic)
                .expect("p2p re-decode must succeed on re-encoded message");
        assert_eq!(
            re_decoded, message,
            "p2p round-trip message equality failed for {command}"
        );
        let mut reencoded2 = Vec::new();
        let written2 = bitcoin_rs_wire::wire::write_message(&mut reencoded2, magic, &re_decoded)
            .expect("p2p idempotent re-encode must succeed");
        assert_eq!(written2, written);
        assert_eq!(
            reencoded, reencoded2,
            "p2p canonical re-encode must be idempotent for {command}"
        );
    }
});
