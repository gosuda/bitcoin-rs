//! Fuzz the Bitcoin P2P command decoders.
#![no_main]

use std::io::Cursor;

use bitcoin::hashes::{Hash as _, sha256d};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    let payload = payload
        .get(..bitcoin_rs_p2p::wire::MAX_MESSAGE_PAYLOAD)
        .unwrap_or(payload);
    let Some(spec) =
        bitcoin_rs_p2p::COMMANDS.get(usize::from(*selector) % bitcoin_rs_p2p::COMMANDS.len())
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

    let mut cursor = Cursor::new(framed.as_slice());
    let _ = bitcoin_rs_p2p::wire::read_message(&mut cursor, magic);
});
