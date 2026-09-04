#![no_main]

use std::io::Cursor;

use bitcoin::hashes::{Hash as _, sha256d};
use libfuzzer_sys::fuzz_target;

/// Fuzz the Bitcoin P2P command decoders.
///
/// Command names come from [`bitcoin_rs_p2p::COMMANDS`], so a decoder arm
/// missing from the inventory is a payload no fuzz input can reach.
///
/// The envelope is BUILT here rather than taken from the fuzz data. Fed raw
/// bytes, arbitrary input has to satisfy the network magic, the command
/// framing, the advertised length, AND a four-byte double-SHA256 checksum
/// before `decode_payload` runs. The checksum is cryptographic, so mutation
/// terminates at `BadChecksum` essentially always and the command decoders —
/// the code this target exists to fuzz — are never reached.
///
/// So the first byte selects a command, the rest is the payload, and the
/// header is derived from both. Everything the envelope proves is then
/// constant, and the fuzzer's whole budget goes into the payload.
fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    let payload = payload
        .get(..bitcoin_rs_p2p::wire::MAX_MESSAGE_PAYLOAD)
        .unwrap_or(payload);
    let Some(spec) = bitcoin_rs_p2p::COMMANDS
        .get(usize::from(*selector) % bitcoin_rs_p2p::COMMANDS.len())
    else {
        return;
    };
    let command = spec.name;

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
