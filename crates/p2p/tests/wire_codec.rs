//! Wire codec message round trips.
use std::io::Cursor;

use bitcoin::Txid;
use bitcoin::block::BlockHash;
use bitcoin::hashes::Hash;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin_rs_p2p::handshake::version_message;
use bitcoin_rs_p2p::wire::{PeerError, read_message, write_message};

#[test]
fn round_trips_ping_pong_version_verack_inv_getheaders() -> Result<(), PeerError> {
    let messages = vec![
        NetworkMessage::Ping(42),
        NetworkMessage::Pong(42),
        NetworkMessage::Version(version_message(99, 123)),
        NetworkMessage::Verack,
        NetworkMessage::Inv(vec![Inventory::Transaction(Txid::from_byte_array(
            [7u8; 32],
        ))]),
        NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![BlockHash::all_zeros()],
            BlockHash::all_zeros(),
        )),
    ];

    for message in messages {
        let mut cursor = Cursor::new(Vec::new());
        write_message(&mut cursor, Magic::BITCOIN, &message)?;
        cursor.set_position(0);
        let decoded = read_message(&mut cursor, Magic::BITCOIN)?;
        assert_eq!(decoded, message);
    }

    Ok(())
}
