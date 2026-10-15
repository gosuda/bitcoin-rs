//! BIP324 v2 transport.
//!
//! The `ElligatorSwift` key agreement, the HKDF key schedule, the
//! forward-secure ciphers that seal and open packets, the handshake state
//! machine, resumable packet reads, and the message type encoding. Nothing
//! here owns a socket: [`crate::transport`] drives it over a connection.

mod cipher;
mod handshake;
mod keys;
pub(crate) mod msg_type;
mod packet;
mod reader;

pub(crate) use handshake::{Established, Handshake, Step};
pub(crate) use packet::SendCipher;
pub(crate) use reader::{PacketReader, is_poll_timeout};

/// A BIP324 transport failed. A poll-timeout [`TransportError::Io`] is
/// retried with all progress kept; every other error ends the connection.
#[derive(Debug, thiserror::Error)]
pub(crate) enum TransportError {
    /// No garbage terminator within the 4095 bytes of garbage BIP324 allows.
    #[error("BIP324 garbage terminator not found within the garbage limit")]
    TerminatorNotFound,
    /// A responder received a v1 `version` header for another network.
    #[error("peer sent a v1 version header for another network")]
    WrongNetworkV1,
    /// A packet declared more contents than a peer may send.
    #[error("BIP324 packet contents of {0} bytes exceed the receive limit")]
    PacketTooLarge(usize),
    /// A packet could not be sealed or failed authentication.
    #[error(transparent)]
    Packet(#[from] packet::PacketError),
    /// HKDF refused an output length.
    #[error("BIP324 key schedule failed: {0}")]
    KeySchedule(hkdf::InvalidLength),
    /// The handshake was advanced after it finished.
    #[error("BIP324 handshake already completed")]
    Completed,
    /// The stream failed, or its poll interval elapsed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod vector_tests {
    use std::error::Error;

    use bitcoin::hex::FromHex as _;
    use bitcoin::p2p::Magic;
    use bitcoin::secp256k1::ellswift::ElligatorSwift;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, ecdh};

    use super::cipher::{LENGTH_FIELD_LEN, TAG_LEN};
    use super::keys::{KeyMaterial, Role, Session, shared_secret};
    use super::packet::HEADER_LEN;

    type TestResult = Result<(), Box<dyn Error>>;

    /// One upstream CSV file from `tests/data/bip324/`.
    struct Csv {
        header: Vec<String>,
        rows: Vec<Vec<String>>,
    }

    impl Csv {
        fn load(name: &str) -> Result<Self, Box<dyn Error>> {
            let path = format!("{}/tests/data/bip324/{name}", env!("CARGO_MANIFEST_DIR"));
            let text = std::fs::read_to_string(path)?;
            let mut lines = text
                .lines()
                .map(|line| line.trim_end_matches('\r'))
                .filter(|line| !line.is_empty())
                .map(|line| line.split(',').map(str::to_owned).collect::<Vec<_>>());
            let header = lines.next().ok_or("empty vector file")?;
            Ok(Self {
                header,
                rows: lines.collect(),
            })
        }

        fn value<'a>(&self, row: &'a [String], name: &str) -> Result<&'a str, Box<dyn Error>> {
            let column = self
                .header
                .iter()
                .position(|field| field == name)
                .ok_or_else(|| format!("missing column {name}"))?;
            Ok(row.get(column).ok_or("short row")?.as_str())
        }
    }

    fn x_only(key: PublicKey) -> [u8; 32] {
        key.x_only_public_key().0.serialize()
    }

    /// Opens `packet` on the receiving side, returning its ignore bit and
    /// contents.
    fn open(
        receiver: &mut Session,
        aad: &[u8],
        mut packet: Vec<u8>,
    ) -> Result<(bool, Vec<u8>), Box<dyn Error>> {
        let mut field = [0u8; LENGTH_FIELD_LEN];
        field.copy_from_slice(&packet[..LENGTH_FIELD_LEN]);
        let length = receiver.recv.decrypt_length(field);
        let body = &mut packet[LENGTH_FIELD_LEN..];
        assert_eq!(body.len(), HEADER_LEN + length + TAG_LEN);
        let opened = receiver.recv.open(aad, body)?;
        Ok((opened.ignore, opened.contents.to_vec()))
    }

    #[test]
    fn packet_encoding_vectors() -> TestResult {
        let secp = Secp256k1::new();
        let csv = Csv::load("packet_encoding_test_vectors.csv")?;
        assert_eq!(csv.rows.len(), 7);
        for row in &csv.rows {
            let value = |name: &str| csv.value(row, name);
            let secret_key = SecretKey::from_slice(&Vec::<u8>::from_hex(value("in_priv_ours")?)?)?;
            let ours =
                ElligatorSwift::from_array(<[u8; 64]>::from_hex(value("in_ellswift_ours")?)?);
            let theirs =
                ElligatorSwift::from_array(<[u8; 64]>::from_hex(value("in_ellswift_theirs")?)?);
            let (role, peer_role) = if value("in_initiating")? == "1" {
                (Role::Initiator, Role::Responder)
            } else {
                (Role::Responder, Role::Initiator)
            };
            let contents =
                Vec::<u8>::from_hex(value("in_contents")?)?.repeat(value("in_multiply")?.parse()?);
            let aad = Vec::<u8>::from_hex(value("in_aad")?)?;
            let ignore = value("in_ignore")? == "1";
            let hex32 = |name: &str| -> Result<[u8; 32], Box<dyn Error>> {
                Ok(<[u8; 32]>::from_hex(value(name)?)?)
            };
            let hex16 = |name: &str| -> Result<[u8; 16], Box<dyn Error>> {
                Ok(<[u8; 16]>::from_hex(value(name)?)?)
            };

            // The key agreement inputs decode to the points the BIP records.
            let their_key = PublicKey::from_ellswift(theirs);
            assert_eq!(
                x_only(PublicKey::from_secret_key(&secp, &secret_key)),
                hex32("mid_x_ours")?
            );
            assert_eq!(x_only(PublicKey::from_ellswift(ours)), hex32("mid_x_ours")?);
            assert_eq!(x_only(their_key), hex32("mid_x_theirs")?);
            assert_eq!(
                ecdh::shared_secret_point(&their_key, &secret_key)[..32],
                hex32("mid_x_shared")?
            );

            let secret = shared_secret(secret_key, ours, theirs, role);
            assert_eq!(secret, hex32("mid_shared_secret")?);
            let material = KeyMaterial::derive(&secret, Magic::BITCOIN)?;
            assert_eq!(material.initiator_length, hex32("mid_initiator_l")?);
            assert_eq!(material.initiator_packet, hex32("mid_initiator_p")?);
            assert_eq!(material.responder_length, hex32("mid_responder_l")?);
            assert_eq!(material.responder_packet, hex32("mid_responder_p")?);

            let mut sender = Session::new(&material, role);
            let mut receiver = Session::new(&material, peer_role);
            assert_eq!(sender.session_id, hex32("out_session_id")?);
            assert_eq!(receiver.session_id, sender.session_id);
            assert_eq!(
                sender.send_garbage_terminator,
                hex16("mid_send_garbage_terminator")?
            );
            assert_eq!(
                sender.recv_garbage_terminator,
                hex16("mid_recv_garbage_terminator")?
            );
            assert_eq!(
                receiver.recv_garbage_terminator,
                sender.send_garbage_terminator
            );

            // `in_idx` empty packets precede the vector packet.
            for _ in 0..value("in_idx")?.parse::<usize>()? {
                let filler = sender.send.seal(&[], &[], false)?;
                assert_eq!(open(&mut receiver, &[], filler)?, (false, Vec::new()));
            }
            let packet = sender.send.seal(&contents, &aad, ignore)?;
            match value("out_ciphertext")? {
                "" => assert!(
                    packet.ends_with(&Vec::<u8>::from_hex(value("out_ciphertext_endswith")?)?)
                ),
                full => assert_eq!(packet, Vec::<u8>::from_hex(full)?),
            }
            let (opened_ignore, opened_contents) = open(&mut receiver, &aad, packet)?;
            assert_eq!(opened_ignore, ignore);
            assert!(
                opened_contents == contents,
                "receiver recovers the contents"
            );
        }
        Ok(())
    }

    #[test]
    fn ellswift_decode_vectors() -> TestResult {
        let csv = Csv::load("ellswift_decode_test_vectors.csv")?;
        assert_eq!(csv.rows.len(), 76);
        for row in &csv.rows {
            let encoding =
                ElligatorSwift::from_array(<[u8; 64]>::from_hex(csv.value(row, "ellswift")?)?);
            assert_eq!(
                x_only(PublicKey::from_ellswift(encoding)),
                <[u8; 32]>::from_hex(csv.value(row, "x")?)?,
                "{}",
                csv.value(row, "comment")?
            );
        }
        Ok(())
    }

    #[test]
    fn network_magic_binds_the_key_schedule() -> TestResult {
        let mainnet = KeyMaterial::derive(&[7; 32], Magic::BITCOIN)?;
        let regtest = KeyMaterial::derive(&[7; 32], Magic::REGTEST)?;
        assert_ne!(mainnet.session_id, regtest.session_id);
        assert_ne!(mainnet.initiator_packet, regtest.initiator_packet);
        Ok(())
    }
}
