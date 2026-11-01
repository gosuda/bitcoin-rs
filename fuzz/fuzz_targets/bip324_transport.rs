#![no_main]

use std::io::{self, Cursor, Read};

use bitcoin::p2p::Magic;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::rand::SeedableRng as _;
use bitcoin::secp256k1::rand::rngs::StdRng;
use bitcoin_rs_p2p::bip324::{
    Established, Handshake, PacketReader, RecvCipher, SendCipher, Step, TransportError,
    is_poll_timeout,
};
use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

const V1_VERSION_COMMAND: &[u8; 12] = b"version\0\0\0\0\0";

#[derive(Default)]
struct Inbox {
    bytes: Vec<u8>,
    position: usize,
}

impl Inbox {
    fn feed(&mut self, bytes: &[u8]) {
        if self.position > 0 {
            self.bytes.drain(..self.position);
            self.position = 0;
        }
        self.bytes.extend_from_slice(bytes);
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

impl Read for Inbox {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.is_empty() || out.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let available = &self.bytes[self.position..];
        let read = available.len().min(out.len());
        out[..read].copy_from_slice(&available[..read]);
        self.position += read;
        Ok(read)
    }
}

fn drive(
    initiator: &mut Handshake,
    responder: &mut Handshake,
) -> Option<(Box<Established>, Box<Established>)> {
    let mut to_initiator = Inbox::default();
    let mut to_responder = Inbox::default();
    let mut initiator_established = None;
    let mut responder_established = None;
    let mut initiator_alive = true;
    let mut responder_alive = true;

    for _ in 0..32 {
        to_responder.feed(&initiator.take_outbound());
        to_initiator.feed(&responder.take_outbound());
        if initiator_established.is_none() && initiator_alive {
            match initiator.advance(&mut to_initiator) {
                Ok(Step::Established(established)) => initiator_established = Some(established),
                Ok(_) => {}
                Err(error) => initiator_alive = is_poll_timeout(&error),
            }
        }
        if responder_established.is_none() && responder_alive {
            match responder.advance(&mut to_responder) {
                Ok(Step::Established(established)) => responder_established = Some(established),
                Ok(_) => {}
                Err(error) => responder_alive = is_poll_timeout(&error),
            }
        }
        if initiator_established.is_some() && responder_established.is_some() {
            break;
        }
        if !initiator_alive && !responder_alive {
            break;
        }
    }

    Some((initiator_established?, responder_established?))
}

fn exchange(
    sender: &mut SendCipher,
    receiver: &mut PacketReader,
    packets: &[Vec<u8>],
) {
    for contents in packets {
        let Ok(sealed) = sender.seal(contents, &[], false) else {
            return;
        };
        match receiver.read_contents(&mut Cursor::new(sealed)) {
            Ok(Some(opened)) => assert_eq!(opened.as_ref(), contents.as_slice()),
            Ok(None) => panic!("a non-decoy packet must not be skipped"),
            Err(error) => panic!("a freshly sealed packet must authenticate: {error}"),
        }
    }
}

fn packet_contents(u: &mut Unstructured<'_>, count: usize) -> Vec<Vec<u8>> {
    let mut packets = Vec::with_capacity(count.min(256));
    for _ in 0..count {
        let Ok(len) = u.arbitrary::<u8>() else {
            break;
        };
        let len = usize::from(len % 17);
        let Ok(bytes) = u.bytes(len) else {
            break;
        };
        packets.push(bytes.to_vec());
    }
    packets
}

fn v1_prefix(magic: [u8; 4]) -> [u8; 16] {
    let mut prefix = [0u8; 16];
    prefix[..4].copy_from_slice(&magic);
    prefix[4..].copy_from_slice(V1_VERSION_COMMAND);
    prefix
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(seed) = u.arbitrary::<u64>() else {
        return;
    };
    let mut rng = StdRng::seed_from_u64(seed);
    let magic = Magic::REGTEST;
    let magic_bytes = magic.to_bytes();

    let mut detector = Handshake::responder(magic, &mut rng);
    match detector.advance(&mut Cursor::new(v1_prefix(magic_bytes))) {
        Ok(Step::V1(prefix)) => assert_eq!(prefix, v1_prefix(magic_bytes)),
        other => panic!("a magic-prefixed version header must be detected: {other:?}"),
    }
    let mut wrong_network = Handshake::responder(magic, &mut rng);
    assert!(matches!(
        wrong_network.advance(&mut Cursor::new(v1_prefix(
            Magic::BITCOIN.to_bytes()
        ))),
        Err(TransportError::WrongNetworkV1)
    ));

    let mut initiator = Handshake::initiator(magic, &mut rng);
    let mut responder = Handshake::responder(magic, &mut rng);
    let Some((mut initiator_established, mut responder_established)) =
        drive(&mut initiator, &mut responder)
    else {
        return;
    };
    assert_eq!(
        initiator_established.session_id, responder_established.session_id,
        "both roles must derive the same session id"
    );

    let selector = u.arbitrary::<u8>().unwrap_or_default();
    let count = if selector % 16 == 0 {
        usize::from(224 + selector % 32)
    } else {
        usize::from(selector % 8)
    };
    let packets = packet_contents(&mut u, count);
    exchange(
        &mut initiator_established.send,
        &mut responder_established.recv,
        &packets,
    );
    exchange(
        &mut responder_established.send,
        &mut initiator_established.recv,
        &packets,
    );

    let decoy = b"decoy-check";
    let Ok(decoy_packet) = initiator_established.send.seal(decoy, &[], true) else {
        return;
    };
    assert!(
        matches!(
            responder_established
                .recv
                .read_contents(&mut Cursor::new(decoy_packet)),
            Ok(None)
        ),
        "a decoy packet must be skipped"
    );
    exchange(
        &mut initiator_established.send,
        &mut responder_established.recv,
        &[decoy.to_vec()],
    );

    let Ok(sealed) = initiator_established.send.seal(b"ping", &[], false) else {
        return;
    };
    let offset = data.first().copied().unwrap_or_default();
    let bit = data.get(1).copied().unwrap_or_default();
    let mut corrupted = sealed.clone();
    let index = usize::from(offset) % corrupted.len();
    corrupted[index] ^= 1u8 << (bit % 8);
    assert!(
        responder_established
            .recv
            .read_contents(&mut Cursor::new(corrupted))
            .is_err(),
        "a corrupted packet must fail authentication"
    );
    let Ok(sealed) = initiator_established.send.seal(b"ping", &[], false) else {
        return;
    };
    assert!(
        responder_established
            .recv
            .read_contents(&mut Cursor::new(sealed))
            .is_err(),
        "a poisoned reader must reject every later packet"
    );

    let digest = bitcoin::hashes::sha256::Hash::hash(data).to_byte_array();
    let length_key = digest;
    let packet_key = digest.map(|byte| !byte);
    let mut arbitrary_reader =
        PacketReader::new(RecvCipher::new(length_key, packet_key), Vec::new());
    let mut cursor = Cursor::new(data);
    let mut reads = 0usize;
    while let Ok(Some(_)) = arbitrary_reader.read_contents(&mut cursor) {
        reads += 1;
        if reads > 64 {
            break;

        }
    }

    let mut arbitrary_sender = SendCipher::new(length_key, packet_key);
    let Ok(sealed) = arbitrary_sender.seal(b"arbitrary-key round trip", &[], false) else {
        return;
    };
    let mut checking_reader =
        PacketReader::new(RecvCipher::new(length_key, packet_key), Vec::new());
    assert!(matches!(
        checking_reader.read_contents(&mut Cursor::new(sealed)),
        Ok(Some(opened)) if opened.as_ref() == b"arbitrary-key round trip"
    ));
});
