#![no_main]

use std::io::Cursor;

use bitcoin::p2p::Magic;
use bitcoin::secp256k1::rand::SeedableRng as _;
use bitcoin::secp256k1::rand::rngs::StdRng;
use bitcoin_rs_p2p::bip324::{Handshake, PacketReader, RecvCipher, SendCipher};
use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(seed) = u.arbitrary::<u64>() else {
        return;
    };
    let mut rng = StdRng::seed_from_u64(seed);

    let magic = Magic::REGTEST;
    let mut responder = Handshake::responder(magic, &mut rng);
    let mut reader = Cursor::new(data);
    let _ = responder.advance(&mut reader);

    let mut initiator = Handshake::initiator(magic, &mut rng);
    let mut reader2 = Cursor::new(data);
    let _ = initiator.advance(&mut reader2);

    let Ok(send_len_key) = u.arbitrary::<[u8; 32]>() else {
        return;
    };
    let Ok(send_pkt_key) = u.arbitrary::<[u8; 32]>() else {
        return;
    };
    let mut sender = SendCipher::new(send_len_key, send_pkt_key);
    let mut packet_reader =
        PacketReader::new(RecvCipher::new(send_len_key, send_pkt_key), Vec::new());

    let Ok(iterations) = u.arbitrary::<u8>() else {
        return;
    };
    let count = usize::from(iterations % 8);
    let mut tag_failed = false;

    for _ in 0..count {
        let Ok(contents_len) = u.arbitrary::<u16>() else {
            break;
        };
        let len = usize::from(contents_len % 256);
        let Ok(contents) = u.bytes(len) else {
            break;
        };
        let Ok(ignore) = u.arbitrary::<bool>() else {
            break;
        };
        let Ok(corrupt) = u.arbitrary::<bool>() else {
            break;
        };

        let Ok(mut sealed) = sender.seal(contents, &[], ignore) else {
            break;
        };

        if corrupt && !sealed.is_empty() {
            let last = sealed.len() - 1;
            sealed[last] ^= 0x01;
        }

        let mut stream = Cursor::new(&sealed);
        let opened = packet_reader.read_contents(&mut stream);

        if corrupt {
            tag_failed = true;
            assert!(
                opened.is_err(),
                "corrupted packet must fail tag verification"
            );
        } else if !tag_failed {
            match opened {
                Ok(Some(decrypted)) => {
                    assert_eq!(decrypted.as_ref(), contents);
                }
                Ok(None) => {
                    assert!(ignore);
                }
                Err(_) => {
                    break;
                }
            }
        } else {
            assert!(
                opened.is_err(),
                "no desync or forged packet accepted after tag failure"
            );
        }
    }

    let mut raw_reader = Cursor::new(data);
    let mut arbitrary_reader =
        PacketReader::new(RecvCipher::new(send_len_key, send_pkt_key), Vec::new());
    while let Ok(Some(_)) = arbitrary_reader.read_contents(&mut raw_reader) {}
});
