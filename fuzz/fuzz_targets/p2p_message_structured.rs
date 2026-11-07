#![no_main]

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, ShortId};
use bitcoin::bip158::FilterHeader;
use bitcoin::hashes::Hash as _;
use bitcoin::hashes::sha256d;
use bitcoin::p2p::address::{AddrV2, AddrV2Message};
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::p2p::message_bloom::{BloomFlags, FilterLoad};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_filter::{
    CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters,
};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Address, Magic, ServiceFlags};
use bitcoin::{BlockHash, FilterHash, Txid, merkle_tree::MerkleBlock};
use bitcoin_rs_wire::wire::{
    MAX_MESSAGE_PAYLOAD, Message, encode_payload, read_message, write_message,
};
use bitcoin_rs_consensus::primitives::layout::decode_reservation;
use bitcoin_rs_consensus::primitives::{BlockPayload, CompactTarget, Header, Network};
use libfuzzer_sys::arbitrary::{self, Unstructured};
use libfuzzer_sys::{fuzz_mutator, fuzz_target, fuzzer_mutate};

fn synthetic_header() -> bitcoin::block::Header {
    bitcoin::block::Header {
        version: bitcoin::block::Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 1_234_567,
        bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
        nonce: 0,
    }
}

fn arbitrary_message(u: &mut Unstructured<'_>) -> arbitrary::Result<Message> {
    let selector = u.arbitrary::<u8>()? % 22;
    let genesis = Network::Regtest.genesis_block();
    let zero_hash = BlockHash::all_zeros();
    let zero_filter = FilterHash::all_zeros();
    let zero_header = FilterHeader::all_zeros();

    match selector {
        0 => {
            let version = u.arbitrary::<u32>()?;
            let services = u.arbitrary::<u64>()?;
            let timestamp = u.arbitrary::<i64>()?;
            let recv_ip = Ipv4Addr::from(u.arbitrary::<[u8; 4]>()?);
            let recv_port = u.arbitrary::<u16>()?;
            let send_ip = Ipv4Addr::from(u.arbitrary::<[u8; 4]>()?);
            let send_port = u.arbitrary::<u16>()?;
            let nonce = u.arbitrary::<u64>()?;
            let start_height = u.arbitrary::<i32>()?;
            let relay = u.arbitrary::<bool>()?;
            Ok(Message::Version(VersionMessage {
                version,
                services: ServiceFlags::from(services),
                timestamp,
                receiver: Address::new(
                    &SocketAddr::new(IpAddr::V4(recv_ip), recv_port),
                    ServiceFlags::NONE,
                ),
                sender: Address::new(
                    &SocketAddr::new(IpAddr::V4(send_ip), send_port),
                    ServiceFlags::NONE,
                ),
                nonce,
                user_agent: String::from("/btc-rs-fuzz/"),
                start_height,
                relay,
            }))
        }
        1 => {
            let count = usize::from(u.arbitrary::<u8>()? % 4);
            let mut addrs = Vec::with_capacity(count);
            for _ in 0..count {
                let time = u.arbitrary::<u32>()?;
                let ip = Ipv4Addr::from(u.arbitrary::<[u8; 4]>()?);
                let port = u.arbitrary::<u16>()?;
                addrs.push((
                    time,
                    Address::new(
                        &SocketAddr::new(IpAddr::V4(ip), port),
                        ServiceFlags::NETWORK,
                    ),
                ));
            }
            Ok(Message::Addr(addrs))
        }
        2 => {
            let count = usize::from(u.arbitrary::<u8>()? % 4);
            let mut addrs = Vec::with_capacity(count);
            for _ in 0..count {
                let time = u.arbitrary::<u32>()?;
                let services = ServiceFlags::from(u.arbitrary::<u64>()?);
                let ip = Ipv4Addr::from(u.arbitrary::<[u8; 4]>()?);
                let port = u.arbitrary::<u16>()?;
                addrs.push(AddrV2Message {
                    time,
                    services,
                    addr: AddrV2::Ipv4(ip),
                    port,
                });
            }
            Ok(Message::AddrV2(addrs))
        }
        3 => {
            let count = usize::from(u.arbitrary::<u8>()? % 4);
            let mut invs = Vec::with_capacity(count);
            for _ in 0..count {
                let raw_hash = u.arbitrary::<[u8; 32]>()?;
                let hash = BlockHash::from_byte_array(raw_hash);
                invs.push(Inventory::Block(hash));
            }
            Ok(Message::Inv(invs))
        }
        4 => {
            let raw_hash = u.arbitrary::<[u8; 32]>()?;
            let hash = Txid::from_byte_array(raw_hash);
            Ok(Message::GetData(vec![Inventory::Transaction(hash)]))
        }
        5 => {
            let count = usize::from(u.arbitrary::<u8>()? % 4);
            let mut headers = Vec::with_capacity(count);
            for _ in 0..count {
                let version = u.arbitrary::<i32>()?;
                let time = u.arbitrary::<u32>()?;
                let bits = u.arbitrary::<u32>()?;
                let nonce = u.arbitrary::<u32>()?;
                headers.push(Header {
                    version,
                    prev_blockhash: genesis.header.prev_blockhash,
                    merkle_root: genesis.header.merkle_root,
                    time,
                    bits: CompactTarget::from_consensus(bits),
                    nonce,
                });
            }
            Ok(Message::Headers(headers))
        }
        6 => {
            let version = u.arbitrary::<u32>()?;
            Ok(Message::GetHeaders(GetHeadersMessage {
                version,
                locator_hashes: vec![zero_hash],
                stop_hash: zero_hash,
            }))
        }
        7 => {
            let nonce = u.arbitrary::<u64>()?;
            let b_header = synthetic_header();
            let dummy_txid = Txid::all_zeros();
            let short_id = ShortId::with_siphash_keys(&dummy_txid, (0, 0));
            Ok(Message::CmpctBlock(CmpctBlock {
                compact_block: HeaderAndShortIds {
                    header: b_header,
                    nonce,
                    short_ids: vec![short_id],
                    prefilled_txs: vec![],
                },
            }))
        }
        8 => Ok(Message::BlockTxn(BlockTxn {
            transactions: BlockTransactions {
                block_hash: zero_hash,
                transactions: vec![],
            },
        })),
        9 => Ok(Message::GetBlockTxn(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: zero_hash,
                indexes: vec![0],
            },
        })),
        10 => {
            let send_compact = u.arbitrary::<bool>()?;
            Ok(Message::SendCmpct(SendCmpct {
                send_compact,
                version: 2,
            }))
        }
        11 => {
            let rate = u.arbitrary::<i64>()?;
            Ok(Message::FeeFilter(rate))
        }
        12 => {
            let b_header = synthetic_header();
            let txid = Txid::all_zeros();
            let pmt = bitcoin::merkle_tree::PartialMerkleTree::from_txids(&[txid], &[true]);
            Ok(Message::MerkleBlock(MerkleBlock {
                header: b_header,
                txn: pmt,
            }))
        }
        13 => {
            let tweak = u.arbitrary::<u32>()?;
            Ok(Message::FilterLoad(FilterLoad {
                filter: vec![0xaa, 0xbb],
                hash_funcs: 1,
                tweak,
                flags: BloomFlags::None,
            }))
        }
        14 => Ok(Message::CFilter(CFilter {
            filter_type: 0,
            block_hash: zero_hash,
            filter: vec![1, 2, 3],
        })),
        15 => Ok(Message::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: 0,
            stop_hash: zero_hash,
        })),
        16 => Ok(Message::CFHeaders(CFHeaders {
            filter_type: 0,
            stop_hash: zero_hash,
            previous_filter_header: zero_header,
            filter_hashes: vec![zero_filter],
        })),
        17 => Ok(Message::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height: 0,
            stop_hash: zero_hash,
        })),
        18 => Ok(Message::CFCheckpt(CFCheckpt {
            filter_type: 0,
            stop_hash: zero_hash,
            filter_headers: vec![zero_header],
        })),
        19 => Ok(Message::GetCFCheckpt(GetCFCheckpt {
            filter_type: 0,
            stop_hash: zero_hash,
        })),
        20 => Ok(Message::Tx(genesis.txs[0].clone())),
        _ => Ok(Message::Block(BlockPayload::from_local(genesis))),
    }
}

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let magic = Magic::REGTEST;
    let seed_bytes = seed.to_le_bytes();
    let mut u = Unstructured::new(&seed_bytes);

    if size < 24 || seed % 7 == 0 {
        if let Ok(msg) = arbitrary_message(&mut u) {
            let mut framed = Vec::new();
            if write_message(&mut framed, magic, &msg).is_ok() && framed.len() <= max_size {
                let len = framed.len();
                data[..len].copy_from_slice(&framed);
                return len;
            }
        }
    }

    if size >= 24 {
        let payload_len = size - 24;
        let mutated_payload_len = fuzzer_mutate(
            &mut data[24..],
            payload_len,
            max_size.saturating_sub(24).min(MAX_MESSAGE_PAYLOAD),
        );
        let Ok(len_u32) = u32::try_from(mutated_payload_len) else {
            return size;
        };
        data[16..20].copy_from_slice(&len_u32.to_le_bytes());
        let digest = sha256d::Hash::hash(&data[24..24 + mutated_payload_len]);
        data[20..24].copy_from_slice(&digest.as_byte_array()[..4]);
        return 24 + mutated_payload_len;
    }

    fuzzer_mutate(data, size, max_size)
});

fuzz_target!(|data: &[u8]| {
    let magic = Magic::REGTEST;
    let mut cursor = Cursor::new(data);
    for _ in 0..32 {
        let before = cursor.position();
        let Ok((message, raw_payload)) = read_message(&mut cursor, magic) else {
            return;
        };
        assert!(
            cursor.position() > before,
            "a decoded frame must advance the reader"
        );

        let decoded_retained = match &message {
            Message::Block(payload) => payload.block().retained_heap_bytes(),
            Message::Tx(tx) => tx.retained_heap_bytes(),
            _ => 0,
        };
        let reservation = decode_reservation(raw_payload.len());
        assert!(
            raw_payload.len().saturating_add(decoded_retained) <= reservation,
            "payload decode exceeded reservation bound"
        );

        if let Ok(re_encoded) = encode_payload(&message) {
            assert_eq!(
                re_encoded.as_slice(),
                raw_payload.as_ref(),
                "message re-encode must match decoded payload"
            );
        }
    }
});
