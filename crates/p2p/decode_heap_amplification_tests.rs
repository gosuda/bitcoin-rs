//! Transient decode allocation stays inside the pre-charged decode reservation.
#![expect(clippy::expect_used, reason = "fixture construction must fail loudly")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Cursor;

use bitcoin::hashes::Hash;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_filter::CFilter;
use bitcoin_rs_p2p::wire::{Message, PeerError, encode_payload, read_message, wire_len};
use sha2::{Digest, Sha256};

thread_local! {
    static MEASURING: Cell<bool> = const { Cell::new(false) };
    static THREAD_ALLOCATION_LIVE: Cell<usize> = const { Cell::new(0) };
    static THREAD_ALLOCATION_PEAK: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

fn measuring() -> bool {
    MEASURING.try_with(Cell::get).unwrap_or(false)
}

fn observe(live: usize) {
    THREAD_ALLOCATION_PEAK.with(|peak| {
        if live > peak.get() {
            peak.set(live);
        }
    });
}

fn grow(bytes: usize) {
    THREAD_ALLOCATION_LIVE.with(|live| {
        let next = live.get() + bytes;
        live.set(next);
        observe(next);
    });
}

// SAFETY: every call forwards to `System` with the caller's layout; the counters only observe sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && measuring() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract for `layout`.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && measuring() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if measuring() {
            THREAD_ALLOCATION_LIVE.with(|live| live.set(live.get().saturating_sub(layout.size())));
        }
        // SAFETY: the caller passes a pointer and layout from a matching `alloc` call.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() && measuring() {
            THREAD_ALLOCATION_LIVE.with(|live| {
                let next = live.get().saturating_sub(layout.size()) + new_size;
                live.set(next);
                observe(next);
            });
        }
        moved
    }
}

#[global_allocator]
static DECODE_HEAP_TESTS_ALLOCATOR: CountingAllocator = CountingAllocator;

struct Measurement;

impl Measurement {
    fn start() -> Self {
        MEASURING.with(|flag| flag.set(true));
        THREAD_ALLOCATION_LIVE.with(|live| live.set(0));
        THREAD_ALLOCATION_PEAK.with(|peak| peak.set(0));
        Measurement
    }

    fn peak(&self) -> usize {
        THREAD_ALLOCATION_PEAK.with(Cell::get)
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        MEASURING.with(|flag| flag.set(false));
    }
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

fn frame(command: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&Magic::REGTEST.to_bytes());
    let mut command_bytes = [0u8; 12];
    command_bytes[..command.len()].copy_from_slice(command);
    frame.extend_from_slice(&command_bytes);
    let len = u32::try_from(payload.len()).expect("payload fits u32");
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&checksum(payload));
    frame.extend_from_slice(payload);
    frame
}

fn one_witness_input_blocktxn_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x07; 32]);
    payload.push(0x01);
    payload.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]);
    payload.extend_from_slice(&[0x00; 32]);
    payload.extend_from_slice(&[0xFF; 4]);
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0xFF; 4]);
    payload.extend_from_slice(&[0x01]);
    payload.extend_from_slice(&[0x00; 8]);
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0xFE, 0x00, 0x09, 0x3D, 0x00]);
    payload
}

#[test]
fn blocktxn_decode_allocation_stays_within_the_reservation() {
    let invalid_payload = one_witness_input_blocktxn_payload();
    let invalid_reservation =
        bitcoin_rs_consensus::primitives::layout::decode_reservation(invalid_payload.len());
    let invalid_frame = frame(b"blocktxn", &invalid_payload);

    let measurement = Measurement::start();
    let invalid_outcome = read_message(&mut Cursor::new(invalid_frame), Magic::REGTEST);
    let invalid_peak = measurement.peak();
    drop(measurement);
    assert!(
        invalid_peak <= invalid_reservation,
        "transient decode allocation {invalid_peak} exceeded the {invalid_reservation}-byte reservation for a {}-byte payload",
        invalid_payload.len()
    );
    assert!(
        matches!(invalid_outcome, Err(PeerError::NativeDecode(_))),
        "4,000,000 declared witness items cannot exist in the remaining bytes: {invalid_outcome:?}"
    );

    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x07; 32]);
    let mut transaction = Vec::new();
    transaction.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]);
    transaction.extend_from_slice(&[0x00; 32]);
    transaction.extend_from_slice(&[0xFF; 4]);
    transaction.extend_from_slice(&[0x00]);
    transaction.extend_from_slice(&[0xFF; 4]);
    transaction.extend_from_slice(&[0x01]);
    transaction.extend_from_slice(&[0x00; 8]);
    transaction.extend_from_slice(&[0x00]);
    transaction.extend_from_slice(&[0x01, 0x01, 0x2A]);
    transaction.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    payload.push(0x01);
    payload.extend_from_slice(&transaction);

    let reservation = bitcoin_rs_consensus::primitives::layout::decode_reservation(payload.len());
    let frame = frame(b"blocktxn", &payload);

    let measurement = Measurement::start();
    let outcome = read_message(&mut Cursor::new(frame), Magic::REGTEST);
    let peak = measurement.peak();
    drop(measurement);

    let (message, _) = outcome.expect("a valid blocktxn decodes");
    assert!(matches!(message, Message::BlockTxn(_)));
    assert!(
        peak <= reservation,
        "transient decode allocation {peak} exceeded the {reservation}-byte reservation for a {}-byte payload",
        payload.len()
    );
}

#[test]
fn cmpctblock_prefilled_transaction_decode_allocation_stays_within_the_reservation() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x00; 80]);
    payload.extend_from_slice(&[0x00; 8]);
    payload.extend_from_slice(&[0x00, 0x01, 0x00]);
    payload.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]);
    payload.extend_from_slice(&[0x00; 32]);
    payload.extend_from_slice(&[0xFF; 4]);
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0xFF; 4]);
    payload.extend_from_slice(&[0x01]);
    payload.extend_from_slice(&[0x00; 8]);
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0xFE, 0x00, 0x09, 0x3D, 0x00]);

    let reservation = bitcoin_rs_consensus::primitives::layout::decode_reservation(payload.len());
    let frame = frame(b"cmpctblock", &payload);

    let measurement = Measurement::start();
    let outcome = read_message(&mut Cursor::new(frame), Magic::REGTEST);
    let peak = measurement.peak();
    drop(measurement);
    assert!(
        peak <= reservation,
        "transient decode allocation {peak} exceeded the {reservation}-byte reservation for a {}-byte cmpctblock payload",
        payload.len()
    );
    assert!(
        matches!(outcome, Err(PeerError::NativeDecode(_))),
        "4,000,000 declared witness items cannot exist in the remaining bytes: {outcome:?}"
    );
}

#[test]
fn wire_length_borrows_retained_payloads() {
    let hash = bitcoin::BlockHash::from_byte_array([7; 32]);
    let cases = [
        (
            Message::Inv(vec![Inventory::Block(hash); 50_000]),
            24 + 3 + 50_000 * 36,
        ),
        (
            Message::CFilter(CFilter {
                filter_type: 0,
                block_hash: hash,
                filter: vec![0x2a; 100_000],
            }),
            24 + 1 + 32 + 5 + 100_000,
        ),
    ];

    for (message, expected_len) in cases {
        let measurement = Measurement::start();
        let result = wire_len(&message);
        let peak = measurement.peak();
        drop(measurement);

        assert_eq!(result.expect("message has a wire length"), expected_len);
        assert_eq!(peak, 0, "counting a borrowed payload must not allocate");
    }
}

#[test]
fn encoding_inventory_allocates_only_the_output() {
    let hash = bitcoin::BlockHash::from_byte_array([7; 32]);
    let message = Message::Inv(vec![Inventory::Block(hash); 50_000]);

    let measurement = Measurement::start();
    let result = encode_payload(&message);
    let peak = measurement.peak();
    drop(measurement);

    let payload = result.expect("inventory encodes");
    assert_eq!(payload.len(), 3 + 50_000 * 36);
    assert_eq!(payload.capacity(), payload.len());
    assert_eq!(
        peak,
        payload.capacity(),
        "encoding must own only its output buffer, without cloning the inventory"
    );
}

// P2P-01
#[test]
fn borrowed_payloads_match_rust_bitcoin_without_length_allocations() -> Result<(), PeerError> {
    use std::net::Ipv4Addr;

    use bitcoin::BlockHash;
    use bitcoin::bip152::{
        BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction,
        ShortId,
    };
    use bitcoin::bip158::{FilterHash, FilterHeader};
    use bitcoin::consensus::encode as bitcoin_encode;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
    use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
    use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage};
    use bitcoin::p2p::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
    use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
    use bitcoin::p2p::message_filter::{
        CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters,
    };
    use bitcoin::p2p::message_network::Reject;
    use bitcoin_rs_p2p::wire::write_message;

    let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let hash = block.block_hash();
    let mut transaction = block.txdata[0].clone();
    transaction.input[0].witness = bitcoin::Witness::from_slice(&[b"witness"]);
    let mut reject_payload = vec![2, b't', b'x', 0x10, 3, b'b', b'a', b'd'];
    reject_payload.extend_from_slice(&[7; 32]);
    let reject: Reject = bitcoin_encode::deserialize(&reject_payload).map_err(PeerError::from)?;
    let cases = [
        NetworkMessage::Addr(vec![(
            123,
            Address::new(
                &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 18444)),
                ServiceFlags::NETWORK,
            ),
        )]),
        NetworkMessage::NotFound(vec![Inventory::WitnessBlock(hash)]),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(vec![hash], BlockHash::all_zeros())),
        NetworkMessage::GetHeaders(GetHeadersMessage::new(vec![hash], BlockHash::all_zeros())),
        NetworkMessage::MerkleBlock(
            bitcoin::merkle_tree::MerkleBlock::from_block_with_predicate(&block, |_| true),
        ),
        NetworkMessage::FilterLoad(FilterLoad {
            filter: vec![0x2a; 253],
            hash_funcs: 3,
            tweak: 7,
            flags: BloomFlags::All,
        }),
        NetworkMessage::FilterAdd(FilterAdd {
            data: vec![1, 2, 3],
        }),
        NetworkMessage::FilterClear,
        NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 0,
            start_height: 3,
            stop_hash: hash,
        }),
        NetworkMessage::CFilter(CFilter {
            filter_type: 0,
            block_hash: hash,
            filter: vec![0x3c; 253],
        }),
        NetworkMessage::GetCFHeaders(GetCFHeaders {
            filter_type: 0,
            start_height: 3,
            stop_hash: hash,
        }),
        NetworkMessage::CFHeaders(CFHeaders {
            filter_type: 0,
            stop_hash: hash,
            previous_filter_header: FilterHeader::from_byte_array([4; 32]),
            filter_hashes: vec![FilterHash::from_byte_array([5; 32]); 2],
        }),
        NetworkMessage::GetCFCheckpt(GetCFCheckpt {
            filter_type: 0,
            stop_hash: hash,
        }),
        NetworkMessage::CFCheckpt(CFCheckpt {
            filter_type: 0,
            stop_hash: hash,
            filter_headers: vec![FilterHeader::from_byte_array([6; 32]); 2],
        }),
        NetworkMessage::SendCmpct(SendCmpct {
            send_compact: true,
            version: 2,
        }),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: HeaderAndShortIds {
                header: block.header,
                nonce: 9,
                short_ids: vec![ShortId::from([1; 6])],
                prefilled_txs: vec![PrefilledTransaction {
                    idx: 0,
                    tx: transaction.clone(),
                }],
            },
        }),
        NetworkMessage::GetBlockTxn(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: hash,
                indexes: vec![1, 3, 9],
            },
        }),
        NetworkMessage::BlockTxn(BlockTxn {
            transactions: BlockTransactions {
                block_hash: hash,
                transactions: vec![transaction],
            },
        }),
        NetworkMessage::Alert(vec![0x5a; 253]),
        NetworkMessage::Reject(reject),
        NetworkMessage::AddrV2(vec![AddrV2Message {
            time: 123,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
            port: 18444,
        }]),
        NetworkMessage::Unknown {
            command: "custom".parse().expect("valid command"),
            payload: vec![0x5a; 253],
        },
    ];

    for reference in cases {
        let command = reference.command();
        let expected =
            bitcoin_encode::serialize(&RawNetworkMessage::new(Magic::REGTEST, reference));
        let (message, _) = read_message(&mut Cursor::new(&expected), Magic::REGTEST)?;
        assert_eq!(message.command(), command);

        let measurement = Measurement::start();
        let length = wire_len(&message);
        let peak = measurement.peak();
        drop(measurement);

        assert_eq!(peak, 0, "counting {command} must borrow its payload");
        assert_eq!(length?, expected.len());
        let mut actual = Vec::new();
        write_message(&mut actual, Magic::REGTEST, &message)?;
        assert_eq!(actual, expected, "v1 frame for {command}");
    }
    Ok(())
}
