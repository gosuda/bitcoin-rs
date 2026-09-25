//! Benchmarks for the p2p receive and send hot paths.
//!
//! `write_message` measures the end-to-end cost of emitting one message onto
//! a real loopback socket (small `ping` vs a genesis-sized `block` payload)
//! so transport changes such as write coalescing and `TCP_NODELAY` can be
//! compared. Note: loopback has ~0 RTT, so Nagle/delayed-ACK latency effects
//! from wide-area links are not visible here; this group captures syscall and
//! serialization overhead.
//!
//! `compact_reconstruction` measures one receive-side BIP152 `cmpctblock`
//! reconstruction: the short-ID scan over a resident mempool and the verified
//! completion that delivers the block.

use std::hint::black_box;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::Instant;

use hashbrown::HashMap;

use bitcoin::Network;
use bitcoin::bip152::HeaderAndShortIds;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_compact_blocks::CmpctBlock;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Sequence, Tx,
    TxIn, TxOut, Txid, Witness, Wtxid, consensus_bytes,
};
use criterion::{Criterion, criterion_group, criterion_main};

use bitcoin_rs_p2p::peer::COMPACT_BLOCK_VERSION;
use bitcoin_rs_p2p::wire::{Message, write_message};
use bitcoin_rs_p2p::{CompactBlockHints, Reconstruction};

/// Open a connected loopback pair and drain the read side on a thread so the
/// writer never blocks on a full socket buffer.
// A fixture that fails to build has no degraded mode: an I/O error would be
// timed as a fast early return and reported as a win.
#[expect(clippy::expect_used, reason = "fixture setup must fail loudly")]
fn connected_pair() -> (TcpStream, JoinHandle<()>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let writer = TcpStream::connect(addr).expect("connect loopback");
    writer.set_nodelay(true).expect("set nodelay");
    let (mut reader, _) = listener.accept().expect("accept loopback");
    let drain = std::thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        while reader.read(&mut buf).is_ok_and(|n| n > 0) {}
    });
    (writer, drain)
}

// A fixture that fails to build has no degraded mode: a decode or write
// error would be timed as a fast early return and reported as a win.
#[expect(clippy::expect_used, reason = "timed fixture calls must fail loudly")]
fn bench_write_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_message");

    let ping = Message::Ping(42);

    // Build a native `Block` from the regtest genesis so the benchmark
    // exercises the same consensus-encode path as real block relay.
    let genesis = genesis_block(Network::Regtest);
    let genesis_bytes = serialize(&genesis);
    let native_block = Block::consensus_decode(&genesis_bytes).expect("decode genesis block");
    let block = Message::Block(native_block);

    group.bench_function("ping_8B_payload", |b| {
        let (mut stream, _drain) = connected_pair();
        b.iter(|| write_message(&mut stream, Magic::BITCOIN, &ping).expect("write ping"));
    });

    group.bench_function("block_285B_payload", |b| {
        let (mut stream, _drain) = connected_pair();
        b.iter(|| write_message(&mut stream, Magic::BITCOIN, &block).expect("write block"));
    });

    group.finish();
}

/// A mempool-shaped hint source: an identity scan plus hash-indexed body
/// lookups, so the timed cost is the reconstruction code and not the fixture.
struct BenchHints {
    identities: Vec<(Txid, Wtxid)>,
    by_txid: HashMap<Txid, Tx>,
    by_wtxid: HashMap<Wtxid, Tx>,
}

impl BenchHints {
    fn new(txs: impl IntoIterator<Item = Tx>) -> Self {
        let mut hints = Self {
            identities: Vec::new(),
            by_txid: HashMap::new(),
            by_wtxid: HashMap::new(),
        };
        for tx in txs {
            let (txid, wtxid) = (tx.txid(), tx.wtxid());
            hints.identities.push((txid, wtxid));
            hints.by_txid.insert(txid, tx.clone());
            hints.by_wtxid.insert(wtxid, tx);
        }
        hints
    }
}

impl CompactBlockHints for BenchHints {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
        for (txid, wtxid) in &self.identities {
            f(*txid, *wtxid);
        }
    }

    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        self.by_txid.get(&txid).cloned()
    }

    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        self.by_wtxid.get(&wtxid).cloned()
    }
}

/// A distinct, witness-free transaction keyed on `seed`.
#[expect(clippy::expect_used, reason = "timed fixture calls must fail loudly")]
fn bench_tx(seed: u32) -> Tx {
    let mut prevout = [0_u8; 32];
    prevout[..4].copy_from_slice(&seed.to_le_bytes());
    let byte = u8::try_from(seed & 0xff).expect("low byte");
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from(Hash256::from_le_bytes(&prevout)),
                vout: 0,
            },
            script_sig: vec![byte].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![byte].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

/// A block of `tx_count` transactions whose header commits to their
/// transaction-ID merkle root, plus the registry `cmpctblock` a peer would
/// send for it.
#[expect(clippy::expect_used, reason = "timed fixture calls must fail loudly")]
fn bench_cmpctblock(txs: &[Tx], nonce: u64) -> CmpctBlock {
    let mut native = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::from(Hash256::from_le_bytes(&[0xab; 32])),
            merkle_root: Hash256::default(),
            time: 7,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 9,
        },
        txs: txs.to_vec(),
    };
    let registry: bitcoin::Block =
        bitcoin::consensus::encode::deserialize(&consensus_bytes(&native))
            .expect("fixture block bridges to the registry type");
    let root = registry
        .compute_merkle_root()
        .expect("a non-empty block has a merkle root");
    native.header.merkle_root = Hash256::from_le_bytes(&root.to_byte_array());
    let bridged: bitcoin::Block =
        bitcoin::consensus::encode::deserialize(&consensus_bytes(&native))
            .expect("the patched header still bridges");
    CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(&bridged, nonce, 2, &[])
            .expect("fixture compact block builds"),
    }
}

/// Times one receive-side `cmpctblock` reconstruction: the short-ID scan over
/// a resident mempool and the verified completion that delivers the block.
#[expect(clippy::expect_used, reason = "timed fixture calls must fail loudly")]
fn bench_compact_reconstruction(c: &mut Criterion) {
    let mut group = c.benchmark_group("compact_reconstruction");
    for (block_txs, pool_txs, missing) in [(100_usize, 5_000_usize, 0_usize), (100, 5_000, 5)] {
        let body: Vec<Tx> = (1..=u32::try_from(block_txs).expect("block size fits u32"))
            .map(bench_tx)
            .collect();
        let mut pool: Vec<Tx> = (1..=u32::try_from(pool_txs).expect("pool size fits u32"))
            .map(|seed| bench_tx(seed + 1_000_000))
            .collect();
        // The first `missing` block transactions stay out of the pool, so the
        // reconstruction has to ask for them by absolute index.
        pool.extend(body.iter().skip(missing).cloned());
        let hints = BenchHints::new(pool);
        let cmpct = bench_cmpctblock(&body, 0x1234);
        let label = format!("block_{block_txs}_pool_{pool_txs}_missing_{missing}");
        group.bench_function(label, |b| {
            b.iter(|| {
                let mut reconstruction = Reconstruction::new();
                reconstruction.receive_cmpctblock(
                    black_box(&cmpct),
                    COMPACT_BLOCK_VERSION,
                    black_box(&hints),
                    Instant::now(),
                );
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_write_message, bench_compact_reconstruction);
criterion_main!(benches);
