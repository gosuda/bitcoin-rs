use std::hint::black_box;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::Instant;

use hashbrown::HashMap;

use bitcoin::Network;
use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, BlockPayload, CompactTarget, Hash256, Header, LockTime, OutPoint,
    Sequence, Tx, TxIn, TxOut, Txid, Witness, Wtxid, consensus_bytes,
};
use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};

use bitcoin_rs_p2p::compact_blocks::{COMPACT_BLOCK_VERSION, Outcome};
use bitcoin_rs_p2p::wire::{Message, write_message};
use bitcoin_rs_p2p::{CompactBlockHints, Reconstruction};

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

#[expect(clippy::expect_used, reason = "timed fixture calls must fail loudly")]
fn bench_write_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_message");

    let ping = Message::Ping(42);

    let genesis = genesis_block(Network::Regtest);
    let genesis_bytes = serialize(&genesis);
    let payload = BlockPayload::from_raw(Bytes::from(genesis_bytes)).expect("decode genesis block");
    let block = Message::Block(payload);

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

#[expect(clippy::expect_used, reason = "timed fixture calls must fail loudly")]
fn bench_block_txn(request: &BlockTransactionsRequest, body: &[Tx]) -> BlockTxn {
    let transactions = request
        .indexes
        .iter()
        .map(|index| {
            let tx = body
                .get(usize::try_from(*index).expect("request index fits usize"))
                .expect("a requested index names a block transaction");
            bitcoin::consensus::encode::deserialize(&consensus_bytes(tx))
                .expect("fixture tx bridges to the registry type")
        })
        .collect();
    BlockTxn {
        transactions: BlockTransactions {
            block_hash: request.block_hash,
            transactions,
        },
    }
}

#[expect(clippy::expect_used, reason = "timed fixture calls must fail loudly")]
fn bench_compact_reconstruction(c: &mut Criterion) {
    let mut group = c.benchmark_group("compact_reconstruction");
    for (block_txs, decoys, missing) in [(100_usize, 5_000_usize, 0_usize), (100, 5_000, 5)] {
        let body: Vec<Tx> = (1..=u32::try_from(block_txs).expect("block size fits u32"))
            .map(bench_tx)
            .collect();
        let mut pool: Vec<Tx> = (1..=u32::try_from(decoys).expect("decoy count fits u32"))
            .map(|seed| bench_tx(seed + 1_000_000))
            .collect();
        pool.extend(body.iter().skip(1 + missing).cloned());
        let hints = BenchHints::new(pool);
        let cmpct = bench_cmpctblock(&body, 0x1234);
        let mut probe = Reconstruction::new();
        let first = probe.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &hints, Instant::now());
        let reply = match first {
            Outcome::Complete(block) => {
                assert_eq!(block.txs, body, "missing=0 reconstructs the block");
                None
            }
            Outcome::RequestMissing(request) => {
                assert_eq!(
                    request.txs_request.indexes,
                    (1_u64..).take(missing).collect::<Vec<u64>>(),
                    "the request must name exactly the excluded transactions"
                );
                Some(bench_block_txn(&request.txs_request, &body))
            }
            outcome => panic!("fixture must complete or request missing txs, got {outcome:?}"),
        };
        if let Some(reply) = &reply {
            assert!(
                matches!(
                    probe.receive_blocktxn(reply, Instant::now()),
                    Outcome::Complete(_)
                ),
                "the completion stage must deliver the verified block"
            );
        }
        let label = format!("block_{block_txs}_decoys_{decoys}_missing_{missing}");
        group.bench_function(label, |b| {
            b.iter(|| {
                let mut reconstruction = Reconstruction::new();
                let outcome = reconstruction.receive_cmpctblock(
                    black_box(&cmpct),
                    COMPACT_BLOCK_VERSION,
                    black_box(&hints),
                    Instant::now(),
                );
                black_box(&outcome);
                if let Outcome::RequestMissing(_) = outcome {
                    let reply = reply.as_ref().expect("missing cells always have a reply");
                    black_box(reconstruction.receive_blocktxn(black_box(reply), Instant::now()));
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_write_message, bench_compact_reconstruction);
criterion_main!(benches);
