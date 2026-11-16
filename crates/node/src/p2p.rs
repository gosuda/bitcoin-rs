pub mod block_announce;
pub mod block_stager;
pub mod chain_query;
pub mod download_window;
pub mod sync;
pub mod tx_policy;
pub mod tx_relay;

#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::as_conversions,
    reason = "relocated p2p orchestration test fixtures"
)]
mod block_forward_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arc_swap::ArcSwapOption;
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin_rs_consensus::primitives::{Hash256, consensus_bytes};
    use parking_lot::RwLock;

    use crate::p2p::sync::BlockSync;
    use crate::p2p::sync::chain::SyncChain;
    use crate::p2p::sync::test_support::{TestChain, mined_chain};
    use crate::test_support::{TestError, TestResult};
    use bitcoin_rs_execution::chain::regtest_fixture;
    use bitcoin_rs_wire::PeerSource;
    use bitcoin_rs_wire::connection::MAX_UNSOLICITED_BLOCK_FORWARDS;
    use bitcoin_rs_wire::listener::{ConnectionShared, test_shared};
    use bitcoin_rs_wire::test_support::{connect_peer, current_source, synthetic_peer, test_addr};

    fn genesis_body() -> bitcoin_rs_consensus::primitives::Block {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let bytes = bitcoin::consensus::encode::serialize(&genesis);
        bitcoin_rs_consensus::primitives::deserialize::<bitcoin_rs_consensus::primitives::Block>(
            &bytes,
        )
        .expect("regtest genesis block must decode")
    }

    struct MinedSyncFixture {
        sync: Arc<BlockSync>,
        blocks: Vec<bitcoin_rs_consensus::primitives::Block>,
        sync_headers_tx: crossbeam_channel::Sender<bitcoin_rs_wire::InboundHeaders>,
    }

    fn test_sync_with_mined_chain(
        peers: &Arc<bitcoin_rs_wire::PeerTable>,
    ) -> Result<MinedSyncFixture, TestError> {
        let (mut tree, blocks) = mined_chain(1, 0)?;
        let chain_tip = tree.tip_handle();
        let block_tree = Arc::new(RwLock::new(tree));
        let (sync_headers_tx, sync_headers_rx) = crossbeam_channel::unbounded();
        let (sync_blocks_tx, sync_blocks_rx) = crossbeam_channel::unbounded();
        let chain: Arc<dyn SyncChain> = Arc::new(TestChain::new(
            chain_tip,
            Arc::new(ArcSwapOption::empty()),
            Arc::clone(&block_tree),
        ));
        let sync = Arc::new(BlockSync::new(
            chain,
            Arc::clone(peers),
            sync_headers_rx,
            sync_blocks_rx,
            crate::p2p::sync::syncing_ibd_latch(),
        ));
        sync_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
        sync.tick();
        Ok(MinedSyncFixture {
            sync,
            blocks,
            sync_headers_tx,
        })
    }

    #[test]
    fn unsolicited_block_flood_is_bounded_per_source() -> TestResult {
        let peers = Arc::new(bitcoin_rs_wire::PeerTable::new());
        let MinedSyncFixture {
            sync,
            blocks,
            sync_headers_tx,
        } = test_sync_with_mined_chain(&peers)?;

        let flooded = test_addr(9780, 0)?;
        let _rx = connect_peer(&peers, synthetic_peer(flooded, 3));
        let source = current_source(&peers, flooded);
        let block2 = regtest_fixture::mined_block_with_prev_hash(
            blocks[0].block_hash(),
            2,
            vec![regtest_fixture::coinbase(2)],
        )
        .unwrap_or_else(|error| panic!("regtest fixture block: {error}"));
        sync_headers_tx.send(bitcoin_rs_wire::InboundHeaders {
            headers: vec![block2.header],
            source: Some(source),
            wire_response: true,
        })?;
        sync.tick();
        assert!(
            sync.owns_body_fetch(source, Hash256::from(block2.block_hash())),
            "fixture: the window must own block 2's body for this connection"
        );

        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(&peers), headers_tx, blocks_tx);
        shared.block_sync =
            Some(sync.clone() as Arc<dyn bitcoin_rs_wire::listener::BlockSyncObserver>);
        let lease = peers
            .lease(flooded)
            .ok_or("flood connection must be registered")?;
        let unrelated = genesis_body();

        for _ in 0..=MAX_UNSOLICITED_BLOCK_FORWARDS {
            shared.send_block(
                &lease,
                flooded,
                bitcoin_rs_consensus::primitives::BlockImage::from_local(unrelated.clone()),
                None,
            );
        }
        assert_eq!(
            blocks_rx.len(),
            MAX_UNSOLICITED_BLOCK_FORWARDS,
            "one connection may not exceed its own unsolicited forwarding bound"
        );

        shared.send_block(
            &lease,
            flooded,
            bitcoin_rs_consensus::primitives::BlockImage::from_local(block2),
            None,
        );
        assert_eq!(
            blocks_rx.len(),
            MAX_UNSOLICITED_BLOCK_FORWARDS + 1,
            "a delivery the window owns is never dropped for the unsolicited bound"
        );

        let other: bitcoin_rs_wire::PeerRemote = test_addr(9781, 0)?;
        let _other_rx = connect_peer(&peers, synthetic_peer(other, 3));
        let other_lease = peers
            .lease(other)
            .ok_or("second connection must be registered")?;
        shared.send_block(
            &other_lease,
            other,
            bitcoin_rs_consensus::primitives::BlockImage::from_local(unrelated.clone()),
            None,
        );
        assert_eq!(
            blocks_rx.len(),
            MAX_UNSOLICITED_BLOCK_FORWARDS + 2,
            "the bound is one connection's share of the channel, not a global cap"
        );

        while blocks_rx.try_recv().is_ok() {}
        shared.send_block(
            &lease,
            flooded,
            bitcoin_rs_consensus::primitives::BlockImage::from_local(unrelated),
            None,
        );
        assert_eq!(
            blocks_rx.len(),
            1,
            "a forwarding slot returns once sync has taken the body"
        );
        Ok(())
    }

    struct ScanCounter(std::sync::atomic::AtomicUsize);

    impl bitcoin_rs_wire::compact_blocks::CompactBlockHints for ScanCounter {
        fn for_each_identity(
            &self,
            _f: &mut dyn FnMut(
                bitcoin_rs_consensus::primitives::Txid,
                bitcoin_rs_consensus::primitives::Wtxid,
            ),
        ) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        fn get_tx_by_txid(
            &self,
            _txid: bitcoin_rs_consensus::primitives::Txid,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            None
        }

        fn get_tx_by_wtxid(
            &self,
            _wtxid: bitcoin_rs_consensus::primitives::Wtxid,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            None
        }
    }

    struct CompactTestFixture {
        sync: Arc<BlockSync>,
        blocks: Vec<bitcoin_rs_consensus::primitives::Block>,
        addr: bitcoin_rs_wire::PeerRemote,
        lease: bitcoin_rs_wire::PeerLease,
        source: PeerSource,
        other_source: PeerSource,
        headers_rx: crossbeam_channel::Receiver<bitcoin_rs_wire::InboundHeaders>,
        blocks_rx: crossbeam_channel::Receiver<bitcoin_rs_wire::InboundBlock>,
        shared: ConnectionShared,
    }

    fn test_sync_with_applied_chain(
        peers: &Arc<bitcoin_rs_wire::PeerTable>,
    ) -> Result<CompactTestFixture, TestError> {
        let (mut tree, blocks) = mined_chain(2, 0)?;
        let chain_tip = tree.tip_handle();
        let applied_tip = Arc::new(ArcSwapOption::new(chain_tip.load_full()));
        let chain: Arc<dyn SyncChain> = Arc::new(TestChain::new(
            chain_tip,
            applied_tip,
            Arc::new(RwLock::new(tree)),
        ));
        let sync = Arc::new(BlockSync::new(
            chain,
            Arc::clone(peers),
            crossbeam_channel::unbounded().1,
            crossbeam_channel::unbounded().1,
            crate::p2p::sync::syncing_ibd_latch(),
        ));
        let addr = test_addr(9782, 0)?;
        let _outbound = connect_peer(peers, synthetic_peer(addr, 3));
        let lease = peers.lease(addr).ok_or("peer must be registered")?;
        let source = lease.source(addr.endpoint());
        let other_addr = test_addr(9783, 0)?;
        let _other = connect_peer(peers, synthetic_peer(other_addr, 3));
        let other_source = peers
            .lease(other_addr)
            .ok_or("second peer must be registered")?
            .source(other_addr.endpoint());
        let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
        let mut shared = test_shared(Arc::clone(peers), headers_tx, blocks_tx);
        shared.block_sync =
            Some(sync.clone() as Arc<dyn bitcoin_rs_wire::listener::BlockSyncObserver>);
        Ok(CompactTestFixture {
            sync,
            blocks,
            addr,
            lease,
            source,
            other_source,
            headers_rx,
            blocks_rx,
            shared,
        })
    }

    fn deliver_compact_block(
        block: &bitcoin_rs_consensus::primitives::Block,
        reconstruction: &mut bitcoin_rs_wire::compact_blocks::Reconstruction,
        hints: &ScanCounter,
        lease: &bitcoin_rs_wire::PeerLease,
        addr: bitcoin_rs_wire::PeerRemote,
        shared: &ConnectionShared,
    ) -> Result<(), TestError> {
        let block: bitcoin::Block =
            bitcoin::consensus::encode::deserialize(&consensus_bytes(block))?;
        let message = crate::p2p::Message::CmpctBlock(CmpctBlock {
            compact_block: HeaderAndShortIds::from_block(&block, 7, 2, &[]).expect("compact block"),
        });
        let reply = bitcoin_rs_wire::listener::reply_bound(&message, false)
            .and_then(|bound| lease.try_reserve_reply(bound).ok());
        let sink = bitcoin_rs_wire::listener::ProductionSink::new(lease, reply);
        bitcoin_rs_wire::listener::process_compact_wire_message(
            &message,
            reconstruction,
            Some(2),
            Some(hints),
            &sink,
            addr,
            shared,
            None,
        );
        Ok(())
    }

    #[test]
    fn compact_reconstruction_requires_an_earning_header() -> TestResult {
        let peers = Arc::new(bitcoin_rs_wire::PeerTable::new());
        let fixture = test_sync_with_applied_chain(&peers)?;
        let sync = fixture.sync;
        let blocks = fixture.blocks;
        let addr = fixture.addr;
        let lease = fixture.lease;
        let source = fixture.source;
        let other_source = fixture.other_source;
        let headers_rx = fixture.headers_rx;
        let blocks_rx = fixture.blocks_rx;
        let shared = fixture.shared;

        let hints = ScanCounter(AtomicUsize::new(0));
        let mut reconstruction = bitcoin_rs_wire::compact_blocks::Reconstruction::new();
        let mut deliver = |block: &bitcoin_rs_consensus::primitives::Block| {
            deliver_compact_block(block, &mut reconstruction, &hints, &lease, addr, &shared)
        };
        let scans = || hints.0.load(Ordering::Relaxed);

        let assert_reconstructed =
            |expected_scans: usize, expected_blocks: usize, message: &str| {
                assert_eq!(scans(), expected_scans, "{message}");
                assert_eq!(blocks_rx.len(), expected_blocks, "{message}");
            };
        let tip = blocks.last().ok_or("chain has a tip")?;
        let next = |height| {
            regtest_fixture::mined_block_with_prev_hash(
                tip.block_hash(),
                height,
                vec![regtest_fixture::coinbase(height)],
            )
        };

        let mut no_work = next(3)?;
        no_work.header.bits =
            bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x1d00_ffff);
        deliver(&no_work)?;

        let orphan = regtest_fixture::mined_block_with_prev_hash(
            no_work.header.compute_hash(),
            4,
            vec![regtest_fixture::coinbase(4)],
        )?;
        deliver(&orphan)?;

        let replayed = blocks.first().ok_or("chain has block 1")?;
        deliver(replayed)?;
        assert_reconstructed(0, 0, "no rejected header reaches the mempool");
        for _ in 0..3 {
            let announced = headers_rx.try_recv()?;
            assert_eq!(announced.headers.len(), 1, "each header is still announced");
        }

        assert!(sync.enqueue_owned_body_fetch(
            other_source,
            Hash256::from(replayed.block_hash()),
            || true,
        ));
        deliver(replayed)?;
        assert_reconstructed(0, 0, "ownership is by exact connection");
        assert_eq!(headers_rx.try_recv()?.headers.len(), 1);

        assert!(sync.enqueue_owned_body_fetch(
            source,
            Hash256::from(replayed.block_hash()),
            || true,
        ));
        deliver(replayed)?;
        assert_reconstructed(1, 1, "this connection owns the replayed body fetch");

        let extending = next(3)?;
        deliver(&extending)?;
        assert_reconstructed(2, 2, "an extending block reconstructs without a request");

        deliver(&extending)?;
        assert_reconstructed(2, 2, "a repeat never rescans the mempool");
        Ok(())
    }
}
#[cfg(test)]
mod compact_blocks_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use crate::p2p::RefTxInventory;
    use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds, PrefilledTransaction, ShortId};
    use bitcoin::blockdata::block::Block as RegistryBlock;
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, Hash256, Header, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut,
        Txid, Witness, Wtxid, consensus_bytes, unix_time_secs,
    };
    use bitcoin_rs_wire::compact_blocks::{
        CompactBlockHints, MAX_BLOCK_TX_COUNT, MAX_PENDING_RETAINED_BYTES, Outcome,
        PENDING_DEADLINE, Reconstruction,
    };
    use bitcoin_rs_wire::inv::wire_block_hash;
    use bitcoin_rs_wire::peer::COMPACT_BLOCK_VERSION;

    struct SetHints {
        txs: Vec<Tx>,
    }

    impl CompactBlockHints for SetHints {
        fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
            for tx in &self.txs {
                f(tx.txid(), tx.wtxid());
            }
        }

        fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
            self.txs.iter().find(|tx| tx.txid() == txid).cloned()
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            self.txs.iter().find(|tx| tx.wtxid() == wtxid).cloned()
        }
    }

    struct CountingHints {
        inner: SetHints,
        scans: AtomicUsize,
    }

    impl CompactBlockHints for CountingHints {
        fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
            self.scans.fetch_add(1, Ordering::Relaxed);
            self.inner.for_each_identity(f);
        }

        fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
            self.inner.get_tx_by_txid(txid)
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            self.inner.get_tx_by_wtxid(wtxid)
        }
    }

    fn test_coinbase(byte: u8) -> Tx {
        let mut tx = test_tx(byte);
        tx.inputs[0].previous_output = OutPoint::null();
        assert!(tx.is_coinbase(), "fixture must be a coinbase");
        tx
    }

    fn test_tx(byte: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
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

    fn registry_tx(tx: &Tx) -> bitcoin::Transaction {
        bitcoin::consensus::encode::deserialize(&consensus_bytes(tx))
            .unwrap_or_else(|error| panic!("test tx must bridge: {error}"))
    }

    fn registry_block(native: &Block) -> RegistryBlock {
        bitcoin::consensus::encode::deserialize(&consensus_bytes(native))
            .unwrap_or_else(|error| panic!("test block must bridge: {error}"))
    }

    fn conforming_block(txs: Vec<Tx>) -> Block {
        let mut native = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::from(Hash256::from_le_bytes(&[0xab; 32])),
                merkle_root: Hash256::default(),
                time: 7,
                bits: bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(
                    bitcoin_rs_execution::chain::regtest_fixture::REGTEST_BITS,
                ),
                nonce: 9,
            },
            txs,
        };
        let root = registry_block(&native)
            .compute_merkle_root()
            .unwrap_or_else(|| panic!("a non-empty block has a merkle root"));
        native.header.merkle_root = Hash256::from_le_bytes(&root.to_byte_array());
        assert_eq!(
            registry_block(&native).header.merkle_root,
            root,
            "merkle bytes must bridge losslessly"
        );
        native
    }

    fn compact_of(native: &Block, version: u64, nonce: u64) -> CmpctBlock {
        let version =
            u32::try_from(version).unwrap_or_else(|error| panic!("version fits u32: {error}"));
        let compact = HeaderAndShortIds::from_block(&registry_block(native), nonce, version, &[])
            .unwrap_or_else(|error| panic!("sample compact block must build: {error}"));
        CmpctBlock {
            compact_block: compact,
        }
    }

    fn sample_cmpct(txs: Vec<Tx>, version: u64, nonce: u64) -> (Block, CmpctBlock) {
        let native = conforming_block(txs);
        let cmpct = compact_of(&native, version, nonce);
        (native, cmpct)
    }

    fn cmpct_with_slots(native: &Block, nonce: u64, short_ids: Vec<ShortId>) -> CmpctBlock {
        CmpctBlock {
            compact_block: HeaderAndShortIds {
                header: registry_block(native).header,
                nonce,
                short_ids,
                prefilled_txs: vec![PrefilledTransaction {
                    idx: 0,
                    tx: registry_tx(&native.txs[0]),
                }],
            },
        }
    }

    fn wtxid_short_id(native: &Block, nonce: u64, tx: &Tx) -> ShortId {
        let keys = ShortId::calculate_siphash_keys(&registry_block(native).header, nonce);
        ShortId::with_siphash_keys(tx.wtxid().as_bytes(), keys)
    }

    fn now() -> Instant {
        Instant::now()
    }

    struct MissingCoins;
    impl bitcoin_rs_mempool::AdmissionChain for MissingCoins {
        fn snapshot(&self, _: &Tx) -> Option<bitcoin_rs_mempool::ChainAdmissionSnapshot> {
            Some(bitcoin_rs_mempool::ChainAdmissionSnapshot {
                prevouts: Vec::new(),
                height: 0,
                locktime_cutoff: 0,
                prevout_meta: hashbrown::HashMap::new(),
                csv_active: false,
                ..bitcoin_rs_mempool::ChainAdmissionSnapshot::default()
            })
        }
    }

    fn test_gateway() -> bitcoin_rs_mempool::MempoolGateway {
        bitcoin_rs_mempool::MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(bitcoin_rs_mempool::Mempool::new(
                bitcoin_rs_mempool::MempoolLimits::default(),
            ))),
            None,
            bitcoin_rs_consensus::ValidationEngine::Native,
            None,
        )
    }

    fn peer_source(connection_id: u64) -> bitcoin_rs_mempool::PeerToken {
        bitcoin_rs_mempool::PeerToken {
            endpoint: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::Ip(
                std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            )),
            addr: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::from((
                [127, 0, 0, 1],
                8333,
            ))),
            connection_id,
        }
    }

    fn orphan_tx(prev_byte: u8, witness_byte: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[prev_byte; 32])),
                    vout: 0,
                },
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![witness_byte]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x6a, 4, 1, 2, 3, 4].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn p2sh_true_output() -> Vec<u8> {
        bitcoin::ScriptBuf::from_bytes(vec![0x51])
            .to_p2sh()
            .into_bytes()
    }

    fn p2sh_true_script_sig() -> Vec<u8> {
        vec![0x01, 0x51]
    }

    fn p2p_parent() -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0xD0; 32])), 0),
                script_sig: Vec::<u8>::new().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: p2sh_true_output().into(),
            }],
        }
    }

    fn p2p_child(parent_txid: Txid, marker: u8) -> Tx {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[marker; 20]);
        script.extend_from_slice(&[0x88, 0xac]);
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: p2sh_true_script_sig().into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: script.into(),
            }],
        }
    }

    #[track_caller]
    fn hold_orphan(gateway: &bitcoin_rs_mempool::MempoolGateway, tx: &Arc<Tx>) {
        let outcome = gateway.submit_transaction(
            Arc::clone(tx),
            bitcoin_rs_mempool::AdmissionOrigin::Peer(peer_source(1)),
            None,
            0,
            &MissingCoins,
        );
        assert!(
            matches!(outcome, Ok(bitcoin_rs_mempool::SubmitOutcome::Held { .. })),
            "a peer tx with missing parents must be orphan-held, got {outcome:?}"
        );
    }

    #[test]
    fn extra_ring_orphan_only_hint_completes_reconstruction() {
        let gateway = test_gateway();
        let orphan = Arc::new(orphan_tx(0xA1, 0x01));
        hold_orphan(&gateway, &orphan);
        assert!(
            !gateway.read().contains_txid(&orphan.txid()),
            "an orphan-held tx must not be pool-resident"
        );
        assert_eq!(gateway.get_tx(orphan.txid()), None);

        let native = conforming_block(vec![test_tx(0xC0), (*orphan).clone()]);
        let cmpct = compact_of(&native, COMPACT_BLOCK_VERSION, 0x60);
        let mut reconstruction = Reconstruction::new();
        let outcome = reconstruction.receive_cmpctblock(
            &cmpct,
            COMPACT_BLOCK_VERSION,
            &RefTxInventory(&gateway),
            now(),
        );
        let Outcome::Complete(block) = outcome else {
            panic!("a ring-only hint must complete the block, got {outcome:?}");
        };
        assert_eq!(block.block_hash(), native.block_hash());
        assert_eq!(block.materialize().txs, native.txs);
        assert!(
            !gateway.read().contains_txid(&orphan.txid()),
            "reconstruction must never admit a hinted body"
        );
        assert_eq!(gateway.get_tx(orphan.txid()), None);
    }

    #[test]
    fn pool_and_ring_share_identity_without_false_collision() {
        let gateway = test_gateway();
        let parent = p2p_parent();
        let parent_txid = parent.txid();
        let child = Arc::new(p2p_child(parent_txid, 0x07));
        hold_orphan(&gateway, &child);
        let fresh_time = unix_time_secs();
        gateway
            .insert_entry(
                bitcoin_rs_mempool::AdmissionOrigin::Rpc,
                bitcoin_rs_mempool::MempoolEntry::new(
                    Arc::new(parent),
                    100,
                    1_000,
                    fresh_time,
                    1,
                    0,
                ),
            )
            .unwrap_or_else(|error| panic!("parent insertion failed: {error}"));
        let retried = gateway.retry_orphans(&MissingCoins, fresh_time);
        assert!(
            retried.iter().any(|retry| matches!(
                retry.result,
                Ok(bitcoin_rs_mempool::SubmitOutcome::Committed(_))
            )),
            "the orphan child must admit once its parent commits"
        );
        assert!(gateway.read().contains_txid(&child.txid()));

        let native = conforming_block(vec![test_tx(0xC1), (*child).clone()]);
        let cmpct = compact_of(&native, COMPACT_BLOCK_VERSION, 0x61);
        let mut reconstruction = Reconstruction::new();
        let outcome = reconstruction.receive_cmpctblock(
            &cmpct,
            COMPACT_BLOCK_VERSION,
            &RefTxInventory(&gateway),
            now(),
        );
        let Outcome::Complete(block) = outcome else {
            panic!("a pool+ring duplicate identity must complete, got {outcome:?}");
        };
        assert_eq!(block.materialize().txs, native.txs);
    }

    #[test]
    fn v2_witness_variants_stay_distinct() {
        let gateway = test_gateway();
        let first = Arc::new(orphan_tx(0xA2, 0x01));
        let second = Arc::new(orphan_tx(0xA2, 0x02));
        assert_eq!(first.txid(), second.txid(), "variants must share a txid");
        assert_ne!(
            first.wtxid(),
            second.wtxid(),
            "variants must differ in wtxid"
        );
        hold_orphan(&gateway, &first);
        hold_orphan(&gateway, &second);

        let native_first = conforming_block(vec![test_tx(0xC2), (*first).clone()]);
        let cmpct_first = compact_of(&native_first, COMPACT_BLOCK_VERSION, 0x62);
        let mut reconstruction = Reconstruction::new();
        let outcome = reconstruction.receive_cmpctblock(
            &cmpct_first,
            COMPACT_BLOCK_VERSION,
            &RefTxInventory(&gateway),
            now(),
        );
        let Outcome::Complete(block) = outcome else {
            panic!("v2 must resolve the first variant, got {outcome:?}");
        };
        assert_eq!(block.materialize().txs, native_first.txs);

        let native_second = conforming_block(vec![test_tx(0xC2), (*second).clone()]);
        let cmpct_second = compact_of(&native_second, COMPACT_BLOCK_VERSION, 0x66);
        let mut reconstruction = Reconstruction::new();
        let outcome = reconstruction.receive_cmpctblock(
            &cmpct_second,
            COMPACT_BLOCK_VERSION,
            &RefTxInventory(&gateway),
            now(),
        );
        let Outcome::Complete(block) = outcome else {
            panic!("v2 must resolve the second variant, got {outcome:?}");
        };
        assert_eq!(block.materialize().txs, native_second.txs);
    }

    #[test]
    fn v1_shared_txid_ambiguity_requests_missing() {
        let gateway = test_gateway();
        let first = Arc::new(orphan_tx(0xA3, 0x01));
        let second = Arc::new(orphan_tx(0xA3, 0x02));
        assert_eq!(first.txid(), second.txid(), "variants must share a txid");
        assert_ne!(
            first.wtxid(),
            second.wtxid(),
            "variants must differ in wtxid"
        );
        hold_orphan(&gateway, &first);
        hold_orphan(&gateway, &second);

        let native = conforming_block(vec![test_tx(0xC3), (*first).clone()]);
        let cmpct_v1 = compact_of(&native, 1, 0x63);
        let mut reconstruction = Reconstruction::new();
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct_v1, 1, &RefTxInventory(&gateway), now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("v1 txid ambiguity must safely request the slot, got {outcome:?}");
        };
        assert_eq!(request.txs_request.indexes, vec![1]);
        assert_eq!(
            request.txs_request.block_hash,
            wire_block_hash(native.block_hash())
        );

        let cmpct_v2 = compact_of(&native, COMPACT_BLOCK_VERSION, 0x63);
        let mut reconstruction = Reconstruction::new();
        let outcome = reconstruction.receive_cmpctblock(
            &cmpct_v2,
            COMPACT_BLOCK_VERSION,
            &RefTxInventory(&gateway),
            now(),
        );
        let Outcome::Complete(block) = outcome else {
            panic!("v2 must resolve the same variants, got {outcome:?}");
        };
        assert_eq!(block.materialize().txs, native.txs);
    }

    struct EvictAfterWalk<'a> {
        hints: &'a dyn CompactBlockHints,
        gateway: &'a bitcoin_rs_mempool::MempoolGateway,
        evict: Vec<Tx>,
    }

    impl CompactBlockHints for EvictAfterWalk<'_> {
        fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
            self.hints.for_each_identity(f);
            for tx in &self.evict {
                hold_orphan(self.gateway, &Arc::new(tx.clone()));
            }
        }

        fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
            self.hints.get_tx_by_txid(txid)
        }

        fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
            self.hints.get_tx_by_wtxid(wtxid)
        }
    }

    #[test]
    fn eviction_between_walk_and_fetch_requests_missing() {
        let gateway = test_gateway();
        let victim = Arc::new(orphan_tx(0xB0, 0xB0));
        hold_orphan(&gateway, &victim);
        let native = conforming_block(vec![test_tx(0xC4), (*victim).clone()]);
        let cmpct = compact_of(&native, COMPACT_BLOCK_VERSION, 0x64);

        let mut baseline = Reconstruction::new();
        let outcome = baseline.receive_cmpctblock(
            &cmpct,
            COMPACT_BLOCK_VERSION,
            &RefTxInventory(&gateway),
            now(),
        );
        let Outcome::Complete(block) = outcome else {
            panic!("the held victim must complete before eviction, got {outcome:?}");
        };
        assert_eq!(block.block_hash(), native.block_hash());
        assert_eq!(block.materialize().txs, native.txs);

        let evict: Vec<Tx> = (0..100_u8).map(|i| orphan_tx(0x10 + i, 0x20 + i)).collect();
        let racing = EvictAfterWalk {
            hints: &RefTxInventory(&gateway),
            gateway: &gateway,
            evict,
        };
        let mut reconstruction = Reconstruction::new();
        let outcome =
            reconstruction.receive_cmpctblock(&cmpct, COMPACT_BLOCK_VERSION, &racing, now());
        let Outcome::RequestMissing(request) = outcome else {
            panic!("a body evicted after the walk must be requested, got {outcome:?}");
        };
        assert_eq!(request.txs_request.indexes, vec![1]);
        assert_eq!(
            request.txs_request.block_hash,
            wire_block_hash(native.block_hash())
        );
    }

    #[test]
    fn gateway_hints_do_not_rescue_merkle_mismatch() {
        let gateway = test_gateway();
        let orphan = Arc::new(orphan_tx(0xA5, 0x05));
        hold_orphan(&gateway, &orphan);
        let txs = vec![test_tx(0xC5), (*orphan).clone()];
        let header = Header {
            version: 1,
            prev_blockhash: BlockHash::from(Hash256::from_le_bytes(&[0xab; 32])),
            merkle_root: Hash256::from_le_bytes(&[0; 32]),
            time: 7,
            bits: bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 9,
        };
        let bridged =
            bitcoin::consensus::encode::deserialize::<RegistryBlock>(&consensus_bytes(&Block {
                header,
                txs,
            }))
            .unwrap_or_else(|error| panic!("sample block must decode: {error}"));
        let compact = HeaderAndShortIds::from_block(&bridged, 0x65, 2, &[])
            .unwrap_or_else(|error| panic!("sample compact block must build: {error}"));
        let mut reconstruction = Reconstruction::new();
        let outcome = reconstruction.receive_cmpctblock(
            &CmpctBlock {
                compact_block: compact,
            },
            COMPACT_BLOCK_VERSION,
            &RefTxInventory(&gateway),
            now(),
        );
        assert!(
            matches!(outcome, Outcome::Fallback(_)),
            "ring hints must never rescue a merkle mismatch, got {outcome:?}"
        );
        assert!(gateway.read().is_empty(), "hints are read-only");
    }

    fn blocks_with_prefilled_witness_items(items: usize) -> (Block, CmpctBlock) {
        let mut heavy = test_coinbase(1);
        heavy.inputs[0].witness = Witness::from_stack(vec![Vec::new(); items]);
        let native = conforming_block(vec![heavy, test_tx(2)]);
        let short_id = wtxid_short_id(&native, 7, &native.txs[1]);
        let cmpct = cmpct_with_slots(&native, 7, vec![short_id]);
        (native, cmpct)
    }

    #[test]
    fn prefilled_witness_heap_counts_against_the_pending_retention_cap() {
        let hints = SetHints { txs: Vec::new() };

        let (_, light) = blocks_with_prefilled_witness_items(100);
        assert!(
            matches!(
                Reconstruction::new().receive_cmpctblock(&light, 2, &hints, now()),
                Outcome::RequestMissing(_)
            ),
            "control: a small prefilled witness stays well under the 8 MiB cap"
        );

        let (_, heavy) = blocks_with_prefilled_witness_items(2_200_000);
        assert!(
            matches!(
                Reconstruction::new().receive_cmpctblock(&heavy, 2, &hints, now()),
                Outcome::Fallback(_)
            ),
            "decoded witness heap must be charged, not only the serialized length"
        );
    }

    #[test]
    fn slot_metadata_over_budget_falls_back_before_hint_scan() {
        let (_, mut cmpct) = sample_cmpct(vec![test_tx(1), test_tx(2)], 2, 0x81);
        let slots = MAX_BLOCK_TX_COUNT;
        let slot_count =
            u64::try_from(slots).unwrap_or_else(|error| panic!("slot count fits: {error}"));
        cmpct.compact_block.short_ids = (1..slot_count)
            .map(|index: u64| {
                let bytes = index.to_le_bytes();
                ShortId::from(
                    <[u8; 6]>::try_from(&bytes[..6])
                        .unwrap_or_else(|error| panic!("short ID has six bytes: {error}")),
                )
            })
            .collect();
        let hints = CountingHints {
            inner: SetHints { txs: Vec::new() },
            scans: AtomicUsize::new(0),
        };
        let mut reconstruction = Reconstruction::new();
        let mut prefill = test_tx(3);
        prefill.outputs[0].script_pubkey = vec![3; MAX_PENDING_RETAINED_BYTES / 2].into();
        let (_, pending) = sample_cmpct(vec![prefill, test_tx(4)], 2, 0x82);
        assert!(matches!(
            reconstruction.receive_cmpctblock(&pending, 2, &hints, now()),
            Outcome::RequestMissing(_)
        ));
        let retained_before = reconstruction.retained_bytes();
        assert!(
            retained_before + slots * core::mem::size_of::<Option<Tx>>()
                > MAX_PENDING_RETAINED_BYTES
        );
        assert!(matches!(
            reconstruction.receive_cmpctblock(&cmpct, 2, &hints, now()),
            Outcome::Fallback(_)
        ));
        assert_eq!(hints.scans.load(Ordering::Relaxed), 1);
        assert_eq!(reconstruction.retained_bytes(), retained_before);
    }

    #[test]
    fn metadata_inclusive_budget_is_reusable_after_pending_release() {
        let hints = SetHints { txs: Vec::new() };
        for release in 0..3 {
            let mut reconstruction = Reconstruction::new();
            let received_at = now();
            let mut blocks = Vec::new();
            for seed in 1..=3 {
                let mut txs: Vec<Tx> = (0..=128).map(test_tx).collect();
                txs[0].lock_time = LockTime::from_consensus(seed);
                let overhead = 129 * core::mem::size_of::<Option<Tx>>()
                    + 128 * core::mem::size_of::<u64>()
                    + 128 * 6
                    + core::mem::size_of::<Tx>()
                    + txs[0].retained_heap_bytes()
                    - txs[0].outputs[0].script_pubkey.len();
                txs[0].outputs[0].script_pubkey =
                    vec![1; MAX_PENDING_RETAINED_BYTES / 2 - overhead].into();
                blocks.push(sample_cmpct(txs, 2, u64::from(seed)));
            }
            for (index, (_, cmpct)) in blocks[..2].iter().enumerate() {
                if index == 1 {
                    let mut oversized = blocks[1].0.txs.clone();
                    let script_len = oversized[0].outputs[0].script_pubkey.len();
                    oversized[0].outputs[0].script_pubkey = vec![1; script_len + 1].into();
                    let (_, over_budget) = sample_cmpct(oversized, 2, 0x83);
                    assert!(matches!(
                        reconstruction.receive_cmpctblock(&over_budget, 2, &hints, received_at),
                        Outcome::Fallback(_)
                    ));
                    assert_eq!(
                        reconstruction.retained_bytes(),
                        MAX_PENDING_RETAINED_BYTES / 2
                    );
                }
                assert!(matches!(
                    reconstruction.receive_cmpctblock(cmpct, 2, &hints, received_at),
                    Outcome::RequestMissing(_)
                ));
                assert_eq!(
                    reconstruction.retained_bytes(),
                    (index + 1) * (MAX_PENDING_RETAINED_BYTES / 2)
                );
            }
            assert!(matches!(
                reconstruction.receive_cmpctblock(&blocks[2].1, 2, &hints, received_at),
                Outcome::Fallback(_)
            ));
            assert_eq!(reconstruction.pending_len(), 2);
            let retry_at = if release == 2 {
                let expired_at = received_at + PENDING_DEADLINE;
                reconstruction.prune(expired_at);
                assert_eq!(reconstruction.retained_bytes(), 0);
                expired_at
            } else {
                let native = &blocks[0].0;
                let transactions = if release == 0 {
                    native.txs[1..].iter().map(registry_tx).collect()
                } else {
                    Vec::new()
                };
                let result = reconstruction.receive_blocktxn(
                    &BlockTxn {
                        transactions: BlockTransactions {
                            block_hash: wire_block_hash(native.block_hash()),
                            transactions,
                        },
                    },
                    received_at,
                );
                if release == 0 {
                    let Outcome::Complete(block) = result else {
                        panic!("expected complete block, got {result:?}");
                    };
                    assert_eq!(block.materialize().txs, native.txs);
                } else {
                    assert!(matches!(result, Outcome::Fallback(_)));
                }
                assert_eq!(
                    reconstruction.retained_bytes(),
                    MAX_PENDING_RETAINED_BYTES / 2
                );
                received_at
            };
            let mut retry = blocks[2].1.clone();
            retry.compact_block.header.nonce += 1;
            assert!(matches!(
                reconstruction.receive_cmpctblock(&retry, 2, &hints, retry_at),
                Outcome::RequestMissing(_)
            ));
            assert!(reconstruction.retained_bytes() <= MAX_PENDING_RETAINED_BYTES);
        }
    }
}
#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "relocated p2p orchestration test fixtures"
)]
mod dispatch_tests {
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::sync::Arc;

    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::Magic;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_consensus::primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_mempool::{
        AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolEntry,
        MempoolGateway, MempoolLimits, PeerToken, SubmitOutcome,
    };
    use bitcoin_rs_wire::dispatch::{
        ChainQuery, TxInventory, dispatch_inbound_full, serve_getdata,
    };
    use bitcoin_rs_wire::peer::{Peer, PeerState};
    use bitcoin_rs_wire::wire::{Message, PeerError};

    use crate::p2p::RefTxInventory;

    fn dummy_tx(byte: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                    vout: 0,
                },
                script_sig: vec![byte].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x6A].into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn ready_peer() -> Peer<Cursor<Vec<u8>>> {
        let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
        peer.state = PeerState::Ready;
        peer
    }

    fn dispatch_collect_full<S: std::io::Read + std::io::Write>(
        peer: &mut Peer<S>,
        message: &Message,
        chain: Option<&dyn ChainQuery>,
        tx_inventory: Option<&dyn TxInventory>,
    ) -> Result<Vec<Message>, PeerError> {
        let collected = RefCell::new(Vec::new());
        dispatch_inbound_full(
            peer,
            message,
            chain,
            tx_inventory,
            &|| true,
            &|| true,
            &mut |response| {
                collected.borrow_mut().push(response);
                Ok(())
            },
            &mut |_| {},
            &mut |items| collected.borrow_mut().push(Message::GetData(items)),
        )?;
        Ok(collected.into_inner())
    }

    fn gateway_holding_witness_tx(orphan: bool) -> (MempoolGateway, Arc<Tx>) {
        struct MissingCoins;
        impl AdmissionChain for MissingCoins {
            fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
                Some(ChainAdmissionSnapshot {
                    prevouts: Vec::new(),
                    height: 0,
                    locktime_cutoff: 0,
                    prevout_meta: hashbrown::HashMap::new(),
                    csv_active: false,
                    ..ChainAdmissionSnapshot::default()
                })
            }
        }

        let gateway = MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(
                MempoolLimits::default(),
            ))),
            None,
            ValidationEngine::Native,
            None,
        );
        let mut tx = dummy_tx(0x51);
        tx.inputs[0].script_sig.clear();
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
        tx.outputs[0].script_pubkey = Script::from_bytes(vec![0x6a, 4, 1, 2, 3, 4]);
        let tx = Arc::new(tx);
        if orphan {
            let source = PeerToken {
                endpoint: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::Ip(
                    std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
                )),
                addr: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::from((
                    [127, 0, 0, 1],
                    8333,
                ))),
                connection_id: 1,
            };
            assert!(matches!(
                gateway.submit_transaction(
                    Arc::clone(&tx),
                    AdmissionOrigin::Peer(source),
                    None,
                    0,
                    &MissingCoins,
                ),
                Ok(SubmitOutcome::Held { .. })
            ));
            assert_eq!(gateway.orphan_count(), 1);
        } else {
            assert!(
                gateway
                    .insert_entry(
                        AdmissionOrigin::Rpc,
                        MempoolEntry::new(Arc::clone(&tx), 100, 10_000, 1, 0, 0),
                    )
                    .is_ok()
            );
        }
        (gateway, tx)
    }

    #[test]
    fn getdata_completes_initial_broadcast_only_after_successful_send() -> Result<(), PeerError> {
        for kind in 0..3 {
            let gateway = MempoolGateway::new(
                Arc::new(parking_lot::RwLock::new(Mempool::new(
                    MempoolLimits::default(),
                ))),
                None,
                ValidationEngine::Native,
                None,
            );
            let mut tx = dummy_tx(1);
            tx.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
            let txid = tx.txid();
            let wtxid = tx.wtxid();
            gateway
                .insert_entry(
                    AdmissionOrigin::Rpc,
                    MempoolEntry::new(Arc::new(tx), 100, 1000, 1, 0, 0),
                )
                .expect("insert entry");
            let sequence = gateway.read().sequence_number();
            let item = match kind {
                0 => Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())),
                1 => {
                    Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*txid.as_bytes()))
                }
                _ => Inventory::WTx(bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes())),
            };
            let mut not_found = Vec::new();
            assert!(
                serve_getdata(
                    None,
                    Some(&RefTxInventory(&gateway)),
                    None,
                    &[item],
                    &mut not_found,
                    &|| true,
                    &mut |_| Err(PeerError::Misbehavior("test sink full")),
                )
                .is_err()
            );
            assert_eq!(gateway.read().unbroadcast_transactions().count(), 1);
            let mut responses = Vec::new();
            serve_getdata(
                None,
                Some(&RefTxInventory(&gateway)),
                None,
                &[item],
                &mut not_found,
                &|| true,
                &mut |message| {
                    responses.push(message);
                    Ok(())
                },
            )?;
            assert!(matches!(responses.as_slice(), [Message::Tx(_)]));
            assert_eq!(gateway.read().unbroadcast_transactions().count(), 0);
            assert_eq!(gateway.read().sequence_number(), sequence);
        }
        Ok(())
    }

    #[test]
    fn one_sided_wtxid_negotiation_does_not_rerequest_pool_or_orphan_bodies()
    -> Result<(), PeerError> {
        for orphan in [false, true] {
            let (gateway, tx) = gateway_holding_witness_tx(orphan);
            let txid = bitcoin::Txid::from_byte_array(*tx.txid().as_bytes());
            let wtxid = bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes());
            assert_ne!(txid.as_byte_array(), wtxid.as_byte_array());
            for (remote_requested, item) in [
                (false, Inventory::WTx(wtxid)),
                (true, Inventory::Transaction(txid)),
                (true, Inventory::WitnessTransaction(txid)),
            ] {
                let mut peer = ready_peer();
                if remote_requested {
                    peer.wtxid_relay.mark_peer_supported();
                }
                let held_suppresses = !orphan || matches!(item, Inventory::WTx(_));
                let responses = dispatch_collect_full(
                    &mut peer,
                    &Message::Inv(vec![item]),
                    None,
                    Some(&RefTxInventory(&gateway)),
                )?;
                if held_suppresses {
                    assert!(
                        responses.is_empty(),
                        "inventory type must select the held body's identity in either relay direction"
                    );
                } else {
                    assert_eq!(responses, vec![Message::GetData(vec![item])]);
                }

                let unknown = Inventory::WTx(bitcoin::Wtxid::from_byte_array([0xff; 32]));
                let expected = if held_suppresses {
                    vec![unknown]
                } else {
                    vec![item, unknown]
                };
                assert_eq!(
                    dispatch_collect_full(
                        &mut peer,
                        &Message::Inv(vec![item, unknown]),
                        None,
                        Some(&RefTxInventory(&gateway)),
                    )?,
                    vec![Message::GetData(expected)]
                );
            }
        }
        Ok(())
    }

    // P2P-01
    #[test]
    fn getdata_serves_mempool_bodies_but_never_held_orphans() -> Result<(), PeerError> {
        for orphan in [false, true] {
            let (gateway, tx) = gateway_holding_witness_tx(orphan);
            let item = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes()));
            let responses = dispatch_collect_full(
                &mut ready_peer(),
                &Message::GetData(vec![item]),
                None,
                Some(&RefTxInventory(&gateway)),
            )?;
            if orphan {
                assert_eq!(responses, vec![Message::NotFound(vec![item])]);
            } else {
                assert_eq!(responses, vec![Message::Tx((*tx).clone())]);
            }
        }
        Ok(())
    }

    #[test]
    fn gateway_inventory_filters_and_serves_txid_and_wtxid() -> Result<(), PeerError> {
        let gateway = MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(
                MempoolLimits::default(),
            ))),
            None,
            ValidationEngine::Native,
            None,
        );
        let mut tx = dummy_tx(0x42);
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0x01]]);
        let txid_item =
            Inventory::Transaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
        let witness_txid_item =
            Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
        let wtxid_item = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes()));
        assert_ne!(tx.txid().as_bytes(), tx.wtxid().as_bytes());
        assert!(
            gateway
                .insert_entry(
                    AdmissionOrigin::Rpc,
                    MempoolEntry::new(Arc::new(tx.clone()), 100, 10_000, 1, 0, 0),
                )
                .is_ok()
        );

        for (item, wtxid_relay) in [(txid_item, false), (wtxid_item, true)] {
            let mut peer = ready_peer();
            if wtxid_relay {
                peer.wtxid_relay.mark_peer_supported();
            }
            let responses = dispatch_collect_full(
                &mut peer,
                &Message::Inv(vec![item]),
                None,
                Some(&RefTxInventory(&gateway)),
            )?;
            assert_eq!(responses, []);
        }

        let mut stripped = tx.clone();
        for input in &mut stripped.inputs {
            input.witness.clear();
        }
        let missing = Inventory::WTx(bitcoin::Wtxid::from_byte_array([0xFF; 32]));
        let mut peer = ready_peer();
        peer.wtxid_relay.mark_peer_supported();
        let responses = dispatch_collect_full(
            &mut peer,
            &Message::GetData(vec![txid_item, witness_txid_item, wtxid_item, missing]),
            None,
            Some(&RefTxInventory(&gateway)),
        )?;
        assert_eq!(
            responses,
            vec![
                Message::Tx(stripped),
                Message::Tx(tx.clone()),
                Message::Tx(tx.clone()),
                Message::NotFound(vec![missing])
            ],
        );
        assert_eq!(gateway.get_tx_by_wtxid(tx.wtxid()), Some(tx));
        Ok(())
    }
}
#[cfg(test)]
#[expect(
    clippy::as_conversions,
    reason = "relocated p2p orchestration test fixtures"
)]
mod header_ingress_tests {
    use super::*;
    use crate::test_support::TestResult;
    use bitcoin_rs_wire::listener::{ConnectionShared, test_shared};
    use std::time::{Duration, Instant};

    // P2P-07
    #[test]
    fn full_header_ingress_preserves_responses_and_body_first_order() -> TestResult {
        let (headers_tx, headers_rx) = crossbeam_channel::bounded(1);
        let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(1);
        let shared = test_shared(
            Arc::new(bitcoin_rs_wire::PeerTable::new()),
            headers_tx,
            blocks_tx,
        );
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = bitcoin_rs_wire::PeerLease::new(tx);
        let addr = bitcoin_rs_wire::PeerEndpoint::from((std::net::Ipv4Addr::LOCALHOST, 18_450));
        let source = lease.source(Some(addr));
        shared.send_headers_response(&lease, source, Vec::new());
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let payload = bitcoin_rs_consensus::primitives::BlockImage::from_raw(bytes::Bytes::from(
            bitcoin::consensus::serialize(&genesis),
        ))?;
        let expected = payload.materialize().header;
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            shared.send_block(&lease, addr, payload, None);
            let _ = done_tx.send(());
        });

        let body = blocks_rx.recv_timeout(Duration::from_secs(3))?;
        assert_eq!(body.payload().materialize().header, expected);
        assert!(done_rx.recv_timeout(Duration::from_millis(30)).is_err());
        let response = headers_rx.recv()?;
        assert!(response.wire_response);
        assert!(
            response.headers.is_empty(),
            "empty wire responses cannot be lost"
        );
        let carried = headers_rx.recv_timeout(Duration::from_secs(3))?;
        assert_eq!(carried.source, Some(source));
        assert_eq!(carried.headers, vec![expected]);
        assert!(!carried.wire_response);
        done_rx.recv_timeout(Duration::from_secs(3))?;
        worker
            .join()
            .map_err(|_| crate::test_support::TestError::Panicked("header forward panicked"))?;
        Ok(())
    }

    #[test]
    fn full_header_ingress_observes_session_and_lease_cancellation() -> TestResult {
        for cancel_session in [false, true] {
            let (headers_tx, headers_rx) = crossbeam_channel::bounded(1);
            let (blocks_tx, _blocks_rx) = crossbeam_channel::bounded(1);
            let mut shared = test_shared(
                Arc::new(bitcoin_rs_wire::PeerTable::new()),
                headers_tx,
                blocks_tx,
            );
            let session_cancel = bitcoin_rs_consensus::latch::LatchWriter::new();
            shared.session_cancel = session_cancel.reader();
            let (tx, _rx) = crossbeam_channel::unbounded();
            let lease = bitcoin_rs_wire::PeerLease::new(tx);
            let source = lease.source(None);
            shared.send_headers_response(&lease, source, Vec::new());
            let stop = lease.clone();
            let (done_tx, done_rx) = crossbeam_channel::bounded(1);
            let worker = std::thread::spawn(move || {
                shared.send_headers_response(&lease, source, Vec::new());
                let _ = done_tx.send(());
            });
            assert!(done_rx.recv_timeout(Duration::from_millis(30)).is_err());
            if cancel_session {
                session_cancel.trigger();
            } else {
                stop.cancel();
            }
            done_rx.recv_timeout(Duration::from_secs(3))?;
            worker
                .join()
                .map_err(|_| crate::test_support::TestError::Panicked("header forward panicked"))?;
            assert_eq!(headers_rx.len(), 1, "cancelled wait must not enqueue");
        }
        Ok(())
    }

    #[test]
    fn disconnected_header_ingress_releases_the_sender() -> TestResult {
        let (headers_tx, headers_rx) = crossbeam_channel::bounded(1);
        let (blocks_tx, _blocks_rx) = crossbeam_channel::bounded(1);
        let shared = test_shared(
            Arc::new(bitcoin_rs_wire::PeerTable::new()),
            headers_tx,
            blocks_tx,
        );
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = bitcoin_rs_wire::PeerLease::new(tx);
        let source = lease.source(None);
        shared.send_headers_response(&lease, source, Vec::new());
        let (done_tx, done_rx) = crossbeam_channel::bounded(1);
        let worker = std::thread::spawn(move || {
            shared.send_headers_response(&lease, source, Vec::new());
            let _ = done_tx.send(());
        });
        assert!(done_rx.recv_timeout(Duration::from_millis(30)).is_err());
        drop(headers_rx);
        done_rx.recv_timeout(Duration::from_secs(3))?;
        worker
            .join()
            .map_err(|_| crate::test_support::TestError::Panicked("header forward panicked"))?;
        Ok(())
    }

    // P2P-07
    #[test]
    fn sustained_wire_and_body_header_ingress_stays_bounded() -> TestResult {
        run_sustained_ingress_case(HeaderDelivery::WireResponse)?;
        run_sustained_ingress_case(HeaderDelivery::EmbeddedBlock)?;
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum HeaderDelivery {
        WireResponse,
        EmbeddedBlock,
    }

    fn run_sustained_ingress_case(delivery: HeaderDelivery) -> TestResult {
        use crate::p2p::sync::test_support::{TestChain, mined_chain};
        use arc_swap::ArcSwapOption;
        use bitcoin_rs_wire::test_support::{connect_peer, synthetic_peer, test_addr};
        use parking_lot::RwLock;

        const CAPACITY: usize = 64;
        const BATCHES: usize = 128;
        let (mut tree, blocks) = mined_chain(u32::try_from(BATCHES)?, 0)?;
        let tip = tree.tip_handle();
        let tree = Arc::new(RwLock::new(tree));
        let applied = Arc::new(ArcSwapOption::empty());
        let peers = Arc::new(bitcoin_rs_wire::PeerTable::new());
        let (headers_tx, headers_rx) = crossbeam_channel::bounded(CAPACITY);
        let (blocks_tx, blocks_rx) = crossbeam_channel::bounded(256);
        let sync = Arc::new(crate::p2p::sync::BlockSync::new(
            Arc::new(TestChain::new(tip, Arc::clone(&applied), tree)),
            Arc::clone(&peers),
            headers_rx.clone(),
            blocks_rx.clone(),
            crate::p2p::sync::syncing_ibd_latch(),
        ));
        sync.tick();
        let addr = test_addr(9792, 0)?;
        let _outbound_rx = connect_peer(&peers, synthetic_peer(addr, i32::try_from(BATCHES)?));
        let lease = peers
            .lease(addr)
            .ok_or(crate::test_support::TestError::Missing(
                "missing load-test connection",
            ))?;
        let mut shared = test_shared(peers, headers_tx, blocks_tx);
        shared.block_sync =
            Some(sync.clone() as Arc<dyn bitcoin_rs_wire::listener::BlockSyncObserver>);
        let stop = bitcoin_rs_consensus::latch::LatchWriter::new();
        shared.session_cancel = stop.reader();
        let (producer, filled_rx) =
            spawn_ingress_producer(blocks, delivery, shared, lease, addr, Arc::clone(&sync));
        filled_rx.recv_timeout(Duration::from_secs(3))?;
        let started = Instant::now();
        let metrics = drain_sustained_ingress(
            &sync,
            producer,
            &headers_rx,
            &blocks_rx,
            &stop,
            started,
            headers_rx.len(),
        )?;
        let peak_depth = metrics.peak_depth;
        let ticks = metrics.ticks;
        let max_tick = metrics.max_tick;
        assert!(
            headers_rx.is_empty() && blocks_rx.is_empty(),
            "ingress must make progress"
        );
        assert!(peak_depth <= CAPACITY);
        if delivery == HeaderDelivery::EmbeddedBlock {
            assert_eq!(
                applied
                    .load_full()
                    .ok_or(crate::test_support::TestError::Missing("no applied tip",))?
                    .height,
                u32::try_from(BATCHES)?
            );
        }
        let headers_per_batch = if delivery == HeaderDelivery::WireResponse {
            bitcoin_rs_wire::wire::MAX_HEADERS_MESSAGE_COUNT
        } else {
            1
        };
        let payload_bytes =
            peak_depth * headers_per_batch * size_of::<bitcoin_rs_consensus::primitives::Header>();
        let delivery_label = match delivery {
            HeaderDelivery::WireResponse => "wire_response",
            HeaderDelivery::EmbeddedBlock => "embedded_block",
        };
        eprintln!(
            "delivery={delivery_label}, batches={BATCHES}, peak_queue={peak_depth}, queued_header_payload_bytes={payload_bytes}, ticks={ticks}, max_tick={max_tick:?}, elapsed={:?}",
            started.elapsed()
        );
        Ok(())
    }

    struct IngressDrainMetrics {
        peak_depth: usize,
        ticks: usize,
        max_tick: Duration,
    }

    fn drain_sustained_ingress(
        sync: &crate::p2p::sync::BlockSync,
        producer: std::thread::JoinHandle<()>,
        headers_rx: &crossbeam_channel::Receiver<bitcoin_rs_wire::InboundHeaders>,
        blocks_rx: &crossbeam_channel::Receiver<bitcoin_rs_wire::InboundBlock>,
        stop: &bitcoin_rs_consensus::latch::LatchWriter,
        started: Instant,
        initial_peak: usize,
    ) -> Result<IngressDrainMetrics, crate::test_support::TestError> {
        let mut peak_depth = initial_peak;
        let mut max_tick = Duration::ZERO;
        let mut ticks = 0;
        while (!producer.is_finished() || !headers_rx.is_empty() || !blocks_rx.is_empty())
            && started.elapsed() < Duration::from_secs(10)
        {
            peak_depth = peak_depth.max(headers_rx.len());
            let tick_start = Instant::now();
            sync.tick();
            max_tick = max_tick.max(tick_start.elapsed());
            ticks += 1;
            std::thread::yield_now();
        }
        stop.trigger();
        producer
            .join()
            .map_err(|_| crate::test_support::TestError::Panicked("load producer panicked"))?;
        Ok(IngressDrainMetrics {
            peak_depth,
            ticks,
            max_tick,
        })
    }

    fn spawn_ingress_producer(
        blocks: Vec<bitcoin_rs_consensus::primitives::Block>,
        delivery: HeaderDelivery,
        shared: ConnectionShared,
        lease: bitcoin_rs_wire::PeerLease,
        addr: bitcoin_rs_wire::PeerRemote,
        sync: Arc<crate::p2p::sync::BlockSync>,
    ) -> (std::thread::JoinHandle<()>, crossbeam_channel::Receiver<()>) {
        let source = lease.source(addr.endpoint());
        let (filled_tx, filled_rx) = crossbeam_channel::bounded(1);
        let producer = std::thread::spawn(move || {
            for (n, block) in blocks.into_iter().enumerate() {
                if delivery == HeaderDelivery::WireResponse {
                    shared.send_headers_response(
                        &lease,
                        source,
                        vec![block.header; bitcoin_rs_wire::wire::MAX_HEADERS_MESSAGE_COUNT],
                    );
                } else {
                    let hash = bitcoin_rs_consensus::primitives::Hash256::from(block.block_hash());
                    assert!(sync.enqueue_owned_body_fetch(source, hash, || true));
                    shared.send_block(
                        &lease,
                        addr,
                        bitcoin_rs_consensus::primitives::BlockImage::from_local(block),
                        None,
                    );
                }
                if n + 1 == 64 {
                    let _ = filled_tx.send(());
                }
            }
        });
        (producer, filled_rx)
    }
}
#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "relocated p2p orchestration test fixtures"
)]
mod inv_tests {
    use std::net::SocketAddr;

    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin_rs_consensus::primitives::{Hash256, Txid};
    use bitcoin_rs_mempool::PeerToken;
    use bitcoin_rs_wire::connection::PeerLease;
    use bitcoin_rs_wire::peer_table::PeerTable;
    use bitcoin_rs_wire::wire::Message;

    fn parent(byte: u8) -> Txid {
        Txid::from(Hash256::from_le_bytes(&[byte; 32]))
    }

    fn source(lease: &PeerLease) -> PeerToken {
        crate::p2p::peer_token(lease.source_ip(SocketAddr::from(([127, 0, 0, 1], 8333))))
    }

    fn request_missing_parents(peers: &PeerTable, source: PeerToken, parents: &[Txid]) -> bool {
        let Some(session) = peers.sessions().into_iter().find(|session| {
            session.endpoint == source.endpoint
                && session.lease.connection_id().get() == source.connection_id
        }) else {
            return false;
        };
        let lease = session.lease;
        let connection = lease.source(session.endpoint);
        if crate::p2p::peer_token(connection) != source {
            return false;
        }
        let mut witness = false;
        peers.for_each_ready_lease(|addr, current, info| {
            if addr == source.endpoint && current.same_connection(&lease) {
                witness = info.services & bitcoin::p2p::ServiceFlags::WITNESS.to_u64() != 0;
            }
        });
        let mut seen = hashbrown::HashSet::new();
        let mut items: Vec<Inventory> = parents
            .iter()
            .filter(|txid| seen.insert(**txid))
            .map(|txid| Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())))
            .collect();
        if items.is_empty() {
            return false;
        }
        if witness {
            bitcoin_rs_wire::inv::request_witness(&mut items);
        }
        peers.send(connection, Message::GetData(items)).is_ok() && !lease.is_cancelled()
    }

    #[test]
    fn missing_parents_use_txids_and_deduplicate_repeated_inputs() {
        let table = PeerTable::new();
        let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(2);
        let lease = PeerLease::new(sender);
        let source = source(&lease);
        table.register(source.addr.expect("known destination"), lease.clone());

        assert!(request_missing_parents(
            &table,
            source,
            &[parent(1), parent(2), parent(1)],
        ));
        let expected = Message::GetData(vec![
            Inventory::Transaction(bitcoin::Txid::from_byte_array(*parent(1).as_bytes())),
            Inventory::Transaction(bitcoin::Txid::from_byte_array(*parent(2).as_bytes())),
        ]);
        assert!(matches!(receiver.try_recv(), Ok(message) if message == expected));
        assert!(!request_missing_parents(&table, source, &[]));
        assert!(receiver.try_recv().is_err());
        assert!(!lease.is_cancelled());
    }

    #[test]
    fn missing_parents_request_witness_by_service_not_announcement_preference() {
        use bitcoin::p2p::ServiceFlags;
        use std::sync::Arc;

        for witness in [false, true] {
            for wtxid_relay in [false, true] {
                let table = PeerTable::new();
                let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
                let lease = PeerLease::new(sender);
                let source = source(&lease);
                table.register(source.addr.expect("known destination"), lease.clone());
                let mut version = bitcoin_rs_wire::handshake::version_message(
                    1,
                    0,
                    bitcoin_rs_wire::peer_info::PeerRole::FullRelay,
                    bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
                    bitcoin_rs_consensus::primitives::USER_AGENT,
                );
                version.services = if witness {
                    ServiceFlags::NETWORK | ServiceFlags::WITNESS
                } else {
                    ServiceFlags::NETWORK
                };
                let mut info = bitcoin_rs_wire::PeerInfo::inbound_from_version(
                    source.addr.expect("known destination"),
                    source
                        .addr
                        .expect("known destination")
                        .socket_addr()
                        .expect("expected IP fixture"),
                    &version,
                    0,
                    0,
                    Arc::new(bitcoin_rs_wire::PeerCounters::default()),
                );
                info.wtxid_relay = wtxid_relay;
                assert!(table.publish_info(source.addr.expect("known destination"), &lease, info,));

                assert!(request_missing_parents(
                    &table,
                    source,
                    &[parent(1), parent(1)],
                ));
                let txid = bitcoin::Txid::from_byte_array(*parent(1).as_bytes());
                let expected = if witness {
                    Inventory::WitnessTransaction(txid)
                } else {
                    Inventory::Transaction(txid)
                };
                assert!(matches!(
                    receiver.try_recv(),
                    Ok(Message::GetData(items)) if items == vec![expected]
                ));
                assert!(receiver.try_recv().is_err());
                assert!(!lease.is_cancelled());
            }
        }
    }

    #[test]
    fn stale_missing_parent_source_cannot_send_to_or_cancel_replacement() {
        let table = PeerTable::new();
        let (old_sender, old_receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
        let old = PeerLease::new(old_sender);
        let stale_source = source(&old);
        table.register(stale_source.addr.expect("known destination"), old);
        let (new_sender, new_receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
        let current = PeerLease::new(new_sender);
        table.register(
            stale_source.addr.expect("known destination"),
            current.clone(),
        );

        assert!(current.send(Message::Ping(7)).is_ok());
        assert!(!request_missing_parents(&table, stale_source, &[parent(1)]));
        assert!(old_receiver.try_recv().is_err());
        assert!(!current.is_cancelled());
        assert!(matches!(new_receiver.try_recv(), Ok(Message::Ping(7))));
        assert!(new_receiver.try_recv().is_err());
        assert!(request_missing_parents(
            &table,
            source(&current),
            &[parent(1)],
        ));
        assert!(matches!(new_receiver.try_recv(), Ok(Message::GetData(_))));
    }

    #[test]
    fn missing_parent_request_keeps_outbound_saturation_policy() {
        let table = PeerTable::new();
        let (sender, _receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
        let lease = PeerLease::new(sender);
        let source = source(&lease);
        assert!(!request_missing_parents(&table, source, &[parent(1)]));
        table.register(source.addr.expect("known destination"), lease.clone());
        assert!(lease.send(Message::Ping(1)).is_ok());

        assert!(!request_missing_parents(&table, source, &[parent(1)]));
        assert!(lease.is_cancelled());
    }

    #[test]
    fn cancelled_missing_parent_source_does_not_enqueue_a_request() {
        let table = PeerTable::new();
        let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(1);
        let lease = PeerLease::new(sender);
        let source = source(&lease);
        table.register(source.addr.expect("known destination"), lease.clone());
        lease.cancel();

        assert!(!request_missing_parents(&table, source, &[parent(1)]));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn missing_parents_serve_unidentified_inbound_through_own_lease() {
        let table = PeerTable::new();
        let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(2);
        let lease = PeerLease::new_inbound(sender);
        let source = crate::p2p::peer_token(lease.source(None));
        assert!(source.addr.is_none());
        table.register_unidentified(lease.clone());
        let (other_sender, other_receiver) =
            bitcoin_rs_wire::test_support::message_channel_bounded(2);
        let other = PeerLease::new_inbound(other_sender);
        let other_source = crate::p2p::peer_token(other.source(None));
        assert!(other_source.addr.is_none());
        assert_ne!(other_source.connection_id, source.connection_id);
        table.register_unidentified(other.clone());

        assert!(request_missing_parents(
            &table,
            source,
            &[parent(1), parent(1)],
        ));
        let expected = Message::GetData(vec![Inventory::Transaction(
            bitcoin::Txid::from_byte_array(*parent(1).as_bytes()),
        )]);
        assert!(matches!(receiver.try_recv(), Ok(message) if message == expected));
        assert!(other_receiver.try_recv().is_err());
        assert!(!request_missing_parents(&table, source, &[]));
        assert!(receiver.try_recv().is_err());
        assert!(other_receiver.try_recv().is_err());
        assert!(!lease.is_cancelled());
        assert!(!other.is_cancelled());
    }

    #[test]
    fn missing_parents_resolve_unidentified_sessions() {
        let table = PeerTable::new();
        let (sender, receiver) = bitcoin_rs_wire::test_support::message_channel_bounded(2);
        let lease = PeerLease::new(sender);
        table.register_unidentified(lease.clone());
        let source = crate::p2p::peer_token(lease.source(None));
        assert!(source.endpoint.is_none());

        assert!(request_missing_parents(&table, source, &[parent(1)]));
        let expected = Message::GetData(vec![Inventory::Transaction(
            bitcoin::Txid::from_byte_array(*parent(1).as_bytes()),
        )]);
        assert!(matches!(receiver.try_recv(), Ok(message) if message == expected));
        assert!(!lease.is_cancelled());

        let stale = PeerToken {
            endpoint: None,
            addr: None,
            connection_id: source.connection_id.wrapping_add(1),
        };
        assert!(!request_missing_parents(&table, stale, &[parent(1)]));
        assert!(receiver.try_recv().is_err());
    }
}
#[cfg(test)]
mod loopback_serving_tests {
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use std::io;
    use std::net::TcpStream;
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use bitcoin::bip152::ShortId;
    use bitcoin::blockdata::block::Block as RegistryBlock;
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime, Network,
        OutPoint, Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
    };
    use bitcoin_rs_execution::chain::{BlockTree, BlockTreeReader, NodeStatus, TipReader};
    use bitcoin_rs_storage::{
        block_body::{BlockBodyReadError, BlockBodySource},
        split_chainstate_cache_budget,
    };
    use parking_lot::RwLock;

    use crate::p2p::chain_query::{ActiveChainQuery, RecentBlockSlot};
    use bitcoin_rs_wire::listener::{
        ListenerError, bind_listener, configure_peer_stream, run_outbound_handshake, serve,
        test_shared,
    };
    use bitcoin_rs_wire::{
        ChainQuery, Message, Peer, PeerCounters, PeerError, PeerLease, PeerSession, PeerTable,
    };

    const MAGIC: bitcoin::p2p::Magic = bitcoin::p2p::Magic::BITCOIN;
    const FAILSAFE: Duration = Duration::from_secs(20);

    fn wire_len_of(message: &Message) -> Result<usize, PeerError> {
        bitcoin_rs_wire::wire::wire_len(message)
    }

    fn wait_until(what: &str, mut condition: impl FnMut() -> bool) -> Result<(), TestError> {
        let deadline = Instant::now() + FAILSAFE;
        while !condition() {
            if Instant::now() >= deadline {
                return Err(TestError::Failure(format!("timed out waiting for {what}")));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
    use bitcoin_rs_wire::connection::{
        OUTBOUND_QUEUE_MAX_BYTES, Refusal, SHARED_OUTBOUND_QUEUE_MAX_BYTES, SharedOutboundBudget,
    };
    use bitcoin_rs_wire::inv::{MAX_INV_PER_MSG, wire_block_hash};

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Peer(#[from] PeerError),
        #[error(transparent)]
        TryFromInt(#[from] std::num::TryFromIntError),
        #[error(transparent)]
        Chain(#[from] bitcoin_rs_execution::chain::ChainError),
        #[error(transparent)]
        Primitives(#[from] bitcoin_rs_consensus::primitives::DecodeError),
        #[error(transparent)]
        Consensus(#[from] bitcoin::consensus::encode::Error),
        #[error(transparent)]
        Listener(#[from] ListenerError),
        #[error("missing: {0}")]
        Missing(&'static str),
        #[error("failure: {0}")]
        Failure(String),
    }

    type Fallible<T> = Result<T, TestError>;
    type TestResult = Result<(), TestError>;

    impl From<&'static str> for TestError {
        fn from(msg: &'static str) -> Self {
            Self::Missing(msg)
        }
    }

    type Frame = (Message, bytes::Bytes);

    const HOG_OUTPUTS: usize = 30_000;

    const QUIET_POLLS: u32 = 40;

    fn coinbase(tag: u8, outputs: usize) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![tag, tag].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: p2pkh(tag).into(),
                };
                outputs
            ],
            lock_time: LockTime::ZERO,
        }
    }

    fn payment(tag: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from(Hash256::from_le_bytes(&[tag; 32])),
                    vout: 0,
                },
                script_sig: vec![tag].into(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![tag; 32]]),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: p2pkh(tag).into(),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn p2pkh(tag: u8) -> Vec<u8> {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[tag; 20]);
        script.extend_from_slice(&[0x88, 0xac]);
        script
    }

    fn registry_block(block: &Block) -> Result<RegistryBlock, bitcoin::consensus::encode::Error> {
        bitcoin::consensus::encode::deserialize::<RegistryBlock>(&consensus_bytes(block))
    }

    fn child_block(prev_blockhash: BlockHash, nonce: u32, txs: Vec<Tx>) -> Fallible<Block> {
        let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
        let root = bitcoin_rs_consensus::compute_merkle_root(&mut leaves)
            .ok_or(TestError::Missing("a fixture block holds a transaction"))?;
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash,
                merkle_root: Hash256::from_le_bytes(&root),
                time: nonce,
                bits: CompactTarget::from_consensus(
                    bitcoin_rs_execution::chain::regtest_fixture::REGTEST_BITS,
                ),
                nonce,
            },
            txs,
        };
        if !registry_block(&block)?.check_merkle_root() {
            return Err(TestError::Missing(
                "the fixture's merkle root is not the wire decoder's",
            ));
        }
        Ok(block)
    }

    struct StoredBodies(Vec<(u32, BlockHash, Vec<u8>)>);

    impl BlockBodySource for StoredBodies {
        fn block_body(
            &self,
            height: u32,
            hash: BlockHash,
        ) -> Result<Option<Vec<u8>>, BlockBodyReadError> {
            Ok(self
                .0
                .iter()
                .find(|(stored_height, stored_hash, _)| {
                    *stored_height == height && *stored_hash == hash
                })
                .map(|(_, _, body)| body.clone()))
        }
    }

    fn chain_over(blocks: &[Block], recent: RecentBlockSlot) -> Fallible<ActiveChainQuery> {
        let mut tree = BlockTree::new();
        let mut parent = None;
        let mut bodies = Vec::with_capacity(blocks.len());
        for (height, block) in blocks.iter().enumerate() {
            parent = Some(tree.insert_node(parent, block.header, NodeStatus::Active)?);
            bodies.push((
                u32::try_from(height)?,
                block.block_hash(),
                consensus_bytes(block),
            ));
        }
        let block_tree = BlockTreeReader::new(Arc::new(RwLock::new(tree)));
        let applied_tip = TipReader::new(Arc::new(arc_swap::ArcSwapOption::empty()));
        applied_tip.store(block_tree.read().tip());
        Ok(
            ActiveChainQuery::new(block_tree, applied_tip, Network::Regtest)
                .with_block_body_source(Arc::new(StoredBodies(bodies)))
                .with_recent_block(recent),
        )
    }

    struct Node {
        addr: PeerEndpoint,
        table: Arc<PeerTable>,
        aggregate: Arc<SharedOutboundBudget>,
        shutdown: bitcoin_rs_consensus::latch::LatchWriter,
        listener: Option<JoinHandle<Result<(), ListenerError>>>,
    }

    impl Node {
        fn start(chain: ActiveChainQuery) -> Fallible<Self> {
            let table = Arc::new(PeerTable::new());
            let mut shared = test_shared(
                Arc::clone(&table),
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            shared.chain_query = Some(Arc::new(chain));
            let aggregate = Arc::clone(&shared.shared_outbound);
            let listener = bind_listener(
                PeerEndpoint::from(([127, 0, 0, 1], 0))
                    .socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            )?;
            let addr = listener.local_addr()?;
            let shutdown = bitcoin_rs_consensus::latch::LatchWriter::new();
            let reader = shutdown.reader();
            let thread = std::thread::spawn(move || serve(listener, reader, shared));
            Ok(Self {
                addr: addr.into(),
                table,
                aggregate,
                shutdown,
                listener: Some(thread),
            })
        }

        fn request_stop(&self) {
            self.shutdown.trigger();
            self.table.cancel_all();
        }

        fn join_listener(&mut self) -> TestResult {
            let Some(thread) = self.listener.take() else {
                return Ok(());
            };
            let deadline = Instant::now() + FAILSAFE;
            while !thread.is_finished() {
                if Instant::now() >= deadline {
                    self.listener = Some(thread);
                    return Err(TestError::Missing(
                        "the listener did not stop within the failsafe",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let served = thread
                .join()
                .map_err(|_| TestError::Missing("the listener thread panicked"))?;
            served?;
            Ok(())
        }

        fn finish(mut self) -> TestResult {
            self.request_stop();
            self.join_listener()?;
            wait_until("every session to leave the peer table", || {
                self.table.sessions().is_empty()
            })?;
            Ok(())
        }
    }

    impl Drop for Node {
        fn drop(&mut self) {
            self.request_stop();
            let _ = self.join_listener();
        }
    }

    struct Client {
        peer: Peer<TcpStream>,
        local: PeerEndpoint,
        nonce: u64,
    }

    impl Client {
        fn connect(node: &Node) -> Fallible<Self> {
            let stream = TcpStream::connect(
                node.addr
                    .socket_addr()
                    .unwrap_or_else(|| panic!("expected IP fixture")),
            )?;
            configure_peer_stream(&stream)?;
            let local = stream.local_addr()?;
            let mut peer = Peer::new(stream, MAGIC);
            let lease = PeerLease::new(crossbeam_channel::unbounded().0);
            let own = test_shared(
                Arc::new(PeerTable::new()),
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            run_outbound_handshake(
                &mut peer,
                u64::from(local.port()),
                0,
                &lease,
                Instant::now() + FAILSAFE,
                node.addr,
                &own,
            )?;
            let mut client = Self {
                peer,
                local: local.into(),
                nonce: 0,
            };
            let barrier = client.ping()?;
            client.read_through_pong(barrier)?;
            Ok(client)
        }

        fn send(&mut self, message: &Message) -> Fallible<()> {
            self.peer.send(message)?;
            Ok(())
        }

        fn ping(&mut self) -> Fallible<u64> {
            self.nonce += 1;
            let nonce = self.nonce;
            self.send(&Message::Ping(nonce))?;
            Ok(nonce)
        }

        fn frame(&mut self, deadline: Instant) -> Fallible<Frame> {
            loop {
                if Instant::now() >= deadline {
                    return Err("no message arrived before the failsafe deadline".into());
                }
                match self.peer.read_message() {
                    Ok(Some(frame)) => return Ok(frame),
                    Ok(None) => {}
                    Err(PeerError::Io(error))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }

        fn read_frames(&mut self, count: usize) -> Fallible<Vec<Frame>> {
            let deadline = Instant::now() + FAILSAFE;
            (0..count).map(|_| self.frame(deadline)).collect()
        }

        fn read_through_pong(&mut self, nonce: u64) -> Fallible<Vec<Frame>> {
            let deadline = Instant::now() + FAILSAFE;
            let mut before = Vec::new();
            loop {
                let frame = self.frame(deadline)?;
                if frame.0 == Message::Pong(nonce) {
                    return Ok(before);
                }
                before.push(frame);
            }
        }

        fn request(&mut self, items: Vec<Inventory>) -> Fallible<Vec<Frame>> {
            self.send(&Message::GetData(items))?;
            let nonce = self.ping()?;
            self.read_through_pong(nonce)
        }
    }

    fn messages_of(frames: Vec<Frame>) -> Vec<Message> {
        frames.into_iter().map(|(message, _)| message).collect()
    }

    fn session_of(node: &Node, client: &Client) -> Fallible<PeerSession> {
        let mut found = None;
        wait_until("the node to publish the client's session", || {
            found = node.table.sessions().into_iter().find(|session| {
                session.addr == bitcoin_rs_wire::PeerRemote::Endpoint(client.local)
                    && session.info.is_some()
            });
            found.is_some()
        })?;
        found.ok_or(TestError::Missing("the client's session vanished"))
    }

    fn counters_of(session: &PeerSession) -> Fallible<Arc<PeerCounters>> {
        Ok(Arc::clone(
            &session
                .info
                .as_ref()
                .ok_or(TestError::Missing("the session published no metadata"))?
                .counters,
        ))
    }

    #[test]
    fn a_held_block_answers_a_negotiated_compact_getdata_over_a_real_socket() -> TestResult {
        let genesis = child_block(BlockHash::default(), 0, vec![coinbase(0, 1)])?;
        let tip = child_block(genesis.block_hash(), 1, vec![coinbase(1, 1), payment(1)])?;
        let held = Arc::new(child_block(
            tip.block_hash(),
            2,
            vec![coinbase(2, 1), payment(2)],
        )?);
        let held_hash = held.block_hash();
        let slot = RecentBlockSlot::default();
        slot.store(
            Hash256::from(held_hash),
            Arc::new(BlockImage::from_local((*held).clone())),
        );
        let chain = chain_over(&[genesis, tip], slot)?;
        assert_eq!(
            chain.active_height(held_hash),
            None,
            "the held block is in no tree node"
        );

        let node = Node::start(chain)?;
        let mut client = Client::connect(&node)?;

        let compact = Inventory::CompactBlock(wire_block_hash(held_hash));
        let messages = messages_of(client.request(vec![compact])?);
        let [Message::CmpctBlock(cmpct)] = messages.as_slice() else {
            return Err(TestError::Failure(format!(
                "a negotiated compact getdata for the held block must yield one cmpctblock \
             before the pong and no notfound, got {messages:?}"
            )));
        };

        let registry = registry_block(&held)?;
        assert_eq!(registry.block_hash(), wire_block_hash(held_hash));
        let sent = &cmpct.compact_block;
        assert_eq!(sent.header, registry.header, "the held block's header");
        let [coinbase_tx, payment_tx] = registry.txdata.as_slice() else {
            return Err("the held fixture holds a coinbase and one payment".into());
        };
        let [prefilled] = sent.prefilled_txs.as_slice() else {
            return Err("only the coinbase is prefilled".into());
        };
        assert_eq!(prefilled.idx, 0);
        assert_eq!(&prefilled.tx, coinbase_tx);
        assert_ne!(
            payment_tx.compute_txid().to_byte_array(),
            payment_tx.compute_wtxid().to_byte_array(),
            "the payment fixture carries a witness, so txid and wtxid must differ"
        );
        let keys = ShortId::calculate_siphash_keys(&sent.header, sent.nonce);
        assert_eq!(
            sent.short_ids,
            vec![ShortId::with_siphash_keys(
                &payment_tx.compute_wtxid().to_byte_array(),
                keys
            )],
            "version 2 short ids are keyed by wtxid"
        );

        for item in [
            Inventory::Block(wire_block_hash(held_hash)),
            Inventory::WitnessBlock(wire_block_hash(held_hash)),
        ] {
            let messages = messages_of(client.request(vec![item])?);
            assert_eq!(
                messages,
                vec![Message::NotFound(vec![item])],
                "a full request must not use the held body"
            );
        }

        let again = messages_of(client.request(vec![compact])?);
        assert!(
            matches!(again.as_slice(), [Message::CmpctBlock(_)]),
            "the held body answers again, got {again:?}"
        );

        drop(client);
        node.finish()
    }

    fn saturate(
        node: &Node,
        hogs: &mut [Client],
        hog_sessions: &[PeerSession],
        victim_session: &PeerSession,
        frame_len: usize,
        item: Inventory,
    ) -> Fallible<(usize, usize)> {
        let per_hog = OUTBOUND_QUEUE_MAX_BYTES.div_ceil(frame_len) * 2 + 1;
        if per_hog > MAX_INV_PER_MSG {
            return Err(TestError::Failure(format!(
                "{per_hog} frames exceed one getdata"
            )));
        }
        for hog in hogs.iter_mut() {
            hog.send(&Message::GetData(vec![item; per_hog]))?;
        }

        let mut last = None;
        let mut quiet = 0_u32;
        let mut queued = (0, 0);
        wait_until("the hogs' frames to saturate the node aggregate", || {
            let mut total_messages = 0;
            let mut total_bytes = 0;
            let mut total_sent = 0;
            for session in hog_sessions {
                let (m, b) = session.lease.budget_handle().pending();
                total_messages += m;
                total_bytes += b;
                if let Ok(counters) = counters_of(session) {
                    total_sent += counters.bytes_sent();
                }
            }
            let snapshot = (total_messages, total_bytes, total_sent);
            let saturated = total_messages > 0
                && total_bytes == total_messages * frame_len
                && node.aggregate.pending() == total_bytes
                && victim_session.lease.try_reserve_production().err() == Some(Refusal::Shared);
            quiet = if saturated && last == Some(snapshot) {
                quiet + 1
            } else {
                0
            };
            last = saturated.then_some(snapshot);
            queued = (total_messages, total_bytes);
            quiet >= QUIET_POLLS
        })?;
        Ok(queued)
    }

    #[test]
    fn getblocktxn_survives_shared_saturation_without_resending() -> TestResult {
        use bitcoin::bip152::BlockTransactionsRequest;
        use bitcoin::p2p::message_compact_blocks::GetBlockTxn;
        let genesis = child_block(BlockHash::default(), 0, vec![coinbase(0, 1)])?;
        let hog_block = child_block(genesis.block_hash(), 1, vec![coinbase(1, HOG_OUTPUTS)])?;
        let victim_block =
            child_block(hog_block.block_hash(), 2, vec![coinbase(2, 1), payment(2)])?;
        let frame_len = wire_len_of(&Message::BlockBytes(consensus_bytes(&hog_block).into()))?;
        let request = Message::GetBlockTxn(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: wire_block_hash(victim_block.block_hash()),
                indexes: vec![1],
            },
        });
        let hog_item = Inventory::WitnessBlock(wire_block_hash(hog_block.block_hash()));
        let blocks = [genesis, hog_block, victim_block];
        let node = Node::start(chain_over(&blocks, RecentBlockSlot::default())?)?;
        let mut victim = Client::connect(&node)?;
        let victim_session = session_of(&node, &victim)?;
        victim.send(&request)?;
        let nonce = victim.ping()?;
        let baseline = victim.read_through_pong(nonce)?;
        assert!(matches!(baseline.as_slice(), [(Message::BlockTxn(_), _)]));
        let mut hogs = Vec::new();
        let mut hog_sessions = Vec::new();
        for _ in 0..5 {
            let hog = Client::connect(&node)?;
            let session = session_of(&node, &hog)?;
            hogs.push(hog);
            hog_sessions.push(session);
        }
        wait_until("handshake credits returned", || {
            node.aggregate.pending() == 0
        })?;
        let queued = saturate(
            &node,
            &mut hogs,
            &hog_sessions,
            &victim_session,
            frame_len,
            hog_item,
        )?;
        let budget = victim_session.lease.budget_handle();
        let before_refusals = budget.refusals();
        let started = Instant::now();
        victim.send(&request)?;
        wait_until("getblocktxn deferred on reservation refusal", || {
            budget.refusals() > before_refusals
        })?;
        println!(
            "C saturated queued={queued:?} shared={} victim_pending={:?} refusals={} elapsed_ms={}",
            node.aggregate.pending(),
            budget.pending(),
            budget.refusals(),
            started.elapsed().as_millis()
        );
        drop(hogs);
        wait_until("hog credits returned", || node.aggregate.pending() == 0)?;
        let nonce = victim.ping()?;
        let received = victim.read_through_pong(nonce)?;
        println!(
            "C recovered replies={} elapsed_ms={} messages={:?}",
            received.len(),
            started.elapsed().as_millis(),
            messages_of(received.clone())
        );
        assert!(
            matches!(received.as_slice(), [(Message::BlockTxn(_), _)]),
            "the original request must be answered once after recovery"
        );
        drop(victim);
        node.finish()
    }

    #[test]
    fn the_saturated_aggregate_refuses_a_second_connection_until_the_first_closes() -> TestResult {
        let genesis = child_block(BlockHash::default(), 0, vec![coinbase(0, 1)])?;
        let hog_block = child_block(genesis.block_hash(), 1, vec![coinbase(1, HOG_OUTPUTS)])?;
        let victim_block =
            child_block(hog_block.block_hash(), 2, vec![coinbase(2, 1), payment(2)])?;
        let hog_item = Inventory::WitnessBlock(wire_block_hash(hog_block.block_hash()));
        let victim_item = Inventory::WitnessBlock(wire_block_hash(victim_block.block_hash()));
        let missing = Inventory::WitnessBlock(bitcoin::BlockHash::from_byte_array([0xee; 32]));
        let frame_len = wire_len_of(&Message::BlockBytes(bytes::Bytes::from(consensus_bytes(
            &hog_block,
        ))))?;
        let victim_payload = consensus_bytes(&victim_block);
        let blocks = [genesis, hog_block, victim_block];
        let chain = chain_over(&blocks, RecentBlockSlot::default())?;

        let node = Node::start(chain)?;
        let mut victim = Client::connect(&node)?;
        let victim_session = session_of(&node, &victim)?;
        let mut hogs = Vec::new();
        let mut hog_sessions = Vec::new();
        for _ in 0..5 {
            let hog = Client::connect(&node)?;
            let session = session_of(&node, &hog)?;
            hogs.push(hog);
            hog_sessions.push(session);
        }
        wait_until("the handshakes' frames to release the aggregate", || {
            node.aggregate.pending() == 0
        })?;

        let (hog_messages, hog_bytes) = saturate(
            &node,
            &mut hogs,
            &hog_sessions,
            &victim_session,
            frame_len,
            hog_item,
        )?;
        assert!(hog_messages > 1, "the aggregate holds several real frames");

        let reserve = bitcoin_rs_wire::wire::HEADER_LEN
            + bitcoin_rs_wire::peer::MAX_BLOCK_SERIALIZED_SIZE_USIZE;
        let bulk_limit = SHARED_OUTBOUND_QUEUE_MAX_BYTES - reserve;
        let refusal_point = bulk_limit - reserve;
        assert!(
            hog_bytes > refusal_point && hog_bytes <= refusal_point + frame_len,
            "the hog's {hog_bytes} queued bytes are not the first fill past {refusal_point}"
        );

        let victim_counters = counters_of(&victim_session)?;
        let written_before = victim_counters.bytes_sent();
        victim.send(&Message::GetData(vec![missing, victim_item]))?;

        let first = messages_of(victim.read_frames(1)?);
        let miss_reply = Message::NotFound(vec![missing]);
        let missed_len = u64::try_from(wire_len_of(&miss_reply)?)?;
        assert_eq!(
            first,
            vec![miss_reply],
            "a refused body parks behind the miss instead of reaching the wire first"
        );
        assert_eq!(
            victim_session.lease.try_reserve_production().err(),
            Some(Refusal::Shared),
            "the victim's own reservation is refused by the aggregate, not by its empty queue"
        );
        wait_until("the victim's notfound to be counted as written", || {
            victim_counters.bytes_sent() >= written_before + missed_len
        })?;
        assert_eq!(
            victim_counters.bytes_sent(),
            written_before + missed_len,
            "only the notfound was written to the victim: its body waits for the aggregate"
        );
        assert!(
            !victim_session.lease.is_cancelled()
                && hog_sessions.iter().all(|s| !s.lease.is_cancelled()),
            "the aggregate's refusal never disconnects"
        );

        let nonce = victim.ping()?;

        drop(hogs);
        wait_until("every frame credit of the closed hogs to return", || {
            node.aggregate.pending() == 0
        })?;

        let delivered = victim.read_through_pong(nonce)?;
        let [(Message::Block(block), raw)] = delivered.as_slice() else {
            let received: Vec<&Message> = delivered.iter().map(|(message, _)| message).collect();
            return Err(TestError::Failure(format!(
                "the victim's body must precede its pong, got {received:?}"
            )));
        };
        assert_eq!(block.materialize(), blocks[2]);
        assert_eq!(&raw[..], victim_payload.as_slice());
        wait_until("the aggregate to drain once the victim was served", || {
            node.aggregate.pending() == 0
        })?;
        assert!(!victim_session.lease.is_cancelled());

        drop(victim);
        node.finish()
    }

    fn node_outbound_ledger(
        peer_outbound: u64,
    ) -> (
        Arc<crate::budget::NodeBudget>,
        Arc<crate::budget::BudgetedOutboundLedger>,
    ) {
        let mut caps = crate::budget::BudgetCaps::from_chainstate_cache_budget(
            split_chainstate_cache_budget(64 * 1024 * 1024),
        );
        caps.peer_outbound = peer_outbound;
        let budget = Arc::new(crate::budget::NodeBudget::new(caps, 4));
        let ledger = Arc::new(crate::budget::BudgetedOutboundLedger::new(Arc::clone(
            &budget,
        )));
        (budget, ledger)
    }

    // BUD-02
    #[test]
    fn a_node_ledger_without_peer_outbound_room_refuses_the_server_reply() -> TestResult {
        let genesis = child_block(BlockHash::default(), 0, vec![coinbase(0, 1)])?;
        let node = Node::start(chain_over(&[genesis], RecentBlockSlot::default())?)?;
        let mut client = Client::connect(&node)?;

        let (budget, ledger) = node_outbound_ledger(0);
        node.aggregate.set_ledger(ledger);
        client.ping()?;
        assert!(
            client
                .frame(Instant::now() + Duration::from_millis(500))
                .is_err(),
            "a pong the node ledger refuses must not reach the peer"
        );
        assert_eq!(
            budget.charged_bytes(bitcoin_rs_storage::budget::BudgetOwner::PeerOutbound),
            0,
            "a refused reply leaves no peer owner charge"
        );
        drop(client);
        node.finish()
    }

    // BUD-02
    #[test]
    fn a_node_ledger_with_peer_outbound_room_delivers_the_server_reply() -> TestResult {
        let genesis = child_block(BlockHash::default(), 0, vec![coinbase(0, 1)])?;
        let node = Node::start(chain_over(&[genesis], RecentBlockSlot::default())?)?;
        let mut client = Client::connect(&node)?;

        let (budget, ledger) = node_outbound_ledger(64 * 1024 * 1024);
        node.aggregate.set_ledger(ledger);
        let nonce = client.ping()?;
        client.read_through_pong(nonce)?;
        wait_until("the pong's peer owner charge to return", || {
            budget.charged_bytes(bitcoin_rs_storage::budget::BudgetOwner::PeerOutbound) == 0
        })?;
        drop(client);
        node.finish()
    }
}
#[cfg(test)]
#[expect(
    clippy::expect_used,
    clippy::as_conversions,
    reason = "relocated p2p orchestration test fixtures"
)]
mod writer_shutdown_tests {
    use std::io;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::p2p::NodeTxPolicy;
    use bitcoin::hashes::Hash as _;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin::secp256k1::rand::SeedableRng as _;
    use bitcoin_rs_consensus::primitives::PeerEndpoint;
    use bitcoin_rs_mempool::{
        AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits,
    };
    use bitcoin_rs_wire::connection::PeerLease;
    use bitcoin_rs_wire::dispatch::TxInventory;
    use bitcoin_rs_wire::listener::{run_message_loop, test_shared};
    use bitcoin_rs_wire::peer::{Peer, PeerState};
    use bitcoin_rs_wire::peer_table::PeerTable;

    struct RelayDuringInventoryLookup {
        _table: Arc<PeerTable>,
        tx_policy: Arc<NodeTxPolicy>,
        gateway: Arc<MempoolGateway>,
        lease: PeerLease,
        due: std::time::Instant,
        calls: AtomicUsize,
    }

    impl TxInventory for RelayDuringInventoryLookup {
        fn have_tx(&self, hash: bitcoin_rs_consensus::primitives::Hash256, witness: bool) -> bool {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::seed_from_u64(1484);
            self.tx_policy
                .poll_transaction_relay(&self.gateway, self.due, false, &mut rng);
            self.lease.cancel();
            self.gateway.have_tx(hash, witness)
        }

        fn get_tx(
            &self,
            txid: bitcoin_rs_consensus::primitives::Txid,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            self.gateway.get_tx(txid)
        }

        fn get_tx_by_wtxid(
            &self,
            wtxid: bitcoin_rs_consensus::primitives::Wtxid,
        ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
            self.gateway.get_tx_by_wtxid(wtxid)
        }

        fn resident_ancestor_package(
            &self,
            wtxid: bitcoin_rs_consensus::primitives::Wtxid,
        ) -> Option<Vec<bitcoin_rs_consensus::primitives::Wtxid>> {
            self.gateway.ancestor_package_wtxids(wtxid)
        }

        fn resident_package(
            &self,
            wtxids: &[bitcoin_rs_consensus::primitives::Wtxid],
        ) -> Option<Vec<Arc<bitcoin_rs_consensus::primitives::Tx>>> {
            self.gateway.resident_package(wtxids)
        }
    }

    fn peer_info(addr: PeerEndpoint, start_height: i32) -> bitcoin_rs_wire::PeerInfo {
        bitcoin_rs_wire::PeerInfo {
            addr: addr.into(),
            endpoint: Some(addr),
            network: bitcoin_rs_wire::PeerRemote::from(addr).network().into(),
            version: 70_016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: true,
            send_headers: true,
            services: 0,
            user_agent: String::new(),
            start_height,
            best_known_height: start_height,
            conn_time: 0,
            inbound: false,
            addr_bind: bitcoin_rs_wire::endpoint::TransportRemote::new(
                addr.socket_addr().expect("valid IP fixture"),
            ),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_wire::PeerCounters::default()),
            transport: bitcoin_rs_wire::TransportProtocol::V1,
        }
    }

    struct ScriptedStream {
        script: io::Cursor<Vec<u8>>,
    }

    impl io::Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.script.read(buf)
        }
    }

    impl io::Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn announced_inventory_is_known_before_dispatch_gateway_callbacks() {
        use bitcoin::secp256k1::rand::SeedableRng as _;

        for announces_pending in [false, true] {
            let table = Arc::new(PeerTable::new());
            let tx_policy = Arc::new(NodeTxPolicy::with_table(Arc::clone(&table)));
            let addr = PeerEndpoint::from((Ipv4Addr::LOCALHOST, 18_447));
            let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
            let lease = PeerLease::new(outbound_tx);
            table.register(addr, lease.clone());
            table.publish_info(addr, &lease, peer_info(addr, 0));
            let gateway = Arc::new(MempoolGateway::new(
                Arc::new(parking_lot::RwLock::new(Mempool::new(
                    MempoolLimits::default(),
                ))),
                None,
                bitcoin_rs_consensus::ValidationEngine::Native,
                None,
            ));
            let tx = Arc::new(bitcoin_rs_consensus::primitives::Tx::default());
            let sequence = gateway
                .insert_entry(
                    AdmissionOrigin::Rpc,
                    MempoolEntry::new(Arc::clone(&tx), 100, 1_000, 1, 0, 0),
                )
                .expect("relay fixture admitted")
                .sequence_of(0)
                .expect("admission epoch");
            let now = std::time::Instant::now();
            let mut rng = bitcoin::secp256k1::rand::rngs::StdRng::seed_from_u64(1484);
            assert_eq!(
                tx_policy
                    .queue_transaction_relay(
                        crate::p2p::RelayRequest::new(tx.txid(), tx.wtxid(), None, sequence),
                        now,
                        &mut rng,
                    )
                    .attempted,
                1
            );
            let inventory = Arc::new(RelayDuringInventoryLookup {
                _table: Arc::clone(&table),
                tx_policy,
                gateway,
                lease: lease.clone(),
                due: now + Duration::from_secs(31),
                calls: AtomicUsize::new(0),
            });
            let mut shared = test_shared(
                table,
                crossbeam_channel::unbounded().0,
                crossbeam_channel::unbounded().0,
            );
            shared.tx_inventory = Some(inventory.clone());
            shared.tx_policy = Some(Arc::clone(&inventory.tx_policy) as _);
            let announced = if announces_pending {
                *tx.txid().as_bytes()
            } else {
                [9; 32]
            };
            let mut wire = Vec::new();
            bitcoin_rs_wire::wire::write_message(
                &mut wire,
                shared.magic,
                &bitcoin_rs_wire::Message::Inv(vec![Inventory::Transaction(
                    bitcoin::Txid::from_byte_array(announced),
                )]),
            )
            .expect("inventory frame");
            let mut peer = Peer::new(
                ScriptedStream {
                    script: io::Cursor::new(wire),
                },
                shared.magic,
            );
            peer.state = PeerState::Ready;
            assert!(run_message_loop(&mut peer, addr, &lease, &shared, None).is_ok());
            assert_eq!(inventory.calls.load(Ordering::Relaxed), 1);
            let echoed = outbound_rx
                .try_iter()
                .any(|frame| matches!(frame.message(), bitcoin_rs_wire::Message::Inv(_)));
            assert_eq!(
                echoed, !announces_pending,
                "only the announced identity suppresses the pending relay"
            );
        }
    }
}

pub use block_announce::{
    BlockAnnounceConfig, BlockAnnounceQueue, BlockAnnounceReceiver, BlockAnnouncer,
    MAX_BLOCKS_TO_ANNOUNCE, MAX_HIGH_BANDWIDTH_PEERS, spawn_block_announce_worker,
};
pub(crate) use block_stager::BlockStager;
pub use chain_query::{ActiveChainQuery, RecentBlockSlot};
pub use download_window::default_sync_budget;
pub use sync::{BlockSync, StaleTipRetainer, SyncChain};
pub use tx_policy::{
    InboundBody, InboundPackage, MAX_DECODED_PACKAGES_PER_PEER, NodeTxPolicy, OpenedPackage,
    PackageCapacity, PackageCharge, PackageOpening, PackagePlan, PackageRefusal, PackageRejection,
    PackageTeardown, PackageToken, TxPolicy, plan_package_charge,
};
pub use tx_relay::{
    DEFAULT_TX_RELAY_QUEUE_CAPACITY, LocalTxRelayObserver, PeerRelaySink, RelayOutcome,
    RelayRequest, RelaySink, TxRelayQueue, spawn_tx_relay_worker,
};

use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_consensus::primitives::{Hash256, Header, Network, Tx, Txid, Wtxid};
use bitcoin_rs_wire::compact_blocks::CompactBlockHints;
use bitcoin_rs_wire::connection::{PeerRemote, PeerSource};
use bitcoin_rs_wire::dispatch::TxInventory;
use bitcoin_rs_wire::inbound::{BlockMemoryCredit, InboundBlock};
use bitcoin_rs_wire::listener::{
    BlockAnnounceObserver, BlockSyncObserver, IbdState, TxIngressObserver, TxPolicyObserver,
};
use bitcoin_rs_wire::wire::{Message, PeerError};
use crossbeam_channel::Sender;
use std::sync::Arc;
pub fn peer_token(source: PeerSource) -> bitcoin_rs_mempool::PeerToken {
    bitcoin_rs_mempool::PeerToken {
        endpoint: source.endpoint,
        addr: PeerRemote::from(source).endpoint(),
        connection_id: source.connection_id.get(),
    }
}

pub fn peer_source(token: bitcoin_rs_mempool::PeerToken) -> PeerSource {
    PeerSource::from_raw(token.endpoint, token.connection_id)
}

pub struct NodeIbd(pub Arc<bitcoin_rs_execution::chain::InitialBlockDownload>);

impl IbdState for NodeIbd {
    fn is_ibd(&self, now: u64, network: Network) -> bool {
        self.0.is_active(now, network)
    }
}

pub struct NodeTxInventory(pub Arc<bitcoin_rs_mempool::MempoolGateway>);

impl TxInventory for NodeTxInventory {
    fn transaction_sent(&self, wtxid: Wtxid) {
        self.0.mark_broadcast(wtxid);
    }
    fn transaction_send_committed(&self, wtxid: Wtxid) {
        self.0.commit_broadcast(wtxid);
    }
    fn transaction_send_failed(&self, wtxid: Wtxid) {
        self.0.restore_unbroadcast(wtxid);
    }
    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
        bitcoin_rs_mempool::MempoolGateway::ancestor_package_wtxids(&self.0, wtxid)
    }
    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
        bitcoin_rs_mempool::MempoolGateway::resident_package(&self.0, wtxids)
    }
    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
        bitcoin_rs_mempool::MempoolGateway::have_tx(&self.0, hash, hash_is_wtxid)
    }
    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::get_tx(&self.0, txid)
    }
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::get_tx_by_wtxid(&self.0, wtxid)
    }
}

pub struct RefTxInventory<'a>(pub &'a bitcoin_rs_mempool::MempoolGateway);

impl TxInventory for RefTxInventory<'_> {
    fn transaction_sent(&self, wtxid: Wtxid) {
        self.0.mark_broadcast(wtxid);
    }
    fn transaction_send_committed(&self, wtxid: Wtxid) {
        self.0.commit_broadcast(wtxid);
    }
    fn transaction_send_failed(&self, wtxid: Wtxid) {
        self.0.restore_unbroadcast(wtxid);
    }
    fn resident_ancestor_package(&self, wtxid: Wtxid) -> Option<Vec<Wtxid>> {
        bitcoin_rs_mempool::MempoolGateway::ancestor_package_wtxids(self.0, wtxid)
    }
    fn resident_package(&self, wtxids: &[Wtxid]) -> Option<Vec<Arc<Tx>>> {
        bitcoin_rs_mempool::MempoolGateway::resident_package(self.0, wtxids)
    }
    fn have_tx(&self, hash: Hash256, hash_is_wtxid: bool) -> bool {
        bitcoin_rs_mempool::MempoolGateway::have_tx(self.0, hash, hash_is_wtxid)
    }
    fn get_tx(&self, txid: Txid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::get_tx(self.0, txid)
    }
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::get_tx_by_wtxid(self.0, wtxid)
    }
}

impl CompactBlockHints for NodeTxInventory {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
        bitcoin_rs_mempool::MempoolGateway::for_each_reconstruction_identity(&self.0, f);
    }
    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::reconstruction_tx_by_txid(&self.0, txid)
    }
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::reconstruction_tx_by_wtxid(&self.0, wtxid)
    }
}

impl CompactBlockHints for RefTxInventory<'_> {
    fn for_each_identity(&self, f: &mut dyn FnMut(Txid, Wtxid)) {
        bitcoin_rs_mempool::MempoolGateway::for_each_reconstruction_identity(self.0, f);
    }
    fn get_tx_by_txid(&self, txid: Txid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::reconstruction_tx_by_txid(self.0, txid)
    }
    fn get_tx_by_wtxid(&self, wtxid: Wtxid) -> Option<Tx> {
        bitcoin_rs_mempool::MempoolGateway::reconstruction_tx_by_wtxid(self.0, wtxid)
    }
}

pub struct NodeTxIngress {
    inbound_tx: Sender<InboundBody>,
    package_capacity: PackageCapacity,
    tx_policy: Arc<NodeTxPolicy>,
    inventory: Arc<NodeTxInventory>,
    cancel: bitcoin_rs_consensus::latch::LatchReader,
}

impl NodeTxIngress {
    pub fn new(
        inbound_tx: Sender<InboundBody>,
        package_capacity: PackageCapacity,
        tx_policy: Arc<NodeTxPolicy>,
        inventory: Arc<NodeTxInventory>,
        cancel: bitcoin_rs_consensus::latch::LatchReader,
    ) -> Self {
        Self {
            inbound_tx,
            package_capacity,
            tx_policy,
            inventory,
            cancel,
        }
    }
}

impl TxIngressObserver for NodeTxIngress {
    fn on_inbound_tx(&self, source: PeerSource, tx: Tx, memory_credit: Option<BlockMemoryCredit>) {
        let body = InboundBody::from(
            bitcoin_rs_wire::InboundTx::new(tx, source).with_memory_credit(memory_credit),
        );
        if self.cancel.is_triggered() {
            return;
        }
        let dropped = match self.inbound_tx.try_send(body) {
            Ok(()) => None,
            Err(crossbeam_channel::TrySendError::Full(b)) => Some(b),
            Err(crossbeam_channel::TrySendError::Disconnected(b)) => Some(b),
        };
        if let Some(InboundBody::Tx(inbound)) = dropped {
            let source = inbound.source;
            let txid = inbound.tx.txid();
            let wtxid = inbound.tx.wtxid();
            drop(inbound);
            self.tx_policy
                .transaction_response_completed(source, txid, wtxid);
            self.tx_policy
                .poll_transaction_response(self.inventory.as_ref(), txid, wtxid);
        }
    }

    fn on_inbound_package(
        &self,
        source: PeerSource,
        payload: bytes::Bytes,
    ) -> Result<(), PeerError> {
        let package = match self.tx_policy.admit_package(
            &self.package_capacity,
            self.inventory.as_ref(),
            source,
            payload,
        ) {
            Ok(pkg) => pkg,
            Err(refusal) if refusal.is_peer_fault() => {
                return Err(PeerError::Protocol(
                    "malformed package in violation of protocol",
                ));
            }
            Err(_) => return Ok(()),
        };
        let body = InboundBody::from(package);
        if self.cancel.is_triggered() {
            return Ok(());
        }
        let refused = match self.inbound_tx.try_send(body) {
            Ok(()) => None,
            Err(crossbeam_channel::TrySendError::Full(b)) => Some(b),
            Err(crossbeam_channel::TrySendError::Disconnected(b)) => Some(b),
        };
        if let Some(InboundBody::Package(pkg)) = refused {
            self.tx_policy
                .package_response_rejected(pkg.into_token(), self.inventory.as_ref());
        }
        Ok(())
    }
}

impl TxPolicyObserver for NodeTxPolicy {
    fn announce_transactions(&self, source: PeerSource, items: &[Inventory]) {
        self.announce_transactions(source, items);
    }

    fn request_parent_transactions(&self, source: PeerSource, items: &[Inventory]) -> bool {
        self.request_parent_transactions(source, items)
    }

    fn transaction_not_found(
        &self,
        source: PeerSource,
        items: &[Inventory],
        inventory: &dyn TxInventory,
    ) {
        self.transaction_not_found(source, items, inventory);
    }

    fn poll_transaction_requests(&self, inventory: &dyn TxInventory) {
        self.poll_transaction_requests(inventory);
    }

    fn transaction_peer_disconnected(&self, source: PeerSource, inventory: &dyn TxInventory) {
        self.transaction_peer_disconnected(source, inventory);
    }

    fn note_transaction_inventory(&self, source: PeerSource, items: &[Inventory]) {
        self.note_transaction_inventory(source, items);
    }

    fn request_package_transactions(&self, source: PeerSource, subject: Wtxid, wtxids: Vec<Wtxid>) {
        self.request_package_transactions(source, subject, wtxids);
    }

    fn release_package_info(
        &self,
        source: PeerSource,
        subject: Wtxid,
        inventory: &dyn TxInventory,
    ) {
        self.release_package_info(source, subject, inventory);
    }

    fn receive_fee_filter(&self, source: PeerSource, rate: i64) {
        self.receive_fee_filter(source, rate);
    }
}

impl BlockSyncObserver for sync::BlockSync {
    fn announce_block(&self, source: PeerSource, hash: Hash256) {
        self.announce_block(source, hash);
    }
    fn block_not_found(&self, source: PeerSource, items: &[Inventory]) -> bool {
        self.block_not_found(source, items)
    }
    fn note_header_response_received(&self, source: PeerSource) {
        self.note_header_response_received(source);
    }
    fn owns_body_fetch(&self, source: PeerSource, hash: Hash256) -> bool {
        self.owns_body_fetch(source, hash)
    }
    fn compact_reconstruction_admissible(&self, source: PeerSource, header: &Header) -> bool {
        self.compact_reconstruction_admissible(source, header)
    }
    fn enqueue_owned_body_fetch(
        &self,
        source: PeerSource,
        hash: Hash256,
        follow_up: &mut dyn FnMut() -> bool,
    ) -> bool {
        self.enqueue_owned_body_fetch(source, hash, follow_up)
    }
    fn note_stale_tip_heard(&self, source: PeerSource, tip_hash: Hash256) {
        self.stale_tips().note_heard(source, tip_hash);
    }
    fn allow_extra_full_relay_dial(&self) -> bool {
        self.allow_extra_full_relay_dial()
    }
    fn is_downloading_bodies(&self, source: PeerSource) -> bool {
        self.is_downloading_bodies(source)
    }
}

impl BlockAnnounceObserver for block_announce::BlockAnnouncer {
    fn on_peer_ready(&self) {
        self.on_peer_ready();
    }
    fn on_peer_disconnected(&self, source: PeerSource) {
        self.on_peer_disconnected(source);
    }
    fn reconcile_high_bandwidth_peers(&self) {
        self.reconcile_high_bandwidth_peers();
    }
}
