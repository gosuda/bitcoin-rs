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
use bitcoin_rs_mempool::{AdmissionOrigin, Mempool, MempoolEntry, MempoolGateway, MempoolLimits};
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
