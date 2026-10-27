//! Connection retry policy for every configured pin, independent of its route.
use super::{ActiveOutbound, HashMap, PeerEndpoint, is_manual_endpoint};
use std::time::{Duration, Instant};

const INITIAL_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(60);

struct Retry {
    next: Instant,
    delay: Duration,
}

#[derive(Default)]
pub(super) struct PinnedPeers {
    retries: HashMap<PeerEndpoint, Retry>,
}

impl PinnedPeers {
    // The drain owns this state and active handles. Resolution only supplies
    // desired destinations; neither resolvers nor transports schedule dials.
    pub(super) fn due(
        &mut self,
        configured: &[PeerEndpoint],
        active: &HashMap<PeerEndpoint, ActiveOutbound>,
        peers: &crate::PeerTable,
        now: Instant,
    ) -> Vec<PeerEndpoint> {
        self.retries
            .retain(|endpoint, _| is_manual_endpoint(configured, *endpoint));
        let mut due = Vec::new();
        for &endpoint in configured {
            let endpoint = crate::addrman::canonical(endpoint);
            let retry = self.retries.entry(endpoint).or_insert(Retry {
                next: now,
                delay: INITIAL_RETRY,
            });
            if peers.ready_source(endpoint).is_some() {
                retry.delay = INITIAL_RETRY;
            }
            if now >= retry.next
                && !active.contains_key(&endpoint)
                && !peers.is_connected(endpoint)
                && !due.contains(&endpoint)
            {
                due.push(endpoint);
            }
        }
        due
    }

    // Completion or local admission refusal starts the next delay. A long
    // pending dial never consumes another retry or creates a second handle.
    pub(super) fn finished(&mut self, endpoint: PeerEndpoint, now: Instant) {
        if let Some(retry) = self.retries.get_mut(&crate::addrman::canonical(endpoint)) {
            retry.next = now + retry.delay;
            retry.delay = (retry.delay * 2).min(MAX_RETRY);
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_route_shares_canonical_backoff_and_removal_without_parallel_attempts() {
        let peers = crate::PeerTable::new();
        let mut pins = PinnedPeers::default();
        let mut active = HashMap::new();
        let ip: PeerEndpoint = "8.8.8.8:8333".parse().expect("IP");
        let onion = PeerEndpoint::new(crate::PeerAddress::Onion([1; 32]), 8333);
        let i2p = PeerEndpoint::new(crate::PeerAddress::I2p([2; 32]), 8333);
        let configured = [
            ip,
            onion,
            i2p,
            "[::ffff:8.8.8.8]:8333".parse().expect("alias"),
        ];
        let mut now = Instant::now();
        assert_eq!(
            pins.due(&configured, &active, &peers, now),
            vec![ip, onion, i2p]
        );
        assert_eq!(pins.retries.len(), 3);
        for endpoint in [ip, onion, i2p] {
            active.insert(
                endpoint,
                ActiveOutbound {
                    feeler: false,
                    role: crate::PeerRole::FullRelay,
                    manual: true,
                },
            );
        }
        assert_eq!(
            pins.due(&configured, &active, &peers, now + Duration::from_secs(80)),
            []
        );
        assert!(
            pins.retries
                .values()
                .all(|retry| retry.delay == INITIAL_RETRY)
        );
        active.clear();
        for seconds in [1, 2, 4, 8, 16, 32, 60, 60] {
            for endpoint in [ip, onion, i2p] {
                pins.finished(endpoint, now);
            }
            now += Duration::from_secs(seconds);
            assert_eq!(
                pins.due(
                    &configured,
                    &active,
                    &peers,
                    now.checked_sub(Duration::from_millis(1))
                        .expect("elapsed retry interval")
                ),
                []
            );
            assert_eq!(
                pins.due(&configured, &active, &peers, now),
                vec![ip, onion, i2p]
            );
        }
        assert_eq!(pins.due(&[], &active, &peers, now), []);
        assert_eq!(pins.retries.len(), 0);
        assert_eq!(pins.due(&[ip], &active, &peers, now), vec![ip]);
        assert_eq!(pins.retries[&ip].delay, INITIAL_RETRY);
    }

    #[test]
    fn only_a_ready_connection_resets_backoff() {
        let peers = crate::PeerTable::new();
        let mut pins = PinnedPeers::default();
        let active = HashMap::new();
        let endpoint: PeerEndpoint = "8.8.8.8:8333".parse().expect("IP");
        let now = Instant::now();
        let _ = pins.due(&[endpoint], &active, &peers, now);
        pins.finished(endpoint, now);
        assert_eq!(pins.retries[&endpoint].delay, Duration::from_secs(2));
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new_manual(tx, crate::PeerRole::FullRelay);
        peers.register(endpoint, lease.clone());
        assert_eq!(pins.due(&[endpoint], &active, &peers, now + MAX_RETRY), []);
        assert_eq!(pins.retries[&endpoint].delay, Duration::from_secs(2));
        let info = crate::PeerInfo {
            addr: endpoint.into(),
            version: 70016,
            wtxid_relay: false,
            relay_transactions: true,
            compact_block_relay: false,
            send_headers: false,
            services: 9,
            user_agent: String::new(),
            start_height: 0,
            best_known_height: 0,
            conn_time: 0,
            inbound: false,
            addr_bind: "127.0.0.1:1".parse().expect("bind"),
            time_offset: 0,
            counters: std::sync::Arc::new(crate::PeerCounters::default()),
            transport: crate::TransportProtocol::V1,
        };
        assert!(peers.publish_info(endpoint, &lease, info));
        assert_eq!(pins.due(&[endpoint], &active, &peers, now + MAX_RETRY), []);
        assert_eq!(pins.retries[&endpoint].delay, INITIAL_RETRY);
        peers.remove_current(endpoint, &lease);
        pins.finished(endpoint, now + MAX_RETRY);
        assert_eq!(pins.due(&[endpoint], &active, &peers, now + MAX_RETRY), []);
        assert_eq!(
            pins.due(
                &[endpoint],
                &active,
                &peers,
                now + MAX_RETRY + INITIAL_RETRY
            ),
            vec![endpoint]
        );
    }

    #[test]
    fn fixed_and_persistent_addnode_ip_peers_retry_through_the_same_drain() {
        use super::super::{P2pService, P2pServiceConfig};
        use std::sync::{Arc, atomic::AtomicBool};
        for fixed in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
            listener.set_nonblocking(true).expect("nonblocking");
            let endpoint = PeerEndpoint::from(listener.local_addr().expect("endpoint"));
            let service = P2pService::new(
                P2pServiceConfig {
                    listen_addrs: Vec::new(),
                    fixed_peers: if fixed {
                        vec![endpoint.to_string()]
                    } else {
                        Vec::new()
                    },
                    dns_seeds_enabled: false,
                    outbound_full_relay_slots: 0,
                    outbound_block_relay_slots: 0,
                    ..P2pServiceConfig::default()
                },
                Arc::new(AtomicBool::new(false)),
            );
            if !fixed {
                service
                    .add_node(endpoint, true)
                    .expect("persistent addnode");
            }
            let ready: Arc<dyn Fn(crate::PeerSource) + Send + Sync> = Arc::new(|_| {});
            service
                .start(None, None, &ready, crate::ListenerExtras::default())
                .expect("start");
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut attempts = 0;
            while attempts < 2 && Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        attempts += 1;
                        drop(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            }
            service.shutdown();
            service.join().expect("join");
            assert_eq!(
                attempts, 2,
                "fixed={fixed}: a failed handshake must permit a new dial"
            );
        }
    }
}
