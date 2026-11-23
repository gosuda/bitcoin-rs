use crate::PeerRemote;
use std::cmp::Ordering;
use std::time::{Duration, Instant};

use hashbrown::HashMap;

#[derive(Clone, Copy, Debug)]
pub(crate) struct EvictionCandidate {
    pub(crate) addr: PeerRemote,
    pub(crate) connected: Instant,
    pub(crate) minimum_ping: Option<Duration>,
    pub(crate) last_block: u64,
    pub(crate) last_tx: u64,
    pub(crate) relevant_services: bool,
    pub(crate) relay_txs: bool,
    pub(crate) keyed_netgroup: u64,
    pub(crate) is_local: bool,
}

pub(crate) fn select_inbound_to_evict(
    mut candidates: Vec<EvictionCandidate>,
) -> Option<PeerRemote> {
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.connected));
    protect_last(
        &mut candidates,
        4,
        |a, b| a.keyed_netgroup.cmp(&b.keyed_netgroup),
        |_| true,
    );
    protect_last(
        &mut candidates,
        8,
        |a, b| {
            a.minimum_ping
                .map(std::cmp::Reverse)
                .cmp(&b.minimum_ping.map(std::cmp::Reverse))
        },
        |_| true,
    );
    protect_last(&mut candidates, 4, compare_tx_time, |_| true);
    protect_last(
        &mut candidates,
        8,
        compare_block_relay_only_time,
        |candidate| !candidate.relay_txs && candidate.relevant_services,
    );
    protect_last(&mut candidates, 4, compare_block_time, |_| true);
    protect_by_ratio(&mut candidates);
    newest_in_largest_netgroup(&candidates)
}

fn protect_last(
    candidates: &mut Vec<EvictionCandidate>,
    k: usize,
    compare: impl FnMut(&EvictionCandidate, &EvictionCandidate) -> Ordering,
    protect: impl Fn(&EvictionCandidate) -> bool,
) {
    candidates.sort_by(compare);
    let tail = candidates.split_off(candidates.len().saturating_sub(k));
    candidates.extend(tail.into_iter().filter(|candidate| !protect(candidate)));
}

fn compare_tx_time(a: &EvictionCandidate, b: &EvictionCandidate) -> Ordering {
    a.last_tx
        .cmp(&b.last_tx)
        .then_with(|| a.relay_txs.cmp(&b.relay_txs))
        .then_with(|| b.connected.cmp(&a.connected))
}

fn compare_block_relay_only_time(a: &EvictionCandidate, b: &EvictionCandidate) -> Ordering {
    b.relay_txs
        .cmp(&a.relay_txs)
        .then_with(|| a.last_block.cmp(&b.last_block))
        .then_with(|| a.relevant_services.cmp(&b.relevant_services))
        .then_with(|| b.connected.cmp(&a.connected))
}

fn compare_block_time(a: &EvictionCandidate, b: &EvictionCandidate) -> Ordering {
    a.last_block
        .cmp(&b.last_block)
        .then_with(|| a.relevant_services.cmp(&b.relevant_services))
        .then_with(|| b.connected.cmp(&a.connected))
}

#[derive(Clone, Copy)]
enum ProtectedNetwork {
    I2p,
    Local,
    Onion,
}

impl ProtectedNetwork {
    fn contains(self, candidate: &EvictionCandidate) -> bool {
        match self {
            Self::I2p => candidate.addr.network() == crate::PeerNetwork::I2p,
            Self::Local => candidate.is_local,
            Self::Onion => candidate.addr.network() == crate::PeerNetwork::Onion,
        }
    }
}

fn protect_by_ratio(candidates: &mut Vec<EvictionCandidate>) {
    let initial = candidates.len();
    let protect_total = initial / 2;
    let network_quota = protect_total / 2;
    let mut networks = [
        ProtectedNetwork::I2p,
        ProtectedNetwork::Local,
        ProtectedNetwork::Onion,
    ]
    .map(|network| {
        let count = candidates
            .iter()
            .filter(|candidate| network.contains(candidate))
            .count();
        (network, count)
    });
    networks.sort_by_key(|(_, count)| *count);
    let mut protected = 0;
    while protected < network_quota {
        let active = networks.iter().filter(|(_, count)| *count > 0).count();
        if active == 0 {
            break;
        }
        let per_network = ((network_quota - protected) / active).max(1);
        let previous = protected;
        for (network, count) in &mut networks {
            if *count == 0 {
                continue;
            }
            let before = candidates.len();
            protect_last(
                candidates,
                per_network,
                |a, b| {
                    network
                        .contains(a)
                        .cmp(&network.contains(b))
                        .then_with(|| b.connected.cmp(&a.connected))
                },
                |candidate| network.contains(candidate),
            );
            let removed = before - candidates.len();
            protected += removed;
            *count -= removed;
            if protected >= network_quota {
                break;
            }
        }
        if protected == previous {
            break;
        }
    }
    assert_eq!(protected, initial - candidates.len());
    protect_last(
        candidates,
        protect_total - protected,
        |a, b| b.connected.cmp(&a.connected),
        |_| true,
    );
}

fn newest_in_largest_netgroup(candidates: &[EvictionCandidate]) -> Option<PeerRemote> {
    let mut groups: HashMap<u64, (usize, &EvictionCandidate)> = HashMap::new();
    let mut chosen: Option<(usize, &EvictionCandidate)> = None;
    for candidate in candidates {
        let group = groups
            .entry(candidate.keyed_netgroup)
            .or_insert((0, candidate));
        group.0 += 1;
        let (size, newest) = *group;
        if chosen.is_none_or(|(best_size, best)| {
            size > best_size || (size == best_size && newest.connected > best.connected)
        }) {
            chosen = Some((size, newest));
        }
    }
    chosen.map(|(_, newest)| newest.addr)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn candidate(base: Instant, order: u16, keyed_netgroup: u64) -> EvictionCandidate {
        EvictionCandidate {
            addr: PeerRemote::from(([203, 0, 113, 1], order)),
            connected: base + Duration::from_secs(u64::from(order)),
            minimum_ping: None,
            last_block: 0,
            last_tx: 0,
            relevant_services: false,
            relay_txs: false,
            keyed_netgroup,
            is_local: false,
        }
    }

    fn flood(base: Instant) -> Vec<EvictionCandidate> {
        (0..40).map(|order| candidate(base, order, 7)).collect()
    }

    fn port(selected: Option<PeerRemote>) -> Option<u16> {
        selected
            .and_then(PeerRemote::endpoint)
            .map(crate::PeerEndpoint::port)
    }

    #[test]
    fn twenty_plain_candidates_are_all_protected() {
        let base = Instant::now();
        assert_eq!(select_inbound_to_evict(Vec::new()), None);
        let twenty: Vec<_> = (0..20).map(|order| candidate(base, order, 7)).collect();
        assert_eq!(select_inbound_to_evict(twenty), None);
        let twenty_one: Vec<_> = (0..21).map(|order| candidate(base, order, 7)).collect();
        assert_eq!(port(select_inbound_to_evict(twenty_one)), Some(20));
    }

    // P2P-08
    #[test]
    fn the_flooding_netgroup_loses_its_newest_member() {
        let base = Instant::now();
        let mut candidates = flood(base);
        candidates.extend((40..45).map(|order| candidate(base, order, 100 + u64::from(order))));
        assert_eq!(port(select_inbound_to_evict(candidates)), Some(39));
    }

    #[test]
    fn a_recent_transaction_protects_a_connection() {
        let base = Instant::now();
        let mut candidates = flood(base);
        candidates[39].last_tx = 1;
        assert_eq!(port(select_inbound_to_evict(candidates)), Some(38));
    }

    #[test]
    fn a_recent_block_protects_a_connection() {
        let base = Instant::now();
        let mut candidates = flood(base);
        candidates[39].last_block = 1;
        assert_eq!(port(select_inbound_to_evict(candidates)), Some(38));
    }

    #[test]
    fn a_block_relay_only_peer_with_wanted_services_is_protected() {
        let base = Instant::now();
        let mut candidates = flood(base);
        for candidate in &mut candidates {
            candidate.relay_txs = true;
        }
        candidates[39].relay_txs = false;
        candidates[39].relevant_services = true;
        assert_eq!(port(select_inbound_to_evict(candidates.clone())), Some(38));
        candidates[39].relevant_services = false;
        assert_eq!(port(select_inbound_to_evict(candidates)), Some(39));
    }

    // P2P-08
    #[test]
    fn eight_lowest_minimum_pings_protect_connections() {
        let base = Instant::now();
        let mut candidates = flood(base);
        for (offset, candidate) in candidates[31..].iter_mut().enumerate() {
            candidate.minimum_ping = Some(Duration::from_micros(
                9 - u64::try_from(offset).unwrap_or_else(|_| panic!("fixture index fits")),
            ));
        }
        assert_eq!(port(select_inbound_to_evict(candidates)), Some(31));
    }

    // P2P-08
    #[test]
    fn zero_ping_is_measured_and_unknown_ping_is_not_fast() {
        let base = Instant::now();
        let mut candidates = flood(base);
        candidates[39].minimum_ping = Some(Duration::ZERO);
        assert_eq!(port(select_inbound_to_evict(candidates)), Some(38));
    }

    // P2P-08
    #[test]
    fn network_ratio_matches_core_v31_1_vectors() {
        struct Case {
            count: u16,
            local: &'static [u16],
            i2p: &'static [u16],
            onion: &'static [u16],
            expected: &'static [u16],
        }

        let base = Instant::now();
        let cases = [
            Case {
                count: 4,
                local: &[2],
                i2p: &[3],
                onion: &[1],
                expected: &[1, 2],
            },
            Case {
                count: 7,
                local: &[4],
                i2p: &[6],
                onion: &[5],
                expected: &[2, 3, 4, 5],
            },
            Case {
                count: 8,
                local: &[6],
                i2p: &[5],
                onion: &[4],
                expected: &[2, 3, 4, 7],
            },
            Case {
                count: 16,
                local: &[6, 12, 13, 14, 15],
                i2p: &[7, 11],
                onion: &[9, 10],
                expected: &[4, 5, 8, 10, 12, 13, 14, 15],
            },
            Case {
                count: 24,
                local: &[12],
                i2p: &[15, 16, 17, 18, 19, 20, 21, 22],
                onion: &[23],
                expected: &[6, 7, 8, 9, 10, 11, 13, 14, 19, 20, 21, 22],
            },
            Case {
                count: 24,
                local: &[15],
                i2p: &[12, 14, 17],
                onion: &[18, 19, 20, 21, 22, 23],
                expected: &[6, 7, 8, 9, 10, 11, 13, 16, 20, 21, 22, 23],
            },
            Case {
                count: 24,
                local: &[13],
                i2p: &[17, 18, 19, 20, 21, 22, 23],
                onion: &[12, 14, 15, 16],
                expected: &[6, 7, 8, 9, 10, 11, 16, 19, 20, 21, 22, 23],
            },
        ];
        for Case {
            count,
            local,
            i2p,
            onion,
            expected,
        } in cases
        {
            for anonymous in [false, true] {
                for reverse in [false, true] {
                    let mut candidates: Vec<_> = (0..count)
                        .map(|order| {
                            let mut entry = candidate(base, order, 7);
                            entry.is_local = local.contains(&order);
                            if i2p.contains(&order) {
                                entry.addr = crate::PeerEndpoint::I2p {
                                    hash: [1; 32],
                                    port: order,
                                }
                                .into();
                            } else if onion.contains(&order) {
                                entry.addr = if anonymous {
                                    PeerRemote::AnonymousTor(
                                        crate::connection::ConnectionId::for_test_raw(
                                            u64::from(order) + 1,
                                        ),
                                    )
                                } else {
                                    crate::PeerEndpoint::TorV3 {
                                        key: [2; 32],
                                        port: order,
                                    }
                                    .into()
                                };
                            }
                            entry
                        })
                        .collect();
                    if reverse {
                        candidates.reverse();
                    }
                    protect_by_ratio(&mut candidates);
                    let mut retained: Vec<_> = candidates
                        .iter()
                        .map(|candidate| candidate.connected.duration_since(base).as_secs())
                        .collect();
                    retained.sort_unstable();
                    let expected: Vec<_> = expected.iter().copied().map(u64::from).collect();
                    assert_eq!(retained, expected, "{count}, {anonymous}, {reverse}");
                }
            }
        }
    }

    // P2P-08
    #[test]
    fn absent_network_groups_leave_half_protected_by_uptime() {
        let base = Instant::now();
        for count in 0..40_u16 {
            let mut candidates: Vec<_> =
                (0..count).map(|order| candidate(base, order, 7)).collect();
            protect_by_ratio(&mut candidates);
            let mut retained: Vec<_> = candidates
                .iter()
                .map(|candidate| candidate.connected.duration_since(base).as_secs())
                .collect();
            retained.sort_unstable();
            assert_eq!(
                retained,
                (u64::from(count / 2)..u64::from(count)).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn localhost_peers_keep_up_to_a_quarter_of_the_protection() {
        let base = Instant::now();
        let mut candidates: Vec<_> = (0..36)
            .map(|order| candidate(base, order, 1 + u64::from(order)))
            .collect();
        candidates.extend((36..40).map(|order| EvictionCandidate {
            is_local: true,
            ..candidate(base, order, 0)
        }));
        assert_eq!(port(select_inbound_to_evict(candidates.clone())), Some(23));
        for candidate in &mut candidates[36..] {
            candidate.is_local = false;
        }
        assert_eq!(port(select_inbound_to_evict(candidates)), Some(39));
    }
}
