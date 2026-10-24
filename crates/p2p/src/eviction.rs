//! Inbound eviction selection, ported from Bitcoin Core's `SelectNodeToEvict`
//! (`node/eviction.cpp:178-240`).
//!
//! Three Core steps are absent. Core protects the eight inbound peers with the
//! lowest minimum ping time, and bitcoin-rs measures no ping round trip. Core
//! breaks transaction-time ties on a loaded bloom filter, and BIP37 filters are
//! never loaded here. Core prefers peers it accepted while discouraged, and
//! bitcoin-rs refuses a discouraged address at accept.

use std::cmp::Ordering;
use std::time::Instant;

use hashbrown::HashMap;

/// One inbound connection the policy may choose: Core's
/// `NodeEvictionCandidate` without the fields of the absent steps.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EvictionCandidate {
    pub(crate) key: crate::ConnectionId,
    pub(crate) connected: Instant,
    /// Recency of the last block from this connection the node committed;
    /// 0 when there is none (Core `m_last_block_time`).
    pub(crate) last_block: u64,
    /// Recency of the last transaction from this connection the mempool
    /// accepted; 0 when there is none (Core `m_last_tx_time`).
    pub(crate) last_tx: u64,
    /// Core `fRelevantServices`.
    pub(crate) relevant_services: bool,
    /// Core `m_relay_txs`.
    pub(crate) relay_txs: bool,
    /// Core `nKeyedNetGroup`.
    pub(crate) keyed_netgroup: u64,
    /// Core `m_is_local`.
    pub(crate) is_local: bool,
}

/// Chooses the inbound connection to drop for a newcomer, or `None` when
/// every candidate is protected.
///
/// PRE: `candidates` holds only live inbound connections without `NoBan`,
///   which Core's `ProtectNoBanConnections` and `ProtectOutboundConnections`
///   leave.
/// POST: the result is the newest member of the netgroup with the most
///   unprotected candidates.
pub(crate) fn select_inbound_to_evict(
    mut candidates: Vec<EvictionCandidate>,
) -> Option<crate::ConnectionId> {
    // Core's `std::sort` leaves ties unordered; stable sorts from a
    // newest-first start make them deterministic.
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.connected));
    protect_last(
        &mut candidates,
        4,
        |a, b| a.keyed_netgroup.cmp(&b.keyed_netgroup),
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

/// Core's `EraseLastKElements`: sorts by `compare`, then removes from the last
/// `k` the candidates `protect` accepts.
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

/// Core `CompareNodeTXTime`.
fn compare_tx_time(a: &EvictionCandidate, b: &EvictionCandidate) -> Ordering {
    a.last_tx
        .cmp(&b.last_tx)
        .then_with(|| a.relay_txs.cmp(&b.relay_txs))
        .then_with(|| b.connected.cmp(&a.connected))
}

/// Core `CompareNodeBlockRelayOnlyTime`.
fn compare_block_relay_only_time(a: &EvictionCandidate, b: &EvictionCandidate) -> Ordering {
    b.relay_txs
        .cmp(&a.relay_txs)
        .then_with(|| a.last_block.cmp(&b.last_block))
        .then_with(|| a.relevant_services.cmp(&b.relevant_services))
        .then_with(|| b.connected.cmp(&a.connected))
}

/// Core `CompareNodeBlockTime`.
fn compare_block_time(a: &EvictionCandidate, b: &EvictionCandidate) -> Ordering {
    a.last_block
        .cmp(&b.last_block)
        .then_with(|| a.relevant_services.cmp(&b.relevant_services))
        .then_with(|| b.connected.cmp(&a.connected))
}

/// Core's `ProtectEvictionCandidatesByRatio`: protects the half connected
/// longest, reserving up to a quarter of the candidates for localhost peers
/// even when they are newer. Core's other reserved networks (onion, I2P,
/// CJDNS) are not transports here, so localhost is the only one.
fn protect_by_ratio(candidates: &mut Vec<EvictionCandidate>) {
    let initial = candidates.len();
    let protect_total = initial / 2;
    let local_quota = protect_total / 2;
    if local_quota > 0 && candidates.iter().any(|candidate| candidate.is_local) {
        protect_last(
            candidates,
            local_quota,
            |a, b| {
                a.is_local
                    .cmp(&b.is_local)
                    .then_with(|| b.connected.cmp(&a.connected))
            },
            |candidate| candidate.is_local,
        );
    }
    let protected = initial - candidates.len();
    protect_last(
        candidates,
        protect_total - protected,
        |a, b| b.connected.cmp(&a.connected),
        |_| true,
    );
}

/// Core's final step: the newest member of the netgroup with the most
/// candidates, a size tie going to the group whose newest member is newer.
///
/// PRE: `candidates` is sorted newest first.
fn newest_in_largest_netgroup(candidates: &[EvictionCandidate]) -> Option<crate::ConnectionId> {
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
    chosen.map(|(_, newest)| newest.key)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A plain candidate: `order` sets its connection age, higher is newer.
    fn candidate(base: Instant, order: u16, keyed_netgroup: u64) -> EvictionCandidate {
        EvictionCandidate {
            key: crate::ConnectionId::for_test_raw(u64::from(order)),
            connected: base + Duration::from_secs(u64::from(order)),
            last_block: 0,
            last_tx: 0,
            relevant_services: false,
            relay_txs: false,
            keyed_netgroup,
            is_local: false,
        }
    }

    /// Forty connections from one netgroup, oldest first.
    fn flood(base: Instant) -> Vec<EvictionCandidate> {
        (0..40).map(|order| candidate(base, order, 7)).collect()
    }

    fn port(selected: Option<crate::ConnectionId>) -> Option<u16> {
        selected.and_then(|id| u16::try_from(id.get()).ok())
    }

    #[test]
    fn twelve_plain_candidates_are_all_protected() {
        let base = Instant::now();
        assert_eq!(select_inbound_to_evict(Vec::new()), None);
        let twelve: Vec<_> = (0..12).map(|order| candidate(base, order, 7)).collect();
        assert_eq!(select_inbound_to_evict(twelve), None);
        let thirteen: Vec<_> = (0..13).map(|order| candidate(base, order, 7)).collect();
        assert_eq!(port(select_inbound_to_evict(thirteen)), Some(12));
    }

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

    #[test]
    fn localhost_peers_keep_up_to_a_quarter_of_the_protection() {
        let base = Instant::now();
        // Thirty-six older peers in their own netgroups, then four newer
        // localhost peers sharing one: without the reservation the localhost
        // group would be the largest.
        let mut candidates: Vec<_> = (0..36)
            .map(|order| candidate(base, order, 1 + u64::from(order)))
            .collect();
        candidates.extend((36..40).map(|order| EvictionCandidate {
            is_local: true,
            ..candidate(base, order, 0)
        }));
        assert_eq!(port(select_inbound_to_evict(candidates.clone())), Some(31));
        for candidate in &mut candidates[36..] {
            candidate.is_local = false;
        }
        assert_eq!(port(select_inbound_to_evict(candidates)), Some(39));
    }
}
