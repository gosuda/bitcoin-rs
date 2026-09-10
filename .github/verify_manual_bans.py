from pathlib import Path
import subprocess
import sys
import textwrap

BASE = '93a340bad78365691c14cad0dca0dcaa85942874'
HASHES = {
    'crates/p2p/src/subnet.rs': '49359d2fde7f21c31f0751276af6e41f94c56b7c',
    'crates/p2p/src/service.rs': '3f4c83c51f05ff39b554b92131a95d15e138a491',
    'crates/p2p/src/peer.rs': '3f7fd1b8767860bfc4633758a91625e8c810e4c4',
    'crates/p2p/src/listener.rs': '1cc77a8c9e4492d45dd3cd78d166aed9d6a5b423',
    'docs/contracts/p2p-wire.md': '096842360d1ff627cacfb1b4adb9f8be159bd71a',
    'crates/rpc/src/handlers/network.rs': '3dad7fb5505626389365aba6771f6485d5a27160',
}

def replace(path, old, new):
    p = Path(path)
    text = p.read_text()
    assert text.count(old) == 1, (path, text.count(old), old[:120])
    p.write_text(text.replace(old, new, 1))

def append(path, source):
    p = Path(path)
    p.write_text(p.read_text().rstrip() + '\n\n' + textwrap.dedent(source).strip() + '\n')

RPC_TESTS = r'''
#[cfg(test)]
mod manual_ban_tests {
    use super::*;
    use bitcoin_rs_p2p::{Message, PeerLease};
    use sonic_rs::json;

    fn register(ctx: &Context, address: &str) -> PeerLease {
        let addr = address.parse().unwrap_or_else(|error| panic!("address: {error}"));
        let (sender, _receiver) = crossbeam_channel::unbounded::<Message>();
        let lease = PeerLease::new(sender);
        ctx.peer_table.register(addr, lease.clone());
        lease
    }

    #[test]
    fn rpc_manual_ban_disconnects_matching_handshakes_only() {
        let ctx = Arc::new(Context::new());
        let target = register(&ctx, "192.0.2.10:8333");
        let mapped = register(&ctx, "[::ffff:192.0.2.11]:8333");
        let other = register(&ctx, "198.51.100.10:8333");
        let result = setban(&ctx, &json!(["192.0.2.0/24", "add", 60]))
            .unwrap_or_else(|error| panic!("setban: {error}"));
        assert!(result.is_null());
        assert!(target.is_cancelled(), "manual ban left a matching lease active");
        assert!(mapped.is_cancelled());
        assert!(!other.is_cancelled());
        assert_eq!(ctx.peer_table.len(), 1);
        assert_eq!(ctx.banned.read().len(), 1);
    }

    #[test]
    fn rpc_manual_ban_time_overflow_preserves_state() {
        let ctx = Arc::new(Context::new());
        setban(&ctx, &json!(["203.0.113.0/24", "add", 60]))
            .unwrap_or_else(|error| panic!("seed ban: {error}"));
        let before = ctx.banned.read().clone();
        let target = register(&ctx, "192.0.2.10:8333");
        for absolute in [false, true] {
            assert!(matches!(
                setban(&ctx, &json!(["192.0.2.0/24", "add", u64::MAX, absolute])),
                Err(RpcError::InvalidParameter(_))
            ), "unrepresentable expiry became a permanent ban");
            assert_eq!(*ctx.banned.read(), before);
            assert!(!target.is_cancelled());
            assert_eq!(ctx.peer_table.len(), 1);
        }
    }
}
'''

SERVICE_TESTS = r'''
#[cfg(test)]
mod manual_ban_tests {
    use super::*;

    #[test]
    fn service_manual_ban_disconnects_matching_handshakes() {
        let service = P2pService::new(P2pServiceConfig::default(), Arc::new(AtomicBool::new(false)));
        let addr = SocketAddr::from(([192, 0, 2, 10], 8333));
        let (sender, _receiver) = crossbeam_channel::unbounded::<crate::Message>();
        let lease = crate::PeerLease::new(sender);
        service.table().register(addr, lease.clone());
        service.set_ban(crate::BannedSubnet {
            subnet: crate::IpSubnet::from_ip(addr.ip()),
            banned_until: None,
            ban_created: UNIX_EPOCH,
            reason: "test".to_owned(),
        });
        assert!(lease.is_cancelled(), "manual ban left a matching lease active");
        assert!(service.table().is_empty());
        assert_eq!(service.banned().len(), 1);
    }
}
'''

SUBNET_CODE = r'''
/// Replaces an exact manual-ban entry and revokes matching active sessions.
///
/// Lock order is ban list, then peer table, also used by listener registration.
/// Lease cancellation only signals connection owners; socket I/O stays outside
/// these locks. Expired entries do not revoke sessions.
pub fn apply_manual_ban(
    banned: &parking_lot::RwLock<Vec<BannedSubnet>>,
    peers: &crate::PeerTable,
    entry: BannedSubnet,
    now: SystemTime,
) -> Vec<std::net::SocketAddr> {
    let subnet = entry.subnet;
    let active = entry.banned_until.is_none_or(|until| until > now);
    let mut banned = banned.write();
    banned.retain(|current| current.subnet != subnet);
    banned.push(entry);
    let disconnected = if active {
        peers.disconnect_matching(|addr, _| subnet.contains(addr.ip()))
    } else {
        Vec::new()
    };
    drop(banned);
    disconnected
}

/// Registers under the same ban-list reservation used by manual ban updates.
pub(crate) fn register_unbanned(
    banned: &parking_lot::RwLock<Vec<BannedSubnet>>,
    peers: &crate::PeerTable,
    addr: std::net::SocketAddr,
    lease: crate::PeerLease,
    now: SystemTime,
) -> bool {
    let banned = banned.read();
    if is_banned(&banned, addr.ip(), now) {
        lease.cancel();
        return false;
    }
    peers.register(addr, lease);
    drop(banned);
    true
}

#[cfg(test)]
mod manual_ban_tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Barrier;
    use std::time::{Duration, UNIX_EPOCH};
    use parking_lot::RwLock;

    fn lease() -> crate::PeerLease {
        let (sender, _receiver) = crossbeam_channel::unbounded::<crate::Message>();
        crate::PeerLease::new(sender)
    }

    fn entry(addr: SocketAddr, until: Option<SystemTime>) -> BannedSubnet {
        BannedSubnet {
            subnet: IpSubnet::from_ip(addr.ip()),
            banned_until: until,
            ban_created: UNIX_EPOCH,
            reason: "test".to_owned(),
        }
    }

    #[test]
    fn manual_ban_and_registration_are_order_independent() {
        let addr = SocketAddr::from(([192, 0, 2, 10], 8333));
        for ban_first in [false, true] {
            let bans = RwLock::new(Vec::new());
            let peers = crate::PeerTable::new();
            let lease = lease();
            if ban_first {
                assert!(apply_manual_ban(&bans, &peers, entry(addr, None), UNIX_EPOCH).is_empty());
                assert!(!register_unbanned(&bans, &peers, addr, lease.clone(), UNIX_EPOCH));
            } else {
                assert!(register_unbanned(&bans, &peers, addr, lease.clone(), UNIX_EPOCH));
                assert_eq!(apply_manual_ban(&bans, &peers, entry(addr, None), UNIX_EPOCH), vec![addr]);
            }
            assert!(peers.is_empty());
            assert!(lease.is_cancelled());
        }
    }

    #[test]
    fn expired_manual_ban_allows_registration_and_does_not_revoke() {
        let addr = SocketAddr::from(([192, 0, 2, 10], 8333));
        let now = UNIX_EPOCH + Duration::from_secs(1);
        let bans = RwLock::new(Vec::new());
        let peers = crate::PeerTable::new();
        let lease = lease();
        assert!(apply_manual_ban(&bans, &peers, entry(addr, Some(UNIX_EPOCH)), now).is_empty());
        assert!(register_unbanned(&bans, &peers, addr, lease.clone(), now));
        assert!(apply_manual_ban(&bans, &peers, entry(addr, Some(now)), now).is_empty());
        assert!(!lease.is_cancelled());
        assert_eq!(peers.len(), 1);
        assert_eq!(bans.read().len(), 1);
    }

    #[test]
    fn concurrent_manual_ban_cannot_leave_a_registered_session() {
        let addr = SocketAddr::from(([192, 0, 2, 10], 8333));
        for _ in 0..64 {
            let bans = RwLock::new(Vec::new());
            let peers = crate::PeerTable::new();
            let lease = lease();
            let start = Barrier::new(2);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    start.wait();
                    apply_manual_ban(&bans, &peers, entry(addr, None), UNIX_EPOCH);
                });
                scope.spawn(|| {
                    start.wait();
                    register_unbanned(&bans, &peers, addr, lease.clone(), UNIX_EPOCH);
                });
            });
            assert!(peers.is_empty());
            assert!(lease.is_cancelled());
        }
    }
}
'''

def main():
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == BASE
    if sys.argv[1] == 'tests':
        for path, expected in HASHES.items():
            assert subprocess.check_output(['git', 'hash-object', path], text=True).strip() == expected, path
        append('crates/rpc/src/handlers/network.rs', RPC_TESTS)
        append('crates/p2p/src/service.rs', SERVICE_TESTS)
    elif sys.argv[1] == 'fix':
        append('crates/p2p/src/subnet.rs', SUBNET_CODE)
        replace('crates/p2p/src/service.rs', '''        let mut banned = self.banned.write();
        banned.retain(|current| current.subnet != entry.subnet);
        banned.push(entry);''', '''        let _ = crate::subnet::apply_manual_ban(&self.banned, &self.lifecycle.table(), entry, SystemTime::now());''')
        replace('crates/rpc/src/handlers/network.rs', '''            let mut banned = ctx.banned.write();
            banned.retain(|entry| entry.subnet != subnet);
            banned.push(BannedSubnet {
                subnet,
                banned_until: ban_until(now, bantime, absolute),
                ban_created: now,
                reason: "manual".to_owned(),
            });''', '''            let banned_until = ban_until(now, bantime, absolute).ok_or_else(|| {
                RpcError::InvalidParameter("ban time is out of range".to_owned())
            })?;
            let _ = bitcoin_rs_p2p::subnet::apply_manual_ban(
                &ctx.banned,
                &ctx.peer_table,
                BannedSubnet {
                    subnet,
                    banned_until: Some(banned_until),
                    ban_created: now,
                    reason: "manual".to_owned(),
                },
                now,
            );''')
        replace('crates/p2p/src/peer.rs', '''        self.banned.write().push(crate::BannedSubnet {
            subnet,
            banned_until: Some(
                SystemTime::UNIX_EPOCH
                    + Duration::from_secs(until_epoch.max(0).try_into().unwrap_or(u64::MAX)),
            ),
            ban_created: now,
            reason: reason.to_owned(),
        });

        let disconnected = self.disconnect_matching(|addr, _| subnet.contains(addr.ip()));''', '''        let disconnected = crate::subnet::apply_manual_ban(
            &self.banned,
            &self.peer_table,
            crate::BannedSubnet {
                subnet,
                banned_until: Some(
                    SystemTime::UNIX_EPOCH
                        + Duration::from_secs(until_epoch.max(0).try_into().unwrap_or(u64::MAX)),
                ),
                ban_created: now,
                reason: reason.to_owned(),
            },
            now,
        );''')
        replace('docs/contracts/p2p-wire.md', '### `P2P-03`:',
                '- Manual ban application and inbound/outbound registration share ban-list-then-\n'
                '  peer-table lock ordering in `crates/p2p/src/subnet.rs`. An active ban revokes\n'
                '  matching sessions, including handshakes; registration cannot slip behind\n'
                '  its sweep. Expired bans do not revoke or block sessions. RPC rejects an\n'
                '  unrepresentable expiry before mutation instead of creating a permanent ban.\n\n'
                '### `P2P-03`:')
        replace('docs/contracts/p2p-wire.md', '## Proven by\n',
                '## Proven by\n\n'
                '- `manual_ban_tests` in `crates/p2p/src/subnet.rs`, `service.rs`, and\n'
                '  `crates/rpc/src/handlers/network.rs` cover both registration orders,\n'
                '  concurrent registration, expiry boundaries, mapped IPv4 addresses,\n'
                '  matching-only revocation, and failure before mutation (P2P-02).\n')
        for addr in ('addr', 'peer_addr'):
            replace('crates/p2p/src/listener.rs', f'    shared.peer_table.register({addr}, lease.clone());', f'''    if !crate::subnet::register_unbanned(
        &shared.banned, &shared.peer_table, {addr}, lease.clone(), SystemTime::now(),
    ) {{
        return Err(crate::wire::PeerError::BannedDestination({addr}.ip()));
    }}''')
    else:
        raise ValueError('Expected tests or fix')

if __name__ == '__main__':
    main()
