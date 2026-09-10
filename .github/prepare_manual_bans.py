"""Build narrow test-first candidates in a disposable, hash-verified checkout."""
from pathlib import Path
import subprocess
import sys

EXPECTED = {
    'crates/p2p/src/lib.rs': '3bccad30c4be1fd96cb2bdbed46ea7a3d62a02bb',
    'crates/p2p/src/service.rs': '3f4c83c51f05ff39b554b92131a95d15e138a491',
    'crates/p2p/src/listener.rs': '1cc77a8c9e4492d45dd3cd78d166aed9d6a5b423',
    'crates/p2p/src/peer.rs': '3f7fd1b8767860bfc4633758a91625e8c810e4c4',
    'crates/rpc/src/handlers/network.rs': '3dad7fb5505626389365aba6771f6485d5a27160',
}
RPC = 'crates/rpc/src/handlers/network.rs'

def replace(path, old, new):
    p = Path(path)
    text = p.read_text()
    assert text.count(old) == 1, (path, text.count(old), old[:80])
    p.write_text(text.replace(old, new, 1))

def append(path, text):
    p = Path(path)
    p.write_text(p.read_text() + text)

phase = sys.argv[1]
if phase.endswith('-tests'):
    for path, expected in EXPECTED.items():
        actual = subprocess.check_output(['git', 'hash-object', path], text=True).strip()
        assert actual == expected, (path, actual, expected)

if phase == 'expiry-tests':
    append(RPC, r'''

#[cfg(test)]
mod expiry_tests {
    use super::*;
    use sonic_rs::json;

    #[test]
    fn expiry_overflow_preserves_the_existing_ban() -> Result<(), RpcError> {
        let ctx = Arc::new(Context::new());
        setban(&ctx, &json!(["10.0.0.1", "add"]))?;
        let original = ctx.banned.read().clone();
        assert!(original[0].banned_until.is_some());
        for absolute in [false, true] {
            let result = setban(&ctx, &json!(["10.0.0.1", "add", u64::MAX, absolute]));
            assert!(matches!(result, Err(RpcError::InvalidParams(_))),
                "unrepresentable expiry must fail before ban mutation: {result:?}");
            assert_eq!(*ctx.banned.read(), original);
        }
        Ok(())
    }
}
''')
elif phase == 'expiry-fix':
    replace(RPC, '''fn ban_until(now: SystemTime, bantime: u64, absolute: bool) -> Option<SystemTime> {
    if absolute {
        return UNIX_EPOCH.checked_add(Duration::from_secs(bantime));
    }

    let duration = if bantime == 0 {
        Duration::from_secs(DEFAULT_BAN_TIME_SECS)
    } else {
        Duration::from_secs(bantime)
    };
    now.checked_add(duration)
}
''', '''fn ban_until(now: SystemTime, bantime: u64, absolute: bool) -> Result<SystemTime, RpcError> {
    let (start, seconds) = if absolute {
        (UNIX_EPOCH, bantime)
    } else {
        (now, if bantime == 0 { DEFAULT_BAN_TIME_SECS } else { bantime })
    };
    start
        .checked_add(Duration::from_secs(seconds))
        .ok_or(RpcError::InvalidParams("bantime exceeds the supported timestamp range"))
}
''')
    replace(RPC, '''            let absolute = optional_bool(params, 3, false)?;
            let mut banned = ctx.banned.write();''', '''            let absolute = optional_bool(params, 3, false)?;
            let banned_until = Some(ban_until(now, bantime, absolute)?);
            let mut banned = ctx.banned.write();''')
    replace(RPC, '                banned_until: ban_until(now, bantime, absolute),', '                banned_until,')
elif phase == 'ban-tests':
    append('crates/p2p/src/service.rs', r'''

#[cfg(test)]
mod manual_ban_tests {
    use super::*;

    #[test]
    fn manual_ban_service_revokes_registered_sessions() -> Result<(), Box<dyn std::error::Error>> {
        let service = P2pService::new(P2pServiceConfig::default(), Arc::new(AtomicBool::new(false)));
        let table = service.table();
        let addresses: [SocketAddr; 3] = [
            "127.0.0.1:8333".parse()?,
            "[::ffff:127.0.0.2]:8333".parse()?,
            "127.0.1.1:8333".parse()?,
        ];
        let mut leases = Vec::new();
        for address in addresses {
            let (tx, rx) = crossbeam_channel::unbounded();
            let lease = crate::PeerLease::new(tx);
            table.register(address, lease.clone());
            leases.push((lease, rx));
        }
        let subnet = "127.0.0.0/24".parse()?;
        service.set_ban(crate::BannedSubnet {
            subnet,
            banned_until: None,
            ban_created: SystemTime::now(),
            reason: "test".into(),
        });
        assert!(leases[0].0.is_cancelled(), "manual ban left a matching lease active");
        assert!(leases[1].0.is_cancelled(), "mapped IPv4 lease escaped its subnet ban");
        assert!(!leases[2].0.is_cancelled(), "manual ban cancelled an unrelated lease");
        assert_eq!(table.len(), 1);
        assert!(table.is_current(leases[2].0.source(addresses[2])));
        assert_eq!(service.banned().len(), 1);
        assert_eq!(service.banned()[0].subnet, subnet);
        Ok(())
    }

    #[test]
    fn manual_ban_expired_entry_preserves_current_peers() -> Result<(), Box<dyn std::error::Error>> {
        let service = P2pService::new(P2pServiceConfig::default(), Arc::new(AtomicBool::new(false)));
        let addr: SocketAddr = "127.0.0.1:8333".parse()?;
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = crate::PeerLease::new(tx);
        service.table().register(addr, lease.clone());
        service.set_ban(crate::BannedSubnet {
            subnet: crate::IpSubnet::from_ip(addr.ip()),
            banned_until: Some(UNIX_EPOCH),
            ban_created: UNIX_EPOCH,
            reason: "expired".into(),
        });
        assert!(!lease.is_cancelled());
        assert!(service.table().is_current(lease.source(addr)));
        Ok(())
    }
}
''')
    append(RPC, r'''

#[cfg(test)]
mod manual_ban_tests {
    use super::*;
    use sonic_rs::json;

    #[test]
    fn manual_ban_rpc_disconnects_only_the_selected_subnet() -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let mut leases = Vec::new();
        for address in ["10.0.0.1:8333", "10.0.0.2:8333", "10.0.1.1:8333"] {
            let addr: SocketAddr = address.parse()?;
            let (tx, rx) = crossbeam_channel::unbounded();
            let lease = bitcoin_rs_p2p::PeerLease::new_inbound(tx);
            ctx.peer_table.register(addr, lease.clone());
            leases.push((lease, rx));
        }
        let handler = crate::Handler::new(Arc::clone(&ctx));
        handler.dispatch("setban", &json!(["10.0.0.0/24", "add"]))?;
        assert!(leases[0].0.is_cancelled(), "RPC ban left the first matching lease active");
        assert!(leases[1].0.is_cancelled(), "RPC ban left the second matching lease active");
        assert!(!leases[2].0.is_cancelled());
        assert_eq!(ctx.peer_table.len(), 1);
        assert_eq!(ctx.banned.read().len(), 1);
        Ok(())
    }
}
''')
    append('crates/p2p/src/listener.rs', r'''

#[cfg(test)]
mod manual_ban_tests {
    use super::*;

    #[test]
    fn manual_ban_is_rechecked_after_accept_before_registration() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (server, peer_addr) = listener.accept()?;
        // The old path terminates on EOF rather than waiting for its read timeout.
        client.shutdown(std::net::Shutdown::Write)?;
        let service = crate::P2pService::new(
            crate::P2pServiceConfig::default(), Arc::new(AtomicBool::new(false)));
        let shared = ConnectionShared::from_parts(service.table(), service.banned_handle(), None);
        // The socket has been accepted, but its worker has not registered.
        service.set_ban(crate::BannedSubnet {
            subnet: crate::IpSubnet::from_ip(peer_addr.ip()),
            banned_until: None,
            ban_created: SystemTime::now(),
            reason: "late ban".into(),
        });
        let (headers, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks, _blocks_rx) = crossbeam_channel::unbounded();
        let sinks = InboundSyncSinks::new(headers, blocks, None);
        let result = run_handshake(server, peer_addr, Magic::BITCOIN, &shared, &sinks);
        assert!(matches!(result, Err(crate::PeerError::BannedDestination(ip)) if ip == peer_addr.ip()),
            "late ban must reject before registration and wire I/O: {result:?}");
        assert!(service.table().is_empty());
        Ok(())
    }
}
''')
    append('crates/p2p/src/peer.rs', r'''

#[cfg(test)]
mod manual_ban_tests {
    use super::*;

    #[test]
    fn manual_ban_concurrent_add_has_exactly_one_success() {
        let controls = NetworkControls::new(
            Arc::new(crate::PeerTable::new()), Arc::new(RwLock::new(Vec::new())), 8_333);
        let subnet = crate::IpSubnet::from_ip(std::net::Ipv4Addr::LOCALHOST.into());
        let now = SystemTime::now();
        let barrier = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8).map(|_| scope.spawn(|| {
                barrier.wait();
                controls.ban(subnet, 60, false, now, "test")
            })).collect();
            handles.into_iter().map(|handle|
                handle.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            ).collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(results.iter().all(|result| matches!(result, Ok(_) | Err(BanError::AlreadyBanned))));
        assert_eq!(controls.banned_list(now).len(), 1);
    }
}
''')
elif phase == 'ban-fix':
    replace('crates/p2p/src/service.rs', '''    /// Adds or replaces one manual ban entry.
    pub fn set_ban(&self, entry: crate::BannedSubnet) {
        let mut banned = self.banned.write();
        banned.retain(|current| current.subnet != entry.subnet);
        banned.push(entry);
    }
''', '''    /// Adds or replaces a manual ban and disconnects matching active sessions.
    pub fn set_ban(&self, entry: crate::BannedSubnet) {
        let _ = apply_manual_ban(
            &mut self.banned.write(),
            &self.lifecycle.table(),
            entry,
            SystemTime::now(),
        );
    }
''')
    replace('crates/p2p/src/service.rs', 'fn reap_finished_outbound_connections(\n', '''/// Installs a manual ban and revokes matching sessions, including handshakes.
///
/// Callers retain the shared ban-list write guard through this operation.
/// Registration takes that list's read guard before the peer-table lock, so a
/// connection either registers before the ban and is revoked here, or observes
/// the ban before registration. Lease cancellation is nonblocking; no socket
/// I/O or callbacks run under these locks. Expired entries revoke no sessions.
pub fn apply_manual_ban(
    banned: &mut Vec<crate::BannedSubnet>,
    table: &crate::PeerTable,
    entry: crate::BannedSubnet,
    now: SystemTime,
) -> Vec<SocketAddr> {
    let subnet = entry.subnet;
    let active = entry.banned_until.is_none_or(|until| until > now);
    banned.retain(|current| current.subnet != subnet);
    banned.push(entry);
    if active {
        table.disconnect_matching(|addr, _| subnet.contains(addr.ip()))
    } else {
        Vec::new()
    }
}

fn reap_finished_outbound_connections(
''')
    replace('crates/p2p/src/lib.rs', '    apply_network_active,\n', '    apply_manual_ban, apply_network_active,\n')
    replace('crates/p2p/src/listener.rs', '    fn is_session_cancelled(&self) -> bool {\n', '''    fn register_connection(
        &self,
        addr: SocketAddr,
        lease: &crate::PeerLease,
    ) -> Result<(), crate::PeerError> {
        // Ban list -> peer table, shared with the manual-ban transition.
        // Keep the guard until registration completes; checking before connect
        // or in the accept loop leaves a gap before the worker registers.
        let banned = self.banned.read();
        if crate::subnet::is_banned(&banned, addr.ip(), SystemTime::now()) {
            return Err(crate::PeerError::BannedDestination(addr.ip()));
        }
        self.peer_table.register(addr, lease.clone());
        drop(banned);
        Ok(())
    }

    fn is_session_cancelled(&self) -> bool {
''')
    replace('crates/p2p/src/listener.rs', '''    let lease = crate::PeerLease::new(outbound_tx);
    shared.peer_table.register(addr, lease.clone());
''', '''    let lease = crate::PeerLease::new(outbound_tx);
    shared.register_connection(addr, &lease)?;
''')
    replace('crates/p2p/src/listener.rs', '''    let lease = crate::PeerLease::new_inbound(outbound_tx);
    shared.peer_table.register(peer_addr, lease.clone());
''', '''    let lease = crate::PeerLease::new_inbound(outbound_tx);
    shared.register_connection(peer_addr, &lease)?;
''')
    replace('crates/p2p/src/peer.rs', '''        let now_secs = unix_time_secs_at(now);
        if self.banned.read().iter().any(|entry| {
''', '''        let now_secs = unix_time_secs_at(now);
        let mut banned = self.banned.write();
        if banned.iter().any(|entry| {
''')
    replace('crates/p2p/src/peer.rs', '        self.banned.write().push(crate::BannedSubnet {\n', '        let entry = crate::BannedSubnet {\n')
    replace('crates/p2p/src/peer.rs', '''            reason: reason.to_owned(),
        });

        let disconnected = self.disconnect_matching(|addr, _| subnet.contains(addr.ip()));
''', '''            reason: reason.to_owned(),
        };
        let disconnected = crate::service::apply_manual_ban(&mut banned, &self.peer_table, entry, now);
        drop(banned);
''')
    replace(RPC, '''            let mut banned = ctx.banned.write();
            banned.retain(|entry| entry.subnet != subnet);
            banned.push(BannedSubnet {
                subnet,
                banned_until: ban_until(now, bantime, absolute),
                ban_created: now,
                reason: "manual".to_owned(),
            });
''', '''            let entry = BannedSubnet {
                subnet,
                banned_until: ban_until(now, bantime, absolute),
                ban_created: now,
                reason: "manual".to_owned(),
            };
            let _ = bitcoin_rs_p2p::apply_manual_ban(
                &mut ctx.banned.write(), &ctx.peer_table, entry, now,
            );
''')
else:
    raise SystemExit('unknown phase: ' + phase)
