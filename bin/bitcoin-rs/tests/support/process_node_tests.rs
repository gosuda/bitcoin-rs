//! Unit tests for the harness port reservation and shared time-limit helper.
//!
//! Included only by the `support_unit_tests` target so each assertion runs
//! once per profile instead of once per embedding binary (issue #1083).

use std::net::TcpListener;
use std::time::{Duration, Instant};

use crate::support::process_node::{loopback_addresses, remaining_time};

#[test]
fn socket_time_limit_rejects_sub_microsecond_intervals() {
    let now = Instant::now();
    for nanos in [0, 1, 999] {
        assert!(remaining_time(now + Duration::from_nanos(nanos), now, "expired").is_err());
    }
    for duration in [Duration::from_micros(1), Duration::from_secs(1)] {
        assert_eq!(
            remaining_time(now + duration, now, "expired").expect("valid time limit"),
            duration
        );
    }
}

#[test]
fn selected_ports_stay_reserved() {
    let ports = loopback_addresses().expect("select two ports");
    let rpc = ports.0.local_addr().expect("RPC address");
    let p2p = ports.1.local_addr().expect("P2P address");
    assert_ne!(rpc, p2p);
    for address in [rpc, p2p] {
        let error = TcpListener::bind(address).expect_err("the selected port must stay reserved");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }
    drop(ports);
    for address in [rpc, p2p] {
        let listener = TcpListener::bind(address).expect("the released port must be available");
        drop(listener);
    }
}
