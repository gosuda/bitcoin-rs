//! Readiness gauge agreement with the RPC capability source.
//!
//! The gauge must render exactly the `getcapabilities` outcome spelling and
//! flip its active label atomically across transitions, because operators
//! read the scrape and the RPC row as one fact.

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bitcoin_rs_rpc::capabilities::{
    CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource, derived_index_status,
};

use super::super::MetricsServer;
use super::super::readiness::{
    READINESS_OUTCOMES, TXINDEX_READINESS_GAUGE, publish_txindex_readiness, readiness_state_name,
};
use super::SERVER_TEST_LOCK;
use super::server::identity;

/// One rendered readiness sample: `(state label, value)`.
type RenderedSample = (String, f64);

/// Exact one/zero checks: gauge outcomes are set from `bool`, so their bit
/// patterns are exactly 1.0 and 0.0 and may be compared exactly.
fn is_one(value: f64) -> bool {
    value.to_bits() == 1.0f64.to_bits()
}

fn is_zero(value: f64) -> bool {
    value.to_bits() == 0.0f64.to_bits()
}

struct FixedSource {
    enabled: bool,
    state: CapabilityState,
}

impl FixedSource {
    fn enabled(state: CapabilityState) -> Self {
        Self {
            enabled: true,
            state,
        }
    }
}

impl DerivedIndexCapabilitySource for FixedSource {
    fn capability(&self) -> CapabilityStatus {
        derived_index_status(self.enabled, self.state.clone())
    }
}

fn scrape(addr: SocketAddr) -> String {
    let mut last = None;
    for _ in 0..50 {
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            let request = b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            stream
                .write_all(request)
                .unwrap_or_else(|error| panic!("write scrape request: {error}"));
            let mut body = String::new();
            stream
                .read_to_string(&mut body)
                .unwrap_or_else(|error| panic!("read scrape response: {error}"));
            return body;
        }
        last = Some(());
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("scrape connect failed after retries: {last:?}");
}

/// Extracts `(state, value)` samples for the readiness gauge from rendered
/// Prometheus text.
fn readiness_samples(body: &str) -> Vec<RenderedSample> {
    let metric = TXINDEX_READINESS_GAUGE.replace('.', "_");
    let prefix = format!("{metric}{{");
    body.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix(&prefix)?;
            let (labels, value) = rest.split_once('}')?;
            let state = labels.split(',').find_map(|label| {
                label
                    .trim()
                    .strip_prefix("state=\"")
                    .and_then(|spelled| spelled.strip_suffix('"'))
            })?;
            let value = value.trim().parse::<f64>().ok()?;
            Some((state.to_owned(), value))
        })
        .collect()
}

/// One active outcome, spelled exactly as the RPC row spells it.
fn assert_one_active(samples: &[RenderedSample], expected: &str) {
    let active: Vec<_> = samples.iter().filter(|(_, value)| is_one(*value)).collect();
    assert_eq!(
        active.len(),
        1,
        "exactly one outcome must be active: {samples:?}"
    );
    assert_eq!(
        active.first().map(|(state, _)| state.as_str()),
        Some(expected),
        "the active label must be the getcapabilities spelling"
    );
    assert_eq!(
        samples.len(),
        READINESS_OUTCOMES.len(),
        "every documented outcome must be rendered: {samples:?}"
    );
}

/// Extracts the serde tag of a rendered `CapabilityState`: a bare string
/// for unit outcomes, the object key for payload outcomes.
fn wire_tag(rendered: &str) -> &str {
    if let Some(rest) = rendered.strip_prefix("{\"") {
        rest.split('"').next().unwrap_or(rest)
    } else {
        rendered.trim_matches('"')
    }
}

#[test]
fn readiness_names_match_the_rpc_wire_spelling() {
    let states = [
        CapabilityState::Ready,
        CapabilityState::CatchingUp {
            processed_height: 1,
            target_height: 2,
        },
        CapabilityState::RollingBack {
            from_height: 2,
            to_height: 1,
        },
        CapabilityState::Rebuilding {
            processed_height: 1,
            target_height: 2,
        },
        CapabilityState::Failed {
            reason: "worker stopped".to_owned(),
        },
        CapabilityState::Disabled,
        CapabilityState::Opening,
        CapabilityState::ShutdownAbandoned,
    ];
    for state in &states {
        let rendered = serde_json::to_string(state)
            .unwrap_or_else(|error| panic!("serialize {state:?}: {error}"));
        let name = readiness_state_name(state);
        assert_eq!(
            wire_tag(&rendered),
            name,
            "gauge label and getcapabilities row must be one vocabulary"
        );
        assert!(
            READINESS_OUTCOMES.contains(&name),
            "every state must be a published outcome: {name}"
        );
    }
    let distinct: std::collections::BTreeSet<_> = states.iter().map(readiness_state_name).collect();
    assert_eq!(
        distinct.len(),
        states.len(),
        "distinct outcomes must keep distinct labels"
    );
}

#[test]
fn published_gauge_flips_its_active_label_with_the_rpc_source() {
    let _guard = SERVER_TEST_LOCK.lock();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = MetricsServer::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Arc::clone(&shutdown),
        &identity(),
    )
    .unwrap_or_else(|error| panic!("bind metrics: {error}"));

    publish_txindex_readiness(&FixedSource::enabled(CapabilityState::Ready));
    let samples = readiness_samples(&scrape(server.local_addr()));
    assert_one_active(&samples, "Ready");

    // A transition must retire the previous active label in the same pass:
    // a scrape after the move never reports two live outcomes.
    publish_txindex_readiness(&FixedSource::enabled(CapabilityState::Rebuilding {
        processed_height: 40,
        target_height: 101,
    }));
    let samples = readiness_samples(&scrape(server.local_addr()));
    assert_one_active(&samples, "Rebuilding");
    assert!(
        samples
            .iter()
            .all(|(state, value)| state != "Ready" || is_zero(*value)),
        "the retired Ready label must read 0 after the transition: {samples:?}"
    );

    // The disabled outcome is a distinct documented state, not the absence
    // of a row: the source reports enabled:false with its own label.
    publish_txindex_readiness(&FixedSource {
        enabled: false,
        state: CapabilityState::Disabled,
    });
    let samples = readiness_samples(&scrape(server.local_addr()));
    assert_one_active(&samples, "Disabled");

    server.join();
    shutdown.store(true, Ordering::Release);
}
