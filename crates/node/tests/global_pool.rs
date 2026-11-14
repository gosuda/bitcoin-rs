//! The global rayon pool is configured once per process, so this test owns its binary.

use std::future::Future;
use std::num::NonZeroUsize;
use std::task::{Context, Poll, Waker};

use bitcoin_rs_node::{Network, Node, NodeConfig, RuntimeInputs};

fn run<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("node start unexpectedly parked"),
    }
}

// BUD-04
#[test]
#[expect(clippy::expect_used)]
fn node_start_caps_the_global_rayon_pool_at_four_threads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.p2p.connect.clear();
    config.rpc.bind.set_port(0);
    config.observability.metrics_bind = None;
    let _node = run(Node::start(config, RuntimeInputs::default())).expect("node starts");
    let available = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    assert!(
        rayon::current_num_threads() <= 4,
        "the global pool never exceeds four threads"
    );
    if available > 4 {
        assert_eq!(
            rayon::current_num_threads(),
            4,
            "hosts with more than four cores still pin the pool at four"
        );
    }
}
