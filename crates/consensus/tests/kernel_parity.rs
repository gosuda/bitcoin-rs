//! Kernel smoke tests; ignored locally and executed by the kernel CI job.

#[cfg(feature = "kernel")]
#[test]
#[ignore = "kernel parity requires libboost-dev and the kernel CI job"]
fn kernel_context_builds_for_mainnet() {
    bitcoin_rs_consensus::kernel::KernelContext::new(bitcoin::Network::Bitcoin)
        .unwrap_or_else(|error| panic!("kernel context should build: {error}"));
}

#[cfg(feature = "kernel")]
#[test]
#[ignore = "kernel parity requires libboost-dev and the kernel CI job"]
fn kernel_parity_fixture_set_is_available() {
    let text = match std::fs::read_to_string("tests/vectors/tx_valid.json") {
        Ok(text) => text,
        Err(error) => panic!("tx_valid.json should be readable: {error}"),
    };
    let root: serde_json::Value = match serde_json::from_str(&text) {
        Ok(root) => root,
        Err(error) => panic!("tx_valid.json should parse: {error}"),
    };
    assert!(root.as_array().is_some_and(|rows| rows.len() > 1));
}

#[cfg(not(feature = "kernel"))]
#[test]
#[ignore = "kernel feature is off in portable verification"]
const fn kernel_parity_skipped_without_kernel_feature() {}
