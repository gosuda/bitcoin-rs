//! G2 — Full IBD UTXO root parity (muhash).
//! **G2 — Full IBD UTXO root parity.** Every 10 000 blocks during IBD, our running coinstats hash matches Bitcoin Core's `gettxoutsetinfo` muhash field byte-for-byte.
//!
//! This ignored gate does not run live mainnet IBD itself. It verifies
//! externally collected Bitcoin Core and bitcoin-rs `MuHash` samples and fails
//! closed when the evidence contract is missing, malformed, incomplete, stale,
//! or mismatched.

use std::{collections::BTreeMap, env, process::Command};

const SAMPLE_INTERVAL: u32 = 10_000;

const EVIDENCE_HELP: &str = "required G2 evidence env: \
G2_COMMIT_SHA=<current git HEAD as 40 lowercase hex>, \
G2_MEASUREMENT_TARGET=mainnet-ibd, \
G2_REFERENCE_IMPL=bitcoind, \
G2_HASH_TYPE=muhash, \
G2_SAMPLE_INTERVAL=10000, \
G2_TIP_HEIGHT=<mainnet tip height>, \
G2_BITCOIN_RS_MUHASH_SAMPLES=<height:64-lowerhex[,height:64-lowerhex...]>, \
G2_BITCOIND_MUHASH_SAMPLES=<height:64-lowerhex[,height:64-lowerhex...]>";

type Samples = BTreeMap<u32, String>;

struct G2Evidence {
    commit_sha: String,
    tip_height: u32,
    bitcoin_rs_samples: Samples,
    bitcoind_samples: Samples,
}

/// Gate G2 manual run instructions: run
/// `cargo test -p bitcoin-rs --test g02_ibd_muhash_parity -- --ignored --nocapture`
/// with externally collected mainnet IBD `MuHash` samples from bitcoin-rs and
/// `bitcoin-cli gettxoutsetinfo "muhash"` at height 0, every 10 000 blocks,
/// and the IBD tip height.
#[test]
#[ignore = "requires externally collected full IBD + bitcoind gettxoutsetinfo evidence"]
fn full_ibd_utxo_root_parity_muhash() {
    let evidence = G2Evidence::from_env();
    evidence.assert_samples();
    evidence.report();
}

impl G2Evidence {
    fn from_env() -> Self {
        let commit_sha = required_commit_sha();
        require_literal("G2_MEASUREMENT_TARGET", "mainnet-ibd");
        require_literal("G2_REFERENCE_IMPL", "bitcoind");
        require_literal("G2_HASH_TYPE", "muhash");
        require_exact_u32("G2_SAMPLE_INTERVAL", SAMPLE_INTERVAL);
        let tip_height = positive_u32("G2_TIP_HEIGHT");
        let bitcoin_rs_samples = samples_from_env("G2_BITCOIN_RS_MUHASH_SAMPLES");
        let bitcoind_samples = samples_from_env("G2_BITCOIND_MUHASH_SAMPLES");
        Self {
            commit_sha,
            tip_height,
            bitcoin_rs_samples,
            bitcoind_samples,
        }
    }

    fn assert_samples(&self) {
        let expected_heights = expected_sample_heights(self.tip_height);
        assert_eq!(
            sample_heights(&self.bitcoin_rs_samples),
            expected_heights,
            "G2 bitcoin-rs samples must cover height 0, every {SAMPLE_INTERVAL} blocks, and tip height {}",
            self.tip_height,
        );
        assert_eq!(
            sample_heights(&self.bitcoind_samples),
            expected_heights,
            "G2 bitcoind samples must cover height 0, every {SAMPLE_INTERVAL} blocks, and tip height {}",
            self.tip_height,
        );
        assert_eq!(
            self.bitcoin_rs_samples, self.bitcoind_samples,
            "G2 MuHash parity failed: bitcoin-rs samples differ from bitcoind samples",
        );
    }

    fn report(&self) {
        let commit_sha = &self.commit_sha;
        let tip_height = self.tip_height;
        let sample_count = self.bitcoin_rs_samples.len();
        println!("G2 MuHash evidence accepted for current git HEAD {commit_sha}");
        println!("tip_height={tip_height}");
        println!("sample_interval={SAMPLE_INTERVAL}");
        println!("sample_count={sample_count}");
    }
}

fn expected_sample_heights(tip_height: u32) -> Vec<u32> {
    let mut heights = Vec::new();
    let mut height = 0_u32;
    loop {
        heights.push(height);
        let Some(next) = height.checked_add(SAMPLE_INTERVAL) else {
            break;
        };
        if next > tip_height {
            break;
        }
        height = next;
    }
    if heights.last().copied() != Some(tip_height) {
        heights.push(tip_height);
    }
    heights
}

fn sample_heights(samples: &Samples) -> Vec<u32> {
    samples.keys().copied().collect()
}

fn samples_from_env(name: &str) -> Samples {
    let raw = required_env(name);
    let mut samples = Samples::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        assert!(
            !entry.is_empty(),
            "{name} contains an empty sample; {EVIDENCE_HELP}"
        );
        let Some((height_raw, hash_raw)) = entry.split_once(':') else {
            panic!("{name} sample {entry:?} must use height:64-lowerhex format; {EVIDENCE_HELP}");
        };
        let height = parse_u32(name, height_raw);
        let hash = hash_raw.trim();
        assert!(
            is_lower_hex_hash(hash),
            "{name} sample at height {height} must be a 64-character lowercase hex MuHash digest, got {hash:?}",
        );
        assert!(
            samples.insert(height, hash.to_owned()).is_none(),
            "{name} contains duplicate height {height}",
        );
    }
    assert!(
        !samples.is_empty(),
        "{name} must contain at least one sample; {EVIDENCE_HELP}"
    );
    samples
}

fn required_env(name: &str) -> String {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) => panic!("{name} must not be empty; {EVIDENCE_HELP}"),
        Err(env::VarError::NotPresent) => panic!("missing {name}; {EVIDENCE_HELP}"),
        Err(env::VarError::NotUnicode(_)) => panic!("{name} must be valid UTF-8; {EVIDENCE_HELP}"),
    }
}

fn required_commit_sha() -> String {
    let value = required_env("G2_COMMIT_SHA");
    assert!(
        is_lower_hex_sha(&value),
        "G2_COMMIT_SHA must be a 40-character lowercase hex commit sha, got {value:?}",
    );
    let current_head = current_git_head();
    assert_eq!(
        value, current_head,
        "G2_COMMIT_SHA must match current git HEAD; evidence {value}, current HEAD {current_head}",
    );
    assert_clean_tracked_tree();
    value
}

fn current_git_head() -> String {
    let output = match Command::new("git")
        .args([
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            "rev-parse",
            "--verify",
            "HEAD",
        ])
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run git rev-parse for G2_COMMIT_SHA binding: {error}"),
    };
    assert!(
        output.status.success(),
        "git rev-parse HEAD failed while validating G2_COMMIT_SHA: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout,
        Err(error) => panic!("git rev-parse HEAD did not return UTF-8: {error}"),
    };
    let head = stdout.trim().to_owned();
    assert!(
        is_lower_hex_sha(&head),
        "git rev-parse HEAD returned invalid sha {head:?}",
    );
    head
}

fn assert_clean_tracked_tree() {
    let repo_root = current_git_root();
    let output = match Command::new("git")
        .args([
            "-C",
            repo_root.as_str(),
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
        ])
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run git status for G2 evidence binding: {error}"),
    };
    assert!(
        output.status.success(),
        "git status failed while validating G2 evidence binding: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let status = match String::from_utf8(output.stdout) {
        Ok(status) => status,
        Err(error) => panic!("git status did not return UTF-8: {error}"),
    };
    assert!(
        status.trim().is_empty(),
        "G2 evidence requires a clean tracked git tree for current HEAD; dirty entries:\n{status}",
    );
}

fn current_git_root() -> String {
    let output = match Command::new("git")
        .args([
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            "rev-parse",
            "--show-toplevel",
        ])
        .output()
    {
        Ok(output) => output,
        Err(error) => panic!("failed to run git rev-parse --show-toplevel: {error}"),
    };
    assert!(
        output.status.success(),
        "git rev-parse --show-toplevel failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout.trim().to_owned(),
        Err(error) => panic!("git rev-parse --show-toplevel did not return UTF-8: {error}"),
    }
}

fn require_literal(name: &str, expected: &str) {
    let value = required_env(name);
    assert_eq!(
        value, expected,
        "{name} must be {expected:?} for G2 evidence, got {value:?}",
    );
}

fn require_exact_u32(name: &str, expected: u32) {
    let value = positive_u32(name);
    assert_eq!(
        value, expected,
        "{name} must be {expected} for G2 evidence, got {value}",
    );
}

fn positive_u32(name: &str) -> u32 {
    let raw = required_env(name);
    let value = parse_u32(name, &raw);
    assert_ne!(value, 0, "{name} must be positive");
    value
}

fn parse_u32(name: &str, raw: &str) -> u32 {
    match raw.trim().parse::<u32>() {
        Ok(value) => value,
        Err(error) => panic!("{name} must contain a u32 integer, got {raw:?}: {error}"),
    }
}

fn is_lower_hex_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
