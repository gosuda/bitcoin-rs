//! G1 — Headers-only sync parity.
//! **G1 — Headers-only sync parity.** Externally collected bitcoin-rs mainnet active-header-chain hashes match `bitcoind`'s `getblockhash` for every height `0..=tip`.
//!
//! This ignored gate does not run live mainnet header sync itself. It verifies
//! externally collected bitcoin-rs and Bitcoin Core header hash evidence, binds
//! it to the current clean git `HEAD`, and fails closed when that evidence
//! contract is missing, malformed, incomplete, or mismatched.

use std::{collections::BTreeMap, env, fs, process::Command};

const EVIDENCE_HELP: &str = "required G1 evidence env: \
G1_COMMIT_SHA=<current git HEAD as 40 lowercase hex>, \
G1_MEASUREMENT_TARGET=mainnet-headers, \
G1_REFERENCE_IMPL=bitcoind, \
G1_HASH_TYPE=blockhash, \
G1_TIP_HEIGHT=<declared mainnet header tip height>, \
G1_BITCOIN_RS_HEADER_HASHES=<height:64-lowerhex[,height:64-lowerhex...]> \
  or G1_BITCOIN_RS_HEADER_HASHES_FILE=<path>, \
G1_BITCOIND_BLOCK_HASHES=<height:64-lowerhex[,height:64-lowerhex...]> \
  or G1_BITCOIND_BLOCK_HASHES_FILE=<path>";

type Samples = BTreeMap<u32, String>;

struct G1Evidence {
    commit_sha: String,
    tip_height: u32,
    bitcoin_rs_samples: Samples,
    bitcoind_samples: Samples,
}

/// Gate G1 manual run instructions: run
/// `cargo test -p bitcoin-rs --test g01_headers_only_sync -- --ignored --nocapture`
/// with externally collected mainnet active-header-chain hashes from bitcoin-rs
/// and `bitcoin-cli getblockhash <height>` for every height `0..=tip`.
#[test]
#[ignore = "requires externally collected bitcoin-rs and bitcoind mainnet header evidence"]
fn headers_only_sync_parity() {
    let evidence = G1Evidence::from_env();
    evidence.assert_samples();
    evidence.report();
}

impl G1Evidence {
    fn from_env() -> Self {
        let commit_sha = required_commit_sha();
        require_literal("G1_MEASUREMENT_TARGET", "mainnet-headers");
        require_literal("G1_REFERENCE_IMPL", "bitcoind");
        require_literal("G1_HASH_TYPE", "blockhash");
        let tip_height = positive_u32("G1_TIP_HEIGHT");
        let bitcoin_rs_samples = samples_from_evidence(
            "G1_BITCOIN_RS_HEADER_HASHES",
            "G1_BITCOIN_RS_HEADER_HASHES_FILE",
        );
        let bitcoind_samples =
            samples_from_evidence("G1_BITCOIND_BLOCK_HASHES", "G1_BITCOIND_BLOCK_HASHES_FILE");
        Self {
            commit_sha,
            tip_height,
            bitcoin_rs_samples,
            bitcoind_samples,
        }
    }

    fn assert_samples(&self) {
        assert_complete_heights("G1 bitcoin-rs", &self.bitcoin_rs_samples, self.tip_height);
        assert_complete_heights("G1 bitcoind", &self.bitcoind_samples, self.tip_height);
        assert_eq!(
            self.bitcoin_rs_samples, self.bitcoind_samples,
            "G1 header parity failed: bitcoin-rs active-header-chain hashes differ from bitcoind getblockhash results",
        );
    }

    fn report(&self) {
        let commit_sha = &self.commit_sha;
        let tip_height = self.tip_height;
        let sample_count = self.bitcoin_rs_samples.len();
        println!("G1 header evidence accepted for current git HEAD {commit_sha}");
        println!("tip_height={tip_height}");
        println!("sample_count={sample_count}");
    }
}

fn assert_complete_heights(label: &str, samples: &Samples, tip_height: u32) {
    for height in 0..=tip_height {
        assert!(
            samples.contains_key(&height),
            "{label} samples missing height {height}; expected every height 0..={tip_height}",
        );
    }
    assert_eq!(
        samples.len(),
        usize::try_from(tip_height)
            .ok()
            .and_then(|height| height.checked_add(1))
            .unwrap_or(usize::MAX),
        "{label} samples must contain exactly every height 0..={tip_height}",
    );
}

fn samples_from_evidence(env_name: &str, file_env_name: &str) -> Samples {
    let raw = evidence_string(env_name, file_env_name);
    let mut samples = Samples::new();
    for entry in raw.split(|ch: char| ch == ',' || ch.is_whitespace()) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((height_raw, hash_raw)) = entry.split_once(':') else {
            panic!(
                "{env_name} sample {entry:?} must use height:64-lowerhex format; {EVIDENCE_HELP}"
            );
        };
        let height = parse_u32(env_name, height_raw);
        let hash = hash_raw.trim();
        assert!(
            is_lower_hex_hash(hash),
            "{env_name} sample at height {height} must be a 64-character lowercase hex block hash, got {hash:?}",
        );
        assert!(
            samples.insert(height, hash.to_owned()).is_none(),
            "{env_name} contains duplicate height {height}",
        );
    }
    assert!(
        !samples.is_empty(),
        "{env_name} must contain at least one sample; {EVIDENCE_HELP}",
    );
    samples
}

fn evidence_string(env_name: &str, file_env_name: &str) -> String {
    match env::var(env_name) {
        Ok(value) if !value.trim().is_empty() => return value,
        Ok(_) => panic!("{env_name} must not be empty; {EVIDENCE_HELP}"),
        Err(env::VarError::NotUnicode(_)) => {
            panic!("{env_name} must be valid UTF-8; {EVIDENCE_HELP}")
        }
        Err(env::VarError::NotPresent) => {}
    }

    let path = match env::var(file_env_name) {
        Ok(value) if !value.trim().is_empty() => value,
        Ok(_) => panic!("{file_env_name} must not be empty; {EVIDENCE_HELP}"),
        Err(env::VarError::NotPresent) => {
            panic!("missing {env_name} or {file_env_name}; {EVIDENCE_HELP}")
        }
        Err(env::VarError::NotUnicode(_)) => {
            panic!("{file_env_name} must be valid UTF-8; {EVIDENCE_HELP}")
        }
    };
    match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) => panic!("failed to read {file_env_name} path {path:?}: {error}"),
    }
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
    let value = required_env("G1_COMMIT_SHA");
    assert!(
        is_lower_hex_sha(&value),
        "G1_COMMIT_SHA must be a 40-character lowercase hex commit sha, got {value:?}",
    );
    let current_head = current_git_head();
    assert_eq!(
        value, current_head,
        "G1_COMMIT_SHA must match current git HEAD; evidence {value}, current HEAD {current_head}",
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
        Err(error) => panic!("failed to run git rev-parse for G1_COMMIT_SHA binding: {error}"),
    };
    assert!(
        output.status.success(),
        "git rev-parse HEAD failed while validating G1_COMMIT_SHA: {}",
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
        Err(error) => panic!("failed to run git status for G1 evidence binding: {error}"),
    };
    assert!(
        output.status.success(),
        "git status failed while validating G1 evidence binding: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    let status = match String::from_utf8(output.stdout) {
        Ok(status) => status,
        Err(error) => panic!("git status did not return UTF-8: {error}"),
    };
    assert!(
        status.trim().is_empty(),
        "G1 evidence requires a clean tracked git tree for current HEAD; dirty entries:\n{status}",
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
        "{name} must be {expected:?} for G1 evidence, got {value:?}",
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
