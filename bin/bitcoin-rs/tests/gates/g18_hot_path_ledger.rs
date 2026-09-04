//! G18 — Product hot-path attribution ledger.
//!
//! Contract: `docs/contracts/hot-path-attribution.md`.
//! Inventory owner: `docs/benchmarks/hot-path-ledger.toml`.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

const SCHEMA: &str = "bitcoin-rs-hot-path-ledger-v1";
const CONTRACT: &str = "docs/contracts/hot-path-attribution.md";
const LEDGER: &str = "docs/benchmarks/hot-path-ledger.toml";
const CELL_COUNT: usize = 36;

const KINDS: [&str; 4] = ["interval", "stage", "class", "memory"];
const DISPOSITIONS: [&str; 4] = ["optimize", "already_bounded", "blocked", "rejected"];
const TIMED_REGIONS: [&str; 3] = ["inside", "outside", "domain-defined"];

/// Metaphorics inventory from issue #39. The TOML may add rows; it may not drop these.
const REQUIRED_PATHS: [&str; 41] = [
    "cell.wall",
    "apply.header_accept",
    "apply.block_decode",
    "apply.window_overlay",
    "apply.merkle_witness",
    "apply.script_verify",
    "apply.contextual_checks",
    "apply.utxo_commit",
    "apply.undo_persist",
    "apply.body_persist",
    "apply.optional_index",
    "apply.tip_publish",
    "apply.checkpoint",
    "apply.shutdown_reopen",
    "offline.startup_open",
    "offline.corpus_read",
    "p2p.socket_io",
    "p2p.wire",
    "p2p.channels",
    "p2p.header_sync",
    "p2p.request_schedule",
    "p2p.stage",
    "p2p.staller",
    "p2p.event_loop",
    "p2p.shutdown_reopen",
    "muhash.tcp_http",
    "muhash.json_dispatch",
    "muhash.stable_view",
    "muhash.shard_scan",
    "muhash.preimage",
    "muhash.element_expand",
    "muhash.modmul",
    "muhash.response",
    "class.alloc",
    "class.lock_sched",
    "class.io_syscall",
    "class.backend",
    "class.microarch",
    "class.retained_memory",
    "memory.utxo_set",
    "memory.rss_residual",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workspace_file(relative: &str) -> PathBuf {
    workspace_root().join(relative)
}

#[derive(Debug, Deserialize)]
struct Ledger {
    schema: String,
    contract: String,
    matrix: Matrix,
    cell_defaults: CellDefaults,
    paths: Vec<PathRow>,
    candidates: Vec<Candidate>,
    levers: Vec<Lever>,
    forbidden_probes: Vec<ForbiddenProbe>,
}

#[derive(Debug, Deserialize)]
struct Matrix {
    domains: Vec<String>,
    corpora: Vec<String>,
    archs: Vec<String>,
    backends: Vec<String>,
}

impl Matrix {
    fn cell_count(&self) -> usize {
        self.domains
            .len()
            .saturating_mul(self.corpora.len())
            .saturating_mul(self.archs.len())
            .saturating_mul(self.backends.len())
    }
}

#[derive(Debug, Deserialize)]
struct CellDefaults {
    custody: String,
    residual: String,
    residual_blocker: String,
    noise_floor: String,
}

#[derive(Debug, Deserialize)]
struct PathRow {
    id: String,
    kind: String,
    name: String,
    parent: String,
    concurrency_group: String,
    domains: Vec<String>,
    #[serde(default)]
    corpora: Vec<String>,
    #[serde(default)]
    archs: Vec<String>,
    #[serde(default)]
    backends: Vec<String>,
    #[serde(default)]
    seams: Vec<String>,
    #[serde(default)]
    histogram: Option<String>,
    #[serde(default)]
    timed_region: Option<String>,
    #[serde(default)]
    custody: Option<String>,
    #[serde(default)]
    wall_contribution: Option<String>,
    #[serde(default)]
    disable_delta: Option<String>,
    disposition: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct Candidate {
    rank: u32,
    path: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct Lever {
    id: String,
    path: String,
    disposition: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct ForbiddenProbe {
    id: String,
    name: String,
    reason: String,
}

fn load_ledger() -> Ledger {
    let path = workspace_file(LEDGER);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("read {}: {error}", path.display());
    });
    toml::from_str(&text).unwrap_or_else(|error| {
        panic!("parse {LEDGER}: {error}");
    })
}

fn known(value: &str, allowed: &[&str]) -> bool {
    allowed.contains(&value)
}

#[test]
fn ledger_schema_and_contract_are_current() {
    let ledger = load_ledger();
    assert_eq!(ledger.schema, SCHEMA);
    assert_eq!(ledger.contract, CONTRACT);
    assert!(
        workspace_file(&ledger.contract).is_file(),
        "contract {} is missing",
        ledger.contract
    );
}

#[test]
fn matrix_is_the_frozen_36_cell_denominator() {
    let ledger = load_ledger();
    assert_eq!(
        ledger.matrix.cell_count(),
        CELL_COUNT,
        "HPA-01 freezes 3×2×2×3 = 36 cells"
    );
    assert_eq!(ledger.matrix.domains, ["offline", "p2p", "muhash"]);
    assert_eq!(ledger.matrix.corpora, ["c150", "cmodern"]);
    assert_eq!(ledger.matrix.archs, ["x86_64", "arm64"]);
    assert_eq!(ledger.matrix.backends, ["fjall", "rocksdb", "redb"]);
}

#[test]
fn unmeasured_cells_cannot_claim_a_noise_floor() {
    let ledger = load_ledger();
    assert_eq!(ledger.cell_defaults.custody, "none");
    assert_eq!(ledger.cell_defaults.residual, "unmeasured");
    assert_eq!(ledger.cell_defaults.noise_floor, "unobserved");
    assert!(
        !ledger.cell_defaults.residual_blocker.is_empty(),
        "unmeasured residual must name a blocker"
    );
    assert_ne!(ledger.cell_defaults.residual, "other");
}

#[test]
fn required_inventory_is_present() {
    let ledger = load_ledger();
    let ids: BTreeSet<&str> = ledger.paths.iter().map(|row| row.id.as_str()).collect();
    for required in REQUIRED_PATHS {
        assert!(
            ids.contains(required),
            "ledger dropped required path `{required}`"
        );
    }
}

#[test]
fn path_rows_are_well_formed() {
    let ledger = load_ledger();
    let ids: BTreeSet<String> = ledger.paths.iter().map(|row| row.id.clone()).collect();
    assert_eq!(ids.len(), ledger.paths.len(), "duplicate path id");

    for row in &ledger.paths {
        assert!(!row.id.is_empty(), "empty path id");
        assert!(!row.name.is_empty(), "`{}` needs a name", row.id);
        assert!(
            !row.concurrency_group.is_empty(),
            "`{}` needs a group",
            row.id
        );
        assert!(!row.evidence.is_empty(), "`{}` needs evidence", row.id);
        assert!(
            known(&row.kind, &KINDS),
            "`{}` has unknown kind `{}`",
            row.id,
            row.kind
        );
        assert!(
            known(&row.disposition, &DISPOSITIONS),
            "`{}` has unknown disposition `{}`",
            row.id,
            row.disposition
        );
        assert_ne!(row.disposition, "other");
        assert!(!row.domains.is_empty(), "`{}` names no domain", row.id);
        for domain in &row.domains {
            assert!(
                ledger.matrix.domains.iter().any(|item| item == domain),
                "`{}` names unknown domain `{domain}`",
                row.id
            );
        }
        if row.id == "cell.wall" {
            assert!(row.parent.is_empty(), "cell.wall is the root");
        } else {
            assert!(
                ids.contains(&row.parent),
                "`{}` parent `{}` is missing",
                row.id,
                row.parent
            );
            assert_ne!(row.id, row.parent, "`{}` is its own parent", row.id);
        }
        let timed = row.timed_region.as_deref().unwrap_or("inside");
        assert!(
            known(timed, &TIMED_REGIONS),
            "`{}` has unknown timed_region `{timed}`",
            row.id
        );
        let custody = row.custody.as_deref().unwrap_or("none");
        let wall = row.wall_contribution.as_deref().unwrap_or("unmeasured");
        if wall != "unmeasured" {
            assert_ne!(
                custody, "none",
                "`{}` records wall contribution without custody",
                row.id
            );
        }
        assert_ne!(wall, "other");
    }
}

#[test]
fn seams_exist_in_this_tree() {
    let ledger = load_ledger();
    for row in &ledger.paths {
        for seam in &row.seams {
            assert!(
                workspace_file(seam).is_file(),
                "`{}` seam `{seam}` is not a file in this tree",
                row.id
            );
        }
    }
}

#[test]
fn histograms_are_diagnostics_not_custody() {
    let ledger = load_ledger();
    for row in &ledger.paths {
        if row.histogram.is_some() {
            let wall = row.wall_contribution.as_deref().unwrap_or("unmeasured");
            assert_eq!(
                wall, "unmeasured",
                "`{}` treats a nested histogram as wall contribution",
                row.id
            );
        }
    }
}

#[test]
fn candidate_list_is_ordered_and_points_at_paths() {
    let ledger = load_ledger();
    let ids: BTreeSet<&str> = ledger.paths.iter().map(|row| row.id.as_str()).collect();
    let forbidden: BTreeSet<&str> = ledger
        .forbidden_probes
        .iter()
        .map(|probe| probe.id.as_str())
        .collect();
    assert!(!ledger.candidates.is_empty(), "candidate list is empty");
    for (index, candidate) in ledger.candidates.iter().enumerate() {
        let expected = u32::try_from(index + 1).expect("rank fits u32");
        assert_eq!(candidate.rank, expected, "candidate ranks must be 1..=n");
        assert!(
            ids.contains(candidate.path.as_str()),
            "candidate `{}` is not a ledger path",
            candidate.path
        );
        assert!(
            !forbidden.contains(candidate.path.as_str()),
            "candidate `{}` is a forbidden probe",
            candidate.path
        );
        assert!(!candidate.reason.is_empty());
    }
}

#[test]
fn levers_and_forbidden_probes_are_complete() {
    let ledger = load_ledger();
    let ids: BTreeSet<&str> = ledger.paths.iter().map(|row| row.id.as_str()).collect();
    let mut lever_ids = BTreeSet::new();
    for lever in &ledger.levers {
        assert!(lever_ids.insert(lever.id.as_str()), "duplicate lever id");
        assert!(
            ids.contains(lever.path.as_str()),
            "lever `{}` path `{}` is missing",
            lever.id,
            lever.path
        );
        assert!(
            known(&lever.disposition, &DISPOSITIONS),
            "lever `{}` has unknown disposition",
            lever.id
        );
        assert!(!lever.evidence.is_empty());
    }
    assert!(
        lever_ids.contains("lever.utxo_arena"),
        "arena rejection must stay recorded"
    );
    assert!(
        lever_ids.contains("lever.decoded_block_cache"),
        "decoded-block cache rejection must stay recorded"
    );
    assert!(
        lever_ids.contains("lever.phantom_dbcache"),
        "phantom dbcache rejection must stay recorded"
    );

    let mut probe_ids = BTreeSet::new();
    for probe in &ledger.forbidden_probes {
        assert!(probe_ids.insert(probe.id.as_str()), "duplicate probe id");
        assert!(probe.id.starts_with("probe."));
        assert!(!probe.name.is_empty());
        assert!(!probe.reason.is_empty());
    }
    for required in [
        "probe.assume_valid",
        "probe.skip_merkle_witness",
        "probe.dummy_utxo",
        "probe.suppress_undo_body",
        "probe.weaken_durability",
        "probe.drop_stable_view",
        "probe.constant_muhash",
        "probe.skip_checkpoint",
    ] {
        assert!(
            probe_ids.contains(required),
            "forbidden probe `{required}` missing"
        );
    }

    for candidate in &ledger.candidates {
        assert!(
            !probe_ids.contains(candidate.path.as_str()),
            "candidate {} is a forbidden probe",
            candidate.path
        );
    }
    for lever in &ledger.levers {
        assert!(
            !probe_ids.contains(lever.id.as_str()),
            "lever {} is a forbidden probe",
            lever.id
        );
        if lever.disposition == "optimize" {
            assert!(
                !probe_ids.contains(lever.path.as_str()),
                "optimize lever {} points at a forbidden probe",
                lever.id
            );
        }
    }
}

#[test]
fn shared_versus_specific_paths_are_derived_from_applicability() {
    let ledger = load_ledger();
    let mut shared = 0_usize;
    let mut specific = 0_usize;
    for row in &ledger.paths {
        if row.kind == "interval" {
            continue;
        }
        let domain_specific = row.domains.len() != ledger.matrix.domains.len();
        let corpus_specific =
            !row.corpora.is_empty() && row.corpora.len() != ledger.matrix.corpora.len();
        let arch_specific = !row.archs.is_empty() && row.archs.len() != ledger.matrix.archs.len();
        let backend_specific =
            !row.backends.is_empty() && row.backends.len() != ledger.matrix.backends.len();
        if domain_specific || corpus_specific || arch_specific || backend_specific {
            specific += 1;
        } else {
            shared += 1;
        }
    }
    assert!(shared > 0, "no shared hot paths");
    assert!(specific > 0, "no domain- or axis-specific hot paths");
}

#[test]
fn every_domain_has_exclusive_leaves() {
    let ledger = load_ledger();
    let mut leaves: BTreeMap<&str, usize> = BTreeMap::new();
    for domain in &ledger.matrix.domains {
        leaves.insert(domain.as_str(), 0);
    }
    for row in &ledger.paths {
        if row.kind != "stage" {
            continue;
        }
        for domain in &row.domains {
            if let Some(count) = leaves.get_mut(domain.as_str()) {
                *count += 1;
            }
        }
    }
    for (domain, count) in leaves {
        assert!(count > 0, "domain `{domain}` has no exclusive stage rows");
    }
}

#[test]
fn no_path_hides_cost_in_other() {
    let ledger = load_ledger();
    for row in &ledger.paths {
        let blob = format!(
            "{} {} {} {}",
            row.id,
            row.disposition,
            row.wall_contribution.as_deref().unwrap_or(""),
            row.disable_delta.as_deref().unwrap_or("")
        );
        assert!(
            !blob.split_whitespace().any(|word| word == "other"),
            "`{}` uses forbidden residual name `other`",
            row.id
        );
    }
}

/// Overlap-aware accounting (HPA-04). Nested inclusive histograms are not addends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountError {
    NestedInclusiveSum,
    ExclusiveExceedsWall,
}

fn nested_inclusive_sum(_parent_ns: u64, _child_ns: u64) -> Result<u64, AccountError> {
    Err(AccountError::NestedInclusiveSum)
}

fn parallel_elapsed(worker_ns: &[u64]) -> u64 {
    worker_ns.iter().copied().max().unwrap_or(0)
}

fn residual_ns(wall_ns: u64, exclusive_union_ns: u64) -> Result<u64, AccountError> {
    wall_ns
        .checked_sub(exclusive_union_ns)
        .ok_or(AccountError::ExclusiveExceedsWall)
}

#[test]
fn nested_inclusive_histograms_cannot_be_added() {
    const APPLY_WINDOW_NS: u64 = 10_000;
    const PROVE_WINDOW_NS: u64 = 7_000;
    const SCRIPT_NS: u64 = 4_000;
    assert_eq!(
        nested_inclusive_sum(APPLY_WINDOW_NS, PROVE_WINDOW_NS),
        Err(AccountError::NestedInclusiveSum)
    );
    assert_eq!(
        nested_inclusive_sum(PROVE_WINDOW_NS, SCRIPT_NS),
        Err(AccountError::NestedInclusiveSum)
    );
}

#[test]
fn parallel_script_workers_contribute_span_not_sum() {
    let workers = [4_000_u64, 3_800, 3_900];
    let span = parallel_elapsed(&workers);
    let summed: u64 = workers.iter().sum();
    assert_eq!(span, 4_000);
    assert!(summed > span);
}

#[test]
fn residual_is_wall_minus_exclusive_union() {
    assert_eq!(residual_ns(10_000, 8_500), Ok(1_500));
    assert_eq!(
        residual_ns(10_000, 10_001),
        Err(AccountError::ExclusiveExceedsWall)
    );
}

#[test]
fn apply_idle_and_download_blocked_share_an_overlap_group() {
    let ledger = load_ledger();
    let idle = ledger
        .paths
        .iter()
        .find(|row| row.id == "p2p.apply_idle")
        .expect("p2p.apply_idle");
    let blocked = ledger
        .paths
        .iter()
        .find(|row| row.id == "p2p.download_blocked_by_apply")
        .expect("p2p.download_blocked_by_apply");
    assert_eq!(idle.concurrency_group, blocked.concurrency_group);
    assert_eq!(idle.concurrency_group, "p2p-overlap");
}

#[test]
fn script_pool_is_not_the_serial_apply_group() {
    let ledger = load_ledger();
    let script = ledger
        .paths
        .iter()
        .find(|row| row.id == "apply.script_verify")
        .expect("apply.script_verify");
    let overlay = ledger
        .paths
        .iter()
        .find(|row| row.id == "apply.window_overlay")
        .expect("apply.window_overlay");
    assert_eq!(script.concurrency_group, "script-pool");
    assert_eq!(overlay.concurrency_group, "apply-serial");
    assert_ne!(script.concurrency_group, overlay.concurrency_group);
}
