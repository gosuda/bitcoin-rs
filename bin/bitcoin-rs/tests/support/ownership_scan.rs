//! Static source scan used by `overhaul_ownership` to enforce single-owner
//! boundaries that `cargo metadata` cannot see.
//!
//! The scan walks the workspace Rust sources (excluding `tests/`, `benches/`,
//! and in-file test items) and fails if any production code outside
//! `crates/mempool/src/` directly calls a mutating `Mempool` method, or acquires
//! the pool write lock through a bypass pattern (`mempool().write(` on a raw
//! `Arc<RwLock<Mempool>>` or `.pool().write(` on a `MempoolGateway`).

use std::path::Path;

/// Audited cross-crate gateway mutation expressions.
///
/// The scanner has no Rust type information, so a generic local name such as
/// `gateway` or `mempool` cannot prove ownership. Every exception is therefore
/// tied to one source file and one complete receiver expression. Adding a new
/// production gateway mutation requires an explicit review of this list.
const AUTHORIZED_GATEWAY_CALLS: &[(&str, &str)] =
    &[("crates/rpc/src/handlers/mining.rs", "ctx.mempool")];

/// Mutating methods on `Mempool` that only the mempool owner may call from
/// production code. `MempoolGateway` deliberately reuses some of these names,
/// so a match is only permitted at an audited gateway expression above.
///
/// `clear` and `commit_insert` are intentionally omitted: `clear` is too common
/// across collection types and is caught by `.pool().write(`; `commit_insert` is
/// a `pub(crate)` helper that is only reachable through `insert_entry`.
pub(crate) const MUTATING_METHODS: &[&str] = &[
    // Adds a transaction to the in-memory pool.
    "insert_entry(",
    // Replaces an existing entry via the RBF path.
    "replace_transaction(",
    // Removes confirmed transactions after a block connect.
    "remove_for_block(",
    // Evicts low-fee packages to enforce a byte limit.
    "enforce_size_limit(",
    // Removes entries below a fee-rate threshold.
    "evict_below_fee_rate(",
    // Applies a fee delta to an in-pool transaction.
    "prioritise(",
    // Bulk removal helper used during reorg/replacement.
    "remove_entries_with_reasons(",
    // Recursive removal of an entry and all descendants.
    "remove_entry_and_descendants_into(",
    // Free-function package eviction; mutates the pool.
    "evict_lowest_fee_packages(",
];

/// Patterns that indicate a raw `Mempool` write lock acquisition outside the
/// mempool owner. `mempool().write(` covers `state.mempool()` (which returns
/// `Arc<RwLock<Mempool>>`); `.pool().write(` covers `MempoolGateway::pool()`.
pub(crate) const POOL_WRITE_PATTERNS: &[&str] = &[".mempool().write(", ".pool().write("];

/// Result of the source scan.
#[derive(Debug)]
pub(crate) struct WriterScanResult {
    /// Human-readable violations, one per call site.
    pub violations: Vec<String>,
    /// Number of production source files examined.
    pub files_scanned: usize,
    /// Number of raw pool write sites found.
    pub pool_writes_found: usize,
    /// Number of mutating method calls found (including gateway calls).
    pub mutating_calls_found: usize,
}

fn empty_result() -> WriterScanResult {
    WriterScanResult {
        violations: Vec::new(),
        files_scanned: 0,
        pool_writes_found: 0,
        mutating_calls_found: 0,
    }
}

/// Walks the workspace and returns any mempool-writer violations.
pub(crate) fn scan_mempool_writer_violations() -> WriterScanResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut result = empty_result();
    scan_dir(&root, &mut result);
    result
}

fn scan_dir(dir: &Path, result: &mut WriterScanResult) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "target" || name == "tests" || name == "benches" || name == "examples" {
                    continue;
                }
                scan_dir(&path, result);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                scan_file(&path, result);
            }
        }
    }
}

fn scan_file(path: &Path, result: &mut WriterScanResult) {
    let path_str = path.to_string_lossy();
    let content = std::fs::read_to_string(path).unwrap_or_default();
    scan_source(&path_str, &content, result);
    result.files_scanned += 1;
}

fn scan_source(path_str: &str, content: &str, result: &mut WriterScanResult) {
    let is_mempool_owner = path_str.replace('\\', "/").contains("/crates/mempool/src/");
    let lines: Vec<&str> = content.lines().collect();
    let mut skip_test_item = false;

    for (index, raw_line) in lines.iter().enumerate() {
        // Strip `//`, `///`, and `//!` line comments before any other inspection.
        let line = if let Some(pos) = raw_line.find("//") {
            &raw_line[..pos]
        } else {
            raw_line
        };
        let trimmed = line.trim();

        if skip_test_item {
            // Rustfmt places the closing brace of a top-level module/function
            // at column zero. Resume scanning after it so later production
            // items cannot hide behind an earlier test item.
            if line == "}" {
                skip_test_item = false;
            }
            continue;
        }

        // Skip a top-level inline `#[cfg(test)] mod ... { ... }`, but not a
        // semicolon module declaration; the next production item is scanned.
        if trimmed == "#[cfg(test)]" || trimmed.starts_with("#[cfg(test)] ") {
            for next in lines.iter().skip(index + 1) {
                let next_trimmed = next.trim();
                if next_trimmed.is_empty()
                    || next_trimmed.starts_with("//")
                    || next_trimmed.starts_with("#!")
                    || next_trimmed.starts_with("#[")
                {
                    continue;
                }
                if next_trimmed.starts_with("mod ") && !next_trimmed.ends_with(';') {
                    skip_test_item = true;
                }
                break;
            }
            if skip_test_item {
                continue;
            }
        } else if trimmed.starts_with("#[test]") {
            // A top-level test function is also skipped only through its own
            // rustfmt-aligned closing brace, never to end-of-file.
            for next in lines.iter().skip(index + 1) {
                let next_trimmed = next.trim();
                if next_trimmed.is_empty()
                    || next_trimmed.starts_with("//")
                    || next_trimmed.starts_with("#!")
                    || next_trimmed.starts_with("#[")
                {
                    continue;
                }
                if next_trimmed.starts_with("fn ") {
                    skip_test_item = true;
                }
                break;
            }
            if skip_test_item {
                continue;
            }
        }

        // Unconditional raw-pool-write patterns.
        for pattern in POOL_WRITE_PATTERNS {
            if line.contains(pattern) {
                result.pool_writes_found += 1;
                if !is_mempool_owner {
                    result.violations.push(format!(
                        "raw pool write `{pattern}` at {}:{}: {}",
                        path_str,
                        index + 1,
                        trimmed
                    ));
                }
            }
        }

        // Mutating method calls are permitted only at audited, qualified
        // gateway expressions. Receiver names alone are not ownership proof.
        for method in MUTATING_METHODS {
            if let Some(pos) = line.find(method) {
                result.mutating_calls_found += 1;
                if !is_mempool_owner
                    && !is_authorized_gateway_call(path_str, line, pos, &lines, index)
                {
                    result.violations.push(format!(
                        "raw mempool mutation `{method}` at {}:{}: {}",
                        path_str,
                        index + 1,
                        trimmed
                    ));
                }
            }
        }
    }
}

/// Returns true only when the call is on a receiver expression explicitly
/// audited in [`AUTHORIZED_GATEWAY_CALLS`].
///
/// A call may be split across lines (`ctx.mempool` then `.prioritise(...)`).
/// In that shape the previous non-empty line supplies the complete receiver.
fn is_authorized_gateway_call(
    path: &str,
    line: &str,
    method_pos: usize,
    lines: &[&str],
    line_index: usize,
) -> bool {
    // A `.write().method(` chain is a raw-pool-guard call; do not hide it as an
    // authorized gateway call (the `POOL_WRITE_PATTERNS` check will report it).
    if line[..method_pos].contains(".write(") {
        return false;
    }

    let before = &line[..method_pos];
    let receiver = match before.rfind('.') {
        Some(dot_pos) => before[..dot_pos].trim(),
        None => before.trim(),
    };
    let receiver = if receiver.is_empty() {
        lines[..line_index]
            .iter()
            .rev()
            .map(|previous| previous.trim())
            .find(|previous| !previous.is_empty() && !previous.starts_with("//"))
            .unwrap_or("")
    } else {
        receiver
    };

    let normalized_path = path.replace('\\', "/");
    AUTHORIZED_GATEWAY_CALLS.iter().any(|(allowed_path, allowed_receiver)| {
        normalized_path.ends_with(allowed_path) && receiver == *allowed_receiver
    })
}

#[cfg(test)]
mod tests {
    use super::{empty_result, is_authorized_gateway_call, scan_source};

    const MINING_HANDLER: &str = "/workspace/crates/rpc/src/handlers/mining.rs";
    const NON_OWNER: &str = "/workspace/crates/node/src/fake.rs";

    fn authorized(path: &str, source: &str) -> bool {
        let lines: Vec<&str> = source.lines().collect();
        let (line_index, line) = lines
            .iter()
            .enumerate()
            .find(|(_, line)| line.contains("prioritise("))
            .expect("fixture contains prioritise call");
        let method_pos = line.find("prioritise(").expect("method position");
        is_authorized_gateway_call(path, line, method_pos, &lines, line_index)
    }

    fn violations(source: &str) -> Vec<String> {
        let mut result = empty_result();
        scan_source(NON_OWNER, source, &mut result);
        result.violations
    }

    #[test]
    fn only_the_audited_qualified_gateway_receiver_is_authorized() {
        assert!(authorized(
            MINING_HANDLER,
            "ctx.mempool\n    .prioritise(txid, fee_delta)"
        ));
        assert!(authorized(
            MINING_HANDLER,
            "ctx.mempool.prioritise(txid, fee_delta)"
        ));

        for source in [
            "gateway.prioritise(txid, fee_delta)",
            "mempool.prioritise(txid, fee_delta)",
            "other.mempool.prioritise(txid, fee_delta)",
            "ctx.mempool_gateway.prioritise(txid, fee_delta)",
        ] {
            assert!(!authorized(MINING_HANDLER, source), "{source}");
        }
        assert!(!authorized(
            "/workspace/crates/node/src/apply.rs",
            "ctx.mempool\n    .prioritise(txid, fee_delta)"
        ));
    }

    #[test]
    fn a_raw_write_chain_is_never_authorized() {
        assert!(!authorized(
            MINING_HANDLER,
            "ctx.mempool.write().prioritise(txid, fee_delta)"
        ));
    }

    #[test]
    fn production_after_an_inline_test_module_is_still_scanned() {
        let source = r#"
#[cfg(test)]
mod tests {
    #[test]
    fn fixture() {
        gateway.prioritise(txid, 1);
    }
}

pub fn production() {
    gateway.prioritise(txid, 2);
}
"#;
        let found = violations(source);
        assert_eq!(found.len(), 1, "test mutation is skipped, production is not");
        assert!(found[0].contains("gateway.prioritise(txid, 2)"));
    }

    #[test]
    fn production_after_a_top_level_test_function_is_still_scanned() {
        let source = r#"
#[test]
fn fixture() {
    mempool.prioritise(txid, 1);
}

pub fn production() {
    mempool.prioritise(txid, 2);
}
"#;
        let found = violations(source);
        assert_eq!(found.len(), 1, "test mutation is skipped, production is not");
        assert!(found[0].contains("mempool.prioritise(txid, 2)"));
    }

    #[test]
    fn external_test_module_declaration_does_not_hide_following_production() {
        let source = r#"
#[cfg(test)]
mod tests;

pub fn production() {
    gateway.prioritise(txid, 3);
}
"#;
        let found = violations(source);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("gateway.prioritise(txid, 3)"));
    }
}
