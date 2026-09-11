//! Static source scan used by `overhaul_ownership` to enforce single-owner
//! boundaries that `cargo metadata` cannot see.
//!
//! The scan walks workspace Rust sources (excluding `tests/`, `benches/`, and
//! `examples/`) and ignores code inside top-level `#[cfg(test)]` items and
//! `#[test]` functions. A small Rust lexical mask keeps braces and mutator-like
//! text inside comments, quoted strings, raw strings, and character literals
//! from changing item boundaries or producing false matches. Production code
//! outside `crates/mempool/src/` fails the scan if it directly calls a mutating
//! `Mempool` method or acquires the pool write lock through a bypass pattern.

use std::path::Path;

/// Audited cross-crate gateway mutation expressions.
///
/// The scanner has no Rust type information, so a generic local name such as
/// `gateway` or `mempool` cannot prove ownership. Every exception is therefore
/// tied to one source file and one complete receiver expression. Adding a new
/// production gateway mutation requires an explicit review of this list.
const AUTHORIZED_GATEWAY_CALLS: &[(&str, &str)] = &[
    // Mining RPC prioritisation through the handler's gateway view.
    ("crates/rpc/src/handlers/mining.rs", "ctx.mempool"),
    // Block apply evicts the block's transactions through the generation
    // guarded gateway; this is the node's only production mutation site.
    (
        "crates/node/src/apply/connect.rs",
        "handles.mempool_gateway",
    ),
    // Reorg transaction reconsideration uses the same typed gateway owner.
    (
        "crates/node/src/reorg/execution.rs",
        "handles.mempool_gateway",
    ),
];

/// Mutating methods on `Mempool` that only the mempool owner may call from
/// production code. `MempoolGateway` deliberately reuses some of these names,
/// so a match is only permitted at an audited gateway expression above.
///
/// `clear` and `commit_insert` are intentionally omitted: `clear` is too common
/// across collection types and is caught by `.pool().write(`; `commit_insert` is
/// a `pub(crate)` helper that is only reachable through `insert_entry`.
pub(crate) const MUTATING_METHODS: &[&str] = &[
    "insert_entry(",
    "replace_transaction(",
    "remove_for_block(",
    "reconsider_disconnected(",
    "enforce_size_limit(",
    "evict_below_fee_rate(",
    "prioritise(",
    "remove_entries_with_reasons(",
    "remove_entry_and_descendants_into(",
    "evict_lowest_fee_packages(",
];

/// Patterns that indicate a raw `Mempool` write lock acquisition outside the
/// mempool owner. `mempool().write(` covers `state.mempool()`; `.pool().write(`
/// covers `MempoolGateway::pool()`.
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
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("");
                if matches!(name, "target" | "tests" | "benches" | "examples") {
                    continue;
                }
                scan_dir(&path, result);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
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

#[derive(Default)]
struct LexState {
    block_comment_depth: usize,
    quoted: Option<u8>,
    escaped: bool,
    raw_hashes: Option<usize>,
}

/// Masks non-code bytes with spaces while preserving byte positions.
///
/// This is deliberately narrower than a parser: the ownership gate needs only
/// identifiers, dots, parentheses, and structural braces. Keeping positions
/// stable lets method offsets continue to refer to the original source line.
fn code_line(raw: &str, state: &mut LexState) -> String {
    let bytes = raw.as_bytes();
    let mut masked = vec![b' '; bytes.len()];
    let mut at = 0;

    while at < bytes.len() {
        if let Some(hashes) = state.raw_hashes {
            if bytes[at] == b'"'
                && bytes
                    .get(at + 1..at + 1 + hashes)
                    .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
            {
                at += 1 + hashes;
                state.raw_hashes = None;
            } else {
                at += 1;
            }
            continue;
        }

        if let Some(quote) = state.quoted {
            let byte = bytes[at];
            if state.escaped {
                state.escaped = false;
            } else if byte == b'\\' {
                state.escaped = true;
            } else if byte == quote {
                state.quoted = None;
            }
            at += 1;
            continue;
        }

        if state.block_comment_depth > 0 {
            if bytes.get(at..at + 2) == Some(b"/*") {
                state.block_comment_depth += 1;
                at += 2;
            } else if bytes.get(at..at + 2) == Some(b"*/") {
                state.block_comment_depth -= 1;
                at += 2;
            } else {
                at += 1;
            }
            continue;
        }

        if bytes.get(at..at + 2) == Some(b"//") {
            break;
        }
        if bytes.get(at..at + 2) == Some(b"/*") {
            state.block_comment_depth = 1;
            at += 2;
            continue;
        }
        if let Some((prefix_len, hashes)) = raw_string_prefix(bytes, at) {
            state.raw_hashes = Some(hashes);
            at += prefix_len;
            continue;
        }
        if bytes[at] == b'"' {
            state.quoted = Some(b'"');
            at += 1;
            continue;
        }
        if bytes[at] == b'\'' {
            if let Some(length) = char_literal_len(bytes, at) {
                at += length;
                continue;
            }
        }

        masked[at] = bytes[at];
        at += 1;
    }

    // An odd trailing backslash inside an ordinary string escapes the physical
    // newline itself. `str::lines()` removes that newline, so consume the
    // continuation here while keeping the string open for the next line.
    if state.quoted.is_some() && state.escaped {
        state.escaped = false;
    }

    String::from_utf8(masked).expect("mask preserves UTF-8 outside literals")
}

fn raw_string_prefix(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut cursor = at;
    if bytes.get(cursor) == Some(&b'b') && bytes.get(cursor + 1) == Some(&b'r') {
        cursor += 2;
    } else if bytes.get(cursor) == Some(&b'r') {
        cursor += 1;
    } else {
        return None;
    }

    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    let hashes = cursor - hashes_start;
    Some((cursor - at + 1, hashes))
}

fn char_literal_len(bytes: &[u8], at: usize) -> Option<usize> {
    let first = *bytes.get(at + 1)?;
    let closing = if first == b'\\' {
        match bytes.get(at + 2).copied()? {
            b'x' => at.checked_add(5)?,
            b'u' if bytes.get(at + 3) == Some(&b'{') => {
                let end = bytes.get(at + 4..)?.iter().position(|byte| *byte == b'}')?;
                at.checked_add(5 + end)?
            }
            _ => at.checked_add(3)?,
        }
    } else {
        let tail = std::str::from_utf8(bytes.get(at + 1..)?).ok()?;
        let width = tail.chars().next()?.len_utf8();
        at.checked_add(1 + width)?
    };
    (bytes.get(closing) == Some(&b'\'')).then_some(closing - at + 1)
}

fn brace_delta(code: &str) -> (usize, usize) {
    let opens = code.bytes().filter(|byte| *byte == b'{').count();
    let closes = code.bytes().filter(|byte| *byte == b'}').count();
    (opens, closes)
}

fn is_test_attribute(trimmed: &str) -> bool {
    trimmed == "#[cfg(test)]"
        || trimmed.starts_with("#[cfg(test)] ")
        || trimmed == "#[test]"
        || trimmed.starts_with("#[test(")
}

fn scan_source(path_str: &str, content: &str, result: &mut WriterScanResult) {
    let is_mempool_owner = path_str.replace('\\', "/").contains("/crates/mempool/src/");
    let raw_lines: Vec<&str> = content.lines().collect();
    let mut lex = LexState::default();
    let code_lines: Vec<String> = raw_lines
        .iter()
        .map(|line| code_line(line, &mut lex))
        .collect();
    let mut pending_test_item = false;
    let mut test_depth = 0_i64;

    for (index, line) in code_lines.iter().enumerate() {
        let trimmed = line.trim();

        if test_depth > 0 {
            let (opens, closes) = brace_delta(line);
            test_depth += i64::try_from(opens).unwrap_or(i64::MAX);
            test_depth -= i64::try_from(closes).unwrap_or(i64::MAX);
            if test_depth <= 0 {
                test_depth = 0;
            }
            continue;
        }

        if pending_test_item {
            if trimmed.is_empty() || trimmed.starts_with("#[") {
                continue;
            }
            let (opens, closes) = brace_delta(line);
            if opens > 0 {
                test_depth = i64::try_from(opens).unwrap_or(i64::MAX)
                    - i64::try_from(closes).unwrap_or(i64::MAX);
                pending_test_item = false;
                if test_depth < 0 {
                    test_depth = 0;
                }
            } else if trimmed.ends_with(';') {
                pending_test_item = false;
            }
            continue;
        }

        if is_test_attribute(trimmed) {
            pending_test_item = true;
            continue;
        }

        for pattern in POOL_WRITE_PATTERNS {
            if line.contains(pattern) {
                result.pool_writes_found += 1;
                if !is_mempool_owner {
                    result.violations.push(format!(
                        "raw pool write `{pattern}` at {}:{}: {}",
                        path_str,
                        index + 1,
                        raw_lines[index].trim()
                    ));
                }
            }
        }

        for method in MUTATING_METHODS {
            if let Some(pos) = line.find(method) {
                result.mutating_calls_found += 1;
                if !is_mempool_owner
                    && !is_authorized_gateway_call(path_str, line, pos, &code_lines, index)
                {
                    result.violations.push(format!(
                        "raw mempool mutation `{method}` at {}:{}: {}",
                        path_str,
                        index + 1,
                        raw_lines[index].trim()
                    ));
                }
            }
        }
    }
}

/// Returns true only when the call is on a receiver expression explicitly
/// audited in [`AUTHORIZED_GATEWAY_CALLS`].
fn is_authorized_gateway_call(
    path: &str,
    line: &str,
    method_pos: usize,
    lines: &[String],
    line_index: usize,
) -> bool {
    if line[..method_pos].contains(".write(") {
        return false;
    }

    let before = &line[..method_pos];
    // Resolve the receiver chain. A call split across lines leaves only a
    // leading dot on the method line, so accumulate continuation lines above
    // that start with '.' and anchor on the chain root's trailing expression.
    // Single-line receivers keep their last whitespace-delimited token, which
    // drops statement prefixes such as `let _ =`.
    let fragment = match before.rfind('.') {
        Some(dot_pos) => before[..dot_pos].trim(),
        None => before.trim(),
    };
    let chained: String;
    let receiver: &str = if fragment.contains(char::is_whitespace) {
        fragment.split_whitespace().next_back().unwrap_or(fragment)
    } else if fragment.is_empty() {
        let mut parts: Vec<&str> = Vec::new();
        for previous in lines[..line_index].iter().rev() {
            let trimmed = previous.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(link) = trimmed.strip_prefix('.') {
                parts.push(link.trim());
            } else {
                parts.push(
                    trimmed
                        .split_whitespace()
                        .next_back()
                        .unwrap_or(trimmed)
                        .trim_end_matches(';'),
                );
                break;
            }
        }
        parts.reverse();
        chained = parts.join(".");
        &chained
    } else {
        fragment
    };

    let normalized_path = path.replace('\\', "/");
    AUTHORIZED_GATEWAY_CALLS
        .iter()
        .any(|(allowed_path, allowed_receiver)| {
            let path_matches = normalized_path == *allowed_path
                || normalized_path
                    .strip_suffix(allowed_path)
                    .is_some_and(|prefix| prefix.ends_with('/'));
            path_matches && receiver == *allowed_receiver
        })
}

#[cfg(test)]
mod tests {
    use super::{LexState, code_line, empty_result, is_authorized_gateway_call, scan_source};

    const MINING_HANDLER: &str = "/workspace/crates/rpc/src/handlers/mining.rs";
    const NON_OWNER: &str = "/workspace/crates/node/src/fake.rs";

    fn authorized(path: &str, source: &str) -> bool {
        let raw: Vec<&str> = source.lines().collect();
        let mut lex = LexState::default();
        let lines: Vec<String> = raw.iter().map(|line| code_line(line, &mut lex)).collect();
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
        for path in [
            "/workspace/crates/node/src/apply.rs",
            "/workspace/fakecrates/rpc/src/handlers/mining.rs",
        ] {
            assert!(!authorized(
                path,
                "ctx.mempool\n    .prioritise(txid, fee_delta)"
            ));
        }
    }

    /// ARCH-07 permits this gateway call, not a second mempool mutation owner.
    #[test]
    fn node_connection_authorizes_only_its_typed_gateway_receiver() {
        let owner = "/workspace/crates/node/src/apply/connect.rs";
        for (path, call, expected_violations) in [
            (
                owner,
                "handles.mempool_gateway.remove_for_block(origin, txs, txids, height);",
                0,
            ),
            (
                "crates/node/src/reorg/execution.rs",
                "handles.mempool_gateway.reconsider_disconnected(AdmissionOrigin::Reorg, candidates.into_entries());",
                0,
            ),
            (
                NON_OWNER,
                "handles.mempool_gateway.reconsider_disconnected(AdmissionOrigin::Reorg, candidates.into_entries());",
                1,
            ),
            (
                NON_OWNER,
                "handles.mempool_gateway.remove_for_block(origin, txs, txids, height);",
                1,
            ),
            (
                owner,
                "handles.mempool.remove_for_block(origin, txs, txids, height);",
                1,
            ),
            (
                owner,
                "handles.mempool_gateway.write().remove_for_block(origin, txs, txids, height);",
                1,
            ),
        ] {
            let mut result = empty_result();
            scan_source(path, call, &mut result);
            assert_eq!(
                result.violations.len(),
                expected_violations,
                "{path}: {call}"
            );
            assert_eq!(result.mutating_calls_found, 1);
        }
    }

    #[test]
    fn multiline_receiver_chain_resolves_to_its_root() {
        let owner = "/workspace/crates/node/src/reorg/execution.rs";
        for (path, call, expected_violations) in [
            (
                owner,
                "let _ = handles\n.mempool_gateway\n.reconsider_disconnected(origin, entries);",
                0,
            ),
            (
                owner,
                "let _ = other\n.mempool_gateway\n.reconsider_disconnected(origin, entries);",
                1,
            ),
            (
                NON_OWNER,
                "let _ = handles\n.mempool_gateway\n.reconsider_disconnected(origin, entries);",
                1,
            ),
        ] {
            let mut result = empty_result();
            scan_source(path, call, &mut result);
            assert_eq!(
                result.violations.len(),
                expected_violations,
                "{path}: {call}"
            );
            assert_eq!(result.mutating_calls_found, 1);
        }
    }

    #[test]
    fn a_raw_write_chain_is_never_authorized() {
        assert!(!authorized(
            MINING_HANDLER,
            "ctx.mempool.write().prioritise(txid, fee_delta)"
        ));
    }

    #[test]
    fn strings_and_comments_do_not_create_mutation_matches() {
        let source = r##"
const TEXT: &str = "gateway.prioritise(txid, 1) // not code";
const RAW: &str = r#"mempool.prioritise(txid, 2)"#;
/* pool.prioritise(txid, 3); */
// gateway.prioritise(txid, 4);
pub fn production() {}
"##;
        assert!(violations(source).is_empty());
    }

    #[test]
    fn string_continuation_does_not_hide_following_production() {
        let source = r#"
const TEXT: &str = "continued\
";
pub fn production() {
    gateway.prioritise(txid, 9);
}
"#;
        let found = violations(source);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("gateway.prioritise(txid, 9)"));
    }

    #[test]
    fn production_after_an_inline_test_module_is_still_scanned() {
        let source = r##"
#[cfg(test)]
mod tests {
    #[test]
    fn fixture() {
        let _ = r#"
}
gateway.prioritise(txid, 1)
"#;
        gateway.prioritise(txid, 2);
    }
} // trailing comment must not hide production below

pub fn production() {
    gateway.prioritise(txid, 3);
}
"##;
        let found = violations(source);
        assert_eq!(found.len(), 1, "only production mutation is scanned");
        assert!(found[0].contains("gateway.prioritise(txid, 3)"));
    }

    #[test]
    fn cfg_test_helper_and_visibility_qualified_test_are_skipped_only_to_their_end() {
        let source = r"
#[cfg(test)]
pub fn helper() {
    gateway.prioritise(txid, 1);
}

#[test]
pub fn fixture() {
    mempool.prioritise(txid, 2);
}

pub fn production() {
    mempool.prioritise(txid, 3);
}
";
        let found = violations(source);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("mempool.prioritise(txid, 3)"));
    }

    #[test]
    fn external_test_module_declaration_does_not_hide_following_production() {
        let source = r"
#[cfg(test)]
mod tests;

pub fn production() {
    gateway.prioritise(txid, 3);
}
";
        let found = violations(source);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("gateway.prioritise(txid, 3)"));
    }
}
