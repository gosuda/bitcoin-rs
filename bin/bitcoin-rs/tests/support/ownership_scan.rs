//! Static source scan used by `overhaul_ownership` to enforce single-owner
//! boundaries that `cargo metadata` cannot see.
//!
//! The scan walks workspace Rust sources (excluding `tests/`, `benches/`, and
//! `examples/`) and ignores code inside top-level `#[cfg(test)]` items and
//! `#[test]` functions. Whole files whose module is declared with a
//! `#[cfg(test)] mod <name>;` attribute — test-support files whose helpers
//! carry no `#[test]` marks of their own — are skipped as well. A small Rust
//! lexical mask keeps braces and mutator-like text inside comments, quoted
//! strings, raw strings, and character literals from changing item boundaries
//! or producing false matches. Production code outside `crates/mempool/src/`
//! fails the scan if it directly calls a mutating `Mempool` method or
//! acquires the pool write lock through a bypass pattern. Derived-index
//! capability selection fails the scan outside its three owners: the
//! `crates/index` crate, the `crates/node` txindex runtime, and the
//! `crates/node/src/state` config projection.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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
    // guarded gateway, without introducing raw pool mutation.
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

/// Capability-forcing and config-projection expressions for the derived
/// transaction/script index.
///
/// `txindex` and `scriptindex` are config-optional: a node composes and
/// validates without them. They become a required dependency of a compose
/// path exactly when code outside the owners constructs `IndexCapabilities`
/// or calls the config projection, so every such expression must sit in an
/// owner file. A bare type mention (a field, a parameter, an import) forces
/// nothing and is not matched.
pub(crate) const INDEX_CAPABILITY_PATTERNS: &[&str] = &[
    "IndexCapabilities {",
    "IndexCapabilities::",
    "derived_index_capabilities(",
    "build_derived_index_open_spec(",
];

/// Result of the source scan.
#[derive(Debug)]
pub(crate) struct OwnershipScanResult {
    /// Mempool mutations outside the mempool owner, one per call site.
    pub mempool_writer_violations: Vec<String>,
    /// Derived-index capability selection outside the index owners.
    pub index_capability_violations: Vec<String>,
    /// Number of production source files examined.
    pub files_scanned: usize,
    /// Number of raw pool write sites found.
    pub pool_writes_found: usize,
    /// Number of mutating mempool method calls found (including gateway
    /// calls).
    pub mempool_mutations_found: usize,
    /// Number of derived-index capability expressions found (including
    /// owner files).
    pub index_capability_sites: usize,
}

fn empty_result() -> OwnershipScanResult {
    OwnershipScanResult {
        mempool_writer_violations: Vec::new(),
        index_capability_violations: Vec::new(),
        files_scanned: 0,
        pool_writes_found: 0,
        mempool_mutations_found: 0,
        index_capability_sites: 0,
    }
}

/// Walks the workspace and returns every single-owner boundary violation.
pub(crate) fn scan_ownership_violations() -> OwnershipScanResult {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files);
    files.sort();
    let test_modules = cfg_test_module_stems(&files);
    let mut result = empty_result();
    for path in &files {
        if is_test_module_file(path, &test_modules) {
            continue;
        }
        scan_file(path, &mut result);
    }
    result
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
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
                collect_rust_files(&path, files);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
}

/// Collects the stems of modules declared `#[cfg(test)] mod <stem>;`.
///
/// Such a declaration compiles its module file only under `cfg(test)`, but a
/// per-file lexical scan cannot see the parent's attribute. Recording the
/// stems keeps test-support files such as `sync/tests.rs` — whose helpers
/// carry no `#[test]` marks of their own — out of the production scan without
/// guessing from file names alone. An inline `mod <stem> { .. }` block is not
/// recorded: [`scan_source`] already skips its items line by line.
fn cfg_test_module_stems(files: &[PathBuf]) -> BTreeSet<String> {
    let contents = files
        .iter()
        .map(|path| std::fs::read_to_string(path).unwrap_or_default());
    cfg_test_module_stems_from(contents)
}

fn cfg_test_module_stems_from<I>(contents: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = String>,
{
    let mut stems = BTreeSet::new();
    for content in contents {
        let lines: Vec<&str> = content.lines().collect();
        for (index, raw_line) in lines.iter().enumerate() {
            let trimmed = raw_line.trim();
            let Some(rest) = cfg_test_attribute(trimmed) else {
                continue;
            };
            if let Some(stem) = mod_stem(rest) {
                stems.insert(stem);
                continue;
            }
            if !rest.trim().is_empty() {
                continue;
            }
            // Attribute-only line: the `mod` declaration follows after any
            // further attributes, comments, or blank lines.
            for next in lines.iter().skip(index + 1) {
                let next_trimmed = next.trim();
                if next_trimmed.is_empty()
                    || next_trimmed.starts_with("//")
                    || next_trimmed.starts_with("#!")
                    || cfg_test_attribute(next_trimmed).is_some()
                    || next_trimmed.starts_with("#[")
                {
                    continue;
                }
                if let Some(stem) = mod_stem(next_trimmed) {
                    stems.insert(stem);
                }
                break;
            }
        }
    }
    stems
}

/// Recognizes a `#[cfg(…test…)]` attribute and returns the line remainder
/// after the closing bracket. `cfg(not(test))` is rejected: it flags
/// production code, not test code.
fn cfg_test_attribute(trimmed: &str) -> Option<&str> {
    let rest = trimmed.strip_prefix("#[cfg(")?;
    let end = rest.rfind(")]")?;
    let payload = &rest[..end];
    if !payload.contains("test") || payload.contains("not(test)") {
        return None;
    }
    Some(&rest[end + ")]".len()..])
}

/// Extracts `<stem>` from a complete external `mod <stem>;` declaration.
/// Returns `None` for inline `mod <stem> { .. }` blocks and non-mod items.
fn mod_stem(rest: &str) -> Option<String> {
    let tail = rest.trim().strip_prefix("mod ")?;
    let name = tail.strip_suffix(';')?.trim();
    (!name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_'))
    .then(|| name.to_owned())
}

fn is_test_module_file(path: &Path, test_modules: &BTreeSet<String>) -> bool {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| test_modules.contains(stem))
}

fn scan_file(path: &Path, result: &mut OwnershipScanResult) {
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

fn scan_source(path_str: &str, content: &str, result: &mut OwnershipScanResult) {
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
                    result.mempool_writer_violations.push(format!(
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
                result.mempool_mutations_found += 1;
                if !is_mempool_owner
                    && !is_authorized_gateway_call(path_str, line, pos, &code_lines, index)
                {
                    result.mempool_writer_violations.push(format!(
                        "raw mempool mutation `{method}` at {}:{}: {}",
                        path_str,
                        index + 1,
                        raw_lines[index].trim()
                    ));
                }
            }
        }

        for pattern in INDEX_CAPABILITY_PATTERNS {
            if line.contains(pattern) {
                result.index_capability_sites += 1;
                if !is_index_capability_owner(path_str) {
                    result.index_capability_violations.push(format!(
                        "derived-index capability `{pattern}` at {}:{}: {}",
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
    let normalized_path = path.replace('\\', "/");
    AUTHORIZED_GATEWAY_CALLS
        .iter()
        .any(|(allowed_path, allowed_receiver)| {
            let path_matches = normalized_path == *allowed_path
                || normalized_path
                    .strip_suffix(allowed_path)
                    .is_some_and(|prefix| prefix.ends_with('/'));
            if !path_matches {
                return false;
            }

            // Rustfmt can split both field access and the method call across
            // lines. Read the masked code backwards, skipping only whitespace,
            // and require the entire audited receiver rather than a suffix.
            let mut before = line[..method_pos]
                .chars()
                .rev()
                .chain(
                    lines[..line_index]
                        .iter()
                        .rev()
                        .flat_map(|previous| previous.chars().rev()),
                )
                .filter(|ch| !ch.is_whitespace());
            before.next() == Some('.')
                && allowed_receiver
                    .chars()
                    .rev()
                    .all(|expected| before.next() == Some(expected))
                && before
                    .next()
                    .is_none_or(|ch| ch != '.' && ch != '_' && ch.is_ascii_punctuation())
        })
}

/// Returns true when `path` belongs to one of the three derived-index
/// capability owners: the `crates/index` crate that owns the type and its
/// durable writer, the node txindex runtime that drives the worker and query
/// engine, and the node state module whose `index.rs` is the only config
/// projection.
fn is_index_capability_owner(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.contains("/crates/index/src/")
        || normalized.contains("/crates/node/src/state/")
        || normalized.contains("/crates/node/src/txindex.rs")
        || normalized.contains("/crates/node/src/txindex/")
}

#[cfg(test)]
mod tests {
    use super::{
        LexState, cfg_test_module_stems_from, code_line, empty_result, is_authorized_gateway_call,
        is_test_module_file, scan_source,
    };
    use std::path::Path;

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
        result.mempool_writer_violations
    }

    #[test]
    fn cfg_test_stems_cover_external_module_declarations_only() {
        let stems = cfg_test_module_stems_from([
            "#[cfg(test)]\nmod tests;\n".to_owned(),
            "#[cfg(all(test, feature = \"fjall\"))]\nmod body_reader_tests;\n".to_owned(),
            "#[cfg(test)] mod tests;\n".to_owned(),
            "#[cfg(test)]\n\n// leading comment\n#[expect(unused)]\nmod helpers;\n".to_owned(),
        ]);
        assert_eq!(
            stems,
            ["body_reader_tests", "helpers", "tests"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );

        let not_stems = cfg_test_module_stems_from([
            "#[cfg(not(test))]\nmod production;\n".to_owned(),
            "#[cfg(test)]\nmod inline {\n    fn helper() {}\n}\n".to_owned(),
            "#[cfg(test)]\nfn a_test_helper() {}\n".to_owned(),
            "mod plainly_gated;\n".to_owned(),
        ]);
        assert!(not_stems.is_empty(), "{not_stems:?}");
    }

    #[test]
    fn a_test_module_file_is_skipped_by_its_stem() {
        let stems = cfg_test_module_stems_from(["#[cfg(test)]\nmod tests;\n".to_owned()]);
        assert!(is_test_module_file(
            Path::new("/workspace/crates/node/src/sync/tests.rs"),
            &stems
        ));
        assert!(!is_test_module_file(
            Path::new("/workspace/crates/node/src/sync/peers.rs"),
            &stems
        ));
        assert!(!is_test_module_file(
            Path::new("/workspace/crates/node/src/lib.rs"),
            &stems
        ));
    }

    #[test]
    fn only_derived_index_owners_select_capabilities() {
        for (path, source) in [
            (
                "/workspace/crates/node/src/state/index.rs",
                "bitcoin_rs_index::IndexCapabilities {\n    tx_lookup: config.indexes.txindex,\n}",
            ),
            (
                "/workspace/crates/node/src/state/open.rs",
                "let indexed = !derived_index_capabilities(&config).is_empty();",
            ),
            (
                "/workspace/crates/node/src/txindex/query.rs",
                "self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {})",
            ),
            (
                "/workspace/crates/index/src/write.rs",
                "writer.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;",
            ),
        ] {
            let mut result = empty_result();
            scan_source(path, source, &mut result);
            assert!(
                result.index_capability_violations.is_empty(),
                "{path}: {:?}",
                result.index_capability_violations
            );
            assert_eq!(result.index_capability_sites, 1, "{path}");
        }
    }

    /// Forcing capability selection in a compose or apply path is exactly
    /// the config-optional index becoming required.
    #[test]
    fn capability_forcing_outside_the_owners_is_flagged() {
        for (path, source) in [
            (
                "/workspace/crates/node/src/apply/connect.rs",
                "let caps = IndexCapabilities::ALL;",
            ),
            (
                "/workspace/crates/node/src/startup.rs",
                "let spec = build_derived_index_open_spec(&config, 0, 1)?.unwrap();",
            ),
            (
                "/workspace/crates/rpc/src/handlers/chain.rs",
                "IndexCapabilities::TX_LOOKUP",
            ),
        ] {
            let mut result = empty_result();
            scan_source(path, source, &mut result);
            assert_eq!(
                result.index_capability_violations.len(),
                1,
                "{path}: {:?}",
                result.index_capability_violations
            );
        }
    }

    #[test]
    fn capability_type_mentions_and_text_do_not_force_anything() {
        for source in [
            "fn f(capabilities: IndexCapabilities) {}",
            "use bitcoin_rs_index::IndexCapabilities;",
            "const T: &str = \"IndexCapabilities::ALL\";",
            "// IndexCapabilities::ALL in a comment",
        ] {
            let mut result = empty_result();
            scan_source(NON_OWNER, source, &mut result);
            assert!(
                result.index_capability_violations.is_empty(),
                "{source}"
            );
            assert_eq!(result.index_capability_sites, 0, "{source}");
        }
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
                "crates/node/src/reorg/execution.rs",
                "let _ = handles\n    .mempool_gateway\n    .reconsider_disconnected(origin, candidates);",
                0,
            ),
            (
                NON_OWNER,
                "let _ = handles\n    .mempool_gateway\n    .reconsider_disconnected(origin, candidates);",
                1,
            ),
            (
                "crates/node/src/reorg/execution.rs",
                "let _ = other\n    .mempool_gateway\n    .reconsider_disconnected(origin, candidates);",
                1,
            ),
            (
                "crates/node/src/reorg/execution.rs",
                "other.handles\n    .mempool_gateway\n    .reconsider_disconnected(origin, candidates);",
                1,
            ),
            (
                "crates/node/src/reorg/execution.rs",
                "other\u{301}handles.mempool_gateway.reconsider_disconnected(origin, candidates);",
                1,
            ),
            (
                "crates/node/src/reorg/execution.rs",
                "handles.mempool_gateway.write()\n    .reconsider_disconnected(origin, candidates);",
                1,
            ),
            (
                "crates/node/src/reorg/execution.rs",
                "other.mempool_gateway /* handles.mempool_gateway */\n    .reconsider_disconnected(origin, candidates);",
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
                result.mempool_writer_violations.len(),
                expected_violations,
                "{path}: {call}"
            );
            assert_eq!(result.mempool_mutations_found, 1);
        }
    }

    #[test]
    fn only_the_current_connect_gateway_path_is_authorized() {
        for (path, receiver, permitted) in [
            (
                "/workspace/crates/node/src/apply/connect.rs",
                "handles.mempool_gateway",
                true,
            ),
            (
                "/workspace/crates/node/src/apply.rs",
                "handles.mempool_gateway",
                false,
            ),
            (
                "/workspace/crates/node/src/apply/connect.rs",
                "handles.mempool",
                false,
            ),
            (
                "/workspace/crates/node/src/apply/connect.rs",
                "handles.mempool_gateway.pool().write()",
                false,
            ),
        ] {
            let mut result = empty_result();
            scan_source(
                path,
                &format!("{receiver}.remove_for_block(block_txs, block_txids, height);"),
                &mut result,
            );
            assert_eq!(
                result.mempool_writer_violations.is_empty(),
                permitted,
                "{path}: {receiver}"
            );
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
                result.mempool_writer_violations.len(),
                expected_violations,
                "{path}: {call}"
            );
            assert_eq!(result.mempool_mutations_found, 1);
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
