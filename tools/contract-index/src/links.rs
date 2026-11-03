use std::path::Path;

const CHECKED_ROOTS: [&str; 5] = ["crates", "bin", "e2e", "fuzz", "tools"];

struct Citation<'a> {
    document: &'a str,
    number: usize,
    span: &'a str,
}

pub(crate) fn check(root: &Path, problems: &mut Vec<String>) {
    for path in crate::text::walk(root, &["md"]) {
        let document = crate::text::relative(root, &path);
        let Ok(text) = std::fs::read_to_string(&path) else {
            problems.push(format!("cannot read {document}"));
            continue;
        };
        let parent = path.parent().unwrap_or(root);
        for (number, line) in crate::text::prose_lines(&text) {
            check_relative_links(parent, &document, number, line, problems);
            for span in crate::text::code_spans(line) {
                check_citation(
                    root,
                    &Citation {
                        document: &document,
                        number,
                        span: span.trim(),
                    },
                    problems,
                );
            }
        }
    }
}
impl Citation<'_> {
    fn is_dated_record(&self) -> bool {
        self.document.starts_with("docs/benchmarks/data/")
    }
}

fn check_relative_links(
    parent: &Path,
    document: &str,
    number: usize,
    line: &str,
    problems: &mut Vec<String>,
) {
    let stripped = crate::text::strip_code_spans(line);
    for target in link_targets(&stripped) {
        let Some(path) = local_path(&target) else {
            continue;
        };
        if parent.join(&path).exists() {
            continue;
        }
        problems.push(format!(
            "{document}:{number}: relative link `{target}` does not resolve"
        ));
    }
}

fn link_targets(line: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("](") {
        let after = &rest[start + 2..];
        let Some(end) = after.find(')') else {
            break;
        };
        targets.push(
            after[..end]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string(),
        );
        rest = &after[end + 1..];
    }
    if let Some(rest) = line.trim_start().strip_prefix('[') {
        if let Some(position) = rest.find("]:") {
            let target = rest[position + 2..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            if !target.is_empty() {
                targets.push(target);
            }
        }
    }
    targets
}

fn local_path(target: &str) -> Option<String> {
    if target.is_empty() || target.starts_with('#') || target.starts_with("//") {
        return None;
    }
    if target.starts_with('<') || has_scheme(target) {
        return None;
    }
    let path = target
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    (!path.is_empty()).then(|| path.to_string())
}

fn has_scheme(target: &str) -> bool {
    let Some(colon) = target.find(':') else {
        return false;
    };
    let scheme = &target[..colon];
    !scheme.is_empty()
        && scheme.starts_with(|value: char| value.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '-' | '.'))
}

fn check_citation(root: &Path, citation: &Citation<'_>, problems: &mut Vec<String>) {
    let span = citation.span;
    if span.is_empty() || span.contains(char::is_whitespace) {
        return;
    }
    if span.contains(['<', '>', '*', '{', '}', '|', ',']) {
        return;
    }
    let without_line = strip_line_suffix(span);
    let (path, symbol) = split_symbol(without_line);
    if !is_code_path(path) {
        return;
    }
    let target = root.join(path);
    match symbol {
        Some(symbol) => check_symbol(&target, path, citation, symbol, problems),
        None if citation.is_dated_record() => {}
        None => check_path(&target, path, citation, problems),
    }
}

fn check_symbol(
    target: &Path,
    path: &str,
    citation: &Citation<'_>,
    symbol: &str,
    problems: &mut Vec<String>,
) {
    let document = citation.document;
    let number = citation.number;
    let span = citation.span;
    match resolve_symbol(target, symbol) {
        Some(true) => {}
        Some(false) => problems.push(format!(
            "{document}:{number}: citation `{span}` does not resolve: `{symbol}` is not in `{path}`"
        )),
        None => problems.push(format!(
            "{document}:{number}: citation `{span}` does not resolve: `{path}` does not exist"
        )),
    }
}

fn check_path(target: &Path, path: &str, citation: &Citation<'_>, problems: &mut Vec<String>) {
    if !path.rsplit('/').next().unwrap_or("").contains('.') {
        return;
    }
    if target.exists() {
        return;
    }
    problems.push(format!(
        "{}:{}: citation `{}` does not resolve",
        citation.document, citation.number, citation.span
    ));
}

fn strip_line_suffix(span: &str) -> &str {
    let Some((head, tail)) = span.rsplit_once(':') else {
        return span;
    };
    let tail = tail.split('-').next().unwrap_or(tail);
    if !tail.is_empty() && tail.bytes().all(|byte| byte.is_ascii_digit()) {
        head
    } else {
        span
    }
}

fn split_symbol(span: &str) -> (&str, Option<&str>) {
    match span.rsplit_once("::") {
        Some((path, symbol)) if !path.is_empty() && is_identifier(symbol) => (path, Some(symbol)),
        _ => (span, None),
    }
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    match characters.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    characters.all(|value| value.is_ascii_alphanumeric() || value == '_')
}

fn is_code_path(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with('.') || path.ends_with('/') {
        return false;
    }
    let first = path.split('/').next().unwrap_or("");
    path.contains('/') && CHECKED_ROOTS.contains(&first)
}

fn resolve_symbol(target: &Path, symbol: &str) -> Option<bool> {
    if target.is_file() {
        let text = std::fs::read_to_string(target).ok()?;
        return Some(contains_word(&text, symbol));
    }
    if !target.is_dir() {
        return None;
    }
    for path in crate::text::walk(target, &["rs", "py", "sh", "toml", "md"]) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        if contains_word(&text, symbol) {
            return Some(true);
        }
    }
    Some(false)
}

fn contains_word(haystack: &str, word: &str) -> bool {
    let mut from = 0;
    while let Some(position) = haystack[from..].find(word) {
        let start = from + position;
        let end = start + word.len();
        let bytes = haystack.as_bytes();
        let before = start == 0 || !is_word_byte(bytes[start - 1]);
        let after = end == bytes.len() || !is_word_byte(bytes[end]);
        if before && after {
            return true;
        }
        from = end;
    }
    false
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::{contains_word, link_targets, split_symbol, strip_line_suffix};

    #[test]
    fn citation_suffixes_and_symbols_split_cleanly() {
        assert_eq!(
            strip_line_suffix("crates/node/src/chain_effects/tests.rs:519"),
            "crates/node/src/chain_effects/tests.rs"
        );
        assert_eq!(
            strip_line_suffix("crates/node/src/lib.rs:510-520"),
            "crates/node/src/lib.rs"
        );
        assert_eq!(
            strip_line_suffix("crates/node/src/lib.rs::symbol"),
            "crates/node/src/lib.rs::symbol"
        );
        assert_eq!(
            split_symbol("crates/node/src/lib.rs::symbol"),
            ("crates/node/src/lib.rs", Some("symbol"))
        );
        assert_eq!(
            split_symbol("crates/node/src/lib.rs"),
            ("crates/node/src/lib.rs", None)
        );
    }

    #[test]
    fn word_search_needs_identifier_boundaries() {
        assert!(contains_word("fn alpha() {}", "alpha"));
        assert!(!contains_word("fn alpha() {}", "alp"));
        assert!(!contains_word("fn alpha_beta() {}", "alpha"));
    }

    #[test]
    fn link_targets_ignore_inline_code() {
        let line = "see `[a](b)` and [c](d.md) and [e][ref]";
        assert_eq!(
            link_targets(&crate::text::strip_code_spans(line)),
            vec!["d.md"]
        );
    }
}
