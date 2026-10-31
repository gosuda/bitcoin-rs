use std::path::Path;

use crate::clauses::Definitions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    Test,
    Kani,
    Model,
    Lean,
    Tla,
    Owner,
}

impl Kind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Kani => "kani",
            Self::Model => "model",
            Self::Lean => "lean",
            Self::Tla => "tla",
            Self::Owner => "owner",
        }
    }

    pub(crate) fn is_proof(self) -> bool {
        self != Self::Owner
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Artifact {
    pub(crate) path: String,
    pub(crate) item: String,
    pub(crate) kind: Kind,
}

pub(crate) type Tagged = std::collections::BTreeMap<String, Vec<Artifact>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Rust,
    Lean,
    Tla,
}

pub(crate) fn scan(root: &Path, definitions: &Definitions, problems: &mut Vec<String>) -> Tagged {
    let mut tagged = Tagged::new();
    for path in crate::text::walk(root, &["rs", "lean", "tla"]) {
        let Some(language) = language_of(&path) else {
            continue;
        };
        let relative = crate::text::relative(root, &path);
        let Ok(text) = std::fs::read_to_string(&path) else {
            problems.push(format!("cannot read {relative}"));
            continue;
        };
        scan_file(
            &text,
            &relative,
            language,
            definitions,
            &mut tagged,
            problems,
        );
    }
    tagged
}

fn language_of(path: &Path) -> Option<Language> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("rs") => Some(Language::Rust),
        Some("lean") => Some(Language::Lean),
        Some("tla") => Some(Language::Tla),
        _ => None,
    }
}

fn scan_file(
    text: &str,
    relative: &str,
    language: Language,
    definitions: &Definitions,
    tagged: &mut Tagged,
    problems: &mut Vec<String>,
) {
    let lines: Vec<&str> = text.lines().collect();
    let is_model = relative.ends_with("_model.rs");
    for (index, line) in lines.iter().enumerate() {
        let Some(ids) = tag_ids(line, language) else {
            continue;
        };
        let number = index + 1;
        let mut unknown = false;
        for id in &ids {
            if definitions.get(id).is_none() {
                problems.push(format!(
                    "{relative}:{number}: tag names unknown clause ID {id}"
                ));
                unknown = true;
            }
        }
        let item = match language {
            Language::Rust => rust_item(&lines, index + 1),
            Language::Lean => lean_item(&lines, index + 1),
            Language::Tla => tla_item(&lines),
        };
        let Some((item_name, found_kind)) = item else {
            problems.push(format!(
                "{relative}:{number}: tag is not followed by an item"
            ));
            continue;
        };
        if unknown {
            continue;
        }
        let kind = if is_model { Kind::Model } else { found_kind };
        let artifact = Artifact {
            path: relative.to_string(),
            item: item_name,
            kind,
        };
        for id in ids {
            tagged.entry(id).or_default().push(artifact.clone());
        }
    }
}

fn tag_ids(line: &str, language: Language) -> Option<Vec<String>> {
    let trimmed = line.trim();
    let body = match language {
        Language::Rust => {
            let rest = trimmed.strip_prefix("//")?;
            if rest.starts_with('/') {
                return None;
            }
            rest
        }
        Language::Lean => trimmed.strip_prefix("--")?,
        Language::Tla => trimmed.strip_prefix("\\*")?,
    };
    let ids: Vec<String> = body
        .split(',')
        .map(|part| part.trim().to_string())
        .collect();
    if ids.iter().any(|id| !crate::clauses::is_clause_id(id)) {
        return None;
    }
    Some(ids)
}

fn rust_item(lines: &[&str], start: usize) -> Option<(String, Kind)> {
    let end = skip_attributes(lines, start)?;
    let attributes = &lines[start..end];
    let declaration = *lines.get(end)?;
    let macro_name = leading_macro(declaration);
    let kind = rust_kind(attributes, macro_name);
    let name = match macro_name {
        Some("proptest") => first_function(lines, end + 1).unwrap_or_else(|| "proptest!".into()),
        Some(name) => format!("{name}!"),
        None => rust_name(declaration)?,
    };
    Some((name, kind))
}

fn skip_attributes(lines: &[&str], mut index: usize) -> Option<usize> {
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() {
            return None;
        }
        if !(trimmed.starts_with("#[") || trimmed.starts_with("#![")) {
            return Some(index);
        }
        index = skip_attribute(lines, index)?;
    }
    None
}

fn skip_attribute(lines: &[&str], mut index: usize) -> Option<usize> {
    let mut balance = 0_i32;
    loop {
        let line = *lines.get(index)?;
        for value in line.chars() {
            match value {
                '[' => balance += 1,
                ']' => balance -= 1,
                _ => {}
            }
        }
        index += 1;
        if balance <= 0 {
            return Some(index);
        }
    }
}

fn rust_kind(attributes: &[&str], macro_name: Option<&str>) -> Kind {
    if attributes
        .iter()
        .any(|attribute| attribute.contains("kani::proof"))
    {
        return Kind::Kani;
    }
    let has_test = attributes.iter().any(|attribute| {
        let inner = attribute
            .trim_start_matches("#![")
            .trim_start_matches("#[")
            .trim_end_matches(']')
            .trim();
        inner == "test" || inner.ends_with("::test")
    });
    if has_test || macro_name == Some("proptest") {
        return Kind::Test;
    }
    Kind::Owner
}

fn first_function(lines: &[&str], from: usize) -> Option<String> {
    for line in lines.iter().skip(from) {
        if line.trim() == "}" {
            return None;
        }
        let Some(position) = line.find("fn ") else {
            continue;
        };
        if let Some((name, _)) = leading_word(&line[position + 3..]) {
            return Some(name.to_string());
        }
    }
    None
}

fn rust_name(declaration: &str) -> Option<String> {
    let trimmed = declaration.trim_start();
    if let Some(name) = leading_macro(trimmed) {
        if name == "macro_rules" {
            let rest = trimmed.find('!').map(|index| &trimmed[index + 1..])?;
            return leading_word(rest).map(|(word, _)| word.to_string());
        }
        return Some(format!("{name}!"));
    }
    let (keyword, tail) = item_keyword(trimmed)?;
    if keyword == "impl" {
        let start = trimmed.find("impl")?;
        let end = trimmed[start..]
            .find('{')
            .map_or(trimmed.len(), |offset| start + offset);
        return Some(trimmed[start..end].trim().to_string());
    }
    leading_word(tail).map(|(word, _)| word.to_string())
}

fn leading_macro(declaration: &str) -> Option<&str> {
    let trimmed = declaration.trim_start();
    let (word, rest) = leading_word(trimmed)?;
    rest.trim_start().starts_with('!').then_some(word)
}

fn leading_word(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    let end = value
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(value.len());
    if end == 0 {
        return None;
    }
    Some((&value[..end], &value[end..]))
}

fn item_keyword(declaration: &str) -> Option<(&str, &str)> {
    let mut rest = declaration.trim_start();
    loop {
        let (word, after) = leading_word(rest)?;
        let trimmed = after.trim_start();
        match word {
            "pub" => rest = after_visibility(trimmed)?,
            "async" | "unsafe" | "default" => rest = trimmed,
            "extern" => rest = after_abi(trimmed),
            "const" => {
                let (next, tail) = leading_word(trimmed)?;
                if next == "fn" {
                    return Some(("fn", tail.trim_start()));
                }
                return Some(("const", trimmed));
            }
            _ => return Some((word, trimmed)),
        }
    }
}

fn after_visibility(trimmed: &str) -> Option<&str> {
    let Some(inner) = trimmed.strip_prefix('(') else {
        return Some(trimmed);
    };
    let mut depth = 1_usize;
    for (index, character) in inner.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(inner[index + 1..].trim_start());
                }
            }
            _ => {}
        }
    }
    None
}

fn after_abi(trimmed: &str) -> &str {
    let Some(inner) = trimmed.strip_prefix('"') else {
        return trimmed;
    };
    match inner.find('"') {
        Some(end) => inner[end + 1..].trim_start(),
        None => trimmed,
    }
}

fn lean_item(lines: &[&str], mut index: usize) -> Option<(String, Kind)> {
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.starts_with("@[") {
            index = skip_attribute(lines, index)?;
            continue;
        }
        if trimmed.starts_with("/-") {
            index = skip_block_comment(lines, index)?;
            continue;
        }
        if trimmed.starts_with("--") {
            index += 1;
            continue;
        }
        break;
    }
    let trimmed = lines.get(index)?.trim();
    for keyword in ["theorem", "lemma"] {
        if let Some(rest) = keyword_tail(trimmed, keyword) {
            return leading_word(rest).map(|(word, _)| (word.to_string(), Kind::Lean));
        }
    }
    let (word, _) = leading_word(trimmed)?;
    Some((word.to_string(), Kind::Owner))
}

fn skip_block_comment(lines: &[&str], mut index: usize) -> Option<usize> {
    let mut depth = 0_usize;
    loop {
        let bytes = lines.get(index)?.as_bytes();
        let mut position = 0;
        while position + 1 < bytes.len() {
            match (bytes[position], bytes[position + 1]) {
                (b'/', b'-') => {
                    depth += 1;
                    position += 2;
                }
                (b'-', b'/') => {
                    depth = depth.saturating_sub(1);
                    position += 2;
                    if depth == 0 {
                        return Some(index + 1);
                    }
                }
                _ => position += 1,
            }
        }
        index += 1;
    }
}

fn keyword_tail<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword)?;
    (rest.is_empty() || rest.starts_with(char::is_whitespace)).then_some(rest)
}

fn tla_item(lines: &[&str]) -> Option<(String, Kind)> {
    for line in lines {
        let trimmed = line.trim();
        let Some(position) = trimmed.find("MODULE ") else {
            continue;
        };
        if let Some((name, _)) = leading_word(&trimmed[position + "MODULE ".len()..]) {
            return Some((name.to_string(), Kind::Tla));
        }
    }
    None
}

#[expect(clippy::expect_used, reason = "test assertions")]
#[cfg(test)]
mod tests {
    use super::{Kind, scan};
    use crate::clauses;

    fn fixture(sources: &[(&str, &str)]) -> (tempfile::TempDir, super::Tagged) {
        let directory = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir_all(directory.path().join("docs/contracts")).expect("contracts");
        std::fs::write(
            directory.path().join("docs/contracts/demo.md"),
            "# Demo\n### `DEMO-01`: A clause\n### `DEMO-02`: Another clause\n",
        )
        .expect("contract");
        for (path, text) in sources {
            let target = directory.path().join(path);
            std::fs::create_dir_all(target.parent().expect("parent")).expect("source dir");
            std::fs::write(target, text).expect("source");
        }
        let mut problems = Vec::new();
        let definitions = clauses::parse(directory.path(), &mut problems);
        let tagged = scan(directory.path(), &definitions, &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
        (directory, tagged)
    }

    #[test]
    fn rust_tags_classify_tests_kani_models_and_owners() {
        let (_directory, tagged) = fixture(&[(
            "crates/demo/src/lib.rs",
            "// DEMO-01\n#[test]\nfn plain_test() {}\n// DEMO-01\n#[kani::proof]\nfn proof() {}\n// DEMO-02\npub(crate) fn owner() {}\n",
        )]);
        let artifacts = &tagged["DEMO-01"];
        assert_eq!(artifacts.len(), 2);
        assert!(
            artifacts
                .iter()
                .any(|item| item.item == "plain_test" && item.kind == Kind::Test)
        );
        assert!(
            artifacts
                .iter()
                .any(|item| item.item == "proof" && item.kind == Kind::Kani)
        );
        assert_eq!(tagged["DEMO-02"][0].item, "owner");
        assert_eq!(tagged["DEMO-02"][0].kind, Kind::Owner);
    }

    #[test]
    fn model_files_and_proptest_blocks_are_recognised() {
        let (_directory, tagged) = fixture(&[
            (
                "crates/demo/src/thing_model.rs",
                "// DEMO-01\n#[test]\nfn model_case() {}\n",
            ),
            (
                "crates/demo/src/tests.rs",
                "// DEMO-02\nproptest! {\n    #[test]\n    fn round_trip(value in 0..4u8) {}\n}\n",
            ),
        ]);
        assert_eq!(tagged["DEMO-01"][0].kind, Kind::Model);
        assert_eq!(tagged["DEMO-02"][0].kind, Kind::Test);
        assert_eq!(tagged["DEMO-02"][0].item, "round_trip");
    }

    #[test]
    fn lean_and_tla_tags_resolve_their_items() {
        let (_directory, tagged) = fixture(&[
            (
                "docs/lean/Demo.lean",
                "-- DEMO-01\ntheorem demo_round_trip : True := trivial\n",
            ),
            (
                "docs/models/Demo.tla",
                "\\* DEMO-02\n---- MODULE Demo ----\n====",
            ),
        ]);
        assert_eq!(tagged["DEMO-01"][0].kind, Kind::Lean);
        assert_eq!(tagged["DEMO-01"][0].item, "demo_round_trip");
        assert_eq!(tagged["DEMO-02"][0].kind, Kind::Tla);
        assert_eq!(tagged["DEMO-02"][0].item, "Demo");
    }

    #[test]
    fn lean_tags_attribute_proofs_behind_doc_comments() {
        let (_directory, tagged) = fixture(&[(
            "docs/lean/Demo.lean",
            "-- DEMO-01\n/-- `safety` is inductive. -/\n@[simp]\ntheorem safety_inductive : True := trivial\n",
        )]);
        assert_eq!(tagged["DEMO-01"][0].kind, Kind::Lean);
        assert_eq!(tagged["DEMO-01"][0].item, "safety_inductive");
    }
}
