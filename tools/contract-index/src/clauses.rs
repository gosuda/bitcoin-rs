use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct Clause {
    pub(crate) id: String,
    pub(crate) file: String,
}

#[derive(Debug, Default)]
pub(crate) struct Definitions {
    pub(crate) clauses: Vec<Clause>,
    pub(crate) by_id: BTreeMap<String, usize>,
    pub(crate) files: Vec<String>,
}

impl Definitions {
    pub(crate) fn get(&self, id: &str) -> Option<&Clause> {
        self.by_id.get(id).map(|index| &self.clauses[*index])
    }

    fn push(&mut self, id: String, file: &str, problems: &mut Vec<String>) {
        if let Some(existing) = self.get(&id) {
            if existing.file != file {
                problems.push(format!(
                    "clause {id} is defined in both {} and {file}",
                    existing.file
                ));
            }
            return;
        }
        self.by_id.insert(id.clone(), self.clauses.len());
        self.clauses.push(Clause {
            id,
            file: file.to_string(),
        });
    }
}

pub(crate) fn parse(root: &Path, problems: &mut Vec<String>) -> Definitions {
    let mut definitions = Definitions::default();
    let directory = root.join("docs/contracts");
    let Ok(read) = std::fs::read_dir(&directory) else {
        problems.push(format!("cannot read {}", directory.display()));
        return definitions;
    };
    let mut files: Vec<_> = read
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("md"))
        .collect();
    files.sort();
    for path in files {
        let name = path
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == "README.md" || name == "evidence-index.md" {
            continue;
        }
        let file = crate::text::relative(root, &path);
        definitions.files.push(file.clone());
        let Ok(text) = std::fs::read_to_string(&path) else {
            problems.push(format!("cannot read {file}"));
            continue;
        };
        collect_definitions(&text, &file, &mut definitions, problems);
    }
    definitions
}

fn collect_definitions(
    text: &str,
    file: &str,
    definitions: &mut Definitions,
    problems: &mut Vec<String>,
) {
    for (_, line) in crate::text::prose_lines(text) {
        for id in heading_ids(line).into_iter().chain(bold_ids(line)) {
            definitions.push(id, file, problems);
        }
    }
}

fn heading_ids(line: &str) -> Vec<String> {
    let trimmed = line.trim_start();
    let hashes = trimmed.chars().take_while(|value| *value == '#').count();
    if !(2..=6).contains(&hashes) {
        return Vec::new();
    }
    let rest = trimmed[hashes..].trim_start();
    let rest = rest.trim_end_matches('#').trim();
    match rest.strip_prefix('`') {
        Some(stripped) => stripped
            .find('`')
            .map(|end| &stripped[..end])
            .filter(|token| is_clause_id(token))
            .map(|token| vec![token.to_string()])
            .unwrap_or_default(),
        None => plain_heading_id(rest),
    }
}

fn plain_heading_id(rest: &str) -> Vec<String> {
    let Some(token) = rest.split_whitespace().next() else {
        return Vec::new();
    };
    let token = token.trim_end_matches(':');
    if !is_clause_id(token) {
        return Vec::new();
    }
    vec![token.to_string()]
}

fn bold_ids(line: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("**") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("**") else {
            break;
        };
        let token = after[..end]
            .split(|value: char| value == ':' || value.is_whitespace())
            .next()
            .unwrap_or_default();
        if is_clause_id(token) {
            ids.push(token.to_string());
        }
        rest = &after[end + 2..];
    }
    ids
}

pub(crate) fn is_clause_id(token: &str) -> bool {
    let mut parts = token.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    if !is_upper_alnum(first) {
        return false;
    }
    let mut separators = 0;
    loop {
        let Some(part) = parts.next() else {
            return separators > 0;
        };
        separators += 1;
        let last = parts.clone().next().is_none();
        if !(if last {
            is_upper_alnum(part) || ends_with_lowercase(part)
        } else {
            is_upper_alnum(part)
        }) {
            return false;
        }
    }
}

fn is_upper_alnum(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn ends_with_lowercase(part: &str) -> bool {
    let rest = match part.as_bytes().last() {
        Some(byte) if byte.is_ascii_lowercase() => &part[..part.len() - 1],
        _ => return false,
    };
    !rest.is_empty() && is_upper_alnum(rest)
}

#[expect(clippy::expect_used, reason = "test assertions")]
#[cfg(test)]
mod tests {
    use super::{is_clause_id, parse};

    #[test]
    fn clause_ids_cover_the_inventory_shapes() {
        for id in [
            "ARCH-01",
            "ARCH-07a",
            "SYNC-05",
            "JW-BOOT-1",
            "JW-MARK-2",
            "CONV-1",
            "CORP-00",
            "P2P-11",
        ] {
            assert!(is_clause_id(id), "{id} must be a clause ID");
        }
        for id in ["RCV", "rcv-01", "RCV-", "-04", "Rcv-01", "SHA--256", ""] {
            assert!(!is_clause_id(id), "{id} must not be a clause ID");
        }
    }

    #[test]
    fn definitions_read_headings_and_bold_requirements() {
        let directory = tempfile::tempdir().expect("temp dir");
        let contracts = directory.path().join("docs/contracts");
        std::fs::create_dir_all(&contracts).expect("contracts dir");
        std::fs::write(
            contracts.join("demo.md"),
            "# Demo\n## `HEAD-01`: A heading clause\n### HEAD-02a: A plain clause\n- **BOLD-01: A bold clause.** Text.\n> **CONV-1**: A quoted clause.\n### Not a clause heading\n",
        )
        .expect("contract");
        let mut problems = Vec::new();
        let definitions = parse(directory.path(), &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
        let mut ids: Vec<_> = definitions
            .clauses
            .iter()
            .map(|clause| clause.id.as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["BOLD-01", "CONV-1", "HEAD-01", "HEAD-02a"]);
    }
}
