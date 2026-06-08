//! G15 — Workspace version pin.
//! Internal `[workspace.dependencies]` path crates must declare the same `version`
//! as `[workspace.package].version` (Cargo cannot inherit version into that table).

use core::str::FromStr;
use std::path::Path;

/// Gate G15: `[workspace.package].version` equals every internal path-dep version.
#[test]
fn workspace_internal_dep_versions_match_package_version() {
    let root_toml = std::fs::read_to_string(root_cargo_toml_path())
        .expect("read workspace root Cargo.toml");

    let workspace_version =
        parse_workspace_package_version(&root_toml).expect("parse [workspace.package].version");

    let mismatches: Vec<String> = parse_internal_workspace_dep_versions(&root_toml)
        .into_iter()
        .filter(|(_, version)| version != &workspace_version)
        .map(|(name, version)| format!("{name} = \"{version}\" (expected \"{workspace_version}\")"))
        .collect();

    assert!(
        mismatches.is_empty(),
        "internal workspace dependency versions must match [workspace.package].version:\n{}",
        mismatches.join("\n")
    );
}

fn root_cargo_toml_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Cargo.toml")
}

fn parse_workspace_package_version(cargo_toml: &str) -> Option<String> {
    let mut in_workspace_package = false;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed == "[workspace.package]" {
            in_workspace_package = true;
            continue;
        }
        if in_workspace_package {
            if trimmed.starts_with('[') {
                break;
            }
            if let Some(value) = parse_toml_string_assignment(trimmed, "version") {
                return Some(value);
            }
        }
    }
    None
}

fn parse_internal_workspace_dep_versions(cargo_toml: &str) -> Vec<(String, String)> {
    let mut in_internal = false;
    let mut deps = Vec::new();

    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# Internal crates") {
            in_internal = true;
            continue;
        }
        if in_internal && trimmed.starts_with("# ---") {
            break;
        }
        if !in_internal || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((name, version)) = parse_internal_dep_line(trimmed) {
            deps.push((name, version));
        }
    }

    deps
}

fn parse_internal_dep_line(line: &str) -> Option<(String, String)> {
    let (name, rest) = line.split_once('=')?;
    let name = name.trim();
    if !name.starts_with("bitcoin-rs-") {
        return None;
    }
    let version = extract_version_requirement(rest.trim())?;
    Some((name.to_owned(), version))
}

fn extract_version_requirement(value: &str) -> Option<String> {
    if value.starts_with('{') {
        for part in value
            .trim_start_matches('{')
            .trim_end_matches('}')
            .split(',')
        {
            let part = part.trim();
            if let Some(v) = parse_toml_string_assignment(part, "version") {
                return Some(v);
            }
        }
        return None;
    }
    parse_toml_string_value(value)
}

fn parse_toml_string_assignment(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}");
    let rest = line.strip_prefix(&prefix)?.trim();
    let rest = rest.strip_prefix('=')?.trim();
    parse_toml_string_value(rest)
}

fn parse_toml_string_value(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.starts_with('"') {
        return String::from_str(raw.trim_matches('"')).ok();
    }
    if raw.starts_with('\'') {
        return String::from_str(raw.trim_matches('\'')).ok();
    }
    None
}

#[cfg(test)]
mod unit {
    use super::{
        parse_internal_dep_line, parse_internal_workspace_dep_versions,
        parse_workspace_package_version,
    };

    #[test]
    fn parses_workspace_package_version() {
        let sample = r#"
[workspace.package]
version = "0.3.1"
edition = "2024"
"#;
        assert_eq!(
            parse_workspace_package_version(sample).as_deref(),
            Some("0.3.1")
        );
    }

    #[test]
    fn parses_internal_dep_block() {
        let sample = r#"
# Internal crates
bitcoin-rs-primitives = { path = "crates/primitives", version = "0.3.1" }
bitcoin-rs-node       = { path = "crates/node", version = "0.3.1", default-features = false }

# --- Bitcoin ecosystem
"#;
        let deps = parse_internal_workspace_dep_versions(sample);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0], ("bitcoin-rs-primitives".to_owned(), "0.3.1".to_owned()));
    }

    #[test]
    fn parse_internal_dep_line_handles_spacing() {
        let (name, version) =
            parse_internal_dep_line("bitcoin-rs-rpc        = { path = \"crates/rpc\", version = \"0.3.0\" }")
                .expect("parse line");
        assert_eq!(name, "bitcoin-rs-rpc");
        assert_eq!(version, "0.3.0");
    }
}
