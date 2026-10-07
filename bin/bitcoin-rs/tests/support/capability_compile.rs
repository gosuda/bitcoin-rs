//! Compile real consumer code without workspace dev-feature unification.

use std::path::Path;
use std::process::{Command, Output};

use anyhow::Result;
use serde_json::Value;

/// A separate Cargo workspace and target directory containing one consumer.
pub(super) struct ProductionConsumer {
    directory: tempfile::TempDir,
}

impl ProductionConsumer {
    /// Adds node without its workspace dev-dependencies or fixture feature.
    pub(super) fn with_node(root: &Path) -> Result<Self> {
        use std::io::Write as _;

        let consumer = Self::new(root)?;
        let node = serde_json::to_string(&root.join("crates/node"))?;
        let mut manifest = std::fs::OpenOptions::new()
            .append(true)
            .open(consumer.directory.path().join("Cargo.toml"))?;
        writeln!(
            manifest,
            "bitcoin-rs-node = {{ path = {node}, default-features = false, features = [\"fjall\"] }}"
        )?;
        Ok(consumer)
    }

    /// Copies the repository lock to retain its pinned dependency versions.
    pub(super) fn new(root: &Path) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let chain = serde_json::to_string(&root.join("crates/chain"))?;
        let chainstate = serde_json::to_string(&root.join("crates/chainstate"))?;
        let p2p = serde_json::to_string(&root.join("crates/p2p"))?;
        let utxo = serde_json::to_string(&root.join("crates/utxo"))?;
        std::fs::create_dir(directory.path().join("src"))?;
        std::fs::write(
            directory.path().join("Cargo.toml"),
            format!(
                r#"[package]
name = "capability-consumer"
version = "0.0.0"
edition = "2024"

[workspace]
resolver = "3"

[lib]
name = "capability_consumer"

[dependencies]
bitcoin-rs-chain = {{ path = {chain}, default-features = false }}
bitcoin-rs-chainstate = {{ path = {chainstate}, default-features = false }}
bitcoin-rs-p2p = {{ path = {p2p}, default-features = false }}
bitcoin-rs-utxo = {{ path = {utxo}, default-features = false }}
"#
            ),
        )?;
        std::fs::copy(root.join("Cargo.lock"), directory.path().join("Cargo.lock"))?;
        Ok(Self { directory })
    }

    /// Adds the storage and RPC fixture owners without enabling test features.
    pub(super) fn with_fixture_owners(root: &Path) -> Result<Self> {
        let consumer = Self::new(root)?;
        let storage = serde_json::to_string(&root.join("crates/storage"))?;
        let rpc = serde_json::to_string(&root.join("crates/rpc"))?;
        let path = consumer.directory.path().join("Cargo.toml");
        let mut manifest = std::fs::read_to_string(&path)?;
        manifest.push_str(&format!(
            "bitcoin-rs-storage = {{ path = {storage}, default-features = false }}\n\
             bitcoin-rs-rpc = {{ path = {rpc}, default-features = false }}\n"
        ));
        std::fs::write(path, manifest)?;
        Ok(consumer)
    }

    fn check(&self, source: &str, locked: bool) -> Result<Output> {
        std::fs::write(self.directory.path().join("src/lib.rs"), source)?;
        let mut command = Command::new(env!("CARGO"));
        command
            .current_dir(self.directory.path())
            .args([
                "check",
                "--offline",
                "--no-default-features",
                "--lib",
                "--message-format=json",
                "--manifest-path",
            ])
            .arg(self.directory.path().join("Cargo.toml"))
            .arg("--target-dir")
            .arg(self.directory.path().join("target"));
        if locked {
            command.arg("--locked");
        }
        Ok(command.output()?)
    }

    /// The positive control also normalizes the seeded lock for this workspace.
    pub(super) fn allow_reads(&self, source: &str) -> Result<()> {
        let output = self.check(source, false)?;
        assert!(
            output.status.success(),
            "production read control did not compile:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    /// Requires the intended consumer diagnostic, never just a failed build.
    pub(super) fn deny(&self, source: &str, codes: &[&str], member: &str) -> Result<()> {
        let output = self.check(source, true)?;
        assert!(
            !output.status.success(),
            "production consumer can access `{member}`"
        );
        let messages = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<Result<Vec<_>, _>>()?;
        let errors: Vec<_> = messages
            .iter()
            .filter(|message| {
                message["reason"] == "compiler-message" && message["message"]["level"] == "error"
            })
            .collect();
        assert_eq!(
            errors.len(),
            1,
            "expected one of {codes:?} for `{member}`:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let diagnostic = &errors[0]["message"];
        assert_eq!(errors[0]["target"]["name"], "capability_consumer");
        assert!(
            diagnostic["code"]["code"]
                .as_str()
                .is_some_and(|code| codes.contains(&code)),
            "{diagnostic}"
        );
        let names_member = diagnostic["message"]
            .as_str()
            .is_some_and(|message| message.contains(&format!("`{member}`")));
        let spans_member = diagnostic["spans"].as_array().is_some_and(|spans| {
            spans.iter().any(|span| {
                span["is_primary"] == true
                    && span["text"].as_array().is_some_and(|lines| {
                        lines.iter().any(|line| {
                            line["text"]
                                .as_str()
                                .is_some_and(|text| text.contains(member))
                        })
                    })
            })
        });
        assert!(
            names_member || spans_member,
            "unrelated diagnostic: {diagnostic}"
        );
        Ok(())
    }
}
