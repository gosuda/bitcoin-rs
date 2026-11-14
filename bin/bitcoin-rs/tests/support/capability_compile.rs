use std::path::Path;
use std::process::{Command, Output};

use crate::support::TestError;
type Result<T = ()> = std::result::Result<T, TestError>;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};

pub(super) struct ProductionConsumer {
    directory: tempfile::TempDir,
}

impl ProductionConsumer {
    pub(super) fn with_node(root: &Path) -> Result<Self> {
        Self::new(root)
    }

    pub(super) fn new(root: &Path) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let execution = sonic_rs::to_string(&root.join("crates/execution"))?;
        let wire = sonic_rs::to_string(&root.join("crates/wire"))?;
        let storage = sonic_rs::to_string(&root.join("crates/storage"))?;
        let node = sonic_rs::to_string(&root.join("crates/node"))?;
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
bitcoin-rs-execution = {{ path = {execution}, default-features = false }}
bitcoin-rs-wire = {{ path = {wire}, default-features = false }}
bitcoin-rs-storage = {{ path = {storage}, default-features = false }}
bitcoin-rs-node = {{ path = {node}, default-features = false }}
"#
            ),
        )?;
        std::fs::copy(root.join("Cargo.lock"), directory.path().join("Cargo.lock"))?;
        Ok(Self { directory })
    }

    pub(super) fn with_fixture_owners(root: &Path) -> Result<Self> {
        let consumer = Self::new(root)?;
        let serving = sonic_rs::to_string(&root.join("crates/serving"))?;
        let path = consumer.directory.path().join("Cargo.toml");
        let mut manifest = std::fs::read_to_string(&path)?;
        manifest.push_str(&format!(
            "bitcoin-rs-serving = {{ path = {serving}, default-features = false }}\n"
        ));
        std::fs::write(path, manifest)?;
        Ok(consumer)
    }

    fn check(&self, source: &str, locked: bool) -> Result<Output> {
        std::fs::write(self.directory.path().join("src/lib.rs"), source)?;
        let target = self.directory.path().join("target");
        let mut command = Command::new(env!("CARGO"));
        command
            .current_dir(self.directory.path())
            .env("CARGO_BUILD_BUILD_DIR", &target)
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
            .arg(&target);
        if locked {
            command.arg("--locked");
        }
        Ok(command.output()?)
    }

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

    pub(super) fn deny(&self, source: &str, codes: &[&str], member: &str) -> Result<()> {
        let output = self.check(source, true)?;
        assert!(
            !output.status.success(),
            "production consumer can access `{member}`"
        );
        let messages = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(sonic_rs::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
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
