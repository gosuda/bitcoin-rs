//! Read-only, single-pass measurement of a stopped node's data directory.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::Serialize;

#[derive(Default, Serialize)]
pub(super) struct Bytes {
    apparent_bytes: u64,
    allocated_bytes: u64,
}

impl Bytes {
    fn add(&mut self, metadata: &fs::Metadata) -> io::Result<()> {
        self.apparent_bytes = self
            .apparent_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| io::Error::other("apparent byte count overflow"))?;
        let allocated = metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| io::Error::other("allocated byte count overflow"))?;
        self.allocated_bytes = self
            .allocated_bytes
            .checked_add(allocated)
            .ok_or_else(|| io::Error::other("allocated byte count overflow"))?;
        Ok(())
    }
}

#[derive(Serialize)]
pub(super) struct Report {
    format: &'static str,
    observation: &'static str,
    totals: Bytes,
    namespaces: BTreeMap<String, Bytes>,
}

pub(super) fn measure(root: &Path) -> io::Result<Report> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() {
        return Err(io::Error::other("data directory must be a real directory"));
    }
    let mut report = Report {
        format: "bitcoin-rs-storage-allocation-v1",
        observation: "offline_snapshot_lower_bound",
        totals: Bytes::default(),
        namespaces: BTreeMap::new(),
    };
    let mut seen = HashSet::new();
    visit(root, ".", metadata.dev(), &mut seen, &mut report)?;
    Ok(report)
}

fn visit(
    path: &Path,
    namespace: &str,
    device: u64,
    seen: &mut HashSet<(u64, u64)>,
    report: &mut Report,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.dev() != device || !(metadata.is_dir() || metadata.is_file()) {
        return Err(io::Error::other(format!(
            "unsupported entry or mount crossing: {}",
            path.display()
        )));
    }
    if !seen.insert((metadata.dev(), metadata.ino())) {
        return Ok(());
    }
    report.totals.add(&metadata)?;
    report
        .namespaces
        .entry(namespace.to_owned())
        .or_default()
        .add(&metadata)?;
    if metadata.is_dir() {
        // Stable order gives cross-namespace hard links a deterministic owner.
        let mut entries = fs::read_dir(path)?.collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name;
            let child_namespace = if namespace == "." {
                // Each top-level entry is its own namespace, including loose files.
                name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| io::Error::other("non-UTF-8 top-level entry"))?;
                name.as_str()
            } else {
                namespace
            };
            visit(&entry.path(), child_namespace, device, seen, report)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn sparse_file_and_hard_link_are_not_double_counted() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let file = fs::File::create(dir.path().join("a"))?;
        file.set_len(16 * 1024 * 1024)?;
        fs::hard_link(dir.path().join("a"), dir.path().join("b"))?;
        let report = measure(dir.path())?;
        let root = fs::metadata(dir.path())?;
        let data = file.metadata()?;
        assert_eq!(report.totals.apparent_bytes, root.len() + data.len());
        assert_eq!(
            report.totals.allocated_bytes,
            (root.blocks() + data.blocks()) * 512
        );
        assert!(data.blocks() * 512 < data.len());
        assert_eq!(report.namespaces["a"].apparent_bytes, data.len());
        Ok(())
    }

    #[test]
    fn namespace_totals_match_and_measurement_leaves_files_unchanged() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        for name in ["chainstate", "blocks", "txindex"] {
            fs::create_dir(dir.path().join(name))?;
            fs::write(dir.path().join(name).join("data"), b"operator data")?;
        }
        let report = measure(dir.path())?;
        assert_eq!(report.namespaces.len(), 4);
        assert_eq!(
            report.totals.allocated_bytes,
            report
                .namespaces
                .values()
                .map(|b| b.allocated_bytes)
                .sum::<u64>()
        );
        for name in ["chainstate", "blocks", "txindex"] {
            assert_eq!(
                fs::read(dir.path().join(name).join("data"))?,
                b"operator data"
            );
            assert_eq!(fs::read_dir(dir.path().join(name))?.count(), 1);
        }
        Ok(())
    }

    #[test]
    fn refuses_symlinks_and_special_entries() -> io::Result<()> {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir()?;
        symlink(dir.path(), dir.path().with_extension("link"))?;
        assert!(measure(&dir.path().with_extension("link")).is_err());
        fs::remove_file(dir.path().with_extension("link"))?;
        symlink("/etc/passwd", dir.path().join("link"))?;
        assert!(measure(dir.path()).is_err());
        fs::remove_file(dir.path().join("link"))?;
        let _socket = UnixListener::bind(dir.path().join("socket"))?;
        assert!(measure(dir.path()).is_err());
        Ok(())
    }
}
