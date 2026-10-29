//! Read-only, single-pass measurement of a stopped node's data directory.
//!
//! In `bitcoin-rs-storage-allocation-v1`, the `namespaces` key `"."` accounts
//! only for the root directory itself. Other keys account for each top-level
//! entry and its descendants, with hard-linked inodes counted only once.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{AtFlags, CWD, StatxFlags};
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

/// Datadirs are only a few levels deep; the cap keeps a mis-pointed root
/// from recursing without bound and exhausting the stack.
const MAX_DEPTH: u32 = 32;

pub(super) fn measure(root: &Path) -> io::Result<Report> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() {
        return Err(io::Error::other("data directory must be a real directory"));
    }
    let mount = mount_id(root)?;
    let mut report = Report {
        format: "bitcoin-rs-storage-allocation-v1",
        observation: "offline_snapshot_lower_bound",
        totals: Bytes::default(),
        namespaces: BTreeMap::new(),
    };
    let mut seen = HashSet::new();
    visit(root, ".", metadata.dev(), mount, &mut seen, &mut report, 0)?;
    Ok(report)
}

fn mount_id(path: &Path) -> io::Result<u64> {
    let metadata = rustix::fs::statx(
        CWD,
        path,
        AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::MNT_ID,
    )?;
    if !StatxFlags::from_bits_retain(metadata.stx_mask).contains(StatxFlags::MNT_ID) {
        return Err(io::Error::other(format!(
            "mount identity is unavailable for {}",
            path.display()
        )));
    }
    Ok(metadata.stx_mnt_id)
}

fn visit(
    path: &Path,
    namespace: &str,
    device: u64,
    mount: u64,
    seen: &mut HashSet<(u64, u64)>,
    report: &mut Report,
    depth: u32,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !(metadata.is_dir() || metadata.is_file())
        || metadata.dev() != device
        || mount_id(path)? != mount
    {
        return Err(io::Error::other(format!(
            "unsupported entry or mount crossing: {}",
            path.display()
        )));
    }
    // Preserve the complete top-level inventory even when this path aliases
    // an inode whose bytes were assigned to an earlier namespace.
    report.namespaces.entry(namespace.to_owned()).or_default();
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
        if depth >= MAX_DEPTH {
            return Err(io::Error::other(format!(
                "directory nesting exceeds {MAX_DEPTH} at {}",
                path.display()
            )));
        }
        // Entries stream one at a time so a wide directory is never
        // materialized in memory. Totals are order-independent; a
        // cross-namespace hard link's bytes follow first-visit order.
        for entry in fs::read_dir(path)? {
            let entry = entry?;
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
            visit(
                &entry.path(),
                child_namespace,
                device,
                mount,
                seen,
                report,
                depth + 1,
            )?;
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
        // This creates a sparse file where supported; allocation is determined
        // by the filesystem, not required to be smaller than the file length.
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
        // Entries stream in readdir order, so either namespace may own the
        // shared inode; exactly one of them must, and totals stay exact.
        assert_eq!(
            report.namespaces["a"].apparent_bytes + report.namespaces["b"].apparent_bytes,
            data.len()
        );
        assert_eq!(
            report.namespaces["a"].allocated_bytes + report.namespaces["b"].allocated_bytes,
            data.blocks() * 512
        );
        assert!(
            (report.namespaces["a"].apparent_bytes == data.len()
                && report.namespaces["b"].apparent_bytes == 0)
                || (report.namespaces["b"].apparent_bytes == data.len()
                    && report.namespaces["a"].apparent_bytes == 0)
        );
        Ok(())
    }

    #[test]
    fn nesting_beyond_max_depth_is_refused() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut parent = dir.path().to_path_buf();
        for level in 0..=MAX_DEPTH {
            parent = parent.join(format!("level{level}"));
            fs::create_dir(&parent)?;
        }
        fs::write(parent.join("data"), b"too deep")?;
        let failure = match measure(dir.path()) {
            Ok(_) => return Err(io::Error::other("deep nesting was accepted")),
            Err(failure) => failure,
        };
        assert!(
            failure.to_string().contains("nesting exceeds"),
            "unexpected error: {failure}"
        );
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
        let root = fs::metadata(dir.path())?;
        assert_eq!(report.namespaces["."].apparent_bytes, root.len());
        assert_eq!(report.namespaces["."].allocated_bytes, root.blocks() * 512);
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
