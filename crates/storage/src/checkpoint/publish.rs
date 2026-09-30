use super::format::{
    generation_name, valid_current_temp_name, valid_generation_name, valid_staging_name,
};
use super::fs::{CheckpointRoot, create_file, remove_known_dir};
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
use super::io::rename_generation;
use super::io::{rename_current, sync_checkpoint_dir, sync_file, sync_root, write_file};
use super::load::read_current;
use super::{
    CHECKPOINT_ROOT, CURRENT_FORMAT, CURRENT_VERSION, CheckpointError, CheckpointFailpoint,
    CheckpointManifestV1, CurrentV1, GenerationPaths, HashingWriter, MANIFEST_FILE,
};
use bitcoin_rs_primitives::hex_encode;
use cap_std::fs::Dir;
use sha2::{Digest, Sha256};
use std::io::Write;

/// Size and SHA-256 digest produced while writing one checkpoint artifact.
pub struct ArtifactDigest {
    /// Number of artifact bytes written.
    pub bytes: u64,
    /// SHA-256 digest of the written bytes.
    pub sha256: [u8; 32],
}
/// Capability-scoped staging state for one checkpoint generation.
pub struct CheckpointStage {
    pub(crate) root: CheckpointRoot,
    pub(crate) staging: Dir,
    pub(crate) generation: u64,
    pub(crate) paths: GenerationPaths,
    pub(crate) failpoint: Option<CheckpointFailpoint>,
}
impl CheckpointStage {
    /// Returns the generation reserved by this staging transaction.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Writes, hashes, and synchronizes one staged artifact.
    pub fn write_artifact<T, E: From<CheckpointError>>(
        &self,
        name: &str,
        write_failpoint: CheckpointFailpoint,
        sync_failpoint: CheckpointFailpoint,
        write: impl FnOnce(&mut dyn std::io::Write) -> Result<T, E>,
    ) -> Result<(T, ArtifactDigest), E> {
        let mut file =
            create_file(&self.staging, name).map_err(|e| E::from(CheckpointError::from(e)))?;
        let mut writer = HashingWriter::new(&mut file, self.failpoint, write_failpoint);
        let value = write(&mut writer)?;
        let (bytes, sha256) = writer
            .finish()
            .map_err(|e| E::from(CheckpointError::from(e)))?;
        sync_file(&file, self.failpoint, sync_failpoint).map_err(|e| E::from(e))?;
        Ok((value, ArtifactDigest { bytes, sha256 }))
    }
}
/// Reserves a new generation directory and opens its staging transaction.
pub fn begin_publication(
    data_dir: &Dir,
    failpoint: Option<CheckpointFailpoint>,
) -> Result<CheckpointStage, CheckpointError> {
    let root = CheckpointRoot::open_or_create(data_dir, CHECKPOINT_ROOT)?;
    let current_generation = match read_current(&root)? {
        Some(current) => current.generation,
        None => 0,
    };
    let (generation, paths, staging) = allocate_generation(&root, current_generation)?;
    Ok(CheckpointStage {
        root,
        staging,
        generation,
        paths,
        failpoint,
    })
}
/// Atomically publishes a staged generation through CURRENT.
pub fn commit_publication(
    stage: CheckpointStage,
    manifest: &CheckpointManifestV1,
) -> Result<u64, CheckpointError> {
    let CheckpointStage {
        root,
        staging,
        generation,
        paths,
        failpoint,
    } = stage;
    // Caller built the manifest for a different generation than the stage
    // reserved; publishing it would make CURRENT point at an unreadable checkpoint.
    if manifest.generation != generation {
        return Err(CheckpointError::Invalid(format!(
            "manifest generation {} does not match staged generation {generation}",
            manifest.generation
        )));
    }
    let manifest_bytes = serde_json::to_vec(manifest)?;
    let mut mf = create_file(&staging, MANIFEST_FILE)?;
    write_file(
        &mut mf,
        &manifest_bytes,
        failpoint,
        CheckpointFailpoint::ManifestWrite,
    )?;
    mf.flush()?;
    sync_file(&mf, failpoint, CheckpointFailpoint::ManifestSync)?;
    sync_checkpoint_dir(&staging, failpoint, CheckpointFailpoint::StageSync)?;
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    rename_generation(
        &root,
        &paths.staging,
        &paths.final_dir,
        failpoint,
        CheckpointFailpoint::GenerationRename,
    )?;
    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    )))]
    super::io::injected_io(failpoint, CheckpointFailpoint::GenerationRename)?;
    sync_root(&root, failpoint, CheckpointFailpoint::GenerationRootSync)?;
    let current = CurrentV1 {
        format: CURRENT_FORMAT.to_owned(),
        version: CURRENT_VERSION,
        generation,
        directory: paths.directory.clone(),
        manifest_sha256: hex_encode(&Sha256::digest(&manifest_bytes)),
    };
    let current_bytes = serde_json::to_vec(&current)?;
    let mut cf = root.create_file(&paths.current_temp)?;
    write_file(
        &mut cf,
        &current_bytes,
        failpoint,
        CheckpointFailpoint::CurrentTempWrite,
    )?;
    cf.flush()?;
    sync_file(&cf, failpoint, CheckpointFailpoint::CurrentTempSync)?;
    rename_current(
        &root,
        &paths.current_temp,
        failpoint,
        CheckpointFailpoint::CurrentRename,
    )?;
    sync_root(&root, failpoint, CheckpointFailpoint::CurrentRootSync)?;
    cleanup_after_publication(&root, &paths.directory);
    Ok(generation)
}
fn allocate_generation(
    root: &CheckpointRoot,
    current_generation: u64,
) -> Result<(u64, GenerationPaths, Dir), CheckpointError> {
    let mut generation = current_generation.checked_add(1).ok_or_else(|| {
        CheckpointError::Invalid("checkpoint generation exhausted u64".to_owned())
    })?;
    loop {
        let paths = generation_paths(generation);
        #[cfg(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        ))]
        if root.entry_exists(&paths.final_dir)? || root.entry_exists(&paths.current_temp)? {
            generation = generation.checked_add(1).ok_or_else(|| {
                CheckpointError::Invalid("checkpoint generation exhausted u64".to_owned())
            })?;
            continue;
        }
        #[cfg(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        ))]
        let name = &paths.staging;
        #[cfg(not(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        )))]
        let name = &paths.final_dir;
        match root.create_dir(name) {
            Ok(dir) => return Ok((generation, paths, dir)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                generation = generation.checked_add(1).ok_or_else(|| {
                    CheckpointError::Invalid("checkpoint generation exhausted u64".to_owned())
                })?;
            }
            Err(e) => return Err(e.into()),
        }
    }
}
fn generation_paths(generation: u64) -> GenerationPaths {
    let directory = generation_name(generation);
    GenerationPaths {
        #[cfg(any(
            target_vendor = "apple",
            target_os = "linux",
            target_os = "android",
            target_os = "redox"
        ))]
        staging: format!(".{directory}.tmp"),
        final_dir: directory.clone(),
        current_temp: format!(".CURRENT-{generation:020}.tmp"),
        directory,
    }
}
fn cleanup_after_publication(root: &CheckpointRoot, current: &str) {
    let entries = match root.entries() {
        Ok(entries) => entries,
        Err(error) => {
            // Directory enumeration failed while retiring stale generations.
            tracing::warn!(%error, "failed to enumerate checkpoint cleanup entries");
            return;
        }
    };
    let mut attempted = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                // An entry could not be inspected during cleanup.
                tracing::warn!(%error, "failed to inspect checkpoint cleanup entry");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                // File type inspection failed for a cleanup entry.
                tracing::warn!(%error, entry = name, "failed to classify checkpoint cleanup entry");
                continue;
            }
        };
        let result = if file_type.is_dir()
            && name != current
            && (valid_generation_name(name) || valid_staging_name(name))
        {
            attempted = true;
            remove_known_dir(root, name)
        } else if file_type.is_file() && valid_current_temp_name(name) {
            attempted = true;
            root.remove_file(name)
        } else {
            continue;
        };
        if let Err(error) = result {
            // Removing a stale generation or CURRENT temporary failed.
            tracing::warn!(%error, entry = name, "failed to remove checkpoint cleanup entry");
        }
    }
    if attempted {
        if let Err(error) = root.sync() {
            // Cleanup completed but its directory durability barrier failed.
            tracing::warn!(%error, "failed to sync checkpoint directory after cleanup");
        }
    }
}
