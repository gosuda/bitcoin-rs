#[cfg(any(test, feature = "test-seam"))]
use super::CheckpointFailpoint;
use super::format::{
    generation_name, valid_current_temp_name, valid_generation_name, valid_staging_name,
};
use super::fs::{CheckpointRoot, create_file, remove_known_dir};
#[cfg(any(test, feature = "test-seam"))]
use super::io::injected_io;
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
    CURRENT_FORMAT, CURRENT_VERSION, CheckpointError, CheckpointManifestV1, CurrentV1,
    GenerationPaths, HashingWriter, MANIFEST_FILE,
};
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
    retain_generations: bool,
    #[cfg(any(test, feature = "test-seam"))]
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
        write: impl FnOnce(&mut dyn std::io::Write) -> Result<T, E>,
    ) -> Result<(T, ArtifactDigest), E> {
        self.write_artifact_inner(
            name,
            #[cfg(any(test, feature = "test-seam"))]
            None,
            write,
        )
    }

    /// Writes an artifact while arming its test-only write and sync boundaries.
    #[cfg(any(test, feature = "test-seam"))]
    pub fn write_artifact_with_failpoints<T, E: From<CheckpointError>>(
        &self,
        name: &str,
        write_failpoint: CheckpointFailpoint,
        sync_failpoint: CheckpointFailpoint,
        write: impl FnOnce(&mut dyn std::io::Write) -> Result<T, E>,
    ) -> Result<(T, ArtifactDigest), E> {
        self.write_artifact_inner(name, Some((write_failpoint, sync_failpoint)), write)
    }

    fn write_artifact_inner<T, E: From<CheckpointError>>(
        &self,
        name: &str,
        #[cfg(any(test, feature = "test-seam"))] failpoints: Option<(
            CheckpointFailpoint,
            CheckpointFailpoint,
        )>,
        write: impl FnOnce(&mut dyn std::io::Write) -> Result<T, E>,
    ) -> Result<(T, ArtifactDigest), E> {
        let mut file =
            create_file(&self.staging, name).map_err(|e| E::from(CheckpointError::from(e)))?;
        #[cfg(any(test, feature = "test-seam"))]
        let mut writer = HashingWriter::new(
            &mut file,
            self.failpoint,
            failpoints.map(|(write_failpoint, _)| write_failpoint),
        );
        #[cfg(not(any(test, feature = "test-seam")))]
        let mut writer = HashingWriter::new(&mut file);
        let value = write(&mut writer)?;
        let (bytes, sha256) = writer
            .finish()
            .map_err(|e| E::from(CheckpointError::from(e)))?;
        #[cfg(any(test, feature = "test-seam"))]
        if let Some((_, sync_failpoint)) = failpoints {
            injected_io(self.failpoint, sync_failpoint)
                .map_err(|e| E::from(CheckpointError::from(e)))?;
        }
        sync_file(&file).map_err(|e| E::from(e))?;
        Ok((value, ArtifactDigest { bytes, sha256 }))
    }
}
/// Reserves a new generation directory and opens its staging transaction.
pub fn begin_publication(data_dir: &Dir) -> Result<CheckpointStage, CheckpointError> {
    begin_publication_at(data_dir, super::CHECKPOINT_ROOT)
}

/// Reserves a generation in an explicit checkpoint namespace.
pub fn begin_publication_at(
    data_dir: &Dir,
    root_name: &str,
) -> Result<CheckpointStage, CheckpointError> {
    begin_publication_inner(
        data_dir,
        root_name,
        #[cfg(any(test, feature = "test-seam"))]
        None,
    )
}

/// Reserves a staging transaction with an optional test-only failure boundary.
#[cfg(any(test, feature = "test-seam"))]
pub fn begin_publication_with_failpoint(
    data_dir: &Dir,
    failpoint: Option<CheckpointFailpoint>,
) -> Result<CheckpointStage, CheckpointError> {
    begin_publication_at_with_failpoint(data_dir, super::CHECKPOINT_ROOT, failpoint)
}

/// Reserves a generation in an explicit checkpoint namespace with a test-only
/// failure boundary armed.
#[cfg(any(test, feature = "test-seam"))]
pub fn begin_publication_at_with_failpoint(
    data_dir: &Dir,
    root_name: &str,
    failpoint: Option<CheckpointFailpoint>,
) -> Result<CheckpointStage, CheckpointError> {
    begin_publication_inner(data_dir, root_name, failpoint)
}

fn begin_publication_inner(
    data_dir: &Dir,
    root_name: &str,
    #[cfg(any(test, feature = "test-seam"))] failpoint: Option<CheckpointFailpoint>,
) -> Result<CheckpointStage, CheckpointError> {
    let root = CheckpointRoot::open_or_create(data_dir, root_name)?;
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
        retain_generations: root_name == super::HISTORICAL_CHECKPOINT_ROOT,
        #[cfg(any(test, feature = "test-seam"))]
        failpoint,
    })
}

/// Atomically publishes a staged generation through CURRENT.
///
/// The write → flush → sync → rename → sync-root barrier sequence exists
/// exactly once; under `test`/`test-seam` each boundary is armed through
/// `injected_io` immediately before the operation it names, so a failpoint
/// run exercises this same sequence.
pub fn commit_publication(
    stage: CheckpointStage,
    manifest: &CheckpointManifestV1,
) -> Result<u64, CheckpointError> {
    #[cfg(any(test, feature = "test-seam"))]
    let failpoint = stage.failpoint;
    let CheckpointStage {
        root,
        staging,
        generation,
        paths,
        retain_generations,
        ..
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
    #[cfg(any(test, feature = "test-seam"))]
    injected_io(failpoint, CheckpointFailpoint::ManifestWrite)?;
    write_file(&mut mf, &manifest_bytes)?;
    mf.flush()?;
    #[cfg(any(test, feature = "test-seam"))]
    injected_io(failpoint, CheckpointFailpoint::ManifestSync)?;
    sync_file(&mf)?;
    #[cfg(any(test, feature = "test-seam"))]
    injected_io(failpoint, CheckpointFailpoint::StageSync)?;
    sync_checkpoint_dir(&staging)?;
    #[cfg(any(test, feature = "test-seam"))]
    injected_io(failpoint, CheckpointFailpoint::GenerationRename)?;
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    rename_generation(&root, &paths.staging, &paths.final_dir)?;
    #[cfg(any(test, feature = "test-seam"))]
    injected_io(failpoint, CheckpointFailpoint::GenerationRootSync)?;
    sync_root(&root)?;
    let current = CurrentV1 {
        format: CURRENT_FORMAT.to_owned(),
        version: CURRENT_VERSION,
        generation,
        directory: paths.directory.clone(),
        manifest_sha256: super::format::hex_encode(&Sha256::digest(&manifest_bytes)),
    };
    let current_bytes = serde_json::to_vec(&current)?;
    let mut cf = root.create_file(&paths.current_temp)?;
    #[cfg(any(test, feature = "test-seam"))]
    injected_io(failpoint, CheckpointFailpoint::CurrentTempWrite)?;
    write_file(&mut cf, &current_bytes)?;
    cf.flush()?;
    #[cfg(any(test, feature = "test-seam"))]
    injected_io(failpoint, CheckpointFailpoint::CurrentTempSync)?;
    sync_file(&cf)?;
    #[cfg(any(test, feature = "test-seam"))]
    injected_io(failpoint, CheckpointFailpoint::CurrentRename)?;
    rename_current(&root, &paths.current_temp)?;
    #[cfg(any(test, feature = "test-seam"))]
    injected_io(failpoint, CheckpointFailpoint::CurrentRootSync)?;
    sync_root(&root)?;
    if !retain_generations {
        cleanup_after_publication(&root, &paths.directory);
    }
    Ok(generation)
}
/// Retires historical generations only after the authoritative head accepts
/// `generation`. Cleanup failure leaves recoverable extra files in place.
pub fn retire_historical_checkpoints(
    data_dir: &Dir,
    generation: u64,
) -> Result<(), CheckpointError> {
    if let Some(root) = CheckpointRoot::open_existing(data_dir, super::HISTORICAL_CHECKPOINT_ROOT)?
    {
        cleanup_after_publication(&root, &generation_name(generation));
    }
    Ok(())
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
