use super::{CheckpointError, EngineArtifactV1, EngineFileV1};
use bitcoin_rs_consensus::primitives::hex::hex_encode;
use cap_std::fs::Dir;
use sha2::{Digest, Sha256};
use std::io::Read;

/// Directory holding the engine image inside a checkpoint generation.
pub const ENGINE_IMAGE_DIR: &str = "chainstate";

const DIGEST_BUFFER_SIZE: usize = 64 * 1024;

/// Records every file under `store_dir` except lock and log names.
///
/// Refuses a non-empty write-ahead log: checkpoints flush first, so a WAL
/// carrying bytes is unflushed data.
pub fn digest_engine_dir(store_dir: &Dir) -> Result<EngineArtifactV1, CheckpointError> {
    let mut relative = Vec::new();
    collect_files(store_dir, &mut String::new(), &mut relative)?;
    relative.retain(|rel| !is_lock_or_log(rel.rsplit('/').next().unwrap_or(rel)));
    relative.sort();
    let mut files = Vec::with_capacity(relative.len());
    let mut total = 0_u64;
    for rel in &relative {
        let (bytes, sha256) = hash_file(store_dir, rel)?;
        if rel.rsplit('/').next().unwrap_or(rel).ends_with(".log") && bytes > 0 {
            return Err(CheckpointError::Invalid(format!(
                "checkpoint write-ahead log {rel:?} carries {bytes} unflushed bytes"
            )));
        }
        total = total
            .checked_add(bytes)
            .ok_or_else(|| CheckpointError::Invalid("engine image byte count overflow".into()))?;
        files.push(EngineFileV1 {
            file: rel.clone(),
            bytes,
            sha256: hex_encode(&sha256),
        });
    }
    let mut parts = Vec::with_capacity(files.len());
    for file in &files {
        parts.push(record_parts(file)?);
    }
    let sha256 = rollup(parts.into_iter())?;
    Ok(EngineArtifactV1 {
        dir: ENGINE_IMAGE_DIR.to_owned(),
        bytes: total,
        sha256: hex_encode(&sha256),
        files,
    })
}

/// Requires the on-disk image to match `expected` before the engine opens it.
///
/// A missing or changed recorded file, or an unrecorded file other than a
/// lock or log name, is corruption.
pub fn verify_engine_artifact(
    store_dir: &Dir,
    expected: &EngineArtifactV1,
) -> Result<(), CheckpointError> {
    if expected.dir != ENGINE_IMAGE_DIR {
        return Err(CheckpointError::Invalid(format!(
            "unexpected engine image dir {:?}",
            expected.dir
        )));
    }
    let actual = digest_engine_dir(store_dir)?;
    for wanted in &expected.files {
        let Some(got) = actual.files.iter().find(|got| got.file == wanted.file) else {
            return Err(CheckpointError::Invalid(format!(
                "checkpoint engine image {:?} is missing",
                wanted.file
            )));
        };
        if got.bytes != wanted.bytes || got.sha256 != wanted.sha256 {
            return Err(CheckpointError::Invalid(format!(
                "checkpoint engine image {:?} length or SHA256 mismatch",
                wanted.file
            )));
        }
    }
    let mut relative = Vec::new();
    collect_files(store_dir, &mut String::new(), &mut relative)?;
    for rel in relative {
        if is_lock_or_log(rel.rsplit('/').next().unwrap_or(&rel)) {
            continue;
        }
        if !expected.files.iter().any(|file| file.file == rel) {
            return Err(CheckpointError::Invalid(format!(
                "checkpoint engine image has an unrecorded file {rel:?}"
            )));
        }
    }
    let mut matched = Vec::with_capacity(expected.files.len());
    for wanted in &expected.files {
        let Some(got) = actual.files.iter().find(|got| got.file == wanted.file) else {
            return Err(CheckpointError::Invalid(format!(
                "checkpoint engine image {:?} is missing",
                wanted.file
            )));
        };
        matched.push(record_parts(got)?);
    }
    let mut expected_parts = Vec::with_capacity(expected.files.len());
    for file in &expected.files {
        expected_parts.push(record_parts(file)?);
    }
    let matched_rollup = rollup(matched.into_iter())?;
    let expected_rollup = rollup(expected_parts.into_iter())?;
    if matched_rollup != expected_rollup || hex_encode(&matched_rollup) != expected.sha256 {
        return Err(CheckpointError::Invalid(
            "checkpoint engine image digest mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn is_lock_or_log(name: &str) -> bool {
    name == "LOCK" || name == "LOG" || name.starts_with("LOG.old")
}

fn record_parts(file: &EngineFileV1) -> Result<(&str, u64, [u8; 32]), CheckpointError> {
    Ok((file.file.as_str(), file.bytes, decode_sha256(&file.sha256)?))
}

fn rollup<'a>(
    files: impl Iterator<Item = (&'a str, u64, [u8; 32])>,
) -> Result<[u8; 32], CheckpointError> {
    let mut hasher = Sha256::new();
    for (file, bytes, sha256) in files {
        hasher.update(file.as_bytes());
        hasher.update([0]);
        hasher.update(bytes.to_le_bytes());
        hasher.update(sha256);
    }
    Ok(hasher.finalize().into())
}

fn decode_sha256(encoded: &str) -> Result<[u8; 32], CheckpointError> {
    let invalid =
        || CheckpointError::Invalid("checkpoint engine image has a malformed SHA256".to_owned());
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut out = [0_u8; 32];
    for (index, chunk) in encoded.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| invalid())?;
        out[index] = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
    }
    Ok(out)
}

fn collect_files(
    dir: &Dir,
    prefix: &mut String,
    out: &mut Vec<String>,
) -> Result<(), CheckpointError> {
    let mut names = Vec::new();
    for entry in dir.entries().map_err(CheckpointError::from)? {
        let entry = entry.map_err(CheckpointError::from)?;
        let name = entry.file_name().into_string().map_err(|_| {
            CheckpointError::Invalid("checkpoint engine image has a non-UTF8 file name".into())
        })?;
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(CheckpointError::Invalid(format!(
                "checkpoint engine image has an unsupported file name {name:?}"
            )));
        }
        names.push(name);
    }
    names.sort();
    for name in names {
        let file_type = dir
            .symlink_metadata(&name)
            .map_err(CheckpointError::from)?
            .file_type();
        if file_type.is_symlink() {
            return Err(CheckpointError::Invalid(format!(
                "checkpoint engine image contains a symlink {name:?}"
            )));
        }
        if file_type.is_dir() {
            let child = dir.open_dir(&name).map_err(CheckpointError::from)?;
            let saved = prefix.len();
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(&name);
            collect_files(&child, prefix, out)?;
            prefix.truncate(saved);
        } else if file_type.is_file() {
            if is_lock_or_log(&name) {
                continue;
            }
            if prefix.is_empty() {
                out.push(name);
            } else {
                out.push(format!("{prefix}/{name}"));
            }
        } else {
            return Err(CheckpointError::Invalid(format!(
                "checkpoint engine image contains an unsupported file type {name:?}"
            )));
        }
    }
    Ok(())
}

fn hash_open_error(relative: &str, error: std::io::Error) -> CheckpointError {
    CheckpointError::Invalid(format!(
        "checkpoint engine image file {relative:?} failed: {error}"
    ))
}

fn hash_file(root: &Dir, relative: &str) -> Result<(u64, [u8; 32]), CheckpointError> {
    let mut components: Vec<&str> = relative.split('/').collect();
    let leaf = components.pop().ok_or_else(|| {
        CheckpointError::Invalid("checkpoint engine image has an empty file name".into())
    })?;
    let mut stack: Vec<Dir> = Vec::new();
    let mut current = root;
    for component in components {
        let child = current
            .open_dir(component)
            .map_err(|error| hash_open_error(relative, error))?;
        stack.push(child);
        current = stack.last().ok_or_else(|| {
            CheckpointError::Invalid(
                "checkpoint engine image traversal lost its directory handle".into(),
            )
        })?;
    }
    let mut file = current
        .open(leaf)
        .map_err(|error| hash_open_error(relative, error))?;
    if file.metadata().map_err(CheckpointError::from)?.len() > super::MAX_CHECKPOINT_PAYLOAD_BYTES {
        return Err(CheckpointError::Invalid(format!(
            "checkpoint engine image file {relative:?} exceeds the payload bound"
        )));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; DIGEST_BUFFER_SIZE];
    let mut bytes = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| hash_open_error(relative, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| CheckpointError::Invalid("engine image byte count overflow".into()))?;
    }
    Ok((bytes, hasher.finalize().into()))
}
