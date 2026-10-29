use std::io::{self, Read};
use std::path::Path;

use parking_lot::RwLock;

use crate::{FeeEstimator, Mempool};

const HISTORY_FILE: &str = "fee-estimator-history.dat";
const HISTORY_TEMP: &str = "fee-estimator-history.dat.tmp";
const MAX_HISTORY_FILE_BYTES: u64 = 64 * 1024 * 1024;

fn read_history(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::other("history is not a regular file"));
    }
    if metadata.len() > MAX_HISTORY_FILE_BYTES {
        return Err(io::Error::other("exceeds the version-1 size bound"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_HISTORY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_HISTORY_FILE_BYTES {
        return Err(io::Error::other("exceeds the version-1 size bound"));
    }
    Ok(Some(bytes))
}

pub fn load(data_dir: &Path, mempool: &RwLock<Mempool>) {
    let path = data_dir.join(HISTORY_FILE);
    let bytes = match read_history(&path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            tracing::debug!(
                path = %path.display(),
                "no fee-estimator history: starting with insufficient data"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "fee-estimator history is unreadable; degrading to insufficient data and leaving the file in place"
            );
            return;
        }
    };
    match FeeEstimator::from_history_bytes(&bytes) {
        Ok(history) => {
            mempool.write().adopt_estimator_history(history);
            tracing::info!(
                path = %path.display(),
                bytes = bytes.len(),
                "restored fee-estimator history"
            );
        }
        Err(reject) => tracing::warn!(
            path = %path.display(),
            ?reject,
            "fee-estimator history rejected; degrading to insufficient data and leaving the file in place"
        ),
    }
}

pub fn save(data_dir: &Path, history_bytes: &[u8]) {
    let temp_path = data_dir.join(HISTORY_TEMP);
    let live_path = data_dir.join(HISTORY_FILE);
    let result = (|| -> std::io::Result<Option<usize>> {
        match std::fs::remove_file(&temp_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        match read_history(&live_path) {
            Ok(Some(bytes)) => {
                if let Err(reject) = FeeEstimator::from_history_bytes(&bytes) {
                    tracing::warn!(
                        path = %live_path.display(),
                        ?reject,
                        "fee-estimator history rejected; leaving the file in place without saving"
                    );
                    return Ok(None);
                }
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(
                    path = %live_path.display(),
                    %error,
                    "fee-estimator history is unreadable; leaving the file in place without saving"
                );
                return Ok(None);
            }
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        std::io::Write::write_all(&mut file, history_bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, &live_path)?;
        if let Ok(dir) = std::fs::File::open(data_dir) {
            let _ = dir.sync_all();
        }
        Ok(Some(history_bytes.len()))
    })();
    match result {
        Ok(Some(bytes)) => tracing::info!(
            path = %live_path.display(),
            bytes,
            "saved fee-estimator history"
        ),
        Ok(None) => {}
        Err(error) => tracing::warn!(
            path = %live_path.display(),
            %error,
            "failed to save fee-estimator history; the node still shuts down cleanly"
        ),
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
