use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub(crate) enum TempDirMountError {
    #[error("resolve the temporary directory: {0}")]
    Resolve(std::io::Error),
    #[error("read /proc/self/mounts: {0}")]
    Mounts(std::io::Error),
    #[error("no mount holds {0}")]
    NoMount(String),
    #[error("{path} is on {fstype}: set TMPDIR to a disk-backed directory")]
    Volatile { path: String, fstype: String },
}

#[derive(Debug)]
pub(crate) struct TempDirMount {
    pub(crate) temp_dir: PathBuf,
    pub(crate) device: String,
    pub(crate) mount_point: String,
    pub(crate) fstype: String,
}

pub(crate) fn require_disk_backed_temp_dir() -> Result<TempDirMount, TempDirMountError> {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .map_err(TempDirMountError::Resolve)?;
    let mounts = std::fs::read_to_string("/proc/self/mounts").map_err(TempDirMountError::Mounts)?;
    let (device, mount_point, fstype) = mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let device = fields.next()?;
            let mount_point = fields.next()?;
            let fstype = fields.next()?;
            temp_dir
                .starts_with(mount_point)
                .then_some((device, mount_point, fstype))
        })
        .max_by_key(|(_, mount_point, _)| mount_point.len())
        .ok_or_else(|| TempDirMountError::NoMount(temp_dir.display().to_string()))?;
    if matches!(fstype, "tmpfs" | "ramfs") {
        return Err(TempDirMountError::Volatile {
            path: temp_dir.display().to_string(),
            fstype: fstype.to_owned(),
        });
    }
    Ok(TempDirMount {
        temp_dir,
        device: device.to_owned(),
        mount_point: mount_point.to_owned(),
        fstype: fstype.to_owned(),
    })
}
