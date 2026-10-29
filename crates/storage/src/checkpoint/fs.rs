use std::io::{self, Read, Write};
use std::path::Path;

use cap_fs_ext::{
    DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt, OpenOptionsSyncExt,
};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};

pub const CURRENT_SCHEMA_FILE: &str = "CURRENT_SCHEMA";
pub const DATA_DIR_LOCK_FILE: &str = ".lock";
const CURRENT_SCHEMA_TEMP_FILE: &str = ".CURRENT_SCHEMA.tmp";
const CURRENT_SCHEMA_VERSION: u32 = 2;

pub fn open_data_dir(path: &Path) -> io::Result<Dir> {
    Dir::open_ambient_dir(path, ambient_authority())
}

pub fn ensure_current_schema(data: &Dir) -> io::Result<()> {
    match read_file(data, CURRENT_SCHEMA_FILE, 16) {
        Ok(bytes) => validate_current_schema(&bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut stale_temp = false;
            let mut has_other_entry = false;
            for entry in data.entries()? {
                let entry = entry?;
                match entry.file_name().to_str() {
                    Some(name) if name == CURRENT_SCHEMA_TEMP_FILE => stale_temp = true,
                    Some(name) if name == DATA_DIR_LOCK_FILE => {
                        if !entry.file_type()?.is_file() {
                            has_other_entry = true;
                        }
                    }
                    _ => has_other_entry = true,
                }
            }
            if has_other_entry {
                return Err(incompatible_schema(
                    "datadir has no CURRENT_SCHEMA marker and is implicitly schema epoch 0, which is not current",
                ));
            }
            if stale_temp {
                data.remove_file(CURRENT_SCHEMA_TEMP_FILE)?;
            }

            let mut marker = create_file(data, CURRENT_SCHEMA_TEMP_FILE)?;
            let bytes = current_schema_bytes();
            marker.write_all(&bytes)?;
            marker.sync_all()?;
            drop(marker);
            data.rename(CURRENT_SCHEMA_TEMP_FILE, data, CURRENT_SCHEMA_FILE)?;
            sync_dir(data)
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Err(incompatible_schema(
            format!("invalid CURRENT_SCHEMA: {error}"),
        )),
        Err(error) => Err(error),
    }
}

fn validate_current_schema(bytes: &[u8]) -> io::Result<()> {
    if bytes == current_schema_bytes().as_slice() {
        return Ok(());
    }
    Err(incompatible_schema(
        "CURRENT_SCHEMA is not the current datadir schema epoch",
    ))
}

/// Returns the newline-terminated bytes for the current schema marker.
pub fn current_schema_bytes() -> Vec<u8> {
    let mut bytes = CURRENT_SCHEMA_VERSION.to_string().into_bytes();
    bytes.push(b'\n');
    bytes
}

fn incompatible_schema(reason: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{}; remove or replace the datadir and restart to perform a full resync",
            reason.into()
        ),
    )
}

pub(crate) struct CheckpointRoot {
    dir: Dir,
}

impl CheckpointRoot {
    pub(crate) fn dir(&self) -> &Dir {
        &self.dir
    }
    pub(crate) fn open_existing(data: &Dir, name: &str) -> io::Result<Option<Self>> {
        match data.open_dir_nofollow(name) {
            Ok(dir) => Ok(Some(Self { dir })),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn open_or_create(data: &Dir, name: &str) -> io::Result<Self> {
        match data.open_dir_nofollow(name) {
            Ok(dir) => Ok(Self { dir }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match data.create_dir(name) {
                    Ok(()) => sync_dir(data)?,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error),
                }
                Ok(Self {
                    dir: data.open_dir_nofollow(name)?,
                })
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn open_dir(&self, name: &str) -> io::Result<Dir> {
        self.dir.open_dir_nofollow(name)
    }

    pub(crate) fn create_dir(&self, name: &str) -> io::Result<Dir> {
        self.dir.create_dir(name)?;
        self.dir.open_dir_nofollow(name)
    }

    pub(crate) fn create_file(&self, name: &str) -> io::Result<File> {
        create_file(&self.dir, name)
    }

    pub(crate) fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.dir.rename(from, &self.dir, to)
    }

    pub(crate) fn sync(&self) -> io::Result<()> {
        sync_dir(&self.dir)
    }

    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    pub(crate) fn entry_exists(&self, name: &str) -> io::Result<bool> {
        match self.dir.symlink_metadata(name) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn entries(&self) -> io::Result<cap_std::fs::ReadDir> {
        self.dir.entries()
    }

    pub(crate) fn remove_file(&self, name: &str) -> io::Result<()> {
        self.dir.remove_file(name)
    }

    pub(crate) fn remove_dir(&self, name: &str) -> io::Result<()> {
        self.dir.remove_dir(name)
    }
}

pub const HAS_ATOMIC_NOREPLACE_RENAME: bool = cfg!(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
));

/// Renames `from` to `to` inside `dir` in one filesystem step that fails with
/// [`io::ErrorKind::AlreadyExists`] instead of replacing an existing `to`.
#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
pub fn rename_noreplace(dir: &Dir, from: &str, to: &str) -> io::Result<()> {
    check_confined_endpoint(from)?;
    check_confined_endpoint(to)?;
    rustix::fs::renameat_with(dir, from, dir, to, rustix::fs::RenameFlags::NOREPLACE)
        .map_err(Into::into)
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
pub fn rename_noreplace(_dir: &Dir, _from: &str, _to: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this platform has no atomic no-replace rename",
    ))
}

pub fn create_file(dir: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    dir.open_with(name, &options)
}

pub fn open_file(dir: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = dir.open_with(name, &options)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint entry {name:?} is not a regular file"),
        ));
    }
    Ok(file)
}

pub fn read_file(dir: &Dir, name: &str, limit: u64) -> io::Result<Vec<u8>> {
    let mut file = open_file(dir, name)?;
    let length = file.metadata()?.len();
    if length > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint entry {name:?} exceeds its size bound"),
        ));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "checkpoint file is too large"))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).ok() != Some(length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint entry {name:?} changed while it was read"),
        ));
    }
    Ok(bytes)
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
pub fn sync_dir(dir: &Dir) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    dir.open_with(".", &options)?.sync_all()
}

#[cfg(windows)]
pub fn sync_dir(dir: &Dir) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    dir.open_with(".", &options)?.sync_all()
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    windows
)))]
pub fn sync_dir(_dir: &Dir) -> io::Result<()> {
    Ok(())
}

/// Rejects any rename endpoint that could resolve outside the checkpoint root.
fn check_confined_endpoint(name: &str) -> io::Result<()> {
    fn invalid(name: &str, reason: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("checkpoint rename endpoint {name:?} is not confined: {reason}"),
        )
    }
    if name.is_empty() {
        return Err(invalid(name, "empty name"));
    }
    if name.contains('\0') {
        return Err(invalid(name, "NUL byte"));
    }
    if name.contains('/') {
        return Err(invalid(name, "path separator"));
    }
    let mut components = Path::new(name).components();
    match components.next() {
        Some(std::path::Component::Normal(_)) => {}
        _ => return Err(invalid(name, "not a single normal component")),
    }
    if components.next().is_some() {
        return Err(invalid(name, "nested path"));
    }
    Ok(())
}

pub(crate) fn remove_known_dir(root: &CheckpointRoot, name: &str) -> io::Result<()> {
    let dir = root.open_dir(name)?;
    for entry in dir.entries()? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let file_type = entry.file_type()?;
        if file_type.is_file() {
            dir.remove_file(file_name)?;
        }
    }
    drop(dir);
    root.remove_dir(name)
}
