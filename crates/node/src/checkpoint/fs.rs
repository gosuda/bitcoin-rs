use std::io::{self, Read, Write};
use std::path::Path;

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
use cap_fs_ext::OpenOptionsMaybeDirExt;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};

/// Name of the datadir-wide clean-cutover schema marker.
pub(crate) const CURRENT_SCHEMA_FILE: &str = "CURRENT_SCHEMA";
const CURRENT_SCHEMA_TEMP_FILE: &str = ".CURRENT_SCHEMA.tmp";
const CURRENT_SCHEMA_VERSION: u32 = 0;
// This serialized marker is the single source of truth for the current
// persistent format epoch. Increment it for a schema-breaking storage change;
// no converter or compatibility reader accompanies the bump.

pub(crate) fn open_data_dir(path: &Path) -> io::Result<Dir> {
    Dir::open_ambient_dir(path, ambient_authority())
}

/// Opens the current datadir epoch. A non-empty directory without the marker is
/// treated as baseline epoch 0 and adopted only while epoch 0 is current; a
/// later schema epoch rejects it and requires an explicit resync.
pub(crate) fn ensure_current_schema(data: &Dir) -> io::Result<()> {
    match read_file(data, CURRENT_SCHEMA_FILE, 16) {
        Ok(bytes) => validate_current_schema(&bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut stale_temp = false;
            let mut has_other_entry = false;
            for entry in data.entries()? {
                let entry = entry?;
                if entry.file_name().to_str() == Some(CURRENT_SCHEMA_TEMP_FILE) {
                    stale_temp = true;
                } else {
                    has_other_entry = true;
                }
            }
            if has_other_entry && CURRENT_SCHEMA_VERSION != 0 {
                return Err(incompatible_schema(
                    "datadir has no CURRENT_SCHEMA marker and is implicitly schema epoch 0, which is not current",
                ));
            }
            if stale_temp {
                // This is a reserved temporary marker left by an interrupted
                // initialization, not user data. Removing it lets the next
                // attempt start a fresh atomic publication.
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

pub(crate) fn current_schema_bytes() -> Vec<u8> {
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

    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    pub(crate) fn rename_noreplace(&self, from: &str, to: &str) -> io::Result<()> {
        rustix::fs::renameat_with(
            self.dir(),
            from,
            self.dir(),
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(Into::into)
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

pub(crate) fn create_file(dir: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    dir.open_with(name, &options)
}

pub(crate) fn open_file(dir: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = dir.open_with(name, &options)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint entry {name:?} is not a regular file"),
        ));
    }
    Ok(file)
}

pub(crate) fn read_file(dir: &Dir, name: &str, limit: u64) -> io::Result<Vec<u8>> {
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
pub(crate) fn sync_dir(dir: &Dir) -> io::Result<()> {
    // cap-std directory capabilities use O_PATH on Linux; reopen "." read-only
    // so fsync has an I/O-capable descriptor without leaving this capability.
    let mut options = OpenOptions::new();
    options
        .read(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    dir.open_with(".", &options)?.sync_all()
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
)))]
pub(crate) fn sync_dir(_dir: &Dir) -> io::Result<()> {
    // Windows does not support flushing a directory handle with the access
    // mode used by cap-std. File contents are still flushed by File::sync_all.
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
    root.remove_dir(name)
}
