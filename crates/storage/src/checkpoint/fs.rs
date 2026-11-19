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
pub const CURRENT_SCHEMA_VERSION: u32 = 6;

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

fn validate_current_schema(bytes: &[u8]) -> Result<(), io::Error> {
    if bytes == current_schema_bytes().as_slice() {
        return Ok(());
    }
    Err(incompatible_schema(
        "CURRENT_SCHEMA is not the current datadir schema epoch",
    ))
}

pub fn current_schema_bytes() -> Vec<u8> {
    let mut bytes = CURRENT_SCHEMA_VERSION.to_string().into_bytes();
    bytes.push(b'\n');
    bytes
}

fn incompatible_schema(reason: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{}; convert it with bitcoin-rs-storage-convert --from <old> --to <new>, or resync into a new datadir",
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
        target_os = "redox",
        windows
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
    target_os = "redox",
    windows
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

/// `FILE_RENAME_INFO` requires an absolute destination, resolved here through
/// the `dir` handle; `FILE_RENAME_INFO_EX`'s `RootDirectory` field would make
/// it handle-relative but is rejected with `ERROR_INVALID_PARAMETER` on this
/// kernel.
#[cfg(windows)]
pub fn rename_noreplace(dir: &Dir, from: &str, to: &str) -> io::Result<()> {
    check_confined_endpoint(from)?;
    check_confined_endpoint(to)?;

    use cap_std::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, GetFinalPathNameByHandleW, SetFileInformationByHandle,
    };

    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let mut options = OpenOptions::new();
    options
        .follow(FollowSymlinks::No)
        .access_mode(DELETE_ACCESS)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let from_file = dir.open_with(from, &options)?;

    let mut root = vec![0_u16; 512];
    let root_len = loop {
        // SAFETY: `root` is a live, writable buffer of the given length.
        let written = unsafe {
            GetFinalPathNameByHandleW(
                dir.as_raw_handle().cast(),
                root.as_mut_ptr(),
                u32::try_from(root.len()).unwrap_or(u32::MAX),
                0,
            )
        };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        let written = usize::try_from(written).unwrap_or(usize::MAX);
        if written < root.len() {
            break written;
        }
        root.resize(written + 1, 0);
    };
    let root = &root[..root_len];
    let mut name: Vec<u16> = Vec::with_capacity(root.len() + to.len() + 2);
    name.extend_from_slice(root);
    name.push(u16::from(b'\\'));
    name.extend(to.encode_utf16());
    name.push(0);

    let name_offset = 2 * core::mem::size_of::<usize>() + 4;
    let mut info = vec![0_u8; name_offset + name.len() * 2];
    info[name_offset - 4..name_offset].copy_from_slice(
        &u32::try_from(name.len().saturating_sub(1) * 2)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for (index, unit) in name.iter().enumerate() {
        info[name_offset + index * 2..name_offset + 2 + index * 2]
            .copy_from_slice(&unit.to_le_bytes());
    }
    // SAFETY: `info` is a correctly laid out `FILE_RENAME_INFO` buffer (u8
    // replace flag, padding, NULL `RootDirectory`, u32 name length, NUL-
    // terminated UTF-16 name) and `from_file` is a live handle opened with
    // `DELETE` access.
    let renamed = unsafe {
        SetFileInformationByHandle(
            from_file.as_raw_handle().cast(),
            FileRenameInfo,
            info.as_ptr().cast(),
            u32::try_from(info.len()).unwrap_or(u32::MAX),
        )
    };
    if renamed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox",
    windows
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

/// Name of the nested engine-image directory a staged checkpoint generation
/// writes under itself (`CheckpointStage::checkpoint_store`).
pub(crate) const STAGED_STORE_DIR: &str = "chainstate";

fn remove_engine_dir_content(dir: &Dir) -> io::Result<()> {
    for entry in dir.entries()? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let child = dir.open_dir_nofollow(&file_name)?;
            remove_engine_dir_content(&child)?;
            drop(child);
            dir.remove_dir(&file_name)?;
        } else {
            dir.remove_file(&file_name)?;
        }
    }
    Ok(())
}

pub(crate) fn remove_known_dir(root: &CheckpointRoot, name: &str) -> io::Result<()> {
    let dir = root.open_dir(name)?;
    for entry in dir.entries()? {
        let entry = entry?;
        let file_name = entry.file_name();
        if entry.file_type()?.is_dir() {
            if file_name != std::ffi::OsStr::new(STAGED_STORE_DIR) {
                continue;
            }
            let child = dir.open_dir_nofollow(&file_name)?;
            remove_engine_dir_content(&child)?;
            drop(child);
            dir.remove_dir(&file_name)?;
        } else {
            dir.remove_file(&file_name)?;
        }
    }
    drop(dir);
    root.remove_dir(name)
}
