use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, MetadataExt, OpenOptions};

use crate::cli::CliArgs;
use crate::error::ConvertError;

pub(crate) struct OpenedRoots {
    pub(crate) from_dir: Dir,
    pub(crate) to_dir: Dir,
    pub(crate) pool_from_dir: Option<Dir>,
    pub(crate) pool_to_dir: Option<Dir>,
}

pub(crate) fn check_symlink_final_component(path: &Path) -> Result<(), ConvertError> {
    let clean_path = path.components().as_path();
    match fs::symlink_metadata(clean_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(ConvertError::InvalidOperation(format!(
                    "path '{}' has a symlink final component, which is forbidden",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ConvertError::Io(err)),
    }
}

pub(crate) fn validate_and_open_roots(args: &CliArgs) -> Result<OpenedRoots, ConvertError> {
    let (from, to) = args.convert_roots()?;
    args.validate()?;

    check_symlink_final_component(from)?;
    check_symlink_final_component(to)?;
    if let Some(pool_from) = &args.pool_from {
        check_symlink_final_component(pool_from)?;
    }
    if let Some(pool_to) = &args.pool_to {
        check_symlink_final_component(pool_to)?;
    }

    if !from.exists() {
        return Err(ConvertError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            format!("source datadir '{}' does not exist", from.display()),
        )));
    }
    if !from.is_dir() {
        return Err(ConvertError::InvalidOperation(format!(
            "source datadir '{}' is not a directory",
            from.display()
        )));
    }

    if let Some(pool_from) = &args.pool_from {
        if !pool_from.exists() {
            return Err(ConvertError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "source pool datadir '{}' does not exist",
                    pool_from.display()
                ),
            )));
        }
        if !pool_from.is_dir() {
            return Err(ConvertError::InvalidOperation(format!(
                "source pool datadir '{}' is not a directory",
                pool_from.display()
            )));
        }
    }

    validate_pre_creation_disjointness(args, from, to)?;

    prepare_destination_dir(to)?;
    if let Some(pool_to) = &args.pool_to {
        prepare_destination_dir(pool_to)?;
    }

    let from_dir = Dir::open_ambient_dir(from, ambient_authority())?;
    let to_dir = Dir::open_ambient_dir(to, ambient_authority())?;

    let pool_from_dir = if let Some(pool_from) = &args.pool_from {
        Some(Dir::open_ambient_dir(pool_from, ambient_authority())?)
    } else {
        None
    };

    let pool_to_dir = if let Some(pool_to) = &args.pool_to {
        Some(Dir::open_ambient_dir(pool_to, ambient_authority())?)
    } else {
        None
    };

    let mut open_dirs: Vec<(&Path, &Dir)> = vec![(from, &from_dir), (to, &to_dir)];
    if let (Some(pf_path), Some(pf_dir)) = (&args.pool_from, &pool_from_dir) {
        open_dirs.push((pf_path, pf_dir));
    }
    if let (Some(pt_path), Some(pt_dir)) = (&args.pool_to, &pool_to_dir) {
        open_dirs.push((pt_path, pt_dir));
    }

    check_disjoint_and_non_ancestral(&open_dirs)?;

    Ok(OpenedRoots {
        from_dir,
        to_dir,
        pool_from_dir,
        pool_to_dir,
    })
}

fn validate_pre_creation_disjointness(
    args: &CliArgs,
    from: &Path,
    to: &Path,
) -> Result<(), ConvertError> {
    let from_canon = fs::canonicalize(from)?;

    let pool_from_canon = if let Some(pf) = &args.pool_from {
        Some(fs::canonicalize(pf)?)
    } else {
        None
    };

    if let (Some(pf_c), Some(pf_orig)) = (&pool_from_canon, &args.pool_from) {
        if *pf_c == from_canon {
            return Err(ConvertError::InvalidOperation(format!(
                "source pool '{}' is the same directory as source '{}'",
                pf_orig.display(),
                from.display()
            )));
        }
        if pf_c.starts_with(&from_canon) || from_canon.starts_with(pf_c) {
            return Err(ConvertError::InvalidOperation(format!(
                "source pool '{}' and source '{}' overlap or are nested",
                pf_orig.display(),
                from.display()
            )));
        }
    }

    check_dest_candidate_against_sources(to, &from_canon, pool_from_canon.as_deref())?;

    if let Some(pool_to) = &args.pool_to {
        check_dest_candidate_against_sources(pool_to, &from_canon, pool_from_canon.as_deref())?;

        check_two_dest_candidates(to, pool_to)?;
    }

    Ok(())
}

fn path_parent_or_dot(p: &Path) -> &Path {
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn check_dest_candidate_against_sources(
    dest: &Path,
    from_canon: &Path,
    pool_from_canon: Option<&Path>,
) -> Result<(), ConvertError> {
    let dest_canon = if dest.exists() {
        fs::canonicalize(dest)?
    } else {
        let parent = path_parent_or_dot(dest);
        let parent_canon = fs::canonicalize(parent).map_err(|err| {
            ConvertError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "parent directory '{}' does not exist: {err}",
                    parent.display()
                ),
            ))
        })?;
        let file_name = dest.file_name().ok_or_else(|| {
            ConvertError::InvalidOperation(format!("invalid destination path '{}'", dest.display()))
        })?;
        parent_canon.join(file_name)
    };

    if dest_canon == from_canon {
        return Err(ConvertError::InvalidOperation(format!(
            "destination '{}' is the same directory as source",
            dest.display()
        )));
    }
    if dest_canon.starts_with(from_canon) {
        return Err(ConvertError::InvalidOperation(format!(
            "destination '{}' is nested inside source datadir",
            dest.display()
        )));
    }
    if from_canon.starts_with(&dest_canon) {
        return Err(ConvertError::InvalidOperation(format!(
            "source datadir is nested inside destination '{}'",
            dest.display()
        )));
    }

    if let Some(pf_c) = pool_from_canon {
        if dest_canon == pf_c {
            return Err(ConvertError::InvalidOperation(format!(
                "destination '{}' is the same directory as source pool",
                dest.display()
            )));
        }
        if dest_canon.starts_with(pf_c) {
            return Err(ConvertError::InvalidOperation(format!(
                "destination '{}' is nested inside source pool datadir",
                dest.display()
            )));
        }
        if pf_c.starts_with(&dest_canon) {
            return Err(ConvertError::InvalidOperation(format!(
                "source pool datadir is nested inside destination '{}'",
                dest.display()
            )));
        }
    }

    Ok(())
}

fn check_two_dest_candidates(d1: &Path, d2: &Path) -> Result<(), ConvertError> {
    let resolve = |p: &Path| -> Result<PathBuf, ConvertError> {
        if p.exists() {
            Ok(fs::canonicalize(p)?)
        } else {
            let parent = path_parent_or_dot(p);
            let parent_canon = fs::canonicalize(parent)?;
            let file_name = p.file_name().ok_or_else(|| {
                ConvertError::InvalidOperation(format!("invalid path '{}'", p.display()))
            })?;
            Ok(parent_canon.join(file_name))
        }
    };

    let c1 = resolve(d1)?;
    let c2 = resolve(d2)?;

    if c1 == c2 {
        return Err(ConvertError::InvalidOperation(format!(
            "destination '{}' and pool destination '{}' resolve to the same path",
            d1.display(),
            d2.display()
        )));
    }
    if c1.starts_with(&c2) || c2.starts_with(&c1) {
        return Err(ConvertError::InvalidOperation(format!(
            "destination '{}' and pool destination '{}' overlap or are nested",
            d1.display(),
            d2.display()
        )));
    }

    Ok(())
}

fn prepare_destination_dir(dest: &Path) -> Result<(), ConvertError> {
    if dest.exists() {
        let dir = Dir::open_ambient_dir(dest, ambient_authority())?;
        let mut entries = dir.entries()?;
        if entries.next().is_some() {
            return Err(ConvertError::DestinationNotEmpty(dest.to_path_buf()));
        }
    } else {
        let parent = path_parent_or_dot(dest);
        if !parent.exists() {
            return Err(ConvertError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("parent directory '{}' does not exist", parent.display()),
            )));
        }
        fs::create_dir(dest)?;
    }
    Ok(())
}

fn check_disjoint_and_non_ancestral(dirs: &[(&Path, &Dir)]) -> Result<(), ConvertError> {
    let mut identities = Vec::new();
    for (path, dir) in dirs {
        let meta = dir.dir_metadata()?;
        let id = (meta.dev(), meta.ino());
        if identities.iter().any(|&(_, existing_id)| existing_id == id) {
            return Err(ConvertError::InvalidOperation(format!(
                "directory '{}' resolves to the same device and inode as another root",
                path.display()
            )));
        }
        identities.push((*path, id));
    }

    for (path, dir) in dirs {
        let meta = dir.dir_metadata()?;
        let mut curr_id = (meta.dev(), meta.ino());
        let mut curr_dir = dir.open_parent_dir(ambient_authority())?;
        let mut ancestors = HashSet::new();

        loop {
            let parent_meta = curr_dir.dir_metadata()?;
            let parent_id = (parent_meta.dev(), parent_meta.ino());
            if parent_id == curr_id {
                break;
            }

            for &(other_path, other_id) in &identities {
                if other_id == parent_id {
                    return Err(ConvertError::InvalidOperation(format!(
                        "directory '{}' is nested inside directory '{}'",
                        path.display(),
                        other_path.display()
                    )));
                }
            }

            if !ancestors.insert(parent_id) {
                break;
            }

            curr_id = parent_id;
            curr_dir = curr_dir.open_parent_dir(ambient_authority())?;
        }
    }

    Ok(())
}

pub(crate) fn create_file_no_follow(dir: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    dir.open_with(name, &options)
}

pub(crate) fn open_file_read_no_follow(dir: &Dir, name: &str) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    dir.open_with(name, &options)
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "android",
    target_os = "redox"
))]
pub(crate) fn sync_dir(dir: &Dir) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    dir.open_with(".", &options)?.sync_all()
}

#[cfg(windows)]
pub(crate) fn sync_dir(dir: &Dir) -> io::Result<()> {
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
pub(crate) fn sync_dir(_dir: &Dir) -> io::Result<()> {
    Ok(())
}

pub(crate) fn copy_dir_recursive(src: &Dir, dst: &Dir) -> Result<(), ConvertError> {
    for entry in src.entries()? {
        let entry = entry?;
        let file_type = entry.file_type()?;

        if file_type.is_symlink() {
            return Err(ConvertError::InvalidOperation(format!(
                "symlink '{:?}' encountered during directory copy; symlinks are rejected",
                entry.file_name()
            )));
        }

        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            return Err(ConvertError::InvalidOperation(
                "non-UTF8 file name encountered".into(),
            ));
        };

        if file_type.is_dir() {
            dst.create_dir(name_str)?;
            let child_src = src.open_dir_nofollow(name_str)?;
            let child_dst = dst.open_dir_nofollow(name_str)?;
            copy_dir_recursive(&child_src, &child_dst)?;
            sync_dir(&child_dst)?;
        } else if file_type.is_file() {
            let mut src_file = open_file_read_no_follow(src, name_str)?;
            let mut dst_file = create_file_no_follow(dst, name_str)?;
            io::copy(&mut src_file, &mut dst_file)?;
            dst_file.sync_all()?;
        } else {
            return Err(ConvertError::InvalidOperation(format!(
                "unsupported file type for '{:?}'",
                entry.file_name()
            )));
        }
    }
    sync_dir(dst)?;
    Ok(())
}

pub(crate) fn publish_current_schema(dest_dir: &Dir, epoch: u32) -> Result<(), ConvertError> {
    const TEMP_FILE: &str = ".CURRENT_SCHEMA.tmp";
    const FINAL_FILE: &str = "CURRENT_SCHEMA";

    let mut marker = create_file_no_follow(dest_dir, TEMP_FILE)?;
    let content = format!("{epoch}\n").into_bytes();
    marker.write_all(&content)?;
    marker.sync_all()?;
    drop(marker);

    dest_dir.rename(TEMP_FILE, dest_dir, FINAL_FILE)?;
    sync_dir(dest_dir)?;
    Ok(())
}
