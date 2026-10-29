//! Create-once application keys. Existing files are never replaced or repaired implicitly.
use super::invalid;
use base64::{
    Engine as _, alphabet,
    engine::GeneralPurposeConfig,
    engine::general_purpose::{GeneralPurpose, STANDARD},
};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};
const LIMIT: u64 = 16_384;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    key: String,
    checksum: [u8; 32],
}
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Tor,
    I2p,
}
#[expect(
    clippy::expect_used,
    reason = "The fixed I2P alphabet is a compile-time constant"
)]
pub(super) fn i2p_base64() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::Alphabet::new(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~",
        )
        .expect("I2P alphabet"),
        GeneralPurposeConfig::new(),
    )
}
pub(super) fn public_destination(text: &str) -> io::Result<Vec<u8>> {
    let bytes = i2p_base64()
        .decode(text)
        .map_err(|_| invalid("invalid I2P destination encoding"))?;
    let length = destination_length(&bytes)?;
    if bytes.len() != length {
        return Err(invalid("invalid I2P public destination length"));
    }
    let payload = &bytes[387..];
    let valid = match bytes[384] {
        0 | 2 => payload.is_empty(),
        1 | 4 => true,
        3 => matches!(payload.len(), 40 | 72),
        5 if payload.len() >= 4 => {
            let signing = u16::from_be_bytes([payload[0], payload[1]]);
            let crypto = u16::from_be_bytes([payload[2], payload[3]]);
            let signing_len: usize = match signing {
                0 | 10 => 128,
                1 | 9 => 64,
                2 => 96,
                3 => 132,
                4 => 256,
                5 => 384,
                6 => 512,
                7 | 8 | 11 => 32,
                _ => return Err(invalid("unsupported I2P signing key type")),
            };
            let crypto_len: usize = match crypto {
                0 => 256,
                1 => 64,
                2 => 96,
                3 => 132,
                4 | 6 | 7 => 32,
                _ => return Err(invalid("unsupported I2P encryption key type")),
            };
            payload.len() == 4 + signing_len.saturating_sub(128) + crypto_len.saturating_sub(256)
        }
        _ => false,
    };
    if !valid {
        return Err(invalid("invalid I2P destination certificate"));
    }
    Ok(bytes)
}
fn destination_length(bytes: &[u8]) -> io::Result<usize> {
    if bytes.len() < 387 {
        return Err(invalid("truncated I2P destination"));
    }
    let length = 387 + usize::from(u16::from_be_bytes([bytes[385], bytes[386]]));
    if length > bytes.len() {
        return Err(invalid("truncated I2P certificate"));
    }
    Ok(length)
}
pub(super) fn validate(text: &str, kind: Kind) -> io::Result<()> {
    match kind {
        Kind::Tor => {
            let key = text
                .strip_prefix("ED25519-V3:")
                .ok_or_else(|| invalid("invalid Tor service key type"))?;
            if STANDARD
                .decode(key)
                .map_err(|_| invalid("invalid Tor service key encoding"))?
                .len()
                != 64
            {
                return Err(invalid("invalid Tor service key length"));
            }
        }
        Kind::I2p => {
            let bytes = i2p_base64()
                .decode(text)
                .map_err(|_| invalid("invalid I2P private destination encoding"))?;
            let public_length = destination_length(&bytes)?;
            if bytes.len() < public_length + 256 + 20 || bytes.len() > 12_288 {
                return Err(invalid("invalid I2P private destination length"));
            }
        }
    }
    Ok(())
}
pub(super) fn read(path: &Path, kind: Kind) -> io::Result<Option<String>> {
    #[cfg(unix)]
    let opened = {
        use rustix::fs::{Mode, OFlags};
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(io::Error::from)
    };
    #[cfg(not(unix))]
    let opened = (|| {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() {
            return Err(invalid("invalid overlay identity file type or size"));
        }
        File::open(path)
    })();
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > LIMIT {
        return Err(invalid("invalid overlay identity file type or size"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("overlay identity file must be private (0600)"));
        }
    }
    let mut text = String::new();
    file.take(LIMIT + 1).read_to_string(&mut text)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > LIMIT {
        return Err(invalid("overlay identity file too large"));
    }
    let stored: Stored =
        sonic_rs::from_str(&text).map_err(|_| invalid("damaged overlay identity file"))?;
    if stored.version != 1
        || stored.checksum != <[u8; 32]>::from(Sha256::digest(stored.key.as_bytes()))
    {
        return Err(invalid("overlay identity version or checksum mismatch"));
    }
    validate(&stored.key, kind)?;
    Ok(Some(stored.key))
}
fn ensure_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => return Err(invalid("overlay identity directory is not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_directory(parent)?;
    let created = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            fs::DirBuilder::new().mode(0o700).create(path)
        }
        #[cfg(not(unix))]
        {
            fs::create_dir(path)
        }
    };
    match created {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            ensure_directory(path)?;
        }
        Err(error) => return Err(error),
    }
    bitcoin_rs_storage::checkpoint::fs::sync_dir(
        &bitcoin_rs_storage::checkpoint::fs::open_data_dir(parent)?,
    )
}
pub(super) fn create(path: &Path, text: &str, kind: Kind) -> io::Result<()> {
    use bitcoin::secp256k1::rand::RngCore as _;
    validate(text, kind)?;
    let bytes = sonic_rs::to_vec(&Stored {
        version: 1,
        key: text.to_owned(),
        checksum: Sha256::digest(text.as_bytes()).into(),
    })
    .map_err(|_| invalid("overlay identity serialization failed"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > LIMIT {
        return Err(invalid("overlay identity file too large"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("identity path has no parent"))?;
    ensure_directory(parent)?;
    if let Some(existing) = read(path, kind)? {
        if existing != text {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "overlay identity already exists with a different key",
            ));
        }
        return bitcoin_rs_storage::checkpoint::fs::sync_dir(
            &bitcoin_rs_storage::checkpoint::fs::open_data_dir(parent)?,
        );
    }
    let temporary = path.with_extension(format!(
        "tmp-{}-{:016x}",
        std::process::id(),
        bitcoin::secp256k1::rand::thread_rng().next_u64()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary, path)?;
        bitcoin_rs_storage::checkpoint::fs::sync_dir(
            &bitcoin_rs_storage::checkpoint::fs::open_data_dir(parent)?,
        )
    })();
    let _ = fs::remove_file(temporary);
    result
}
