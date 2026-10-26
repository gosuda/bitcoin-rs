use std::io::{self, Read as _};
use std::path::Path;

use bitcoin_rs_stratum_v2::AuthorityKeypair;
use thiserror::Error;
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const KEY_HEX_LEN: usize = KEY_BYTES * 2;
const MAX_KEY_FILE_BYTES: usize = 256;
const MAX_KEY_FILE_READ: u64 = 257;

/// Failure to load the SV2 Noise authority key.
///
/// Parse errors deliberately carry no input text so key material cannot reach
/// logs through either `Display` or `Debug`.
#[derive(Debug, Error)]
pub(crate) enum AuthorityKeyError {
    #[error("could not open or read the SV2 authority key: {0}")]
    Io(#[from] io::Error),
    #[error(
        "the SV2 authority key must contain a 32-byte hex public key followed by a 32-byte hex secret key"
    )]
    InvalidFormat,
    #[cfg(unix)]
    #[error("the SV2 authority key must be a regular file with mode 0600")]
    InsecureFile,
    #[cfg(not(unix))]
    #[error("the SV2 authority key must be a regular file")]
    InsecureFile,
}

pub(crate) fn load(path: &Path) -> Result<AuthorityKeypair, AuthorityKeyError> {
    let file = open_private_file(path)?;
    let mut contents = Zeroizing::new(Vec::with_capacity(MAX_KEY_FILE_BYTES + 1));
    file.take(MAX_KEY_FILE_READ).read_to_end(&mut contents)?;
    if contents.len() > MAX_KEY_FILE_BYTES {
        return Err(AuthorityKeyError::InvalidFormat);
    }

    let text = std::str::from_utf8(&contents).map_err(|_| AuthorityKeyError::InvalidFormat)?;
    let mut fields = text.split_ascii_whitespace();
    let public_text = fields.next().ok_or(AuthorityKeyError::InvalidFormat)?;
    let secret_text = fields.next().ok_or(AuthorityKeyError::InvalidFormat)?;
    if fields.next().is_some() {
        return Err(AuthorityKeyError::InvalidFormat);
    }

    let mut public = [0; KEY_BYTES];
    decode_key_into(public_text, &mut public)?;
    let mut secret = Zeroizing::new([0; KEY_BYTES]);
    decode_key_into(secret_text, &mut secret)?;
    Ok(AuthorityKeypair::from_bytes(public, secret))
}

fn decode_key_into(text: &str, key: &mut [u8; KEY_BYTES]) -> Result<(), AuthorityKeyError> {
    if text.len() != KEY_HEX_LEN {
        return Err(AuthorityKeyError::InvalidFormat);
    }
    let digits = text.as_bytes();
    for (index, destination) in key.iter_mut().enumerate() {
        let high = hex_digit(digits[index * 2]).ok_or(AuthorityKeyError::InvalidFormat)?;
        let low = hex_digit(digits[index * 2 + 1]).ok_or(AuthorityKeyError::InvalidFormat)?;
        *destination = (high << 4) | low;
    }
    Ok(())
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(unix)]
fn open_private_file(path: &Path) -> Result<std::fs::File, AuthorityKeyError> {
    use std::os::unix::fs::PermissionsExt as _;

    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = std::fs::File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err(AuthorityKeyError::InsecureFile);
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_file(_path: &Path) -> Result<std::fs::File, AuthorityKeyError> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure SV2 authority-key loading is unavailable on this platform",
    )
    .into())
}
