use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use bitcoin::hashes::{Hash as _, sha256};
use thiserror::Error;

/// RPC authentication policy.
#[derive(Clone, Debug)]
pub enum Auth {
    /// HTTP Basic auth with a cleartext username and SHA256 password digest.
    Basic {
        /// Expected username.
        user: String,
        /// SHA256 of the expected password.
        password_hash: [u8; 32],
    },
    /// Bitcoin Core cookie auth loaded from `path` during construction.
    Cookie {
        /// Cookie file path retained for diagnostics and reload decisions.
        path: PathBuf,
        /// Username read from the cookie file.
        user: String,
        /// SHA256 of the cookie password.
        password_hash: [u8; 32],
    },
}

/// Authentication construction errors.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Cookie file could not be read.
    #[error("cookie read failed: {0}")]
    Io(#[from] io::Error),
    /// Cookie contents were not `user:password`.
    #[error("cookie file must contain user:password")]
    InvalidCookie,
}

impl Auth {
    /// Builds Basic auth by hashing `password` once at startup.
    #[must_use]
    pub fn basic(user: impl Into<String>, password: &str) -> Self {
        Self::Basic {
            user: user.into(),
            password_hash: hash_password(password),
        }
    }

    /// Builds cookie auth by reading and hashing the cookie file once.
    pub fn cookie(path: impl AsRef<Path>) -> Result<Self, AuthError> {
        let path = path.as_ref().to_path_buf();
        let contents = fs::read_to_string(&path)?;
        let trimmed = contents.trim_end_matches(['\r', '\n']);
        let Some((user, password)) = trimmed.split_once(':') else {
            return Err(AuthError::InvalidCookie);
        };
        Ok(Self::Cookie {
            path,
            user: user.to_owned(),
            password_hash: hash_password(password),
        })
    }

    /// Returns true when `Authorization` contains valid HTTP Basic credentials.
    #[must_use]
    pub fn validate_header(&self, header: Option<&str>) -> bool {
        let Some(header) = header else {
            return false;
        };
        let Some(encoded) = header.strip_prefix("Basic ") else {
            return false;
        };
        let Some(decoded) = decode_base64(encoded) else {
            return false;
        };
        let Ok(credentials) = core::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((candidate_user, candidate_password)) = credentials.split_once(':') else {
            return false;
        };
        let candidate_hash = hash_password(candidate_password);
        match self {
            Self::Basic {
                user,
                password_hash,
            }
            | Self::Cookie {
                user,
                password_hash,
                ..
            } => {
                constant_time_eq(candidate_user.as_bytes(), user.as_bytes())
                    && constant_time_eq(&candidate_hash, password_hash)
            }
        }
    }
}

/// Compares byte strings without early exit.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    // SPEC: constant-time eq to avoid auth-timing leaks.
    let len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    let mut index = 0;
    while index < len {
        let l = left.get(index).copied().unwrap_or(0);
        let r = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(l ^ r);
        index += 1;
    }
    diff == 0
}

fn hash_password(password: &str) -> [u8; 32] {
    *sha256::Hash::hash(password.as_bytes()).as_byte_array()
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut index = 0;
    while index < bytes.len() {
        let a = decode_base64_byte(bytes[index])?;
        let b = decode_base64_byte(bytes[index + 1])?;
        let c = if bytes[index + 2] == b'=' {
            64
        } else {
            decode_base64_byte(bytes[index + 2])?
        };
        let d = if bytes[index + 3] == b'=' {
            64
        } else {
            decode_base64_byte(bytes[index + 3])?
        };
        if c == 64 && d != 64 {
            return None;
        }
        output.push((a << 2) | (b >> 4));
        if c != 64 {
            output.push(((b & 0x0f) << 4) | (c >> 2));
        }
        if d != 64 {
            output.push(((c & 0x03) << 6) | d);
        }
        index += 4;
    }
    Some(output)
}

fn decode_base64_byte(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
