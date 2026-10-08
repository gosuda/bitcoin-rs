use std::fs;
use std::io;
use std::path::Path;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// RPC authentication policy: one expected `(user, password)` pair hashed at
/// construction, regardless of how the password was sourced.
#[derive(Debug)]
pub struct Auth {
    /// Expected username.
    user: String,
    /// SHA256 of the expected password.
    password_hash: [u8; 32],
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
        Self {
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
        Ok(Self {
            user: user.to_owned(),
            password_hash: hash_password(password),
        })
    }

    /// Returns true when `Authorization` contains valid HTTP Basic credentials.
    #[must_use]
    pub(crate) fn validate_header(&self, header: Option<&str>) -> bool {
        let Some(header) = header else {
            return false;
        };
        let Some(encoded) = header.strip_prefix("Basic ") else {
            return false;
        };
        let Ok(decoded) = crate::base64::decode(encoded) else {
            return false;
        };
        let Ok(credentials) = core::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((candidate_user, candidate_password)) = credentials.split_once(':') else {
            return false;
        };
        let candidate_hash = hash_password(candidate_password);
        constant_time_eq(candidate_user.as_bytes(), self.user.as_bytes())
            && constant_time_eq(&candidate_hash, &self.password_hash)
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
    let digest = Sha256::digest(password.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
