//! Admission-local positive cache for cryptographic signature results.
//!
//! The cache stores the keys of group operations that already verified
//! successfully, so the second admission pass over the same transaction can
//! skip repeating the `secp256k1` call. Every flag, encoding, parsing, and
//! sighash check still runs on a hit; only the group operation is skipped.
//!
//! The cache is serial admission-local state: a [`RefCell`] over a bounded
//! set, so [`SignatureCache`] is `!Sync` by construction and must never be
//! stored in [`crate::interpreter::PreparedTransaction`]. Failures are never
//! inserted. At capacity, existing hits keep working and new distinct entries
//! are refused, never evicting.

use std::cell::RefCell;
use std::collections::HashSet;

use sha2::{Digest as _, Sha256};

/// Hard bound on successful entries. An independent resource bound, not policy.
const MAX_ENTRIES: usize = 64;

/// Domain tag for the fixed-size digest key.
const DOMAIN: &[u8] = b"btcrs-sigcache-v1\x00";
/// Algorithm tag for ECDSA keys.
const TAG_ECDSA: &[u8] = b"ecdsa-v1\x00";
/// Algorithm tag for Schnorr keys.
const TAG_SCHNORR: &[u8] = b"schnorr-v1\x00";

/// Admission-local positive cache for successful signature verifications.
///
/// Created per admission, shared across the admission's verification passes,
/// then dropped. Lookup and insert stay crate-private; only the constructor
/// (and [`Default`], which delegates to it) is public.
#[derive(Debug)]
pub struct SignatureCache {
    inner: RefCell<HashSet<[u8; 32]>>,
}

impl SignatureCache {
    /// Creates an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(HashSet::new()),
        }
    }

    /// Reports whether `key` was inserted by an earlier success.
    pub(crate) fn contains(&self, key: &[u8; 32]) -> bool {
        self.inner.borrow().contains(key)
    }

    /// Records a successful verification, unless already present or at capacity.
    ///
    /// At capacity the insert is refused so existing hits keep working; no
    /// eviction ever occurs.
    pub(crate) fn insert(&self, key: [u8; 32]) {
        let mut inner = self.inner.borrow_mut();
        if inner.contains(&key) {
            return;
        }
        if inner.len() >= MAX_ENTRIES {
            return;
        }
        inner.insert(key);
    }

    /// Builds the unambiguous fixed-size key for a successful ECDSA check.
    ///
    /// `message` is the 32-byte sighash digest actually verified, `sig` the
    /// exact signature bytes presented (hashtype byte included), and `pubkey`
    /// the exact public-key bytes presented.
    pub(crate) fn ecdsa_key(message: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> [u8; 32] {
        cache_key(TAG_ECDSA, message, sig, pubkey)
    }

    /// Builds the unambiguous fixed-size key for a successful Schnorr check.
    ///
    /// `sig` is the exact signature bytes presented (65-byte form with its
    /// hashtype byte included when present).
    pub(crate) fn schnorr_key(message: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> [u8; 32] {
        cache_key(TAG_SCHNORR, message, sig, pubkey)
    }
}

impl Default for SignatureCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Domain-separated unambiguous digest over algorithm, message, and the
/// length-prefixed signature and public-key bytes. Length prefixes keep
/// concatenations from aliasing across split points.
fn cache_key(tag: &[u8], message: &[u8; 32], sig: &[u8], pubkey: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(tag);
    hasher.update(message);
    hasher.update(u64::try_from(sig.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(sig);
    hasher.update(
        u64::try_from(pubkey.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(pubkey);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::SignatureCache;

    fn message(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn distinct_fields_miss() {
        let cache = SignatureCache::new();
        let key = SignatureCache::ecdsa_key(&message(1), &[0x30, 0x44], &[0x02, 0x03]);
        cache.insert(key);
        assert!(!cache.contains(&SignatureCache::ecdsa_key(
            &message(2),
            &[0x30, 0x44],
            &[0x02, 0x03]
        )));
        assert!(!cache.contains(&SignatureCache::ecdsa_key(
            &message(1),
            &[0x30, 0x45],
            &[0x02, 0x03]
        )));
        assert!(!cache.contains(&SignatureCache::ecdsa_key(
            &message(1),
            &[0x30, 0x44],
            &[0x02, 0x04]
        )));
    }

    #[test]
    fn algorithm_tags_do_not_alias() {
        let msg = message(7);
        let ecdsa = SignatureCache::ecdsa_key(&msg, &[0x01, 0x02], &[0x03]);
        let schnorr = SignatureCache::schnorr_key(&msg, &[0x01, 0x02], &[0x03]);
        assert_ne!(ecdsa, schnorr);
        let cache = SignatureCache::new();
        cache.insert(ecdsa);
        assert!(!cache.contains(&schnorr));
    }

    #[test]
    fn length_prefixes_prevent_split_aliasing() {
        let msg = message(9);
        let left = SignatureCache::ecdsa_key(&msg, &[0xAB], &[0xCD, 0xEF]);
        let right = SignatureCache::ecdsa_key(&msg, &[0xAB, 0xCD], &[0xEF]);
        assert_ne!(left, right);
    }

    #[test]
    fn at_capacity_existing_hits_work_and_new_entries_refused() {
        let cache = SignatureCache::new();
        let mut first = [0u8; 32];
        for i in 0u64..64 {
            let mut msg = [0u8; 32];
            msg[..8].copy_from_slice(&i.to_le_bytes());
            let key = SignatureCache::ecdsa_key(&msg, &[0x30], &[0x02]);
            if i == 0 {
                first = key;
            }
            cache.insert(key);
        }
        assert!(cache.contains(&first));
        let extra = SignatureCache::ecdsa_key(&[0xFF; 32], &[0x30], &[0x02]);
        assert!(!cache.contains(&extra));
        cache.insert(extra);
        assert!(!cache.contains(&extra));
        assert!(cache.contains(&first));
    }
}
