//! Process-lifetime ownership of index storage namespaces.
//!
//! An abandoned open permanently poisons its namespace. Only the matching
//! generation may release or poison an active claim.

use std::path::{Path, PathBuf};

use hashbrown::HashMap;

/// Process-global namespace ownership state.
#[derive(Debug)]
enum NamespaceEntry {
    /// An active open owns this namespace.
    Active(u64),
    /// An abandoned open poisoned this namespace permanently.
    Poisoned,
}

/// Process-global, process-lifetime namespace map. The key is the canonical
/// data root joined with one validated fixed child component.
pub(super) struct NamespaceRegistry {
    entries: parking_lot::Mutex<HashMap<PathBuf, NamespaceEntry>>,
}

impl NamespaceRegistry {
    pub(super) fn new() -> Self {
        Self {
            entries: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Validates the child component: exactly the fixed name, no separator, not
    /// `.` or `..`, not absolute. Does not canonicalize the child.
    pub(super) fn validate_child(root: &Path, child: &str) -> Result<PathBuf, String> {
        if child.is_empty() {
            return Err("namespace child is empty".to_owned());
        }
        if child.contains(std::path::MAIN_SEPARATOR) {
            return Err(format!("namespace child {child} contains a path separator"));
        }
        if child == "." || child == ".." {
            return Err(format!("namespace child {child} is a path traversal"));
        }
        if Path::new(child).is_absolute() {
            return Err(format!("namespace child {child} is absolute"));
        }
        Ok(root.join(child))
    }

    /// Atomically claims `Active(owner)` for the key. Rejects an existing
    /// `Active` or `Poisoned` entry without touching the store.
    pub(super) fn claim(&self, key: PathBuf, owner: u64) -> bool {
        let mut entries = self.entries.lock();
        match entries.get(&key) {
            None => {
                entries.insert(key, NamespaceEntry::Active(owner));
                true
            }
            Some(NamespaceEntry::Active(_) | NamespaceEntry::Poisoned) => false,
        }
    }

    /// Releases `Active(owner)` only if the map still contains the same owner.
    /// Does nothing if the entry was already changed (e.g. poisoned).
    pub(super) fn release(&self, key: &Path, owner: u64) {
        let mut entries = self.entries.lock();
        if let Some(NamespaceEntry::Active(current)) = entries.get(key) {
            if *current == owner {
                entries.remove(key);
            }
        }
    }

    /// Poisons the namespace only if the entry is `Active(owner)`. Used for
    /// abandoned opens only.
    pub(super) fn poison(&self, key: &Path, owner: u64) {
        let mut entries = self.entries.lock();
        if let Some(NamespaceEntry::Active(current)) = entries.get(key) {
            if *current == owner {
                entries.insert(key.to_path_buf(), NamespaceEntry::Poisoned);
            }
        }
    }

    /// Returns true if the namespace is poisoned.
    pub(super) fn is_poisoned(&self, key: &Path) -> bool {
        matches!(self.entries.lock().get(key), Some(NamespaceEntry::Poisoned))
    }
}

/// One shared process-global namespace registry for all index workers.
pub(super) static NAMESPACE_REGISTRY: std::sync::LazyLock<NamespaceRegistry> =
    std::sync::LazyLock::new(NamespaceRegistry::new);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_registry_claims_and_releases() {
        let registry = NamespaceRegistry::new();
        let key = PathBuf::from("/tmp/test-namespace-claim");

        // First claim succeeds.
        assert!(registry.claim(key.clone(), 1));
        // Second claim by different owner fails.
        assert!(!registry.claim(key.clone(), 2));
        // Release by wrong owner does nothing.
        registry.release(&key, 2);
        assert!(matches!(
            registry.entries.lock().get(&key),
            Some(NamespaceEntry::Active(1))
        ));
        // Release by correct owner removes the entry.
        registry.release(&key, 1);
        assert!(registry.entries.lock().get(&key).is_none());
    }

    #[test]
    fn namespace_registry_poisons_on_abandon() {
        let registry = NamespaceRegistry::new();
        let key = PathBuf::from("/tmp/test-namespace-poison");

        assert!(registry.claim(key.clone(), 1));
        registry.poison(&key, 1);
        assert!(registry.is_poisoned(&key));
        // Poisoned namespace cannot be claimed.
        assert!(!registry.claim(key, 2));
    }

    #[test]
    fn namespace_registry_poison_only_for_matching_owner() {
        let registry = NamespaceRegistry::new();
        let key = PathBuf::from("/tmp/test-namespace-poison-owner");

        assert!(registry.claim(key.clone(), 1));
        // Poison by wrong owner does nothing.
        registry.poison(&key, 2);
        assert!(!registry.is_poisoned(&key));
        assert!(matches!(
            registry.entries.lock().get(&key),
            Some(NamespaceEntry::Active(1))
        ));
    }

    #[test]
    fn namespace_registry_validates_child() {
        let root = Path::new("/tmp");
        assert!(NamespaceRegistry::validate_child(root, "txindex").is_ok());
        assert!(NamespaceRegistry::validate_child(root, "").is_err());
        assert!(NamespaceRegistry::validate_child(root, ".").is_err());
        assert!(NamespaceRegistry::validate_child(root, "..").is_err());
        #[cfg(unix)]
        {
            assert!(NamespaceRegistry::validate_child(root, "foo/bar").is_err());
            assert!(NamespaceRegistry::validate_child(root, "/absolute").is_err());
        }
    }
}
