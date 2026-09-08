//! Node-owned persistence adapter for the Drivechain state machine.

use std::sync::Arc;

use bitcoin_rs_drivechain::{State, StateTransition, Thresholds};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageError, WriteBatch};
use parking_lot::Mutex;

const CURRENT_KEY: &[u8] = b"drivechain:state:v1";
const UNDO_PREFIX: &[u8] = b"drivechain:undo:v1:";
const ENVELOPE_MAGIC: &[u8; 4] = b"DCS1";

pub(crate) trait DrivechainStore: Send + Sync {
    fn load_current(&self) -> Result<Option<(State, State)>, StorageError>;
    fn load_undo(&self, hash: [u8; 32]) -> Result<Option<State>, StorageError>;
    fn stage_connect(&self, transition: &StateTransition) -> Result<(), StorageError>;
    fn stage_disconnect(&self, parent: &State, child: &State) -> Result<(), StorageError>;
}

pub(crate) struct KvDrivechainStore<S> {
    store: Arc<S>,
}

impl<S> KvDrivechainStore<S> {
    pub(crate) fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

impl<S: KvStore> DrivechainStore for KvDrivechainStore<S> {
    fn load_current(&self) -> Result<Option<(State, State)>, StorageError> {
        self.store
            .get(ColumnFamily::UtxoMeta, CURRENT_KEY)?
            .map(|bytes| decode_envelope(&bytes))
            .transpose()
    }

    fn load_undo(&self, hash: [u8; 32]) -> Result<Option<State>, StorageError> {
        self.store
            .get(ColumnFamily::UndoData, &undo_key(hash))?
            .map(|bytes| decode_state(&bytes))
            .transpose()
    }

    fn stage_connect(&self, transition: &StateTransition) -> Result<(), StorageError> {
        let child_hash = transition
            .next()
            .tip()
            .ok_or(StorageError::InvalidOperation(
                "Drivechain child state has no tip",
            ))?;
        let mut batch = self.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            CURRENT_KEY,
            &encode_envelope(transition.next(), transition.previous())?,
        );
        batch.put(
            ColumnFamily::UndoData,
            &undo_key(child_hash),
            &encode_state(transition.previous())?,
        );
        self.store.write_durable(batch)
    }

    fn stage_disconnect(&self, parent: &State, child: &State) -> Result<(), StorageError> {
        let mut batch = self.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            CURRENT_KEY,
            &encode_envelope(parent, child)?,
        );
        self.store.write_durable(batch)
    }
}

pub(crate) struct DrivechainRuntime {
    pub(crate) state: State,
    pub(crate) store: Arc<dyn DrivechainStore>,
}

pub(crate) type SharedDrivechain = Arc<Mutex<DrivechainRuntime>>;

impl DrivechainRuntime {
    pub(crate) fn open(
        store: Arc<dyn DrivechainStore>,
        applied: Option<(u32, Hash256)>,
        thresholds: Thresholds,
        activation_height: u32,
    ) -> Result<Self, StorageError> {
        let target = applied.map(|(height, hash)| (height, hash.to_le_bytes()));
        let state = match store.load_current()? {
            Some((primary, alternate)) => {
                if cursor(&primary) == target {
                    primary
                } else if cursor(&alternate) == target {
                    alternate
                } else {
                    rewind_to(store.as_ref(), primary, target)?
                }
            }
            None => {
                if target.is_some_and(|(height, _)| height >= activation_height) {
                    return Err(StorageError::IncompatibleData("Drivechain state is absent at or beyond its activation height; resync this network with a Drivechain-capable build".to_owned()));
                }
                State::at_cursor(thresholds, activation_height, target)
            }
        };
        Ok(Self { state, store })
    }
}

fn rewind_to(
    store: &dyn DrivechainStore,
    mut state: State,
    target: Option<(u32, [u8; 32])>,
) -> Result<State, StorageError> {
    loop {
        if cursor(&state) == target {
            return Ok(state);
        }
        let Some(hash) = state.tip() else {
            break;
        };
        state = store.load_undo(hash)?.ok_or_else(|| StorageError::IncompatibleData("Drivechain state cursor does not match the authoritative tip and required undo state is missing".to_owned()))?;
    }
    Err(StorageError::IncompatibleData(
        "Drivechain state cannot be reconciled to the authoritative tip".to_owned(),
    ))
}

fn cursor(state: &State) -> Option<(u32, [u8; 32])> {
    state.height().zip(state.tip())
}

fn undo_key(hash: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(UNDO_PREFIX.len() + hash.len());
    key.extend_from_slice(UNDO_PREFIX);
    key.extend_from_slice(&hash);
    key
}

fn encode_state(state: &State) -> Result<Vec<u8>, StorageError> {
    state
        .encode()
        .map_err(|error| StorageError::IncompatibleData(error.to_string()))
}

fn decode_state(bytes: &[u8]) -> Result<State, StorageError> {
    State::decode(bytes).map_err(|error| StorageError::IncompatibleData(error.to_string()))
}

fn encode_envelope(primary: &State, alternate: &State) -> Result<Vec<u8>, StorageError> {
    let primary = encode_state(primary)?;
    let alternate = encode_state(alternate)?;
    let primary_len = u32::try_from(primary.len())
        .map_err(|_| StorageError::InvalidOperation("Drivechain state is too large"))?;
    let mut encoded = Vec::with_capacity(12 + primary.len() + alternate.len());
    encoded.extend_from_slice(ENVELOPE_MAGIC);
    encoded.extend_from_slice(&primary_len.to_be_bytes());
    encoded.extend_from_slice(&primary);
    encoded.extend_from_slice(&alternate);
    Ok(encoded)
}

fn decode_envelope(bytes: &[u8]) -> Result<(State, State), StorageError> {
    if bytes.get(..4) != Some(ENVELOPE_MAGIC) {
        return Err(StorageError::IncompatibleData(
            "invalid Drivechain state envelope".to_owned(),
        ));
    }
    let len = bytes.get(4..8).ok_or_else(|| {
        StorageError::IncompatibleData("truncated Drivechain state envelope".to_owned())
    })?;
    let primary_len = usize::try_from(u32::from_be_bytes(len.try_into().map_err(|_| {
        StorageError::IncompatibleData("invalid Drivechain state length".to_owned())
    })?))
    .map_err(|_| StorageError::IncompatibleData("invalid Drivechain state length".to_owned()))?;
    let split = 8_usize
        .checked_add(primary_len)
        .ok_or(StorageError::InvalidOperation(
            "Drivechain state length overflow",
        ))?;
    let primary = bytes.get(8..split).ok_or_else(|| {
        StorageError::IncompatibleData("truncated Drivechain primary state".to_owned())
    })?;
    let alternate = bytes.get(split..).ok_or_else(|| {
        StorageError::IncompatibleData("truncated Drivechain alternate state".to_owned())
    })?;
    Ok((decode_state(primary)?, decode_state(alternate)?))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        current: Mutex<Option<(State, State)>>,
        undo: Mutex<BTreeMap<[u8; 32], State>>,
    }

    impl DrivechainStore for MemoryStore {
        fn load_current(&self) -> Result<Option<(State, State)>, StorageError> {
            Ok(self.current.lock().clone())
        }

        fn load_undo(&self, hash: [u8; 32]) -> Result<Option<State>, StorageError> {
            Ok(self.undo.lock().get(&hash).cloned())
        }

        fn stage_connect(&self, transition: &StateTransition) -> Result<(), StorageError> {
            *self.current.lock() = Some((
                transition.next().clone(),
                transition.previous().clone(),
            ));
            let hash = transition
                .next()
                .tip()
                .ok_or(StorageError::InvalidOperation("missing test tip"))?;
            self.undo
                .lock()
                .insert(hash, transition.previous().clone());
            Ok(())
        }

        fn stage_disconnect(&self, parent: &State, child: &State) -> Result<(), StorageError> {
            *self.current.lock() = Some((parent.clone(), child.clone()));
            Ok(())
        }
    }

    fn state(height: u32, byte: u8) -> State {
        State::at_cursor(Thresholds::REGTEST, 0, Some((height, [byte; 32])))
    }

    #[test]
    fn envelope_round_trip_preserves_both_crash_sides() {
        let primary = state(12, 2);
        let alternate = state(11, 1);
        let encoded = encode_envelope(&primary, &alternate).expect("encode envelope");
        assert_eq!(decode_envelope(&encoded), Ok((primary, alternate)));
    }

    #[test]
    fn restart_selects_the_state_matching_the_authoritative_tip() {
        let store = Arc::new(MemoryStore::default());
        let child = state(12, 2);
        let parent = state(11, 1);
        *store.current.lock() = Some((child, parent.clone()));
        let runtime = DrivechainRuntime::open(
            store,
            Some((11, Hash256::from_le_bytes([1; 32]))),
            Thresholds::REGTEST,
            0,
        )
        .expect("recover alternate");
        assert_eq!(runtime.state, parent);
    }

    #[test]
    fn restart_walks_undo_until_the_authoritative_tip() {
        let store = Arc::new(MemoryStore::default());
        let grandchild = state(12, 3);
        let child = state(11, 2);
        let parent = state(10, 1);
        *store.current.lock() = Some((grandchild.clone(), state(12, 9)));
        store.undo.lock().insert([3; 32], child);
        store.undo.lock().insert([2; 32], parent.clone());
        let runtime = DrivechainRuntime::open(
            store,
            Some((10, Hash256::from_le_bytes([1; 32]))),
            Thresholds::REGTEST,
            0,
        )
        .expect("rewind undo chain");
        assert_eq!(runtime.state, parent);
    }

    #[test]
    fn missing_state_at_activation_fails_closed() {
        let result = DrivechainRuntime::open(
            Arc::new(MemoryStore::default()),
            Some((0, Hash256::from_le_bytes([1; 32]))),
            Thresholds::REGTEST,
            0,
        );
        assert!(matches!(result, Err(StorageError::IncompatibleData(_))));
    }
}
