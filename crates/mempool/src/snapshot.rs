use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use bitcoin_rs_consensus::primitives::{
    ConsensusEncode, Hash256, Network, Tx, Txid, consensus_bytes, deserialize,
};
use hashbrown::HashMap;
use sha2::{Digest, Sha256};

use crate::{AdmissionChain, LocalOrigin, MempoolGateway, MutationResult};

const FILE_NAME: &str = "mempool-snapshot.dat";
const MAGIC: &[u8; 8] = b"BRSMPOOL";
const VERSION: u32 = 2;
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TX_BYTES: usize = 400_000;
const MAX_AGE: u64 = 14 * 24 * 60 * 60;
const MAX_SUBSET_ATTEMPTS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedTransaction {
    pub tx: Arc<Tx>,
    pub txid: Txid,
    pub time: u64,
    pub unbroadcast: bool,
    pub sigop_cost: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub transactions: Vec<SavedTransaction>,
    pub deltas: Vec<(Txid, i64)>,
}

#[derive(Debug)]
pub struct RestoreReport {
    pub candidates: usize,
    pub restored: usize,
    pub skipped: usize,
    pub timed_out: bool,
    pub limited: usize,
    pub package_attempts: u64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "mempool snapshot deadline exceeded",
        ))
    } else {
        Ok(())
    }
}

fn read_file(path: &Path, max_bytes: u64, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
    check_deadline(deadline)?;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(invalid("snapshot is not an ordinary bounded file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(invalid("snapshot exceeds its size limit"));
    }
    check_deadline(deadline)?;
    Ok(Some(bytes))
}

fn take<const N: usize>(input: &mut &[u8]) -> io::Result<[u8; N]> {
    let (value, rest) = input
        .split_at_checked(N)
        .ok_or_else(|| invalid("truncated snapshot"))?;
    *input = rest;
    value.try_into().map_err(|_| invalid("truncated snapshot"))
}

impl Snapshot {
    fn capture(
        gateway: &MempoolGateway,
        deadline: Instant,
        max_bytes: u64,
        max_records: usize,
    ) -> io::Result<Self> {
        let pool = gateway
            .pool
            .try_read_for(deadline.saturating_duration_since(Instant::now()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "mempool snapshot read lock busy")
            })?;
        let deltas = pool.fee_deltas();
        if 84_u64.saturating_add(
            u64::try_from(deltas.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(40),
        ) > max_bytes
        {
            return Err(invalid("too many mempool snapshot fee deltas"));
        }
        let mut deltas: Vec<_> = deltas.collect();
        let mut bytes = 84 + u64::try_from(deltas.len()).unwrap_or(u64::MAX) * 40;
        let mut transactions = Vec::with_capacity(pool.len().min(max_records));
        for cluster in pool.iter_clusters() {
            check_deadline(deadline)?;
            let cluster_bytes: u64 = cluster.iter().map(|row| u64::from(row.size) + 17).sum();
            if transactions.len() + cluster.len() > max_records
                || bytes.saturating_add(cluster_bytes) > max_bytes
                || cluster
                    .iter()
                    .any(|row| usize::try_from(row.size).unwrap_or(usize::MAX) > MAX_TX_BYTES)
            {
                break;
            }
            bytes += cluster_bytes;
            for entry in cluster {
                transactions.push(SavedTransaction {
                    tx: Arc::clone(&entry.tx),
                    txid: entry.txid,
                    time: entry.time,
                    unbroadcast: entry.unbroadcast,
                    sigop_cost: entry.sigop_cost,
                });
            }
        }
        if transactions.len() < pool.len() {
            tracing::warn!(
                saved = transactions.len(),
                omitted = pool.len() - transactions.len(),
                "mempool snapshot capacity reached; saving complete families within the budget"
            );
        }
        drop(pool);
        transactions.sort_unstable_by_key(|row| row.txid);
        deltas.sort_unstable_by_key(|row| row.0);
        Ok(Self {
            transactions,
            deltas,
        })
    }

    pub fn encode(
        &self,
        network: Network,
        max_bytes: u64,
        deadline: Instant,
    ) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&network.genesis_block_hash().to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.transactions.len())
                .map_err(|_| invalid("too many transactions"))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.deltas.len())
                .map_err(|_| invalid("too many fee deltas"))?
                .to_le_bytes(),
        );
        for row in &self.transactions {
            check_deadline(deadline)?;
            bytes.extend_from_slice(&row.time.to_le_bytes());
            bytes.push(u8::from(row.unbroadcast));
            bytes.extend_from_slice(&row.sigop_cost.to_le_bytes());
            bytes.extend_from_slice(
                &u32::try_from(row.tx.consensus_size())
                    .map_err(|_| invalid("transaction too large"))?
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(&consensus_bytes(row.tx.as_ref()));
        }
        for (txid, delta) in &self.deltas {
            check_deadline(deadline)?;
            bytes.extend_from_slice(txid.as_bytes());
            bytes.extend_from_slice(&delta.to_le_bytes());
        }
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
            return Err(invalid("snapshot exceeds its size limit"));
        }
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        network: Network,
        max_bytes: u64,
        deadline: Instant,
    ) -> io::Result<Self> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes || bytes.len() < 84 {
            return Err(invalid("invalid snapshot size"));
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 32);
        if Sha256::digest(payload).as_slice() != checksum {
            return Err(invalid("snapshot checksum mismatch"));
        }
        let mut input = payload;
        if &take::<8>(&mut input)? != MAGIC {
            return Err(invalid("invalid snapshot magic"));
        }
        if u32::from_le_bytes(take(&mut input)?) != VERSION {
            return Err(invalid("unsupported mempool snapshot version"));
        }
        if take::<32>(&mut input)? != network.genesis_block_hash().to_le_bytes() {
            return Err(invalid("mempool snapshot belongs to another network"));
        }
        let count = usize::try_from(u32::from_le_bytes(take(&mut input)?))
            .map_err(|_| invalid("transaction count overflow"))?;
        let delta_count = usize::try_from(u32::from_le_bytes(take(&mut input)?))
            .map_err(|_| invalid("fee delta count overflow"))?;
        if count > bytes.len() / 17 || delta_count > bytes.len() / 40 {
            return Err(invalid("snapshot record count exceeds its bound"));
        }
        let mut transactions = Vec::new();
        let mut ids = hashbrown::HashSet::new();
        for _ in 0..count {
            check_deadline(deadline)?;
            let saved = decode_saved_transaction(&mut input)?;
            if !ids.insert(saved.txid) {
                return Err(invalid("duplicate snapshot transaction"));
            }
            transactions.push(saved);
        }
        let mut deltas = Vec::new();
        let mut ids = hashbrown::HashSet::new();
        for _ in 0..delta_count {
            check_deadline(deadline)?;
            let (txid, delta) = decode_fee_delta(&mut input)?;
            if !ids.insert(txid) {
                return Err(invalid("duplicate snapshot fee delta"));
            }
            deltas.push((txid, delta));
        }
        if !input.is_empty() {
            return Err(invalid("trailing snapshot bytes"));
        }
        transactions.sort_unstable_by_key(|row| row.txid);
        Ok(Self {
            transactions,
            deltas,
        })
    }

    pub fn order(&self) -> io::Result<Vec<usize>> {
        let positions: HashMap<_, _> = self
            .transactions
            .iter()
            .enumerate()
            .map(|(i, row)| (row.txid, i))
            .collect();
        let parents: Vec<Vec<usize>> = self
            .transactions
            .iter()
            .map(|row| {
                row.tx
                    .inputs
                    .iter()
                    .filter_map(|input| positions.get(&input.previous_output.txid).copied())
                    .collect()
            })
            .collect();
        crate::fee_diagram::topological(&parents, &(0..self.transactions.len()).collect::<Vec<_>>())
            .map_err(|_| invalid("cyclic snapshot dependencies"))
    }
}
fn decode_saved_transaction(input: &mut &[u8]) -> io::Result<SavedTransaction> {
    let time = u64::from_le_bytes(take(input)?);
    let unbroadcast = match take::<1>(input)? {
        [0] => false,
        [1] => true,
        _ => return Err(invalid("invalid initial broadcast flag")),
    };
    let sigop_cost = u32::from_le_bytes(take(input)?);
    if sigop_cost > crate::standardness::MAX_STANDARD_TX_SIGOPS_COST {
        return Err(invalid("snapshot transaction exceeds standard sigop cost"));
    }
    let len = usize::try_from(u32::from_le_bytes(take(input)?))
        .map_err(|_| invalid("transaction size overflow"))?;
    if len == 0 || len > MAX_TX_BYTES {
        return Err(invalid("snapshot transaction exceeds its size bound"));
    }
    let (raw, rest) = input
        .split_at_checked(len)
        .ok_or_else(|| invalid("truncated transaction"))?;
    *input = rest;
    let tx: Tx = deserialize(raw).map_err(|_| invalid("invalid snapshot transaction"))?;
    if consensus_bytes(&tx) != raw {
        return Err(invalid("noncanonical snapshot transaction"));
    }
    let txid = tx.txid();
    Ok(SavedTransaction {
        tx: Arc::new(tx),
        txid,
        time,
        unbroadcast,
        sigop_cost,
    })
}

fn decode_fee_delta(input: &mut &[u8]) -> io::Result<(Txid, i64)> {
    let txid = Txid(Hash256::from_le_bytes(&take(input)?));
    let delta = i64::from_le_bytes(take(input)?);
    Ok((txid, delta))
}

pub struct PreparedSnapshot {
    file: tempfile::NamedTempFile,
    network: Network,
    deadline: Instant,
    max_bytes: u64,
}

impl PreparedSnapshot {
    pub fn publish(self) -> io::Result<()> {
        check_deadline(self.deadline)?;
        let data_dir = self
            .file
            .path()
            .parent()
            .ok_or_else(|| invalid("missing staging directory"))?
            .to_path_buf();
        let live = data_dir.join(FILE_NAME);
        let validation = read_file(&live, self.max_bytes, self.deadline).and_then(|bytes| {
            bytes
                .map(|bytes| Snapshot::decode(&bytes, self.network, self.max_bytes, self.deadline))
                .transpose()
        });
        match validation {
            Ok(_) => {}
            Err(error)
                if error.kind() == io::ErrorKind::InvalidData
                    && std::fs::symlink_metadata(&live)?.is_file() =>
            {
                check_deadline(self.deadline)?;
                let rejected = tempfile::Builder::new()
                    .prefix("mempool-snapshot-rejected-")
                    .tempdir_in(&data_dir)?;
                std::fs::rename(&live, rejected.path().join(FILE_NAME))?;
                let path = rejected.keep();
                tracing::warn!(%error, path = %path.display(), "quarantined rejected mempool snapshot");
            }
            Err(error) => return Err(error),
        }
        check_deadline(self.deadline)?;
        self.file.persist(&live).map_err(|error| error.error)?;
        if let Ok(directory) = std::fs::File::open(&data_dir) {
            if let Err(error) = directory.sync_all() {
                tracing::warn!(%error, "mempool snapshot published but directory sync failed; crash durability is uncertain");
            }
        }
        Ok(())
    }
}

pub fn prepare(
    data_dir: &Path,
    gateway: &MempoolGateway,
    network: Network,
    max_bytes: u64,
    deadline: Instant,
) -> io::Result<PreparedSnapshot> {
    let started = Instant::now();
    let snapshot = Snapshot::capture(
        gateway,
        deadline,
        max_bytes,
        usize::try_from(u32::MAX).unwrap_or(usize::MAX),
    )?;
    let bytes = snapshot.encode(network, max_bytes, deadline)?;
    let mut file = tempfile::Builder::new()
        .prefix("mempool-snapshot-")
        .suffix(".tmp")
        .tempfile_in(data_dir)?;
    for chunk in bytes.chunks(64 * 1024) {
        check_deadline(deadline)?;
        file.write_all(chunk)?;
    }
    file.as_file().sync_all()?;
    check_deadline(deadline)?;
    tracing::info!(
        transactions = snapshot.transactions.len(),
        bytes = bytes.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "prepared mempool snapshot"
    );
    Ok(PreparedSnapshot {
        file,
        network,
        deadline,
        max_bytes,
    })
}

pub fn save(
    data_dir: &Path,
    gateway: &MempoolGateway,
    network: Network,
    max_bytes: u64,
    deadline: Instant,
) -> io::Result<()> {
    prepare(data_dir, gateway, network, max_bytes, deadline)?.publish()
}

pub fn restore(
    data_dir: &Path,
    gateway: &MempoolGateway,
    network: Network,
    chain: &dyn AdmissionChain,
    now: u64,
    max_bytes: u64,
    deadline: Instant,
) -> io::Result<Option<RestoreReport>> {
    {
        let pool = gateway.read();
        if !pool.is_empty() || pool.fee_deltas().len() != 0 {
            return Err(invalid("snapshot restore requires a fresh mempool"));
        }
    }
    let Some(bytes) = read_file(&data_dir.join(FILE_NAME), max_bytes, deadline)? else {
        return Ok(None);
    };
    let snapshot = Snapshot::decode(&bytes, network, max_bytes, deadline)?;
    drop(bytes);
    restore_candidates(&snapshot, gateway, chain, now, deadline).map(Some)
}

struct RestoreGraph {
    neighbors: HashMap<Txid, Vec<Txid>>,
    confirmed: hashbrown::HashSet<Txid>,
}

fn build_restore_graph(
    snapshot: &Snapshot,
    positions: &HashMap<Txid, &SavedTransaction>,
    chain: &dyn AdmissionChain,
    deadline: Instant,
) -> io::Result<RestoreGraph> {
    let mut graph = RestoreGraph {
        neighbors: HashMap::new(),
        confirmed: hashbrown::HashSet::new(),
    };
    for row in &snapshot.transactions {
        check_deadline(deadline)?;
        let view = chain.snapshot(&row.tx).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "snapshot admission chain facts unavailable",
            )
        })?;
        if view.confirmed {
            graph.confirmed.insert(row.txid);
        }
        for input in &row.tx.inputs {
            check_deadline(deadline)?;
            let point = input.previous_output;
            if positions.contains_key(&point.txid) {
                graph
                    .neighbors
                    .entry(row.txid)
                    .or_default()
                    .push(point.txid);
                graph
                    .neighbors
                    .entry(point.txid)
                    .or_default()
                    .push(row.txid);
            }
        }
    }
    Ok(graph)
}

fn collect_saved_family(
    root: Txid,
    graph: &RestoreGraph,
    deadline: Instant,
) -> io::Result<hashbrown::HashSet<Txid>> {
    let mut members = hashbrown::HashSet::new();
    members.insert(root);
    let mut pending = vec![root];
    while let Some(id) = pending.pop() {
        check_deadline(deadline)?;
        for neighbor in graph.neighbors.get(&id).into_iter().flatten() {
            check_deadline(deadline)?;
            if members.insert(*neighbor) {
                if members.len() > crate::standardness::MAX_PACKAGE_COUNT {
                    return Ok(members);
                }
                pending.push(*neighbor);
            }
        }
    }
    Ok(members)
}
enum FamilyRestore {
    Accepted(MutationResult),
    Rejected,
    Limited,
}

fn restore_family(
    family: &[&SavedTransaction],
    gateway: &MempoolGateway,
    chain: &dyn AdmissionChain,
    deadline: Instant,
    package_attempts: &mut u64,
) -> io::Result<FamilyRestore> {
    let mut attempts = 0;
    let times: HashMap<_, _> = family.iter().map(|row| (row.txid, row.time)).collect();
    for count in (1..=family.len()).rev() {
        let mut subset: Vec<_> = (0..count).collect();
        loop {
            check_deadline(deadline)?;
            if attempts == MAX_SUBSET_ATTEMPTS {
                return Ok(FamilyRestore::Limited);
            }
            attempts += 1;
            *package_attempts += 1;
            let package: Vec<_> = subset
                .iter()
                .map(|&index| family[index].tx.as_ref().clone())
                .collect();
            match gateway.submit_package_with_times(
                &package,
                LocalOrigin::Snapshot,
                None,
                |tx| times[&tx.txid()],
                chain,
            ) {
                Ok(result) => return Ok(FamilyRestore::Accepted(result)),
                Err(crate::SubmitError::RetryExhausted) => return Ok(FamilyRestore::Limited),
                Err(crate::SubmitError::Policy(_) | crate::SubmitError::Consensus) => {}
            }
            let Some(position) = (0..count)
                .rev()
                .find(|&position| subset[position] < family.len() - count + position)
            else {
                break;
            };
            subset[position] += 1;
            for next in position + 1..count {
                subset[next] = subset[next - 1] + 1;
            }
        }
    }
    Ok(FamilyRestore::Rejected)
}

fn restore_candidates(
    snapshot: &Snapshot,
    gateway: &MempoolGateway,
    chain: &dyn AdmissionChain,
    now: u64,
    deadline: Instant,
) -> io::Result<RestoreReport> {
    let order = snapshot.order()?;
    let topo_order: HashMap<Txid, usize> = order
        .iter()
        .enumerate()
        .map(|(topo, &idx)| (snapshot.transactions[idx].txid, topo))
        .collect();
    let positions: HashMap<_, _> = snapshot
        .transactions
        .iter()
        .map(|row| (row.txid, row))
        .collect();
    let eligible = |row: &SavedTransaction| {
        row.time <= now
            && now - row.time <= MAX_AGE
            && row.sigop_cost <= crate::standardness::MAX_STANDARD_TX_SIGOPS_COST
    };
    for (txid, delta) in &snapshot.deltas {
        gateway
            .prioritise(*txid, *delta)
            .map_err(|_| invalid("snapshot fee delta overflow"))?;
    }
    let mut report = RestoreReport {
        candidates: snapshot.transactions.len(),
        restored: 0,
        skipped: snapshot.transactions.len(),
        timed_out: false,
        limited: 0,
        package_attempts: 0,
    };
    let graph = match build_restore_graph(snapshot, &positions, chain, deadline) {
        Ok(graph) => graph,
        Err(error) => {
            if error.kind() == io::ErrorKind::TimedOut {
                report.timed_out = true;
            } else {
                report.limited = report.candidates;
            }
            return Ok(report);
        }
    };
    let mut processed = hashbrown::HashSet::new();
    for index in order {
        if check_deadline(deadline).is_err() {
            report.timed_out = true;
            break;
        }
        let row = &snapshot.transactions[index];
        if processed.contains(&row.txid) {
            continue;
        }
        let Ok(family) = collect_saved_family(row.txid, &graph, deadline) else {
            report.timed_out = true;
            break;
        };
        let newly_processed = family
            .iter()
            .filter(|&&id| {
                processed.insert(id) && eligible(positions[&id]) && !graph.confirmed.contains(&id)
            })
            .count();
        if family.len() > crate::standardness::MAX_PACKAGE_COUNT {
            report.limited += newly_processed;
            continue;
        }
        let mut candidates: Vec<_> = family
            .iter()
            .filter(|id| eligible(positions[*id]) && !graph.confirmed.contains(*id))
            .map(|id| positions[id])
            .collect();
        candidates.sort_unstable_by_key(|row| topo_order[&row.txid]);
        match restore_family(
            &candidates,
            gateway,
            chain,
            deadline,
            &mut report.package_attempts,
        ) {
            Ok(FamilyRestore::Accepted(result)) => {
                for change in result.changes {
                    let id = Txid(change.txid);
                    if let Some(saved) = positions.get(&id)
                        && saved.unbroadcast
                    {
                        gateway.set_pending_broadcast(saved.tx.wtxid());
                    }
                }
            }
            Ok(FamilyRestore::Limited) => report.limited += candidates.len(),
            Ok(FamilyRestore::Rejected) => {}
            Err(_) => {
                report.timed_out = true;
                break;
            }
        }
    }
    report.timed_out |= check_deadline(deadline).is_err();
    report.restored = gateway.read().len();
    report.skipped = report.candidates.saturating_sub(report.restored);
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolLimits, PrevoutMeta};
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_consensus::primitives::{
        Amount, LockTime, OutPoint, Script, Sequence, TxIn, TxOut, Witness,
    };
    use parking_lot::{Mutex, RwLock};
    use std::time::Duration;

    type TestResult = Result<(), crate::test_error::TestError>;
    const NOW: u64 = 2_000_000;
    const INTERRUPTED_STAGE: &str = "mempool-snapshot-interrupted.tmp";

    mod restore_model {
        use super::*;

        const LINK_RECORDS: u64 = 8;

        #[expect(
            clippy::expect_used,
            reason = "every generated graph index and output count is bounded by four"
        )]
        fn graph(
            parents: &[Vec<usize>],
            fees: u32,
            nonfinal: u32,
            chain_state: u8,
        ) -> (Snapshot, Coins) {
            let mut rows: Vec<SavedTransaction> = Vec::new();
            let mut coins = Coins {
                outputs: Vec::new(),
                height: 100,
                coinbase: false,
            };
            for (index, inputs) in parents.iter().enumerate() {
                let mut funding = Vec::new();
                if inputs.is_empty() {
                    let point = OutPoint::new(
                        Txid(Hash256::from_le_bytes(
                            &[u8::try_from(index + 40).expect("small graph"); 32],
                        )),
                        0,
                    );
                    coins.outputs.push((point, output(100_000)));
                    funding.push((point, 100_000));
                } else {
                    for &parent in inputs {
                        let slot = parents[..index]
                            .iter()
                            .filter(|edges| edges.contains(&parent))
                            .count();
                        funding.push((
                            OutPoint::new(
                                rows[parent].txid,
                                u32::try_from(slot).expect("small graph"),
                            ),
                            rows[parent].tx.outputs[slot].value.to_sat(),
                        ));
                    }
                }
                let available = funding.iter().map(|(_, value)| value).sum::<u64>()
                    - if fees & (1 << index) == 0 { 0 } else { 2_000 };
                let outputs = parents
                    .iter()
                    .filter(|edges| edges.contains(&index))
                    .count()
                    + 1;
                let outputs = u64::try_from(outputs).expect("small graph");
                let mut tx = spend(funding[0].0, available);
                tx.inputs = funding
                    .iter()
                    .map(|(point, _)| {
                        let mut input = tx.inputs[0].clone();
                        input.previous_output = *point;
                        input
                    })
                    .collect();
                tx.outputs = (0..outputs)
                    .map(|slot| {
                        output(
                            available / outputs + if slot == 0 { available % outputs } else { 0 },
                        )
                    })
                    .collect();
                if nonfinal & (1 << index) != 0 {
                    tx.lock_time = LockTime::from_consensus(150);
                    tx.inputs[0].sequence = Sequence::ZERO;
                }
                rows.push(SavedTransaction {
                    txid: tx.txid(),
                    tx: Arc::new(tx),
                    time: NOW - u64::try_from(index).expect("small graph"),
                    unbroadcast: index % 2 == 0,
                    sigop_cost: 0,
                });
            }
            if (1..=3).contains(&chain_state) {
                let root = &rows[0];
                coins
                    .outputs
                    .retain(|(point, _)| *point != root.tx.inputs[0].previous_output);
                if chain_state == 1 || chain_state == 3 {
                    coins
                        .outputs
                        .extend(root.tx.outputs.iter().enumerate().map(|(slot, out)| {
                            (
                                OutPoint::new(root.txid, u32::try_from(slot).expect("small graph")),
                                out.clone(),
                            )
                        }));
                }
            }
            if chain_state == 3 || chain_state == 4 {
                rows[0].time = NOW - MAX_AGE - 1;
            }
            (
                Snapshot {
                    transactions: rows,
                    deltas: Vec::new(),
                },
                coins,
            )
        }

        fn membership(gateway: &MempoolGateway, ids: &[Txid]) -> u32 {
            let pool = gateway.read();
            ids.iter().enumerate().fold(0, |mask, (index, id)| {
                mask | if pool.contains_txid(id) {
                    1 << index
                } else {
                    0
                }
            })
        }

        #[test]
        fn generated_small_graphs_match_direct_gateway_maximal_subsets() -> TestResult {
            let shapes = [
                vec![vec![], vec![0]],
                vec![vec![], vec![0], vec![1]],
                vec![vec![], vec![0], vec![0]],
                vec![vec![], vec![], vec![0, 1]],
                vec![vec![], vec![0], vec![0], vec![1, 2]],
            ];
            let mut comparisons = 0;
            for (shape, parents) in shapes.iter().enumerate() {
                for fees in 0..1_u32 << parents.len() {
                    for nonfinal in 0..1_u32 << parents.len() {
                        for state in 0..5 {
                            let (mut snapshot, chain) = graph(parents, fees, nonfinal, state);
                            let ids: Vec<_> =
                                snapshot.transactions.iter().map(|row| row.txid).collect();
                            for capacity in
                                [0, crate::entry_memory_usage(&snapshot.transactions[0].tx)]
                            {
                                let mut best = vec![0_u32];
                                for mask in 1..1_u32 << parents.len() {
                                    let control = gateway(
                                        MempoolLimits {
                                            max_total_bytes: capacity,
                                            ..Default::default()
                                        },
                                        None,
                                    );
                                    let package: Vec<_> = snapshot
                                        .transactions
                                        .iter()
                                        .enumerate()
                                        .filter(|(index, _)| mask & (1 << index) != 0)
                                        .filter(|(index, _)| {
                                            !((state == 3 || state == 4) && *index == 0)
                                        })
                                        .map(|(_, row)| row.tx.as_ref().clone())
                                        .collect();
                                    if control
                                        .submit_package_with_times(
                                            &package,
                                            LocalOrigin::Rpc,
                                            None,
                                            |_| NOW,
                                            &chain,
                                        )
                                        .is_ok()
                                    {
                                        let admitted = membership(&control, &ids);
                                        match admitted.count_ones().cmp(&best[0].count_ones()) {
                                            std::cmp::Ordering::Greater => best = vec![admitted],
                                            std::cmp::Ordering::Equal => best.push(admitted),
                                            std::cmp::Ordering::Less => {}
                                        }
                                    }
                                }
                                for reversed in [false, true] {
                                    if reversed {
                                        snapshot.transactions.reverse();
                                    }
                                    let target = gateway(
                                        MempoolLimits {
                                            max_total_bytes: capacity,
                                            ..Default::default()
                                        },
                                        None,
                                    );
                                    let report = restore_candidates(
                                        &snapshot,
                                        &target,
                                        &chain,
                                        NOW,
                                        deadline(),
                                    )?;
                                    assert!(!report.timed_out);
                                    assert_eq!(report.limited, 0);
                                    let actual = membership(&target, &ids);
                                    assert!(
                                        best.contains(&actual),
                                        "shape={shape} fees={fees:b} nonfinal={nonfinal:b} state={state} capacity={capacity} reversed={reversed}: actual={actual:b} best={best:?}"
                                    );
                                    comparisons += 1;
                                    if reversed {
                                        snapshot.transactions.reverse();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            eprintln!(
                "compared {comparisons} generated restore outcomes with direct gateway subsets"
            );
            Ok(())
        }

        #[test]
        fn search_limits_do_not_commit_a_parent_before_subset_search_finishes() -> TestResult {
            for (count, nonfinal_children) in [(8, true), (9, true), (25, false), (26, false)] {
                let funding = OutPoint::new(Txid(Hash256::from_le_bytes(&[32; 32])), 0);
                let chain = Coins {
                    outputs: vec![(funding, output(100_000))],
                    height: 100,
                    coinbase: false,
                };
                let mut point = funding;
                let mut rows = Vec::new();
                for index in 0..count {
                    let mut tx = spend(point, 95_000);
                    if index != 0 && nonfinal_children {
                        tx.lock_time = LockTime::from_consensus(150);
                        tx.inputs[0].sequence = Sequence::ZERO;
                    }
                    point = OutPoint::new(tx.txid(), 0);
                    rows.push(SavedTransaction {
                        txid: tx.txid(),
                        tx: Arc::new(tx),
                        time: NOW,
                        unbroadcast: true,
                        sigop_cost: 0,
                    });
                }
                let control = gateway(MempoolLimits::default(), None);
                admit(&control, &rows[0].tx, &chain)?;
                assert_eq!(control.read().len(), 1, "the parent can enter alone");
                let snapshot = Snapshot {
                    transactions: rows,
                    deltas: Vec::new(),
                };
                let seen = Arc::new(Seen::default());
                let target = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
                let report = restore_candidates(&snapshot, &target, &chain, NOW, deadline())?;
                assert!(!report.timed_out);
                if count == 8 {
                    assert_eq!((report.restored, report.limited), (1, 0));
                    assert!(report.package_attempts <= 255);
                    assert_eq!(seen.0.lock().len(), 1);
                } else if count == 25 {
                    assert_eq!(
                        (report.restored, report.limited, report.package_attempts),
                        (25, 0, 1)
                    );
                    assert_eq!(seen.0.lock().len(), 1);
                } else {
                    assert_eq!((report.restored, report.limited), (0, count));
                    assert!(
                        seen.0.lock().is_empty(),
                        "failed searches publish no commits"
                    );
                    assert_eq!(target.read().sequence_number(), 0);
                    assert_eq!(
                        report.package_attempts,
                        if count == 9 {
                            u64::try_from(MAX_SUBSET_ATTEMPTS)?
                        } else {
                            0
                        }
                    );
                }
            }
            Ok(())
        }

        #[test]
        fn deadline_exhaustion_leaves_the_current_family_uncommitted() -> TestResult {
            let rows = saved_ancestor_chain(3);
            let members: Vec<_> = rows.iter().collect();
            let target = gateway(MempoolLimits::default(), None);
            let (prefix_chain, prefix, _) = family();
            admit(&target, &prefix, &prefix_chain)?;
            let sequence = target.read().sequence_number();
            let chain = AncestorReads {
                calls: std::sync::atomic::AtomicUsize::new(0),
                expire_at: None,
            };
            let mut attempts = 0;
            let error = restore_family(&members, &target, &chain, Instant::now(), &mut attempts)
                .err()
                .ok_or("expired deadline must stop subset search")?;
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(attempts, 0);
            assert_eq!(chain.calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            assert_eq!(target.read().len(), 1);
            assert!(target.read().contains_txid(&prefix.txid()));
            assert_eq!(target.read().sequence_number(), sequence);
            Ok(())
        }

        #[test]
        fn eight_member_rejection_exhausts_exactly_all_nonempty_subsets() -> TestResult {
            let snapshot = Snapshot {
                transactions: saved_ancestor_chain(8),
                deltas: Vec::new(),
            };
            let target = gateway(MempoolLimits::default(), None);
            let chain = Coins {
                outputs: Vec::new(),
                height: 100,
                coinbase: false,
            };
            let report = restore_candidates(&snapshot, &target, &chain, NOW, deadline())?;
            assert_eq!(
                (report.restored, report.limited, report.package_attempts),
                (0, 0, 255)
            );
            assert!(!report.timed_out);
            assert_eq!(target.read().sequence_number(), 0);
            Ok(())
        }

        #[test]
        fn subset_selection_respects_an_already_committed_pool_prefix() -> TestResult {
            let (snapshot, mut chain) = graph(&[vec![], vec![0]], 1, 0, 0);
            let funding = OutPoint::new(Txid(Hash256::from_le_bytes(&[61; 32])), 0);
            chain.outputs.push((funding, output(100_000)));
            let prefix = spend(funding, 99_000);
            let ids: Vec<_> = snapshot.transactions.iter().map(|row| row.txid).collect();
            let family: Vec<_> = snapshot.transactions.iter().collect();
            let parent_size = crate::entry_memory_usage(&family[0].tx);
            let child_size = crate::entry_memory_usage(&family[1].tx) + LINK_RECORDS;
            for budget in [parent_size, parent_size + child_size] {
                let capacity = crate::entry_memory_usage(&prefix) + budget;
                let mut best = vec![0_u32];
                for mask in 1..4 {
                    let control = gateway(
                        MempoolLimits {
                            max_total_bytes: capacity,
                            ..Default::default()
                        },
                        None,
                    );
                    admit(&control, &prefix, &chain)?;
                    let package: Vec<_> = family
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| mask & (1 << index) != 0)
                        .map(|(_, row)| row.tx.as_ref().clone())
                        .collect();
                    if control
                        .submit_package_with_times(
                            &package,
                            LocalOrigin::Rpc,
                            None,
                            |_| NOW,
                            &chain,
                        )
                        .is_ok()
                    {
                        let admitted = membership(&control, &ids);
                        match admitted.count_ones().cmp(&best[0].count_ones()) {
                            std::cmp::Ordering::Greater => best = vec![admitted],
                            std::cmp::Ordering::Equal => best.push(admitted),
                            std::cmp::Ordering::Less => {}
                        }
                    }
                }
                let target = gateway(
                    MempoolLimits {
                        max_total_bytes: capacity,
                        ..Default::default()
                    },
                    None,
                );
                admit(&target, &prefix, &chain)?;
                let mut attempts = 0;
                assert!(matches!(
                    restore_family(&family, &target, &chain, deadline(), &mut attempts)?,
                    FamilyRestore::Accepted(_)
                ));
                assert!(best.contains(&membership(&target, &ids)));
                assert!(
                    target.read().contains_txid(&prefix.txid()),
                    "restore must not evict its prefix"
                );
            }
            Ok(())
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    struct Coins {
        outputs: Vec<(OutPoint, TxOut)>,
        height: u32,
        coinbase: bool,
    }
    impl AdmissionChain for Coins {
        fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            Some(ChainAdmissionSnapshot {
                prevouts: self.outputs.clone(),
                height: self.height,
                prevout_meta: self
                    .outputs
                    .iter()
                    .map(|(point, _)| {
                        (
                            *point,
                            PrevoutMeta {
                                height: 1,
                                mtp: 0,
                                coinbase: self.coinbase,
                            },
                        )
                    })
                    .collect(),
                confirmed: self
                    .outputs
                    .iter()
                    .any(|(point, _)| point.txid == tx.txid()),
                ..Default::default()
            })
        }
    }

    #[derive(Default)]
    struct Seen(Mutex<Vec<crate::MutationEnvelope>>);
    impl crate::MempoolObserver for Seen {
        fn on_mutation(&self, batch: &crate::MutationEnvelope) {
            self.0.lock().push(batch.clone());
        }
    }

    fn gateway(limits: MempoolLimits, seen: Option<Arc<Seen>>) -> MempoolGateway {
        MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(limits))),
            seen.map(|observer| {
                let leg: Arc<dyn crate::MempoolObserver> = observer;
                (leg, crate::BodyInterest::Metadata)
            }),
            ValidationEngine::Native,
            None,
        )
    }
    fn output(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(
                [vec![0, 32], Sha256::digest([0x51]).to_vec()].concat(),
            ),
        }
    }

    fn spend(point: OutPoint, value: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: point,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_stack(vec![vec![0x51]]),
            }],
            outputs: vec![output(value)],
        }
    }

    fn family() -> (Coins, Tx, Tx) {
        let point = OutPoint::new(Txid(Hash256::from_le_bytes(&[7; 32])), 0);
        let parent = spend(point, 99_000);
        let child = spend(OutPoint::new(parent.txid(), 0), 98_000);
        (
            Coins {
                outputs: vec![(point, output(100_000))],
                height: 100,
                coinbase: true,
            },
            parent,
            child,
        )
    }

    fn admit(gateway: &MempoolGateway, tx: &Tx, chain: &dyn AdmissionChain) -> TestResult {
        gateway.submit_transaction(
            Arc::new(tx.clone()),
            AdmissionOrigin::Rpc,
            None,
            NOW - 10,
            chain,
        )?;
        Ok(())
    }

    #[test]
    fn restores_dependencies_priorities_and_gateway_publication() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (chain, parent, child) = family();
        let source = gateway(MempoolLimits::default(), None);
        admit(&source, &parent, &chain)?;
        admit(&source, &child, &chain)?;
        source.mark_broadcast(parent.wtxid());
        source.commit_broadcast(parent.wtxid());
        source.prioritise(parent.txid(), 500)?;
        let absent = Txid(Hash256::from_le_bytes(&[8; 32]));
        source.prioritise(absent, i64::MIN)?;
        let before_history = source.read().estimator_history();
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let seen = Arc::new(Seen::default());
        let restored = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
        crate::fee_history::save(dir.path(), &before_history);
        crate::fee_history::load(dir.path(), &restored.pool);
        let report = restore(
            dir.path(),
            &restored,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing snapshot")?;
        assert_eq!(
            (
                report.candidates,
                report.restored,
                report.skipped,
                report.timed_out
            ),
            (2, 2, 0, false)
        );
        let pool = restored.read();
        let entry = pool.entry_by_txid(&child.txid()).ok_or("missing child")?;
        assert!(entry.unbroadcast);
        assert!(
            !pool
                .entry_by_txid(&parent.txid())
                .ok_or("missing parent")?
                .unbroadcast
        );
        assert_eq!(
            (
                entry.ancestor_fee,
                entry.ancestor_fee_delta,
                entry.time,
                entry.height
            ),
            (2_000, 500, NOW - 10, 100)
        );
        assert_eq!(
            pool.entry_by_txid(&parent.txid())
                .ok_or("missing parent")?
                .fee_delta,
            500
        );
        assert!(
            pool.prioritised_transactions()
                .iter()
                .any(|row| row.txid == absent && row.fee_delta == i64::MIN)
        );
        assert!(
            pool.estimator_history() == before_history,
            "snapshot restore must not rewrite estimator state"
        );
        assert_eq!(
            Sha256::digest(std::fs::read(dir.path().join("fee-estimator-history.dat"))?),
            Sha256::digest(&before_history)
        );
        drop(pool);
        let batches = seen.0.lock();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].result.changes.len(), 2);
        assert_eq!(
            batches[0].result.changes[0].txid,
            Hash256::from(parent.txid())
        );
        assert_eq!(
            batches[0].result.changes[1].txid,
            Hash256::from(child.txid())
        );
        assert!(
            batches
                .iter()
                .all(|batch| batch.origin == AdmissionOrigin::Snapshot)
        );
        assert_eq!(restored.orphan_count(), 0);
        assert_eq!(restored.recent_rejects_count(), 0);
        Ok(())
    }

    #[test]
    fn rechecks_spent_coins_maturity_fee_floor_capacity_and_expiry() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (chain, parent, child) = family();
        let source = gateway(MempoolLimits::default(), None);
        admit(&source, &parent, &chain)?;
        admit(&source, &child, &chain)?;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        for (chain, limits, now) in [
            (
                Coins {
                    outputs: vec![],
                    height: 100,
                    coinbase: false,
                },
                MempoolLimits::default(),
                NOW,
            ),
            (
                Coins {
                    outputs: chain.outputs.clone(),
                    height: 1,
                    coinbase: true,
                },
                MempoolLimits::default(),
                NOW,
            ),
            (
                Coins {
                    outputs: chain.outputs.clone(),
                    height: 100,
                    coinbase: true,
                },
                MempoolLimits {
                    min_relay_fee_sat_per_kvb: 1_000_000,
                    ..Default::default()
                },
                NOW,
            ),
            (
                Coins {
                    outputs: chain.outputs.clone(),
                    height: 100,
                    coinbase: true,
                },
                MempoolLimits {
                    max_total_bytes: 1,
                    ..Default::default()
                },
                NOW,
            ),
            (
                Coins {
                    outputs: chain.outputs,
                    height: 100,
                    coinbase: true,
                },
                MempoolLimits::default(),
                NOW + MAX_AGE + 1,
            ),
        ] {
            let pool = gateway(limits, None);
            let report = restore(
                dir.path(),
                &pool,
                Network::Regtest,
                &chain,
                now,
                DEFAULT_MAX_BYTES,
                deadline(),
            )?
            .ok_or("missing snapshot")?;
            assert_eq!(report.restored, 0);
            assert!(pool.read().is_empty());
            assert_eq!(pool.read().unbroadcast_transactions().count(), 0);
            assert_eq!(pool.orphan_count(), 0);
        }
        let confirmed = Coins {
            outputs: vec![(OutPoint::new(parent.txid(), 0), parent.outputs[0].clone())],
            height: 101,
            coinbase: false,
        };
        let pool = gateway(MempoolLimits::default(), None);
        let report = restore(
            dir.path(),
            &pool,
            Network::Regtest,
            &confirmed,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing snapshot")?;
        assert_eq!(report.restored, 1);
        assert!(pool.read().contains_txid(&child.txid()));
        Ok(())
    }

    #[test]
    fn restores_cpfp_and_ephemeral_dust_through_atomic_package_admission() -> TestResult {
        for ephemeral in [false, true] {
            let dir = tempfile::tempdir()?;
            let (chain, mut parent, _) = family();
            parent.version = 3;
            parent.outputs[0].value = Amount::from_sat(100_000);
            if ephemeral {
                parent.outputs.push(output(0));
            }
            let mut child = spend(OutPoint::new(parent.txid(), 0), 98_000);
            child.version = 3;
            if ephemeral {
                let mut input = child.inputs[0].clone();
                input.previous_output.vout = 1;
                child.inputs.push(input);
            }
            let source = gateway(MempoolLimits::default(), None);
            source.submit_local_package(
                vec![child.clone(), parent.clone()],
                LocalOrigin::Rpc,
                None,
                NOW - 10,
                &chain,
            )?;
            let mut snapshot =
                Snapshot::capture(&source, deadline(), DEFAULT_MAX_BYTES, usize::MAX)?;
            for row in &mut snapshot.transactions {
                row.time = if row.txid == parent.txid() {
                    NOW - 100
                } else {
                    NOW - 10
                };
                row.unbroadcast = row.txid == child.txid();
            }
            std::fs::write(
                dir.path().join(FILE_NAME),
                snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?,
            )?;
            let seen = Arc::new(Seen::default());
            let target = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
            let report = restore(
                dir.path(),
                &target,
                Network::Regtest,
                &chain,
                NOW,
                DEFAULT_MAX_BYTES,
                deadline(),
            )?
            .ok_or("missing snapshot")?;
            assert_eq!(report.restored, 2);
            assert_eq!(
                target
                    .read()
                    .unbroadcast_transactions()
                    .map(|(txid, _, _)| txid)
                    .collect::<Vec<_>>(),
                vec![child.txid()]
            );
            assert_eq!(
                target
                    .read()
                    .entry_by_txid(&parent.txid())
                    .ok_or("parent")?
                    .time,
                NOW - 100
            );
            assert_eq!(
                target
                    .read()
                    .entry_by_txid(&child.txid())
                    .ok_or("child")?
                    .time,
                NOW - 10
            );
            let batches = seen.0.lock();
            assert_eq!(batches.len(), 1);
            assert_eq!(batches[0].result.changes.len(), 2);
        }
        Ok(())
    }

    fn reseal(bytes: &mut [u8]) {
        let end = bytes.len() - 32;
        let digest = Sha256::digest(&bytes[..end]);
        bytes[end..].copy_from_slice(&digest);
    }

    #[test]
    fn restores_valid_subset_when_a_descendant_becomes_nonfinal() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (mut chain, mut a, _) = family();
        a.outputs[0].value = Amount::from_sat(100_000);
        let funding_b = OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0);
        chain.outputs.push((funding_b, output(100_000)));
        let mut b = spend(funding_b, 50_000);
        b.outputs.push(output(50_000));
        let mut c = spend(OutPoint::new(a.txid(), 0), 150_000);
        let mut second = c.inputs[0].clone();
        second.previous_output = OutPoint::new(b.txid(), 0);
        c.inputs.push(second);
        let fee = a.vsize() + c.vsize();
        c.outputs[0].value = Amount::from_sat(150_000 - fee);
        let d = spend(OutPoint::new(b.txid(), 1), 49_000);
        let source = gateway(MempoolLimits::default(), None);
        source.submit_local_package(
            vec![b.clone(), d.clone()],
            LocalOrigin::Rpc,
            None,
            NOW - 20,
            &chain,
        )?;
        source.submit_local_package(
            vec![a.clone(), c.clone()],
            LocalOrigin::Rpc,
            None,
            NOW - 10,
            &chain,
        )?;
        let mut nonfinal = spend(OutPoint::new(d.txid(), 0), 48_000);
        nonfinal.lock_time = LockTime::from_consensus(150);
        nonfinal.inputs[0].sequence = Sequence::ZERO;
        chain.height = 200;
        admit(&source, &nonfinal, &chain)?;
        chain.height = 100;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let seen = Arc::new(Seen::default());
        let target = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("snapshot")?;
        assert_eq!((report.restored, report.timed_out), (4, false));
        assert_eq!((report.candidates, report.skipped), (5, 1));
        assert!(!target.read().contains_txid(&nonfinal.txid()));
        for tx in [&a, &b, &c, &d] {
            assert!(target.read().contains_txid(&tx.txid()));
        }
        let batches = seen.0.lock();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].result.changes.len(), 4);
        assert!(
            batches[0]
                .result
                .changes
                .iter()
                .any(|row| row.txid == Hash256::from(d.txid()))
        );
        assert!(
            batches[0]
                .result
                .changes
                .iter()
                .any(|row| row.txid == Hash256::from(c.txid()))
        );
        Ok(())
    }

    #[test]
    fn capacity_limits_save_whole_families_and_all_priorities() -> TestResult {
        let (mut chain, parent, child) = family();
        let source = gateway(MempoolLimits::default(), None);
        admit(&source, &parent, &chain)?;
        admit(&source, &child, &chain)?;
        let point = OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0);
        chain.outputs.push((point, output(100_000)));
        let independent = spend(point, 99_000);
        admit(&source, &independent, &chain)?;
        let absent = Txid(Hash256::from_le_bytes(&[10; 32]));
        source.prioritise(absent, 50)?;
        let family_bytes =
            84 + 40 + u64::try_from(parent.total_size())? + u64::try_from(child.total_size())? + 34;
        for (bytes, count) in [(family_bytes, usize::MAX), (DEFAULT_MAX_BYTES, 2)] {
            let snapshot = Snapshot::capture(&source, deadline(), bytes, count)?;
            assert_eq!(snapshot.transactions.len(), 2);
            assert!(
                snapshot
                    .transactions
                    .iter()
                    .any(|row| row.txid == parent.txid())
            );
            assert!(
                snapshot
                    .transactions
                    .iter()
                    .any(|row| row.txid == child.txid())
            );
            assert_eq!(snapshot.deltas, vec![(absent, 50)]);
            let dir = tempfile::tempdir()?;
            let encoded = snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
            assert!(u64::try_from(encoded.len())? <= bytes);
            std::fs::write(dir.path().join(FILE_NAME), encoded)?;
        }
        assert_eq!(
            Snapshot::capture(&source, deadline(), family_bytes - 1, usize::MAX)?.transactions,
            []
        );
        assert_eq!(
            Snapshot::capture(&source, deadline(), DEFAULT_MAX_BYTES, 1)?.transactions,
            []
        );
        let dir = tempfile::tempdir()?;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            family_bytes,
            deadline(),
        )?;
        let target = gateway(MempoolLimits::default(), None);
        assert_eq!(
            restore(
                dir.path(),
                &target,
                Network::Regtest,
                &chain,
                NOW,
                family_bytes,
                deadline()
            )?
            .ok_or("snapshot")?
            .candidates,
            2
        );
        let full_bytes = family_bytes + u64::try_from(independent.total_size())? + 17;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            full_bytes,
            deadline(),
        )?;
        let target = gateway(MempoolLimits::default(), None);
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            full_bytes,
            deadline(),
        )?
        .ok_or("snapshot")?;
        assert_eq!((report.candidates, report.restored), (3, 3));
        Ok(())
    }

    #[test]
    fn byte_budget_allows_more_than_one_hundred_thousand_records() -> TestResult {
        let (_, parent, _) = family();
        let transactions = (0..100_001)
            .map(|index| {
                let mut tx = parent.clone();
                tx.inputs[0].previous_output.vout = index;
                let txid = tx.txid();
                SavedTransaction {
                    tx: Arc::new(tx),
                    txid,
                    time: NOW,
                    unbroadcast: false,
                    sigop_cost: 0,
                }
            })
            .collect();
        let snapshot = Snapshot {
            transactions,
            deltas: Vec::new(),
        };
        let encoded = snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
        assert_eq!(
            Snapshot::decode(&encoded, Network::Regtest, DEFAULT_MAX_BYTES, deadline())?
                .transactions
                .len(),
            100_001
        );
        Ok(())
    }

    #[test]
    fn restore_rejects_preexisting_absent_transaction_priorities() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (chain, parent, _) = family();
        let source = gateway(MempoolLimits::default(), None);
        source.prioritise(parent.txid(), 1)?;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let target = gateway(MempoolLimits::default(), None);
        target.prioritise(parent.txid(), i64::MAX)?;
        assert!(
            restore(
                dir.path(),
                &target,
                Network::Regtest,
                &chain,
                NOW,
                DEFAULT_MAX_BYTES,
                deadline()
            )
            .is_err()
        );
        assert_eq!(
            target.read().prioritised_transactions()[0].fee_delta,
            i64::MAX
        );
        Ok(())
    }

    #[test]
    fn rejects_bad_artifacts_without_mutation_or_overwriting_operator_data() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (chain, parent, _) = family();
        let source = gateway(MempoolLimits::default(), None);
        admit(&source, &parent, &chain)?;
        let valid = Snapshot::capture(&source, deadline(), DEFAULT_MAX_BYTES, usize::MAX)?.encode(
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let mut version = valid.clone();
        version[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        reseal(&mut version);
        let mut network = valid.clone();
        network[12] ^= 1;
        reseal(&mut network);
        let mut count = valid.clone();
        count[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
        reseal(&mut count);
        let mut length = valid.clone();
        length[61..65].copy_from_slice(&u32::MAX.to_le_bytes());
        reseal(&mut length);
        let mut checksum = valid.clone();
        checksum[65] ^= 1;
        let mut trailing = valid.clone();
        trailing.insert(trailing.len() - 32, 0);
        reseal(&mut trailing);
        for bytes in [
            version,
            network,
            count,
            length,
            checksum,
            trailing,
            valid[..valid.len() - 1].to_vec(),
        ] {
            std::fs::write(dir.path().join(FILE_NAME), &bytes)?;
            let pool = gateway(MempoolLimits::default(), None);
            assert!(
                restore(
                    dir.path(),
                    &pool,
                    Network::Regtest,
                    &chain,
                    NOW,
                    DEFAULT_MAX_BYTES,
                    deadline()
                )
                .is_err()
            );
            assert!(pool.read().is_empty());
            save(
                dir.path(),
                &source,
                Network::Regtest,
                DEFAULT_MAX_BYTES,
                deadline(),
            )?;
            assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, valid);
            assert!(
                std::fs::read_dir(dir.path())?
                    .filter_map(Result::ok)
                    .any(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with("mempool-snapshot-rejected-")
                            && std::fs::read(entry.path().join(FILE_NAME))
                                .is_ok_and(|saved| saved == bytes)
                    })
            );
        }
        Ok(())
    }

    #[test]
    fn interrupted_or_failed_save_preserves_the_complete_live_snapshot() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (chain, parent, _) = family();
        let source = gateway(MempoolLimits::default(), None);
        admit(&source, &parent, &chain)?;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let before = std::fs::read(dir.path().join(FILE_NAME))?;
        let guard = source.pool.write();
        assert!(
            save(
                dir.path(),
                &source,
                Network::Regtest,
                DEFAULT_MAX_BYTES,
                Instant::now() + Duration::from_millis(2)
            )
            .is_err()
        );
        drop(guard);
        assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, before);
        std::fs::write(dir.path().join(INTERRUPTED_STAGE), b"interrupted write")?;
        let target = gateway(MempoolLimits::default(), None);
        assert_eq!(
            restore(
                dir.path(),
                &target,
                Network::Regtest,
                &chain,
                NOW,
                DEFAULT_MAX_BYTES,
                deadline()
            )?
            .ok_or("missing")?
            .restored,
            1
        );
        std::fs::remove_file(dir.path().join(INTERRUPTED_STAGE))?;
        std::fs::create_dir(dir.path().join(INTERRUPTED_STAGE))?;
        let marker = dir.path().join(INTERRUPTED_STAGE).join("operator-data");
        std::fs::write(&marker, b"preserve")?;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, before);
        assert_eq!(std::fs::read(marker)?, b"preserve");
        assert!(
            save(
                dir.path(),
                &source,
                Network::Regtest,
                DEFAULT_MAX_BYTES,
                Instant::now()
            )
            .is_err()
        );
        assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, before);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn failed_atomic_replacement_keeps_the_previous_snapshot() -> TestResult {
        use std::os::windows::fs::OpenOptionsExt as _;
        let dir = tempfile::tempdir()?;
        let (chain, parent, child) = family();
        let source = gateway(MempoolLimits::default(), None);
        admit(&source, &parent, &chain)?;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let path = dir.path().join(FILE_NAME);
        let before = std::fs::read(&path)?;
        let guard = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&path)?;
        admit(&source, &child, &chain)?;
        assert!(
            save(
                dir.path(),
                &source,
                Network::Regtest,
                DEFAULT_MAX_BYTES,
                deadline()
            )
            .is_err()
        );
        drop(guard);
        assert_eq!(std::fs::read(&path)?, before);
        assert_eq!(std::fs::read_dir(dir.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn missing_oversized_and_non_file_snapshots_fail_safely() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (chain, _, _) = family();
        let pool = gateway(MempoolLimits::default(), None);
        assert!(
            restore(
                dir.path(),
                &pool,
                Network::Regtest,
                &chain,
                NOW,
                DEFAULT_MAX_BYTES,
                deadline()
            )?
            .is_none()
        );
        let path = dir.path().join(FILE_NAME);
        let file = std::fs::File::create(&path)?;
        file.set_len(DEFAULT_MAX_BYTES + 1)?;
        drop(file);
        assert!(
            restore(
                dir.path(),
                &pool,
                Network::Regtest,
                &chain,
                NOW,
                DEFAULT_MAX_BYTES,
                deadline()
            )
            .is_err()
        );
        save(
            dir.path(),
            &pool,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let rejected = std::fs::read_dir(dir.path())?
            .filter_map(Result::ok)
            .find(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .ok_or("quarantine")?;
        assert_eq!(
            std::fs::metadata(rejected.path().join(FILE_NAME))?.len(),
            DEFAULT_MAX_BYTES + 1
        );
        std::fs::remove_file(&path)?;
        std::fs::create_dir(&path)?;
        std::fs::write(path.join("operator-data"), b"preserve")?;
        assert!(
            restore(
                dir.path(),
                &pool,
                Network::Regtest,
                &chain,
                NOW,
                DEFAULT_MAX_BYTES,
                deadline()
            )
            .is_err()
        );
        assert!(
            save(
                dir.path(),
                &pool,
                Network::Regtest,
                DEFAULT_MAX_BYTES,
                deadline()
            )
            .is_err()
        );
        assert_eq!(std::fs::read(path.join("operator-data"))?, b"preserve");
        Ok(())
    }

    #[test]
    fn revalidates_witness_standardness_finality_and_only_saves_live_rbf_members() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (chain, parent, child) = family();
        let source = gateway(MempoolLimits::default(), None);
        admit(&source, &parent, &chain)?;
        admit(&source, &child, &chain)?;
        let mut replacement = parent.clone();
        replacement.outputs[0].value = Amount::from_sat(90_000);
        admit(&source, &replacement, &chain)?;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let target = gateway(MempoolLimits::default(), None);
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing")?;
        assert_eq!((report.candidates, report.restored), (1, 1));
        assert!(target.read().contains_txid(&replacement.txid()));
        assert!(!target.read().contains_txid(&parent.txid()));
        assert!(!target.read().contains_txid(&child.txid()));

        let mut invalid_witness = parent.clone();
        invalid_witness.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
        let mut nonstandard = parent.clone();
        nonstandard.outputs[0].script_pubkey = Script::from_bytes(vec![0x51]);
        let mut nonfinal = parent;
        nonfinal.lock_time = LockTime::from_consensus(200);
        nonfinal.inputs[0].sequence = Sequence::from_consensus(0xffff_fffe);
        for tx in [invalid_witness, nonstandard, nonfinal] {
            let snapshot = Snapshot {
                transactions: vec![SavedTransaction {
                    txid: tx.txid(),
                    tx: Arc::new(tx),
                    time: NOW - 10,
                    unbroadcast: false,
                    sigop_cost: 0,
                }],
                deltas: vec![],
            };
            std::fs::write(
                dir.path().join(FILE_NAME),
                snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?,
            )?;
            let target = gateway(MempoolLimits::default(), None);
            let report = restore(
                dir.path(),
                &target,
                Network::Regtest,
                &chain,
                NOW,
                DEFAULT_MAX_BYTES,
                deadline(),
            )?
            .ok_or("missing")?;
            assert_eq!((report.restored, report.skipped), (0, 1));
            assert_eq!(target.read().sequence_number(), 0);
        }
        Ok(())
    }

    #[test]
    fn concurrent_admission_and_save_capture_a_coherent_candidate_set() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (chain, parent, child) = family();
        let source = Arc::new(gateway(MempoolLimits::default(), None));
        admit(&source, &parent, &chain)?;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let writer = {
            let source = Arc::clone(&source);
            let barrier = Arc::clone(&barrier);
            let data_dir = dir.path().to_path_buf();
            std::thread::spawn(move || {
                barrier.wait();
                source
                    .submit_transaction(
                        Arc::new(child),
                        AdmissionOrigin::Rpc,
                        None,
                        NOW - 10,
                        &chain,
                    )
                    .map_err(io::Error::other)?;
                save(
                    &data_dir,
                    &source,
                    Network::Regtest,
                    DEFAULT_MAX_BYTES,
                    deadline(),
                )
            })
        };
        barrier.wait();
        let first = save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        );
        let second = writer.join().map_err(|_| "admission thread panicked")?;
        assert!(first.is_ok() || second.is_ok());
        for result in [first, second] {
            #[cfg(windows)]
            if let Err(error) = result {
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            }
            #[cfg(not(windows))]
            result?;
        }
        let (chain, _, _) = family();
        let target = gateway(MempoolLimits::default(), None);
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing")?;
        assert!((1..=2).contains(&report.candidates));
        assert_eq!(report.restored, report.candidates);
        assert!(target.read().contains_txid(&parent.txid()));
        Ok(())
    }

    #[test]
    fn restores_multi_generational_cpfp_package() -> TestResult {
        let dir = tempfile::tempdir()?;
        let point = OutPoint::new(Txid(Hash256::from_le_bytes(&[12; 32])), 0);
        let grandparent = spend(point, 100_000);
        let parent = spend(OutPoint::new(grandparent.txid(), 0), 100_000);
        let child = spend(OutPoint::new(parent.txid(), 0), 90_000);
        let chain = Coins {
            outputs: vec![(point, output(100_000))],
            height: 100,
            coinbase: true,
        };
        let snapshot = Snapshot {
            transactions: vec![
                SavedTransaction {
                    tx: Arc::new(grandparent.clone()),
                    txid: grandparent.txid(),
                    time: NOW - 30,
                    unbroadcast: false,
                    sigop_cost: 0,
                },
                SavedTransaction {
                    tx: Arc::new(parent.clone()),
                    txid: parent.txid(),
                    time: NOW - 20,
                    unbroadcast: false,
                    sigop_cost: 0,
                },
                SavedTransaction {
                    tx: Arc::new(child.clone()),
                    txid: child.txid(),
                    time: NOW - 10,
                    unbroadcast: true,
                    sigop_cost: 0,
                },
            ],
            deltas: vec![],
        };
        std::fs::write(
            dir.path().join(FILE_NAME),
            snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?,
        )?;
        let target = gateway(MempoolLimits::default(), None);
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing snapshot")?;
        assert_eq!(
            (report.candidates, report.restored, report.skipped),
            (3, 3, 0)
        );
        assert!(target.read().contains_txid(&grandparent.txid()));
        assert!(target.read().contains_txid(&parent.txid()));
        assert!(target.read().contains_txid(&child.txid()));
        assert_eq!(
            target
                .read()
                .unbroadcast_transactions()
                .map(|(txid, _, _)| txid)
                .collect::<Vec<_>>(),
            vec![child.txid()]
        );
        Ok(())
    }

    #[test]
    fn snapshot_decode_rejects_excessive_sigop_cost() -> TestResult {
        let (_, parent, _) = family();
        let snapshot = Snapshot {
            transactions: vec![SavedTransaction {
                tx: Arc::new(parent.clone()),
                txid: parent.txid(),
                time: NOW,
                unbroadcast: false,
                sigop_cost: crate::standardness::MAX_STANDARD_TX_SIGOPS_COST + 1,
            }],
            deltas: Vec::new(),
        };
        let encoded = snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
        assert!(
            Snapshot::decode(&encoded, Network::Regtest, DEFAULT_MAX_BYTES, deadline()).is_err()
        );
        Ok(())
    }

    #[test]
    fn restores_cpfp_after_saved_ancestors_confirm_and_are_fully_spent() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (original_chain, grandparent, parent) = family();
        let low_fee = spend(OutPoint::new(parent.txid(), 0), 98_000);
        let paying_child = spend(OutPoint::new(low_fee.txid(), 0), 90_000);
        let source = gateway(MempoolLimits::default(), None);
        admit(&source, &grandparent, &original_chain)?;
        admit(&source, &parent, &original_chain)?;
        source.submit_local_package(
            vec![low_fee.clone(), paying_child.clone()],
            LocalOrigin::Rpc,
            None,
            NOW - 10,
            &original_chain,
        )?;
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;

        let changed_chain = Coins {
            outputs: vec![(OutPoint::new(parent.txid(), 0), parent.outputs[0].clone())],
            height: 102,
            coinbase: false,
        };
        let control = gateway(MempoolLimits::default(), None);
        control.submit_local_package(
            vec![low_fee.clone(), paying_child.clone()],
            LocalOrigin::Rpc,
            None,
            NOW,
            &changed_chain,
        )?;
        assert_eq!(control.read().len(), 2, "independent gateway control");
        let target = gateway(MempoolLimits::default(), None);
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &changed_chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing snapshot")?;
        assert_eq!(
            (report.candidates, report.restored, report.skipped),
            (4, 2, 2)
        );
        assert!(target.read().contains_txid(&low_fee.txid()));
        assert!(target.read().contains_txid(&paying_child.txid()));
        assert!(!target.read().contains_txid(&grandparent.txid()));
        assert!(!target.read().contains_txid(&parent.txid()));
        Ok(())
    }

    #[test]
    fn restores_parent_paying_for_a_low_fee_child_before_standalone_admission() -> TestResult {
        for with_sibling in [false, true] {
            let dir = tempfile::tempdir()?;
            let (chain, mut parent, _) = family();
            parent.outputs = vec![output(49_000), output(49_000)];
            let child = spend(OutPoint::new(parent.txid(), 0), 49_000);
            let sibling = spend(OutPoint::new(parent.txid(), 1), 48_000);
            let source = gateway(MempoolLimits::default(), None);
            source.submit_local_package(
                vec![parent.clone(), child.clone()],
                LocalOrigin::Rpc,
                None,
                NOW - 20,
                &chain,
            )?;
            if with_sibling {
                admit(&source, &sibling, &chain)?;
            }
            let expected = if with_sibling { 3 } else { 2 };
            assert_eq!(source.read().len(), expected, "normal gateway control");
            save(
                dir.path(),
                &source,
                Network::Regtest,
                DEFAULT_MAX_BYTES,
                deadline(),
            )?;
            let target = gateway(MempoolLimits::default(), None);
            let report = restore(
                dir.path(),
                &target,
                Network::Regtest,
                &chain,
                NOW,
                DEFAULT_MAX_BYTES,
                deadline(),
            )?
            .ok_or("missing snapshot")?;
            assert!(!report.timed_out);
            assert_eq!(
                report.restored, expected,
                "a resident parent's fee cannot be reused later"
            );
            assert!(target.read().contains_txid(&parent.txid()));
            assert!(target.read().contains_txid(&child.txid()));
        }
        Ok(())
    }

    #[test]
    fn restore_timeout_preserves_all_priorities_through_the_next_save() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (chain, parent, _) = family();
        let source = gateway(MempoolLimits::default(), None);
        admit(&source, &parent, &chain)?;
        source.prioritise(parent.txid(), 500)?;
        source.prioritise(Txid(Hash256::from_le_bytes(&[8; 32])), i64::MIN)?;
        source.prioritise(Txid(Hash256::from_le_bytes(&[9; 32])), i64::MAX)?;
        let snapshot = Snapshot::capture(&source, deadline(), DEFAULT_MAX_BYTES, usize::MAX)?;
        let bytes = snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
        let decoded = Snapshot::decode(&bytes, Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
        let target = gateway(MempoolLimits::default(), None);
        let report = restore_candidates(&decoded, &target, &chain, NOW, Instant::now())?;
        assert!(report.timed_out);
        assert_eq!(report.restored, 0);
        let expected: std::collections::BTreeMap<_, _> = source.read().fee_deltas().collect();
        assert_eq!(
            target
                .read()
                .fee_deltas()
                .collect::<std::collections::BTreeMap<_, _>>(),
            expected
        );
        save(
            dir.path(),
            &target,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let next = gateway(MempoolLimits::default(), None);
        restore(
            dir.path(),
            &next,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        assert_eq!(
            next.read()
                .fee_deltas()
                .collect::<std::collections::BTreeMap<_, _>>(),
            expected
        );
        assert!(next.read().is_empty());
        Ok(())
    }

    struct AncestorReads {
        calls: std::sync::atomic::AtomicUsize,
        expire_at: Option<Instant>,
    }

    impl AdmissionChain for AncestorReads {
        fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Some(deadline) = self.expire_at {
                while Instant::now() < deadline {
                    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                }
            }
            Some(ChainAdmissionSnapshot::default())
        }
    }

    fn saved_ancestor_chain(count: usize) -> Vec<SavedTransaction> {
        let mut point = OutPoint::new(Txid(Hash256::from_le_bytes(&[31; 32])), 0);
        let mut rows = Vec::new();
        for _ in 0..count {
            let tx = Arc::new(spend(point, 100_000));
            point = OutPoint::new(tx.txid(), 0);
            rows.push(SavedTransaction {
                txid: tx.txid(),
                tx,
                time: NOW,
                unbroadcast: false,
                sigop_cost: 0,
            });
        }
        rows
    }

    #[test]
    fn family_collection_stops_at_the_package_count_boundary() -> TestResult {
        let limit = crate::standardness::MAX_PACKAGE_COUNT;
        for count in [limit, limit + 1, limit * 4] {
            let rows = saved_ancestor_chain(count);
            let mut graph = RestoreGraph {
                neighbors: HashMap::new(),
                confirmed: hashbrown::HashSet::new(),
            };
            for pair in rows.windows(2) {
                graph
                    .neighbors
                    .entry(pair[0].txid)
                    .or_default()
                    .push(pair[1].txid);
                graph
                    .neighbors
                    .entry(pair[1].txid)
                    .or_default()
                    .push(pair[0].txid);
            }
            let family = collect_saved_family(rows[0].txid, &graph, deadline())?;
            assert_eq!(family.len(), count.min(limit + 1));
            assert_eq!(family.len() <= limit, count == limit);
        }
        Ok(())
    }

    #[test]
    fn graph_build_stops_when_a_chain_read_exhausts_the_deadline() -> TestResult {
        let snapshot = Snapshot {
            transactions: saved_ancestor_chain(100),
            deltas: Vec::new(),
        };
        let positions = snapshot
            .transactions
            .iter()
            .map(|row| (row.txid, row))
            .collect();
        let expires = Instant::now() + Duration::from_secs(1);
        let chain = AncestorReads {
            calls: std::sync::atomic::AtomicUsize::new(0),
            expire_at: Some(expires),
        };
        let error = build_restore_graph(&snapshot, &positions, &chain, expires)
            .err()
            .ok_or("deadline must stop graph construction")?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(chain.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        Ok(())
    }
}
