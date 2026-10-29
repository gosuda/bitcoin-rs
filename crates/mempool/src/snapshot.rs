use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use bitcoin_rs_primitives::{
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

struct SavedTransaction {
    tx: Arc<Tx>,
    txid: Txid,
    time: u64,
    unbroadcast: bool,
    sigop_cost: u32,
}

struct Snapshot {
    transactions: Vec<SavedTransaction>,
    deltas: Vec<(Txid, i64)>,
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

    fn encode(&self, network: Network, max_bytes: u64, deadline: Instant) -> io::Result<Vec<u8>> {
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

    fn decode(
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
            let time = u64::from_le_bytes(take(&mut input)?);
            let unbroadcast = match take::<1>(&mut input)? {
                [0] => false,
                [1] => true,
                _ => return Err(invalid("invalid initial broadcast flag")),
            };
            let sigop_cost = u32::from_le_bytes(take(&mut input)?);
            if sigop_cost > crate::standardness::MAX_STANDARD_TX_SIGOPS_COST {
                return Err(invalid("snapshot transaction exceeds standard sigop cost"));
            }
            let len = usize::try_from(u32::from_le_bytes(take(&mut input)?))
                .map_err(|_| invalid("transaction size overflow"))?;
            if len == 0 || len > MAX_TX_BYTES {
                return Err(invalid("snapshot transaction exceeds its size bound"));
            }
            let (raw, rest) = input
                .split_at_checked(len)
                .ok_or_else(|| invalid("truncated transaction"))?;
            input = rest;
            let tx: Tx = deserialize(raw).map_err(|_| invalid("invalid snapshot transaction"))?;
            if consensus_bytes(&tx) != raw {
                return Err(invalid("noncanonical snapshot transaction"));
            }
            let txid = tx.txid();
            if !ids.insert(txid) {
                return Err(invalid("duplicate snapshot transaction"));
            }
            transactions.push(SavedTransaction {
                tx: Arc::new(tx),
                txid,
                time,
                unbroadcast,
                sigop_cost,
            });
        }
        let mut deltas = Vec::new();
        let mut ids = hashbrown::HashSet::new();
        for _ in 0..delta_count {
            check_deadline(deadline)?;
            let txid = Txid(Hash256::from_le_bytes(&take(&mut input)?));
            let delta = i64::from_le_bytes(take(&mut input)?);
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

    fn order(&self) -> io::Result<Vec<usize>> {
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

/// No saved membership, base fee, height or admission token is trusted. A malformed artifact changes
/// nothing; a budget-limited restore retains only successfully re-admitted rows.
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
                        gateway.restore_unbroadcast(saved.tx.wtxid());
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
mod tests;
