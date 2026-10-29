//! BIP325 signet block solution check: a port of Core `src/signet.cpp`.

use bitcoin_rs_primitives::{
    Amount, Block, Header, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
    Witness, varint,
};
use bitcoin_rs_script::{PreparedTransaction, VerifyFlags, push_data};

use crate::ConsensusError;
use crate::verify_block::{compute_merkle_root, witness_commitment_index};

const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

const BLOCK_SCRIPT_VERIFY_FLAGS: VerifyFlags = VerifyFlags::P2SH
    .union(VerifyFlags::WITNESS)
    .union(VerifyFlags::DERSIG)
    .union(VerifyFlags::NULLDUMMY);

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_RETURN: u8 = 0x6a;

pub fn check_signet_block_solution(block: &Block, challenge: &[u8]) -> Result<(), ConsensusError> {
    if block.block_hash().0 == Network::Signet.genesis_block_hash() {
        return Ok(());
    }
    if signet_spend(block, challenge).is_some_and(|spend| verify_solution(&spend)) {
        Ok(())
    } else {
        Err(ConsensusError::SignetSolution)
    }
}

struct SolutionSpend {
    to_sign: Tx,
    prevout: (OutPoint, TxOut),
}

fn signet_spend(block: &Block, challenge: &[u8]) -> Option<SolutionSpend> {
    let coinbase = block.txs.first()?;
    let commitment_index = witness_commitment_index(coinbase)?;
    let commitment = &coinbase.outputs.get(commitment_index)?.script_pubkey;
    let section = fetch_and_clear_commitment_section(commitment);
    let (script_sig, witness) = match &section {
        Some(found) => decode_solution(found.solution)?,
        None => (Script::new(), Witness::new()),
    };
    let coinbase_txid = match section {
        Some(found) => coinbase_txid_with_commitment(coinbase, commitment_index, found.rewritten),
        None => coinbase.txid(),
    };
    let merkle_root = modified_merkle_root(block, coinbase_txid)?;

    let mut to_spend_script_sig = vec![OP_0];
    to_spend_script_sig.extend(push_data(&signet_block_data(&block.header, &merkle_root)));
    let challenge_output = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: Script::from_bytes(challenge.to_vec()),
    };
    let to_spend = Tx {
        version: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(to_spend_script_sig),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        outputs: vec![challenge_output.clone()],
        lock_time: LockTime::ZERO,
    };
    let prevout = (OutPoint::new(to_spend.txid(), 0), challenge_output);
    let to_sign = Tx {
        version: 0,
        inputs: vec![TxIn {
            previous_output: prevout.0,
            script_sig,
            sequence: Sequence::ZERO,
            witness,
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: Script::from_bytes(vec![OP_RETURN]),
        }],
        lock_time: LockTime::ZERO,
    };
    Some(SolutionSpend { to_sign, prevout })
}

fn verify_solution(spend: &SolutionSpend) -> bool {
    let Ok(prepared) =
        PreparedTransaction::new(&spend.to_sign, std::slice::from_ref(&spend.prevout))
    else {
        return false;
    };
    matches!(
        prepared.verify_input(0, BLOCK_SCRIPT_VERIFY_FLAGS, None),
        Ok(true)
    )
}

fn signet_block_data(header: &Header, modified_root: &[u8; 32]) -> Vec<u8> {
    let mut data = Vec::with_capacity(72);
    data.extend_from_slice(&header.version.to_le_bytes());
    data.extend_from_slice(header.prev_blockhash.as_bytes());
    data.extend_from_slice(modified_root);
    data.extend_from_slice(&header.time.to_le_bytes());
    data
}

fn modified_merkle_root(block: &Block, coinbase_txid: Txid) -> Option<[u8; 32]> {
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(block.txs.len());
    leaves.push(*coinbase_txid.as_bytes());
    leaves.extend(block.txs.iter().skip(1).map(|tx| *tx.txid().as_bytes()));
    compute_merkle_root(&mut leaves)
}

fn coinbase_txid_with_commitment(coinbase: &Tx, index: usize, commitment_script: Vec<u8>) -> Txid {
    let mut modified = coinbase.clone();
    modified.outputs[index].script_pubkey = Script::from_bytes(commitment_script);
    modified.txid()
}

struct CommitmentSection<'a> {
    rewritten: Vec<u8>,
    solution: &'a [u8],
}

fn fetch_and_clear_commitment_section(script: &[u8]) -> Option<CommitmentSection<'_>> {
    let mut rewritten = Vec::with_capacity(script.len());
    let mut solution = None;
    let mut rest = script;
    while let Some((op, tail)) = next_script_op(rest) {
        rest = tail;
        if op.push.is_empty() {
            rewritten.push(op.opcode);
        } else if solution.is_none()
            && let Some(after_header) = solution_after_header(op.push)
        {
            solution = Some(after_header);
            rewritten.extend(push_data(&SIGNET_HEADER));
        } else {
            rewritten.extend(push_data(op.push));
        }
    }
    solution.map(|solution| CommitmentSection {
        rewritten,
        solution,
    })
}

fn solution_after_header(push: &[u8]) -> Option<&[u8]> {
    push.strip_prefix(&SIGNET_HEADER[..])
        .filter(|after_header| !after_header.is_empty())
}

struct ScriptOp<'a> {
    opcode: u8,
    push: &'a [u8],
}

fn next_script_op(script: &[u8]) -> Option<(ScriptOp<'_>, &[u8])> {
    let (&opcode, rest) = script.split_first()?;
    let (length, rest) = match opcode {
        OP_PUSHDATA1 => read_le_length(rest, 1)?,
        OP_PUSHDATA2 => read_le_length(rest, 2)?,
        OP_PUSHDATA4 => read_le_length(rest, 4)?,
        0x00..=0x4b => (usize::from(opcode), rest),
        _ => return Some((ScriptOp { opcode, push: &[] }, rest)),
    };
    let (push, tail) = rest.split_at_checked(length)?;
    Some((ScriptOp { opcode, push }, tail))
}

fn read_le_length(bytes: &[u8], width: usize) -> Option<(usize, &[u8])> {
    let (raw, rest) = bytes.split_at_checked(width)?;
    let length = raw
        .iter()
        .rev()
        .fold(0_u64, |length, byte| (length << 8) | u64::from(*byte));
    Some((usize::try_from(length).ok()?, rest))
}

fn decode_solution(solution: &[u8]) -> Option<(Script, Witness)> {
    let (script_sig, rest) = read_prefixed(solution)?;
    let (count, mut rest) = read_compact_size(rest)?;
    if count > rest.len() {
        return None;
    }
    let mut stack = Vec::with_capacity(count);
    for _ in 0..count {
        let (item, tail) = read_prefixed(rest)?;
        stack.push(item.to_vec());
        rest = tail;
    }
    rest.is_empty().then(|| {
        (
            Script::from_bytes(script_sig.to_vec()),
            Witness::from_stack(stack),
        )
    })
}

fn read_compact_size(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let (value, used) = varint::decode(bytes).ok()?;
    Some((usize::try_from(value).ok()?, bytes.get(used..)?))
}

fn read_prefixed(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = read_compact_size(bytes)?;
    rest.split_at_checked(length)
}

#[cfg(test)]
mod tests;
