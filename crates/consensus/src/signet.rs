use crate::primitives::{
    Amount, Header, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    varint,
};
use crate::script::{PreparedTransaction, VerifyFlags, push_data};

use crate::ConsensusError;
use crate::verify_block::compute_merkle_root;

const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

const BLOCK_SCRIPT_VERIFY_FLAGS: VerifyFlags = VerifyFlags::P2SH
    .union(VerifyFlags::WITNESS)
    .union(VerifyFlags::DERSIG)
    .union(VerifyFlags::NULLDUMMY);

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
use crate::script::opcode::OP_RETURN;

pub fn check_signet_block_solution(
    image: &crate::primitives::BlockImage,
    challenge: &[u8],
) -> Result<(), ConsensusError> {
    if image.block_hash().0 == Network::Signet.genesis_block_hash() {
        return Ok(());
    }
    if signet_spend(image, challenge).is_some_and(|spend| verify_solution(&spend)) {
        Ok(())
    } else {
        Err(ConsensusError::SignetSolution)
    }
}

struct SolutionSpend {
    to_sign: Tx,
    prevout: (OutPoint, TxOut),
}

fn signet_spend(image: &crate::primitives::BlockImage, challenge: &[u8]) -> Option<SolutionSpend> {
    if image.tx_count() == 0 {
        return None;
    }
    let coinbase = image.tx(0);
    let commitment_index = crate::verify_block::image_witness_commitment_index(&coinbase)?;
    let commitment = coinbase.output_script(commitment_index);
    let section = fetch_and_clear_commitment_section(commitment);
    let (script_sig, witness) = match &section {
        Some(found) => decode_solution(found.solution)?,
        None => (Script::new(), Witness::new()),
    };
    let coinbase_txid = match section {
        Some(found) => coinbase_txid_with_commitment(
            &coinbase.materialize(),
            commitment_index,
            found.rewritten,
        ),
        None => coinbase.txid(),
    };
    let header = image.header();
    let merkle_root = modified_merkle_root(image, coinbase_txid)?;

    let mut to_spend_script_sig = vec![OP_0];
    to_spend_script_sig.extend(push_data(&signet_block_data(&header, &merkle_root)));
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

fn modified_merkle_root(
    image: &crate::primitives::BlockImage,
    coinbase_txid: Txid,
) -> Option<[u8; 32]> {
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(image.tx_count());
    leaves.push(*coinbase_txid.as_bytes());
    leaves.extend(
        image
            .identities()
            .iter()
            .skip(1)
            .map(|identity| *identity.txid().as_bytes()),
    );
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
mod tests {
    use crate::primitives::{
        Amount, Block, BlockImage, Hash256, Header, LockTime, Network, OutPoint, Script, Sequence,
        Tx, TxIn, TxOut, Txid, Witness, deserialize, encode::double_sha256,
    };
    use crate::script::push_data;

    use super::{
        OP_RETURN, SIGNET_HEADER, check_signet_block_solution, coinbase_txid_with_commitment,
        decode_solution, fetch_and_clear_commitment_section, modified_merkle_root,
    };
    use crate::ConsensusError;
    use crate::verify_block::witness_commitment_index;

    use crate::test_error::TestError;

    type TestResult = Result<(), TestError>;

    fn check_solution(block: &Block, challenge: &[u8]) -> Result<(), ConsensusError> {
        check_signet_block_solution(&BlockImage::from_local(block.clone()), challenge)
    }

    fn core_signet_blocks() -> impl Iterator<Item = &'static str> {
        include_str!("../../../testdata/consensus/vectors/core-signet-blocks.txt").lines()
    }

    fn hex_bytes(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..hex.len())
            .step_by(2)
            .map(|start| u8::from_str_radix(&hex[start..start + 2], 16))
            .collect()
    }

    fn core_blocks() -> Result<Vec<Block>, TestError> {
        let mut blocks = Vec::with_capacity(10);
        for hex in core_signet_blocks() {
            blocks.push(deserialize::<Block>(&hex_bytes(hex)?)?);
        }
        Ok(blocks)
    }

    fn default_challenge() -> Result<&'static [u8], TestError> {
        let challenge = Network::Signet
            .signet_challenge()
            .ok_or("signet defines a challenge")?;
        Ok(challenge)
    }

    fn commitment_output(block: &Block) -> Result<(usize, Vec<u8>), TestError> {
        let coinbase = block.txs.first().ok_or("block has a coinbase")?;
        let index =
            witness_commitment_index(coinbase).ok_or("coinbase has a witness commitment")?;
        Ok((index, coinbase.outputs[index].script_pubkey.to_vec()))
    }

    fn coinbase_with_script(script: Vec<u8>) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Script::new(),
                sequence: Sequence::ZERO,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::from_bytes(script),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn spend_tx(seed: u8) -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::ZERO,
        }
    }

    fn witness_section() -> Vec<u8> {
        let mut section = vec![0xaa, 0x21, 0xa9, 0xed];
        section.extend([0xff; 32]);
        section
    }

    fn commitment_script(sections: &[Vec<u8>]) -> Vec<u8> {
        let mut script = vec![OP_RETURN];
        script.extend(push_data(&witness_section()));
        for section in sections {
            script.extend(push_data(section));
        }
        script
    }

    fn block_with_coinbase_script(script: Vec<u8>) -> Block {
        Block {
            header: Header::default(),
            txs: vec![coinbase_with_script(script), spend_tx(1)],
        }
    }

    fn header_then(tail: &[u8]) -> Vec<u8> {
        let mut section = SIGNET_HEADER.to_vec();
        section.extend_from_slice(tail);
        section
    }

    fn rewrite(script: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        fetch_and_clear_commitment_section(script)
            .map(|section| (section.rewritten, section.solution.to_vec()))
    }

    fn pair_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut buffer = [0_u8; 64];
        buffer[..32].copy_from_slice(left);
        buffer[32..].copy_from_slice(right);
        double_sha256(&buffer).to_le_bytes()
    }

    #[test]
    fn core_signet_blocks_satisfy_the_default_challenge() -> TestResult {
        let challenge = default_challenge()?;
        let mut parent = Network::Signet.genesis_block_hash();
        for (index, block) in core_blocks()?.iter().enumerate() {
            assert_eq!(
                block.header.prev_blockhash.0, parent,
                "block {index} extends the previous fixture"
            );
            parent = block.block_hash().0;
            let (_, script) = commitment_output(block)?;
            assert!(
                fetch_and_clear_commitment_section(&script).is_some(),
                "block {index} carries a solution, so the signature path is exercised"
            );
            assert_eq!(check_solution(block, challenge), Ok(()), "block {index}");
        }
        Ok(())
    }

    #[test]
    fn the_genesis_block_needs_no_solution() -> TestResult {
        let challenge = default_challenge()?;
        let genesis = Network::Signet.genesis_block();
        assert_eq!(check_solution(&genesis, challenge), Ok(()));

        let mut other = genesis;
        other.header.nonce ^= 1;
        assert_eq!(
            check_solution(&other, challenge),
            Err(ConsensusError::SignetSolution)
        );
        Ok(())
    }

    #[test]
    fn any_change_to_a_signed_field_is_rejected() -> TestResult {
        let challenge = default_challenge()?;
        let blocks = core_blocks()?;
        let valid = blocks.first().ok_or("fixture has blocks")?;
        let (index, script) = commitment_output(valid)?;
        let solution_at = script
            .windows(SIGNET_HEADER.len())
            .position(|window| window == SIGNET_HEADER.as_slice())
            .ok_or("fixture carries the solution header")?;

        let mut flipped_solution = valid.clone();
        let mut solution_script = script;
        solution_script[solution_at + SIGNET_HEADER.len() + 16] ^= 0x01;
        flipped_solution.txs[0].outputs[index].script_pubkey = Script::from_bytes(solution_script);

        let mut retimed = valid.clone();
        retimed.header.time += 1;
        let mut reversioned = valid.clone();
        reversioned.header.version ^= 1;
        let mut repaid = valid.clone();
        repaid.txs[0].outputs[0].value = Amount::from_sat(1);

        for (changed, block) in [
            ("solution byte", flipped_solution),
            ("header time", retimed),
            ("header version", reversioned),
            ("coinbase output", repaid),
        ] {
            assert_eq!(
                check_solution(&block, challenge),
                Err(ConsensusError::SignetSolution),
                "{changed}"
            );
        }
        assert_eq!(check_solution(valid, challenge), Ok(()));
        Ok(())
    }

    #[test]
    fn solution_parsing_follows_core() {
        let op_true = [0x51_u8];
        let with_sections =
            |sections: &[Vec<u8>]| block_with_coinbase_script(commitment_script(sections));
        let cases = [
            ("empty block", Block::default(), false),
            (
                "no witness commitment",
                block_with_coinbase_script(Vec::new()),
                false,
            ),
            ("commitment without a header", with_sections(&[]), true),
            (
                "header without data",
                with_sections(&[header_then(&[])]),
                true,
            ),
            (
                "premature end of data",
                with_sections(&[header_then(&[0x01, 0x51])]),
                false,
            ),
            (
                "scriptSig and an empty witness",
                with_sections(&[header_then(&[0x01, 0x51, 0x00])]),
                true,
            ),
            (
                "extraneous data",
                with_sections(&[header_then(&[0x01, 0x51, 0x00, 0x00])]),
                false,
            ),
        ];
        for (name, block, valid) in cases {
            let expected = if valid {
                Ok(())
            } else {
                Err(ConsensusError::SignetSolution)
            };
            assert_eq!(check_solution(&block, &op_true), expected, "{name}");
        }
    }

    #[test]
    fn the_challenge_decides_a_commitment_without_a_solution() -> TestResult {
        let block = block_with_coinbase_script(commitment_script(&[]));
        assert_eq!(check_solution(&block, &[0x51]), Ok(()));
        assert_eq!(
            check_solution(&block, &[0x00]),
            Err(ConsensusError::SignetSolution)
        );
        assert_eq!(
            check_solution(&block, default_challenge()?),
            Err(ConsensusError::SignetSolution)
        );
        Ok(())
    }

    #[test]
    fn only_signet_defines_a_challenge() {
        for network in [
            Network::Mainnet,
            Network::Testnet3,
            Network::Testnet4,
            Network::Regtest,
        ] {
            assert_eq!(network.signet_challenge(), None, "{network:?}");
        }
        let Some(challenge) = Network::Signet.signet_challenge() else {
            panic!("signet defines a challenge");
        };
        assert_eq!(challenge.len(), 71);
        assert_eq!(challenge.first(), Some(&0x51));
        assert_eq!(challenge.last(), Some(&0xae));
    }

    #[test]
    fn the_rewrite_removes_exactly_the_solution() -> TestResult {
        let blocks = core_blocks()?;
        for (number, block) in blocks.iter().enumerate() {
            let (index, script) = commitment_output(block)?;
            let Some(section) = fetch_and_clear_commitment_section(&script) else {
                panic!("block {number} carries a solution");
            };
            assert!(
                section.rewritten.ends_with(&header_then(&[])[..]),
                "block {number} keeps the header and drops what follows"
            );
            assert!(
                section.rewritten.len() < script.len(),
                "block {number} shrinks"
            );
            let coinbase = &block.txs[0];
            let rewritten = coinbase_txid_with_commitment(coinbase, index, section.rewritten);
            assert_ne!(rewritten, coinbase.txid(), "block {number}");
        }
        Ok(())
    }

    #[test]
    fn empty_pushes_keep_only_their_opcode_byte() {
        let script = [
            0x6a, 0x00, 0x4c, 0x00, 0x4d, 0x00, 0x00, 0x06, 0xec, 0xc7, 0xda, 0xa2, 0x01, 0x51,
            0x02, 0xaa, 0xbb,
        ];
        assert_eq!(
            rewrite(&script),
            Some((
                vec![
                    0x6a, 0x00, 0x4c, 0x4d, 0x04, 0xec, 0xc7, 0xda, 0xa2, 0x02, 0xaa, 0xbb
                ],
                vec![0x01, 0x51],
            ))
        );
    }

    #[test]
    fn pushes_are_reencoded_canonically() {
        let mut script = vec![
            0x4c, 0x03, 0xaa, 0xbb, 0xcc, 0x4c, 0x06, 0xec, 0xc7, 0xda, 0xa2,
        ];
        script.extend([0x01, 0x51]);
        assert_eq!(
            rewrite(&script),
            Some((
                vec![0x03, 0xaa, 0xbb, 0xcc, 0x04, 0xec, 0xc7, 0xda, 0xa2],
                vec![0x01, 0x51],
            ))
        );

        let mut long_push = vec![0x4d, 0x2c, 0x01];
        long_push.extend(header_then(&[0x07; 296]));
        assert_eq!(
            rewrite(&long_push),
            Some((vec![0x04, 0xec, 0xc7, 0xda, 0xa2], vec![0x07; 296]))
        );
    }

    #[test]
    fn only_the_first_header_push_is_the_solution() {
        let script = [
            0x06, 0xec, 0xc7, 0xda, 0xa2, 0x01, 0x51, 0x06, 0xec, 0xc7, 0xda, 0xa2, 0x02, 0x52,
        ];
        assert_eq!(
            rewrite(&script),
            Some((
                vec![
                    0x04, 0xec, 0xc7, 0xda, 0xa2, 0x06, 0xec, 0xc7, 0xda, 0xa2, 0x02, 0x52,
                ],
                vec![0x01, 0x51],
            ))
        );
    }

    #[test]
    fn the_walk_stops_at_the_first_truncated_instruction() {
        let script = [0x6a, 0x06, 0xec, 0xc7, 0xda, 0xa2, 0x01, 0x51, 0x4c];
        assert_eq!(
            rewrite(&script),
            Some((vec![0x6a, 0x04, 0xec, 0xc7, 0xda, 0xa2], vec![0x01, 0x51]))
        );

        let overlong_push = [0x6a, 0x4c, 0x09, 0xec, 0xc7, 0xda, 0xa2, 0x01, 0x51];
        assert_eq!(rewrite(&overlong_push), None);
    }

    #[test]
    fn a_header_needs_data_and_a_push_start() {
        assert_eq!(rewrite(&[0x04, 0xec, 0xc7, 0xda, 0xa2]), None);
        assert_eq!(rewrite(&[0x05, 0x00, 0xec, 0xc7, 0xda, 0xa2]), None);
        assert_eq!(rewrite(&[0x6a]), None);
        assert_eq!(rewrite(&[]), None);
    }

    #[test]
    fn solution_decoding_is_strict_and_bounded_by_the_available_bytes() {
        assert_eq!(
            decode_solution(&[0x01, 0x51, 0x02, 0x01, 0xaa, 0x00]),
            Some((
                Script::from_bytes(vec![0x51]),
                Witness::from_stack(vec![vec![0xaa], Vec::new()]),
            ))
        );
        assert_eq!(
            decode_solution(&[0x00, 0x00]),
            Some((Script::new(), Witness::new()))
        );

        for (name, solution) in [
            ("empty", Vec::new()),
            ("script longer than the data", vec![0x02, 0x51]),
            (
                "non-canonical script length",
                vec![0xfd, 0x01, 0x00, 0x51, 0x00],
            ),
            ("missing witness count", vec![0x01, 0x51]),
            ("witness item truncated", vec![0x01, 0x51, 0x01, 0x02, 0xaa]),
            ("trailing byte", vec![0x01, 0x51, 0x00, 0x00]),
            (
                "hostile witness count",
                vec![0x00, 0xfe, 0xff, 0xff, 0xff, 0x7f],
            ),
            (
                "hostile item length",
                vec![0x00, 0x01, 0xfe, 0xff, 0xff, 0xff, 0x7f],
            ),
            (
                "count above the remaining bytes",
                vec![0x00, 0x03, 0x00, 0x00],
            ),
        ] {
            assert_eq!(decode_solution(&solution), None, "{name}");
        }
    }

    #[test]
    fn the_modified_root_replaces_only_the_coinbase_leaf() {
        let coinbase_txid = Txid(Hash256::from_le_bytes(&[0x11; 32]));
        let block = Block {
            header: Header::default(),
            txs: vec![coinbase_with_script(Vec::new()), spend_tx(1), spend_tx(2)],
        };
        let left = pair_hash(coinbase_txid.as_bytes(), block.txs[1].txid().as_bytes());
        let second = *block.txs[2].txid().as_bytes();
        let right = pair_hash(&second, &second);
        assert_eq!(
            modified_merkle_root(&BlockImage::from_local(block), coinbase_txid),
            Some(pair_hash(&left, &right))
        );
    }
}
