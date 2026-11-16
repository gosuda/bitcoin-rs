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

    const CORE_SIGNET_BLOCKS: [&str; 10] = [
        "00000020f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000f575c83235984e7dc4afc1f30944c170462e84437ab6f2d52e16878a79e4678bd1914d5fae77031eccf4070001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025151feffffff0200f2052a010000001600149243f727dd5343293eb83174324019ec16c2630f0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402205e423a8754336ca99dbe16509b877ef1bf98d008836c725005b3c787c41ebe46022047246e4467ad7cc7f1ad98662afcaf14c115e0095a227c7b05c5182591c23e7e01000120000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000020533b53ded9bff4adc94101d32400a144c54edc5ed492a3b26c63b2d686000000b38fef50592017cfafbcab88eb3d9cf50b2c801711cad8299495d26df5e54812e7914d5fae77031ecfdd0b0001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025251feffffff0200f2052a01000000160014fd09839740f0e0b4fc6d5e2527e4022aa9b89dfa0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022031d64a1692cdad1fc0ced69838169fe19ae01be524d831b95fcf5ea4e6541c3c02204f9dea0801df8b4d0cd0857c62ab35c6c25cc47c930630dc7fe723531daa3e9b01000120000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000202960f3752f0bfa8858a3e333294aedc7808025e868c9dc03e71d88bb320000007765fcd3d5b4966beb338bba2675dc2cf2ad28d4ad1d83bdb6f286e7e27ac1f807924d5fae77031e81d60b0001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025351feffffff0200f2052a010000001600141e5fb426042692ae0e87c070e78c39307a5661c20000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402205de93694763a42954865bcf1540cb82958bc62d0ec4eee02070fb7937cd037f4022067f333753bce47b10bc25eb6e1f311482e994c862a7e0b2d41ab1c8679fd1b1101000120000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000020b06443a13ae1d3d50faef5ecad38c6818194dc46abca3e972e2aacdae800000069a5829097e80fee00ac49a56ea9f82d741a6af84d32b3bc455cf31871e2a8ac27924d5fae77031e9c91050001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025451feffffff0200f2052a0100000016001430db2f8225dcf7751361ab38735de08190318cb70000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402200936f5f9872f6df5dd242026ad52241a68423f7f682e79169a8d85a374eab9b802202cd2979c48b321b3453e65e8f92460db3fca93cbea8539b450c959f4fbe630c601000120000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000207ed403758a4f228a1939418a155e2ebd4ae6b26e5ffd0ae433123f7694010000542e80b609c5bc58af5bdf492e26d4f60cd43a3966c2e063c50444c29b3757a636924d5fae77031ee8601d0001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025551feffffff0200f2052a01000000160014edc207e014df34fa3885dff97d1129d356e1186a0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022021a3656609f85a66a2c5672ed9322c2158d57251040d2716ed202a1fe14f0c12022057d68bc6611f7a9424a7e00bbf3e27e6ae6b096f60bac624a094bc97a59aa1ff01000120000000000000000000000000000000000000000000000000000000000000000000000000",
        "000000205bea0a88d1422c3df08d766ad72df95084d0700e6f873b75dd4e986c7703000002b57516d33ed60c2bdd9f93d6d5614083324c837e68e5ba6e04287a7285633585924d5fae77031ed171960001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025651feffffff0200f2052a010000001600143ae612599cf96f2442ce572633e0251116eaa52f0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022059a7c54de76bfdbb1dd44c78ea2dbd2bb4e97f4abad38965f41e76433e56423c022054bf17f04fe17415c0141f60eebd2b839200f574d8ad8d55a0917b92b0eb913401000120000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000020daf3b60d374b19476461f97540498dcfa2eb7016238ec6b1d022f82fb60100007a7ae65b53cb988c2ec92d2384996713821d5645ffe61c9acea60da75cd5edfa1a944d5fae77031e9dbb050001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025751feffffff0200f2052a01000000160014ef2dceae02e35f8137de76768ae3345d99ca68860000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402202b3f946d6447f9bf17d00f3696cede7ee70b785495e5498274ee682a493befd5022045fc0bcf9332243168b5d35507175f9f374a8eba2336873885d12aada67ea5f601000120000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000020457cc5f3c2e1a5655bc20e20e48d33e1b7ea68786c614032b5c518f0b6000000541f36942d82c6e7248275ff15c8933487fbe1819c67a9ecc0f4b70bb7e6cf672a944d5fae77031e8f39860001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025851feffffff0200f2052a0100000016001472a27906947c06d034b38ba2fa13c6391a4832790000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402202d62805ce60cbd60591f97f949b5ea5bd7e2307bcde343e6ea8394da92758e72022053a25370b0aa20da100189b7899a8f8675a0fdc60e38ece6b8a4f98edd94569e01000120000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000020a2eb61eb4f3831baa3a3363e1b42db4462663f756f07423e81ed30322102000077224de7dea0f8d0ec22b1d2e2e255f0a987b96fe7200e1a2e6373f48a2f5b7894954d5fae77031e36867e0001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025951feffffff0200f2052a01000000160014aa0ad9f26801258382e0734dceec03a4a75f60240000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402206fa0d59990eed369bd7375767c9a6c9369fae209152b8674e520da270605528c0220749eed3b12dbe3f583f505d21803e4aef59c8e24c5831951eafa4f15a8f92c4e01000120000000000000000000000000000000000000000000000000000000000000000000000000",
        "00000020a868e8514be5e46dabd6a122132f423f36a43b716a40c394e2a8d063e1010000f4c6c717e99d800c699c25a2006a75a0c5c09f432a936f385e6fce139cdbd1a5e9964d5fae77031e7d026e0001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025a51feffffff0200f2052a01000000160014aaa671c82b138e3b8f510cd801e5f2bd0aa305940000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa24900473044022042309f4c3c7a1a2ac8c24f890f962df1c0086cec10be0868087cfc427520cb2702201dafee8911c269b7e786e242045bb57cef3f5b0f177010c6159abae42f646cc501000120000000000000000000000000000000000000000000000000000000000000000000000000",
    ];

    fn hex_bytes(hex: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..hex.len())
            .step_by(2)
            .map(|start| u8::from_str_radix(&hex[start..start + 2], 16))
            .collect()
    }

    fn core_blocks() -> Result<Vec<Block>, TestError> {
        let mut blocks = Vec::with_capacity(CORE_SIGNET_BLOCKS.len());
        for hex in CORE_SIGNET_BLOCKS {
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
