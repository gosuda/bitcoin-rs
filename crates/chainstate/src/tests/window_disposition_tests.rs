use bitcoin_rs_chain::ChainError;
use bitcoin_rs_consensus::{ConsensusError, ScriptEngine, ValidationEngine};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::StorageError;

use crate::{ApplyError, WindowApplyDisposition, classify_apply_error};

#[test]
fn apply_errors_classify_into_their_documented_dispositions() {
    use ApplyError::{Chain, Consensus, DurableHeadCommit, ProofOfWork};
    use ConsensusError::{
        Kernel, MerkleRoot, MissingCoinbase, PrevoutCount, PrevoutMatrixSize, PrevoutMismatch,
        Script, SignetSolution, SixtyFourByteMutation, UnsupportedEngine,
    };
    use WindowApplyDisposition::{BodyMutated, Fatal, Operational, Permanent};

    let script = |engine| Script {
        input_index: 0,
        reason: "script failed".to_owned(),
        engine,
    };
    let cases = [
        (
            Consensus(UnsupportedEngine {
                engine: ValidationEngine::Kernel,
            }),
            Operational,
        ),
        (
            Consensus(PrevoutCount {
                input_count: 2,
                prevout_count: 1,
            }),
            Operational,
        ),
        (
            Consensus(PrevoutMatrixSize {
                expected: 2,
                actual: 1,
            }),
            Operational,
        ),
        (Consensus(PrevoutMismatch { input_index: 1 }), Operational),
        (Consensus(Kernel("parse failed".to_owned())), Operational),
        (Consensus(script(ScriptEngine::Kernel)), Operational),
        (Consensus(script(ScriptEngine::Native)), Permanent),
        (Consensus(SignetSolution), Permanent),
        (
            ProofOfWork {
                hash: Hash256::default(),
            },
            Permanent,
        ),
        (
            Chain(ChainError::NbitsMismatch {
                height: 2016,
                expected: 1,
                actual: 2,
            }),
            Permanent,
        ),
        (Consensus(MerkleRoot), BodyMutated),
        (Consensus(SixtyFourByteMutation), BodyMutated),
        (Consensus(MissingCoinbase), Permanent),
        (
            DurableHeadCommit(StorageError::backend("head batch lost")),
            Fatal,
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(classify_apply_error(&error), expected, "{error}");
    }
}
