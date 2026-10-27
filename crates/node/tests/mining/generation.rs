use anyhow::Result;
use bitcoin_rs_mining::{
    BlockValidationResult, GenerateRequest, GenerateSelection, GenerateTx, MiningControl,
    MiningControlError,
};
use bitcoin_rs_node::{MiningCoordinator, Network};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};

use super::support::{open_at_genesis, regtest_mining, solved_template_block};

/// API-05: a 64-character generateblock entry must already be in the mempool.
#[test]
fn generateblock_rejects_unknown_mempool_txid() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    let missing = Txid::from(Hash256::from_le_bytes(&[0xcd; 32]));
    let error = mining
        .generate(GenerateRequest {
            payout: vec![0x51],
            count: 1,
            max_tries: 16,
            selection: GenerateSelection::Ordered(vec![GenerateTx::Mempool(missing)]),
            submit: true,
        })
        .err()
        .unwrap_or_else(|| panic!("missing mempool txid must fail"));
    assert!(matches!(error, MiningControlError::InvalidRequest(_)));
    Ok(())
}

/// API-05: decoded generateblock hex is included without mempool lookup.
/// Invalid spends fail Core `TestBlockValidity` before the nonce search.
#[test]
// CONTRACT: docs/contracts/external-api.md#API-27
fn generateblock_raw_tx_does_not_require_mempool_admission() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let raw = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0x11; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    let error = mining
        .generate(GenerateRequest {
            payout: vec![0x51],
            count: 1,
            max_tries: 16,
            selection: GenerateSelection::Ordered(vec![GenerateTx::Raw(raw)]),
            submit: false,
        })
        .err()
        .unwrap_or_else(|| panic!("invalid raw spend must fail validation, not mempool lookup"));
    match error {
        MiningControlError::Rejected(reason) => {
            assert!(
                reason.starts_with("TestBlockValidity failed:"),
                "Core wraps TestBlockValidity: {reason}"
            );
            assert!(
                reason.contains("bad-txns-inputs-missingorspent"),
                "missing prevout is Core's GetRejectReason: {reason}"
            );
        }
        other => panic!("raw generateblock txs skip mempool membership: {other:?}"),
    }
    Ok(())
}

/// API-05: submit=false dry-validates through the apply gates and does not persist.
#[test]
fn generate_without_submit_does_not_advance_the_tip() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let before = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing before generate"));
    let generated = mining.generate(GenerateRequest {
        payout: vec![0x51],
        count: 1,
        max_tries: GenerateRequest::DEFAULT_MAX_TRIES,
        selection: GenerateSelection::Ordered(Vec::new()),
        submit: false,
    })?;
    assert_eq!(generated.len(), 1);
    assert_ne!(generated[0].hex, "");
    let after = state
        .chainstate()
        .applied_tip_snapshot()
        .unwrap_or_else(|| panic!("applied tip missing after generate"));
    assert_eq!(after.height, before.height);
    assert_eq!(after.hash, before.hash);
    Ok(())
}

/// Raw generateblock inputs must include the confirmed P2SH redeem costs before
/// solving, and a refusal retains Core's API-30 rejection class and reason.
#[test]
fn generateblock_raw_p2sh_costs_use_confirmed_prevouts() -> Result<()> {
    let state = open_at_genesis(Network::Regtest)?;
    // The unreachable branch is valid to spend but counts 199 * 20 sigops.
    // IF + 199 CHECKMULTISIG + ENDIF also fits the 201-op execution limit.
    let redeem = [vec![0x00, 0x63], vec![0xae; 199], vec![0x68, 0x51]].concat();
    let payout = bitcoin::ScriptBuf::from_bytes(redeem.clone())
        .to_p2sh()
        .into_bytes();
    let mining = MiningCoordinator::new(
        state.mempool_reader(),
        state.chainstate(),
        state.stable_read(),
        state.chain_followers(),
        payout,
    );
    let mut inputs = Vec::new();
    for _ in 0..6 {
        let block = solved_template_block(&mining)?;
        inputs.push(TxIn {
            previous_output: OutPoint::new(block.txs[0].txid(), 0),
            script_sig: bitcoin_rs_script::push_data(&redeem).into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        assert_eq!(mining.submit_block(block)?, BlockValidationResult::Accepted);
    }
    mining.generate(GenerateRequest {
        payout: vec![0x51],
        count: 100,
        max_tries: GenerateRequest::DEFAULT_MAX_TRIES,
        selection: GenerateSelection::Ordered(Vec::new()),
        submit: true,
    })?;
    let before = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| anyhow::anyhow!("missing tip"))?;
    let mut raw = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: inputs[..5].to_vec(),
        // 5 * (199 * 20 * 4) + 100 * 4 = exactly 80,000 cost units.
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0xac; 100].into(),
        }],
    };
    let request = |tx, max_tries| GenerateRequest {
        payout: vec![0x51],
        count: 1,
        max_tries,
        selection: GenerateSelection::Ordered(vec![GenerateTx::Raw(tx)]),
        submit: false,
    };
    assert_eq!(
        mining
            .generate(request(raw.clone(), GenerateRequest::DEFAULT_MAX_TRIES))?
            .len(),
        1
    );
    raw.inputs.push(inputs[5].clone());
    let error = mining
        .generate(request(raw, 0))
        .err()
        .ok_or_else(|| anyhow::anyhow!("over-budget raw transaction must fail before solve"))?;
    assert!(
        matches!(error, MiningControlError::Rejected(ref reason) if reason == "TestBlockValidity failed: bad-blk-sigops"),
        "unexpected refusal: {error:?}"
    );
    let after = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| anyhow::anyhow!("missing tip"))?;
    assert_eq!(after.hash, before.hash);
    assert!(state.mempool().read().is_empty());
    Ok(())
}
