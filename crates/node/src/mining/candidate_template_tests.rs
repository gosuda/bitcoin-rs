// CONTRACT: `docs/contracts/external-api.md#API-11` owns BIP22/BIP23
// template capabilities, submitold, signet projection, and template rules.
use alloc::sync::Arc;
use bitcoin_rs_mining::CANDIDATE_CACHE_LIMIT;
use bitcoin_rs_mining::Candidate;
use bitcoin_rs_mining::CoordinatorState;
use bitcoin_rs_mining::TemplateId;
use bitcoin_rs_mining::template_from_candidate;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::TxOut;

#[test]
fn candidate_cache_evicts_the_oldest_entry_at_the_bound() {
    use alloc::sync::Arc;
    use bitcoin_rs_mining::CANDIDATE_CACHE_LIMIT;
use bitcoin_rs_mining::Candidate;
    use bitcoin_rs_primitives::{Amount, CompactTarget, LockTime, Script};

    let mut state = CoordinatorState::new();
    let coinbase = Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: Vec::new(),
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::new(),
        }],
    };
    let mut first_id = None;
    for seq in 0..=CANDIDATE_CACHE_LIMIT {
        let seq = u64::try_from(seq).unwrap_or(u64::MAX);
        let hash = Hash256::from_le_bytes(&[u8::try_from(seq).unwrap_or(0xff); 32]);
        let id = TemplateId::new(&hash, seq);
        if seq == 0 {
            first_id = Some(id.clone());
        }
        let candidate = Arc::new(Candidate {
            template_id: id.clone(),
            previous_block_hash: hash,
            height: 1,
            version: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            min_time: 1,
            current_time: 1,
            csv_active: false,
            segwit_active: false,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
            mempool_sequence: seq,
            coinbase: coinbase.clone(),
            coinbase_value: 50,
            fees: 0,
            weight: 800,
            size: 200,
            sigop_cost: 0,
            transactions: Vec::new(),
            witness_merkle_root: None,
            witness_reserved_value: None,
            witness_commitment: None,
        });
        state.cache_insert(id, candidate);
    }
    assert_eq!(state.cache.len(), CANDIDATE_CACHE_LIMIT);
    assert!(
        !state
            .cache
            .contains_key(first_id.as_ref().unwrap_or_else(|| panic!("first id"))),
        "oldest cached candidate must be evicted at the bound"
    );
}

fn sample_candidate(previous: Hash256, csv_active: bool, segwit_active: bool) -> Candidate {
    use bitcoin_rs_primitives::{Amount, CompactTarget, LockTime, Script};
    Candidate {
        template_id: TemplateId::new(&previous, 1),
        previous_block_hash: previous,
        height: 1,
        version: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        min_time: 1,
        current_time: 1,
        csv_active,
        segwit_active,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
        mempool_sequence: 1,
        coinbase: Tx {
            version: 2,
            lock_time: LockTime::from_consensus(0),
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        },
        coinbase_value: 50,
        fees: 0,
        weight: 800,
        size: 200,
        sigop_cost: 0,
        transactions: Vec::new(),
        witness_merkle_root: None,
        witness_reserved_value: None,
        witness_commitment: None,
    }
}

fn template_for(
    candidate: Candidate,
    submit_old: Option<bool>,
) -> bitcoin_rs_mining::BlockTemplate {
    template_from_candidate(
        Network::Regtest,
        Arc::new(candidate),
        submit_old,
        Vec::new(),
        0,
    )
}

#[test]
fn template_facts_follow_mutated_candidate_generation() {
    use bitcoin_rs_mining::MiningRule;

    let first_prev = Hash256::from_le_bytes(&[0x11; 32]);
    let first = template_for(sample_candidate(first_prev, false, true), Some(true));
    assert_eq!(first.candidate.previous_block_hash, first_prev);
    assert_eq!(
        first
            .rules
            .iter()
            .map(MiningRule::as_str)
            .collect::<Vec<_>>(),
        vec!["segwit", "taproot"]
    );

    let mutated_prev = Hash256::from_le_bytes(&[0x22; 32]);
    let mutated = template_for(sample_candidate(mutated_prev, true, false), Some(false));
    assert_eq!(mutated.candidate.previous_block_hash, mutated_prev);
    assert_ne!(mutated.candidate.template_id, first.candidate.template_id);
    assert_eq!(
        mutated
            .rules
            .iter()
            .map(MiningRule::as_str)
            .collect::<Vec<_>>(),
        vec!["csv", "taproot"]
    );
    assert_eq!(mutated.submit_old, Some(false));
    assert_eq!(
        first
            .capabilities
            .iter()
            .map(bitcoin_rs_mining::MiningCapability::as_str)
            .collect::<Vec<_>>(),
        vec!["proposal", "longpoll"]
    );
    assert!(first.signet.is_none());
}

#[test]
fn signet_template_carries_challenge_and_mandatory_rule() {
    use bitcoin_rs_mining::MiningRule;

    let template = template_from_candidate(
        Network::Signet,
        Arc::new(sample_candidate(
            Hash256::from_le_bytes(&[0x44; 32]),
            true,
            true,
        )),
        None,
        Vec::new(),
        0,
    );
    assert!(
        template
            .rules
            .iter()
            .map(MiningRule::as_str)
            .any(|rule| rule == "signet")
    );
    assert!(template.signet.is_some());
    assert_eq!(
        template
            .capabilities
            .iter()
            .map(bitcoin_rs_mining::MiningCapability::as_str)
            .collect::<Vec<_>>(),
        vec!["proposal", "longpoll"]
    );
}

#[test]
fn deployment_boundary_rules_follow_candidate_flags() {
    use bitcoin_rs_mining::MiningRule;

    let prev = Hash256::from_le_bytes(&[0x33; 32]);
    let cases = [
        (false, false, vec!["taproot"]),
        (true, false, vec!["csv", "taproot"]),
        (false, true, vec!["segwit", "taproot"]),
        (true, true, vec!["segwit", "csv", "taproot"]),
    ];
    for (csv_active, segwit_active, expected) in cases {
        let template = template_for(sample_candidate(prev, csv_active, segwit_active), None);
        assert_eq!(template.candidate.csv_active, csv_active);
        assert_eq!(template.candidate.segwit_active, segwit_active);
        assert_eq!(
            template
                .rules
                .iter()
                .map(MiningRule::as_str)
                .collect::<Vec<_>>(),
            expected
        );
    }
}
