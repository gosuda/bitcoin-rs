// CONTRACT: `docs/contracts/external-api.md#API-11` owns BIP22/BIP23
// template capabilities, submitold, signet projection, and template rules.
use super::CANDIDATE_CACHE_LIMIT;
use super::CoordinatorState;
use super::template_from_candidate;
use crate::control::BlockTemplate;
use crate::control::MiningCapability;
use crate::control::MiningRule;
use crate::template::Candidate;
use crate::template::TemplateId;
use bitcoin_rs_primitives::Amount;
use bitcoin_rs_primitives::CompactTarget;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::LockTime;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::Script;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::TxOut;
use std::sync::Arc;

fn sample_candidate(
    previous: Hash256,
    sequence: u64,
    csv_active: bool,
    segwit_active: bool,
) -> Candidate {
    Candidate {
        template_id: TemplateId::new(&previous, sequence),
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
        mempool_sequence: sequence,
        coinbase: Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            }],
        },
        coinbase_value: 50,
        weight: 800,
        transactions: Vec::new(),
        witness_commitment: None,
    }
}

fn rule_names(template: &BlockTemplate) -> Vec<&str> {
    template.rules.iter().map(MiningRule::as_str).collect()
}

#[test]
fn candidate_cache_evicts_the_oldest_entry_at_the_bound() {
    let mut state = CoordinatorState::default();
    let mut first_id = None;
    for seq in 0..=CANDIDATE_CACHE_LIMIT {
        let seq = u64::try_from(seq).unwrap_or(u64::MAX);
        let hash = Hash256::from_le_bytes(&[u8::try_from(seq).unwrap_or(0xff); 32]);
        let candidate = sample_candidate(hash, seq, false, false);
        let id = candidate.template_id.clone();
        if seq == 0 {
            first_id = Some(id.clone());
        }
        state.cache_insert(id, Arc::new(candidate));
    }
    assert_eq!(state.cache.len(), CANDIDATE_CACHE_LIMIT);
    assert!(
        !state
            .cache
            .contains_key(first_id.as_ref().unwrap_or_else(|| panic!("first id"))),
        "oldest cached candidate must be evicted at the bound"
    );
}

#[test]
fn template_projects_candidate_generation_and_deployment_flags() {
    let cases = [
        (
            Network::Regtest,
            0x11,
            Some(true),
            false,
            true,
            vec!["segwit", "taproot"],
        ),
        (
            Network::Regtest,
            0x22,
            Some(false),
            true,
            false,
            vec!["csv", "taproot"],
        ),
        (Network::Regtest, 0x33, None, false, false, vec!["taproot"]),
        (
            Network::Regtest,
            0x33,
            None,
            true,
            false,
            vec!["csv", "taproot"],
        ),
        (
            Network::Regtest,
            0x33,
            None,
            false,
            true,
            vec!["segwit", "taproot"],
        ),
        (
            Network::Regtest,
            0x33,
            None,
            true,
            true,
            vec!["segwit", "csv", "taproot"],
        ),
        (
            Network::Signet,
            0x44,
            None,
            true,
            true,
            vec!["segwit", "csv", "taproot", "signet"],
        ),
    ];
    let mut generations: Vec<(Hash256, TemplateId)> = Vec::new();
    for (network, label, submit_old, csv_active, segwit_active, expected) in cases {
        let prev = Hash256::from_le_bytes(&[label; 32]);
        let candidate = sample_candidate(prev, 1, csv_active, segwit_active);
        let expected_id = candidate.template_id.clone();
        let template =
            template_from_candidate(network, Arc::new(candidate), submit_old, Vec::new());
        assert_eq!(template.candidate.previous_block_hash, prev);
        assert_eq!(template.candidate.csv_active, csv_active);
        assert_eq!(template.candidate.segwit_active, segwit_active);
        assert_eq!(template.submit_old, submit_old);
        assert_eq!(rule_names(&template), expected);
        assert_eq!(template.candidate.template_id, expected_id);
        for (other_prev, other_id) in &generations {
            assert_eq!(
                prev == *other_prev,
                template.candidate.template_id == *other_id
            );
        }
        generations.push((prev, template.candidate.template_id.clone()));
        assert_eq!(
            template
                .capabilities
                .iter()
                .map(MiningCapability::as_str)
                .collect::<Vec<_>>(),
            vec!["proposal", "longpoll"]
        );
        let challenge = template.signet.map(|signet| signet.challenge);
        assert_eq!(
            challenge.as_ref().map(|script| (script[0], script.len())),
            (network == Network::Signet).then_some((0x51, 71)),
            "only signet carries the 1-of-2 challenge script"
        );
    }
}
