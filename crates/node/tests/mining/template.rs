use anyhow::Result;
use bitcoin_rs_mining::{
    BlockTemplateMode, BlockTemplateRequest, BlockValidationResult, CoinbaseBudget,
    MiningCapability, MiningControl, MiningControlError, TemplateId, solve_block,
};
use bitcoin_rs_node::Network;
use bitcoin_rs_primitives::Hash256;

use super::support::{
    budgeted_template_request, coordinator, expect_template, open_at_genesis, propose_block,
    regtest_mining, template_request,
};

#[test]
fn template_does_not_echo_client_capabilities() -> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let template = expect_template(mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: vec![
            MiningCapability::new("coinbasetxn"),
            MiningCapability::new("unknown-client-only"),
            MiningCapability::new("proposal"),
        ],
        rules: Vec::new(),
        long_poll_id: None,
        coinbase_budget: None,
    })?);
    assert_eq!(
        template
            .capabilities
            .iter()
            .map(MiningCapability::as_str)
            .collect::<Vec<_>>(),
        vec!["proposal", "longpoll"]
    );
    assert_eq!(template.version_bits_required, 0);
    assert!(template.signet.is_none());
    Ok(())
}

#[test]
fn signet_template_includes_challenge_and_signet_rule() -> Result<()> {
    let state = open_at_genesis(Network::Signet)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let template = expect_template(mining.get_block_template(template_request(None))?);
    assert!(template.rules.iter().any(|rule| rule.as_str() == "signet"));
    assert!(template.signet.is_some());
    Ok(())
}

#[test]
fn budgeted_request_reaches_the_selector_and_yields_a_valid_block() -> Result<()> {
    let (state, mining) = regtest_mining()?;
    mining.publish_generation();
    let budget = CoinbaseBudget {
        additional_size: 4_000,
        additional_sigops: 100,
    };
    let budgeted = expect_template(mining.get_block_template(budgeted_template_request(budget))?);
    budgeted.candidate.admits(budget)?;

    let ordinary = expect_template(mining.get_block_template(template_request(None))?);
    let genesis_hash = Hash256::from(Network::Regtest.genesis_block().block_hash());
    let sequence = state.mempool().read().sequence_number();
    assert_eq!(
        ordinary.candidate.template_id,
        TemplateId::new(&genesis_hash, sequence)
    );
    assert_ne!(
        budgeted.candidate.template_id,
        ordinary.candidate.template_id
    );
    assert!(
        budgeted
            .candidate
            .template_id
            .as_str()
            .starts_with(ordinary.candidate.template_id.as_str())
    );

    let mut block = budgeted.candidate.into_unsolved_block()?;
    solve_block(&mut block, 1_000_000)?;
    assert_eq!(
        propose_block(&mining, block)?,
        BlockValidationResult::Accepted
    );
    Ok(())
}

#[test]
fn unsatisfiable_budget_is_the_existing_failed_error_and_ordinary_templates_keep_working()
-> Result<()> {
    let (_state, mining) = regtest_mining()?;
    mining.publish_generation();
    let impossible = CoinbaseBudget {
        additional_size: u32::MAX,
        additional_sigops: u16::MAX,
    };
    let refused = mining.get_block_template(budgeted_template_request(impossible));
    assert!(
        matches!(
            &refused,
            Err(MiningControlError::Failed(message))
                if message.contains("exhausts the weight limit")
        ),
        "{refused:?}"
    );
    expect_template(mining.get_block_template(template_request(None))?);
    Ok(())
}
