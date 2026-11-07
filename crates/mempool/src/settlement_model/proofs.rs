use super::{
    Action, SettlementError, SettlementState, settlement_safety, step,
    step_mutant_unsettled_assembly,
};

fn any_settlement_state() -> SettlementState {
    let applied_epoch: u32 = kani::any();
    let settled_at_epoch: u32 = kani::any();
    let mempool_gen: u64 = kani::any();
    let template_active: bool = kani::any();
    let template_epoch: u32 = kani::any();
    let template_gen: u64 = kani::any();
    let template_has_confirmed: bool = kani::any();
    let unsettled_confirmed_count: u32 = kani::any();
    let facts_queue_len: u32 = kani::any();

    kani::assume(applied_epoch <= 8);
    kani::assume(settled_at_epoch <= 8);
    kani::assume(template_epoch <= 8);
    kani::assume(facts_queue_len <= 8);
    kani::assume(unsettled_confirmed_count <= 8);

    SettlementState {
        applied_epoch,
        settled_at_epoch,
        mempool_gen,
        template_active,
        template_epoch,
        template_gen,
        template_has_confirmed,
        unsettled_confirmed_count,
        facts_queue_len,
    }
}

fn any_action() -> Action {
    let tag: u8 = kani::any();
    kani::assume(tag < 8);
    match tag {
        0 => Action::AdmitTx,
        1 => Action::CommitBlock,
        2 => Action::CommitReorg,
        3 => Action::SettleConnectFact {
            clears_confirmed: kani::any(),
        },
        4 => Action::SettleDisconnectFact,
        5 => Action::AssembleTemplate {
            req_epoch: kani::any(),
            req_gen: kani::any(),
        },
        6 => Action::MineBlock,
        _ => Action::Stutter,
    }
}

// MPS-01, MPS-03
#[kani::proof]
fn harness_settlement_step_inductive_safety() {
    let s = any_settlement_state();
    kani::assume(settlement_safety(&s));
    let a = any_action();
    let s_next = step(&s, a);
    assert!(settlement_safety(&s_next));
}

// MPS-01
#[kani::proof]
fn harness_orderly_settlement_fifo() {
    let mut s = any_settlement_state();
    kani::assume(settlement_safety(&s));
    kani::assume(s.facts_queue_len >= 2);
    let original_settled = s.settled_at_epoch;
    let clears_confirmed: bool = kani::any();
    s = step(&s, Action::SettleConnectFact { clears_confirmed });
    if s.facts_queue_len > 0 {
        assert_eq!(s.settled_at_epoch, original_settled);
    }
}

// MPS-03
#[kani::proof]
fn harness_mining_template_matched_pair() {
    let mut s = any_settlement_state();
    kani::assume(settlement_safety(&s));
    let req_epoch: u32 = kani::any();
    let req_gen: u64 = kani::any();
    let res = s.assemble_template(req_epoch, req_gen);
    let matched = req_epoch == s.applied_epoch
        && req_gen == s.mempool_gen
        && s.settled_at_epoch == s.applied_epoch;
    if matched {
        assert!(res.is_ok());
        assert!(s.template_active);
        assert_eq!(s.template_epoch, req_epoch);
        assert_eq!(s.template_gen, req_gen);
        assert!(!s.template_has_confirmed);
    } else {
        assert_eq!(res, Err(SettlementError::TemplateStaleOrUnsettled));
    }
}

// MPS-03
#[kani::proof]
fn harness_template_never_has_confirmed_tx() {
    let s = any_settlement_state();
    kani::assume(settlement_safety(&s));
    if s.template_active {
        assert!(!s.template_has_confirmed);
    }
}

// MPS-01, MPS-03
#[kani::proof]
fn harness_reorg_unsettles_consistently() {
    let s = any_settlement_state();
    kani::assume(settlement_safety(&s));
    let s_reorg = step(&s, Action::CommitReorg);
    assert!(!s_reorg.template_active);
    assert!(s_reorg.facts_queue_len >= 2);
    assert_ne!(s_reorg.settled_at_epoch, s_reorg.applied_epoch);
    let mut attempt = s_reorg.clone();
    let res = attempt.assemble_template(s_reorg.applied_epoch, s_reorg.mempool_gen);
    assert_eq!(res, Err(SettlementError::TemplateStaleOrUnsettled));
}

// MPS-03
#[kani::proof]
#[kani::should_panic]
fn harness_negative_control_mismatched_pair_assembly() {
    let mut s = SettlementState::init();
    s = step(&s, Action::CommitBlock);
    assert_eq!(s.unsettled_confirmed_count, 1);
    assert_eq!(s.facts_queue_len, 1);
    assert_ne!(s.settled_at_epoch, s.applied_epoch);
    let s_next = step_mutant_unsettled_assembly(
        &s,
        Action::AssembleTemplate {
            req_epoch: s.applied_epoch,
            req_gen: s.mempool_gen,
        },
    );
    assert!(s_next.template_active);
    assert!(!s_next.template_has_confirmed);
}
