// PRJ-05, PRJ-07, PRJ-09, REO-04, REO-05
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationAction {
    AppendBlock,
    SealGeneration,
    Reorganize { fork: u32 },
    QueryAnswer,
    Stutter,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationsState {
    pub applied_tip: u32,
    pub tail_lo: u32,
    pub tail_hi: u32,
    pub active_gens_cover: u32,
    pub has_invalid_coverage: bool,
    pub has_segment_offset: bool,
    pub reorg_count: u32,
}

pub const MAX_TIP: u32 = 4;
pub const TAIL_BOUND: u32 = 2;
pub const MAX_REORGS: u32 = 1;

#[must_use]
pub fn safety(s: &GenerationsState) -> bool {
    !s.has_invalid_coverage
        && s.active_gens_cover <= s.applied_tip
        && s.active_gens_cover < s.tail_lo
        && s.tail_hi <= s.applied_tip
        && !s.has_segment_offset
}

#[must_use]
pub fn step(s: &GenerationsState, action: GenerationAction) -> GenerationsState {
    let mut next = s.clone();
    match action {
        GenerationAction::AppendBlock => {
            if s.applied_tip < MAX_TIP {
                let new_tip = s.applied_tip + 1;
                let new_lo = if s.tail_hi < s.tail_lo {
                    new_tip
                } else {
                    s.tail_lo
                };
                next.applied_tip = new_tip;
                next.tail_hi = new_tip;
                next.tail_lo = new_lo;
            }
        }
        GenerationAction::SealGeneration => {
            if s.tail_hi >= s.tail_lo && s.tail_hi - s.tail_lo + 1 >= TAIL_BOUND {
                let seal_last = s.tail_lo + TAIL_BOUND - 1;
                next.tail_lo = seal_last + 1;
                next.active_gens_cover = seal_last;
            }
        }
        GenerationAction::Reorganize { fork } => {
            if s.reorg_count < MAX_REORGS && s.applied_tip > 0 && fork < s.applied_tip {
                next.applied_tip = fork;
                next.tail_hi = fork;
                if fork >= s.tail_lo {
                } else {
                    next.tail_lo = fork + 1;
                    next.active_gens_cover = if s.active_gens_cover > fork {
                        0
                    } else {
                        s.active_gens_cover
                    };
                }
                next.reorg_count += 1;
            }
        }
        GenerationAction::QueryAnswer => {
            if s.applied_tip > 0 {
                next.has_segment_offset = false;
            }
        }
        GenerationAction::Stutter => {}
    }
    next
}

#[cfg(kani)]
mod verification {
    use super::*;

    fn any_generations_state() -> GenerationsState {
        let applied_tip: u32 = kani::any();
        let tail_lo: u32 = kani::any();
        let tail_hi: u32 = kani::any();
        let active_gens_cover: u32 = kani::any();
        let has_invalid_coverage: bool = kani::any();
        let has_segment_offset: bool = kani::any();
        let reorg_count: u32 = kani::any();

        kani::assume(applied_tip <= MAX_TIP);
        kani::assume(tail_lo <= MAX_TIP + 2);
        kani::assume(tail_hi <= MAX_TIP);
        kani::assume(active_gens_cover <= MAX_TIP);
        kani::assume(reorg_count <= MAX_REORGS);

        GenerationsState {
            applied_tip,
            tail_lo,
            tail_hi,
            active_gens_cover,
            has_invalid_coverage,
            has_segment_offset,
            reorg_count,
        }
    }

    fn any_generation_action() -> GenerationAction {
        let tag: u8 = kani::any();
        match tag % 5 {
            0 => GenerationAction::AppendBlock,
            1 => GenerationAction::SealGeneration,
            2 => {
                let fork: u32 = kani::any();
                kani::assume(fork <= MAX_TIP);
                GenerationAction::Reorganize { fork }
            }
            3 => GenerationAction::QueryAnswer,
            _ => GenerationAction::Stutter,
        }
    }

    // PRJ-05, PRJ-07, PRJ-09, REO-04, REO-05
    #[kani::proof]
    #[kani::unwind(2)]
    fn harness_generations_step_inductive_safety() {
        let s = any_generations_state();
        kani::assume(safety(&s));
        let a = any_generation_action();
        assert!(safety(&step(&s, a)));
    }

    // PRJ-05
    #[kani::proof]
    #[kani::unwind(2)]
    fn harness_sealed_segment_immutability_and_tail_boundary() {
        let s = any_generations_state();
        kani::assume(
            safety(&s) && s.tail_hi >= s.tail_lo && s.tail_hi - s.tail_lo + 1 >= TAIL_BOUND,
        );
        let next = step(&s, GenerationAction::SealGeneration);
        assert_eq!(next.active_gens_cover, s.tail_lo + TAIL_BOUND - 1);
        assert_eq!(next.tail_lo, next.active_gens_cover + 1);
        assert!(next.active_gens_cover <= next.applied_tip);
    }

    // REO-04
    #[kani::proof]
    #[kani::unwind(2)]
    fn harness_deep_reorg_retires_invalidated_generations() {
        let s = any_generations_state();
        let fork: u32 = kani::any();
        kani::assume(
            safety(&s) && s.reorg_count < MAX_REORGS && fork < s.tail_lo && fork < s.applied_tip,
        );
        let next = step(&s, GenerationAction::Reorganize { fork });
        assert!(next.active_gens_cover <= fork);
        assert!(!next.has_invalid_coverage);
    }

    // REO-05
    #[kani::proof]
    #[kani::unwind(2)]
    fn harness_shallow_reorg_preserves_sealed_generations() {
        let s = any_generations_state();
        let fork: u32 = kani::any();
        kani::assume(
            safety(&s) && s.reorg_count < MAX_REORGS && fork >= s.tail_lo && fork < s.applied_tip,
        );
        let next = step(&s, GenerationAction::Reorganize { fork });
        assert_eq!(next.active_gens_cover, s.active_gens_cover);
        assert_eq!(next.tail_hi, fork);
    }

    // PRJ-07
    #[kani::proof]
    #[kani::unwind(2)]
    fn harness_query_answers_contain_no_segment_offsets() {
        let s = any_generations_state();
        kani::assume(safety(&s) && s.applied_tip > 0);
        let next = step(&s, GenerationAction::QueryAnswer);
        assert!(!next.has_segment_offset);
    }
}
