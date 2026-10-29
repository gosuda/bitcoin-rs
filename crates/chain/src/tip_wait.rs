use std::sync::Arc;
use std::time::Instant;

use bitcoin_rs_primitives::Hash256;

use crate::{LatchReader, TipSnapshot};

#[derive(Clone, Copy, Debug)]
pub enum TipWaitCondition {
    Changed(Option<Hash256>),
    Hash(Hash256),
    Height(i32),
}

impl TipWaitCondition {
    #[must_use]
    pub fn matches(self, tip: &TipSnapshot) -> bool {
        match self {
            Self::Changed(hash) => hash.is_some_and(|hash| hash != tip.hash),
            Self::Hash(hash) => hash == tip.hash,
            Self::Height(height) => i64::from(tip.height) >= i64::from(height),
        }
    }
}

pub trait ActiveTipWait: Send + Sync {
    fn wait_for_tip(
        &self,
        condition: TipWaitCondition,
        deadline: Option<Instant>,
        cancellation: &LatchReader,
    ) -> Option<Arc<TipSnapshot>>;

    fn wake_waiters(&self);
}
