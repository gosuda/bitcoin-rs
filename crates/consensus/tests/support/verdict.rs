//! Accept/reject verdict shared by the kernel parity suites.

/// A coarse accept/reject verdict, the only thing the parity harnesses
/// compare. They intentionally collapse *why* a path rejected: the kernel and
/// the Rust path classify failures with different error taxonomies, and
/// requiring identical reasons would test the taxonomy, not consensus.
/// Identical accept/reject is the invariant; reason strings are surfaced only
/// in assertion messages for triage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The engine accepted the spend.
    Accept,
    /// The engine rejected the spend.
    Reject,
}

impl Verdict {
    /// Maps any `Result` to a verdict: `Ok` is accept, any `Err` is reject.
    ///
    /// Infrastructure errors collapse into `Reject` here by design; a caller
    /// asserting a Reject expectation must therefore also match the raw error
    /// to a real verdict variant (`ConsensusError::Script`), or a parse,
    /// precompute or wiring failure satisfies the assertion without any script
    /// ever executing. `kernel_block_parity` and `kernel_vector_parity` keep
    /// the raw `Result` and classify at the call site for exactly that reason.
    pub(crate) fn of<T, E>(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Self::Accept,
            Err(_) => Self::Reject,
        }
    }
}
