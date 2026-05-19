use bitcoin_rs_primitives::Block;

use crate::ConsensusError;
use crate::kernel::KernelContext;
use crate::rust_path::{BlockState, RustValidator, TipState};

/// Connects a block through the kernel authority when enabled, otherwise through the Rust path.
#[cfg(feature = "kernel")]
pub fn connect_block_dual_path(
    kernel: &KernelContext,
    rust: &RustValidator,
    block: &Block,
    prev_tip: &TipState,
) -> Result<BlockState, ConsensusError> {
    let rust_result = rust.connect_block(block, prev_tip);
    let kernel_result = kernel.connect_block(block, prev_tip);
    if kernel_result != rust_result {
        tracing::error!(
            block_hash = %block.0.block_hash(),
            height = prev_tip.next_height(),
            kernel = ?kernel_result,
            rust = ?rust_result,
            "kernel/Rust consensus disagreement; returning kernel verdict"
        );
    }
    kernel_result
}

/// Connects a block through the Rust path when the kernel feature is disabled.
#[cfg(not(feature = "kernel"))]
pub fn connect_block_dual_path(
    _kernel: &KernelContext,
    rust: &RustValidator,
    block: &Block,
    prev_tip: &TipState,
) -> Result<BlockState, ConsensusError> {
    rust.connect_block(block, prev_tip)
}
