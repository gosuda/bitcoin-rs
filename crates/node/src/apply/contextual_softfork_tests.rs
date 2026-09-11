use bitcoin_rs_primitives::BlockHash;
use bitcoin_rs_script::VerifyFlags;

use super::*;

#[test]
fn verify_flags_use_contextual_csv_and_segwit_state() {
    let inactive = bitcoin_rs_chain::SoftforkState {
        csv_active: false,
        segwit_active: false,
    };
    let active = bitcoin_rs_chain::SoftforkState {
        csv_active: true,
        segwit_active: true,
    };

    let non_exception = Hash256::from_le_bytes(&[0u8; 32]);
    let inactive_flags = compute_verify_flags(Network::Mainnet, 481_824, non_exception, inactive);
    assert!(!inactive_flags.contains(VerifyFlags::CHECKSEQUENCEVERIFY));
    assert!(!inactive_flags.contains(VerifyFlags::WITNESS));
    assert!(!inactive_flags.contains(VerifyFlags::NULLDUMMY));

    let active_flags = compute_verify_flags(Network::Mainnet, 1, non_exception, active);
    assert!(active_flags.contains(VerifyFlags::CHECKSEQUENCEVERIFY));
    assert!(active_flags.contains(VerifyFlags::WITNESS));
    assert!(active_flags.contains(VerifyFlags::NULLDUMMY));
}

#[test]
fn compute_verify_flags_drops_p2sh_only_for_bip16_exception_block()
-> Result<(), Box<dyn std::error::Error>> {
    let state = bitcoin_rs_chain::SoftforkState {
        csv_active: false,
        segwit_active: false,
    };

    // Parse the exception hash from its display hex, so a byte-order flip in
    // the stored consensus-LE constant cannot silently drift past this test.
    let exception_display = "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22";
    let exception_hash = Hash256::from(exception_display.parse::<BlockHash>()?);

    // Core exempts exactly this block (its height) from P2SH; flags must not carry P2SH.
    let exception_flags = compute_verify_flags(Network::Mainnet, 170_060, exception_hash, state);
    assert!(!exception_flags.contains(VerifyFlags::P2SH));

    // Any other block at the same height still enforces P2SH.
    let other_hash = Hash256::from_le_bytes(&[0u8; 32]);
    let other_flags = compute_verify_flags(Network::Mainnet, 170_060, other_hash, state);
    assert!(other_flags.contains(VerifyFlags::P2SH));

    Ok(())
}
