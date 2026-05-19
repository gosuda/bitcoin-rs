//! Supported descriptor parser coverage.

use bitcoin_rs_wallet::Descriptor;

#[path = "fixtures/test_signer.rs"]
mod test_signer;

#[test]
fn parser_accepts_task14_descriptor_forms() -> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let public_key = signer.public_key();
    for descriptor in [
        format!("pkh({public_key})"),
        format!("wpkh({public_key})"),
        format!("sh(wpkh({public_key}))"),
        format!("tr({public_key})"),
        format!("wsh(multi(1,{public_key}))"),
        format!("tr({public_key},multi_a(1,{public_key}))"),
    ] {
        Descriptor::parse(&descriptor)?;
    }
    Ok(())
}
