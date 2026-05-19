//! Subscription status-hash notification tests.
use bitcoin::Txid;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_electrum::methods::scripthash_hex;
use bitcoin_rs_electrum::{IndexHandle, MempoolHandle, SessionSubscriptions};
use bitcoin_rs_index::ScriptHash;
use sonic_rs::{JsonContainerTrait, JsonValueTrait};

#[test]
fn subscribed_scripthash_pushes_notification_after_history_change()
-> Result<(), Box<dyn std::error::Error>> {
    let index = IndexHandle::new();
    let mempool = MempoolHandle::default();
    let scripthash = ScriptHash::from_byte_array([9_u8; 32]);
    let mut subscriptions = SessionSubscriptions::new();

    let initial = subscriptions.subscribe_scripthash(&index, &mempool, scripthash);
    assert!(initial.is_null());

    index.add_history_entry(
        scripthash,
        Txid::from_byte_array([3_u8; 32]),
        42,
        12_345,
        0,
        false,
    );

    let notifications = subscriptions.poll(&index, &mempool)?;
    assert_eq!(notifications.len(), 1);
    let notification = &notifications[0];
    let scripthash_string = scripthash_hex(scripthash);
    assert_eq!(
        notification.get("method").and_then(JsonValueTrait::as_str),
        Some("blockchain.scripthash.subscribe")
    );
    let Some(params) = notification
        .get("params")
        .and_then(JsonContainerTrait::as_array)
    else {
        panic!("notification params must be an array");
    };
    assert_eq!(
        params.first().and_then(JsonValueTrait::as_str),
        Some(scripthash_string.as_str())
    );
    assert!(params.get(1).is_str());

    Ok(())
}
