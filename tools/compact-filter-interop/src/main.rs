//! Application driver for the unmodified, commit-pinned Kyoto consumer.
use bip157::{Builder, ChainState, Event, HashCheckpoint, Network, ScriptBuf};
use sonic_rs::json;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: compact-filter-interop LOOPBACK_PORT TARGET_HEIGHT".into());
    }
    let port: u16 = args[1].parse()?;
    let height: u32 = args[2].parse()?;
    let watched = ScriptBuf::from_bytes(vec![0x52]);
    let (node, mut client) = Builder::new(Network::Regtest)
        .chain_state(ChainState::Checkpoint(HashCheckpoint::from_genesis(
            Network::Regtest,
        )))
        .add_peer((IpAddr::V4(Ipv4Addr::LOCALHOST), Some(port)))
        .whitelist_only()
        .handshake_timeout(Duration::from_secs(5))
        .response_timeout(Duration::from_secs(10))
        .build();
    let task = tokio::spawn(node.run());
    let mut target_hash = None;
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            tokio::select! {
                Some(info) = client.info_rx.recv() => eprintln!("{info:?}"),
                Some(warning) = client.warn_rx.recv() => eprintln!("{warning:?}"),
                event = client.event_rx.recv() => match event.ok_or("consumer stopped before reaching target")? {
                    Event::IndexedFilter(filter) => {
                        if filter.height() == height { target_hash = Some(filter.block_hash()); }
                        let matched = filter.contains_any(std::iter::once(&watched));
                        println!("{}", json!({"event": "filter", "height": filter.height(), "hash": filter.block_hash().to_string(), "matched": matched, "bytes": filter.into_contents()}));
                    },
                    Event::FiltersSynced(update) => {
                        println!("{}", json!({"event": "synced", "height": update.tip.height, "hash": update.tip.hash.to_string()}));
                        if update.tip.height >= height {
                            let block = client.requester.get_block(target_hash.ok_or("target filter was not received")?).await?;
                            if block.height != height { return Err("fetched block does not match target height".into()); }
                            println!("{}", json!({"event": "block", "height": block.height, "hash": block.block.block_hash().to_string()}));
                            return Ok::<(), Box<dyn std::error::Error>>(());
                        }
                    },
                    _ => {},
                }
            }
        }
    }).await;
    let _ = client.requester.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    result??;
    Ok(())
}
