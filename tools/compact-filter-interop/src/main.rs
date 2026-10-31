//! Application driver for the unmodified, commit-pinned Kyoto consumer.
use bip157::{Builder, ChainState, Event, HashCheckpoint, Network, ScriptBuf};
use sonic_rs::json;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

#[derive(Debug)]
enum InteropError {
    Usage,
    ParsePort(std::num::ParseIntError),
    ParseHeight(std::num::ParseIntError),
    ConsumerStopped,
    MissingFilter,
    FetchBlock(bip157::error::FetchBlockError),
    HeightMismatch,
    Timeout(tokio::time::error::Elapsed),
}

impl std::fmt::Display for InteropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage => write!(
                f,
                "usage: compact-filter-interop LOOPBACK_PORT TARGET_HEIGHT"
            ),
            Self::ParsePort(err) => write!(f, "invalid port: {err}"),
            Self::ParseHeight(err) => write!(f, "invalid height: {err}"),
            Self::ConsumerStopped => write!(f, "consumer stopped before reaching target"),
            Self::MissingFilter => write!(f, "target filter was not received"),
            Self::FetchBlock(err) => write!(f, "failed to fetch block: {err}"),
            Self::HeightMismatch => write!(f, "fetched block does not match target height"),
            Self::Timeout(err) => write!(f, "timed out: {err}"),
        }
    }
}

impl std::error::Error for InteropError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ParsePort(err) => Some(err),
            Self::ParseHeight(err) => Some(err),
            Self::FetchBlock(err) => Some(err),
            Self::Timeout(err) => Some(err),
            Self::Usage | Self::ConsumerStopped | Self::MissingFilter | Self::HeightMismatch => {
                None
            }
        }
    }
}

impl From<tokio::time::error::Elapsed> for InteropError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        Self::Timeout(err)
    }
}

impl From<bip157::error::FetchBlockError> for InteropError {
    fn from(err: bip157::error::FetchBlockError) -> Self {
        Self::FetchBlock(err)
    }
}

#[tokio::main]
async fn main() -> Result<(), InteropError> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(InteropError::Usage);
    }
    let port: u16 = args[1].parse().map_err(InteropError::ParsePort)?;
    let height: u32 = args[2].parse().map_err(InteropError::ParseHeight)?;
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
                event = client.event_rx.recv() => match event.ok_or(InteropError::ConsumerStopped)? {
                    Event::IndexedFilter(filter) => {
                        if filter.height() == height { target_hash = Some(filter.block_hash()); }
                        let matched = filter.contains_any(std::iter::once(&watched));
                        println!("{}", json!({"event": "filter", "height": filter.height(), "hash": filter.block_hash().to_string(), "matched": matched, "bytes": filter.into_contents()}));
                    },
                    Event::FiltersSynced(update) => {
                        println!("{}", json!({"event": "synced", "height": update.tip.height, "hash": update.tip.hash.to_string()}));
                        if update.tip.height >= height {
                            let block = client.requester.get_block(target_hash.ok_or(InteropError::MissingFilter)?).await?;
                            if block.height != height { return Err(InteropError::HeightMismatch); }
                            println!("{}", json!({"event": "block", "height": block.height, "hash": block.block.block_hash().to_string()}));
                            return Ok::<(), InteropError>(());
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
