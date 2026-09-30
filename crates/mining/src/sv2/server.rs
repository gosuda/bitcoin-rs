//! SV2 Template Distribution Protocol server.
//!
//! Accepts pool connections over Noise-encrypted TCP and distributes
//! block templates via TDP. The server polls [`TemplateHub`] for new
//! templates and pushes [`NewTemplate`] + [`SetNewPrevHash`] to
//! connected pools.

use std::net::SocketAddr;

use super::template::TemplateHub;

/// SV2 template-distribution server.
pub struct Sv2Server {
    listen: SocketAddr,
    hub: TemplateHub,
}

impl Sv2Server {
    /// Creates a new server bound to `listen`.
    pub fn new(listen: SocketAddr, hub: TemplateHub) -> Self {
        Self { listen, hub }
    }

    /// Runs the server, accepting connections and distributing templates.
    ///
    /// This is a stub — the full SV2 Noise/TDP implementation will be
    /// ported from the existing template-provider code.
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        tracing::info!(addr = %self.listen, "sv2 template-provider starting");
        // TODO: implement Noise handshake + TDP framing
        // For now, just poll for templates to verify the MiningSource works.
        loop {
            match self.hub.next_template() {
                Ok(snapshot) => {
                    tracing::info!(
                        height = snapshot.template.candidate.height,
                        tx_count = snapshot.transaction_ids.len(),
                        "new template ready"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "template poll failed");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}
