use anyhow::Result;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

/// Installs process-wide JSON tracing to stderr.
pub fn install_tracing(level: &str) -> Result<()> {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_error| EnvFilter::new("info"));
    let subscriber = tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr),
    );
    let _already_installed = subscriber.try_init();
    Ok(())
}
