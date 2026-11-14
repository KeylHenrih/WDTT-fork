//! Privileged background system service/daemon for Windows, Linux, and macOS.

#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("wdttd starting...");
    Ok(())
}
