//! High-performance standalone server binary for terminating WDTT v2 sessions.

#![forbid(unsafe_code)]

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    tracing::info!("wdtt-server initializing...");
    Ok(())
}
