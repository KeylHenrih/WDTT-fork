//! Standalone server binary for terminating WDTT v2 sessions over TURN.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};
use wdtt_core::{TunnelServer, TunnelServerConfig};

struct ServerArgs {
    turn_server: SocketAddr,
    turn_username: String,
    turn_password: String,
    turn_realm: String,
    wg_endpoint: SocketAddr,
    psk: [u8; 32],
    relayed_addr_file: Option<PathBuf>,
    coalesce_window: Option<Duration>,
    runtime: String,
    workers: usize,
    listen: Option<SocketAddr>,
    listen_tls: Option<SocketAddr>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
}

impl ServerArgs {
    fn parse_from_env() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().collect();
        let mut turn_server = "127.0.0.1:3478".parse().unwrap();
        let mut turn_username = "user".to_string();
        let mut turn_password = "pass".to_string();
        let mut turn_realm = "coturn".to_string();
        let mut wg_endpoint = "127.0.0.1:51820".parse().unwrap();
        let mut psk = [0x55u8; 32];
        let mut relayed_addr_file = None;
        let mut coalesce_window = None;
        let mut runtime = std::env::var("WDTT_RUNTIME").unwrap_or_else(|_| "multi_thread".into());
        let mut workers = std::env::var("WDTT_WORKERS")
            .ok()
            .and_then(|w| w.parse().ok())
            .unwrap_or(2);
        let mut listen = None;
        let mut listen_tls = None;
        let mut tls_cert = None;
        let mut tls_key = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--listen" => {
                    i += 1;
                    listen = Some(
                        args.get(i)
                            .ok_or("Missing value for --listen")?
                            .parse()
                            .map_err(|e| format!("Invalid --listen address: {e}"))?,
                    );
                }
                "--listen-tls" => {
                    i += 1;
                    listen_tls = Some(
                        args.get(i)
                            .ok_or("Missing value for --listen-tls")?
                            .parse()
                            .map_err(|e| format!("Invalid --listen-tls address: {e}"))?,
                    );
                }
                "--tls-cert" => {
                    i += 1;
                    tls_cert = Some(PathBuf::from(
                        args.get(i).ok_or("Missing value for --tls-cert")?,
                    ));
                }
                "--tls-key" => {
                    i += 1;
                    tls_key = Some(PathBuf::from(
                        args.get(i).ok_or("Missing value for --tls-key")?,
                    ));
                }
                "--turn-server" => {
                    i += 1;
                    turn_server = args
                        .get(i)
                        .ok_or("Missing value for --turn-server")?
                        .parse()
                        .map_err(|e| format!("Invalid --turn-server address: {e}"))?;
                }
                "--turn-user" => {
                    i += 1;
                    turn_username = args.get(i).ok_or("Missing value for --turn-user")?.clone();
                }
                "--turn-pass" => {
                    i += 1;
                    turn_password = args.get(i).ok_or("Missing value for --turn-pass")?.clone();
                }
                "--turn-realm" => {
                    i += 1;
                    turn_realm = args.get(i).ok_or("Missing value for --turn-realm")?.clone();
                }
                "--wg-endpoint" => {
                    i += 1;
                    wg_endpoint = args
                        .get(i)
                        .ok_or("Missing value for --wg-endpoint")?
                        .parse()
                        .map_err(|e| format!("Invalid --wg-endpoint address: {e}"))?;
                }
                "--psk" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --psk")?;
                    psk = wdtt_crypto::Psk::parse(val)
                        .map_err(|e| format!("Invalid --psk: {e}"))?
                        .as_bytes()
                        .to_owned();
                }
                "--relayed-addr-file" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --relayed-addr-file")?;
                    relayed_addr_file = Some(PathBuf::from(val));
                }
                "--coalesce-ms" => {
                    i += 1;
                    let ms: u64 = args
                        .get(i)
                        .ok_or("Missing value for --coalesce-ms")?
                        .parse()
                        .map_err(|e| format!("Invalid --coalesce-ms value: {e}"))?;
                    coalesce_window = if ms > 0 {
                        Some(Duration::from_millis(ms))
                    } else {
                        None
                    };
                }
                "--runtime" => {
                    i += 1;
                    runtime = args.get(i).ok_or("Missing value for --runtime")?.clone();
                }
                "--workers" => {
                    i += 1;
                    workers = args
                        .get(i)
                        .ok_or("Missing value for --workers")?
                        .parse()
                        .map_err(|e| format!("Invalid worker count: {e}"))?;
                }
                "-h" | "--help" => {
                    println!(
                        "Usage: wdtt-server [OPTIONS]\n\n\
                         Options:\n  \
                           --listen <ADDR:PORT>         Direct UDP listen address (VK / direct mode)\n  \
                           --listen-tls <ADDR:PORT>     TCP/TLS stream listen address (e.g. 0.0.0.0:443)\n  \
                           --tls-cert <PATH>            TLS certificate chain (DER) for --listen-tls\n  \
                           --tls-key <PATH>             TLS private key (PKCS#8 DER) for --listen-tls\n  \
                           --turn-server <ADDR:PORT>    TURN server address (default: 127.0.0.1:3478)\n  \
                           --turn-user <USER>           TURN username (default: user)\n  \
                           --turn-pass <PASS>           TURN password (default: pass)\n  \
                           --turn-realm <REALM>         TURN realm (default: coturn)\n  \
                           --wg-endpoint <ADDR:PORT>    Local WireGuard endpoint (default: 127.0.0.1:51820)\n  \
                           --psk <HEX>                  Pre-shared key: 64 hex chars (or raw 32-byte string)\n  \
                           --relayed-addr-file <PATH>   Write allocated TURN relay address to file\n  \
                           --runtime <MODE>             Tokio runtime: multi_thread (default), current_thread\n  \
                           --workers <N>                Worker threads for multi_thread runtime (default: 2)\n"
                    );
                    std::process::exit(0);
                }
                other => {
                    return Err(format!("Unknown option: {other}"));
                }
            }
            i += 1;
        }

        Ok(Self {
            turn_server,
            turn_username,
            turn_password,
            turn_realm,
            wg_endpoint,
            psk,
            relayed_addr_file,
            coalesce_window,
            runtime,
            workers,
            listen,
            listen_tls,
            tls_cert,
            tls_key,
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = match ServerArgs::parse_from_env() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let rt = if args.runtime == "current_thread" {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(args.workers)
            .enable_all()
            .build()?
    };

    rt.block_on(async_main(args))
}

async fn async_main(args: ServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== WDTT v2 Server (Stage 3 Standalone) ===");
    if let Some(listen_addr) = args.listen {
        info!("Server mode: DIRECT UDP / VK listener on {}", listen_addr);
    } else if args.listen_tls.is_some() {
        info!("Server mode: STREAM TCP/TLS listener only");
    } else {
        info!(
            "Server mode: TURN client terminating at {}",
            args.turn_server
        );
    }
    if let Some(addr) = args.listen_tls {
        info!("Stream TCP/TLS listener on {}", addr);
    }
    info!("WireGuard endpoint target: {}", args.wg_endpoint);
    info!("Coalesce window: {:?}", args.coalesce_window);
    info!(
        "Tokio runtime: {} (workers: {})",
        args.runtime, args.workers
    );

    let tls_cert_der = match args.tls_cert.as_ref() {
        Some(path) => Some(
            tokio::fs::read(path)
                .await
                .map_err(|e| format!("Failed to read TLS certificate {:?}: {e}", path))?,
        ),
        None => None,
    };
    let tls_key_der = match args.tls_key.as_ref() {
        Some(path) => Some(
            tokio::fs::read(path)
                .await
                .map_err(|e| format!("Failed to read TLS key {:?}: {e}", path))?,
        ),
        None => None,
    };
    if args.listen_tls.is_some() && (tls_cert_der.is_none() || tls_key_der.is_none()) {
        return Err("--listen-tls requires both --tls-cert and --tls-key".into());
    }

    let config = TunnelServerConfig {
        turn_server_addr: args.turn_server,
        turn_username: args.turn_username,
        turn_password: args.turn_password,
        turn_realm: args.turn_realm,
        wg_endpoint_addr: args.wg_endpoint,
        psk: args.psk,
        coalesce_window: args.coalesce_window,
        direct_listen_addr: args.listen,
        stream_listen_addr: args.listen_tls,
        tls_cert_der,
        tls_key_der,
    };

    let mut server = TunnelServer::new(config);
    let metrics = server.metrics();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (alloc_tx, alloc_rx) = tokio::sync::oneshot::channel();

    // Spawn server task
    let server_task =
        tokio::spawn(async move { server.run_with_notify(cancel_rx, Some(alloc_tx)).await });

    // Wait for relay allocation
    match alloc_rx.await {
        Ok(relayed_addr) => {
            info!("Successfully allocated TURN relayed address: {relayed_addr}");
            if let Some(ref path) = args.relayed_addr_file {
                if let Err(e) = tokio::fs::write(path, format!("{relayed_addr}\n")).await {
                    error!("Failed to write relayed address to file {:?}: {e}", path);
                } else {
                    info!("Wrote relayed address to {:?}", path);
                }
            }
        }
        Err(_) => {
            error!("Server task terminated before relay address allocation");
        }
    }

    // Wait for Ctrl+C
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C), stopping server...");
            let _ = cancel_tx.send(true);
        }
        res = server_task => {
            if let Ok(Err(e)) = res {
                error!("Server error: {e}");
            }
        }
    }

    let snap = metrics.snapshot();
    info!(
        "Final Metrics: TX packets={} bytes={} | RX packets={} bytes={} | batches single={} multi={} | pings tx={} rx={}",
        snap.packets_tx,
        snap.bytes_tx,
        snap.packets_rx,
        snap.bytes_rx,
        snap.batches_single,
        snap.batches_multi,
        snap.pings_tx,
        snap.pings_rx
    );

    Ok(())
}
