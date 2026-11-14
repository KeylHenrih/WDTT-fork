//! Standalone client console daemon for initiating WDTT v2 sessions over TURN.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use tokio::sync::watch;
use tracing::{error, info};
use wdtt_core::{TunnelClient, TunnelClientConfig};

struct ClientArgs {
    turn_server: SocketAddr,
    turn_username: String,
    turn_password: String,
    turn_realm: String,
    server_relayed: SocketAddr,
    wg_listen: SocketAddr,
    psk: [u8; 32],
}

impl ClientArgs {
    fn parse_from_env() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().collect();
        let mut turn_server = "127.0.0.1:3478".parse().unwrap();
        let mut turn_username = "user".to_string();
        let mut turn_password = "pass".to_string();
        let mut turn_realm = "coturn".to_string();
        let mut server_relayed = None;
        let mut wg_listen = "127.0.0.1:51821".parse().unwrap();
        let mut psk = [0x55u8; 32];

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
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
                "--server-relayed" => {
                    i += 1;
                    server_relayed = Some(
                        args.get(i)
                            .ok_or("Missing value for --server-relayed")?
                            .parse()
                            .map_err(|e| format!("Invalid --server-relayed address: {e}"))?,
                    );
                }
                "--wg-listen" => {
                    i += 1;
                    wg_listen = args
                        .get(i)
                        .ok_or("Missing value for --wg-listen")?
                        .parse()
                        .map_err(|e| format!("Invalid --wg-listen address: {e}"))?;
                }
                "--psk" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --psk")?;
                    let bytes = val.as_bytes();
                    for (dst, src) in psk.iter_mut().zip(bytes.iter()) {
                        *dst = *src;
                    }
                }
                "-h" | "--help" => {
                    println!(
                        "Usage: wdttd [OPTIONS] --server-relayed <ADDR:PORT>\n\n\
                         Options:\n  \
                           --turn-server <ADDR:PORT>       TURN server address (default: 127.0.0.1:3478)\n  \
                           --turn-user <USER>              TURN username (default: user)\n  \
                           --turn-pass <PASS>              TURN password (default: pass)\n  \
                           --turn-realm <REALM>            TURN realm (default: coturn)\n  \
                           --server-relayed <ADDR:PORT>    Remote server relayed address on TURN (required)\n  \
                           --wg-listen <ADDR:PORT>         Local WireGuard listening port (default: 127.0.0.1:51821)\n  \
                           --psk <STRING>                  Pre-shared key for knock authentication\n"
                    );
                    std::process::exit(0);
                }
                other => {
                    return Err(format!("Unknown option: {other}"));
                }
            }
            i += 1;
        }

        let server_relayed =
            server_relayed.ok_or("Missing required --server-relayed <ADDR:PORT>")?;

        Ok(Self {
            turn_server,
            turn_username,
            turn_password,
            turn_realm,
            server_relayed,
            wg_listen,
            psk,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = match ClientArgs::parse_from_env() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    info!("=== WDTT v2 Client Daemon (Stage 3 Standalone) ===");
    info!("TURN relay server: {}", args.turn_server);
    info!("Server relayed target: {}", args.server_relayed);
    info!("WireGuard bridge listen port: {}", args.wg_listen);

    let config = TunnelClientConfig {
        turn_server_addr: args.turn_server,
        turn_username: args.turn_username,
        turn_password: args.turn_password,
        turn_realm: args.turn_realm,
        server_relayed_addr: args.server_relayed,
        wg_listen_addr: args.wg_listen,
        psk: args.psk,
    };

    let mut client = TunnelClient::new(config);
    let metrics = client.metrics();

    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let client_task =
        tokio::spawn(async move { client.run_with_notify(cancel_rx, Some(ready_tx)).await });

    match ready_rx.await {
        Ok(relayed_addr) => {
            info!("Client allocated relay address: {relayed_addr}");
            info!(
                "Tunnel ready! Configure WireGuard peer endpoint to {}",
                args.wg_listen
            );
        }
        Err(_) => {
            error!("Client task terminated unexpectedly during allocation");
        }
    }

    // Wait for Ctrl+C
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C), stopping client...");
            let _ = cancel_tx.send(true);
        }
        res = client_task => {
            if let Ok(Err(e)) = res {
                error!("Client error: {e}");
            }
        }
    }

    let snap = metrics.snapshot();
    info!(
        "Final Metrics: TX packets={} bytes={} | RX packets={} bytes={}",
        snap.packets_tx, snap.bytes_tx, snap.packets_rx, snap.bytes_rx
    );

    Ok(())
}
