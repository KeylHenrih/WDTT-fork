//! Standalone client console daemon for initiating WDTT v2 sessions over TURN.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info};
use wdtt_core::{KeepaliveMode, TunnelClient, TunnelClientConfig};

struct ClientArgs {
    turn_server: SocketAddr,
    turn_username: String,
    turn_password: String,
    turn_realm: String,
    server_relayed: SocketAddr,
    wg_listen: SocketAddr,
    psk: [u8; 32],
    keepalive_mode: KeepaliveMode,
    coalesce_window: Option<Duration>,
    runtime: String,
    workers: usize,
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
        let mut keepalive_mode = match std::env::var("WDTT_KEEPALIVE").as_deref() {
            Ok("chaff") => KeepaliveMode::Chaff,
            Ok("disabled") => KeepaliveMode::Disabled,
            _ => KeepaliveMode::PowerSave,
        };
        let mut coalesce_window = None;
        let mut runtime = std::env::var("WDTT_RUNTIME").unwrap_or_else(|_| "current_thread".into());
        let mut workers = std::env::var("WDTT_WORKERS")
            .ok()
            .and_then(|w| w.parse().ok())
            .unwrap_or(2);

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
                "--keepalive" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --keepalive")?;
                    keepalive_mode = match val.as_str() {
                        "chaff" => KeepaliveMode::Chaff,
                        "disabled" => KeepaliveMode::Disabled,
                        "powersave" => KeepaliveMode::PowerSave,
                        other => return Err(format!("Unknown keepalive mode '{other}', expected: powersave, chaff, disabled")),
                    };
                }
                "--profile" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --profile")?;
                    match val.as_str() {
                        "powersave" => {
                            keepalive_mode = KeepaliveMode::PowerSave;
                            coalesce_window = Some(Duration::from_millis(1));
                        }
                        "performance" => {
                            keepalive_mode = KeepaliveMode::PowerSave;
                            coalesce_window = None;
                        }
                        "chaff" => {
                            keepalive_mode = KeepaliveMode::Chaff;
                            coalesce_window = None;
                        }
                        other => return Err(format!("Unknown profile '{other}', expected: powersave, performance, chaff")),
                    }
                }
                "--coalesce-ms" => {
                    i += 1;
                    let ms: u64 = args
                        .get(i)
                        .ok_or("Missing value for --coalesce-ms")?
                        .parse()
                        .map_err(|e| format!("Invalid --coalesce-ms value: {e}"))?;
                    coalesce_window = if ms > 0 { Some(Duration::from_millis(ms)) } else { None };
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
                        "Usage: wdttd [OPTIONS] --server-relayed <ADDR:PORT>\n\n\
                         Options:\n  \
                           --turn-server <ADDR:PORT>       TURN server address (default: 127.0.0.1:3478)\n  \
                           --turn-user <USER>              TURN username (default: user)\n  \
                           --turn-pass <PASS>              TURN password (default: pass)\n  \
                           --turn-realm <REALM>            TURN realm (default: coturn)\n  \
                           --server-relayed <ADDR:PORT>    Remote server relayed address on TURN (required)\n  \
                           --wg-listen <ADDR:PORT>         Local WireGuard listening port (default: 127.0.0.1:51821)\n  \
                           --psk <STRING>                  Pre-shared key for knock authentication\n  \
                           --keepalive <MODE>              Keepalive mode: powersave (default), chaff, disabled\n  \
                           --runtime <MODE>                Tokio runtime: multi_thread (default), current_thread\n  \
                           --workers <N>                   Worker threads for multi_thread runtime (default: 2)\n"
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
            keepalive_mode,
            coalesce_window,
            runtime,
            workers,
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = match ClientArgs::parse_from_env() {
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

async fn async_main(args: ClientArgs) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== WDTT v2 Client Daemon (Stage 3 Standalone) ===");
    info!("TURN relay server: {}", args.turn_server);
    info!("Server relayed target: {}", args.server_relayed);
    info!("WireGuard bridge listen port: {}", args.wg_listen);
    info!("Keepalive mode: {:?}", args.keepalive_mode);
    info!("Coalesce window: {:?}", args.coalesce_window);
    info!("Tokio runtime: {} (workers: {})", args.runtime, args.workers);

    let config = TunnelClientConfig {
        turn_server_addr: args.turn_server,
        turn_username: args.turn_username,
        turn_password: args.turn_password,
        turn_realm: args.turn_realm,
        server_relayed_addr: args.server_relayed,
        wg_listen_addr: args.wg_listen,
        psk: args.psk,
        keepalive_mode: args.keepalive_mode,
        coalesce_window: args.coalesce_window,
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
        "Final Metrics: TX packets={} bytes={} | RX packets={} bytes={} | batches single={} multi={} | pings tx={} rx={} | RTT={}ms",
        snap.packets_tx, snap.bytes_tx, snap.packets_rx, snap.bytes_rx,
        snap.batches_single, snap.batches_multi, snap.pings_tx, snap.pings_rx, snap.rtt_latest_ms
    );

    Ok(())
}
