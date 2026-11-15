//! Standalone client console daemon for initiating WDTT v2 sessions over TURN.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};
use wdtt_core::{KeepaliveMode, TunnelClient, TunnelClientConfig, TurnTransportMode};
use wdtt_provider::{CaptchaMode, TurnProvider, VkTurnProvider};

const DEFAULT_EARLIEST_VK_TIME: u64 = 1794734520; // 15:22:00 +06:00

struct ClientArgs {
    turn_server: Option<SocketAddr>,
    turn_domain: Option<(String, u16)>,
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
    turn_transport: TurnTransportMode,
    turn_sni: Option<String>,
    vk_hash: Option<String>,
    vk_cache_path: PathBuf,
    earliest_time_secs: u64,
    bind_iface: Option<String>,
    captcha_mode: CaptchaMode,
}

impl ClientArgs {
    fn parse_from_env() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().collect();
        let mut turn_server = None;
        let mut turn_domain = None;
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
        let mut turn_transport = TurnTransportMode::Udp;
        let mut turn_sni = None;
        let mut vk_hash = None;
        let default_cache = dirs_home().join(".config/wdtt-dev/vk_creds.json");
        let mut vk_cache_path = default_cache;
        let mut earliest_time_secs = std::env::var("WDTT_EARLIEST_TIME")
            .ok()
            .and_then(|t| t.parse().ok())
            .unwrap_or(DEFAULT_EARLIEST_VK_TIME);
        let mut bind_iface = None;
        let mut captcha_mode = CaptchaMode::Helper;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--turn-server" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --turn-server")?;
                    if let Ok(addr) = val.parse::<SocketAddr>() {
                        turn_server = Some(addr);
                    } else if let Some((h, p)) = val.rsplit_once(':') {
                        let port = p
                            .parse::<u16>()
                            .map_err(|e| format!("Invalid port in --turn-server: {e}"))?;
                        turn_domain = Some((h.to_string(), port));
                        if turn_sni.is_none() {
                            turn_sni = Some(h.to_string());
                        }
                    } else {
                        return Err(format!(
                            "Invalid --turn-server format, expected host:port: {val}"
                        ));
                    }
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
                "--vk-hash" => {
                    i += 1;
                    vk_hash = Some(args.get(i).ok_or("Missing value for --vk-hash")?.clone());
                }
                "--vk-link" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --vk-link")?;
                    let content = if std::path::Path::new(val).exists() {
                        std::fs::read_to_string(val)
                            .map_err(|e| format!("Failed to read vk link file {val}: {e}"))?
                    } else {
                        val.clone()
                    };
                    // Extract hash from qwdtt link (hashes=...) or direct join link
                    if let Some(pos) = content.find("hashes=") {
                        let sub = &content[(pos + 7)..];
                        let end = sub.find('&').unwrap_or(sub.len());
                        let first_hash = sub[..end].split(',').next().unwrap_or("").trim();
                        if !first_hash.is_empty() {
                            vk_hash = Some(first_hash.to_string());
                        }
                    } else if let Some(pos) = content.rfind("/join/") {
                        let sub = &content[(pos + 6)..];
                        let end = sub.find('&').or_else(|| sub.find('?')).unwrap_or(sub.len());
                        vk_hash = Some(sub[..end].trim().to_string());
                    } else {
                        vk_hash = Some(content.trim().to_string());
                    }
                }
                "--vk-cache" => {
                    i += 1;
                    vk_cache_path =
                        PathBuf::from(args.get(i).ok_or("Missing value for --vk-cache")?);
                }
                "--earliest-time" => {
                    i += 1;
                    earliest_time_secs = args
                        .get(i)
                        .ok_or("Missing value for --earliest-time")?
                        .parse()
                        .map_err(|e| format!("Invalid --earliest-time epoch: {e}"))?;
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
                        other => {
                            return Err(format!(
                                "Unknown keepalive mode '{other}', expected: powersave, chaff, disabled"
                            ));
                        }
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
                        other => {
                            return Err(format!(
                                "Unknown profile '{other}', expected: powersave, performance, chaff"
                            ));
                        }
                    }
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
                "--transport" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --transport")?;
                    turn_transport = match val.to_lowercase().as_str() {
                        "udp" => TurnTransportMode::Udp,
                        "tcp" => TurnTransportMode::Tcp,
                        "tls" => TurnTransportMode::Tls,
                        "auto" => TurnTransportMode::Auto,
                        other => {
                            return Err(format!(
                                "Unknown transport '{other}', expected: udp, tcp, tls, auto"
                            ));
                        }
                    };
                }
                "--sni" => {
                    i += 1;
                    turn_sni = Some(args.get(i).ok_or("Missing value for --sni")?.clone());
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
                "--bind-iface" => {
                    i += 1;
                    bind_iface = Some(args.get(i).ok_or("Missing value for --bind-iface")?.clone());
                }
                "--captcha-mode" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --captcha-mode")?;
                    captcha_mode = match val.to_lowercase().as_str() {
                        "manual" => CaptchaMode::Manual,
                        _ => CaptchaMode::Helper,
                    };
                }
                "-h" | "--help" => {
                    println!(
                        "Usage: wdttd [OPTIONS] --server-relayed <ADDR:PORT>\n\n\
                         Options:\n  \
                           --turn-server <ADDR:PORT>       TURN server address (default: 127.0.0.1:3478)\n  \
                           --turn-user <USER>              TURN username (default: user)\n  \
                           --turn-pass <PASS>              TURN password (default: pass)\n  \
                           --turn-realm <REALM>            TURN realm (default: coturn)\n  \
                           --transport <MODE>              TURN transport: udp (default), tcp, tls, auto\n  \
                           --sni <HOST>                    SNI hostname for TLS verification\n  \
                           --bind-iface <IFACE>            Bind outbound sockets to a network interface\n  \
                           --server-relayed <ADDR:PORT>    Remote server relayed address on TURN (required)\n  \
                           --wg-listen <ADDR:PORT>         Local WireGuard listening port (default: 127.0.0.1:51821)\n  \
                           --psk <STRING>                  Pre-shared key for knock authentication\n  \
                           --keepalive <MODE>              Keepalive mode: powersave (default), chaff, disabled\n  \
                           --coalesce-ms <MS>              Coalesce window for outbound datagrams (0 = off)\n  \
                           --profile <NAME>                Provider profile (default: vk)\n  \
                           --vk-hash <HASH>                VK call hash (alternative to --vk-link)\n  \
                           --vk-link <URL>                 VK call join link\n  \
                           --vk-cache <PATH>               Path to the VK credential cache file\n  \
                           --earliest-time <EPOCH>         Earliest acceptable VK credential timestamp\n  \
                           --captcha-mode <MODE>           Captcha solving: manual (default), auto, disabled\n  \
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
            turn_domain,
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
            turn_transport,
            turn_sni,
            vk_hash,
            vk_cache_path,
            earliest_time_secs,
            bind_iface,
            captcha_mode,
        })
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

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

async fn async_main(mut args: ClientArgs) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== WDTT v2 Client Daemon (Stage 5 VK/TURN M2) ===");

    // If VK Hash or Link is configured, acquire TURN credentials via VkTurnProvider
    if let Some(ref hash) = args.vk_hash {
        info!("Initializing VK Calls TURN credential provider (hash: {hash})...");
        let provider =
            VkTurnProvider::new(hash, args.vk_cache_path.clone(), args.earliest_time_secs)
                .with_bind_interface(args.bind_iface.clone())
                .with_captcha_mode(args.captcha_mode);
        let creds = provider.acquire_credentials().await?;

        args.turn_username = creds.username;
        args.turn_password = creds.password;
        args.turn_realm = creds.realm;
        args.turn_sni = Some(creds.host.clone());
        if args.turn_transport == TurnTransportMode::Udp && !creds.use_udp {
            args.turn_transport = TurnTransportMode::Tls;
        }

        let port = if (args.turn_transport == TurnTransportMode::Tls
            || args.turn_transport == TurnTransportMode::Tcp)
            && creds.port == 3478
        {
            443
        } else {
            creds.port
        };

        let resolved = tokio::net::lookup_host(format!("{}:{}", creds.host, port))
            .await
            .map_err(|e| format!("Failed to resolve TURN host {}: {e}", creds.host))?
            .next()
            .ok_or_else(|| format!("No IP addresses found for TURN host {}", creds.host))?;

        args.turn_server = Some(resolved);
        info!("Resolved VK TURN server {} -> {resolved}", creds.host);

        // Check UDP reachability to VK TURN (port 3478)
        check_vk_turn_udp(&creds.host, args.bind_iface.as_deref()).await;
    } else if let Some((ref domain, port)) = args.turn_domain
        && args.turn_server.is_none()
    {
        let resolved = tokio::net::lookup_host(format!("{domain}:{port}"))
            .await
            .map_err(|e| format!("Failed to resolve TURN host {domain}: {e}"))?
            .next()
            .ok_or_else(|| format!("No IP addresses found for TURN host {domain}"))?;
        args.turn_server = Some(resolved);
        info!("Resolved TURN domain {domain} -> {resolved}");
    }

    let turn_server = args
        .turn_server
        .unwrap_or_else(|| "127.0.0.1:3478".parse().unwrap());

    info!("TURN relay server: {}", turn_server);
    info!("Server relayed target: {}", args.server_relayed);
    info!("WireGuard bridge listen port: {}", args.wg_listen);
    info!("Keepalive mode: {:?}", args.keepalive_mode);
    info!("Coalesce window: {:?}", args.coalesce_window);
    info!("TURN transport: {:?}", args.turn_transport);
    if let Some(ref sni) = args.turn_sni {
        info!("TLS SNI: {}", sni);
    }
    info!(
        "Tokio runtime: {} (workers: {})",
        args.runtime, args.workers
    );

    let config = TunnelClientConfig {
        turn_server_addr: turn_server,
        turn_username: args.turn_username,
        turn_password: args.turn_password,
        turn_realm: args.turn_realm,
        server_relayed_addr: args.server_relayed,
        wg_listen_addr: args.wg_listen,
        psk: args.psk,
        keepalive_mode: args.keepalive_mode,
        coalesce_window: args.coalesce_window,
        turn_transport: args.turn_transport,
        turn_sni: args.turn_sni,
        custom_ca_der: None,
        bind_interface: args.bind_iface,
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
        snap.packets_tx,
        snap.bytes_tx,
        snap.packets_rx,
        snap.bytes_rx,
        snap.batches_single,
        snap.batches_multi,
        snap.pings_tx,
        snap.pings_rx,
        snap.rtt_latest_ms
    );

    Ok(())
}

async fn check_vk_turn_udp(host: &str, bind_iface: Option<&str>) {
    info!("Testing UDP reachability to VK TURN server {host}:3478 (bind_iface: {bind_iface:?})...");
    let Ok(mut addrs) = tokio::net::lookup_host(format!("{host}:3478")).await else {
        warn!("Failed to resolve UDP endpoint {host}:3478");
        return;
    };
    let Some(udp_addr) = addrs.next() else {
        warn!("No IP for UDP endpoint {host}:3478");
        return;
    };

    let sock2 = match socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to create UDP socket for STUN check: {e}");
            return;
        }
    };

    #[cfg(target_os = "linux")]
    if let Some(iface) = bind_iface
        && let Err(e) = sock2.bind_device(Some(iface.as_bytes()))
    {
        warn!("Failed to bind UDP socket to interface {iface}: {e}");
        return;
    }
    let _ = sock2.set_nonblocking(true);
    let _ = sock2.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into());
    let Ok(sock) = tokio::net::UdpSocket::from_std(sock2.into()) else {
        warn!("Failed to convert std UDP socket to tokio");
        return;
    };

    // Standard STUN Binding Request (RFC 5389): 20 bytes
    let mut req = [0u8; 20];
    req[0] = 0x00;
    req[1] = 0x01; // Binding Request
    req[2] = 0x00;
    req[3] = 0x00; // Message Length = 0
    req[4] = 0x21;
    req[5] = 0x12;
    req[6] = 0xa4;
    req[7] = 0x42; // Magic Cookie
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let bytes = nanos.to_le_bytes();
    req[8..20].copy_from_slice(&bytes[..12]);

    if let Err(e) = sock.send_to(&req, udp_addr).await {
        warn!("Failed to send STUN Binding Request to {udp_addr}: {e}");
        return;
    }

    let mut resp = [0u8; 512];
    let res = tokio::time::timeout(Duration::from_millis(1500), sock.recv_from(&mut resp)).await;
    match res {
        Ok(Ok((len, src))) => {
            if len >= 20 && resp[0] == 0x01 && resp[1] == 0x01 {
                info!(
                    "VK TURN UDP reachability: SUCCESS (STUN Binding Response from {src}, {len} bytes). UDP is OPEN and usable."
                );
            } else {
                info!("VK TURN UDP reachability: received {len} bytes from {src}.");
            }
        }
        Ok(Err(e)) => {
            warn!("VK TURN UDP socket receive error: {e}");
        }
        Err(_) => {
            info!(
                "VK TURN UDP reachability: TIMEOUT (1500ms) to {udp_addr}. UDP is blocked/filtered by ISP or NAT."
            );
        }
    }
}
