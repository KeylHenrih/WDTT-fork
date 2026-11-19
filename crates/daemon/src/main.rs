//! Standalone client console daemon for initiating WDTT v2 sessions over TURN.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};
use wdtt_core::tunnel::RefreshedCredentials;
use wdtt_core::{KeepaliveMode, TunnelClient, TunnelClientConfig, TurnTransportMode};
use wdtt_provider::{CaptchaMode, ProviderConfig, ProviderKind, TurnCredentials, build_provider};
#[cfg(target_os = "linux")]
use wdtt_tun::geo::download::{GeoDownloader, GeoFiles};
#[cfg(target_os = "linux")]
use wdtt_tun::setup::{self, HostSetup, HostSetupConfig};
#[cfg(target_os = "linux")]
use wdtt_tun::{Routing, RoutingTable};

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
    provider: Option<ProviderKind>,
    vk_hash: Option<String>,
    vk_cache_path: PathBuf,
    earliest_time_secs: u64,
    bind_iface: Option<String>,
    captcha_mode: CaptchaMode,
    ca_cert: Option<PathBuf>,
    tun_name: Option<String>,
    tun_mtu: u16,
    route_rules: Option<PathBuf>,
    geo_dir: Option<PathBuf>,
    route_tun_addr: Option<Ipv4Addr>,
    route_relay: Option<Ipv4Addr>,
    route_phys: Option<String>,
    route_gw: Option<Ipv4Addr>,
    no_kill_switch: bool,
    no_dns: bool,
    wg_private_key: Option<String>,
    wg_peer_public_key: Option<String>,
    wg_preshared_key: Option<String>,
    wg_keepalive: Option<u16>,
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
        let mut provider = None;
        let mut vk_hash = None;
        let default_cache = dirs_home().join(".config/wdtt-dev/vk_creds.json");
        let mut vk_cache_path = default_cache;
        let mut earliest_time_secs = std::env::var("WDTT_EARLIEST_TIME")
            .ok()
            .and_then(|t| t.parse().ok())
            .unwrap_or(DEFAULT_EARLIEST_VK_TIME);
        let mut bind_iface = None;
        let mut captcha_mode = CaptchaMode::Helper;
        let mut ca_cert: Option<PathBuf> = None;
        let mut tun_name: Option<String> = None;
        let mut tun_mtu: u16 = 1360;
        let mut route_rules: Option<PathBuf> = None;
        let mut geo_dir: Option<PathBuf> = None;
        let mut route_tun_addr: Option<Ipv4Addr> = None;
        let mut route_relay: Option<Ipv4Addr> = None;
        let mut route_phys: Option<String> = None;
        let mut route_gw: Option<Ipv4Addr> = None;
        let mut no_kill_switch = false;
        let mut no_dns = false;
        let mut wg_private_key: Option<String> = None;
        let mut wg_peer_public_key: Option<String> = None;
        let mut wg_preshared_key: Option<String> = None;
        let mut wg_keepalive: Option<u16> = None;

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
                    psk = wdtt_crypto::Psk::parse(val)
                        .map_err(|e| format!("Invalid --psk: {e}"))?
                        .as_bytes()
                        .to_owned();
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
                "--provider" => {
                    i += 1;
                    let val = args.get(i).ok_or("Missing value for --provider")?;
                    provider = Some(ProviderKind::from_name(val).ok_or_else(|| {
                        format!(
                            "Unknown provider '{val}', expected: {}",
                            ProviderKind::all_names().join(", ")
                        )
                    })?);
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
                "--ca" => {
                    i += 1;
                    ca_cert = Some(PathBuf::from(args.get(i).ok_or("Missing value for --ca")?));
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
                "--tun" => {
                    i += 1;
                    tun_name = Some(args.get(i).ok_or("Missing value for --tun")?.clone());
                }
                "--tun-mtu" => {
                    i += 1;
                    tun_mtu = args
                        .get(i)
                        .ok_or("Missing value for --tun-mtu")?
                        .parse()
                        .map_err(|e| format!("Invalid --tun-mtu: {e}"))?;
                }
                "--route-rules" => {
                    i += 1;
                    route_rules = Some(PathBuf::from(
                        args.get(i).ok_or("Missing value for --route-rules")?,
                    ));
                }
                "--geo-dir" => {
                    i += 1;
                    geo_dir = Some(PathBuf::from(
                        args.get(i).ok_or("Missing value for --geo-dir")?,
                    ));
                }
                "--route-tun-addr" => {
                    i += 1;
                    route_tun_addr = Some(
                        args.get(i)
                            .ok_or("Missing value for --route-tun-addr")?
                            .parse()
                            .map_err(|e| format!("Invalid --route-tun-addr: {e}"))?,
                    );
                }
                "--route-relay" => {
                    i += 1;
                    route_relay = Some(
                        args.get(i)
                            .ok_or("Missing value for --route-relay")?
                            .parse()
                            .map_err(|e| format!("Invalid --route-relay: {e}"))?,
                    );
                }
                "--route-phys" => {
                    i += 1;
                    route_phys = Some(args.get(i).ok_or("Missing value for --route-phys")?.clone());
                }
                "--route-gw" => {
                    i += 1;
                    route_gw = Some(
                        args.get(i)
                            .ok_or("Missing value for --route-gw")?
                            .parse()
                            .map_err(|e| format!("Invalid --route-gw: {e}"))?,
                    );
                }
                "--no-kill-switch" => {
                    no_kill_switch = true;
                }
                "--no-dns" => {
                    no_dns = true;
                }
                "--wg-private-key" => {
                    i += 1;
                    wg_private_key = Some(read_key_arg(
                        args.get(i).ok_or("Missing value for --wg-private-key")?,
                    )?);
                }
                "--wg-peer-key" => {
                    i += 1;
                    wg_peer_public_key = Some(read_key_arg(
                        args.get(i).ok_or("Missing value for --wg-peer-key")?,
                    )?);
                }
                "--wg-psk" => {
                    i += 1;
                    wg_preshared_key = Some(read_key_arg(
                        args.get(i).ok_or("Missing value for --wg-psk")?,
                    )?);
                }
                "--wg-keepalive" => {
                    i += 1;
                    wg_keepalive = Some(
                        args.get(i)
                            .ok_or("Missing value for --wg-keepalive")?
                            .parse()
                            .map_err(|e| format!("Invalid --wg-keepalive: {e}"))?,
                    );
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
                           --ca <PATH>                     Custom CA certificate (DER) for TLS verification\n  \
                           --tun <NAME>                    Create a TUN interface and run WireGuard in-process\n  \
                           --tun-mtu <N>                   TUN interface MTU (default: 1360)\n  \
                           --route-rules <PATH>            Xray-format routing rules (JSON) to apply\n  \
                           --geo-dir <PATH>                Directory for cached geoip.dat / geosite.dat\n  \
                           --route-tun-addr <ADDR>         Address to assign to the TUN interface\n  \
                           --route-relay <ADDR>            TURN relay address (bypass route target)\n  \
                           --route-phys <IFACE>            Physical interface carrying relay traffic\n  \
                           --route-gw <ADDR>               Physical gateway for the relay bypass route\n  \
                           --no-kill-switch                Do not install the kill-switch\n  \
                           --no-dns                        Do not switch the system resolver\n  \
                           --wg-private-key <KEY|PATH>     Local WireGuard private key (base64 or file)\n  \
                           --wg-peer-key <KEY|PATH>        Peer WireGuard public key (base64 or file)\n  \
                           --wg-psk <KEY|PATH>             Optional WireGuard preshared key\n  \
                           --wg-keepalive <SECS>           WireGuard persistent keepalive interval\n  \
                           --bind-iface <IFACE>            Bind outbound sockets to a network interface\n  \
                           --server-relayed <ADDR:PORT>    Remote server relayed address on TURN (required)\n  \
                           --wg-listen <ADDR:PORT>         Local WireGuard listening port (default: 127.0.0.1:51821)\n  \
                           --psk <HEX>                     Pre-shared key: 64 hex chars (or raw 32-byte string)\n  \
                           --keepalive <MODE>              Keepalive mode: powersave (default), chaff, disabled\n  \
                           --coalesce-ms <MS>              Coalesce window for outbound datagrams (0 = off)\n  \
                           --profile <NAME>                Keepalive profile: powersave (default), performance, chaff\n  \
                           --provider <NAME>               Credential provider: vk, static (inferred if omitted)\n  \
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
            provider,
            vk_hash,
            vk_cache_path,
            earliest_time_secs,
            bind_iface,
            captcha_mode,
            ca_cert,
            tun_name,
            tun_mtu,
            route_rules,
            geo_dir,
            route_tun_addr,
            route_relay,
            route_phys,
            route_gw,
            no_kill_switch,
            no_dns,
            wg_private_key,
            wg_peer_public_key,
            wg_preshared_key,
            wg_keepalive,
        })
    }
}

/// Read a key argument: either the literal base64 value or a path to a file.
fn read_key_arg(val: &str) -> Result<String, String> {
    let path = std::path::Path::new(val);
    if path.is_file() {
        std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("Failed to read key file {val}: {e}"))
    } else {
        Ok(val.trim().to_string())
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

    // Resolve which provider to use. An explicit `--provider` wins; otherwise
    // a VK call link implies the VK provider, and a plain relay address
    // implies static credentials.
    let kind = match args.provider {
        Some(kind) => Some(kind),
        None if args.vk_hash.is_some() => Some(ProviderKind::Vk),
        None if args.turn_server.is_some() || args.turn_domain.is_some() => {
            Some(ProviderKind::Static)
        }
        None => None,
    };

    // Kept alive past the credential block so a refresher closure can be
    // handed to the tunnel client for runtime re-acquisition.
    let mut live_provider: Option<std::sync::Arc<dyn wdtt_provider::TurnProvider>> = None;
    let mut credentials_expire_at: u64 = 0;

    if let Some(kind) = kind {
        let config = ProviderConfig {
            kind: Some(kind),
            vk_hash: args.vk_hash.clone(),
            vk_cache_path: Some(args.vk_cache_path.clone()),
            earliest_time_secs: Some(args.earliest_time_secs),
            captcha_mode: Some(args.captcha_mode),
            bind_interface: args.bind_iface.clone(),
            static_credentials: Some(TurnCredentials {
                username: args.turn_username.clone(),
                password: args.turn_password.clone(),
                host: args
                    .turn_server
                    .map(|a| a.ip().to_string())
                    .or_else(|| args.turn_domain.as_ref().map(|(h, _)| h.clone()))
                    .unwrap_or_default(),
                port: args
                    .turn_server
                    .map(|a| a.port())
                    .or_else(|| args.turn_domain.as_ref().map(|(_, p)| *p))
                    .unwrap_or(3478),
                realm: args.turn_realm.clone(),
                use_udp: args.turn_transport == TurnTransportMode::Udp,
                expires_at: 0,
            }),
        };

        let provider: std::sync::Arc<dyn wdtt_provider::TurnProvider> =
            std::sync::Arc::from(build_provider(&config)?);
        info!(
            "Acquiring TURN credentials via the {} provider...",
            kind.name()
        );
        let creds = provider.acquire_credentials().await?;

        credentials_expire_at = creds.expires_at;
        live_provider = Some(provider);

        args.turn_username = creds.username;
        args.turn_password = creds.password;
        args.turn_realm = creds.realm;
        // Only a provider that hands back a hostname may set the SNI. The
        // static provider echoes whatever relay address the user passed, which
        // is usually an IP literal; overwriting an explicit `--sni` with it
        // breaks the TLS handshake against a listener that needs a real name.
        if kind == ProviderKind::Vk || creds.host.parse::<std::net::IpAddr>().is_err() {
            args.turn_sni = Some(creds.host.clone());
        }
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
        info!("Resolved TURN server {} -> {resolved}", creds.host);

        if kind == ProviderKind::Vk {
            // Check UDP reachability to VK TURN (port 3478)
            check_vk_turn_udp(&creds.host, args.bind_iface.as_deref()).await;
        }
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

    // Stage 3.6: the host-side configuration is applied after the TUN device
    // exists, which happens inside the client task. See below. The fields it
    // needs are captured here because building the config below moves `args`.
    #[cfg(target_os = "linux")]
    let setup_args = SetupArgs {
        tun_name: args.tun_name.clone(),
        route_rules: args.route_rules.clone(),
        geo_dir: args.geo_dir.clone(),
        route_tun_addr: args.route_tun_addr,
        route_relay: args.route_relay,
        route_phys: args.route_phys.clone(),
        route_gw: args.route_gw,
        no_kill_switch: args.no_kill_switch,
        no_dns: args.no_dns,
    };

    let credential_refresher: Option<wdtt_core::tunnel::CredentialRefresher> =
        live_provider.map(|provider| {
            let bind_iface = args.bind_iface.clone();
            let transport = args.turn_transport;
            let sni_override = args.turn_sni.clone();
            wdtt_core::tunnel::CredentialRefresher::new(std::sync::Arc::new(move || {
                let provider = provider.clone();
                let bind_iface = bind_iface.clone();
                let sni_override = sni_override.clone();
                Box::pin(async move {
                    let creds = provider
                        .acquire_credentials()
                        .await
                        .map_err(|e| format!("credential refresh failed: {e}"))?;
                    resolve_refreshed_credentials(creds, transport, sni_override, bind_iface).await
                })
            }))
        });

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
        custom_ca_der: match args.ca_cert {
            Some(ref path) => Some(
                std::fs::read(path)
                    .map_err(|e| format!("Failed to read CA certificate {path:?}: {e}"))?,
            ),
            None => None,
        },
        bind_interface: args.bind_iface,
        tun_name: args.tun_name,
        tun_mtu: args.tun_mtu,
        wg_private_key: args.wg_private_key,
        wg_peer_public_key: args.wg_peer_public_key,
        wg_preshared_key: args.wg_preshared_key,
        wg_keepalive: args.wg_keepalive,
        credential_refresher,
        credentials_expire_at,
    };

    let mut client = TunnelClient::new(config);
    let metrics = client.metrics();

    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    let client_task =
        tokio::spawn(async move { client.run_with_notify(cancel_rx, Some(ready_tx)).await });

    // -----------------------------------
    // IPC server (Unix socket) – handles IpcRequest from GUI apps.
    // Only GetStatus is fully supported for now.
    // -----------------------------------
    #[cfg(target_os = "linux")]
    spawn_ipc_server("/tmp/wdttd.ipc", metrics.clone(), cancel_tx.clone());

    #[cfg(target_os = "linux")]
    fn spawn_ipc_server(
        listen_addr: &str,
        metrics: std::sync::Arc<wdtt_core::metrics::TunnelMetrics>,
        cancel_tx: watch::Sender<bool>,
    ) {
        use tokio::net::UnixListener;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use wdtt_ipc::{IpcRequest, IpcResponse};
        let _ = std::fs::remove_file(listen_addr);
        let Ok(listener) = UnixListener::bind(listen_addr) else {
            warn!("Failed to bind IPC socket {listen_addr} — IPC disabled");
            return;
        };
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("IPC accept error: {e}");
                        break;
                    }
                };
                let mut buf = vec![0u8; 4096];
                let n = match stream.read(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(e) => {
                        warn!("IPC read error: {e}");
                        continue;
                    }
                };
                let req: IpcRequest = match postcard::from_bytes(&buf[..n]) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("IPC deserialize error: {e}");
                        continue;
                    }
                };
                let resp = match req {
                    IpcRequest::GetStatus => {
                        let snap = metrics.snapshot();
                        IpcResponse::Status {
                            connected: true,
                            tx_bytes_per_sec: snap.bytes_tx,
                            rx_bytes_per_sec: snap.bytes_rx,
                            rtt_ms: snap.rtt_latest_ms as u32,
                        }
                    }
                    IpcRequest::Connect { config_uri: _ } => {
                        IpcResponse::Error("Connect via IPC not implemented".into())
                    }
                    IpcRequest::Disconnect => {
                        let _ = cancel_tx.send(true);
                        IpcResponse::Ok
                    }
                };
                let out = match postcard::to_allocvec(&resp) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("IPC serialize error: {e}");
                        continue;
                    }
                };
                if let Err(e) = stream.write_all(&out).await {
                    warn!("IPC write error: {e}");
                }
            }
        });
    }
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

    // Stage 3.6: the TUN device is created inside the client task, so the
    // host-side configuration can only be applied once it exists.
    #[cfg(target_os = "linux")]
    let mut host_setup = match prepare_host_setup(&setup_args, turn_server).await {
        Ok(setup) => setup,
        Err(err) => {
            error!("{err}");
            let _ = cancel_tx.send(true);
            return Err(err.into());
        }
    };

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

    // Undo the host-side configuration in reverse order.
    #[cfg(target_os = "linux")]
    if let Some(ref mut setup) = host_setup {
        info!("Restoring host network configuration...");
        setup.teardown().await;
        info!("Host network configuration restored");
    }

    Ok(())
}

/// Waits until a network interface exists and is reachable through the ioctl
/// path, up to a few seconds.
///
/// `if_nametoindex` alone is not enough: it resolves through `/sys`, which can
/// report a device the kernel has already torn down. The ioctl path is what
/// the setup actually uses, so it is what we wait for.
#[cfg(target_os = "linux")]
async fn wait_for_interface(name: &str) -> Result<(), String> {
    for _ in 0..50 {
        if wdtt_tun::netcfg::interface_is_live(name) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!("Interface {name} did not appear within 5 seconds"))
}

/// Builds and applies the host-side tunnel configuration.
///
/// Parses a routing section from either a bare object or a full Xray config.
///
/// A bare `Routing` object is accepted directly. A full Xray config, which
/// wraps the section in a top-level `"routing"` key, is unwrapped first, so an
/// existing Xray configuration file can be pointed at with `--route-rules`
/// without editing.
#[cfg(target_os = "linux")]
fn parse_routing(raw: &str) -> Result<Routing, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let section = match value.get("routing") {
        Some(inner) => inner.clone(),
        None => value,
    };
    serde_json::from_value(section)
}

/// The subset of client arguments the host setup needs.
///
/// Captured before the tunnel config is built, because building it moves the
/// original argument struct.
#[cfg(target_os = "linux")]
struct SetupArgs {
    tun_name: Option<String>,
    route_rules: Option<PathBuf>,
    geo_dir: Option<PathBuf>,
    route_tun_addr: Option<Ipv4Addr>,
    route_relay: Option<Ipv4Addr>,
    route_phys: Option<String>,
    route_gw: Option<Ipv4Addr>,
    no_kill_switch: bool,
    no_dns: bool,
}

/// Returns `None` when the daemon was not asked to manage routing (no
/// `--route-rules` and no `--tun`), so a plain bridge run is unaffected.
#[cfg(target_os = "linux")]
async fn prepare_host_setup(
    args: &SetupArgs,
    turn_server: SocketAddr,
) -> Result<Option<HostSetup>, String> {
    let Some(ref tun_name) = args.tun_name else {
        return Ok(None);
    };

    // Without an explicit address there is nothing to configure; the caller is
    // expected to set the interface up by hand, as before.
    let Some(tun_addr) = args.route_tun_addr else {
        if args.route_rules.is_some() {
            return Err("--route-rules requires --route-tun-addr".into());
        }
        return Ok(None);
    };

    let relay = args.route_relay.unwrap_or_else(|| {
        turn_server
            .ip()
            .to_string()
            .parse()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    });
    let phys = args
        .route_phys
        .clone()
        .ok_or("--route-tun-addr requires --route-phys <IFACE>")?;

    let mut cfg = HostSetupConfig::new(tun_name.clone(), tun_addr, relay, phys);
    cfg.physical_gateway = args.route_gw;
    cfg.kill_switch = !args.no_kill_switch;
    cfg.dns = !args.no_dns;

    // Compile the routing rules, if any were given.
    if let Some(ref rules_path) = args.route_rules {
        let raw = std::fs::read_to_string(rules_path)
            .map_err(|e| format!("Failed to read routing rules {rules_path:?}: {e}"))?;
        let routing = parse_routing(&raw)
            .map_err(|e| format!("Failed to parse routing rules {rules_path:?}: {e}"))?;

        let geo_dir = args
            .geo_dir
            .clone()
            .unwrap_or_else(setup::default_cache_dir);
        let downloader = GeoDownloader::new(GeoFiles::under(&geo_dir));
        let geo = downloader
            .load()
            .await
            .map_err(|e| format!("Failed to load geo data from {geo_dir:?}: {e}"))?;
        info!(
            "Geo data loaded: {} ip categories, {} domain categories",
            geo.ip_categories().len(),
            geo.domain_categories().len()
        );

        let table = RoutingTable::compile(&routing, &geo)
            .map_err(|e| format!("Failed to compile routing rules: {e}"))?;
        info!("Compiled {} routing rules", table.rules().len());

        let resolver_cfg = wdtt_tun::resolver::ResolverConfig {
            cache_path: Some(wdtt_tun::resolver::default_cache_path(&geo_dir)),
            ..Default::default()
        };
        let (ruleset, _addresses) = setup::prepare_ruleset(&table, resolver_cfg).await;
        for approx in &ruleset.approximations {
            warn!("Rule {} is approximated: {}", approx.index, approx.detail);
        }
        info!("Compiled {} mark rules", ruleset.rules.len());
        cfg.ruleset = ruleset;
    }

    // The TUN device is created by the client task; wait briefly for it to
    // appear before touching it, since the notify fires before the device is
    // necessarily visible to the kernel.
    wait_for_interface(tun_name).await?;

    let mut setup = HostSetup::new(cfg);
    setup
        .apply()
        .await
        .map_err(|e| format!("Failed to configure host networking: {e}"))?;
    info!(
        "Host networking configured: address, policy routing, {} mark rules, dns={}, kill-switch={}",
        setup.config().ruleset.rules.len(),
        setup.config().dns,
        setup.config().kill_switch
    );
    Ok(Some(setup))
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

/// Converts provider credentials into the tunnel's refresh shape, resolving
/// the relay hostname and applying the same SNI and port rules used at startup.
///
/// A TURN credential refresh returns a hostname, not a socket address, and VK
/// hands back the relay host as a name that must also become the TLS SNI. The
/// port is remapped from the 3478 default to 443 when the stream transport
/// requires TLS, mirroring the startup path so a refreshed tunnel connects the
/// same way the original one did.
async fn resolve_refreshed_credentials(
    creds: TurnCredentials,
    transport: TurnTransportMode,
    sni_override: Option<String>,
    _bind_iface: Option<String>,
) -> Result<RefreshedCredentials, String> {
    let host_is_ip = creds.host.parse::<std::net::IpAddr>().is_ok();
    let sni = if host_is_ip {
        sni_override
    } else {
        Some(creds.host.clone())
    };

    let port = if matches!(transport, TurnTransportMode::Tls | TurnTransportMode::Tcp)
        && creds.port == 3478
    {
        443
    } else {
        creds.port
    };

    let server_addr = tokio::net::lookup_host(format!("{}:{}", creds.host, port))
        .await
        .map_err(|e| format!("Failed to resolve TURN host {}: {e}", creds.host))?
        .next()
        .ok_or_else(|| format!("No IP addresses found for TURN host {}", creds.host))?;

    Ok(RefreshedCredentials {
        username: creds.username,
        password: creds.password,
        realm: creds.realm,
        server_addr,
        sni,
        expires_at: creds.expires_at,
    })
}
