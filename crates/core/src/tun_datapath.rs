//! Client-side TUN datapath: TUN device <-> WireGuard <-> tunnel transport.
//!
//! This module owns the packet plumbing that sits between a real TUN
//! interface and the WDTT transport. It is deliberately transport-agnostic:
//! the caller supplies two async closures, one that ships a WireGuard
//! datagram to the peer and one that yields the next inbound datagram.

use crate::tunnel::TunnelError;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tracing::{debug, info, trace, warn};
use wdtt_tun::{DATA_OVERHEAD_SZ, HANDSHAKE_INIT_SZ, TunDevice, WgEngine, WgOutput};

/// Largest IP packet the TUN side may hand us (MTU + IPv6 header slack).
const TUN_BUF_LEN: usize = 2048;
/// Largest WireGuard datagram we expect to receive.
const WG_BUF_LEN: usize = 2048;
/// How often the WireGuard timers are driven.
const TIMER_TICK: Duration = Duration::from_secs(1);

/// Boxed future returned by the transport closures.
pub type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Configuration for the TUN datapath.
#[derive(Debug, Clone)]
pub struct TunDatapathConfig {
    /// Interface name to create (e.g. `wdtt0`).
    pub tun_name: String,
    /// Interface MTU.
    pub tun_mtu: u16,
    /// WireGuard persistent keepalive in seconds, if any.
    pub persistent_keepalive: Option<u16>,
}

/// Run the TUN datapath until cancelled.
///
/// `send_wg` ships one WireGuard datagram to the peer. `recv_wg` yields the
/// next inbound datagram, or `None` when the transport closed.
pub async fn run_tun_datapath<F, R>(
    config: TunDatapathConfig,
    mut engine: WgEngine,
    mut send_wg: F,
    mut recv_wg: R,
    mut cancel_rx: watch::Receiver<bool>,
) -> Result<(), TunnelError>
where
    F: FnMut(Vec<u8>) -> BoxFut<'static, Result<(), TunnelError>>,
    R: FnMut() -> BoxFut<'static, Option<Vec<u8>>>,
{
    let tun_cfg = wdtt_tun::TunConfig {
        name: config.tun_name.clone(),
        mtu: config.tun_mtu,
    };
    let mut tun = TunDevice::open(&tun_cfg)?;
    info!("TUN interface {} up (mtu {})", tun.name(), tun.mtu());

    let mut tun_buf = vec![0u8; TUN_BUF_LEN];
    let mut wg_out = vec![0u8; WG_BUF_LEN];
    let mut timer = tokio::time::interval(TIMER_TICK);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Kick off the handshake immediately rather than waiting for first traffic.
    let init = engine.initiate_handshake(&mut wg_out)?;
    ship(init, &mut send_wg).await?;

    loop {
        tokio::select! {
            biased;

            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    info!("TUN datapath shutting down via cancel signal");
                    break;
                }
            }

            _ = timer.tick() => {
                let out = engine.update_timers(&mut wg_out)?;
                ship(out, &mut send_wg).await?;
            }

            read_res = tun.read(&mut tun_buf) => {
                match read_res {
                    Ok(0) => continue,
                    Ok(n) => {
                        trace!("TUN -> WG {n} bytes");
                        match engine.encapsulate(&tun_buf[..n], &mut wg_out) {
                            Ok(out) => ship(out, &mut send_wg).await?,
                            Err(e) => warn!("WG encapsulate failed: {e}"),
                        }
                    }
                    Err(e) => {
                        warn!("TUN read error: {e}");
                        break;
                    }
                }
            }

            datagram = recv_wg() => {
                let Some(datagram) = datagram else {
                    info!("Transport closed, stopping TUN datapath");
                    break;
                };
                let src: Option<IpAddr> = None;
                match engine.decapsulate(src, &datagram, &mut wg_out) {
                    Ok(out) => deliver(out, &mut tun, &mut send_wg).await?,
                    Err(e) => warn!("WG decapsulate failed: {e}"),
                }
                // Drain anything the engine queued while processing.
                loop {
                    match engine.decapsulate(None, &[], &mut wg_out) {
                        Ok(WgOutput::Done) => break,
                        Ok(out) => deliver(out, &mut tun, &mut send_wg).await?,
                        Err(e) => {
                            warn!("WG drain failed: {e}");
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Ship a datagram produced by the engine, if any.
async fn ship<F>(out: WgOutput<'_>, send_wg: &mut F) -> Result<(), TunnelError>
where
    F: FnMut(Vec<u8>) -> BoxFut<'static, Result<(), TunnelError>>,
{
    match out {
        WgOutput::Done | WgOutput::Tunnel(_) => Ok(()),
        WgOutput::Network(datagram) => {
            debug!("WG -> transport {} bytes", datagram.len());
            send_wg(datagram.to_vec()).await
        }
    }
}

/// Deliver an engine result, writing decrypted IP packets to the TUN device.
async fn deliver<F>(
    out: WgOutput<'_>,
    tun: &mut TunDevice,
    send_wg: &mut F,
) -> Result<(), TunnelError>
where
    F: FnMut(Vec<u8>) -> BoxFut<'static, Result<(), TunnelError>>,
{
    match out {
        WgOutput::Done => Ok(()),
        WgOutput::Network(datagram) => {
            debug!("WG -> transport {} bytes", datagram.len());
            send_wg(datagram.to_vec()).await
        }
        WgOutput::Tunnel(packet) => {
            debug!("WG -> TUN {} bytes", packet.len());
            tun.write_all(packet).await?;
            Ok(())
        }
    }
}

/// Minimum buffer size required by `WgEngine::encapsulate` for a given MTU.
pub const fn wg_output_len(mtu: u16) -> usize {
    let with_overhead = mtu as usize + DATA_OVERHEAD_SZ;
    if with_overhead > HANDSHAKE_INIT_SZ {
        with_overhead
    } else {
        HANDSHAKE_INIT_SZ
    }
}
