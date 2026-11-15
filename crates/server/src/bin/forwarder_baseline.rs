//! Minimal raw UDP forwarder baseline for measuring the absolute cost floor of the networking stack.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  forwarder-baseline forward <LISTEN> <TARGET> [current_thread|multi_thread]");
        eprintln!("  forwarder-baseline sink <LISTEN>");
        eprintln!("  forwarder-baseline gen <TARGET> <RATE_PPS> <DURATION_SEC>");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "forward" => {
            if args.len() < 4 {
                eprintln!("Usage: forwarder-baseline forward <LISTEN> <TARGET> [current_thread|multi_thread]");
                std::process::exit(1);
            }
            let listen_addr: SocketAddr = args[2].parse()?;
            let target_addr: SocketAddr = args[3].parse()?;
            let runtime = args.get(4).map(|s| s.as_str()).unwrap_or("current_thread");

            let rt = if runtime == "current_thread" {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
            } else {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?
            };

            rt.block_on(async move {
                let sock = UdpSocket::bind(listen_addr).await?;
                let mut buf = [0u8; 2048];
                loop {
                    let (len, _src) = sock.recv_from(&mut buf).await?;
                    let _ = sock.send_to(&buf[..len], target_addr).await?;
                }
            })
        }
        "forward-asyncfd" => {
            if args.len() < 4 {
                eprintln!("Usage: forwarder-baseline forward-asyncfd <LISTEN> <TARGET> [current_thread|multi_thread]");
                std::process::exit(1);
            }
            let listen_addr: SocketAddr = args[2].parse()?;
            let target_addr: SocketAddr = args[3].parse()?;
            let runtime = args.get(4).map(|s| s.as_str()).unwrap_or("current_thread");

            let rt = if runtime == "current_thread" {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
            } else {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?
            };

            rt.block_on(async move {
                let std_sock = std::net::UdpSocket::bind(listen_addr)?;
                std_sock.set_nonblocking(true)?;
                #[allow(deprecated)]
                let async_fd = tokio::io::unix::AsyncFd::with_interest(std_sock, tokio::io::Interest::READABLE)?;
                let mut buf = [0u8; 2048];
                loop {
                    let mut guard = async_fd.readable().await?;
                    match guard.try_io(|inner| inner.get_ref().recv_from(&mut buf)) {
                        Ok(Ok((len, _src))) => {
                            let _ = async_fd.get_ref().send_to(&buf[..len], target_addr);
                        }
                        Ok(Err(e)) => return Err(e.into()),
                        Err(_would_block) => continue,
                    }
                }
            })
        }
        "sink" => {
            if args.len() < 3 {
                eprintln!("Usage: forwarder-baseline sink <LISTEN>");
                std::process::exit(1);
            }
            let listen_addr: SocketAddr = args[2].parse()?;
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                let sock = UdpSocket::bind(listen_addr).await?;
                let mut buf = [0u8; 2048];
                let mut count = 0u64;
                let mut bytes = 0u64;
                let start = Instant::now();
                loop {
                    let (len, _) = sock.recv_from(&mut buf).await?;
                    count += 1;
                    bytes += len as u64;
                    if count % 2000 == 0 {
                        let elapsed = start.elapsed().as_secs_f64();
                        let pps = count as f64 / elapsed;
                        let mbps = (bytes * 8) as f64 / (elapsed * 1e6);
                        eprintln!("Sink: received {count} pkts ({pps:.1} pps, {mbps:.2} Mbps)");
                    }
                }
            })
        }
        "gen" => {
            if args.len() < 5 {
                eprintln!("Usage: forwarder-baseline gen <TARGET> <RATE_PPS> <DURATION_SEC>");
                std::process::exit(1);
            }
            let target_addr: SocketAddr = args[2].parse()?;
            let rate_pps: f64 = args[3].parse()?;
            let duration_sec: f64 = args[4].parse()?;

            let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
            let packet = vec![0x42u8; 1200];
            let interval = Duration::from_secs_f64(1.0 / rate_pps);
            let total_packets = (rate_pps * duration_sec) as u64;

            let start = Instant::now();
            let mut sent = 0u64;
            let mut next_deadline = start;

            while sent < total_packets {
                let _ = sock.send_to(&packet, target_addr)?;
                sent += 1;
                next_deadline += interval;
                let now = Instant::now();
                if next_deadline > now {
                    std::thread::sleep(next_deadline - now);
                }
            }
            let elapsed = start.elapsed().as_secs_f64();
            let actual_pps = sent as f64 / elapsed;
            println!(
                r#"{{"sent_packets": {}, "elapsed_sec": {:.3}, "actual_pps": {:.1}}}"#,
                sent, elapsed, actual_pps
            );
            Ok(())
        }
        other => {
            eprintln!("Unknown subcommand: {other}");
            std::process::exit(1);
        }
    }
}
