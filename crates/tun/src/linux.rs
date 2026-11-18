//! Linux TUN device backed by `/dev/net/tun`.
//!
//! The device is opened with `IFF_TUN | IFF_NO_PI`, so reads and writes carry
//! bare IP packets with no 4-byte packet-information prefix. The descriptor is
//! registered with the tokio reactor and exposed as an async read/write pair.

use crate::{TunConfig, TunError};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum interface name length accepted by the kernel (`IFNAMSIZ - 1`).
const IFNAMSIZ: usize = 16;

/// `IFF_TUN`: the device carries IP packets.
const IFF_TUN: libc::c_short = 0x0001;
/// `IFF_NO_PI`: no 4-byte packet information header.
const IFF_NO_PI: libc::c_short = 0x1000;

/// An open Linux TUN interface.
#[derive(Debug)]
pub struct TunDevice {
    inner: AsyncFd<OwnedFd>,
    name: String,
    mtu: u16,
}

impl TunDevice {
    /// Open (or create) the TUN interface described by `config`.
    ///
    /// Requires `CAP_NET_ADMIN` (or root). The interface is brought up and its
    /// MTU applied before this returns.
    pub fn open(config: &TunConfig) -> Result<Self, TunError> {
        let name = config.name.clone();
        if name.len() >= IFNAMSIZ || name.as_bytes().contains(&0) {
            return Err(TunError::InvalidName(name));
        }

        let fd = open_tun_fd(&name)?;
        let actual_name = interface_name(fd.as_raw_fd())?;

        set_mtu(&actual_name, config.mtu)?;
        set_up(&actual_name)?;

        // SAFETY: `fd` is an owned, open TUN descriptor that stays open for the
        // whole lifetime of the `AsyncFd` and always reports the same raw fd.
        let inner = unsafe { AsyncFd::register(fd) }.map_err(|e| TunError::Io(e.into()))?;
        Ok(Self {
            inner,
            name: actual_name,
            mtu: config.mtu,
        })
    }

    /// Interface name as reported by the kernel.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Configured MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Raw file descriptor of the TUN device.
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(guard)) => guard,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            let unfilled = buf.initialize_unfilled();
            // SAFETY: `unfilled` is a valid, writable slice of `unfilled.len()`
            // bytes owned by the caller's `ReadBuf`, and the descriptor is a
            // live TUN device owned by `self`.
            let n = unsafe {
                libc::read(
                    self.inner.get_ref().as_raw_fd(),
                    unfilled.as_mut_ptr().cast(),
                    unfilled.len(),
                )
            };

            if n >= 0 {
                buf.advance(n as usize);
                return std::task::Poll::Ready(Ok(()));
            }

            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return std::task::Poll::Ready(Err(err));
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(guard)) => guard,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            // SAFETY: `buf` is a valid readable slice of `buf.len()` bytes and
            // the descriptor is a live TUN device owned by `self`.
            let n = unsafe {
                libc::write(
                    self.inner.get_ref().as_raw_fd(),
                    buf.as_ptr().cast(),
                    buf.len(),
                )
            };

            if n >= 0 {
                return std::task::Poll::Ready(Ok(n as usize));
            }

            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return std::task::Poll::Ready(Err(err));
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Open `/dev/net/tun` and attach it to the named interface.
fn open_tun_fd(name: &str) -> Result<OwnedFd, TunError> {
    // SAFETY: `open` is called with a static NUL-terminated path and valid flags.
    let raw = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if raw < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a freshly opened descriptor owned by us.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut ifr: libc::ifreq = zeroed_ifreq();
    let bytes = name.as_bytes();
    for (dst, src) in ifr.ifr_name.iter_mut().zip(bytes.iter()) {
        *dst = *src as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

    // SAFETY: `ifr` is a fully initialized `ifreq` and `fd` is a live TUN
    // descriptor; `TUNSETIFF` reads the name and flags from it.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut ifr) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }

    Ok(fd)
}

/// Read back the interface name the kernel assigned.
fn interface_name(fd: RawFd) -> Result<String, TunError> {
    let mut ifr: libc::ifreq = zeroed_ifreq();
    // SAFETY: `ifr` is a zeroed `ifreq`; `TUNGETIFF` fills in the name.
    let rc = unsafe { libc::ioctl(fd, libc::TUNGETIFF, &mut ifr) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    let raw: Vec<u8> = ifr
        .ifr_name
        .iter()
        .map(|c| *c as u8)
        .take_while(|b| *b != 0)
        .collect();
    Ok(String::from_utf8_lossy(&raw).into_owned())
}

/// Apply the MTU to an existing interface via `SIOCSIFMTU`.
fn set_mtu(name: &str, mtu: u16) -> Result<(), TunError> {
    let sock = control_socket()?;
    let mut ifr = ifreq_with_name(name)?;
    ifr.ifr_ifru.ifru_mtu = libc::c_int::from(mtu);

    // SAFETY: `ifr` is a valid `ifreq` with a NUL-terminated name and the
    // socket is an open AF_INET control socket.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFMTU, &ifr) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Bring the interface up via `SIOCGIFFLAGS` + `SIOCSIFFLAGS`.
fn set_up(name: &str) -> Result<(), TunError> {
    let sock = control_socket()?;
    let mut ifr = ifreq_with_name(name)?;

    // SAFETY: `ifr` is a valid `ifreq` with a NUL-terminated name.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &mut ifr) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }

    // SAFETY: `SIOCGIFFLAGS` above initialized `ifru_flags`.
    unsafe {
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    }

    // SAFETY: `ifr` carries the flags read above plus `IFF_UP`.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &ifr) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Open a throwaway AF_INET datagram socket used for interface ioctls.
fn control_socket() -> Result<OwnedFd, TunError> {
    // SAFETY: `socket` is called with valid domain/type/protocol constants.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a freshly created descriptor owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Build a zeroed `ifreq` with the interface name copied in.
fn ifreq_with_name(name: &str) -> Result<libc::ifreq, TunError> {
    if name.len() >= IFNAMSIZ || name.as_bytes().contains(&0) {
        return Err(TunError::InvalidName(name.to_string()));
    }
    let mut ifr: libc::ifreq = zeroed_ifreq();
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes().iter()) {
        *dst = *src as libc::c_char;
    }
    Ok(ifr)
}

/// All-zero `ifreq`, the documented starting state for every ioctl above.
fn zeroed_ifreq() -> libc::ifreq {
    // SAFETY: `ifreq` is a plain C struct of integers and byte arrays; an
    // all-zero bit pattern is a valid value for it.
    unsafe { std::mem::zeroed() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_overlong_name() {
        let cfg = TunConfig {
            name: "a".repeat(IFNAMSIZ),
            mtu: 1200,
        };
        assert!(matches!(
            TunDevice::open(&cfg),
            Err(TunError::InvalidName(_))
        ));
    }

    #[test]
    fn rejects_nul_in_name() {
        let cfg = TunConfig {
            name: "wdtt\0x".into(),
            mtu: 1200,
        };
        assert!(matches!(
            TunDevice::open(&cfg),
            Err(TunError::InvalidName(_))
        ));
    }
}
