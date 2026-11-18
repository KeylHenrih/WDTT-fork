//! Linux network configuration primitives: interface addressing, routing
//! tables, policy rules and packet marking.
//!
//! Everything here is built on `ioctl` and `rtnetlink`-free syscalls so the
//! crate keeps a single, predictable dependency (`libc`). The module is split
//! into three layers:
//!
//! * [`iface`] — address and link state on a single interface.
//! * [`route`] — entries in a routing table, including a dedicated policy
//!   table used to steer selected traffic into the tunnel.
//! * [`rule`] — `ip rule` entries that select the policy table by firewall
//!   mark.
//!
//! The caller is responsible for ordering: addresses before routes, routes
//! before rules, and the reverse when tearing down.

use crate::TunError;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Maximum interface name length accepted by the kernel (`IFNAMSIZ - 1`).
pub(crate) const IFNAMSIZ: usize = 16;

/// Routing table id used for tunnel-selected traffic.
///
/// Chosen from the local-use range (`1..=252`) so it never collides with the
/// kernel's `main` (254) or `local` (255) tables, and stays clear of the
/// `default` table (253).
pub const WDTT_ROUTE_TABLE: u32 = 1000;

/// Firewall mark applied to packets that must be routed into the tunnel.
///
/// The value is arbitrary but must be unique on the host; it is paired with a
/// `ip rule fwmark` entry pointing at [`WDTT_ROUTE_TABLE`].
pub const WDTT_FWMARK: u32 = 0x7764_7400;

/// Priority of the `ip rule` entries installed by this crate.
///
/// Must be lower than the kernel's `main` rule (32766) so the policy table is
/// consulted first, and higher than any rule the host already relies on for
/// its own routing.
pub const WDTT_RULE_PRIORITY: u32 = 10000;

/// Open a throwaway `AF_INET` datagram socket used for interface ioctls.
pub(crate) fn control_socket() -> Result<OwnedFd, TunError> {
    // SAFETY: `socket` is called with valid domain/type/protocol constants.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a freshly created descriptor owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Build a zeroed `ifreq` with the interface name copied in.
pub(crate) fn ifreq_with_name(name: &str) -> Result<libc::ifreq, TunError> {
    if name.len() >= IFNAMSIZ || name.as_bytes().contains(&0) {
        return Err(TunError::InvalidName(name.to_string()));
    }
    let mut ifr: libc::ifreq = zeroed_ifreq();
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes().iter()) {
        *dst = *src as libc::c_char;
    }
    Ok(ifr)
}

/// All-zero `ifreq`, the documented starting state for every ioctl.
pub(crate) fn zeroed_ifreq() -> libc::ifreq {
    // SAFETY: `ifreq` is a plain C struct of integers and byte arrays; an
    // all-zero bit pattern is a valid value for it.
    unsafe { std::mem::zeroed() }
}

/// Build a `sockaddr_in` for an IPv4 address.
fn sockaddr_in(addr: Ipv4Addr) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(addr).to_be(),
        },
        sin_zero: [0; 8],
    }
}

/// Copy a `sockaddr_in` into the generic `sockaddr` slot of an `rtentry`.
fn write_sockaddr(dst: &mut libc::sockaddr, src: libc::sockaddr_in) {
    // SAFETY: `sockaddr_in` is smaller than `sockaddr` and both are plain
    // C structs; the destination is zeroed first so the tail padding is
    // deterministic.
    unsafe {
        std::ptr::write_bytes(dst as *mut libc::sockaddr, 0, 1);
        std::ptr::copy_nonoverlapping(
            (&src as *const libc::sockaddr_in).cast::<u8>(),
            (dst as *mut libc::sockaddr).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
}

/// Assign an IPv4 address to an interface via `SIOCSIFADDR`.
///
/// The prefix length is applied separately by [`set_netmask`]; the kernel
/// derives the connected route from the pair.
pub fn set_addr(name: &str, addr: Ipv4Addr) -> Result<(), TunError> {
    let sock = control_socket()?;
    let mut ifr = ifreq_with_name(name)?;
    let sa = sockaddr_in(addr);

    // SAFETY: `ifr` is a valid `ifreq` with a NUL-terminated name; the union
    // field is written as a `sockaddr` of the documented size.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&sa as *const libc::sockaddr_in).cast::<u8>(),
            (&mut ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }

    // SAFETY: `ifr` carries a fully initialized address and the socket is an
    // open `AF_INET` control socket.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFADDR, &ifr) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Remove an IPv4 address from an interface via `SIOCDIFADDR`.
pub fn del_addr(name: &str, addr: Ipv4Addr) -> Result<(), TunError> {
    let sock = control_socket()?;
    let mut ifr = ifreq_with_name(name)?;
    let sa = sockaddr_in(addr);

    // SAFETY: see `set_addr`.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&sa as *const libc::sockaddr_in).cast::<u8>(),
            (&mut ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }

    // SAFETY: `ifr` carries a fully initialized address.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCDIFADDR, &ifr) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Apply a netmask to an interface via `SIOCSIFNETMASK`.
pub fn set_netmask(name: &str, mask: Ipv4Addr) -> Result<(), TunError> {
    let sock = control_socket()?;
    let mut ifr = ifreq_with_name(name)?;
    let sa = sockaddr_in(mask);

    // SAFETY: see `set_addr`.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&sa as *const libc::sockaddr_in).cast::<u8>(),
            (&mut ifr.ifr_ifru.ifru_netmask as *mut libc::sockaddr).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }

    // SAFETY: `ifr` carries a fully initialized netmask.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFNETMASK, &ifr) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Bring an interface up via `SIOCGIFFLAGS` + `SIOCSIFFLAGS`.
pub fn set_up(name: &str) -> Result<(), TunError> {
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

/// Apply the MTU to an interface via `SIOCSIFMTU`.
pub fn set_mtu(name: &str, mtu: u16) -> Result<(), TunError> {
    let sock = control_socket()?;
    let mut ifr = ifreq_with_name(name)?;
    ifr.ifr_ifru.ifru_mtu = libc::c_int::from(mtu);

    // SAFETY: `ifr` is a valid `ifreq` with a NUL-terminated name.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFMTU, &ifr) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// A single IPv4 route entry installed through `ioctl`.
///
/// The legacy `rtentry` interface cannot address a routing table, so every
/// route built here lands in the kernel's `main` table. Use
/// [`crate::netlink::NlRouteSpec`] when an explicit table is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    /// Destination network address.
    pub dest: Ipv4Addr,
    /// Destination prefix length.
    pub prefix_len: u8,
    /// Next hop, or `None` for a device route.
    pub gateway: Option<Ipv4Addr>,
    /// Output interface name.
    pub device: String,
}

impl RouteSpec {
    /// A device route (no gateway).
    pub fn device(dest: Ipv4Addr, prefix_len: u8, device: impl Into<String>) -> Self {
        Self {
            dest,
            prefix_len,
            gateway: None,
            device: device.into(),
        }
    }

    /// A gateway route.
    pub fn gateway(
        dest: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
        device: impl Into<String>,
    ) -> Self {
        Self {
            dest,
            prefix_len,
            gateway: Some(gateway),
            device: device.into(),
        }
    }

    /// Netmask derived from [`Self::prefix_len`].
    fn netmask(&self) -> Ipv4Addr {
        let mask = if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(self.prefix_len))
        };
        Ipv4Addr::from(mask)
    }

    /// Destination address with host bits cleared.
    fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.dest) & u32::from(self.netmask()))
    }
}

/// Build an `rtentry` from a [`RouteSpec`].
fn build_rtentry(spec: &RouteSpec) -> Result<libc::rtentry, TunError> {
    if spec.prefix_len > 32 {
        return Err(TunError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("prefix length {} out of range", spec.prefix_len),
        )));
    }
    if spec.device.len() >= IFNAMSIZ || spec.device.as_bytes().contains(&0) {
        return Err(TunError::InvalidName(spec.device.clone()));
    }

    // SAFETY: `rtentry` is a plain C struct of integers and pointers; an
    // all-zero bit pattern is a valid starting value.
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };

    write_sockaddr(&mut rt.rt_dst, sockaddr_in(spec.network()));
    write_sockaddr(&mut rt.rt_genmask, sockaddr_in(spec.netmask()));
    if let Some(gw) = spec.gateway {
        write_sockaddr(&mut rt.rt_gateway, sockaddr_in(gw));
        rt.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort;
    } else {
        rt.rt_flags = libc::RTF_UP as libc::c_ushort;
    }
    if spec.prefix_len == 32 {
        rt.rt_flags |= libc::RTF_HOST as libc::c_ushort;
    }

    // The device name must outlive the ioctl call; the caller keeps `spec`
    // alive for the duration, so borrowing its bytes is sound.
    rt.rt_dev = spec.device.as_ptr() as *mut libc::c_char;

    Ok(rt)
}

/// Add a route via `SIOCADDRT`.
pub fn add_route(spec: &RouteSpec) -> Result<(), TunError> {
    let sock = control_socket()?;
    let mut rt = build_rtentry(spec)?;

    // SAFETY: `rt` is a fully initialized `rtentry` whose `rt_dev` points at
    // `spec.device`, which outlives this call.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCADDRT, &mut rt) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Remove a route via `SIOCDELRT`.
pub fn del_route(spec: &RouteSpec) -> Result<(), TunError> {
    let sock = control_socket()?;
    let mut rt = build_rtentry(spec)?;

    // SAFETY: see `add_route`.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCDELRT, &mut rt) };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_from_prefix() {
        let spec = RouteSpec::device(Ipv4Addr::new(10, 99, 99, 0), 24, "wdtt0");
        assert_eq!(spec.netmask(), Ipv4Addr::new(255, 255, 255, 0));

        let spec = RouteSpec::device(Ipv4Addr::new(1, 1, 1, 1), 32, "wdtt0");
        assert_eq!(spec.netmask(), Ipv4Addr::new(255, 255, 255, 255));

        let spec = RouteSpec::device(Ipv4Addr::new(0, 0, 0, 0), 0, "wdtt0");
        assert_eq!(spec.netmask(), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn netmask_masks_off_host_bits() {
        let spec = RouteSpec::device(Ipv4Addr::new(10, 99, 99, 77), 24, "wdtt0");
        assert_eq!(spec.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(spec.network(), Ipv4Addr::new(10, 99, 99, 0));
    }

    #[test]
    fn rejects_overlong_device_name() {
        let spec = RouteSpec::device(Ipv4Addr::new(10, 0, 0, 0), 8, "a".repeat(IFNAMSIZ));
        assert!(matches!(
            build_rtentry(&spec),
            Err(TunError::InvalidName(_))
        ));
    }

    #[test]
    fn rejects_prefix_over_32() {
        let spec = RouteSpec::device(Ipv4Addr::new(10, 0, 0, 0), 33, "wdtt0");
        assert!(build_rtentry(&spec).is_err());
    }

    #[test]
    fn host_route_sets_rtf_host() {
        let spec = RouteSpec::device(Ipv4Addr::new(1, 1, 1, 1), 32, "wdtt0");
        let rt = build_rtentry(&spec).expect("valid spec");
        assert_ne!(rt.rt_flags & libc::RTF_HOST as libc::c_ushort, 0);
        assert_eq!(rt.rt_flags & libc::RTF_GATEWAY as libc::c_ushort, 0);
    }

    #[test]
    fn gateway_route_sets_rtf_gateway() {
        let spec = RouteSpec::gateway(
            Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ipv4Addr::new(192, 168, 0, 1),
            "wlan0",
        );
        let rt = build_rtentry(&spec).expect("valid spec");
        assert_ne!(rt.rt_flags & libc::RTF_GATEWAY as libc::c_ushort, 0);
        assert_eq!(rt.rt_flags & libc::RTF_HOST as libc::c_ushort, 0);
    }
}
