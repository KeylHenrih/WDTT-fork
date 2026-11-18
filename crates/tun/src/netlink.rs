//! Minimal netlink (`NETLINK_ROUTE`) client, used for the operations `ioctl`
//! cannot express: `ip rule` entries and routing-table-scoped routes.
//!
//! Only the subset needed by this crate is implemented. The wire format is
//! stable UAPI, so the message structs and constants are declared here rather
//! than pulled from a netlink crate — this keeps the dependency surface at
//! `libc` alone.
//!
//! Every request is sent on a fresh socket and acknowledged synchronously, so
//! there is no shared state and no background task.

use crate::TunError;
use std::io;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `NETLINK_ROUTE`: routing and link configuration family.
const NETLINK_ROUTE: libc::c_int = 0;

/// `NLM_F_REQUEST`: this message is a request.
const NLM_F_REQUEST: u16 = 0x01;
/// `NLM_F_ACK`: ask the kernel to acknowledge the request.
const NLM_F_ACK: u16 = 0x04;
/// `NLM_F_EXCL`: fail if the object already exists.
const NLM_F_EXCL: u16 = 0x200;
/// `NLM_F_CREATE`: create the object if it does not exist.
const NLM_F_CREATE: u16 = 0x400;

/// `RTM_NEWRULE` / `RTM_DELRULE`: add or remove a routing policy rule.
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;

/// `RTM_NEWROUTE` / `RTM_DELROUTE`: add or remove a route.
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

/// `RTA_DST`, `RTA_OIF`, `RTA_GATEWAY`, `RTA_TABLE`: route attributes.
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_TABLE: u16 = 15;

/// `FRA_*`: routing rule attributes.
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;

/// `RTN_UNICAST`: a normal unicast route.
const RTN_UNICAST: u8 = 1;

/// `RTPROT_STATIC`: the route was installed administratively.
const RTPROT_STATIC: u8 = 4;

/// `FR_ACT_TO_TBL`: the rule selects a routing table.
const FR_ACT_TO_TBL: u8 = 1;

/// `AF_INET`.
const AF_INET: u8 = 2;

/// `RT_SCOPE_UNIVERSE`.
const RT_SCOPE_UNIVERSE: u8 = 0;

/// `RT_SCOPE_LINK`.
const RT_SCOPE_LINK: u8 = 253;

/// `RT_TABLE_UNSPEC`: the table is carried in an attribute instead.
const RT_TABLE_UNSPEC: u8 = 0;

/// Netlink message header (`struct nlmsghdr`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// Netlink socket address (`struct sockaddr_nl`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockAddrNl {
    nl_family: libc::sa_family_t,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

/// Routing rule header (`struct fib_rule_hdr`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct FibRuleHdr {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    res1: u8,
    res2: u8,
    action: u8,
    flags: u32,
}

/// Route message header (`struct rtmsg`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

/// Netlink error payload (`struct nlmsgerr`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NlMsgErr {
    error: i32,
    msg: NlMsgHdr,
}

/// Align `len` up to the netlink attribute boundary (4 bytes).
const fn nl_align(len: usize) -> usize {
    (len + 3) & !3
}

/// A builder for a single netlink request message.
struct NlBuf {
    buf: Vec<u8>,
}

impl NlBuf {
    /// Start a message with the given type and flags.
    fn new(msg_type: u16, flags: u16) -> Self {
        let mut buf = vec![0u8; size_of::<NlMsgHdr>()];
        let hdr = NlMsgHdr {
            nlmsg_len: size_of::<NlMsgHdr>() as u32,
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        // SAFETY: `buf` is at least `size_of::<NlMsgHdr>()` bytes and the
        // header is a plain C struct of integers.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (&hdr as *const NlMsgHdr).cast::<u8>(),
                buf.as_mut_ptr(),
                size_of::<NlMsgHdr>(),
            );
        }
        Self { buf }
    }

    /// Append a plain C struct as the message payload.
    fn push_struct<T: Copy>(&mut self, value: &T) {
        let bytes = size_of::<T>();
        // SAFETY: `value` is a valid `T` and `bytes` is its exact size.
        let src = unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), bytes) };
        self.buf.extend_from_slice(src);
    }

    /// Append a netlink attribute with a raw byte payload.
    fn push_attr(&mut self, attr_type: u16, payload: &[u8]) {
        let len = size_of::<libc::rtattr>() + payload.len();
        let attr = libc::rtattr {
            rta_len: len as libc::c_ushort,
            rta_type: attr_type,
        };
        self.push_struct(&attr);
        self.buf.extend_from_slice(payload);
        let padded = nl_align(len);
        self.buf.resize(self.buf.len() + (padded - len), 0);
    }

    /// Append a netlink attribute holding a `u32`.
    ///
    /// Netlink passes numeric attributes in host byte order; only addresses
    /// are big-endian.
    fn push_attr_u32(&mut self, attr_type: u16, value: u32) {
        self.push_attr(attr_type, &value.to_ne_bytes());
    }

    /// Append a netlink attribute holding an IPv4 address.
    fn push_attr_addr(&mut self, attr_type: u16, addr: Ipv4Addr) {
        self.push_attr(attr_type, &u32::from(addr).to_be_bytes());
    }

    /// Finish the message, patching the length field.
    fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// Open a `NETLINK_ROUTE` socket bound to the kernel.
fn netlink_socket() -> Result<OwnedFd, TunError> {
    // SAFETY: `socket` is called with valid domain/type/protocol constants.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    // SAFETY: `raw` is a freshly created descriptor owned by us.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let addr = SockAddrNl {
        nl_family: libc::AF_NETLINK as libc::sa_family_t,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    // SAFETY: `addr` is a valid `sockaddr_nl` and `fd` is a live netlink
    // socket; the length matches the struct.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const SockAddrNl).cast::<libc::sockaddr>(),
            size_of::<SockAddrNl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Send one request and wait for its acknowledgement.
///
/// The kernel replies with `NLMSG_ERROR`; an `error` field of zero means
/// success, anything else is the negated `errno`.
fn send_and_ack(fd: &OwnedFd, msg: &[u8]) -> Result<(), TunError> {
    // SAFETY: `msg` is a valid readable slice and `fd` is a live netlink
    // socket.
    let sent = unsafe { libc::send(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
    if sent < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }

    let mut reply = [0u8; 4096];
    // SAFETY: `reply` is a valid writable buffer and `fd` is a live socket.
    let n = unsafe { libc::recv(fd.as_raw_fd(), reply.as_mut_ptr().cast(), reply.len(), 0) };
    if n < 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    let n = n as usize;
    if n < size_of::<NlMsgHdr>() + size_of::<NlMsgErr>() {
        return Err(TunError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short netlink acknowledgement",
        )));
    }

    // SAFETY: the buffer holds at least a full `NlMsgHdr` followed by an
    // `NlMsgErr`, both plain C structs of integers.
    let err: NlMsgErr = unsafe {
        std::ptr::read_unaligned(reply[size_of::<NlMsgHdr>()..].as_ptr().cast::<NlMsgErr>())
    };
    if err.error == 0 {
        return Ok(());
    }
    Err(TunError::Io(io::Error::from_raw_os_error(-err.error)))
}

/// A routing policy rule, as installed by `ip rule`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSpec {
    /// Rule priority; lower values are consulted first.
    pub priority: u32,
    /// Firewall mark to match, or `None` to match every packet.
    pub fwmark: Option<u32>,
    /// Routing table selected by this rule.
    pub table: u32,
}

impl RuleSpec {
    /// A rule selecting `table` for packets carrying `fwmark`.
    pub fn fwmark(priority: u32, fwmark: u32, table: u32) -> Self {
        Self {
            priority,
            fwmark: Some(fwmark),
            table,
        }
    }
}

/// Build a `RTM_NEWRULE` / `RTM_DELRULE` message for `spec`.
fn build_rule_msg(msg_type: u16, flags: u16, spec: &RuleSpec) -> Vec<u8> {
    let mut buf = NlBuf::new(msg_type, flags);
    let hdr = FibRuleHdr {
        family: AF_INET,
        action: FR_ACT_TO_TBL,
        ..Default::default()
    };
    buf.push_struct(&hdr);
    buf.push_attr_u32(FRA_PRIORITY, spec.priority);
    buf.push_attr_u32(FRA_TABLE, spec.table);
    if let Some(mark) = spec.fwmark {
        buf.push_attr_u32(FRA_FWMARK, mark);
    }
    buf.finish()
}

/// Install a routing policy rule.
pub fn add_rule(spec: &RuleSpec) -> Result<(), TunError> {
    let fd = netlink_socket()?;
    let msg = build_rule_msg(
        RTM_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        spec,
    );
    send_and_ack(&fd, &msg)
}

/// Remove a routing policy rule.
pub fn del_rule(spec: &RuleSpec) -> Result<(), TunError> {
    let fd = netlink_socket()?;
    let msg = build_rule_msg(RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, spec);
    send_and_ack(&fd, &msg)
}

/// A route installed through netlink, which can carry an explicit table id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlRouteSpec {
    /// Destination network address.
    pub dest: Ipv4Addr,
    /// Destination prefix length.
    pub prefix_len: u8,
    /// Next hop, or `None` for a device route.
    pub gateway: Option<Ipv4Addr>,
    /// Output interface index.
    pub oif: u32,
    /// Routing table id.
    pub table: u32,
}

/// Build a `RTM_NEWROUTE` / `RTM_DELROUTE` message for `spec`.
fn build_route_msg(msg_type: u16, flags: u16, spec: &NlRouteSpec) -> Vec<u8> {
    let mut buf = NlBuf::new(msg_type, flags);
    let scope = if spec.gateway.is_some() {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };
    // The kernel resolves the table from `rtm_table` when it fits in a byte,
    // and from `RTA_TABLE` otherwise. Sending both for a small id makes the
    // lookup ambiguous, so only the attribute is used for ids above 255 and
    // only the header field below that.
    let (rtm_table, table_attr) = if spec.table <= u32::from(u8::MAX) {
        (spec.table as u8, None)
    } else {
        (RT_TABLE_UNSPEC, Some(spec.table))
    };
    let hdr = RtMsg {
        rtm_family: AF_INET,
        rtm_dst_len: spec.prefix_len,
        rtm_table,
        rtm_protocol: RTPROT_STATIC,
        rtm_scope: scope,
        rtm_type: RTN_UNICAST,
        ..Default::default()
    };
    buf.push_struct(&hdr);
    buf.push_attr_addr(RTA_DST, spec.dest);
    buf.push_attr_u32(RTA_OIF, spec.oif);
    if let Some(table) = table_attr {
        buf.push_attr_u32(RTA_TABLE, table);
    }
    if let Some(gw) = spec.gateway {
        buf.push_attr_addr(RTA_GATEWAY, gw);
    }
    buf.finish()
}

/// Install a route in an explicit routing table.
pub fn add_route(spec: &NlRouteSpec) -> Result<(), TunError> {
    let fd = netlink_socket()?;
    let msg = build_route_msg(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        spec,
    );
    send_and_ack(&fd, &msg)
}

/// Expose the serialized route message for diagnostics.
#[doc(hidden)]
pub fn debug_route_msg(spec: &NlRouteSpec) -> Vec<u8> {
    build_route_msg(RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_ACK, spec)
}

/// Remove a route from an explicit routing table.
pub fn del_route(spec: &NlRouteSpec) -> Result<(), TunError> {
    let fd = netlink_socket()?;
    let msg = build_route_msg(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, spec);
    send_and_ack(&fd, &msg)
}

/// Look up an interface index by name via `if_nametoindex`.
pub fn ifindex(name: &str) -> Result<u32, TunError> {
    let cname =
        std::ffi::CString::new(name).map_err(|_| TunError::InvalidName(name.to_string()))?;
    // SAFETY: `cname` is a valid NUL-terminated C string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(TunError::Io(io::Error::last_os_error()));
    }
    Ok(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_rounds_up_to_four() {
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
    }

    #[test]
    fn rule_message_has_expected_length() {
        let spec = RuleSpec::fwmark(10000, 0x7764_7400, 1000);
        let msg = build_rule_msg(RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK, &spec);
        let expected =
            size_of::<NlMsgHdr>() + size_of::<FibRuleHdr>() + 3 * (size_of::<libc::rtattr>() + 4);
        assert_eq!(msg.len(), expected);
        let len = u32::from_ne_bytes(msg[..4].try_into().expect("4 bytes"));
        assert_eq!(len as usize, msg.len());
    }

    #[test]
    fn rule_message_omits_fwmark_when_absent() {
        let spec = RuleSpec {
            priority: 10000,
            fwmark: None,
            table: 1000,
        };
        let msg = build_rule_msg(RTM_NEWRULE, NLM_F_REQUEST | NLM_F_ACK, &spec);
        let expected =
            size_of::<NlMsgHdr>() + size_of::<FibRuleHdr>() + 2 * (size_of::<libc::rtattr>() + 4);
        assert_eq!(msg.len(), expected);
    }

    #[test]
    fn route_message_carries_gateway_when_present() {
        let spec = NlRouteSpec {
            dest: Ipv4Addr::new(0, 0, 0, 0),
            prefix_len: 0,
            gateway: Some(Ipv4Addr::new(192, 168, 0, 1)),
            oif: 2,
            table: 1000,
        };
        let with_gw = build_route_msg(RTM_NEWROUTE, NLM_F_REQUEST, &spec);
        let spec_no_gw = NlRouteSpec {
            gateway: None,
            ..spec
        };
        let without_gw = build_route_msg(RTM_NEWROUTE, NLM_F_REQUEST, &spec_no_gw);
        assert_eq!(
            with_gw.len() - without_gw.len(),
            size_of::<libc::rtattr>() + 4
        );
    }

    #[test]
    fn attributes_are_padded_to_four_bytes() {
        let mut buf = NlBuf::new(RTM_NEWRULE, 0);
        let before = buf.buf.len();
        buf.push_attr(99, &[1, 2, 3]);
        let added = buf.buf.len() - before;
        assert_eq!(added, size_of::<libc::rtattr>() + 4);
    }

    #[test]
    fn numeric_attributes_use_host_byte_order() {
        let mut buf = NlBuf::new(RTM_NEWRULE, 0);
        buf.push_attr_u32(FRA_TABLE, 1000);
        let payload = &buf.buf[buf.buf.len() - 4..];
        assert_eq!(payload, &1000u32.to_ne_bytes());
    }

    #[test]
    fn address_attributes_use_network_byte_order() {
        let mut buf = NlBuf::new(RTM_NEWROUTE, 0);
        buf.push_attr_addr(RTA_DST, Ipv4Addr::new(198, 51, 100, 0));
        let payload = &buf.buf[buf.buf.len() - 4..];
        assert_eq!(payload, &[198, 51, 100, 0]);
    }

    #[test]
    fn rule_message_round_trips_priority_and_table() {
        let spec = RuleSpec::fwmark(10000, 0x7764_7400, 1000);
        let msg = build_rule_msg(RTM_NEWRULE, NLM_F_REQUEST, &spec);
        // Walk the attributes and confirm each numeric value survives.
        let mut offset = size_of::<NlMsgHdr>() + size_of::<FibRuleHdr>();
        let mut seen = Vec::new();
        while offset + size_of::<libc::rtattr>() <= msg.len() {
            // SAFETY: the slice holds at least a full `rtattr`.
            let attr: libc::rtattr =
                unsafe { std::ptr::read_unaligned(msg[offset..].as_ptr().cast::<libc::rtattr>()) };
            let len = attr.rta_len as usize;
            if len < size_of::<libc::rtattr>() || offset + len > msg.len() {
                break;
            }
            let payload = &msg[offset + size_of::<libc::rtattr>()..offset + len];
            if payload.len() == 4 {
                let value = u32::from_ne_bytes(payload.try_into().expect("4 bytes"));
                seen.push((attr.rta_type, value));
            }
            offset += nl_align(len);
        }
        assert!(seen.contains(&(FRA_PRIORITY, 10000)));
        assert!(seen.contains(&(FRA_TABLE, 1000)));
        assert!(seen.contains(&(FRA_FWMARK, 0x7764_7400)));
    }
}
