//! Batched UDP I/O engine with recvmmsg/sendmmsg and GRO/GSO support.
//!
//! Provides zero-overhead batching for high-throughput UDP packet processing,
//! reducing syscall overhead from O(N) to O(1) per packet burst.
//! Includes automated kernel capability probing and graceful fallback to
//! standard single-packet `recvfrom`/`sendto` on unsupported platforms.

#![allow(unsafe_code)]

use std::io;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Default batch size for recvmmsg/sendmmsg.
pub const DEFAULT_BATCH_SIZE: usize = 32;

/// Maximum payload length for single UDP packet buffer.
pub const MAX_PACKET_BUFFER_LEN: usize = 2048;

/// Metadata describing a single received packet in a batch.
#[derive(Debug, Clone, Copy)]
pub struct RecvMeta {
    /// Number of valid payload bytes in the buffer.
    pub len: usize,
    /// Source socket address from which the packet was received.
    pub addr: SocketAddr,
    /// Segment size if GRO aggregated multiple datagrams; equal to `len` otherwise.
    pub stride: usize,
}

impl Default for RecvMeta {
    fn default() -> Self {
        Self {
            len: 0,
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            stride: 0,
        }
    }
}

/// A packet to be transmitted in a batch.
#[derive(Debug, Clone, Copy)]
pub struct TransmitPacket<'a> {
    /// Packet payload bytes.
    pub buf: &'a [u8],
    /// Destination socket address.
    pub addr: SocketAddr,
    /// Optional segment size for UDP GSO offload.
    pub gso_segment_size: Option<u16>,
}

/// Hardware and kernel capabilities detected for the UDP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchCapabilities {
    /// Whether recvmmsg syscall is supported and enabled.
    pub has_recvmmsg: bool,
    /// Whether sendmmsg syscall is supported and enabled.
    pub has_sendmmsg: bool,
    /// Whether UDP Generic Receive Offload (GRO) is supported and active.
    pub has_gro: bool,
    /// Whether UDP Generic Segmentation Offload (GSO) is supported and active.
    pub has_gso: bool,
    /// Whether short batch readiness clearing is disabled (for benchmarking).
    pub disable_short_batch_clear: bool,
}

impl BatchCapabilities {
    /// Return empty capabilities (all batching and offloading disabled).
    pub const fn unsupported() -> Self {
        Self {
            has_recvmmsg: false,
            has_sendmmsg: false,
            has_gro: false,
            has_gso: false,
            disable_short_batch_clear: false,
        }
    }

    /// Probe capabilities on a socket file descriptor.
    #[cfg(target_os = "linux")]
    pub fn probe(fd: RawFd) -> Self {
        let disable_batch = std::env::var("WDTT_DISABLE_BATCH").is_ok();
        let disable_gro = std::env::var("WDTT_DISABLE_GRO").is_ok();
        let disable_gso = std::env::var("WDTT_DISABLE_GSO").is_ok();
        let disable_short_batch_clear = std::env::var("WDTT_DISABLE_SHORT_BATCH_CLEAR").is_ok();

        let has_recvmmsg = !disable_batch;
        let has_sendmmsg = !disable_batch;

        // Probe GRO support
        let mut has_gro = false;
        if !disable_gro {
            let optval: libc::c_int = 1;
            // SAFETY: fd is valid and optval is a valid pointer to c_int of appropriate size.
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_UDP,
                    libc::UDP_GRO,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                )
            };
            if ret == 0 {
                has_gro = true;
                tracing::debug!(fd, "UDP GRO enabled successfully on socket");
            } else {
                tracing::debug!(
                    fd,
                    errno = io::Error::last_os_error().raw_os_error(),
                    "UDP GRO not supported by kernel/driver"
                );
            }
        }

        // Probe GSO support
        let mut has_gso = false;
        if !disable_gso {
            let optval: libc::c_int = 1500;
            // SAFETY: fd is valid and optval is a valid pointer to c_int of appropriate size.
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_UDP,
                    libc::UDP_SEGMENT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                )
            };
            if ret == 0 {
                has_gso = true;
                tracing::debug!(fd, "UDP GSO supported on socket");
            } else {
                tracing::debug!(
                    fd,
                    errno = io::Error::last_os_error().raw_os_error(),
                    "UDP GSO not supported by kernel/driver"
                );
            }
        }

        Self {
            has_recvmmsg,
            has_sendmmsg,
            has_gro,
            has_gso,
            disable_short_batch_clear,
        }
    }
}

/// Batched socket adapter wrapping an Arc<Tokio UdpSocket>.
pub struct BatchedUdpSocket {
    socket: Arc<UdpSocket>,
    caps: BatchCapabilities,
}

impl BatchedUdpSocket {
    /// Create a new batched adapter for a Tokio UdpSocket.
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        #[cfg(target_os = "linux")]
        let caps = BatchCapabilities::probe(socket.as_raw_fd());
        #[cfg(not(target_os = "linux"))]
        let caps = BatchCapabilities::unsupported();

        Self { socket, caps }
    }

    /// Create a batched adapter explicitly operating in single-packet fallback mode.
    pub fn new_fallback(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            caps: BatchCapabilities::unsupported(),
        }
    }

    /// Access the underlying Tokio UdpSocket.
    pub fn inner(&self) -> &UdpSocket {
        &self.socket
    }

    /// Detected capabilities.
    pub fn capabilities(&self) -> BatchCapabilities {
        self.caps
    }

    /// Receive a batch of packets.
    ///
    /// Returns the number of packets successfully read into `buffers` and described in `metas`.
    pub async fn recv_batch(
        &self,
        buffers: &mut [Vec<u8>],
        metas: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let count = buffers.len().min(metas.len());
        if count == 0 {
            return Ok(0);
        }

        #[cfg(target_os = "linux")]
        {
            if self.caps.has_recvmmsg {
                return self.recv_batch_linux(buffers, metas).await;
            }
        }

        // Fallback for non-Linux or when batching is disabled
        self.recv_batch_fallback(buffers, metas).await
    }

    /// Transmit a batch of packets.
    ///
    /// Returns the number of packets successfully transmitted.
    pub async fn send_batch(&self, packets: &[TransmitPacket<'_>]) -> io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        #[cfg(target_os = "linux")]
        {
            if self.caps.has_sendmmsg {
                return self.send_batch_linux(packets).await;
            }
        }

        // Fallback for non-Linux or when batching is disabled
        self.send_batch_fallback(packets).await
    }

    // --- Linux recvmmsg Implementation ---
    #[cfg(target_os = "linux")]
    async fn recv_batch_linux(
        &self,
        buffers: &mut [Vec<u8>],
        metas: &mut [RecvMeta],
    ) -> io::Result<usize> {
        let fd = self.socket.as_raw_fd();
        let batch_size = buffers.len().min(metas.len());
        let res = self
            .socket
            .async_io(Interest::READABLE, || {

                let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(batch_size);
                let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(batch_size);
                let mut addrs: Vec<libc::sockaddr_storage> = Vec::with_capacity(batch_size);
                let mut ctrl_bufs: Vec<[u8; 64]> = vec![[0u8; 64]; batch_size];

                for buf in buffers.iter_mut().take(batch_size) {
                    iovecs.push(libc::iovec {
                        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                        iov_len: buf.len(),
                    });
                    addrs.push(unsafe { std::mem::zeroed() });
                }

                for i in 0..batch_size {
                    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
                    msghdr.msg_name = &mut addrs[i] as *mut _ as *mut libc::c_void;
                    msghdr.msg_namelen =
                        std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                    msghdr.msg_iov = &mut iovecs[i] as *mut _;
                    msghdr.msg_iovlen = 1;

                    if self.caps.has_gro {
                        msghdr.msg_control = ctrl_bufs[i].as_mut_ptr() as *mut libc::c_void;
                        msghdr.msg_controllen = ctrl_bufs[i].len() as _;
                    }

                    hdrs.push(libc::mmsghdr {
                        msg_hdr: msghdr,
                        msg_len: 0,
                    });
                }

                // SAFETY: fd is valid nonblocking socket. hdrs points to contiguous slice of mmsghdr.
                // iov_base pointers point to valid preallocated memory of at least iov_len bytes.
                // ctrl_bufs pointers are valid buffers of 64 bytes.
                // Flags include MSG_DONTWAIT to return immediately with whatever packets are buffered.
                let ret = unsafe {
                    libc::recvmmsg(
                        fd,
                        hdrs.as_mut_ptr(),
                        batch_size as libc::c_uint,
                        libc::MSG_DONTWAIT as _,
                        std::ptr::null_mut(),
                    )
                };

                if ret < 0 {
                    let err = io::Error::last_os_error();
                    return Err(err);
                }

                let pkts_read = ret as usize;
                for i in 0..pkts_read {
                    let pkt_len = hdrs[i].msg_len as usize;
                    let parsed_addr = sockaddr_to_socket_addr(&addrs[i]);
                    let mut stride = pkt_len;

                    // Inspect GRO cmsg if GRO is active
                    if self.caps.has_gro && hdrs[i].msg_hdr.msg_controllen > 0 {
                        // SAFETY: msg_hdr.msg_control is a valid pointer to buffer returned by recvmmsg.
                        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&hdrs[i].msg_hdr) };
                        while !cmsg.is_null() {
                            unsafe {
                                if (*cmsg).cmsg_level == libc::SOL_UDP
                                    && (*cmsg).cmsg_type == libc::UDP_GRO
                                {
                                    let gso_size_ptr = libc::CMSG_DATA(cmsg) as *const u16;
                                    let gso_size = *gso_size_ptr as usize;
                                    if gso_size > 0 && gso_size < pkt_len {
                                        stride = gso_size;
                                    }
                                    break;
                                }
                                cmsg = libc::CMSG_NXTHDR(&hdrs[i].msg_hdr, cmsg);
                            }
                        }
                    }

                    metas[i] = RecvMeta {
                        len: pkt_len,
                        addr: parsed_addr,
                        stride,
                    };
                }

                Ok(pkts_read)
            })
            .await?;

        // Short batch (< batch_size) proves the UDP socket receive queue is now empty.
        // Explicitly clear Tokio's readiness flag so that the subsequent iteration does NOT
        // issue a doomed recvmmsg syscall that returns EAGAIN/WouldBlock.
        if res < batch_size && !self.caps.disable_short_batch_clear {
            let _: io::Result<()> = self
                .socket
                .try_io(Interest::READABLE, || Err(io::Error::from(io::ErrorKind::WouldBlock)));
        }

        Ok(res)
    }

    // --- Linux sendmmsg Implementation with GSO support ---
    #[cfg(target_os = "linux")]
    async fn send_batch_linux(&self, packets: &[TransmitPacket<'_>]) -> io::Result<usize> {
        let fd = self.socket.as_raw_fd();
        self.socket
            .async_io(Interest::WRITABLE, || {
                let batch_size = packets.len();

                let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(batch_size);
                let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(batch_size);
                let mut addrs: Vec<(libc::sockaddr_storage, libc::socklen_t)> =
                    Vec::with_capacity(batch_size);
                let mut ctrl_bufs: Vec<[u8; 64]> = vec![[0u8; 64]; batch_size];

                for pkt in packets {
                    iovecs.push(libc::iovec {
                        iov_base: pkt.buf.as_ptr() as *mut libc::c_void,
                        iov_len: pkt.buf.len(),
                    });
                    addrs.push(socket_addr_to_sockaddr(&pkt.addr));
                }

                for i in 0..batch_size {
                    let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
                    msghdr.msg_name = &mut addrs[i].0 as *mut _ as *mut libc::c_void;
                    msghdr.msg_namelen = addrs[i].1;
                    msghdr.msg_iov = &mut iovecs[i] as *mut _;
                    msghdr.msg_iovlen = 1;

                    // Configure GSO segment offload if requested
                    if self.caps.has_gso
                        && let Some(seg_size) = packets[i].gso_segment_size
                    {
                        msghdr.msg_control = ctrl_bufs[i].as_mut_ptr() as *mut libc::c_void;
                        // SAFETY: std::mem::size_of::<u16>() is 2, fits within 64 byte ctrl_buf.
                        msghdr.msg_controllen =
                            unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as libc::c_uint) }
                                as _;

                        // SAFETY: msghdr has valid msg_control buffer of sufficient length.
                        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
                        if !cmsg.is_null() {
                            unsafe {
                                (*cmsg).cmsg_level = libc::SOL_UDP;
                                (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                                (*cmsg).cmsg_len =
                                    libc::CMSG_LEN(std::mem::size_of::<u16>() as libc::c_uint) as _;
                                let data_ptr = libc::CMSG_DATA(cmsg) as *mut u16;
                                *data_ptr = seg_size;
                            }
                        }
                    }

                    hdrs.push(libc::mmsghdr {
                        msg_hdr: msghdr,
                        msg_len: 0,
                    });
                }

                // SAFETY: fd is a valid socket, hdrs points to valid mmsghdr array of length batch_size,
                // all iov_base pointers are valid for reading their corresponding iov_len bytes.
                let ret = unsafe {
                    libc::sendmmsg(
                        fd,
                        hdrs.as_mut_ptr(),
                        batch_size as libc::c_uint,
                        libc::MSG_DONTWAIT as _,
                    )
                };

                if ret < 0 {
                    let err = io::Error::last_os_error();
                    return Err(err);
                }

                Ok(ret as usize)
            })
            .await
    }

    // --- Fallback Implementation (Single-packet loops) ---
    async fn recv_batch_fallback(
        &self,
        buffers: &mut [Vec<u8>],
        metas: &mut [RecvMeta],
    ) -> io::Result<usize> {
        // Read at least one packet asynchronously
        let (first_len, first_src) = self.socket.recv_from(&mut buffers[0]).await?;
        metas[0] = RecvMeta {
            len: first_len,
            addr: first_src,
            stride: first_len,
        };
        let mut count = 1;

        // Drain any additional immediately available packets without blocking
        let max_count = buffers.len().min(metas.len());
        while count < max_count {
            match self.socket.try_recv_from(&mut buffers[count]) {
                Ok((len, src)) => {
                    metas[count] = RecvMeta {
                        len,
                        addr: src,
                        stride: len,
                    };
                    count += 1;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(count)
    }

    async fn send_batch_fallback(&self, packets: &[TransmitPacket<'_>]) -> io::Result<usize> {
        let mut sent = 0;
        for pkt in packets {
            match self.socket.send_to(pkt.buf, pkt.addr).await {
                Ok(_) => sent += 1,
                Err(e) => {
                    if sent > 0 {
                        break;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(sent)
    }
}

// Convert libc sockaddr_storage into standard Rust SocketAddr
#[cfg(target_os = "linux")]
fn sockaddr_to_socket_addr(storage: &libc::sockaddr_storage) -> SocketAddr {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: storage.ss_family is AF_INET, casting to sockaddr_in is well-defined.
            let sin: &libc::sockaddr_in =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            SocketAddr::V4(std::net::SocketAddrV4::new(ip, port))
        }
        libc::AF_INET6 => {
            // SAFETY: storage.ss_family is AF_INET6, casting to sockaddr_in6 is well-defined.
            let sin6: &libc::sockaddr_in6 =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            ))
        }
        _ => SocketAddr::from(([0, 0, 0, 0], 0)),
    }
}

// Convert standard Rust SocketAddr into libc sockaddr_storage and socklen_t
#[cfg(target_os = "linux")]
fn socket_addr_to_sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            // SAFETY: storage has enough capacity for sockaddr_in.
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            // SAFETY: storage has enough capacity for sockaddr_in6.
            let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo();
            sin6.sin6_scope_id = v6.scope_id();
            (
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_batched_socket_fallback_echo() {
        let srv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let srv_addr = srv.local_addr().unwrap();
        let cln = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let b_srv = BatchedUdpSocket::new(srv);
        let b_cln = BatchedUdpSocket::new(cln);

        let data1 = b"packet-one";
        let data2 = b"packet-two";
        let pkts = [
            TransmitPacket {
                buf: data1,
                addr: srv_addr,
                gso_segment_size: None,
            },
            TransmitPacket {
                buf: data2,
                addr: srv_addr,
                gso_segment_size: None,
            },
        ];

        let sent = b_cln.send_batch(&pkts).await.unwrap();
        assert_eq!(sent, 2);

        let mut bufs = vec![vec![0u8; 128], vec![0u8; 128]];
        let mut metas = vec![RecvMeta::default(), RecvMeta::default()];

        let read = b_srv.recv_batch(&mut bufs, &mut metas).await.unwrap();
        assert!(read >= 1);
        assert_eq!(&bufs[0][..metas[0].len], data1);
    }

    #[tokio::test]
    async fn test_capability_probe() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let b = BatchedUdpSocket::new(sock);
        let caps = b.capabilities();
        #[cfg(target_os = "linux")]
        {
            assert!(caps.has_recvmmsg);
            assert!(caps.has_sendmmsg);
            assert!(caps.has_gro);
            assert!(caps.has_gso);
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!caps.has_recvmmsg);
        }
    }

    #[tokio::test]
    async fn test_gso_transmission() {
        let srv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let srv_addr = srv.local_addr().unwrap();
        let cln = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let b_srv = BatchedUdpSocket::new(srv);
        let b_cln = BatchedUdpSocket::new(cln);

        // 2000 bytes payload with GSO segment size 1000
        let payload = vec![0x42u8; 2000];
        let pkts = [TransmitPacket {
            buf: &payload,
            addr: srv_addr,
            gso_segment_size: if b_cln.capabilities().has_gso {
                Some(1000)
            } else {
                None
            },
        }];

        let sent = b_cln.send_batch(&pkts).await.unwrap();
        assert_eq!(sent, 1);

        let mut bufs = vec![vec![0u8; 2048], vec![0u8; 2048]];
        let mut metas = vec![RecvMeta::default(), RecvMeta::default()];
        let read = b_srv.recv_batch(&mut bufs, &mut metas).await.unwrap();
        assert!(read >= 1);
    }

    #[tokio::test]
    async fn test_explicit_fallback_mode() {
        let srv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let srv_addr = srv.local_addr().unwrap();
        let cln = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Create explicit fallback sockets (forcing single-packet path)
        let b_srv = BatchedUdpSocket::new_fallback(srv);
        let b_cln = BatchedUdpSocket::new_fallback(cln);

        assert_eq!(b_srv.capabilities(), BatchCapabilities::unsupported());
        assert_eq!(b_cln.capabilities(), BatchCapabilities::unsupported());

        let payload = b"fallback-verified-packet";
        let pkts = [TransmitPacket {
            buf: payload,
            addr: srv_addr,
            gso_segment_size: None,
        }];

        let sent = b_cln.send_batch(&pkts).await.unwrap();
        assert_eq!(sent, 1);

        let mut bufs = vec![vec![0u8; 128]];
        let mut metas = vec![RecvMeta::default()];
        let read = b_srv.recv_batch(&mut bufs, &mut metas).await.unwrap();
        assert_eq!(read, 1);
        assert_eq!(&bufs[0][..metas[0].len], payload);
    }

    #[tokio::test]
    async fn test_recvmmsg_short_batch_readiness_and_no_lost_wakeups() {
        use std::time::Duration;
        let srv = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let srv_addr = srv.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let batched = BatchedUdpSocket::new(srv);

        // Send packet 1
        client.send_to(b"pkt1", srv_addr).await.unwrap();

        let mut bufs = vec![vec![0u8; 1024]; 16];
        let mut metas = vec![RecvMeta::default(); 16];

        // Read packet 1: should return 1 (< 16), and clear readiness
        let n1 = batched.recv_batch(&mut bufs, &mut metas).await.unwrap();
        assert_eq!(n1, 1);
        assert_eq!(&bufs[0][..metas[0].len], b"pkt1");

        // Send packet 2 shortly after
        client.send_to(b"pkt2", srv_addr).await.unwrap();

        // Verify packet 2 is received without losing epoll wakeup!
        let n2 = tokio::time::timeout(
            Duration::from_millis(200),
            batched.recv_batch(&mut bufs, &mut metas)
        )
        .await
        .expect("Must not deadlock or lose wakeup")
        .unwrap();

        assert_eq!(n2, 1);
        assert_eq!(&bufs[0][..metas[0].len], b"pkt2");
    }
}
