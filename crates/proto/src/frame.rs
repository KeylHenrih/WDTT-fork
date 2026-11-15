use crate::error::ProtoError;
use bytes::{BufMut, BytesMut};

/// Protocol magic byte for WDTT v2 binary frames.
pub const WDTT_MAGIC: u8 = 0xD2;

/// Frame header length in bytes.
pub const FRAME_HEADER_LEN: usize = 8;

/// Frame flags bitmask.
pub mod flags {
    /// Resets stream sequence counter / resequencer state.
    pub const REORDER_RESET: u8 = 0x01;
    /// Marks the last fragment of a fragmented frame.
    pub const LAST_FRAG: u8 = 0x02;
    /// Indicates pre-auth knock payload attached on handshake.
    pub const PRE_AUTH_KNOCK: u8 = 0x04;
    /// Indicates variable padding bytes present at tail.
    pub const PADDING_PRESENT: u8 = 0x08;
}

/// WDTT v2 Frame Type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// Standard tunneled WireGuard data packet.
    Data = 0x01,
    /// Fragmented data frame chunk.
    Frag = 0x02,
    /// Pre-auth handshake initiation request.
    HandshakeInit = 0x03,
    /// Pre-auth handshake response.
    HandshakeResp = 0x04,
    /// RTT and latency measurement probe.
    Ping = 0x05,
    /// RTT and latency measurement probe response.
    Pong = 0x06,
    /// Measured reorder depth and path metrics feedback.
    StreamFeedback = 0x07,
    /// Session graceful disconnect.
    Disconnect = 0x08,
}

impl TryFrom<u8> for FrameType {
    type Error = ProtoError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x01 => Ok(Self::Data),
            0x02 => Ok(Self::Frag),
            0x03 => Ok(Self::HandshakeInit),
            0x04 => Ok(Self::HandshakeResp),
            0x05 => Ok(Self::Ping),
            0x06 => Ok(Self::Pong),
            0x07 => Ok(Self::StreamFeedback),
            0x08 => Ok(Self::Disconnect),
            other => Err(ProtoError::InvalidFrameType(other)),
        }
    }
}

/// 8-byte WDTT v2 binary frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Frame payload type.
    pub frame_type: FrameType,
    /// TURN / transport stream identifier (0..=255).
    pub stream_id: u8,
    /// Flags bitmask (e.g. `REORDER_RESET`, `LAST_FRAG`).
    pub flags: u8,
    /// 16-bit monotonic sequence number within this stream.
    pub seq: u16,
    /// Length of payload immediately following this header.
    pub len: u16,
}

impl FrameHeader {
    /// Construct a new frame header.
    #[inline]
    pub const fn new(frame_type: FrameType, stream_id: u8, flags: u8, seq: u16, len: u16) -> Self {
        Self {
            frame_type,
            stream_id,
            flags,
            seq,
            len,
        }
    }

    /// Serialize this 8-byte header into the destination buffer.
    #[inline]
    pub fn encode(&self, dst: &mut [u8; FRAME_HEADER_LEN]) {
        dst[0] = WDTT_MAGIC;
        dst[1] = self.frame_type as u8;
        dst[2] = self.stream_id;
        dst[3] = self.flags;
        dst[4..6].copy_from_slice(&self.seq.to_be_bytes());
        dst[6..8].copy_from_slice(&self.len.to_be_bytes());
    }

    /// Parse header from exactly 8 bytes.
    #[inline]
    pub fn decode(src: &[u8; FRAME_HEADER_LEN]) -> Result<Self, ProtoError> {
        if src[0] != WDTT_MAGIC {
            return Err(ProtoError::InvalidMagic {
                expected: WDTT_MAGIC,
                actual: src[0],
            });
        }
        let frame_type = FrameType::try_from(src[1])?;
        let stream_id = src[2];
        let flags = src[3];
        let seq = u16::from_be_bytes([src[4], src[5]]);
        let len = u16::from_be_bytes([src[6], src[7]]);

        Ok(Self {
            frame_type,
            stream_id,
            flags,
            seq,
            len,
        })
    }
}

/// Zero-copy parsed view over a complete frame (header + payload slice).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameView<'a> {
    pub header: FrameHeader,
    pub payload: &'a [u8],
}

impl<'a> FrameView<'a> {
    /// Decode a frame view from an arbitrary buffer slice.
    /// Returns `(FrameView, consumed_bytes)`.
    pub fn decode(buf: &'a [u8]) -> Result<(Self, usize), ProtoError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(ProtoError::BufferTooShort {
                expected: FRAME_HEADER_LEN,
                actual: buf.len(),
            });
        }

        let mut header_bytes = [0u8; FRAME_HEADER_LEN];
        header_bytes.copy_from_slice(&buf[..FRAME_HEADER_LEN]);
        let header = FrameHeader::decode(&header_bytes)?;

        let total_len = FRAME_HEADER_LEN + (header.len as usize);
        if buf.len() < total_len {
            return Err(ProtoError::PayloadLengthMismatch {
                header_len: header.len as usize,
                actual_len: buf.len() - FRAME_HEADER_LEN,
            });
        }

        let payload = &buf[FRAME_HEADER_LEN..total_len];
        Ok((FrameView { header, payload }, total_len))
    }
}

/// Encode a frame (header + payload) into an output `BytesMut` buffer.
pub fn encode_frame(
    frame_type: FrameType,
    stream_id: u8,
    flags: u8,
    seq: u16,
    payload: &[u8],
    out: &mut BytesMut,
) {
    let len = payload.len() as u16;
    let header = FrameHeader::new(frame_type, stream_id, flags, seq, len);
    let mut header_buf = [0u8; FRAME_HEADER_LEN];
    header.encode(&mut header_buf);

    out.reserve(FRAME_HEADER_LEN + payload.len());
    out.put_slice(&header_buf);
    out.put_slice(payload);
}

// ---------------- Control Frame Payloads ----------------

/// Payload for `FrameType::Ping` (10 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingPayload {
    /// Monotonic timestamp in milliseconds or microseconds.
    pub timestamp: u64,
    /// Probe sequence ID.
    pub probe_id: u16,
}

impl PingPayload {
    pub const LEN: usize = 10;

    pub fn encode(&self, dst: &mut [u8; Self::LEN]) {
        dst[0..8].copy_from_slice(&self.timestamp.to_be_bytes());
        dst[8..10].copy_from_slice(&self.probe_id.to_be_bytes());
    }

    pub fn decode(src: &[u8]) -> Result<Self, ProtoError> {
        if src.len() < Self::LEN {
            return Err(ProtoError::BufferTooShort {
                expected: Self::LEN,
                actual: src.len(),
            });
        }
        let timestamp = u64::from_be_bytes(src[0..8].try_into().unwrap());
        let probe_id = u16::from_be_bytes(src[8..10].try_into().unwrap());
        Ok(Self {
            timestamp,
            probe_id,
        })
    }
}

/// Payload for `FrameType::Pong` (18 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PongPayload {
    /// Echoed sender timestamp from Ping.
    pub echo_timestamp: u64,
    /// Probe sequence ID.
    pub probe_id: u16,
    /// Receiver timestamp when Ping arrived.
    pub receive_timestamp: u64,
}

impl PongPayload {
    pub const LEN: usize = 18;

    pub fn encode(&self, dst: &mut [u8; Self::LEN]) {
        dst[0..8].copy_from_slice(&self.echo_timestamp.to_be_bytes());
        dst[8..10].copy_from_slice(&self.probe_id.to_be_bytes());
        dst[10..18].copy_from_slice(&self.receive_timestamp.to_be_bytes());
    }

    pub fn decode(src: &[u8]) -> Result<Self, ProtoError> {
        if src.len() < Self::LEN {
            return Err(ProtoError::BufferTooShort {
                expected: Self::LEN,
                actual: src.len(),
            });
        }
        let echo_timestamp = u64::from_be_bytes(src[0..8].try_into().unwrap());
        let probe_id = u16::from_be_bytes(src[8..10].try_into().unwrap());
        let receive_timestamp = u64::from_be_bytes(src[10..18].try_into().unwrap());
        Ok(Self {
            echo_timestamp,
            probe_id,
            receive_timestamp,
        })
    }
}

/// Payload for `FrameType::StreamFeedback` (9 bytes).
/// Transmits measured reordering depth and path metrics back to sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamFeedbackPayload {
    /// Stream identifier being reported.
    pub stream_id: u8,
    /// Measured reorder depth in packets at receiver resequencer.
    pub measured_reorder_depth: u16,
    /// Measured smoothed RTT in milliseconds.
    pub rtt_ms: u16,
    /// Estimated packet loss in parts per million (PPM).
    pub loss_ppm: u32,
}

impl StreamFeedbackPayload {
    pub const LEN: usize = 9;

    pub fn encode(&self, dst: &mut [u8; Self::LEN]) {
        dst[0] = self.stream_id;
        dst[1..3].copy_from_slice(&self.measured_reorder_depth.to_be_bytes());
        dst[3..5].copy_from_slice(&self.rtt_ms.to_be_bytes());
        dst[5..9].copy_from_slice(&self.loss_ppm.to_be_bytes());
    }

    pub fn decode(src: &[u8]) -> Result<Self, ProtoError> {
        if src.len() < Self::LEN {
            return Err(ProtoError::BufferTooShort {
                expected: Self::LEN,
                actual: src.len(),
            });
        }
        let stream_id = src[0];
        let measured_reorder_depth = u16::from_be_bytes(src[1..3].try_into().unwrap());
        let rtt_ms = u16::from_be_bytes(src[3..5].try_into().unwrap());
        let loss_ppm = u32::from_be_bytes(src[5..9].try_into().unwrap());
        Ok(Self {
            stream_id,
            measured_reorder_depth,
            rtt_ms,
            loss_ppm,
        })
    }
}

/// Payload for `FrameType::HandshakeInit` (49 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeInitPayload {
    pub version: u8,
    pub session_id: [u8; 16],
    pub client_nonce: [u8; 16],
    pub auth_tag: [u8; 16],
}

impl HandshakeInitPayload {
    pub const LEN: usize = 49;

    pub fn encode(&self, dst: &mut [u8; Self::LEN]) {
        dst[0] = self.version;
        dst[1..17].copy_from_slice(&self.session_id);
        dst[17..33].copy_from_slice(&self.client_nonce);
        dst[33..49].copy_from_slice(&self.auth_tag);
    }

    pub fn decode(src: &[u8]) -> Result<Self, ProtoError> {
        if src.len() < Self::LEN {
            return Err(ProtoError::BufferTooShort {
                expected: Self::LEN,
                actual: src.len(),
            });
        }
        let version = src[0];
        let mut session_id = [0u8; 16];
        let mut client_nonce = [0u8; 16];
        let mut auth_tag = [0u8; 16];
        session_id.copy_from_slice(&src[1..17]);
        client_nonce.copy_from_slice(&src[17..33]);
        auth_tag.copy_from_slice(&src[33..49]);
        Ok(Self {
            version,
            session_id,
            client_nonce,
            auth_tag,
        })
    }
}

/// Payload for `FrameType::HandshakeResp` (50 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRespPayload {
    pub version: u8,
    pub status: u8,
    pub session_id: [u8; 16],
    pub server_nonce: [u8; 16],
    pub auth_tag: [u8; 16],
}

impl HandshakeRespPayload {
    pub const LEN: usize = 50;

    pub fn encode(&self, dst: &mut [u8; Self::LEN]) {
        dst[0] = self.version;
        dst[1] = self.status;
        dst[2..18].copy_from_slice(&self.session_id);
        dst[18..34].copy_from_slice(&self.server_nonce);
        dst[34..50].copy_from_slice(&self.auth_tag);
    }

    pub fn decode(src: &[u8]) -> Result<Self, ProtoError> {
        if src.len() < Self::LEN {
            return Err(ProtoError::BufferTooShort {
                expected: Self::LEN,
                actual: src.len(),
            });
        }
        let version = src[0];
        let status = src[1];
        let mut session_id = [0u8; 16];
        let mut server_nonce = [0u8; 16];
        let mut auth_tag = [0u8; 16];
        session_id.copy_from_slice(&src[2..18]);
        server_nonce.copy_from_slice(&src[18..34]);
        auth_tag.copy_from_slice(&src[34..50]);
        Ok(Self {
            version,
            status,
            session_id,
            server_nonce,
            auth_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode_roundtrip() {
        let mut buf = BytesMut::new();
        let payload = b"Hello, WireGuard over TURN!";
        encode_frame(
            FrameType::Data,
            3,
            flags::REORDER_RESET,
            42,
            payload,
            &mut buf,
        );

        let (view, consumed) = FrameView::decode(&buf).expect("decode frame");
        assert_eq!(consumed, buf.len());
        assert_eq!(view.header.frame_type, FrameType::Data);
        assert_eq!(view.header.stream_id, 3);
        assert_eq!(view.header.flags, flags::REORDER_RESET);
        assert_eq!(view.header.seq, 42);
        assert_eq!(view.header.len, payload.len() as u16);
        assert_eq!(view.payload, payload);
    }

    #[test]
    fn test_invalid_magic() {
        let mut raw = [0u8; 10];
        raw[0] = 0xAA; // invalid magic
        assert!(matches!(
            FrameHeader::decode(&raw[..8].try_into().unwrap()),
            Err(ProtoError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn test_ping_pong_payload() {
        let ping = PingPayload {
            timestamp: 1_700_000_123,
            probe_id: 99,
        };
        let mut pbuf = [0u8; PingPayload::LEN];
        ping.encode(&mut pbuf);
        let decoded_ping = PingPayload::decode(&pbuf).expect("decode ping");
        assert_eq!(ping, decoded_ping);

        let pong = PongPayload {
            echo_timestamp: 1_700_000_123,
            probe_id: 99,
            receive_timestamp: 1_700_000_145,
        };
        let mut pong_buf = [0u8; PongPayload::LEN];
        pong.encode(&mut pong_buf);
        let decoded_pong = PongPayload::decode(&pong_buf).expect("decode pong");
        assert_eq!(pong, decoded_pong);
    }

    #[test]
    fn test_stream_feedback_payload() {
        let feedback = StreamFeedbackPayload {
            stream_id: 2,
            measured_reorder_depth: 14,
            rtt_ms: 28,
            loss_ppm: 500, // 0.05%
        };
        let mut fbuf = [0u8; StreamFeedbackPayload::LEN];
        feedback.encode(&mut fbuf);
        let decoded = StreamFeedbackPayload::decode(&fbuf).expect("decode feedback");
        assert_eq!(feedback, decoded);
    }
}
