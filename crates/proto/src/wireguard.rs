use crate::error::ProtoError;

/// WireGuard packet message types per WireGuard specification (Jason A. Donenfeld, Section 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WgPacketType {
    /// Handshake Initiation message (148 bytes).
    HandshakeInitiation = 1,
    /// Handshake Response message (92 bytes).
    HandshakeResponse = 2,
    /// Cookie Reply message (64 bytes).
    CookieReply = 3,
    /// Encrypted Transport Data message (>= 32 bytes).
    Data = 4,
}

impl TryFrom<u8> for WgPacketType {
    type Error = ProtoError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(Self::HandshakeInitiation),
            2 => Ok(Self::HandshakeResponse),
            3 => Ok(Self::CookieReply),
            4 => Ok(Self::Data),
            other => Err(ProtoError::InvalidWireGuardPacket(format!(
                "unknown packet type: 0x{other:02X}"
            ))),
        }
    }
}

/// Zero-copy parsed view of a WireGuard packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgHeaderView<'a> {
    /// WireGuard message type.
    pub packet_type: WgPacketType,
    /// WireGuard receiver index for Data packets (bytes 4..8, little-endian).
    pub receiver_index: Option<u32>,
    /// WireGuard 64-bit monotonic sequence counter for Data packets (bytes 8..16, little-endian).
    pub counter: Option<u64>,
    /// Remaining payload slice.
    pub payload: &'a [u8],
}

impl<'a> WgHeaderView<'a> {
    /// Returns true if this is a control / handshake message (Types 1..3).
    #[inline]
    pub fn is_handshake(&self) -> bool {
        matches!(
            self.packet_type,
            WgPacketType::HandshakeInitiation
                | WgPacketType::HandshakeResponse
                | WgPacketType::CookieReply
        )
    }

    /// Returns true if this is an encrypted transport data packet (Type 4).
    #[inline]
    pub fn is_data(&self) -> bool {
        self.packet_type == WgPacketType::Data
    }
}

/// Inspect a WireGuard packet with zero allocations.
///
/// Returns `WgHeaderView` detailing packet type, receiver index, and 64-bit counter.
pub fn inspect_wg_packet(buf: &[u8]) -> Result<WgHeaderView<'_>, ProtoError> {
    if buf.len() < 4 {
        return Err(ProtoError::BufferTooShort {
            expected: 4,
            actual: buf.len(),
        });
    }

    let ptype = WgPacketType::try_from(buf[0])?;

    match ptype {
        WgPacketType::HandshakeInitiation => {
            if buf.len() < 148 {
                return Err(ProtoError::BufferTooShort {
                    expected: 148,
                    actual: buf.len(),
                });
            }
            Ok(WgHeaderView {
                packet_type: ptype,
                receiver_index: None,
                counter: None,
                payload: &buf[4..],
            })
        }
        WgPacketType::HandshakeResponse => {
            if buf.len() < 92 {
                return Err(ProtoError::BufferTooShort {
                    expected: 92,
                    actual: buf.len(),
                });
            }
            // Response has receiver index at bytes 8..12
            let r_idx = u32::from_le_bytes(buf[8..12].try_into().unwrap());
            Ok(WgHeaderView {
                packet_type: ptype,
                receiver_index: Some(r_idx),
                counter: None,
                payload: &buf[4..],
            })
        }
        WgPacketType::CookieReply => {
            if buf.len() < 64 {
                return Err(ProtoError::BufferTooShort {
                    expected: 64,
                    actual: buf.len(),
                });
            }
            let r_idx = u32::from_le_bytes(buf[4..8].try_into().unwrap());
            Ok(WgHeaderView {
                packet_type: ptype,
                receiver_index: Some(r_idx),
                counter: None,
                payload: &buf[4..],
            })
        }
        WgPacketType::Data => {
            // Data header: 4 bytes type+reserved, 4 bytes receiver_index, 8 bytes counter, >= 16 bytes MAC
            if buf.len() < 32 {
                return Err(ProtoError::BufferTooShort {
                    expected: 32,
                    actual: buf.len(),
                });
            }
            let receiver_index = u32::from_le_bytes(buf[4..8].try_into().unwrap());
            let counter = u64::from_le_bytes(buf[8..16].try_into().unwrap());
            Ok(WgHeaderView {
                packet_type: ptype,
                receiver_index: Some(receiver_index),
                counter: Some(counter),
                payload: &buf[16..],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_wg_data_packet() {
        let mut packet = vec![0u8; 64];
        packet[0] = 4; // Data
        packet[1..4].copy_from_slice(&[0, 0, 0]);
        // Receiver index = 0x12345678 (little endian: 78, 56, 34, 12)
        packet[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        // Counter = 10005 (little endian)
        packet[8..16].copy_from_slice(&10005u64.to_le_bytes());

        let view = inspect_wg_packet(&packet).expect("inspect wg packet");
        assert_eq!(view.packet_type, WgPacketType::Data);
        assert!(view.is_data());
        assert!(!view.is_handshake());
        assert_eq!(view.receiver_index, Some(0x1234_5678));
        assert_eq!(view.counter, Some(10005));
        assert_eq!(view.payload.len(), 48); // 64 - 16
    }

    #[test]
    fn test_inspect_handshake_initiation() {
        let mut packet = vec![0u8; 148];
        packet[0] = 1;
        let view = inspect_wg_packet(&packet).expect("inspect handshake init");
        assert_eq!(view.packet_type, WgPacketType::HandshakeInitiation);
        assert!(view.is_handshake());
        assert!(!view.is_data());
        assert_eq!(view.counter, None);
    }

    #[test]
    fn test_inspect_short_packet() {
        let packet = vec![4u8; 10]; // Short Type 4
        let res = inspect_wg_packet(&packet);
        assert!(matches!(res, Err(ProtoError::BufferTooShort { .. })));
    }
}
