use crate::error::TurnError;
use bytes::{BufMut, Bytes, BytesMut};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

type HmacSha1 = Hmac<Sha1>;

pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
pub const STUN_HEADER_LEN: usize = 20;

// Message Types
pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;
pub const ALLOCATE_REQUEST: u16 = 0x0003;
pub const ALLOCATE_RESPONSE: u16 = 0x0103;
pub const ALLOCATE_ERROR_RESPONSE: u16 = 0x0113;
pub const REFRESH_REQUEST: u16 = 0x0004;
pub const REFRESH_RESPONSE: u16 = 0x0104;
pub const CREATE_PERMISSION_REQUEST: u16 = 0x0008;
pub const CREATE_PERMISSION_RESPONSE: u16 = 0x0108;
pub const CHANNEL_BIND_REQUEST: u16 = 0x0009;
pub const CHANNEL_BIND_RESPONSE: u16 = 0x0109;
pub const SEND_INDICATION: u16 = 0x0016;
pub const DATA_INDICATION: u16 = 0x0017;

// Attributes
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;

/// STUN Attribute representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunAttribute {
    MappedAddress(SocketAddr),
    Username(String),
    MessageIntegrity([u8; 20]),
    ErrorCode { code: u16, reason: String },
    Realm(String),
    Nonce(String),
    XorMappedAddress(SocketAddr),
    XorRelayedAddress(SocketAddr),
    XorPeerAddress(SocketAddr),
    Lifetime(u32),
    RequestedTransport(u8),
    ChannelNumber(u16),
    Data(Bytes),
    Raw { attr_type: u16, value: Bytes },
}

/// Parsed STUN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    pub message_type: u16,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    pub fn new(message_type: u16, transaction_id: [u8; 12]) -> Self {
        Self {
            message_type,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    pub fn with_attribute(mut self, attr: StunAttribute) -> Self {
        self.attributes.push(attr);
        self
    }

    /// Retrieve the first attribute matching ErrorCode.
    pub fn error_code(&self) -> Option<(u16, &str)> {
        for attr in &self.attributes {
            if let StunAttribute::ErrorCode { code, reason } = attr {
                return Some((*code, reason.as_str()));
            }
        }
        None
    }

    /// Retrieve Realm attribute string.
    pub fn realm(&self) -> Option<&str> {
        for attr in &self.attributes {
            if let StunAttribute::Realm(r) = attr {
                return Some(r.as_str());
            }
        }
        None
    }

    /// Retrieve Nonce attribute string.
    pub fn nonce(&self) -> Option<&str> {
        for attr in &self.attributes {
            if let StunAttribute::Nonce(n) = attr {
                return Some(n.as_str());
            }
        }
        None
    }

    /// Retrieve XorRelayedAddress attribute.
    pub fn relayed_address(&self) -> Option<SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::XorRelayedAddress(addr) = attr {
                return Some(*addr);
            }
        }
        None
    }

    /// Retrieve Lifetime attribute in seconds.
    pub fn lifetime(&self) -> Option<u32> {
        for attr in &self.attributes {
            if let StunAttribute::Lifetime(sec) = attr {
                return Some(*sec);
            }
        }
        None
    }

    /// Encode STUN message into binary buffer.
    pub fn encode(&self) -> BytesMut {
        let mut body = BytesMut::new();
        for attr in &self.attributes {
            attr.encode(&self.transaction_id, &mut body);
        }

        let mut msg = BytesMut::with_capacity(STUN_HEADER_LEN + body.len());
        msg.put_u16(self.message_type);
        msg.put_u16(body.len() as u16);
        msg.put_u32(STUN_MAGIC_COOKIE);
        msg.put_slice(&self.transaction_id);
        msg.put_slice(&body);
        msg
    }

    /// Encode message and append MESSAGE-INTEGRITY attribute with given key.
    pub fn encode_with_integrity(&self, key: &[u8]) -> BytesMut {
        let mut msg = self.clone();
        // Remove any prior message integrity
        msg.attributes
            .retain(|a| !matches!(a, StunAttribute::MessageIntegrity(_)));

        let mut body = BytesMut::new();
        for attr in &msg.attributes {
            attr.encode(&msg.transaction_id, &mut body);
        }

        // When calculating MessageIntegrity, the message length must include the
        // MessageIntegrity attribute itself (4 bytes header + 20 bytes digest = 24 bytes).
        let total_body_len = (body.len() + 24) as u16;

        let mut to_hash = BytesMut::with_capacity(STUN_HEADER_LEN + body.len());
        to_hash.put_u16(msg.message_type);
        to_hash.put_u16(total_body_len);
        to_hash.put_u32(STUN_MAGIC_COOKIE);
        to_hash.put_slice(&msg.transaction_id);
        to_hash.put_slice(&body);

        let mut mac = HmacSha1::new_from_slice(key).expect("HMAC can take any key length");
        mac.update(&to_hash);
        let digest = mac.finalize().into_bytes();

        let mut integrity_attr = [0u8; 20];
        integrity_attr.copy_from_slice(&digest);

        msg.attributes
            .push(StunAttribute::MessageIntegrity(integrity_attr));
        msg.encode()
    }

    /// Parse a STUN message from buffer.
    pub fn decode(buf: &[u8]) -> Result<Self, TurnError> {
        if buf.len() < STUN_HEADER_LEN {
            return Err(TurnError::BufferTooShort {
                expected: STUN_HEADER_LEN,
                actual: buf.len(),
            });
        }

        let message_type = u16::from_be_bytes([buf[0], buf[1]]);
        let message_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != STUN_MAGIC_COOKIE {
            return Err(TurnError::InvalidMagicCookie(cookie));
        }

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&buf[8..20]);

        if buf.len() < STUN_HEADER_LEN + message_len {
            return Err(TurnError::BufferTooShort {
                expected: STUN_HEADER_LEN + message_len,
                actual: buf.len(),
            });
        }

        let mut attributes = Vec::new();
        let mut offset = STUN_HEADER_LEN;
        let end = STUN_HEADER_LEN + message_len;

        while offset < end {
            if offset + 4 > end {
                break;
            }
            let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > end {
                return Err(TurnError::BufferTooShort {
                    expected: offset + attr_len,
                    actual: end,
                });
            }

            let attr_val = &buf[offset..offset + attr_len];
            let attr = StunAttribute::decode(attr_type, attr_val, &transaction_id)?;
            attributes.push(attr);

            // Padding to 4 bytes boundary
            let padding = (4 - (attr_len % 4)) % 4;
            offset += attr_len + padding;
        }

        Ok(Self {
            message_type,
            transaction_id,
            attributes,
        })
    }
}

impl StunAttribute {
    pub fn encode(&self, transaction_id: &[u8; 12], out: &mut BytesMut) {
        match self {
            Self::MappedAddress(addr) => {
                encode_raw_address(ATTR_MAPPED_ADDRESS, *addr, out);
            }
            Self::XorMappedAddress(addr) => {
                encode_xor_address(ATTR_XOR_MAPPED_ADDRESS, *addr, transaction_id, out);
            }
            Self::XorRelayedAddress(addr) => {
                encode_xor_address(ATTR_XOR_RELAYED_ADDRESS, *addr, transaction_id, out);
            }
            Self::XorPeerAddress(addr) => {
                encode_xor_address(ATTR_XOR_PEER_ADDRESS, *addr, transaction_id, out);
            }
            Self::Username(user) => {
                encode_tlv(ATTR_USERNAME, user.as_bytes(), out);
            }
            Self::Realm(realm) => {
                encode_tlv(ATTR_REALM, realm.as_bytes(), out);
            }
            Self::Nonce(nonce) => {
                encode_tlv(ATTR_NONCE, nonce.as_bytes(), out);
            }
            Self::Lifetime(sec) => {
                encode_tlv(ATTR_LIFETIME, &sec.to_be_bytes(), out);
            }
            Self::RequestedTransport(proto) => {
                let mut val = [0u8; 4];
                val[0] = *proto;
                encode_tlv(ATTR_REQUESTED_TRANSPORT, &val, out);
            }
            Self::ChannelNumber(num) => {
                let mut val = [0u8; 4];
                val[0..2].copy_from_slice(&num.to_be_bytes());
                encode_tlv(ATTR_CHANNEL_NUMBER, &val, out);
            }
            Self::MessageIntegrity(digest) => {
                encode_tlv(ATTR_MESSAGE_INTEGRITY, digest, out);
            }
            Self::ErrorCode { code, reason } => {
                let mut val = Vec::with_capacity(4 + reason.len());
                val.push(0);
                val.push(0);
                val.push((code / 100) as u8);
                val.push((code % 100) as u8);
                val.extend_from_slice(reason.as_bytes());
                encode_tlv(ATTR_ERROR_CODE, &val, out);
            }
            Self::Data(data) => {
                encode_tlv(ATTR_DATA, data, out);
            }
            Self::Raw { attr_type, value } => {
                encode_tlv(*attr_type, value, out);
            }
        }
    }

    pub fn decode(attr_type: u16, val: &[u8], tx_id: &[u8; 12]) -> Result<Self, TurnError> {
        match attr_type {
            ATTR_MAPPED_ADDRESS => {
                let addr = decode_raw_address(val)?;
                Ok(Self::MappedAddress(addr))
            }
            ATTR_XOR_MAPPED_ADDRESS => {
                let addr = decode_xor_address(val, tx_id)?;
                Ok(Self::XorMappedAddress(addr))
            }
            ATTR_XOR_RELAYED_ADDRESS => {
                let addr = decode_xor_address(val, tx_id)?;
                Ok(Self::XorRelayedAddress(addr))
            }
            ATTR_XOR_PEER_ADDRESS => {
                let addr = decode_xor_address(val, tx_id)?;
                Ok(Self::XorPeerAddress(addr))
            }
            ATTR_USERNAME => {
                let s = String::from_utf8_lossy(val).to_string();
                Ok(Self::Username(s))
            }
            ATTR_REALM => {
                let s = String::from_utf8_lossy(val).to_string();
                Ok(Self::Realm(s))
            }
            ATTR_NONCE => {
                let s = String::from_utf8_lossy(val).to_string();
                Ok(Self::Nonce(s))
            }
            ATTR_LIFETIME => {
                if val.len() < 4 {
                    return Err(TurnError::BufferTooShort {
                        expected: 4,
                        actual: val.len(),
                    });
                }
                let sec = u32::from_be_bytes(val[..4].try_into().unwrap());
                Ok(Self::Lifetime(sec))
            }
            ATTR_REQUESTED_TRANSPORT => {
                if val.is_empty() {
                    return Err(TurnError::BufferTooShort {
                        expected: 1,
                        actual: 0,
                    });
                }
                Ok(Self::RequestedTransport(val[0]))
            }
            ATTR_CHANNEL_NUMBER => {
                if val.len() < 2 {
                    return Err(TurnError::BufferTooShort {
                        expected: 2,
                        actual: val.len(),
                    });
                }
                let num = u16::from_be_bytes(val[..2].try_into().unwrap());
                Ok(Self::ChannelNumber(num))
            }
            ATTR_MESSAGE_INTEGRITY => {
                if val.len() < 20 {
                    return Err(TurnError::BufferTooShort {
                        expected: 20,
                        actual: val.len(),
                    });
                }
                let mut digest = [0u8; 20];
                digest.copy_from_slice(&val[..20]);
                Ok(Self::MessageIntegrity(digest))
            }
            ATTR_ERROR_CODE => {
                if val.len() < 4 {
                    return Err(TurnError::BufferTooShort {
                        expected: 4,
                        actual: val.len(),
                    });
                }
                let class = val[2] as u16;
                let number = val[3] as u16;
                let code = class * 100 + number;
                let reason = String::from_utf8_lossy(&val[4..]).to_string();
                Ok(Self::ErrorCode { code, reason })
            }
            ATTR_DATA => Ok(Self::Data(Bytes::copy_from_slice(val))),
            _ => Ok(Self::Raw {
                attr_type,
                value: Bytes::copy_from_slice(val),
            }),
        }
    }
}

/// Compute long-term credential key: MD5(username:realm:password).
pub fn compute_long_term_key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let input = format!("{username}:{realm}:{password}");
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

fn encode_tlv(attr_type: u16, val: &[u8], out: &mut BytesMut) {
    out.put_u16(attr_type);
    out.put_u16(val.len() as u16);
    out.put_slice(val);
    let padding = (4 - (val.len() % 4)) % 4;
    for _ in 0..padding {
        out.put_u8(0);
    }
}

fn encode_raw_address(attr_type: u16, addr: SocketAddr, out: &mut BytesMut) {
    match addr {
        SocketAddr::V4(v4) => {
            let mut val = [0u8; 8];
            val[1] = 0x01; // IPv4
            val[2..4].copy_from_slice(&v4.port().to_be_bytes());
            val[4..8].copy_from_slice(&v4.ip().octets());
            encode_tlv(attr_type, &val, out);
        }
        SocketAddr::V6(v6) => {
            let mut val = [0u8; 20];
            val[1] = 0x02; // IPv6
            val[2..4].copy_from_slice(&v6.port().to_be_bytes());
            val[4..20].copy_from_slice(&v6.ip().octets());
            encode_tlv(attr_type, &val, out);
        }
    }
}

fn decode_raw_address(val: &[u8]) -> Result<SocketAddr, TurnError> {
    if val.len() < 4 {
        return Err(TurnError::BufferTooShort {
            expected: 4,
            actual: val.len(),
        });
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);
    match family {
        0x01 => {
            if val.len() < 8 {
                return Err(TurnError::BufferTooShort {
                    expected: 8,
                    actual: val.len(),
                });
            }
            let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            if val.len() < 20 {
                return Err(TurnError::BufferTooShort {
                    expected: 20,
                    actual: val.len(),
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&val[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(TurnError::UnknownAttribute(family as u16)),
    }
}

fn encode_xor_address(
    attr_type: u16,
    addr: SocketAddr,
    transaction_id: &[u8; 12],
    out: &mut BytesMut,
) {
    let cookie_high = (STUN_MAGIC_COOKIE >> 16) as u16;
    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();

    match addr {
        SocketAddr::V4(v4) => {
            let mut val = [0u8; 8];
            val[1] = 0x01;
            let xor_port = v4.port() ^ cookie_high;
            val[2..4].copy_from_slice(&xor_port.to_be_bytes());
            let octets = v4.ip().octets();
            let mut xor_ip = [0u8; 4];
            for i in 0..4 {
                xor_ip[i] = octets[i] ^ cookie_bytes[i];
            }
            val[4..8].copy_from_slice(&xor_ip);
            encode_tlv(attr_type, &val, out);
        }
        SocketAddr::V6(v6) => {
            let mut val = [0u8; 20];
            val[1] = 0x02;
            let xor_port = v6.port() ^ cookie_high;
            val[2..4].copy_from_slice(&xor_port.to_be_bytes());
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&cookie_bytes);
            xor_key[4..16].copy_from_slice(transaction_id);
            let octets = v6.ip().octets();
            let mut xor_ip = [0u8; 16];
            for i in 0..16 {
                xor_ip[i] = octets[i] ^ xor_key[i];
            }
            val[4..20].copy_from_slice(&xor_ip);
            encode_tlv(attr_type, &val, out);
        }
    }
}

fn decode_xor_address(val: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr, TurnError> {
    if val.len() < 4 {
        return Err(TurnError::BufferTooShort {
            expected: 4,
            actual: val.len(),
        });
    }
    let family = val[1];
    let cookie_high = (STUN_MAGIC_COOKIE >> 16) as u16;
    let raw_port = u16::from_be_bytes([val[2], val[3]]);
    let port = raw_port ^ cookie_high;
    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();

    match family {
        0x01 => {
            if val.len() < 8 {
                return Err(TurnError::BufferTooShort {
                    expected: 8,
                    actual: val.len(),
                });
            }
            let mut ip_octets = [0u8; 4];
            for i in 0..4 {
                ip_octets[i] = val[4 + i] ^ cookie_bytes[i];
            }
            let ip = Ipv4Addr::from(ip_octets);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            if val.len() < 20 {
                return Err(TurnError::BufferTooShort {
                    expected: 20,
                    actual: val.len(),
                });
            }
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(&cookie_bytes);
            xor_key[4..16].copy_from_slice(transaction_id);
            let mut ip_octets = [0u8; 16];
            for i in 0..16 {
                ip_octets[i] = val[4 + i] ^ xor_key[i];
            }
            let ip = Ipv6Addr::from(ip_octets);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(TurnError::UnknownAttribute(family as u16)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_binding_encode_decode() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let msg = StunMessage::new(BINDING_REQUEST, tx_id);
        let bytes = msg.encode();

        let decoded = StunMessage::decode(&bytes).expect("decode stun message");
        assert_eq!(decoded.message_type, BINDING_REQUEST);
        assert_eq!(decoded.transaction_id, tx_id);
        assert!(decoded.attributes.is_empty());
    }

    #[test]
    fn test_stun_xor_relayed_address() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let target_addr: SocketAddr = "192.0.2.1:54321".parse().unwrap();
        let msg = StunMessage::new(ALLOCATE_RESPONSE, tx_id)
            .with_attribute(StunAttribute::XorRelayedAddress(target_addr))
            .with_attribute(StunAttribute::Lifetime(600));

        let bytes = msg.encode();
        let decoded = StunMessage::decode(&bytes).expect("decode allocate response");

        assert_eq!(decoded.relayed_address(), Some(target_addr));
        assert_eq!(decoded.lifetime(), Some(600));
    }

    #[test]
    fn test_stun_message_integrity_calculation() {
        let tx_id = [0xAA; 12];
        let key = compute_long_term_key("alice", "example.org", "secretpass");
        let msg = StunMessage::new(ALLOCATE_REQUEST, tx_id)
            .with_attribute(StunAttribute::Username("alice".into()))
            .with_attribute(StunAttribute::Realm("example.org".into()))
            .with_attribute(StunAttribute::Nonce("nonce-val".into()));

        let bytes = msg.encode_with_integrity(&key);
        let decoded = StunMessage::decode(&bytes).expect("decode message with integrity");

        let mut has_integrity = false;
        for attr in &decoded.attributes {
            if let StunAttribute::MessageIntegrity(_) = attr {
                has_integrity = true;
            }
        }
        assert!(has_integrity);
    }
}
