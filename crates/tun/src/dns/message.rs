//! Minimal DNS wire-format handling.
//!
//! Only what a forwarding resolver needs: read the header and question of an
//! incoming query, and rewrite the header of the upstream reply so it matches
//! the client's transaction id. Everything between the question and the answer
//! is opaque bytes — the resolver does not interpret records, so it does not
//! need to understand them.
//!
//! This is deliberately not a full DNS implementation. There is no name
//! compression on the write path (queries never use it), no record parsing, and
//! no EDNS handling beyond passing the additional section through untouched.

use std::fmt;

/// Errors produced while parsing or building DNS messages.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DnsError {
    /// The message ended before the expected field.
    #[error("truncated DNS message at offset {0}")]
    Truncated(usize),
    /// A label length byte exceeded the 63-byte limit.
    #[error("DNS label too long at offset {0}")]
    LabelTooLong(usize),
    /// A name exceeded the 255-byte limit.
    #[error("DNS name too long")]
    NameTooLong,
    /// A compression pointer pointed outside the message or formed a loop.
    #[error("invalid DNS compression pointer at offset {0}")]
    BadPointer(usize),
    /// The message carried no question, which a query must.
    #[error("DNS message has no question section")]
    NoQuestion,
}

/// The record types this resolver recognises by name.
///
/// The resolver forwards everything; this enum exists so callers can ask for a
/// specific type without hard-coding numbers, and so unknown types round-trip
/// as [`RecordType::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// Host address (A).
    A,
    /// IPv6 host address (AAAA).
    Aaaa,
    /// Canonical name (CNAME).
    Cname,
    /// Pointer (PTR).
    Ptr,
    /// Mail exchange (MX).
    Mx,
    /// Text (TXT).
    Txt,
    /// Service locator (SRV).
    Srv,
    /// HTTPS binding (HTTPS).
    Https,
    /// Any type (`*`, 255).
    Any,
    /// Any other type, preserved verbatim.
    Other(u16),
}

impl RecordType {
    /// The numeric value used on the wire.
    pub fn as_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Aaaa => 28,
            RecordType::Cname => 5,
            RecordType::Ptr => 12,
            RecordType::Mx => 15,
            RecordType::Txt => 16,
            RecordType::Srv => 33,
            RecordType::Https => 65,
            RecordType::Any => 255,
            RecordType::Other(v) => v,
        }
    }

    /// Interprets a wire value, mapping unknown numbers to [`RecordType::Other`].
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            28 => RecordType::Aaaa,
            5 => RecordType::Cname,
            12 => RecordType::Ptr,
            15 => RecordType::Mx,
            16 => RecordType::Txt,
            33 => RecordType::Srv,
            65 => RecordType::Https,
            255 => RecordType::Any,
            other => RecordType::Other(other),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => f.write_str("A"),
            RecordType::Aaaa => f.write_str("AAAA"),
            RecordType::Cname => f.write_str("CNAME"),
            RecordType::Ptr => f.write_str("PTR"),
            RecordType::Mx => f.write_str("MX"),
            RecordType::Txt => f.write_str("TXT"),
            RecordType::Srv => f.write_str("SRV"),
            RecordType::Https => f.write_str("HTTPS"),
            RecordType::Any => f.write_str("ANY"),
            RecordType::Other(v) => write!(f, "TYPE{v}"),
        }
    }
}

/// A single entry from the question section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The queried name, lowercased and without a trailing dot.
    pub name: String,
    /// The queried record type.
    pub qtype: RecordType,
    /// The queried class; 1 is IN, which is all this resolver sees in practice.
    pub qclass: u16,
}

/// A parsed DNS message header plus its question section.
///
/// The body after the question is kept as a byte range so the resolver can
/// forward it without understanding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Transaction id, echoed back to the client.
    pub id: u16,
    /// Query/response flag.
    pub is_response: bool,
    /// Opcode field (0 for a standard query).
    pub opcode: u8,
    /// Authoritative-answer flag.
    pub authoritative: bool,
    /// Truncation flag.
    pub truncated: bool,
    /// Recursion-desired flag, copied from the query.
    pub recursion_desired: bool,
    /// Recursion-available flag.
    pub recursion_available: bool,
    /// Response code.
    pub rcode: u8,
    /// The question section.
    pub question: Question,
    /// Offset just past the question section, where the body begins.
    pub body_offset: usize,
}

const HEADER_LEN: usize = 12;

impl Message {
    /// Parses the header and first question of a DNS message.
    ///
    /// Only the first question is read. A query with more than one question is
    /// legal but vanishingly rare, and forwarding resolvers universally ignore
    /// the extras; the body offset returned still points past all of them only
    /// if there is exactly one, so callers that care should check
    /// [`Message::question_count`].
    pub fn parse(buf: &[u8]) -> Result<Self, DnsError> {
        if buf.len() < HEADER_LEN {
            return Err(DnsError::Truncated(buf.len()));
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);

        if qdcount == 0 {
            return Err(DnsError::NoQuestion);
        }

        let (name, mut offset) = read_name(buf, HEADER_LEN)?;

        if offset + 4 > buf.len() {
            return Err(DnsError::Truncated(offset));
        }
        let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        offset += 4;

        Ok(Message {
            id,
            is_response: flags & 0x8000 != 0,
            opcode: ((flags >> 11) & 0x0f) as u8,
            authoritative: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursion_desired: flags & 0x0100 != 0,
            recursion_available: flags & 0x0080 != 0,
            rcode: (flags & 0x000f) as u8,
            question: Question {
                name,
                qtype: RecordType::from_u16(qtype),
                qclass,
            },
            body_offset: offset,
        })
    }

    /// The number of questions declared in the header.
    ///
    /// [`Message::parse`] reads only the first; this lets a caller reject the
    /// rare multi-question query rather than forward it with a wrong body
    /// offset.
    pub fn question_count(buf: &[u8]) -> u16 {
        if buf.len() < HEADER_LEN {
            return 0;
        }
        u16::from_be_bytes([buf[4], buf[5]])
    }

    /// Builds a response header for `query`, carrying `rcode`.
    ///
    /// The question section is re-encoded from the parsed question rather than
    /// copied, so the result is well-formed even if the query used compression.
    pub fn response_for(query: &Message, rcode: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + query.question.name.len() + 6);
        out.extend_from_slice(&query.id.to_be_bytes());

        let mut flags: u16 = 0x8000; // QR = response
        flags |= (query.opcode as u16 & 0x0f) << 11;
        if query.recursion_desired {
            flags |= 0x0100;
        }
        flags |= 0x0080; // RA: this resolver always offers recursion
        flags |= rcode as u16 & 0x000f;
        out.extend_from_slice(&flags.to_be_bytes());

        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        encode_name(&query.question.name, &mut out);
        out.extend_from_slice(&query.question.qtype.as_u16().to_be_bytes());
        out.extend_from_slice(&query.question.qclass.to_be_bytes());
        out
    }

    /// Rewrites the transaction id of an upstream reply to `id`.
    ///
    /// The rest of the message is passed through untouched, including any
    /// compression pointers, which stay valid because nothing before them
    /// changes length.
    pub fn rewrite_id(reply: &mut [u8], id: u16) {
        if reply.len() >= 2 {
            reply[0..2].copy_from_slice(&id.to_be_bytes());
        }
    }
}

/// Reads a possibly-compressed name starting at `start`.
///
/// Returns the lowercased name without a trailing dot, and the offset just past
/// the name *in the original position* — a compression pointer ends the name at
/// its own position, not at the target.
fn read_name(buf: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut offset = start;
    let mut end_offset: Option<usize> = None;
    let mut jumps = 0usize;

    loop {
        if offset >= buf.len() {
            return Err(DnsError::Truncated(offset));
        }
        let len = buf[offset] as usize;

        if len == 0 {
            offset += 1;
            break;
        }

        // Top two bits set marks a compression pointer.
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= buf.len() {
                return Err(DnsError::Truncated(offset));
            }
            let target = ((len & 0x3f) << 8) | buf[offset + 1] as usize;
            if end_offset.is_none() {
                end_offset = Some(offset + 2);
            }
            // A pointer must point strictly backwards; that alone rules out
            // loops, but bound the jump count anyway so a malformed message
            // cannot spin.
            if target >= offset {
                return Err(DnsError::BadPointer(offset));
            }
            jumps += 1;
            if jumps > 128 {
                return Err(DnsError::BadPointer(offset));
            }
            offset = target;
            continue;
        }

        if len > 63 {
            return Err(DnsError::LabelTooLong(offset));
        }
        let label_start = offset + 1;
        let label_end = label_start + len;
        if label_end > buf.len() {
            return Err(DnsError::Truncated(offset));
        }

        if !name.is_empty() {
            name.push('.');
        }
        for &byte in &buf[label_start..label_end] {
            name.push(byte.to_ascii_lowercase() as char);
        }
        if name.len() > 255 {
            return Err(DnsError::NameTooLong);
        }

        offset = label_end;
    }

    Ok((name, end_offset.unwrap_or(offset)))
}

/// Writes a name in uncompressed wire form.
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a query for `name`/`qtype` with the given transaction id.
    fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        encode_name(name, &mut buf);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf
    }

    #[test]
    fn parses_a_simple_query() {
        let buf = build_query(0x1234, "example.com", 1);
        let msg = Message::parse(&buf).expect("parse");
        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response);
        assert!(msg.recursion_desired);
        assert_eq!(msg.question.name, "example.com");
        assert_eq!(msg.question.qtype, RecordType::A);
        assert_eq!(msg.question.qclass, 1);
        assert_eq!(msg.body_offset, buf.len());
    }

    #[test]
    fn lowercases_and_strips_trailing_dot() {
        let buf = build_query(1, "WWW.Example.COM", 28);
        let msg = Message::parse(&buf).expect("parse");
        assert_eq!(msg.question.name, "www.example.com");
        assert_eq!(msg.question.qtype, RecordType::Aaaa);
    }

    #[test]
    fn rejects_truncated_header() {
        assert_eq!(Message::parse(&[0u8; 5]), Err(DnsError::Truncated(5)));
    }

    #[test]
    fn rejects_message_without_question() {
        let mut buf = build_query(1, "a.com", 1);
        buf[4] = 0;
        buf[5] = 0;
        assert_eq!(Message::parse(&buf), Err(DnsError::NoQuestion));
    }

    #[test]
    fn rejects_truncated_question() {
        let buf = build_query(1, "example.com", 1);
        let cut = &buf[..buf.len() - 2];
        assert!(matches!(Message::parse(cut), Err(DnsError::Truncated(_))));
    }

    #[test]
    fn follows_a_compression_pointer() {
        // Compression pointers always point backwards, so the target has to sit
        // before the pointer. Build a buffer where the name is stored first and
        // the pointer follows it, then read the name starting at the pointer.
        let mut buf = Vec::new();
        encode_name("example.com", &mut buf);
        let pointer_offset = buf.len();
        buf.extend_from_slice(&[0xc0, 0]); // points at offset 0

        let (name, end) = read_name(&buf, pointer_offset).expect("read");
        assert_eq!(name, "example.com");
        // The name ends at the pointer, not at the target.
        assert_eq!(end, pointer_offset + 2);
    }

    #[test]
    fn parses_a_question_after_a_stored_name() {
        // A message whose question name is a pointer back into the header
        // region is not something a real resolver sends, but the parser must
        // still handle a pointer that lands on a valid name.
        let mut buf = Vec::new();
        buf.extend_from_slice(&7u16.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // Store the name at offset 12, then a question that points at it.
        let name_offset = buf.len();
        encode_name("example.com", &mut buf);
        let pointer_offset = buf.len();
        buf.extend_from_slice(&[0xc0 | (name_offset >> 8) as u8, name_offset as u8]);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());

        let (name, end) = read_name(&buf, pointer_offset).expect("read");
        assert_eq!(name, "example.com");
        assert_eq!(end, pointer_offset + 2);
    }

    #[test]
    fn rejects_forward_pointer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        // Pointer at offset 12 aimed at offset 20, which is forward.
        buf.extend_from_slice(&[0xc0, 20]);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(Message::parse(&buf), Err(DnsError::BadPointer(12)));
    }

    #[test]
    fn rejects_label_over_63_bytes() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0x0100u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        buf.push(64); // illegal length byte
        buf.extend_from_slice(&[b'a'; 64]);
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        assert_eq!(Message::parse(&buf), Err(DnsError::LabelTooLong(12)));
    }

    #[test]
    fn builds_a_response_header() {
        let query = Message::parse(&build_query(0xbeef, "example.com", 1)).expect("parse");
        let resp = Message::response_for(&query, 0);
        let parsed = Message::parse(&resp).expect("parse response");
        assert_eq!(parsed.id, 0xbeef);
        assert!(parsed.is_response);
        assert!(parsed.recursion_desired);
        assert!(parsed.recursion_available);
        assert_eq!(parsed.rcode, 0);
        assert_eq!(parsed.question.name, "example.com");
        assert_eq!(parsed.question.qtype, RecordType::A);
    }

    #[test]
    fn response_carries_rcode() {
        let query = Message::parse(&build_query(1, "example.com", 1)).expect("parse");
        let resp = Message::response_for(&query, 3); // NXDOMAIN
        let parsed = Message::parse(&resp).expect("parse response");
        assert_eq!(parsed.rcode, 3);
    }

    #[test]
    fn rewrites_transaction_id() {
        let mut reply = build_query(0x1111, "example.com", 1);
        Message::rewrite_id(&mut reply, 0x2222);
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), 0x2222);
    }

    #[test]
    fn rewrite_id_tolerates_short_buffer() {
        let mut tiny = [0u8; 1];
        Message::rewrite_id(&mut tiny, 5);
        assert_eq!(tiny[0], 0);
    }

    #[test]
    fn record_type_round_trips() {
        for value in [1u16, 28, 5, 12, 15, 16, 33, 65, 255, 999] {
            assert_eq!(RecordType::from_u16(value).as_u16(), value);
        }
        assert_eq!(RecordType::from_u16(1), RecordType::A);
        assert_eq!(RecordType::from_u16(999), RecordType::Other(999));
    }

    #[test]
    fn question_count_reads_header() {
        let buf = build_query(1, "a.com", 1);
        assert_eq!(Message::question_count(&buf), 1);
        assert_eq!(Message::question_count(&[0u8; 3]), 0);
    }

    #[test]
    fn encodes_root_name() {
        let mut out = Vec::new();
        encode_name("", &mut out);
        assert_eq!(out, vec![0]);
    }
}
