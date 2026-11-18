//! Geo data: a hand-written parser for the v2ray `.dat` protobuf format.
//!
//! The format is small and stable, so the wire encoding is decoded directly
//! rather than pulling in a protobuf runtime and a build script. Two files are
//! understood:
//!
//! * `geoip.dat` — `GeoIPList { repeated GeoIP entry = 1 }`, where
//!   `GeoIP { string country_code = 1; repeated CIDR cidr = 2 }` and
//!   `CIDR { bytes ip = 1; uint32 prefix = 2 }`.
//! * `geosite.dat` — `GeoSiteList { repeated GeoSite entry = 1 }`, where
//!   `GeoSite { string country_code = 1; repeated Domain domain = 2 }` and
//!   `Domain { Type type = 1; string value = 2 }`.
//!
//! Only the fields needed for routing are decoded; unknown fields are skipped
//! by their wire type, which keeps the parser working when the upstream files
//! gain new fields.

pub mod download;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::routing::matcher::{Cidr, DomainMatcher, DomainPattern, IpMatcher};

pub use download::{GeoDownloader, GeoError, GeoFiles};

/// Protobuf wire types.
const WIRE_VARINT: u8 = 0;
const WIRE_64BIT: u8 = 1;
const WIRE_LENGTH: u8 = 2;
const WIRE_32BIT: u8 = 5;

/// `Domain.Type` values used by the v2ray geosite format.
const DOMAIN_PLAIN: u64 = 0;
const DOMAIN_REGEX: u64 = 1;
const DOMAIN_SUFFIX: u64 = 2;
const DOMAIN_FULL: u64 = 3;

/// Errors raised while decoding a `.dat` file.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GeoParseError {
    /// The buffer ended in the middle of a field.
    #[error("truncated protobuf input at offset {0}")]
    Truncated(usize),
    /// A varint ran past ten bytes without terminating.
    #[error("varint overflow at offset {0}")]
    VarintOverflow(usize),
    /// A length-delimited field declared more bytes than remain.
    #[error("length-delimited field at offset {0} exceeds the buffer")]
    LengthOverflow(usize),
    /// A field used a wire type the parser does not know.
    #[error("unsupported wire type {wire} at offset {offset}")]
    UnsupportedWire {
        /// The wire type encountered.
        wire: u8,
        /// Offset of the field.
        offset: usize,
    },
    /// A CIDR entry carried an address that is neither 4 nor 16 bytes.
    #[error("CIDR entry has {0}-byte address, expected 4 or 16")]
    BadAddressLength(usize),
    /// A CIDR entry carried a prefix length out of range.
    #[error("CIDR entry has invalid prefix {0}")]
    BadPrefix(u32),
    /// A domain entry carried a pattern that failed to compile.
    #[error("invalid domain pattern {0:?}")]
    BadDomain(String),
}

/// A cursor over a protobuf byte slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_varint(&mut self) -> Result<u64, GeoParseError> {
        let start = self.pos;
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            if self.pos >= self.buf.len() {
                return Err(GeoParseError::Truncated(start));
            }
            let byte = self.buf[self.pos];
            self.pos += 1;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err(GeoParseError::VarintOverflow(start));
            }
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], GeoParseError> {
        let start = self.pos;
        let end = start
            .checked_add(len)
            .ok_or(GeoParseError::LengthOverflow(start))?;
        if end > self.buf.len() {
            return Err(GeoParseError::LengthOverflow(start));
        }
        self.pos = end;
        Ok(&self.buf[start..end])
    }

    fn read_fixed32(&mut self) -> Result<u32, GeoParseError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_fixed64(&mut self) -> Result<u64, GeoParseError> {
        let bytes = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(arr))
    }

    /// Reads one field header, returning `(field_number, wire_type)`.
    fn read_tag(&mut self) -> Result<(u64, u8), GeoParseError> {
        let key = self.read_varint()?;
        Ok((key >> 3, (key & 0x7) as u8))
    }

    /// Skips a field of the given wire type.
    fn skip(&mut self, wire: u8) -> Result<(), GeoParseError> {
        match wire {
            WIRE_VARINT => {
                self.read_varint()?;
            }
            WIRE_64BIT => {
                self.read_fixed64()?;
            }
            WIRE_LENGTH => {
                let len = self.read_varint()? as usize;
                self.read_bytes(len)?;
            }
            WIRE_32BIT => {
                self.read_fixed32()?;
            }
            other => {
                return Err(GeoParseError::UnsupportedWire {
                    wire: other,
                    offset: self.pos,
                });
            }
        }
        Ok(())
    }
}

/// One decoded `CIDR` message.
fn decode_cidr(buf: &[u8]) -> Result<Cidr, GeoParseError> {
    let mut reader = Reader::new(buf);
    let mut addr: Option<IpAddr> = None;
    let mut prefix: Option<u32> = None;

    while !reader.is_empty() {
        let (field, wire) = reader.read_tag()?;
        match (field, wire) {
            (1, WIRE_LENGTH) => {
                let len = reader.read_varint()? as usize;
                let bytes = reader.read_bytes(len)?;
                addr = Some(match bytes.len() {
                    4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
                    16 => {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(bytes);
                        IpAddr::V6(Ipv6Addr::from(arr))
                    }
                    other => return Err(GeoParseError::BadAddressLength(other)),
                });
            }
            (2, WIRE_VARINT) => {
                prefix = Some(reader.read_varint()? as u32);
            }
            (_, wire) => reader.skip(wire)?,
        }
    }

    let addr = addr.ok_or(GeoParseError::BadAddressLength(0))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(max);
    if prefix > max {
        return Err(GeoParseError::BadPrefix(prefix));
    }
    Ok(Cidr {
        addr,
        prefix: prefix as u8,
    })
}

/// One decoded `Domain` message.
fn decode_domain(buf: &[u8]) -> Result<DomainPattern, GeoParseError> {
    let mut reader = Reader::new(buf);
    let mut kind: u64 = DOMAIN_PLAIN;
    let mut value: Option<String> = None;

    while !reader.is_empty() {
        let (field, wire) = reader.read_tag()?;
        match (field, wire) {
            (1, WIRE_VARINT) => {
                kind = reader.read_varint()?;
            }
            (2, WIRE_LENGTH) => {
                let len = reader.read_varint()? as usize;
                let bytes = reader.read_bytes(len)?;
                value = Some(String::from_utf8_lossy(bytes).into_owned());
            }
            (_, wire) => reader.skip(wire)?,
        }
    }

    let value = value.ok_or_else(|| GeoParseError::BadDomain(String::new()))?;
    let pattern = match kind {
        DOMAIN_FULL => DomainPattern::Full(value.to_ascii_lowercase()),
        DOMAIN_SUFFIX => DomainPattern::Suffix(value.to_ascii_lowercase()),
        DOMAIN_REGEX => DomainPattern::Regexp(value),
        // `Plain` and anything unrecognised are treated as a suffix match,
        // which is the conservative reading: it matches the domain and its
        // subdomains.
        _ => DomainPattern::Suffix(value.to_ascii_lowercase()),
    };
    Ok(pattern)
}

/// Decoded geo data: address sets and domain sets keyed by category.
#[derive(Debug, Clone, Default)]
pub struct GeoData {
    ip: HashMap<String, IpMatcher>,
    domain: HashMap<String, DomainMatcher>,
}

impl GeoData {
    /// Returns the address matcher for a `geoip:` category, if present.
    ///
    /// Lookup is case-insensitive, matching Xray's behaviour.
    #[must_use]
    pub fn ip_matcher(&self, category: &str) -> Option<&IpMatcher> {
        self.ip.get(&category.to_ascii_lowercase())
    }

    /// Returns the domain matcher for a `geosite:` category, if present.
    ///
    /// Lookup is case-insensitive, matching Xray's behaviour.
    #[must_use]
    pub fn domain_matcher(&self, category: &str) -> Option<&DomainMatcher> {
        self.domain.get(&category.to_ascii_lowercase())
    }

    /// Returns the names of all loaded `geoip:` categories.
    #[must_use]
    pub fn ip_categories(&self) -> Vec<&str> {
        self.ip.keys().map(String::as_str).collect()
    }

    /// Returns the names of all loaded `geosite:` categories.
    #[must_use]
    pub fn domain_categories(&self) -> Vec<&str> {
        self.domain.keys().map(String::as_str).collect()
    }

    /// Returns true when no geo data is loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ip.is_empty() && self.domain.is_empty()
    }

    /// Parses a `geoip.dat` buffer and merges its entries into this set.
    ///
    /// # Errors
    ///
    /// Returns [`GeoParseError`] when the buffer is not a valid `GeoIPList`.
    pub fn load_geoip(&mut self, buf: &[u8]) -> Result<usize, GeoParseError> {
        let mut reader = Reader::new(buf);
        let mut count = 0usize;

        while !reader.is_empty() {
            let (field, wire) = reader.read_tag()?;
            if field != 1 || wire != WIRE_LENGTH {
                reader.skip(wire)?;
                continue;
            }
            let len = reader.read_varint()? as usize;
            let entry = reader.read_bytes(len)?;
            if let Some((code, matcher)) = decode_geoip_entry(entry)? {
                self.ip.insert(code, matcher);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Parses a `geosite.dat` buffer and merges its entries into this set.
    ///
    /// # Errors
    ///
    /// Returns [`GeoParseError`] when the buffer is not a valid `GeoSiteList`.
    pub fn load_geosite(&mut self, buf: &[u8]) -> Result<usize, GeoParseError> {
        let mut reader = Reader::new(buf);
        let mut count = 0usize;

        while !reader.is_empty() {
            let (field, wire) = reader.read_tag()?;
            if field != 1 || wire != WIRE_LENGTH {
                reader.skip(wire)?;
                continue;
            }
            let len = reader.read_varint()? as usize;
            let entry = reader.read_bytes(len)?;
            if let Some((code, matcher)) = decode_geosite_entry(entry)? {
                self.domain.insert(code, matcher);
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Decodes one `GeoIP` entry into a category name and its address matcher.
fn decode_geoip_entry(buf: &[u8]) -> Result<Option<(String, IpMatcher)>, GeoParseError> {
    let mut reader = Reader::new(buf);
    let mut code: Option<String> = None;
    let mut cidrs: Vec<Cidr> = Vec::new();

    while !reader.is_empty() {
        let (field, wire) = reader.read_tag()?;
        match (field, wire) {
            (1, WIRE_LENGTH) => {
                let len = reader.read_varint()? as usize;
                let bytes = reader.read_bytes(len)?;
                code = Some(String::from_utf8_lossy(bytes).into_owned());
            }
            (2, WIRE_LENGTH) => {
                let len = reader.read_varint()? as usize;
                let bytes = reader.read_bytes(len)?;
                cidrs.push(decode_cidr(bytes)?);
            }
            (_, wire) => reader.skip(wire)?,
        }
    }

    let Some(code) = code else {
        return Ok(None);
    };
    let mut matcher = IpMatcher::default();
    for cidr in cidrs {
        matcher.extend(
            &IpMatcher::from_cidrs([format!("{}/{}", cidr.addr, cidr.prefix)])
                .map_err(|_| GeoParseError::BadPrefix(u32::from(cidr.prefix)))?,
        );
    }
    Ok(Some((code.to_ascii_lowercase(), matcher)))
}

/// Decodes one `GeoSite` entry into a category name and its domain matcher.
fn decode_geosite_entry(buf: &[u8]) -> Result<Option<(String, DomainMatcher)>, GeoParseError> {
    let mut reader = Reader::new(buf);
    let mut code: Option<String> = None;
    let mut patterns: Vec<DomainPattern> = Vec::new();

    while !reader.is_empty() {
        let (field, wire) = reader.read_tag()?;
        match (field, wire) {
            (1, WIRE_LENGTH) => {
                let len = reader.read_varint()? as usize;
                let bytes = reader.read_bytes(len)?;
                code = Some(String::from_utf8_lossy(bytes).into_owned());
            }
            (2, WIRE_LENGTH) => {
                let len = reader.read_varint()? as usize;
                let bytes = reader.read_bytes(len)?;
                patterns.push(decode_domain(bytes)?);
            }
            (_, wire) => reader.skip(wire)?,
        }
    }

    let Some(code) = code else {
        return Ok(None);
    };
    let mut matcher = DomainMatcher::default();
    for pattern in patterns {
        matcher.extend(&DomainMatcher::from_parsed([pattern]));
    }
    Ok(Some((code.to_ascii_lowercase(), matcher)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a varint, for building test fixtures.
    fn varint(mut value: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn tag(field: u64, wire: u8, out: &mut Vec<u8>) {
        varint((field << 3) | u64::from(wire), out);
    }

    fn length_delimited(field: u64, payload: &[u8], out: &mut Vec<u8>) {
        tag(field, WIRE_LENGTH, out);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    fn build_cidr(addr: [u8; 4], prefix: u32) -> Vec<u8> {
        let mut out = Vec::new();
        length_delimited(1, &addr, &mut out);
        tag(2, WIRE_VARINT, &mut out);
        varint(u64::from(prefix), &mut out);
        out
    }

    fn build_geoip_entry(code: &str, cidrs: &[([u8; 4], u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        length_delimited(1, code.as_bytes(), &mut out);
        for (addr, prefix) in cidrs {
            let cidr = build_cidr(*addr, *prefix);
            length_delimited(2, &cidr, &mut out);
        }
        out
    }

    fn build_domain(kind: u64, value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        tag(1, WIRE_VARINT, &mut out);
        varint(kind, &mut out);
        length_delimited(2, value.as_bytes(), &mut out);
        out
    }

    fn build_geosite_entry(code: &str, domains: &[(u64, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        length_delimited(1, code.as_bytes(), &mut out);
        for (kind, value) in domains {
            let domain = build_domain(*kind, value);
            length_delimited(2, &domain, &mut out);
        }
        out
    }

    #[test]
    fn parses_geoip_list() {
        let entry = build_geoip_entry("RU", &[([10, 0, 0, 0], 8), ([192, 168, 0, 0], 16)]);
        let mut buf = Vec::new();
        length_delimited(1, &entry, &mut buf);

        let mut geo = GeoData::default();
        assert_eq!(geo.load_geoip(&buf).unwrap(), 1);
        let matcher = geo.ip_matcher("ru").unwrap();
        assert!(matcher.matches("10.1.2.3".parse().unwrap()));
        assert!(matcher.matches("192.168.5.5".parse().unwrap()));
        assert!(!matcher.matches("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn geoip_lookup_is_case_insensitive() {
        let entry = build_geoip_entry("RU", &[([10, 0, 0, 0], 8)]);
        let mut buf = Vec::new();
        length_delimited(1, &entry, &mut buf);

        let mut geo = GeoData::default();
        geo.load_geoip(&buf).unwrap();
        assert!(geo.ip_matcher("RU").is_some());
        assert!(geo.ip_matcher("ru").is_some());
        assert!(geo.ip_matcher("Ru").is_some());
    }

    #[test]
    fn parses_geosite_list() {
        let entry = build_geosite_entry(
            "CATEGORY-ADS",
            &[
                (DOMAIN_SUFFIX, "ads.example.com"),
                (DOMAIN_FULL, "exact.example.net"),
                (DOMAIN_KEYWORD_PLACEHOLDER, "tracker"),
            ],
        );
        let mut buf = Vec::new();
        length_delimited(1, &entry, &mut buf);

        let mut geo = GeoData::default();
        assert_eq!(geo.load_geosite(&buf).unwrap(), 1);
        let matcher = geo.domain_matcher("category-ads").unwrap();
        assert!(matcher.matches("sub.ads.example.com"));
        assert!(matcher.matches("exact.example.net"));
        assert!(!matcher.matches("other.example.net"));
    }

    /// `Plain` (0) is treated as a suffix match.
    const DOMAIN_KEYWORD_PLACEHOLDER: u64 = DOMAIN_PLAIN;

    #[test]
    fn parses_regex_domain() {
        let entry = build_geosite_entry("REGEX-CAT", &[(DOMAIN_REGEX, r"^ads\..*\.net$")]);
        let mut buf = Vec::new();
        length_delimited(1, &entry, &mut buf);

        let mut geo = GeoData::default();
        geo.load_geosite(&buf).unwrap();
        let matcher = geo.domain_matcher("regex-cat").unwrap();
        assert!(matcher.matches("ads.foo.net"));
        assert!(!matcher.matches("ads.foo.com"));
    }

    #[test]
    fn skips_unknown_fields() {
        let mut entry = build_geoip_entry("RU", &[([10, 0, 0, 0], 8)]);
        // Append an unknown varint field (number 9) and an unknown
        // length-delimited field (number 10).
        tag(9, WIRE_VARINT, &mut entry);
        varint(12345, &mut entry);
        length_delimited(10, b"ignored", &mut entry);

        let mut buf = Vec::new();
        length_delimited(1, &entry, &mut buf);

        let mut geo = GeoData::default();
        assert_eq!(geo.load_geoip(&buf).unwrap(), 1);
        assert!(geo.ip_matcher("ru").is_some());
    }

    #[test]
    fn rejects_truncated_input() {
        let entry = build_geoip_entry("RU", &[([10, 0, 0, 0], 8)]);
        let mut buf = Vec::new();
        length_delimited(1, &entry, &mut buf);
        buf.truncate(buf.len() - 3);

        let mut geo = GeoData::default();
        assert!(geo.load_geoip(&buf).is_err());
    }

    #[test]
    fn rejects_bad_prefix() {
        let entry = build_geoip_entry("RU", &[([10, 0, 0, 0], 40)]);
        let mut buf = Vec::new();
        length_delimited(1, &entry, &mut buf);

        let mut geo = GeoData::default();
        assert!(matches!(
            geo.load_geoip(&buf),
            Err(GeoParseError::BadPrefix(40))
        ));
    }

    #[test]
    fn empty_buffer_yields_no_entries() {
        let mut geo = GeoData::default();
        assert_eq!(geo.load_geoip(&[]).unwrap(), 0);
        assert_eq!(geo.load_geosite(&[]).unwrap(), 0);
        assert!(geo.is_empty());
    }

    #[test]
    fn multiple_entries_are_all_loaded() {
        let mut buf = Vec::new();
        length_delimited(1, &build_geoip_entry("RU", &[([10, 0, 0, 0], 8)]), &mut buf);
        length_delimited(1, &build_geoip_entry("CN", &[([1, 0, 0, 0], 8)]), &mut buf);

        let mut geo = GeoData::default();
        assert_eq!(geo.load_geoip(&buf).unwrap(), 2);
        assert!(geo.ip_matcher("ru").is_some());
        assert!(geo.ip_matcher("cn").is_some());
    }
}
