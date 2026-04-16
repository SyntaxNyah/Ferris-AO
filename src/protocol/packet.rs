use thiserror::Error;

pub const MAX_PACKET_SIZE: usize = 30_720;

/// Absolute ceiling on `#`-separated fields per packet.  Callers may impose
/// a tighter limit via [`Packet::parse_with_limit`].  Guards against packets
/// crafted solely to allocate huge `Vec<String>` instances.
pub const MAX_PACKET_FIELDS: usize = 1024;

/// Maximum bytes allowed per header token.  AO2 headers are short identifiers
/// (HI, MS, CT…); anything longer is malformed and rejected outright.
pub const MAX_HEADER_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct Packet {
    pub header: String,
    pub body: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("Empty packet header")]
    EmptyHeader,
    #[error("Packet too large")]
    TooLarge,
    #[error("Header token too long")]
    HeaderTooLong,
    #[error("Header contains invalid characters")]
    HeaderInvalid,
    #[error("Packet has too many fields")]
    TooManyFields,
}

impl Packet {
    pub fn new(header: impl Into<String>, body: Vec<String>) -> Self {
        Self { header: header.into(), body }
    }

    /// Parse from raw bytes (not including the trailing `%` delimiter).
    /// Wire format coming in: `HEADER#field1#field2#...#` (trailing # before %)
    ///
    /// Uses the module-wide defaults [`MAX_PACKET_SIZE`] and
    /// [`MAX_PACKET_FIELDS`].  Call [`Packet::parse_with_limit`] to apply
    /// tighter caller-configured bounds.
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        Self::parse_with_limit(data, MAX_PACKET_SIZE, MAX_PACKET_FIELDS)
    }

    /// Parse with custom size + field-count caps.
    pub fn parse_with_limit(
        data: &[u8],
        max_bytes: usize,
        max_fields: usize,
    ) -> Result<Self, PacketError> {
        if data.len() > max_bytes {
            return Err(PacketError::TooLarge);
        }
        let s = String::from_utf8_lossy(data);
        let s = s.trim();
        // Cheap pre-check: count '#' before allocating a Vec.  Each '#'
        // starts a new field; reject early on absurd field counts.
        let delim_count = s.bytes().filter(|&b| b == b'#').count();
        if delim_count.saturating_add(1) > max_fields.max(1) {
            return Err(PacketError::TooManyFields);
        }
        let mut parts: Vec<&str> = s.split('#').collect();
        if parts.is_empty() || parts[0].trim().is_empty() {
            return Err(PacketError::EmptyHeader);
        }
        let header_raw = parts[0];
        if header_raw.len() > MAX_HEADER_LEN {
            return Err(PacketError::HeaderTooLong);
        }
        // AO2 headers are ASCII alphanumeric + underscore only. Reject anything
        // else — stops attempts to smuggle malformed framing, NULs, or unicode
        // bombs through the dispatch table.
        if !header_raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(PacketError::HeaderInvalid);
        }
        let header = header_raw.to_string();
        // Remove header
        parts.remove(0);
        // Remove trailing empty entry (from the trailing '#' before '%')
        if parts.len() > 1 {
            parts.pop();
        }
        let body = parts.iter().map(|s| s.to_string()).collect();
        Ok(Packet { header, body })
    }

    /// Serialize to wire format: `HEADER#field1#field2#...#%`
    /// Matches Athena: header + "#" + join(body, "#") + "#%"
    pub fn to_wire(&self) -> String {
        format!("{}#{}#%", self.header, self.body.join("#"))
    }
}

/// Encode a string for AO2 wire transmission.
/// Replaces special characters with escape sequences.
pub fn ao_encode(s: &str) -> String {
    s.replace('%', "<percent>")
        .replace('#', "<num>")
        .replace('$', "<dollar>")
        .replace('&', "<and>")
}

/// Decode an AO2-encoded string back to plain text.
pub fn ao_decode(s: &str) -> String {
    s.replace("<percent>", "%")
        .replace("<num>", "#")
        .replace("<dollar>", "$")
        .replace("<and>", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hi_packet() {
        let pkt = Packet::parse(b"HI#DEADBEEF#").unwrap();
        assert_eq!(pkt.header, "HI");
        assert_eq!(pkt.body, vec!["DEADBEEF"]);
    }

    #[test]
    fn parse_no_body() {
        let pkt = Packet::parse(b"CH#").unwrap();
        assert_eq!(pkt.header, "CH");
        assert_eq!(pkt.body, vec![""]);
    }

    #[test]
    fn to_wire_roundtrip() {
        let pkt = Packet::new("CT", vec!["Phoenix".into(), "hello".into()]);
        assert_eq!(pkt.to_wire(), "CT#Phoenix#hello#%");
    }

    #[test]
    fn encode_decode_roundtrip() {
        let original = "Hello #world% and $more & stuff";
        assert_eq!(ao_decode(&ao_encode(original)), original);
    }

    #[test]
    fn encode_special_chars() {
        assert_eq!(ao_encode("a#b%c$d&e"), "a<num>b<percent>c<dollar>d<and>e");
    }
}
