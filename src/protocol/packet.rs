use thiserror::Error;

pub const MAX_PACKET_SIZE: usize = 30_720;

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
}

impl Packet {
    pub fn new(header: impl Into<String>, body: Vec<String>) -> Self {
        Self { header: header.into(), body }
    }

    /// Parse from raw bytes (not including the trailing `%` delimiter).
    /// Wire format coming in: `HEADER#field1#field2#...#` (trailing # before %)
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(PacketError::TooLarge);
        }
        let s = String::from_utf8_lossy(data);
        let s = s.trim();
        // Split on '#'
        let mut parts: Vec<&str> = s.split('#').collect();
        if parts.is_empty() || parts[0].trim().is_empty() {
            return Err(PacketError::EmptyHeader);
        }
        let header = parts[0].to_string();
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
