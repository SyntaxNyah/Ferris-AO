use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct PrivacyLayer {
    /// Permanent server secret used for hashing. Never logged.
    server_secret: [u8; 32],
}

impl PrivacyLayer {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { server_secret: secret }
    }

    /// Compute the IPID for a raw IP address string.
    /// Daily-rotating: HMAC-SHA256(server_secret, "YYYY-MM-DD") → daily_salt
    ///                  HMAC-SHA256(daily_salt, ip_str) → hex(first 16 bytes)
    /// Raw IP is never retained after this call.
    pub fn compute_ipid(&self, ip: &str) -> String {
        let date = Utc::now().format("%Y-%m-%d").to_string();

        // Derive daily salt
        let mut daily_mac = HmacSha256::new_from_slice(&self.server_secret)
            .expect("HMAC can take any key size");
        daily_mac.update(date.as_bytes());
        let daily_salt = daily_mac.finalize().into_bytes();

        // Derive IPID
        let mut ipid_mac = HmacSha256::new_from_slice(&daily_salt)
            .expect("HMAC can take any key size");
        ipid_mac.update(ip.as_bytes());
        let result = ipid_mac.finalize().into_bytes();

        hex::encode(&result[..16])
    }

    /// Hash a raw HDID with the permanent server secret.
    /// Permanent (not daily-rotating) so bans survive restarts and day boundaries.
    pub fn hash_hdid(&self, raw_hdid: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.server_secret)
            .expect("HMAC can take any key size");
        mac.update(b"hdid:");
        mac.update(raw_hdid.as_bytes());
        let result = mac.finalize().into_bytes();
        hex::encode(&result[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipid_is_deterministic_within_day() {
        let secret = [42u8; 32];
        let layer = PrivacyLayer::new(secret);
        let a = layer.compute_ipid("192.168.1.1");
        let b = layer.compute_ipid("192.168.1.1");
        assert_eq!(a, b);
    }

    #[test]
    fn different_ips_different_ipids() {
        let secret = [42u8; 32];
        let layer = PrivacyLayer::new(secret);
        let a = layer.compute_ipid("192.168.1.1");
        let b = layer.compute_ipid("10.0.0.1");
        assert_ne!(a, b);
    }

    #[test]
    fn hdid_hash_is_deterministic() {
        let secret = [99u8; 32];
        let layer = PrivacyLayer::new(secret);
        let a = layer.hash_hdid("ABC123");
        let b = layer.hash_hdid("ABC123");
        assert_eq!(a, b);
    }

    #[test]
    fn hdid_different_inputs_differ() {
        let secret = [99u8; 32];
        let layer = PrivacyLayer::new(secret);
        let a = layer.hash_hdid("ABC123");
        let b = layer.hash_hdid("DEF456");
        assert_ne!(a, b);
    }
}
