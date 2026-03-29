use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;

use crate::storage::EncryptedDb;

/// Permission bit flags (mirrors Athena's permission model).
pub mod perms {
    pub const NONE: u64 = 0;
    pub const CM: u64 = 1;
    pub const KICK: u64 = 1 << 1;
    pub const BAN: u64 = 1 << 2;
    pub const BYPASS_LOCK: u64 = 1 << 3;
    pub const MOD_EVI: u64 = 1 << 4;
    pub const MODIFY_AREA: u64 = 1 << 5;
    pub const MOVE_USERS: u64 = 1 << 6;
    pub const MOD_SPEAK: u64 = 1 << 7;
    pub const BAN_INFO: u64 = 1 << 8;
    pub const MOD_CHAT: u64 = 1 << 9;
    pub const MUTE: u64 = 1 << 10;
    pub const LOG: u64 = 1 << 11;
    pub const WATCHLIST: u64 = 1 << 12;
    /// Allow `/play` (music + URL streaming) in any area regardless of CM status.
    /// Assign via `setrole <user> dj` or directly with `setrole <user>` and PERM_DJ.
    pub const DJ: u64 = 1 << 13;
    pub const ADMIN: u64 = u64::MAX;

    pub fn has(perms: u64, required: u64) -> bool {
        required == (perms & required)
    }

    pub fn from_role(role: &str) -> u64 {
        match role.to_uppercase().as_str() {
            "ADMIN" => ADMIN,
            "MOD" | "MODERATOR" => KICK | BAN | BYPASS_LOCK | MOD_EVI | MODIFY_AREA
                | MOVE_USERS | MOD_SPEAK | BAN_INFO | MOD_CHAT | MUTE | LOG | WATCHLIST,
            "TRIAL" => KICK | MUTE | LOG,
            "CM" => CM,
            "DJ" => DJ,
            _ => NONE,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub username: String,
    pub password_hash: String,
    pub permissions: u64,
    /// Base32-encoded TOTP secret.  None = 2FA disabled.
    #[serde(default)]
    pub totp_secret: Option<String>,
}

/// Result of an authentication attempt that may require a second factor.
#[derive(Debug)]
pub enum AuthResult {
    /// Password was correct and no 2FA is configured.
    Success(u64),
    /// Password was correct but TOTP code must be verified next.
    /// Carries the permissions to grant after TOTP succeeds.
    NeedsTOTP(u64),
    /// Invalid username or password.
    InvalidCredentials,
}

#[derive(Clone)]
pub struct AccountManager {
    db: Arc<EncryptedDb>,
    /// Server-side pepper applied to passwords before Argon2id.
    pepper: String,
}

impl AccountManager {
    pub fn new(db: Arc<EncryptedDb>) -> Self {
        Self { db, pepper: String::new() }
    }

    pub fn new_with_pepper(db: Arc<EncryptedDb>, pepper: String) -> Self {
        Self { db, pepper }
    }

    /// Apply the server-side pepper to a password via HMAC-SHA256.
    /// Returns a Cow::Borrowed if no pepper is set (zero allocation).
    fn pepper_password<'a>(&self, password: &'a str) -> Cow<'a, str> {
        if self.pepper.is_empty() {
            return Cow::Borrowed(password);
        }
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.pepper.as_bytes())
            .expect("HMAC accepts any key size");
        mac.update(password.as_bytes());
        Cow::Owned(hex::encode(mac.finalize().into_bytes()))
    }

    /// Hash a password with Argon2id using default parameters.
    /// This is CPU-intensive; call via spawn_blocking.
    pub fn hash_password(password: &str) -> Result<String> {
        Self::hash_password_with_params(password, 65536, 3, 2)
    }

    /// Hash a password with Argon2id using explicit parameters.
    /// - `memory_kib`: memory cost in KiB (e.g. 65536 = 64 MiB)
    /// - `iterations`: time cost (passes)
    /// - `parallelism`: number of threads
    /// This is CPU-intensive; call via spawn_blocking.
    pub fn hash_password_with_params(
        password: &str,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let params = Params::new(memory_kib, iterations, parallelism, None)
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?
            .to_string();
        Ok(hash)
    }

    /// Verify a password against a stored Argon2id hash. CPU-intensive; use spawn_blocking.
    pub fn verify_password(hash: &str, password: &str) -> bool {
        let parsed = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    pub fn create(&self, username: &str, password: &str, role: &str) -> Result<()> {
        self.create_with_params(username, password, role, 65536, 3, 2)
    }

    /// Create an account using explicit Argon2id parameters.
    pub fn create_with_params(
        &self,
        username: &str,
        password: &str,
        role: &str,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<()> {
        let effective = self.pepper_password(password);
        let hash = Self::hash_password_with_params(&effective, memory_kib, iterations, parallelism)?;
        let account = Account {
            username: username.to_lowercase(),
            password_hash: hash,
            permissions: perms::from_role(role),
            totp_secret: None,
        };
        let encoded = serde_json::to_vec(&account)?;
        self.db.accounts_insert(&username.to_lowercase(), &encoded)
    }

    pub fn delete(&self, username: &str) -> Result<bool> {
        self.db.accounts_delete(&username.to_lowercase())
    }

    pub fn get(&self, username: &str) -> Result<Option<Account>> {
        match self.db.accounts_get(&username.to_lowercase())? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Authenticate username + password. Returns an AuthResult.
    /// NOTE: Call inside tokio::task::spawn_blocking due to Argon2 cost.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<AuthResult> {
        let effective = self.pepper_password(password);
        match self.get(username)? {
            Some(account) => {
                if Self::verify_password(&account.password_hash, &effective) {
                    if account.totp_secret.is_some() {
                        Ok(AuthResult::NeedsTOTP(account.permissions))
                    } else {
                        Ok(AuthResult::Success(account.permissions))
                    }
                } else {
                    Ok(AuthResult::InvalidCredentials)
                }
            }
            None => Ok(AuthResult::InvalidCredentials),
        }
    }

    /// Update the permissions of an existing account. Returns Ok(true) if the
    /// account was found and updated, Ok(false) if it does not exist.
    pub fn set_permissions(&self, username: &str, new_perms: u64) -> Result<bool> {
        let key = username.to_lowercase();
        match self.db.accounts_get(&key)? {
            None => Ok(false),
            Some(bytes) => {
                let mut account: Account = serde_json::from_slice(&bytes)
                    .map_err(|e| anyhow::anyhow!("Decode error: {}", e))?;
                account.permissions = new_perms;
                let encoded = serde_json::to_vec(&account)?;
                self.db.accounts_insert(&key, &encoded)?;
                Ok(true)
            }
        }
    }

    /// Set up TOTP for an account. Returns the otpauth:// URI to show the user.
    /// The URI can be scanned by any TOTP authenticator (Google Authenticator,
    /// Authy, Aegis, etc.).
    pub fn enable_totp(&self, username: &str, issuer: &str) -> Result<String> {
        use totp_rs::{Algorithm, Secret, TOTP};
        let key = username.to_lowercase();
        let mut account = match self.get(&key)? {
            Some(a) => a,
            None => anyhow::bail!("Account not found"),
        };
        let secret = Secret::generate_secret();
        let totp = TOTP::new(
            Algorithm::SHA1, 6, 1, 30,
            secret.to_bytes().map_err(|e| anyhow::anyhow!("TOTP secret error: {}", e))?,
            Some(issuer.to_string()),
            key.clone(),
        ).map_err(|e| anyhow::anyhow!("TOTP init error: {}", e))?;
        let uri = totp.get_url();
        account.totp_secret = Some(secret.to_encoded().to_string());
        let encoded = serde_json::to_vec(&account)?;
        self.db.accounts_insert(&key, &encoded)?;
        Ok(uri)
    }

    /// Disable TOTP for an account after verifying the current TOTP code.
    pub fn disable_totp(&self, username: &str, code: &str) -> Result<bool> {
        let key = username.to_lowercase();
        let mut account = match self.get(&key)? {
            Some(a) => a,
            None => return Ok(false),
        };
        if !Self::verify_totp_code(account.totp_secret.as_deref(), code) {
            return Ok(false);
        }
        account.totp_secret = None;
        let encoded = serde_json::to_vec(&account)?;
        self.db.accounts_insert(&key, &encoded)?;
        Ok(true)
    }

    /// Verify a 6-digit TOTP code against the stored secret.
    /// Returns false if no TOTP secret is configured.
    pub fn verify_totp_for(&self, username: &str, code: &str) -> Result<bool> {
        match self.get(&username.to_lowercase())? {
            Some(account) => Ok(Self::verify_totp_code(account.totp_secret.as_deref(), code)),
            None => Ok(false),
        }
    }

    fn verify_totp_code(secret_b32: Option<&str>, code: &str) -> bool {
        use totp_rs::{Algorithm, Secret, TOTP};
        let b32 = match secret_b32 {
            Some(s) => s,
            None => return false,
        };
        let bytes = match Secret::Encoded(b32.to_string()).to_bytes() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes, None, String::new()) {
            Ok(t) => t,
            Err(_) => return false,
        };
        totp.check_current(code).unwrap_or(false)
    }
}
