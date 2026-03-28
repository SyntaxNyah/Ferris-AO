use anyhow::Result;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
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
            _ => NONE,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub username: String,
    pub password_hash: String,
    pub permissions: u64,
}

#[derive(Clone)]
pub struct AccountManager {
    db: Arc<EncryptedDb>,
}

impl AccountManager {
    pub fn new(db: Arc<EncryptedDb>) -> Self {
        Self { db }
    }

    /// Hash a password with Argon2id. This is CPU-intensive; call via spawn_blocking.
    pub fn hash_password(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
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
        let hash = Self::hash_password(password)?;
        let account = Account {
            username: username.to_lowercase(),
            password_hash: hash,
            permissions: perms::from_role(role),
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

    /// Authenticate username + password. Returns permissions on success.
    /// NOTE: Call this inside tokio::task::spawn_blocking due to Argon2 cost.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<Option<u64>> {
        match self.get(username)? {
            Some(account) => {
                if Self::verify_password(&account.password_hash, password) {
                    Ok(Some(account.permissions))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
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
}
