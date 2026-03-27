use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::EncryptedDb;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BanRecord {
    pub id: u64,
    /// Hashed HDID
    pub hdid: String,
    pub timestamp: i64,
    /// None = permanent, Some(ts) = expires at unix timestamp
    pub expires_at: Option<i64>,
    pub reason: String,
    pub moderator: String,
}

impl BanRecord {
    pub fn is_active(&self) -> bool {
        match self.expires_at {
            None => true,
            Some(exp) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                exp > now
            }
        }
    }

    pub fn duration_display(&self) -> String {
        match self.expires_at {
            None => "∞".into(),
            Some(ts) => {
                let dt = chrono::DateTime::from_timestamp(ts, 0)
                    .unwrap_or_default()
                    .format("%d %b %Y %H:%M UTC")
                    .to_string();
                dt
            }
        }
    }
}

pub struct BanManager {
    db: Arc<EncryptedDb>,
    next_id: AtomicU64,
}

impl BanManager {
    pub fn new(db: Arc<EncryptedDb>) -> Self {
        Self {
            db,
            next_id: AtomicU64::new(1),
        }
    }

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Add a new ban. Returns the ban ID.
    pub fn add(&self, hdid: &str, expires_at: Option<i64>, reason: &str, moderator: &str) -> Result<u64> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let record = BanRecord {
            id,
            hdid: hdid.to_string(),
            timestamp: Self::now_unix(),
            expires_at,
            reason: reason.to_string(),
            moderator: moderator.to_string(),
        };
        let encoded = serde_json::to_vec(&record)?;
        self.db.bans_insert(id, &encoded)?;
        self.db.bans_by_hdid_insert(hdid, id)?;
        Ok(id)
    }

    pub fn get(&self, id: u64) -> Result<Option<BanRecord>> {
        match self.db.bans_get(id)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Nullify a ban by setting expires_at to the past.
    pub fn nullify(&self, id: u64) -> Result<bool> {
        match self.get(id)? {
            Some(mut record) => {
                record.expires_at = Some(0); // expired in 1970
                let encoded = serde_json::to_vec(&record)?;
                self.db.bans_insert(id, &encoded)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Check if a hashed HDID is currently banned. Returns the active ban record if found.
    pub fn is_banned(&self, hdid: &str) -> Result<Option<BanRecord>> {
        let ids = self.db.bans_by_hdid_get(hdid)?;
        for id in ids {
            if let Some(record) = self.get(id)? {
                if record.is_active() {
                    return Ok(Some(record));
                }
            }
        }
        Ok(None)
    }

    /// Get all ban records for a hashed HDID.
    pub fn get_by_hdid(&self, hdid: &str) -> Result<Vec<BanRecord>> {
        let ids = self.db.bans_by_hdid_get(hdid)?;
        let mut records = Vec::new();
        for id in ids {
            if let Some(r) = self.get(id)? {
                records.push(r);
            }
        }
        Ok(records)
    }
}
