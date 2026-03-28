use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::EncryptedDb;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpidBanRecord {
    /// Daily-rotating hashed IPID (expires naturally at midnight UTC)
    pub ipid: String,
    pub timestamp: i64,
    /// None = permanent (until daily rotation), Some(ts) = explicit expiry
    pub expires_at: Option<i64>,
    pub reason: String,
    pub moderator: String,
}

impl IpidBanRecord {
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
            None => "until daily IPID rotation".into(),
            Some(ts) => chrono::DateTime::from_timestamp(ts, 0)
                .unwrap_or_default()
                .format("%d %b %Y %H:%M UTC")
                .to_string(),
        }
    }
}

pub struct IpidBanManager {
    db: Arc<EncryptedDb>,
}

impl IpidBanManager {
    pub fn new(db: Arc<EncryptedDb>) -> Self {
        Self { db }
    }

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Ban an IPID. Returns Ok(()) on success.
    pub fn add(&self, ipid: &str, expires_at: Option<i64>, reason: &str, moderator: &str) -> Result<()> {
        let record = IpidBanRecord {
            ipid: ipid.to_string(),
            timestamp: Self::now_unix(),
            expires_at,
            reason: reason.to_string(),
            moderator: moderator.to_string(),
        };
        let encoded = serde_json::to_vec(&record)?;
        self.db.ipid_bans_insert(ipid, &encoded)?;
        Ok(())
    }

    /// Check whether an IPID is currently banned. Returns the record if active.
    pub fn is_banned(&self, ipid: &str) -> Result<Option<IpidBanRecord>> {
        match self.db.ipid_bans_get(ipid)? {
            Some(bytes) => {
                let record: IpidBanRecord = serde_json::from_slice(&bytes)?;
                if record.is_active() {
                    Ok(Some(record))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    /// Remove an IPID ban. Returns true if a record existed.
    pub fn remove(&self, ipid: &str) -> Result<bool> {
        self.db.ipid_bans_remove(ipid)
    }
}
