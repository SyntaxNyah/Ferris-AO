use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::storage::EncryptedDb;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WatchEntry {
    /// Hashed HDID being watched.
    pub hdid: String,
    /// Mod account that added the entry.
    pub added_by: String,
    /// Unix timestamp of when it was added.
    pub timestamp: i64,
    /// Optional note describing why this HDID is being watched.
    pub note: String,
}

pub struct WatchlistManager {
    db: Arc<EncryptedDb>,
}

impl WatchlistManager {
    pub fn new(db: Arc<EncryptedDb>) -> Self {
        Self { db }
    }

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// Add an HDID to the watchlist. Overwrites any existing entry for the same HDID.
    pub fn add(&self, hdid: &str, added_by: &str, note: &str) -> Result<()> {
        let entry = WatchEntry {
            hdid: hdid.to_string(),
            added_by: added_by.to_string(),
            timestamp: Self::now_unix(),
            note: note.to_string(),
        };
        let encoded = serde_json::to_vec(&entry)?;
        self.db.watchlist_insert(hdid, &encoded)
    }

    /// Remove an HDID from the watchlist. Returns true if it was present.
    pub fn remove(&self, hdid: &str) -> Result<bool> {
        self.db.watchlist_remove(hdid)
    }

    /// Check if an HDID is on the watchlist. Returns the entry if found.
    pub fn get(&self, hdid: &str) -> Result<Option<WatchEntry>> {
        match self.db.watchlist_get(hdid)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Return all watchlist entries.
    pub fn list(&self) -> Result<Vec<WatchEntry>> {
        self.db.watchlist_list()
    }
}
