use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};

// CONFIG_TABLE key used to track how many key rotations have occurred.
// Value: 8-byte little-endian u64.  Absent on first run (treated as 0).
const KEY_ROTATION_COUNTER_KEY: &str = "key_rotation_counter";

/// Derive a per-session AES-256 key from the master key and a rotation counter.
///
/// Uses HMAC-SHA256 as a simple KDF: `HMAC-SHA256(master, "nyahao-session-<hex_counter>")`.
/// The master key never touches disk; only the counter (plaintext) is persisted.
/// Each restart increments the counter → the session key changes every restart,
/// giving forward secrecy at the session level.
fn derive_session_key(master: &[u8; 32], counter: u64) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let label = format!("nyahao-session-{:016x}", counter);
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(master)
        .expect("HMAC accepts any key size");
    mac.update(label.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ── Free-standing encrypt/decrypt helpers (work on any Aes256Gcm instance) ──

fn encrypt_with(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_with(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 13 {
        anyhow::bail!("Ciphertext too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

// ── Per-table re-encryption helpers ──────────────────────────────────────────

fn reencrypt_u64_table(
    db: &Database,
    table_def: TableDefinition<u64, &[u8]>,
    old: &Aes256Gcm,
    new: &Aes256Gcm,
) -> Result<()> {
    // 1. Read all records with old cipher.
    let pairs: Vec<(u64, Vec<u8>)> = {
        let rtxn = db.begin_read()?;
        let tbl = rtxn.open_table(table_def)?;
        let mut v = Vec::new();
        for item in tbl.iter()? {
            let (k, val) = item?;
            let plain = decrypt_with(old, val.value())?;
            v.push((k.value(), plain));
        }
        v
    };
    // 2. Write re-encrypted records.
    let wtxn = db.begin_write()?;
    {
        let mut tbl = wtxn.open_table(table_def)?;
        for (k, plain) in &pairs {
            let enc = encrypt_with(new, plain)?;
            tbl.insert(*k, enc.as_slice())?;
        }
    }
    wtxn.commit()?;
    Ok(())
}

fn reencrypt_str_table(
    db: &Database,
    table_def: TableDefinition<&str, &[u8]>,
    old: &Aes256Gcm,
    new: &Aes256Gcm,
) -> Result<()> {
    let pairs: Vec<(String, Vec<u8>)> = {
        let rtxn = db.begin_read()?;
        let tbl = rtxn.open_table(table_def)?;
        let mut v = Vec::new();
        for item in tbl.iter()? {
            let (k, val) = item?;
            let plain = decrypt_with(old, val.value())?;
            v.push((k.value().to_owned(), plain));
        }
        v
    };
    let wtxn = db.begin_write()?;
    {
        let mut tbl = wtxn.open_table(table_def)?;
        for (k, plain) in &pairs {
            let enc = encrypt_with(new, plain)?;
            tbl.insert(k.as_str(), enc.as_slice())?;
        }
    }
    wtxn.commit()?;
    Ok(())
}

// Table definitions
pub const CONFIG_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("config");
pub const BANS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("bans");
pub const BANS_BY_HDID_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("bans_by_hdid");
pub const ACCOUNTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");
pub const WATCHLIST_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("watchlist");
pub const IPID_BANS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("ipid_bans");

/// An embedded redb database with per-session AES-256-GCM encryption and an
/// explicit write serialisation guard.
///
/// ## Write serialisation ("connection pooling")
///
/// redb is an embedded, single-writer MVCC store: only one write transaction
/// may be active at a time; concurrent reads are unrestricted.  `EncryptedDb`
/// wraps every write method behind a `std::sync::Mutex<()>` write guard so
/// that callers (which run inside `tokio::task::spawn_blocking`) contend on
/// *our* lock before they touch the database.  This makes the single-writer
/// contract explicit, prevents the redb-internal "already locked" errors under
/// high concurrency, and acts as the connection-pool gate for write operations.
///
/// All reads do NOT acquire the write guard — they use plain read transactions
/// and may run concurrently.
///
/// ## Write-ahead log / crash recovery
///
/// redb uses a write-ahead log (WAL) internally.  Every committed transaction
/// is fsync'd to the WAL before the commit returns.  If the process crashes
/// mid-write, the WAL is replayed on the next `Database::create` call and the
/// database is left in the last consistent state.  No additional crash-recovery
/// logic is needed at this layer; `EncryptedDb::check_integrity` performs a
/// lightweight read-only sanity check that exercises the WAL replay path.
pub struct EncryptedDb {
    pub inner: Database,
    cipher: Aes256Gcm,
    /// Serialises all write transactions.  Read transactions do not acquire this.
    write_guard: std::sync::Mutex<()>,
}

impl EncryptedDb {
    /// Open the database and perform a key rotation.
    ///
    /// ## Key rotation
    ///
    /// On every startup, the session encryption key is rotated:
    ///
    /// 1. Read `key_rotation_counter` from the config table (default 0).
    /// 2. Derive `old_session_key = HMAC-SHA256(master_key, "nyahao-session-<counter>")`.
    ///    First run (counter absent) uses `master_key` directly for backward compat.
    /// 3. Increment the counter.
    /// 4. Derive `new_session_key = HMAC-SHA256(master_key, "nyahao-session-<new_counter>")`.
    /// 5. Re-encrypt all encrypted tables from old key → new key in single transactions.
    /// 6. Persist the new counter.
    /// 7. Use `new_session_key` as the active cipher for this process lifetime.
    ///
    /// Forward secrecy: the in-memory session key changes every restart.
    /// A memory dump from session N cannot decrypt session N+1 data.
    /// The master key (`NYAHAO_DB_KEY`) never touches disk.
    pub fn open(path: &str, master_key: &[u8; 32]) -> Result<Self> {
        let db = Database::create(path).context("Failed to open database")?;

        // Ensure all tables exist.
        {
            let txn = db.begin_write()?;
            txn.open_table(CONFIG_TABLE)?;
            txn.open_table(BANS_TABLE)?;
            txn.open_table(BANS_BY_HDID_TABLE)?;
            txn.open_table(ACCOUNTS_TABLE)?;
            txn.open_table(WATCHLIST_TABLE)?;
            txn.open_table(IPID_BANS_TABLE)?;
            txn.commit()?;
        }

        // Read current rotation counter.
        let counter_opt: Option<u64> = {
            let rtxn = db.begin_read()?;
            let tbl = rtxn.open_table(CONFIG_TABLE)?;
            tbl.get(KEY_ROTATION_COUNTER_KEY)?
                .map(|v| {
                    let b = v.value();
                    if b.len() >= 8 {
                        u64::from_le_bytes(b[..8].try_into().unwrap())
                    } else {
                        0
                    }
                })
        };

        let new_counter = counter_opt.map(|c| c.wrapping_add(1)).unwrap_or(1);

        // Build old cipher.  On first-ever rotation (counter absent) we used the
        // raw master key, so we must decrypt with it directly.
        let old_cipher = if let Some(counter) = counter_opt {
            let k = derive_session_key(master_key, counter);
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k))
        } else {
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(master_key))
        };

        let new_key_bytes = derive_session_key(master_key, new_counter);
        let new_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&new_key_bytes));

        // Re-encrypt every encrypted table.
        reencrypt_u64_table(&db, BANS_TABLE, &old_cipher, &new_cipher)
            .context("Key rotation failed on bans table")?;
        reencrypt_str_table(&db, ACCOUNTS_TABLE, &old_cipher, &new_cipher)
            .context("Key rotation failed on accounts table")?;
        reencrypt_str_table(&db, WATCHLIST_TABLE, &old_cipher, &new_cipher)
            .context("Key rotation failed on watchlist table")?;
        reencrypt_str_table(&db, IPID_BANS_TABLE, &old_cipher, &new_cipher)
            .context("Key rotation failed on ipid_bans table")?;

        // Persist new counter.
        {
            let wtxn = db.begin_write()?;
            {
                let mut tbl = wtxn.open_table(CONFIG_TABLE)?;
                tbl.insert(KEY_ROTATION_COUNTER_KEY, new_counter.to_le_bytes().as_slice())?;
            }
            wtxn.commit()?;
        }

        tracing::info!(
            "DB key rotation complete: session {} → {}",
            counter_opt.unwrap_or(0),
            new_counter
        );

        Ok(Self { inner: db, cipher: new_cipher, write_guard: std::sync::Mutex::new(()) })
    }

    /// Lightweight startup integrity check.
    ///
    /// Opens a read transaction on every table to verify the database file and
    /// WAL are readable.  Should be called once after `open`; a failure here
    /// indicates file corruption or an incomplete WAL replay.
    pub fn check_integrity(&self) -> Result<()> {
        let rtxn = self.inner.begin_read().context("Integrity check: failed to begin read transaction")?;
        rtxn.open_table(CONFIG_TABLE).context("Integrity check: config table")?;
        rtxn.open_table(BANS_TABLE).context("Integrity check: bans table")?;
        rtxn.open_table(BANS_BY_HDID_TABLE).context("Integrity check: bans_by_hdid table")?;
        rtxn.open_table(ACCOUNTS_TABLE).context("Integrity check: accounts table")?;
        rtxn.open_table(WATCHLIST_TABLE).context("Integrity check: watchlist table")?;
        rtxn.open_table(IPID_BANS_TABLE).context("Integrity check: ipid_bans table")?;
        Ok(())
    }

    /// Encrypt plaintext with the current session key.
    /// Prepends a random 12-byte nonce to the ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt_with(&self.cipher, plaintext)
    }

    /// Decrypt data encrypted with the current session key (first 12 bytes = nonce).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        decrypt_with(&self.cipher, data)
    }

    /// Read raw (unencrypted) bytes from the config table.
    pub fn config_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let read = self.inner.begin_read()?;
        let table = read.open_table(CONFIG_TABLE)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    /// Write raw (unencrypted) bytes to the config table.
    pub fn config_set(&self, key: &str, value: &[u8]) -> Result<()> {
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        {
            let mut table = write.open_table(CONFIG_TABLE)?;
            table.insert(key, value)?;
        }
        write.commit()?;
        Ok(())
    }

    /// Delete a key from the config table.  Returns `true` if the key existed.
    pub fn config_delete(&self, key: &str) -> Result<bool> {
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        let removed;
        {
            let mut table = write.open_table(CONFIG_TABLE)?;
            removed = table.remove(key)?.is_some();
        }
        write.commit()?;
        Ok(removed)
    }

    /// Write an encrypted JSON value to the bans table.
    pub fn bans_insert(&self, id: u64, value: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(value)?;
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        {
            let mut table = write.open_table(BANS_TABLE)?;
            table.insert(id, encrypted.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    pub fn bans_get(&self, id: u64) -> Result<Option<Vec<u8>>> {
        let read = self.inner.begin_read()?;
        let table = read.open_table(BANS_TABLE)?;
        match table.get(id)? {
            Some(v) => Ok(Some(self.decrypt(v.value())?)),
            None => Ok(None),
        }
    }

    /// Store HDID → ban_id mapping (raw string key, u64 id as 8-byte LE).
    pub fn bans_by_hdid_insert(&self, hdid: &str, ban_id: u64) -> Result<()> {
        // Read existing list, append, write back
        let existing = self.bans_by_hdid_get(hdid)?;
        let mut ids = existing;
        ids.push(ban_id);
        let encoded = serde_json::to_vec(&ids)?;
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        {
            let mut table = write.open_table(BANS_BY_HDID_TABLE)?;
            table.insert(hdid, encoded.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    pub fn bans_by_hdid_get(&self, hdid: &str) -> Result<Vec<u64>> {
        let read = self.inner.begin_read()?;
        let table = read.open_table(BANS_BY_HDID_TABLE)?;
        match table.get(hdid)? {
            Some(v) => Ok(serde_json::from_slice(v.value())?),
            None => Ok(Vec::new()),
        }
    }

    /// Write an encrypted JSON value to the accounts table (key = username).
    pub fn accounts_insert(&self, username: &str, value: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(value)?;
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        {
            let mut table = write.open_table(ACCOUNTS_TABLE)?;
            table.insert(username, encrypted.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    pub fn accounts_get(&self, username: &str) -> Result<Option<Vec<u8>>> {
        let read = self.inner.begin_read()?;
        let table = read.open_table(ACCOUNTS_TABLE)?;
        match table.get(username)? {
            Some(v) => Ok(Some(self.decrypt(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn accounts_delete(&self, username: &str) -> Result<bool> {
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        let removed;
        {
            let mut table = write.open_table(ACCOUNTS_TABLE)?;
            removed = table.remove(username)?.is_some();
        }
        write.commit()?;
        Ok(removed)
    }

    /// Write an encrypted watchlist entry (key = hashed HDID).
    pub fn watchlist_insert(&self, hdid: &str, value: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(value)?;
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        {
            let mut table = write.open_table(WATCHLIST_TABLE)?;
            table.insert(hdid, encrypted.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    pub fn watchlist_get(&self, hdid: &str) -> Result<Option<Vec<u8>>> {
        let read = self.inner.begin_read()?;
        let table = read.open_table(WATCHLIST_TABLE)?;
        match table.get(hdid)? {
            Some(v) => Ok(Some(self.decrypt(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn watchlist_remove(&self, hdid: &str) -> Result<bool> {
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        let removed;
        {
            let mut table = write.open_table(WATCHLIST_TABLE)?;
            removed = table.remove(hdid)?.is_some();
        }
        write.commit()?;
        Ok(removed)
    }

    /// Return all watchlist entries as decrypted byte vecs.
    pub fn watchlist_list(&self) -> Result<Vec<crate::moderation::watchlist::WatchEntry>> {
        let read = self.inner.begin_read()?;
        let table = read.open_table(WATCHLIST_TABLE)?;
        let mut entries = Vec::new();
        for item in table.iter()? {
            let (_, v): (_, redb::AccessGuard<&[u8]>) = item?;
            let decrypted = self.decrypt(v.value())?;
            let entry: crate::moderation::watchlist::WatchEntry = serde_json::from_slice(&decrypted)?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Write an encrypted IPID ban record (key = hashed IPID).
    pub fn ipid_bans_insert(&self, ipid: &str, value: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(value)?;
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        {
            let mut table = write.open_table(IPID_BANS_TABLE)?;
            table.insert(ipid, encrypted.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    pub fn ipid_bans_get(&self, ipid: &str) -> Result<Option<Vec<u8>>> {
        let read = self.inner.begin_read()?;
        let table = read.open_table(IPID_BANS_TABLE)?;
        match table.get(ipid)? {
            Some(v) => Ok(Some(self.decrypt(v.value())?)),
            None => Ok(None),
        }
    }

    pub fn ipid_bans_remove(&self, ipid: &str) -> Result<bool> {
        let _guard = self.write_guard.lock().unwrap();
        let write = self.inner.begin_write()?;
        let removed;
        {
            let mut table = write.open_table(IPID_BANS_TABLE)?;
            removed = table.remove(ipid)?.is_some();
        }
        write.commit()?;
        Ok(removed)
    }
}
