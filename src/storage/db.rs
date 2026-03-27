use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use redb::{Database, TableDefinition};

// Table definitions
pub const CONFIG_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("config");
pub const BANS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("bans");
pub const BANS_BY_HDID_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("bans_by_hdid");
pub const ACCOUNTS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");

pub struct EncryptedDb {
    pub inner: Database,
    cipher: Aes256Gcm,
}

impl EncryptedDb {
    pub fn open(path: &str, key_bytes: &[u8; 32]) -> Result<Self> {
        let db = Database::create(path).context("Failed to open database")?;
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Ensure tables exist
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(CONFIG_TABLE)?;
            write_txn.open_table(BANS_TABLE)?;
            write_txn.open_table(BANS_BY_HDID_TABLE)?;
            write_txn.open_table(ACCOUNTS_TABLE)?;
        }
        write_txn.commit()?;

        Ok(Self { inner: db, cipher })
    }

    /// Encrypt plaintext. Prepends a random 12-byte nonce to the ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt data (first 12 bytes are the nonce).
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 13 {
            anyhow::bail!("Ciphertext too short");
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
    }

    /// Read raw (unencrypted) bytes from the config table.
    pub fn config_get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let read = self.inner.begin_read()?;
        let table = read.open_table(CONFIG_TABLE)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    /// Write raw (unencrypted) bytes to the config table.
    pub fn config_set(&self, key: &str, value: &[u8]) -> Result<()> {
        let write = self.inner.begin_write()?;
        {
            let mut table = write.open_table(CONFIG_TABLE)?;
            table.insert(key, value)?;
        }
        write.commit()?;
        Ok(())
    }

    /// Write an encrypted JSON value to the bans table.
    pub fn bans_insert(&self, id: u64, value: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(value)?;
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
        let write = self.inner.begin_write()?;
        let removed;
        {
            let mut table = write.open_table(ACCOUNTS_TABLE)?;
            removed = table.remove(username)?.is_some();
        }
        write.commit()?;
        Ok(removed)
    }
}
