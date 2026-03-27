use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub network: NetworkConfig,
    pub privacy: PrivacyConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub name: String,
    pub description: String,
    pub motd: String,
    pub max_players: usize,
    pub max_message_len: usize,
    pub asset_url: String,
    pub multiclient_limit: usize,
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    pub tcp_port: u16,
    pub ws_port: u16,
    pub bind_addr: String,
}

#[derive(Debug, Deserialize)]
pub struct PrivacyConfig {
    pub server_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub log_level: String,
    pub log_chat: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config at {}", path.display()))?;
        let config: Config = toml::from_str(&content).context("Failed to parse config.toml")?;
        Ok(config)
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            log_chat: false,
        }
    }
}
