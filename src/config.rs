use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub network: NetworkConfig,
    pub privacy: PrivacyConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub master_server: MasterServerConfig,
    #[serde(default)]
    pub rate_limits: RateLimitsConfig,
    #[serde(default)]
    pub censor: CensorConfig,
    #[serde(default)]
    pub cluster: GossipConfig,
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
    /// Hard limit on incoming packet size in bytes. Packets larger than this
    /// are dropped before parsing. Default: 8192.
    #[serde(default = "default_max_packet_bytes")]
    pub max_packet_bytes: usize,

    /// Maximum number of packets allowed in a client's outbound queue at once.
    /// When the queue is full, additional sends are silently dropped and the
    /// client is eventually cleaned up by the keepalive timeout.
    /// Increase this if fast-moving areas generate legitimate bursts; decrease
    /// it to shed slow consumers sooner.  Default: 256.
    #[serde(default = "default_outbound_queue_cap")]
    pub outbound_queue_cap: usize,

    /// When true, applies a pending server_secret rotation on next startup.
    ///
    /// Workflow:
    ///   1. In-game admin runs `/rotatesecret`; this writes a new secret to
    ///      the config table under the key "server_secret_pending".
    ///   2. Set `secret_rotation_enabled = true` in config.toml and restart.
    ///   3. On startup, the pending secret replaces the active one.
    ///
    /// IMPORTANT: HDID-keyed records (bans, watchlist) were derived from the
    /// old secret.  They remain in the database but will never match future
    /// connections.  Review and re-add any critical entries after rotation.
    ///
    /// Default: false.
    #[serde(default)]
    pub secret_rotation_enabled: bool,

    /// When true, the server will look for `data/db_key_new.hex` on startup.
    /// If found, it is used as the new DB key and renamed to `data/db_key_active.hex`.
    /// NOTE: This starts a fresh database — back up your old db before enabling.
    /// Default: false.
    #[serde(default)]
    pub key_rotation_enabled: bool,

    /// Argon2id memory cost in KiB.  Default: 65536 (64 MiB).
    #[serde(default = "default_argon2_memory")]
    pub argon2_memory_kib: u32,

    /// Argon2id iteration count.  Default: 3.
    #[serde(default = "default_argon2_iterations")]
    pub argon2_iterations: u32,

    /// Argon2id parallelism (thread count).  Default: 2.
    #[serde(default = "default_argon2_parallelism")]
    pub argon2_parallelism: u32,

    /// When > 0, outbound packets are batched up to this many before flushing.
    /// 0 = disabled (flush every packet immediately).  Default: 0.
    #[serde(default)]
    pub packet_batch_size: usize,

    /// Milliseconds to wait before force-flushing a partial batch.
    /// Only used when packet_batch_size > 0.  Default: 5.
    #[serde(default = "default_packet_batch_interval_ms")]
    pub packet_batch_interval_ms: u64,

    /// Enable binary (MessagePack) protocol.  Default: false.
    /// Clients opt-in by sending `BINARY#1#%` as their first message.
    #[serde(default)]
    pub binary_protocol: bool,
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    pub tcp_port: u16,
    pub ws_port: u16,
    pub bind_addr: String,
    /// When true, proxy headers (X-Forwarded-For, X-Real-IP) are trusted for
    /// the real client IP. Must be false unless nginx/Cloudflare is in front.
    #[serde(default)]
    pub reverse_proxy_mode: bool,
    /// External HTTP port advertised when reverse_proxy_mode is true (e.g. 80).
    #[serde(default = "default_http_port")]
    pub reverse_proxy_http_port: u16,
    /// External HTTPS port advertised when reverse_proxy_mode is true (e.g. 443).
    #[serde(default = "default_https_port")]
    pub reverse_proxy_https_port: u16,
    /// Interval in seconds between WebSocket ping frames. 0 disables keepalive.
    #[serde(default = "default_ws_ping_interval")]
    pub ws_ping_interval_secs: u64,
    /// Seconds after which a WS client that has not responded to pings is
    /// considered stale and disconnected. 0 disables timeout.
    #[serde(default = "default_ws_ping_timeout")]
    pub ws_ping_timeout_secs: u64,

    /// Enable WebSocket permessage-deflate compression.  Default: false.
    /// NOTE: Requires tungstenite >= 0.20 with the `permessage-deflate` feature.
    /// The current tungstenite 0.26 crate does not expose WebSocketConfig::compression;
    /// this field is reserved for future use.
    /// TODO: Enable when tungstenite exposes permessage-deflate in WebSocketConfig.
    #[serde(default)]
    pub ws_compression: bool,
}

fn default_http_port() -> u16 { 80 }
fn default_https_port() -> u16 { 443 }
fn default_ws_ping_interval() -> u64 { 30 }
fn default_ws_ping_timeout() -> u64 { 90 }
fn default_max_packet_bytes() -> usize { 8192 }
fn default_outbound_queue_cap() -> usize { 256 }
fn default_argon2_memory() -> u32 { 65536 }
fn default_argon2_iterations() -> u32 { 3 }
fn default_argon2_parallelism() -> u32 { 2 }
fn default_packet_batch_interval_ms() -> u64 { 5 }

#[derive(Debug, Deserialize)]
pub struct PrivacyConfig {
    pub server_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub log_level: String,
    pub log_chat: bool,
}

#[derive(Debug, Deserialize)]
pub struct MasterServerConfig {
    /// Advertise this server on the master server list.
    #[serde(default)]
    pub advertise: bool,
    /// Master server URL.
    #[serde(default = "default_ms_addr")]
    pub addr: String,
    /// Optional hostname/IP to advertise. If unset, the master server infers it.
    pub hostname: Option<String>,
}

fn default_ms_addr() -> String {
    "https://servers.aceattorneyonline.com/servers".into()
}

impl Default for MasterServerConfig {
    fn default() -> Self {
        Self {
            advertise: false,
            addr: default_ms_addr(),
            hostname: None,
        }
    }
}

/// Per-packet and per-connection rate limit configuration.
/// All limits use a token bucket algorithm (rate + burst).
/// Defaults are applied when the `[rate_limits]` section is absent from config.toml.
#[derive(Debug, Deserialize)]
pub struct RateLimitsConfig {
    /// IC message (MS) tokens per second.
    #[serde(default = "default_ic_rate")]
    pub ic_rate: f64,
    /// IC message burst ceiling (max tokens).
    #[serde(default = "default_ic_burst")]
    pub ic_burst: u32,

    /// Music change (MC) tokens per second.
    #[serde(default = "default_mc_rate")]
    pub mc_rate: f64,
    /// Music change burst ceiling.
    #[serde(default = "default_mc_burst")]
    pub mc_burst: u32,

    /// OOC message (CT) tokens per second.
    #[serde(default = "default_ct_rate")]
    pub ct_rate: f64,
    /// OOC message burst ceiling.
    #[serde(default = "default_ct_burst")]
    pub ct_burst: u32,

    /// Evidence operation (PE/DE/EE) tokens per second.
    #[serde(default = "default_evi_rate")]
    pub evidence_rate: f64,
    /// Evidence operation burst ceiling.
    #[serde(default = "default_evi_burst")]
    pub evidence_burst: u32,

    /// Seconds a client must wait between mod calls (ZZ). 0 disables the cooldown.
    #[serde(default = "default_zz_cooldown")]
    pub zz_cooldown_secs: u64,

    /// New TCP/WS connections allowed per second per source IP.
    /// e.g. 0.0833 ≈ 5 per minute.
    #[serde(default = "default_conn_rate")]
    pub conn_rate: f64,
    /// Connection burst ceiling per source IP.
    #[serde(default = "default_conn_burst")]
    pub conn_burst: u32,
}

fn default_ic_rate() -> f64 { 3.0 }
fn default_ic_burst() -> u32 { 5 }
fn default_mc_rate() -> f64 { 1.0 }
fn default_mc_burst() -> u32 { 3 }
fn default_ct_rate() -> f64 { 2.0 }
fn default_ct_burst() -> u32 { 5 }
fn default_evi_rate() -> f64 { 5.0 }
fn default_evi_burst() -> u32 { 10 }
fn default_zz_cooldown() -> u64 { 60 }
// 1 connection per second (60/min) — permissive enough for bad WiFi reconnects
fn default_conn_rate() -> f64 { 1.0 }
fn default_conn_burst() -> u32 { 5 }

/// Word-censor configuration. When enabled, IC messages containing any word
/// from `data/censor.txt` are silently intercepted: the sender sees their
/// message as if it was sent, but it is not broadcast to others.
#[derive(Debug, Deserialize)]
pub struct CensorConfig {
    /// Enable the censor filter. Default: false.
    /// Has no effect if `data/censor.txt` is absent or empty.
    #[serde(default)]
    pub enabled: bool,
}

impl Default for CensorConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

impl Default for RateLimitsConfig {
    fn default() -> Self {
        Self {
            ic_rate: default_ic_rate(),
            ic_burst: default_ic_burst(),
            mc_rate: default_mc_rate(),
            mc_burst: default_mc_burst(),
            ct_rate: default_ct_rate(),
            ct_burst: default_ct_burst(),
            evidence_rate: default_evi_rate(),
            evidence_burst: default_evi_burst(),
            zz_cooldown_secs: default_zz_cooldown(),
            conn_rate: default_conn_rate(),
            conn_burst: default_conn_burst(),
        }
    }
}

/// Cluster / gossip configuration.  All fields default to disabled/empty so
/// existing deployments without a `[cluster]` section are unaffected.
#[derive(Debug, Deserialize, Clone)]
pub struct GossipConfig {
    /// Enable the gossip protocol.  Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Unique identifier for this node.  Default: empty (auto-assigned at startup).
    #[serde(default)]
    pub node_id: String,

    /// Peer addresses to gossip with (host:port).  Default: empty.
    #[serde(default)]
    pub peers: Vec<String>,

    /// UDP port to listen on for incoming gossip messages.  Default: 27019.
    #[serde(default = "default_gossip_port")]
    pub gossip_port: u16,

    /// Number of virtual nodes per real node in the consistent-hash ring.  Default: 150.
    #[serde(default = "default_hash_replicas")]
    pub hash_replicas: usize,
}

fn default_gossip_port() -> u16 { 27019 }
fn default_hash_replicas() -> usize { 150 }

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: String::new(),
            peers: Vec::new(),
            gossip_port: default_gossip_port(),
            hash_replicas: default_hash_replicas(),
        }
    }
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
