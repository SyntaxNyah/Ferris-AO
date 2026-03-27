use std::collections::BinaryHeap;
use std::cmp::Reverse;
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use std::collections::HashMap;

use crate::{
    auth::AccountManager,
    client::PairInfo,
    config::Config,
    game::areas::Area,
    moderation::BanManager,
    privacy::PrivacyLayer,
    ratelimit::TokenBucket,
    storage::EncryptedDb,
};

pub const VERSION: &str = "NyahAO v0.1.0";

/// A handle to a connected client, stored in ServerState and readable by all tasks.
#[derive(Clone)]
pub struct ClientHandle {
    pub uid: u32,
    pub area_idx: usize,
    pub ipid: String,
    pub hdid: Option<String>,
    pub char_id: Option<usize>,
    pub authenticated: bool,
    pub tx: mpsc::UnboundedSender<String>,
    // Pairing — updated after each IC message and by /pair//unpair
    pub pair_wanted_id: Option<usize>,
    pub force_pair_uid: Option<u32>,
    pub pair_info: PairInfo,
    pub pos: String,
}

impl ClientHandle {
    pub fn send(&self, msg: &str) {
        let _ = self.tx.send(msg.to_string());
    }

    pub fn send_packet(&self, header: &str, args: &[&str]) {
        let msg = if args.is_empty() {
            format!("{}#%", header)
        } else {
            format!("{}#{}#%", header, args.join("#"))
        };
        self.send(&msg);
    }
}

/// All shared server state. Held in Arc, accessed concurrently.
pub struct ServerState {
    pub config: Config,
    pub characters: Vec<String>,
    pub music: Vec<String>,
    pub backgrounds: Vec<String>,

    /// All areas; each protected by an RwLock.
    pub areas: Vec<Arc<RwLock<Area>>>,

    /// Connected clients indexed by UID.
    pub clients: Mutex<HashMap<u32, Arc<ClientHandle>>>,

    /// UID allocator (min-heap of recycled UIDs).
    pub uid_pool: Mutex<BinaryHeap<Reverse<u32>>>,

    /// Atomic player count for quick access.
    pub player_count: AtomicUsize,

    pub privacy: PrivacyLayer,
    pub db: Arc<EncryptedDb>,
    pub accounts: AccountManager,
    pub bans: BanManager,

    /// Pre-built SM packet string (built once at startup).
    pub sm_packet: String,

    /// Notifies the master server task whenever the player count changes.
    pub player_watch_tx: watch::Sender<usize>,

    /// Per-IP connection rate limiters. Keyed on raw source IP (before IPID hashing).
    /// Checked in the TCP and WebSocket listeners before a session is created.
    pub conn_limiters: Mutex<HashMap<IpAddr, TokenBucket>>,
}

impl ServerState {
    pub fn new(
        config: Config,
        characters: Vec<String>,
        music: Vec<String>,
        backgrounds: Vec<String>,
        areas: Vec<Arc<RwLock<Area>>>,
        privacy: PrivacyLayer,
        db: Arc<EncryptedDb>,
        sm_packet: String,
        player_watch_tx: watch::Sender<usize>,
    ) -> Self {
        let max = config.server.max_players;
        let accounts = AccountManager::new(Arc::clone(&db));
        let bans = BanManager::new(Arc::clone(&db));

        // Initialize UID pool with all available UIDs
        let mut pool = BinaryHeap::new();
        for i in 0..max as u32 {
            pool.push(Reverse(i));
        }

        Self {
            config,
            characters,
            music,
            backgrounds,
            areas,
            clients: Mutex::new(HashMap::new()),
            uid_pool: Mutex::new(pool),
            player_count: AtomicUsize::new(0),
            privacy,
            db,
            accounts,
            bans,
            sm_packet,
            player_watch_tx,
            conn_limiters: Mutex::new(HashMap::new()),
        }
    }

    /// Check whether a new connection from `ip` is within the configured rate limit.
    /// Returns `true` if the connection is allowed, `false` if it should be dropped.
    /// Idle entries whose bucket is full are pruned on each call to keep the map small.
    pub async fn check_conn_rate(&self, ip: IpAddr) -> bool {
        if self.config.rate_limits.conn_burst == 0 {
            return true; // burst=0 means disabled
        }
        let rl = &self.config.rate_limits;
        let mut limiters = self.conn_limiters.lock().await;
        // Prune full (idle) buckets to prevent unbounded growth.
        limiters.retain(|_, bucket| !bucket.is_full());
        let bucket = limiters
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(rl.conn_rate, rl.conn_burst));
        bucket.try_consume()
    }

    pub fn player_count(&self) -> usize {
        self.player_count.load(Ordering::Relaxed)
    }

    /// Allocate a UID. Returns None if server is full.
    pub async fn alloc_uid(&self) -> Option<u32> {
        let mut pool = self.uid_pool.lock().await;
        pool.pop().map(|Reverse(id)| id)
    }

    /// Return a UID to the pool.
    pub async fn free_uid(&self, uid: u32) {
        let mut pool = self.uid_pool.lock().await;
        pool.push(Reverse(uid));
    }

    /// Register a connected client.
    pub async fn add_client(&self, handle: Arc<ClientHandle>) {
        let uid = handle.uid;
        let mut clients = self.clients.lock().await;
        clients.insert(uid, handle);
    }

    /// Remove a client by UID.
    pub async fn remove_client(&self, uid: u32) {
        let mut clients = self.clients.lock().await;
        clients.remove(&uid);
    }

    fn format_packet(header: &str, args: &[&str]) -> String {
        if args.is_empty() {
            format!("{}#%", header)
        } else {
            format!("{}#{}#%", header, args.join("#"))
        }
    }

    /// Send a packet to all clients with a joined UID.
    pub async fn broadcast(&self, header: &str, args: &[&str]) {
        let msg = Self::format_packet(header, args);
        let clients = self.clients.lock().await;
        for handle in clients.values() {
            handle.send(&msg);
        }
    }

    /// Send a packet to all clients in a specific area.
    pub async fn broadcast_to_area(&self, area_idx: usize, header: &str, args: &[&str]) {
        let msg = Self::format_packet(header, args);
        let clients = self.clients.lock().await;
        for handle in clients.values() {
            if handle.area_idx == area_idx {
                handle.send(&msg);
            }
        }
    }

    /// Broadcast ARUP (player counts) to all clients.
    pub async fn send_player_arup(&self) {
        let mut args: Vec<String> = vec!["0".into()];
        for area_arc in &self.areas {
            let area = area_arc.read().await;
            args.push(area.players.to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.broadcast("ARUP", &arg_refs).await;
    }

    /// Broadcast ARUP (statuses) to all clients.
    pub async fn send_status_arup(&self) {
        let mut args: Vec<String> = vec!["1".into()];
        for area_arc in &self.areas {
            let area = area_arc.read().await;
            args.push(area.status.as_str().to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.broadcast("ARUP", &arg_refs).await;
    }

    /// Broadcast ARUP (CM list) to all clients.
    pub async fn send_cm_arup(&self) {
        let clients = self.clients.lock().await;
        let mut args: Vec<String> = vec!["2".into()];
        for area_arc in &self.areas {
            let area = area_arc.read().await;
            if area.cms.is_empty() {
                args.push("FREE".into());
            } else {
                let cm_strs: Vec<String> = area.cms.iter().filter_map(|&uid| {
                    clients.get(&uid).map(|h| {
                        let char_name = h.char_id
                            .and_then(|id| self.characters.get(id))
                            .map(|s| s.as_str())
                            .unwrap_or("Spectator");
                        format!("{} ({})", char_name, uid)
                    })
                }).collect();
                args.push(cm_strs.join(", "));
            }
        }
        drop(clients);
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.broadcast("ARUP", &arg_refs).await;
    }

    /// Broadcast ARUP (lock states) to all clients.
    pub async fn send_lock_arup(&self) {
        let mut args: Vec<String> = vec!["3".into()];
        for area_arc in &self.areas {
            let area = area_arc.read().await;
            args.push(area.lock.as_str().to_string());
        }
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.broadcast("ARUP", &arg_refs).await;
    }
}
