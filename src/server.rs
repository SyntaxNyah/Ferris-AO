use std::collections::BinaryHeap;
use std::cmp::Reverse;
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::{mpsc, mpsc::Sender, watch, Mutex, RwLock};
use std::collections::HashMap;

use std::collections::HashSet;

use crate::{
    auth::AccountManager,
    client::PairInfo,
    config::Config,
    game::{areas::Area, characters::{build_sm_packet, load_censor_words, load_lines}},
    moderation::{BanManager, IpidBanManager, WatchlistManager},
    privacy::PrivacyLayer,
    ratelimit::TokenBucket,
    storage::EncryptedDb,
};

pub const VERSION: &str = "NyahAO v0.1.0";

/// Cached snapshot of the last-broadcast ARUP values.
///
/// `send_*_arup` functions compare current area state against this snapshot
/// before transmitting.  If nothing changed the broadcast is skipped entirely,
/// saving a full client-list walk and socket writes after area events that
/// don't actually change lobby-visible state.
#[derive(Default)]
pub struct ArupSnapshot {
    pub player_counts: Vec<usize>,
    pub statuses:      Vec<String>,
    pub cm_labels:     Vec<String>,
    pub lock_states:   Vec<String>,
}

/// Game data that can be hot-reloaded at runtime via /reload.
pub struct ReloadableData {
    pub characters: Vec<String>,
    pub music: Vec<String>,
    pub backgrounds: Vec<String>,
    /// Pre-built SM packet string (sent to every joining client).
    pub sm_packet: String,
    /// Words loaded from data/censor.txt (pre-lowercased). Empty = no filter.
    pub censor_words: Vec<String>,
}

/// A handle to a connected client, stored in ServerState and readable by all tasks.
#[derive(Clone)]
pub struct ClientHandle {
    pub uid: u32,
    pub area_idx: usize,
    pub ipid: String,
    pub hdid: Option<String>,
    pub char_id: Option<usize>,
    pub authenticated: bool,
    pub tx: Sender<String>,
    // Pairing — updated after each IC message and by /pair//unpair
    pub pair_wanted_id: Option<usize>,
    pub force_pair_uid: Option<u32>,
    pub pair_info: PairInfo,
    pub pos: String,
    /// UIDs this client has /ignored — their IC and OOC messages are not delivered here.
    pub ignored_uids: HashSet<u32>,
}

impl ClientHandle {
    /// Queue a message for this client.  Silently drops on a full channel;
    /// the keepalive timeout will eventually clean up a persistently slow client.
    pub fn send(&self, msg: &str) {
        let _ = self.tx.try_send(msg.to_string());
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
    /// Hot-reloadable game data (characters, music, backgrounds, SM packet).
    pub reloadable: RwLock<ReloadableData>,

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
    pub ipid_bans: IpidBanManager,
    pub watchlist: WatchlistManager,

    /// Notifies the master server task whenever the player count changes.
    pub player_watch_tx: watch::Sender<usize>,

    /// Per-IP connection rate limiters. Keyed on raw source IP (before IPID hashing).
    /// Checked in the TCP and WebSocket listeners before a session is created.
    pub conn_limiters: Mutex<HashMap<IpAddr, TokenBucket>>,

    /// Last-broadcast ARUP values — used for delta suppression.
    pub last_arup: Mutex<ArupSnapshot>,
}

impl ServerState {
    pub fn new(
        config: Config,
        reloadable: ReloadableData,
        areas: Vec<Arc<RwLock<Area>>>,
        privacy: PrivacyLayer,
        db: Arc<EncryptedDb>,
        player_watch_tx: watch::Sender<usize>,
    ) -> Self {
        let max = config.server.max_players;
        let accounts = AccountManager::new(Arc::clone(&db));
        let bans = BanManager::new(Arc::clone(&db));
        let ipid_bans = IpidBanManager::new(Arc::clone(&db));
        let watchlist = WatchlistManager::new(Arc::clone(&db));

        // Initialize UID pool with all available UIDs
        let mut pool = BinaryHeap::new();
        for i in 0..max as u32 {
            pool.push(Reverse(i));
        }

        Self {
            config,
            reloadable: RwLock::new(reloadable),
            areas,
            clients: Mutex::new(HashMap::new()),
            uid_pool: Mutex::new(pool),
            player_count: AtomicUsize::new(0),
            privacy,
            db,
            accounts,
            bans,
            ipid_bans,
            watchlist,
            player_watch_tx,
            conn_limiters: Mutex::new(HashMap::new()),
            last_arup: Mutex::new(ArupSnapshot::default()),
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

    /// Send a packet to all clients in an area, skipping any receiver who has
    /// `sender_uid` in their ignore list (used for IC and OOC messages).
    pub async fn broadcast_to_area_from(&self, area_idx: usize, sender_uid: u32, header: &str, args: &[&str]) {
        let msg = Self::format_packet(header, args);
        let clients = self.clients.lock().await;
        for handle in clients.values() {
            if handle.area_idx == area_idx && !handle.ignored_uids.contains(&sender_uid) {
                handle.send(&msg);
            }
        }
    }

    /// Broadcast ARUP type 0 (player counts) — skipped when nothing changed.
    pub async fn send_player_arup(&self) {
        let current: Vec<usize> = {
            let mut v = Vec::with_capacity(self.areas.len());
            for a in &self.areas {
                v.push(a.read().await.players);
            }
            v
        };
        {
            let mut snap = self.last_arup.lock().await;
            if snap.player_counts == current {
                return;
            }
            snap.player_counts = current.clone();
        }
        let mut args: Vec<String> = vec!["0".into()];
        args.extend(current.iter().map(|n| n.to_string()));
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.broadcast("ARUP", &refs).await;
    }

    /// Broadcast ARUP type 1 (statuses) — skipped when nothing changed.
    pub async fn send_status_arup(&self) {
        let current: Vec<String> = {
            let mut v = Vec::with_capacity(self.areas.len());
            for a in &self.areas {
                v.push(a.read().await.status.as_str().to_string());
            }
            v
        };
        {
            let mut snap = self.last_arup.lock().await;
            if snap.statuses == current {
                return;
            }
            snap.statuses = current.clone();
        }
        let mut args: Vec<String> = vec!["1".into()];
        args.extend(current.iter().cloned());
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.broadcast("ARUP", &refs).await;
    }

    /// Broadcast ARUP type 2 (CM labels) — skipped when nothing changed.
    pub async fn send_cm_arup(&self) {
        let characters: Vec<String> = {
            self.reloadable.read().await.characters.clone()
        };
        let current: Vec<String> = {
            let clients = self.clients.lock().await;
            let mut v = Vec::with_capacity(self.areas.len());
            for a in &self.areas {
                let area = a.read().await;
                if area.cms.is_empty() {
                    v.push("FREE".into());
                } else {
                    let strs: Vec<String> = area.cms.iter().filter_map(|&uid| {
                        clients.get(&uid).map(|h| {
                            let char_name = h.char_id
                                .and_then(|id| characters.get(id))
                                .map(|s| s.as_str())
                                .unwrap_or("Spectator");
                            format!("{} ({})", char_name, uid)
                        })
                    }).collect();
                    v.push(strs.join(", "));
                }
            }
            v
        };
        {
            let mut snap = self.last_arup.lock().await;
            if snap.cm_labels == current {
                return;
            }
            snap.cm_labels = current.clone();
        }
        let mut args: Vec<String> = vec!["2".into()];
        args.extend(current.iter().cloned());
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.broadcast("ARUP", &refs).await;
    }

    /// Broadcast ARUP type 3 (lock states) — skipped when nothing changed.
    pub async fn send_lock_arup(&self) {
        let current: Vec<String> = {
            let mut v = Vec::with_capacity(self.areas.len());
            for a in &self.areas {
                v.push(a.read().await.lock.as_str().to_string());
            }
            v
        };
        {
            let mut snap = self.last_arup.lock().await;
            if snap.lock_states == current {
                return;
            }
            snap.lock_states = current.clone();
        }
        let mut args: Vec<String> = vec!["3".into()];
        args.extend(current.iter().cloned());
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.broadcast("ARUP", &refs).await;
    }
}

/// Hot-reload characters, music, backgrounds, and censor words from disk.
///
/// This is called by both the `/reload` command and the SIGHUP handler (Unix).
/// Returns a human-readable summary string on success, or an error.
pub async fn reload_game_data(state: &Arc<ServerState>) -> anyhow::Result<String> {
    use anyhow::Context;
    let characters = load_lines(std::path::Path::new("data/characters.txt"))
        .context("Failed to load data/characters.txt")?;
    let music = load_lines(std::path::Path::new("data/music.txt"))
        .context("Failed to load data/music.txt")?;
    let backgrounds = load_lines(std::path::Path::new("data/backgrounds.txt"))
        .context("Failed to load data/backgrounds.txt")?;
    let censor_words = load_censor_words(std::path::Path::new("data/censor.txt"));

    // Build new SM packet using current area names.
    let area_names: Vec<String> = {
        let mut names = Vec::new();
        for area_arc in &state.areas {
            let area = area_arc.read().await;
            names.push(area.name.clone());
        }
        names
    };
    let area_name_refs: Vec<&str> = area_names.iter().map(|s| s.as_str()).collect();
    let sm_packet = build_sm_packet(&area_name_refs, &music);

    let counts = format!(
        "{} chars, {} music, {} backgrounds, {} censor words",
        characters.len(),
        music.len(),
        backgrounds.len(),
        censor_words.len()
    );
    {
        let mut data = state.reloadable.write().await;
        data.characters = characters;
        data.music = music;
        data.backgrounds = backgrounds;
        data.sm_packet = sm_packet;
        data.censor_words = censor_words;
    }
    Ok(counts)
}
