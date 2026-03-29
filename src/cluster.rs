//! Cluster scaffolding for horizontal scaling, consistent hashing, gossip
//! protocol, and read-replica support.
//!
//! # Current status: scaffolding only
//!
//! Production deployment requires:
//! - A shared data store (Redis/Postgres) for cross-node session state
//! - A load balancer routing clients to the correct node
//! - Client-side reconnect support
//! - A proper gossip library (e.g. memberlist-rs)
//!
//! The gossip implementation here uses plain UDP + JSON and is intentionally
//! minimal: nodes push their `NodeState` to configured peers every 5 seconds,
//! and log received peer state.  No failure detection or convergence guarantees
//! are provided beyond what a simple heartbeat affords.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::{config::GossipConfig, server::ServerState};

// ─── Consistent Hash Ring ────────────────────────────────────────────────────

/// A consistent-hash ring with virtual nodes for balanced key distribution.
///
/// Keys and nodes are hashed with SHA-256 (truncated to u64) and placed on a
/// sorted ring.  Each physical node occupies `replicas` virtual positions.
pub struct ConsistentHash {
    /// BTreeMap from hash position → physical node name.
    ring: BTreeMap<u64, String>,
    replicas: usize,
}

impl ConsistentHash {
    /// Create an empty ring with `replicas` virtual nodes per physical node.
    pub fn new(replicas: usize) -> Self {
        Self { ring: BTreeMap::new(), replicas }
    }

    /// Add a physical node to the ring.
    pub fn add_node(&mut self, node: &str) {
        for i in 0..self.replicas {
            let key = format!("{}-{}", node, i);
            let hash = sha256_u64(key.as_bytes());
            self.ring.insert(hash, node.to_string());
        }
    }

    /// Remove a physical node (and all its virtual positions) from the ring.
    pub fn remove_node(&mut self, node: &str) {
        for i in 0..self.replicas {
            let key = format!("{}-{}", node, i);
            let hash = sha256_u64(key.as_bytes());
            self.ring.remove(&hash);
        }
    }

    /// Return the node responsible for `key`, or `None` if the ring is empty.
    pub fn get_node(&self, key: &[u8]) -> Option<&str> {
        if self.ring.is_empty() {
            return None;
        }
        let hash = sha256_u64(key);
        // Walk clockwise from `hash`; wrap around if past the last entry.
        self.ring
            .range(hash..)
            .next()
            .or_else(|| self.ring.iter().next())
            .map(|(_, n)| n.as_str())
    }
}

/// SHA-256 of `data`, truncated to the first 8 bytes as a `u64` (big-endian).
fn sha256_u64(data: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    u64::from_be_bytes(result[..8].try_into().expect("SHA-256 is at least 8 bytes"))
}

// ─── Gossip Protocol ─────────────────────────────────────────────────────────

/// The state a node advertises to its peers in each gossip heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node_id: String,
    pub player_count: usize,
    /// Names of areas with at least one player, for rough load display.
    pub active_areas: Vec<String>,
}

/// Live view of all known peers, keyed by node_id.
pub struct ClusterState {
    pub ring: ConsistentHash,
    pub peers: HashMap<String, NodeState>,
}

impl ClusterState {
    pub fn new(replicas: usize) -> Self {
        Self { ring: ConsistentHash::new(replicas), peers: HashMap::new() }
    }

    /// Insert or update a peer's state and keep the ring in sync.
    pub fn upsert_peer(&mut self, state: NodeState) {
        if !self.peers.contains_key(&state.node_id) {
            self.ring.add_node(&state.node_id);
        }
        self.peers.insert(state.node_id.clone(), state);
    }
}

// ─── Connection Multiplexing (scaffolding) ────────────────────────────────────
//
// Goal: one WebSocket connection per player that persists across area changes,
// so the client never reconnects when the player does `/move`.
//
// Current architecture: each connection maps 1:1 to an area session.  When a
// player moves areas, the server updates `ClientHandle.area_idx` in-place —
// the *connection* does not change, only the logical area assignment does.
// This means the server side already supports this; no reconnect is needed.
//
// What IS needed for true connection multiplexing in a multi-process setup:
//   - A routing layer (load balancer) that pins each client's WebSocket to the
//     correct Ferris-AO node based on a session token (e.g. a cookie or query
//     param issued during the HI handshake).
//   - Shared session state so any node can service a client after failover
//     (requires a Redis/Postgres backend — see Read Replicas below).
//   - Client-side reconnect logic that re-sends the session token on the new
//     connection so the server can restore `ClientSession` state.
//
// Within a single process (current deployment model) multiplexing is already
// fully implemented: `ClientHandle` persists for the lifetime of the
// WebSocket connection regardless of how many areas the player visits.

// ─── Read Replicas (scaffolding) ─────────────────────────────────────────────
//
// Goal: secondary read-only server instances that mirror state from the primary
// so that moderators / spectators can connect to a replica without adding load
// to the primary.
//
// Required infrastructure (not yet implemented):
//
//   1. Shared data store — an external Redis or Postgres instance that both the
//      primary and replicas read/write.  `EncryptedDb` (redb) is a local
//      embedded store and cannot be shared across processes.
//
//   2. State replication stream — the primary publishes area events (IC
//      messages, HP changes, music changes, ARUP) to a Redis pub/sub channel;
//      replicas subscribe and forward to their connected read-only clients.
//
//   3. Read-only handshake mode — clients connecting to a replica receive the
//      current area state but all write packets (MS, MC, HP, …) are rejected
//      with a "read-only" error.
//
//   4. `GossipConfig.read_replica = true` flag to enable this mode.
//
// The gossip protocol in this file (`start_cluster`) already broadcasts
// `NodeState` (player counts, active areas) to peers.  The replication stream
// described above is a natural extension once a shared store is available.

/// Placeholder read-replica config — wired through `GossipConfig` when the
/// shared-store backend is available.
#[allow(dead_code)]
pub struct ReadReplicaConfig {
    /// When true, this node operates in read-only mode.
    pub enabled: bool,
    /// Primary node address to subscribe to for state events.
    pub primary_addr: String,
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Start the cluster gossip task if `cfg.enabled = true`.
///
/// When disabled this is a no-op and returns immediately, so it is always safe
/// to call unconditionally from `main`.
pub async fn start_cluster(cfg: GossipConfig, state: Arc<ServerState>) {
    if !cfg.enabled {
        debug!("Cluster gossip disabled (cluster.enabled = false).");
        return;
    }

    let node_id = if cfg.node_id.is_empty() {
        // Auto-generate a node id from the hostname and gossip port.
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "node".into());
        format!("{}:{}", hostname, cfg.gossip_port)
    } else {
        cfg.node_id.clone()
    };

    info!(
        "Cluster gossip enabled.  node_id={} port={} peers={:?}",
        node_id, cfg.gossip_port, cfg.peers
    );

    let bind_addr = format!("0.0.0.0:{}", cfg.gossip_port);
    let socket = match UdpSocket::bind(&bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!("Failed to bind gossip UDP socket on {}: {}", bind_addr, e);
            return;
        }
    };

    // Receiver task
    let recv_socket = Arc::clone(&socket);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match recv_socket.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    match serde_json::from_slice::<NodeState>(&buf[..len]) {
                        Ok(peer_state) => {
                            debug!(
                                "Gossip from {} ({}): {} players, areas={:?}",
                                peer_state.node_id, peer, peer_state.player_count, peer_state.active_areas
                            );
                        }
                        Err(e) => {
                            warn!("Gossip parse error from {}: {}", peer, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Gossip recv error: {}", e);
                }
            }
        }
    });

    // Sender task — push NodeState to all configured peers every 5 seconds.
    let send_socket = Arc::clone(&socket);
    let peers = cfg.peers.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;

            let player_count = state.player_count.load(std::sync::atomic::Ordering::Relaxed);
            let active_areas: Vec<String> = {
                let mut names = Vec::new();
                let clients = state.clients.lock().await;
                let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
                for h in clients.values() {
                    if seen.insert(h.area_idx) {
                        if let Some(area_arc) = state.areas.get(h.area_idx) {
                            let area = area_arc.read().await;
                            names.push(area.name.clone());
                        }
                    }
                }
                names
            };

            let my_state = NodeState {
                node_id: node_id.clone(),
                player_count,
                active_areas,
            };

            if let Ok(payload) = serde_json::to_vec(&my_state) {
                for peer in &peers {
                    if let Err(e) = send_socket.send_to(&payload, peer).await {
                        debug!("Gossip send to {} failed: {}", peer, e);
                    }
                }
            }
        }
    });
}
