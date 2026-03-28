# CLAUDE.md — Ferris-AO Codebase Guide

This file gives a complete picture of the Ferris-AO codebase so Claude can work on it accurately without having to rediscover architecture on every task.

---

## What This Project Is

**Ferris-AO** is a privacy-first game server for [Attorney Online 2 (AO2)](https://attorneyonline.de/), written in Rust. The binary is named `nyahao`. It implements the full AO2 text protocol over both TCP and WebSocket, supporting multiplayer courtroom roleplay sessions (IC messages, music, evidence, pairing, moderation).

**Core philosophy:**
- Raw IPs and HDIDs are hashed immediately and never stored
- All sensitive DB records are AES-256-GCM encrypted at rest
- Passwords use Argon2id
- Rate limiting, proxy support, and privacy are first-class concerns

---

## Project Layout

```
Ferris-AO/
├── Cargo.toml              # Dependencies + release profile (LTO, codegen-units=1)
├── config.toml             # Runtime config (TOML)
├── data/
│   ├── areas.toml          # Area definitions (TOML array of [[area]])
│   ├── characters.txt      # One character folder name per line
│   ├── backgrounds.txt     # One background name per line
│   └── music.txt           # Music list; lines without '.' are category headers
├── nginx/
│   └── nyahao.conf         # Example nginx reverse proxy config
└── src/
    ├── main.rs             # Startup, stdin CLI, task spawning
    ├── server.rs           # ServerState, ClientHandle, broadcast, ARUP, UID pool
    ├── client.rs           # ClientSession: per-connection mutable state
    ├── config.rs           # TOML config structs (serde::Deserialize)
    ├── ratelimit.rs        # TokenBucket: token refill rate limiter
    ├── ms.rs               # Master server HTTP advertisement
    ├── auth/
    │   ├── mod.rs
    │   └── accounts.rs     # Account struct, AccountManager, Argon2id, permission bits
    ├── privacy/
    │   ├── mod.rs
    │   └── hashing.rs      # PrivacyLayer: IPID (daily-rotating) + HDID (permanent) HMAC-SHA256
    ├── moderation/
    │   ├── mod.rs
    │   ├── bans.rs         # BanRecord, BanManager (add/nullify/check)
    │   └── watchlist.rs    # WatchEntry, WatchlistManager (add/remove/list/get)
    ├── storage/
    │   ├── mod.rs
    │   └── db.rs           # EncryptedDb: redb + AES-256-GCM wrapper
    ├── network/
    │   ├── mod.rs          # AoTransport enum, handle_connection entry point
    │   ├── tcp.rs          # TCP listener, PROXY Protocol v2 detection, TcpTransport
    │   └── websocket.rs    # WebSocket listener, header IP extraction, WsTransport, Ping/Pong
    ├── protocol/
    │   ├── mod.rs
    │   ├── packet.rs       # Packet struct, ao_encode/ao_decode, wire format
    │   └── handlers.rs     # All AO2 packet handlers (~900+ lines)
    ├── game/
    │   ├── mod.rs
    │   ├── areas.rs        # Area struct, EvidenceMode, Status, LockState
    │   └── characters.rs   # load_lines(), build_sm_packet()
    └── commands/
        ├── mod.rs
        └── registry.rs     # All /command implementations, dispatch_command()
```

---

## Architecture Overview

### Two network listeners, one server core

```
[TCP :27017]   [WebSocket :27018]
      \               /
       \             /
    AoTransport (network/mod.rs)
          |
    handle_connection()
          |
    per-client async task
          |
    dispatch to handlers.rs
          |
    reads/writes ServerState (Arc<RwLock<_>>)
```

Both transports produce the same `Packet` type. After handshake, every connection runs the same `handle_connection` loop.

### ServerState (server.rs)

The single shared state, wrapped in `Arc` and distributed to every connection task:

```rust
pub struct ServerState {
    pub config: Config,                            // Immutable after startup
    pub reloadable: RwLock<ReloadableData>,        // chars/music/bgs (hot-reloadable)
    pub areas: Vec<Arc<RwLock<Area>>>,             // Per-area mutable state
    pub clients: Mutex<HashMap<u32, Arc<ClientHandle>>>, // Active connections
    pub uid_pool: Mutex<BinaryHeap<Reverse<u32>>>, // Recycled UIDs
    pub player_count: AtomicUsize,
    pub privacy: PrivacyLayer,                     // HMAC key + hashing
    pub db: Arc<EncryptedDb>,                      // Persistent storage
    pub accounts: AccountManager,
    pub bans: BanManager,
    pub watchlist: WatchlistManager,
    pub player_watch_tx: watch::Sender<usize>,     // Triggers master server re-advertise
    pub conn_limiters: Mutex<HashMap<IpAddr, TokenBucket>>, // Per-IP connection rate
}
```

### ClientHandle vs ClientSession

- **`ClientHandle`** (in `ServerState.clients`) — the small, shared-read view of a connection. Holds the `mpsc::UnboundedSender<String>` used to push outgoing messages to the connection's write task.
- **`ClientSession`** (local to connection task) — full mutable per-connection state: rate limiters, mute state, pairing, PM history, case prefs, narrator mode, etc.

When a handler needs to send a packet to *another* client, it looks up `clients.get(&uid).tx.send(...)`. For the *current* client it calls `transport.send(...)` directly.

---

## AO2 Packet Protocol

### Wire format

```
HEADER#field1#field2#...#%
```

- Fields are separated by `#`
- Packet ends with `%`
- Special characters are escaped: `%`→`<percent>`, `#`→`<num>`, `$`→`<dollar>`, `&`→`<and>`

### Packet struct (protocol/packet.rs)

```rust
pub struct Packet {
    pub header: String,
    pub body: Vec<String>,
}
```

`ao_encode` / `ao_decode` handle escaping. `Packet::parse(raw)` splits on `#` and strips the trailing `%` entry.

### Handlers (protocol/handlers.rs)

`dispatch(packet, session, state, transport)` pattern-matches on `packet.header` and calls the appropriate `handle_*` function. All handlers are `async` and take `&mut ClientSession`, `&Arc<ServerState>`, and `&mut AoTransport`.

**All packets handled:**

| Header | Handler | Purpose |
|--------|---------|---------|
| `HI` | `handle_hi` | HDID registration, ban check, watchlist alert |
| `ID` | `handle_id` | Client identification, send PN/FL/ASS |
| `askchaa` | `handle_askchaa` | Send SI (character/evidence/music counts) |
| `RC` | `handle_rc` | Send SC (character list) |
| `RM` | `handle_rm` | Send SM (areas + music list) |
| `RD` | `handle_rd` | Send backgrounds list |
| `CH` | `handle_ch` | Character select (pre-join) |
| `CC` | `handle_cc` | Join area with character; sends CharsCheck, HP, BN, LE, DONE, ARUP |
| `MS` | `handle_ms` | IC message; pairing, shadowmute, rate limit, narrator mode |
| `MC` | `handle_mc` | Music change; rate limit, lock check |
| `HP` | `handle_hp` | Defense/prosecution HP update |
| `RT` | `handle_rt` | Rebuttal / objection |
| `CT` | `handle_ct` | OOC message or `/command` dispatch |
| `PE` | `handle_pe` | Present evidence |
| `DE` | `handle_de` | Delete evidence |
| `EE` | `handle_ee` | Edit evidence |
| `ZZ` | `handle_zz` | Mod call with cooldown |
| `SETCASE` | `handle_setcase` | Set case alert preferences |
| `CASEA` | `handle_casea` | Case announcement broadcast |

---

## Command System (commands/registry.rs)

`dispatch_command(cmd, args, session, state, transport)` is called from `handle_ct` when the OOC message starts with `/`.

### All commands

**Player commands (no auth required):**

| Command | Behavior |
|---------|----------|
| `/help` | Lists commands available to the caller's permission level |
| `/about` | Version string |
| `/who` | List all connected players |
| `/move <area>` | Change area by name or number; releases char in old area |
| `/charselect` | Return to character select; stay in area as spectator |
| `/doc [text]` | View or set area document/notes |
| `/areainfo` | Show area status, lock, CMs, player count |
| `/narrator` | Toggle narrator mode (speak without a character sprite) |
| `/motd` | Show MOTD |
| `/clear` | Clear chat log (sends internal `__CLEAR__` message) |
| `/cm [uid]` | Add self or another player as CM (if area.allow_cms or caller has MODIFY_AREA) |
| `/uncm [uid]` | Remove CM status |
| `/bg <bg>` | Change background (if not locked; requires MODIFY_AREA if locked) |
| `/status <s>` | Set area status (`idle`, `rp`, `casing`, `looking-for-players`, `recess`, `gaming`) |
| `/lock [-s]` | Lock area; `-s` = spectatable mode (requires BYPASS_LOCK or CM) |
| `/unlock` | Unlock area |
| `/play <song>` | Change music (if area.lock_music = false, or has MODIFY_AREA) |
| `/login <u> <p>` | Authenticate; runs Argon2id verify in `spawn_blocking` |
| `/logout` | Deauthenticate |
| `/pair <uid>` | Request pairing with another player |
| `/unpair` | Cancel pairing |
| `/pm <uid> <msg>` | Send private message; updates `last_pm_uid` on both sides |
| `/r <msg>` | Reply to last PM sender |

**Moderator commands (require specific permission bits):**

| Command | Permission | Behavior |
|---------|-----------|---------|
| `/kick <uid> [reason]` | `KICK` | Disconnect player; logs reason |
| `/mute <uid> [ic\|ooc\|all]` | `MUTE` | Set mute state (default: IcOoc) |
| `/unmute <uid>` | `MUTE` | Clear mute state |
| `/shadowmute <uid>` | `MUTE` | Set `Shadowmute` state — victim unaware |
| `/warn <uid> <reason>` | `KICK` | Increment warn_count, notify victim |
| `/ban <uid\|hdid> [dur] <reason>` | `BAN` | Ban by UID or raw HDID; duration: `1h`, `7d`, `30d`, omit=permanent |
| `/unban <ban_id>` | `BAN` | Nullify ban (sets expires_at to 0) |
| `/baninfo <hdid>` | `BAN_INFO` | Fetch active ban for HDID |
| `/announce <msg>` | `MOD_CHAT` | Server-wide CT broadcast |
| `/modchat <msg>` | `MOD_CHAT` | CT message to authenticated mods only |
| `/watchlist add <hdid> [note]` | `WATCHLIST` | Add HDID to watchlist |
| `/watchlist remove <hdid>` | `WATCHLIST` | Remove HDID from watchlist |
| `/watchlist list` | `WATCHLIST` | List all watchlist entries |
| `/reload` | `ADMIN` | Hot-reload characters/music/backgrounds into `ReloadableData` |
| `/logoutall` | `ADMIN` | Send `__LOGOUT__` to all authenticated sessions |

---

## Permission System (auth/accounts.rs)

Permissions are a `u64` bitmask stored on each `Account`.

```rust
pub const PERM_CM:           u64 = 1;
pub const PERM_KICK:         u64 = 2;
pub const PERM_BAN:          u64 = 4;
pub const PERM_BYPASS_LOCK:  u64 = 8;
pub const PERM_MOD_EVI:      u64 = 16;
pub const PERM_MODIFY_AREA:  u64 = 32;
pub const PERM_MOVE_USERS:   u64 = 64;
pub const PERM_MOD_SPEAK:    u64 = 128;
pub const PERM_BAN_INFO:     u64 = 256;
pub const PERM_MOD_CHAT:     u64 = 512;
pub const PERM_MUTE:         u64 = 1024;
pub const PERM_LOG:          u64 = 2048;
pub const PERM_WATCHLIST:    u64 = 4096;
pub const PERM_ADMIN:        u64 = u64::MAX;
```

**Role mappings** (used by `mkusr`/`setrole`):
- `admin` → `PERM_ADMIN`
- `mod` / `moderator` → everything except CM
- `trial` → `KICK | MOD_CHAT | MUTE`
- `cm` → `CM | BYPASS_LOCK | MOD_EVI`
- `none` → `0`

Check: `session.permissions & PERM_KICK != 0`

---

## Config System (config.rs)

Loaded from `config.toml` at startup via `Config::load(path)`. The config is immutable after startup except for `reloadable` data.

### Structs

```rust
Config {
    server: ServerConfig,
    network: NetworkConfig,
    privacy: PrivacyConfig,
    logging: LoggingConfig,
    master_server: MasterServerConfig,   // #[serde(default)]
    rate_limits: RateLimitsConfig,       // #[serde(default)]
}
```

**ServerConfig** key fields:
- `name`, `description`, `motd`, `max_players`, `max_message_len`, `asset_url`, `multiclient_limit`
- `max_packet_bytes` (default: 8192) — hard drop before parsing

**NetworkConfig** key fields:
- `tcp_port` (27017), `ws_port` (27018), `bind_addr`
- `reverse_proxy_mode` — when true, trust X-Forwarded-For / X-Real-IP; also enables PP2 on TCP
- `reverse_proxy_http_port` (80), `reverse_proxy_https_port` (443)
- `ws_ping_interval_secs` (30), `ws_ping_timeout_secs` (90)

**RateLimitsConfig** — all have defaults, entire section is optional:
- IC: `ic_rate=3.0`, `ic_burst=5`
- Music: `mc_rate=1.0`, `mc_burst=3`
- OOC: `ct_rate=2.0`, `ct_burst=5`
- Evidence: `evidence_rate=5.0`, `evidence_burst=10`
- Mod call: `zz_cooldown_secs=60`
- Connections: `conn_rate=1.0`, `conn_burst=5`

---

## Area System (game/areas.rs)

Areas are defined in `data/areas.toml` as `[[area]]` entries and loaded at startup into `ServerState.areas: Vec<Arc<RwLock<Area>>>`.

### Area struct key fields

```rust
pub struct Area {
    // Config (immutable after load)
    pub name: String,
    pub default_bg: String,
    pub evi_mode: EvidenceMode,   // Any | CMs | Mods
    pub allow_iniswap: bool,
    pub allow_cms: bool,
    pub force_nointerrupt: bool,
    pub force_bglist: bool,
    pub lock_bg: bool,
    pub lock_music: bool,
    pub max_players: Option<usize>,
    pub owner: Option<String>,    // Account username; auto-CM on join

    // Runtime state
    pub taken: Vec<bool>,         // Character slot occupancy
    pub players: usize,
    pub def_hp: i32,
    pub pro_hp: i32,
    pub evidence: Vec<String>,    // Serialized evidence entries
    pub cms: Vec<u32>,            // UIDs of current case managers
    pub lock: LockState,          // Free | Spectatable | Locked
    pub status: Status,           // Idle | LookingForPlayers | Casing | Recess | Rp | Gaming
    pub invited: Vec<u32>,        // UIDs allowed into locked area
    pub doc: String,
    pub bg: String,               // Current background (may differ from default_bg)
    pub last_speaker: Option<usize>,
    pub log_buffer: VecDeque<String>,
}
```

### ARUP packets

`ServerState::broadcast_arup()` sends four `ARUP` packets to all clients after any area state change:
- `ARUP#0#...` — player counts
- `ARUP#1#...` — statuses
- `ARUP#2#...` — CM names
- `ARUP#3#...` — lock states

---

## Privacy Layer (privacy/hashing.rs)

```rust
pub struct PrivacyLayer {
    secret: [u8; 32],
}
```

**IPID** (daily-rotating):
```
daily_salt = HMAC-SHA256(secret, "YYYY-MM-DD")
ipid = hex(first_16_bytes(HMAC-SHA256(daily_salt, raw_ip.to_string())))
```

**HDID** (permanent):
```
hdid = hex(first_16_bytes(HMAC-SHA256(secret, "hdid:" + raw_hdid)))
```

The `server_secret` is either loaded from `config.toml` or auto-generated on first startup and stored in the `CONFIG` database table. **Never change it after launch** — all existing HDID hashes and bans become invalid.

---

## Storage Layer (storage/db.rs)

### EncryptedDb

Wraps [redb](https://github.com/cberner/redb) (embedded MVCC key-value). Encryption: AES-256-GCM with key from `NYAHAO_DB_KEY` env var (64-char hex = 32 bytes). Default insecure key is used if unset with a loud warning.

**Encryption format:** `[12-byte random nonce][ciphertext]` — nonce is prepended to every stored value.

**Tables:**

| Constant | Key type | Encrypted | Purpose |
|----------|----------|-----------|---------|
| `CONFIG_TABLE` | `&str` | No | Server metadata (server_secret) |
| `BANS_TABLE` | `u64` | Yes | Ban records |
| `BANS_BY_HDID_TABLE` | `&str` | No | HDID → `Vec<u64>` ban ID index |
| `ACCOUNTS_TABLE` | `&str` | Yes | Moderator accounts |
| `WATCHLIST_TABLE` | `&str` | Yes | Watch entries keyed by hashed HDID |

**Important:** When iterating `redb` tables you must import `use redb::ReadableTable` for `.iter()` to be in scope.

---

## Network Layer

### TCP (network/tcp.rs)

- Reads until `%` delimiter (AO2 packet framing)
- When `reverse_proxy_mode = true`: tries to read PROXY Protocol v2 header from first bytes
  - PP2 magic: `\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A`
  - Extracts real IPv4/IPv6 source address
- Hard packet size cap enforced per `max_packet_bytes`

### WebSocket (network/websocket.rs)

- HTTP upgrade via `tokio_tungstenite::accept_hdr_async`
- When `reverse_proxy_mode = true`: reads `X-Forwarded-For` (first address) or `X-Real-IP` from request headers
- Ping/Pong keepalive: spawns a separate interval task that calls `transport.send_ping()` at `ws_ping_interval_secs`; stale detection via `last_pong` timestamp
- `Message::Text` uses `Utf8Bytes` (tungstenite 0.26 breaking change — use `.into()`)
- `Message::Ping` uses `Bytes` (tungstenite 0.26 — use `vec![].into()`)

### AoTransport enum (network/mod.rs)

```rust
pub enum AoTransport {
    Tcp(TcpTransport),
    Ws(WsTransport),
}
```

Provides `send(&str)` and `recv_packet()` over both transports. The `handle_connection()` function accepts `AoTransport` and a real `IpAddr` (already extracted from proxy headers or raw socket).

---

## Moderation System

### Bans (moderation/bans.rs)

```rust
pub struct BanRecord {
    pub id: u64,
    pub hdid: String,           // Hashed HDID
    pub timestamp: i64,
    pub expires_at: Option<i64>, // None = permanent
    pub reason: String,
    pub moderator: String,
}
```

- `add(hdid, expires_at, reason, moderator)` → `u64` ban ID
- `is_banned(hdid)` → `Option<BanRecord>` (checks expiry)
- `nullify(id)` → sets `expires_at = Some(0)` (soft-delete)

### Watchlist (moderation/watchlist.rs)

```rust
pub struct WatchEntry {
    pub hdid: String,
    pub added_by: String,
    pub timestamp: i64,
    pub note: String,
}
```

- `add(hdid, added_by, note)`
- `remove(hdid)` → `bool`
- `get(hdid)` → `Option<WatchEntry>`
- `list()` → `Vec<WatchEntry>`

**Trigger:** In `handle_hi`, after the ban check, if the HDID is in the watchlist, a mod-only CT alert is broadcast to all authenticated sessions.

### Mute states (client.rs)

```rust
pub enum MuteState {
    None,
    Ic,         // Block IC only
    Ooc,        // Block OOC only
    IcOoc,      // Block both
    Music,      // Block music changes
    Judge,      // Block judge HP/rebuttal packets
    Parrot,     // Repeat last message (future)
    Shadowmute, // Messages appear to send but nobody else sees them
}
```

`mute_until: Option<Instant>` — `None` = permanent, `Some(t)` = expires at `t`.

---

## Rate Limiting (ratelimit.rs)

```rust
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate: f64,          // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    pub fn try_consume(&mut self) -> bool  // true = allowed, false = rate limited
}
```

Per-client buckets in `ClientSession`: `rl_ic`, `rl_mc`, `rl_ct`, `rl_evi`.
Per-IP buckets in `ServerState.conn_limiters` (pruned when full).
Exceeded packets are **silently dropped**.

---

## Auth / Account System (auth/accounts.rs)

```rust
pub struct Account {
    pub username: String,
    pub password_hash: String,  // Argon2id PHC string
    pub permissions: u64,
}
```

`AccountManager` provides:
- `create(username, password, permissions)` — hashes with Argon2id, stores in DB
- `authenticate(username, password)` → `Option<permissions>` — verifies hash
- `get(username)`, `delete(username)`, `set_permissions(username, perms)`

**Always run Argon2id operations in `tokio::task::spawn_blocking`** — they are CPU-intensive and will block the async runtime if called directly.

---

## Master Server (ms.rs)

When `config.master_server.advertise = true`:
- Posts JSON to `config.master_server.addr` immediately on startup
- Repeats every 5 minutes
- Immediately re-posts when player count changes (via `player_watch_tx` watch channel)

Payload includes `name`, `description`, `players`, `port` (TCP), and either `ws_port` or `wss_port` depending on `reverse_proxy_mode`.

---

## Admin CLI (main.rs)

Reads from stdin while server is running. Commands:

| Input | Action |
|-------|--------|
| `players` | List UIDs, characters, areas |
| `say <msg>` | Broadcast CT announcement |
| `mkusr <u> <p> <role>` | Create account |
| `rmusr <u>` | Delete account |
| `setrole <u> <role>` | Change account role |
| `shutdown` | Graceful shutdown (sends broadcast shutdown signal) |
| `help` | List commands |

---

## Key Implementation Patterns

### Sending to another client

```rust
// Get the target's sender from shared state
let clients = state.clients.lock().unwrap();
if let Some(handle) = clients.get(&target_uid) {
    let _ = handle.tx.send(packet_string);
}
```

### Sending to all clients in an area

```rust
let clients = state.clients.lock().unwrap();
for handle in clients.values() {
    if handle.area_idx == area_idx {
        let _ = handle.tx.send(packet_string.clone());
    }
}
```

### Sending to all authenticated mods

```rust
let clients = state.clients.lock().unwrap();
for handle in clients.values() {
    if handle.authenticated {
        let _ = handle.tx.send(msg.clone());
    }
}
```

### Hot reload

```rust
let mut r = state.reloadable.write().unwrap();
r.characters = load_lines("data/characters.txt")?;
r.music = load_lines("data/music.txt")?;
r.backgrounds = load_lines("data/backgrounds.txt")?;
```

### ARUP after area mutation

After any change to area player count, status, CMs, or lock state, always call:
```rust
state.broadcast_arup().await;
```

---

## Dependencies Worth Knowing

| Crate | Version | Notes |
|-------|---------|-------|
| `tokio` | 1 | Full features (rt-multi-thread, sync, time, net, io) |
| `tokio-tungstenite` | **0.26** | Breaking change from 0.24: `Message::Text` takes `Utf8Bytes`, `Message::Ping` takes `Bytes` — use `.into()` |
| `tungstenite` | **0.26** | Same version constraint |
| `redb` | **2** | Breaking change from 1.x: `ReadableTable` trait must be imported for `.iter()` |
| `argon2` | 0.5 | PHC string format; always use `spawn_blocking` |
| `aes-gcm` | 0.10 | `Aes256Gcm`; nonce is 12 bytes |
| `ppp` | 2.3 | PROXY Protocol v2 parsing |
| `reqwest` | 0.12 | `rustls-tls` feature; used only in `ms.rs` |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NYAHAO_DB_KEY` | **Yes (production)** | 64-char hex (32 bytes) AES-256-GCM database key. Insecure default used if unset (warns loudly). |
| `RUST_LOG` | No | Override tracing log level (overrides `config.toml` `log_level`) |

---

## Data File Formats

### data/areas.toml
```toml
[[area]]
name = "Lobby"
background = "gs4"
evidence_mode = "mods"   # "any" | "cms" | "mods"
allow_iniswap = false
allow_cms = false
force_nointerrupt = true
force_bglist = true
lock_bg = true
lock_music = false
# max_players = 30       # Optional
# owner = "username"     # Optional; auto-CM on join
```

### data/characters.txt
One character folder name per line. Must match the client's `characters/` directory.

### data/music.txt
Lines without a `.` (no file extension) are category headers displayed as separators. All other lines are playable tracks.

### data/backgrounds.txt
One background folder name per line.

---

## Common Gotchas

1. **tungstenite 0.26 API:** `Message::Text(s.into())` and `Message::Ping(vec![].into())` — the old `String` and `Vec<u8>` direct constructors no longer compile.

2. **redb 2.x iteration:** Must `use redb::ReadableTable;` to call `.iter()` on `ReadOnlyTable`.

3. **Argon2id blocking:** Never call `authenticate()` or `create()` directly in an async context. Always wrap in `tokio::task::spawn_blocking`.

4. **ARUP after every area change:** Forgetting `broadcast_arup()` leaves clients with stale lobby data.

5. **`server_secret` stability:** Any test that creates a `PrivacyLayer` and checks HDID/IPID output will break if the server_secret changes. The secret is stable within a DB; changing it invalidates all bans.

6. **`ClientHandle` vs `ClientSession`:** `ClientHandle` is the shared/cheap view in `ServerState.clients`. `ClientSession` is the full local state. Don't confuse them when adding new per-session fields — both may need updating.

7. **Shadowmute flow:** In `handle_ms`, if `session.mute_state == MuteState::Shadowmute`, the packet is ACKed to the sender but not broadcast to others. The sender believes it went through.

8. **`conn_limiters` pruning:** The map prunes IPs whose bucket is full (not rate-limited) to prevent unbounded growth. This is intentional — don't "fix" it.

9. **UID pool:** UIDs are `u32` values managed as a min-heap. They are allocated on join and returned on disconnect for reuse. `u32::MAX` is used as a sentinel for "no UID" in some contexts.

10. **`max_players` per area vs global:** `config.server.max_players` is the global cap. `area.max_players` is optional per-area. Both are checked independently in `handle_cc`.
