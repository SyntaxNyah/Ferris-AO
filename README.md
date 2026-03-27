# Ferris-AO

A privacy-first [Attorney Online 2](https://attorneyonline.de/) server written in Rust.

Built with async-first design using Tokio, Ferris-AO implements the full AO2 protocol over both TCP and WebSocket transports, with a strong emphasis on user privacy — raw IP addresses and hardware IDs are never stored.

---

## Table of Contents

- [What is Ferris-AO](#what-is-ferris-ao)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Data Files](#data-files)
- [Running the Server](#running-the-server)
- [nginx Setup](#nginx-setup)
- [Connecting](#connecting)
- [Command Reference](#command-reference)
- [Permission System](#permission-system)
- [Privacy Model](#privacy-model)
- [Protocol Support](#protocol-support)
- [Project Structure](#project-structure)
- [Contributing](#contributing)

---

## What is Ferris-AO

Attorney Online is a courtroom roleplay game where players take on the roles of lawyers, witnesses, and judges to act out cases. Players communicate through in-character speech bubbles, evidence presentation, music, and animations tied to a roster of characters.

Ferris-AO is a server backend for the AO2 protocol. It manages areas (rooms), character slots, evidence, music, moderation, and accounts. It was written from scratch in Rust as a clean, modern alternative to existing C++ and Python-based servers.

**Design philosophy:**
- Raw IP addresses are hashed immediately on receipt and discarded — they are never logged or stored
- Hardware IDs undergo a permanent keyed hash — bans persist across reconnects without storing the original identifier
- All sensitive database records are encrypted at rest with AES-256-GCM
- Passwords are hashed with Argon2id

---

## Features

- **Dual transport** — Accepts both legacy TCP (AO2 protocol) and WebSocket connections simultaneously
- **Full AO2 protocol** — Supports all standard packets including IC messages, music changes, evidence, health points, rebuttals, case alerts, and pairing
- **Privacy-by-design** — IPs hashed to daily-rotating IPIDs; HDIDs permanently hashed; nothing sensitive is ever logged
- **Encrypted database** — All ban and account records are stored with AES-256-GCM encryption via an embedded [redb](https://github.com/cberner/redb) database
- **Argon2id passwords** — Moderator accounts use state-of-the-art password hashing
- **Role-based permissions** — Fine-grained permission bitmask (admin, mod, trial, CM roles)
- **Area system** — Multiple configurable areas with per-area evidence modes, backgrounds, locks, CMs, and HP tracking
- **Moderation suite** — Kick, ban (temporary or permanent), mute (IC/OOC/music/judge variants), warn, announce
- **PROXY Protocol v2** — Recovers real client IPs when running behind nginx (required for accurate IPIDs behind a proxy)
- **Cloudflare-ready** — WebSocket proxy handles `CF-Connecting-IP` and `X-Real-IP` headers (trusted only from loopback)
- **Aggressive release optimization** — LTO + single codegen unit for minimal binary size and maximum throughput

---

## Architecture

```
                    ┌──────────────┐
                    │  Cloudflare  │  DDoS protection, TLS termination
                    └──────┬───────┘
                           │ HTTPS / TCP (Spectrum)
                    ┌──────▼───────┐
                    │    nginx     │  Reverse proxy, rate limiting, PROXY Protocol
                    └──────┬───────┘
               ┌───────────┴───────────┐
               │                       │
        ┌──────▼──────┐         ┌──────▼──────┐
        │  TCP :27017  │         │  WS :27018  │
        └──────┬───────┘         └──────┬──────┘
               └───────────┬────────────┘
                    ┌───────▼────────┐
                    │   Ferris-AO    │
                    │  ServerState   │  Arc<RwLock<_>> shared state
                    ├────────────────┤
                    │ Areas          │  Per-area slots, evidence, lock, HP
                    │ Clients        │  HashMap<uid, ClientHandle>
                    │ Auth / Privacy │  HMAC hashing, Argon2id
                    │ Database       │  redb + AES-256-GCM
                    │ Moderation     │  Bans, kicks, mutes
                    └────────────────┘
```

**Module map:**

| Module | Responsibility |
|---|---|
| `main` | Startup, CLI, config loading |
| `server` | `ServerState`, `ClientHandle`, broadcast logic |
| `client` | Per-connection session state |
| `protocol` | Packet parsing, serialization, handler dispatch |
| `network` | TCP and WebSocket transports, `AoTransport` abstraction |
| `auth` | Account CRUD, Argon2id hashing |
| `privacy` | IPID and HDID hashing via HMAC-SHA256 |
| `moderation` | Ban records and `BanManager` |
| `storage` | Encrypted redb wrapper |
| `game` | Areas, character slots, SM packet builder |
| `commands` | All `/command` implementations |
| `config` | TOML config deserialization |

---

## Requirements

- **Rust** 1.75 or later (`cargo build --release`)
- **Linux** recommended for production (nginx stream module available)
- **nginx** (optional) — required for TLS termination, rate limiting, and PROXY Protocol v2
- **Cloudflare** (optional) — free tier covers WebSocket; TCP passthrough requires Cloudflare Spectrum (paid)

---

## Installation

```bash
git clone https://github.com/SyntaxNyah/Ferris-AO.git
cd Ferris-AO
cargo build --release
```

The compiled binary will be at `target/release/nyahao` (or `nyahao.exe` on Windows).

Copy and edit the example config:

```bash
cp config.toml config.toml.bak   # keep a backup
# edit config.toml with your settings
```

---

## Configuration

Ferris-AO is configured via `config.toml` in the working directory.

### `[server]`

| Key | Type | Default | Description |
|---|---|---|---|
| `name` | string | `"NyahAO Server"` | Server name shown in the master server list and lobby |
| `description` | string | `"A privacy-first AO2 server."` | Short description shown in the server browser |
| `motd` | string | `"Welcome to NyahAO!"` | Message of the day sent to clients on join |
| `max_players` | integer | `100` | Maximum number of simultaneous connected players |
| `max_message_len` | integer | `256` | Maximum character length of a single IC message |
| `asset_url` | string | `""` | URL to an asset bundle for clients to download (leave empty to disable) |
| `multiclient_limit` | integer | `8` | Maximum simultaneous connections sharing the same IPID |

### `[network]`

| Key | Type | Default | Description |
|---|---|---|---|
| `tcp_port` | integer | `27017` | Port for legacy TCP (AO2) connections |
| `ws_port` | integer | `27018` | Port for WebSocket connections |
| `bind_addr` | string | `"0.0.0.0"` | Address to bind both listeners to. Use `"127.0.0.1"` when running behind nginx |
| `reverse_proxy_mode` | boolean | `false` | When `true`, trust `X-Forwarded-For` and `X-Real-IP` headers for real client IPs, and detect PROXY Protocol v2 on TCP. **Must be `false` for direct (no proxy) deployments** — trusting these headers without a proxy is a security risk. |
| `reverse_proxy_http_port` | integer | `80` | External HTTP port advertised to the master server when `reverse_proxy_mode = true` |
| `reverse_proxy_https_port` | integer | `443` | External HTTPS/WSS port advertised to the master server when `reverse_proxy_mode = true` |

### `[privacy]`

| Key | Type | Default | Description |
|---|---|---|---|
| `server_secret` | string | *(generated)* | Optional: 64-character hex string (32 bytes) used as the HMAC key for hashing. If omitted, a random secret is generated at first startup and stored in the database. **Do not change this after launch** — all existing IPIDs and HDID hashes will be invalidated. |

### `[master_server]`

| Key | Type | Default | Description |
|---|---|---|---|
| `advertise` | boolean | `false` | When `true`, posts server info to the master server so players can discover it |
| `addr` | string | `"https://servers.aceattorneyonline.com/servers"` | Master server URL |
| `hostname` | string | *(unset)* | Optional hostname/IP to include in the advertisement. If unset, the master server infers it from the request |

When `reverse_proxy_mode = true`, the server advertises `wss_port` (the `reverse_proxy_https_port` value, e.g. `443`) so the master server lists it as a WSS endpoint. When `reverse_proxy_mode = false`, it advertises `ws_port` (plain WebSocket).

The server posts immediately on startup, every 5 minutes, and whenever the player count changes.

### `[logging]`

| Key | Type | Default | Description |
|---|---|---|---|
| `log_level` | string | `"info"` | Tracing log level: `trace`, `debug`, `info`, `warn`, `error` |
| `log_chat` | boolean | `false` | Whether to log IC message content. Disabled by default for privacy. |

**Example `config.toml` — direct (no proxy):**

```toml
[server]
name = "Ferris-AO"
description = "A Rust AO2 server."
motd = "Welcome! Type /help for commands."
max_players = 100
max_message_len = 256
asset_url = ""
multiclient_limit = 8

[network]
tcp_port = 27017
ws_port = 27018
bind_addr = "0.0.0.0"
reverse_proxy_mode = false

[privacy]
# server_secret = "your_64_char_hex_string_here"

[logging]
log_level = "info"
log_chat = false

[master_server]
advertise = true
addr = "https://servers.aceattorneyonline.com/servers"
# hostname = "your.domain.example"
```

**Example `config.toml` — behind nginx + Cloudflare:**

```toml
[network]
tcp_port = 27017
ws_port = 27018
bind_addr = "127.0.0.1"        # Only accept connections from nginx
reverse_proxy_mode = true
reverse_proxy_http_port = 80
reverse_proxy_https_port = 443 # Advertised as wss_port to the master server

[master_server]
advertise = true
hostname = "your.domain.example"
```

---

## Database Setup

Ferris-AO uses [redb](https://github.com/cberner/redb), an embedded key-value database stored at `data/nyahao.db`. All sensitive records (bans, accounts) are encrypted with **AES-256-GCM** before being written to disk.

### Encryption Key

The database encryption key is read from the environment variable `NYAHAO_DB_KEY`:

```bash
export NYAHAO_DB_KEY="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
```

- Must be a **64-character lowercase hex string** (32 bytes)
- If unset, a default insecure key is used — **do not use the default in production**
- The key is never written to the database or logs

**Generating a secure key:**

```bash
openssl rand -hex 32
```

### Database Tables

| Table | Encrypted | Description |
|---|---|---|
| `CONFIG` | No | Server metadata (stores the generated server secret) |
| `BANS` | Yes | Ban records keyed by ban ID |
| `BANS_BY_HDID` | No | HDID → ban ID index for fast ban lookups |
| `ACCOUNTS` | Yes | Moderator accounts keyed by username |

The database files (`nyahao.db`, `nyahao.db-shm`, `nyahao.db-wal`) are excluded from git via `.gitignore`.

---

## Data Files

All data files live in the `data/` directory.

### `data/characters.txt`

One character folder name per line. These must match the folder names in the AO2 client's `characters/` directory.

```
Phoenix_Wright
Miles_Edgeworth
Maya_Fey
```

### `data/backgrounds.txt`

One background name per line. These must match the folder names in the AO2 client's `background/` directory.

```
gs4
aj
default
```

### `data/music.txt`

Music entries, one per line. Lines that do not contain a `.` (file extension) are treated as **category headers** and are displayed as separators in the client's music list.

```
Turnabout Sisters
trial.opus
cross.opus

Logic and Trick
logic.opus
```

### `data/areas.toml`

TOML array of area definitions. Each entry creates one area on the server.

```toml
[[areas]]
name = "Lobby"
background = "gs4"
evidence_mode = "mods"   # "any" | "cms" | "mods"
allow_iniswap = false
allow_cms = false
force_nointerrupt = false
force_bglist = false
lock_bg = false
lock_music = false

[[areas]]
name = "Courtroom"
background = "aj"
evidence_mode = "cms"
allow_iniswap = true
allow_cms = true
force_nointerrupt = false
force_bglist = false
lock_bg = false
lock_music = false
```

**Area options:**

| Key | Type | Description |
|---|---|---|
| `name` | string | Display name of the area |
| `background` | string | Default background on area reset |
| `evidence_mode` | string | Who can add/edit evidence: `any`, `cms`, `mods` |
| `allow_iniswap` | bool | Allow players to use iniswapped characters |
| `allow_cms` | bool | Allow players to become case managers (`/cm`) |
| `force_nointerrupt` | bool | Force all messages to be non-interrupting |
| `force_bglist` | bool | Restrict backgrounds to the server's `backgrounds.txt` list |
| `lock_bg` | bool | Prevent background changes entirely |
| `lock_music` | bool | Prevent music changes via packet (still changeable by mods) |

---

## Running the Server

**Basic:**
```bash
NYAHAO_DB_KEY="your_hex_key" ./target/release/nyahao
```

**With custom log level:**
```bash
RUST_LOG=debug NYAHAO_DB_KEY="your_hex_key" ./target/release/nyahao
```

**As a systemd service (`/etc/systemd/system/ferris-ao.service`):**
```ini
[Unit]
Description=Ferris-AO Attorney Online Server
After=network.target

[Service]
Type=simple
User=ao
WorkingDirectory=/opt/ferris-ao
ExecStart=/opt/ferris-ao/nyahao
Environment=NYAHAO_DB_KEY=your_hex_key_here
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Admin CLI

While the server is running, the process reads commands from stdin:

| Command | Description |
|---|---|
| `players` | List all connected players with UID, character, and area |
| `say <message>` | Send a server-wide OOC announcement |
| `mkusr <username> <password> <role>` | Create a moderator account (`admin`, `mod`, `trial`, `cm`) |
| `rmusr <username>` | Delete a moderator account |
| `shutdown` | Gracefully shut down the server |
| `help` | List available CLI commands |

---

## nginx Setup

It is strongly recommended to run Ferris-AO behind nginx for TLS termination, rate limiting, and DDoS protection via Cloudflare. Set `reverse_proxy_mode = true` in `config.toml` whenever nginx is in front.

A complete example config with all options is provided at `nginx/nyahao.conf`.

### With Cloudflare (recommended)

Cloudflare handles TLS — nginx sits on port 80 and passes plain HTTP to Ferris-AO. The real client IP arrives in the `X-Forwarded-For` header set by Cloudflare automatically.

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name your.domain.example;

    location / {
        proxy_pass         http://127.0.0.1:27018;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade         $http_upgrade;
        proxy_set_header   Connection      "upgrade";
        proxy_set_header   Host            $host;
        proxy_set_header   X-Forwarded-For $http_x_forwarded_for;
        proxy_set_header   X-Real-IP       $http_x_forwarded_for;
        proxy_read_timeout 7200s;
        proxy_send_timeout 30s;
        proxy_buffering    off;
    }
}
```

Ferris-AO reads `X-Forwarded-For` first (taking the first address in the list), then falls back to `X-Real-IP`. The raw peer address is never used when `reverse_proxy_mode = true`.

### Without Cloudflare (direct nginx TLS)

If you are managing TLS yourself with a Let's Encrypt certificate:

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name your.domain.example;

    ssl_certificate     /etc/letsencrypt/live/your.domain.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain.example/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass         http://127.0.0.1:27018;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade         $http_upgrade;
        proxy_set_header   Connection      "upgrade";
        proxy_set_header   Host            $host;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Real-IP       $remote_addr;
        proxy_read_timeout 7200s;
        proxy_send_timeout 30s;
        proxy_buffering    off;
    }
}
```

### TCP (Optional — requires Cloudflare Spectrum)

For legacy TCP clients behind nginx, the `stream` module must be compiled in (`--with-stream`). With Cloudflare, TCP passthrough requires Cloudflare Spectrum (paid plan).

```nginx
stream {
    server {
        listen     27016;
        proxy_pass 127.0.0.1:27017;
        proxy_protocol        on;   # Prepends PROXY Protocol v2 header
        proxy_connect_timeout 10s;
        proxy_timeout         7200s;
    }
}
```

With `proxy_protocol on`, nginx prepends a PP2 header so Ferris-AO can recover the real client IP. This only activates when `reverse_proxy_mode = true` — without it the server uses the peer address directly.

---

## Connecting

| Transport | Default Port | Notes |
|---|---|---|
| TCP | `27017` | Used by AO2 desktop clients (e.g. Attorney Online 2) |
| WebSocket | `27018` | Used by web clients; expose via nginx + TLS on port 443 |

In the AO2 client, add the server as:
- **IP:** your server's IP or domain
- **Port:** 27017 (TCP) or 443 (WebSocket via nginx)

---

## Command Reference

Commands are entered in the OOC chat box prefixed with `/`.

### Player Commands

| Command | Description |
|---|---|
| `/help` | List all commands available to you |
| `/about` | Show server version and info |
| `/who` | List all connected players (UID, character, area) |
| `/move <area>` | Move to a different area by name or number |
| `/charselect` | Return to the character select screen |
| `/doc [text]` | View or set the area's case document/notes |
| `/areainfo` | Show current area details (status, lock, CMs, player count) |
| `/narrator` | Toggle narrator mode (speak without a character sprite) |
| `/motd` | Display the server's message of the day |
| `/clear` | Clear your client's chat log |
| `/cm [uid]` | Become case manager, or designate another player (if area allows) |
| `/uncm [uid]` | Step down as case manager, or remove another player's CM status |
| `/bg <background>` | Change the area background (if not locked) |
| `/status <status>` | Set the area status: `idle`, `rp`, `casing`, `looking-for-players`, `recess`, `gaming` |
| `/lock [-s]` | Lock the area to new players. `-s` makes it spectatable (can watch, not speak) |
| `/unlock` | Unlock the area, allowing anyone to join |
| `/play <song>` | Change the area music (if not locked) |
| `/login <user> <pass>` | Authenticate as a moderator account |
| `/logout` | Log out of your moderator account |

### Moderator Commands

These commands require specific permissions (see [Permission System](#permission-system)).

| Command | Permission | Description |
|---|---|---|
| `/kick <uid> [reason]` | `KICK` | Disconnect a player. Logs reason. |
| `/ban <uid\|hdid> [duration] <reason>` | `BAN` | Ban a player by UID or hashed HDID. Duration format: `1h`, `7d`, `30d`; omit for permanent. |
| `/unban <ban_id>` | `BAN` | Nullify an active ban by its ID. |
| `/baninfo <hdid>` | `BAN_INFO` | Check the ban status for a given hashed HDID. |
| `/mute <uid> [type]` | `MUTE` | Silence a player. Types: `ic`, `ooc`, `all` (default: `all`). |
| `/unmute <uid>` | `MUTE` | Remove a mute from a player. |
| `/warn <uid> <reason>` | `KICK` | Increment a player's warning count and notify them. |
| `/announce <message>` | `MOD_CHAT` | Send a server-wide OOC announcement to all players. |
| `/modchat <message>` | `MOD_CHAT` | Send a message only visible to authenticated moderators. |

---

## Permission System

Permissions are stored as a 64-bit bitmask on each account. Multiple permissions can be combined.

| Permission | Bit | Description |
|---|---|---|
| `CM` | `1` | Can be a case manager in areas that allow CMs |
| `KICK` | `2` | Can kick and warn players |
| `BAN` | `4` | Can ban and unban players |
| `BYPASS_LOCK` | `8` | Can enter locked areas |
| `MOD_EVI` | `16` | Can modify evidence regardless of area evidence mode |
| `MODIFY_AREA` | `32` | Can modify area settings (background, etc.) |
| `MOVE_USERS` | `64` | Can move other players between areas |
| `MOD_SPEAK` | `128` | Can speak in locked or muted states |
| `BAN_INFO` | `256` | Can look up ban records by HDID |
| `MOD_CHAT` | `512` | Can use modchat and send announcements |
| `MUTE` | `1024` | Can mute/unmute players |
| `LOG` | `2048` | Can access server logs |
| `ADMIN` | `ALL` | All permissions |

### Roles

When creating accounts via `mkusr`, specify one of these role names:

| Role | Permissions Granted |
|---|---|
| `admin` | All permissions (`ADMIN`) |
| `mod` / `moderator` | `KICK`, `BAN`, `BYPASS_LOCK`, `MOD_EVI`, `MODIFY_AREA`, `MOVE_USERS`, `MOD_SPEAK`, `BAN_INFO`, `MOD_CHAT`, `MUTE`, `LOG` |
| `trial` | `KICK`, `MOD_CHAT`, `MUTE` |
| `cm` | `CM`, `BYPASS_LOCK`, `MOD_EVI` |

---

## Privacy Model

Ferris-AO is designed so that neither the server operator nor an attacker who obtains the database can recover a player's real IP address or hardware ID.

### IPID (IP Identifier)

The IPID is a pseudonymous identifier derived from a player's IP address. It is used for multiclient limiting and moderation without retaining the real IP.

**How it works:**
1. A `daily_salt` is derived: `HMAC-SHA256(server_secret, current_date_YYYY-MM-DD)`
2. The IPID is computed: `hex(first_16_bytes(HMAC-SHA256(daily_salt, raw_ip)))`
3. The raw IP is discarded immediately

**Properties:**
- The same IP produces a different IPID each day — protecting long-term tracking
- The IPID is consistent within a single day — allowing ban/multiclient enforcement
- Without the server secret, IPIDs cannot be reversed to IPs

### HDID (Hardware ID)

HDIDs are sent by the AO2 client as a persistent hardware fingerprint. Ferris-AO hashes them permanently so bans survive IP changes and reconnects.

**How it works:**
1. `HMAC-SHA256(server_secret, "hdid:" || raw_hdid)`
2. The result is hex-encoded (first 16 bytes) and stored
3. The raw HDID is never stored or logged

**Properties:**
- The hash is stable across server restarts (uses the fixed server secret)
- Without the server secret, HDID hashes cannot be reversed
- Bans target the hashed HDID — they persist even if the player reconnects from a new IP

### Server Secret

- Generated as 32 cryptographically random bytes on first startup
- Stored in the unencrypted `CONFIG` database table (protected by the `NYAHAO_DB_KEY` env var at the OS level)
- Never logged or printed
- Changing the secret invalidates all existing IPIDs and HDID hashes — avoid doing this after launch

### What is never stored

- Raw IP addresses
- Raw Hardware IDs
- Plaintext passwords (Argon2id PHC format only)
- IC message content (unless `log_chat = true` in config)

---

## Protocol Support

Ferris-AO advertises the following AO2 feature flags to connecting clients:

| Flag | Description |
|---|---|
| `noencryption` | Disables legacy XOR encryption (modern clients only) |
| `yellowtext` | Enables yellow-colored text in IC messages |
| `prezoom` | Pre-zoom desk effects |
| `flipping` | Character sprite horizontal flipping |
| `customobjections` | Custom objection animations |
| `fastloading` | Optimized character/evidence list loading |
| `deskmod` | Desk visibility control per message |
| `evidence` | Evidence system support |
| `cccc_ic_support` | Pairing (Character-Character Concurrent Chat) |
| `arup` | Area update packets (real-time area status in lobby) |
| `casing_alerts` | Case announcement/subscription system |
| `modcall_reason` | Reason field in mod calls |
| `looping_sfx` | Looping sound effects |
| `additive` | Additive text (append to previous message) |
| `effects` | Visual effect overlays |
| `y_offset` | Vertical sprite offset |
| `expanded_desk_mods` | Additional desk modifier values |
| `auth_packet` | Server-side authentication packet support |

---

## Project Structure

```
Ferris-AO/
├── Cargo.toml              # Dependencies and release profile
├── config.toml             # Server configuration
├── data/
│   ├── areas.toml          # Area definitions
│   ├── characters.txt      # Character roster (one per line)
│   ├── backgrounds.txt     # Allowed backgrounds
│   └── music.txt           # Music list with category headers
├── nginx/
│   └── nyahao.conf         # Example nginx reverse proxy config
└── src/
    ├── main.rs             # Startup, CLI, initialization
    ├── server.rs           # ServerState, ClientHandle, broadcast
    ├── client.rs           # Per-connection session state
    ├── config.rs           # TOML config structs
    ├── auth/
    │   ├── mod.rs
    │   └── accounts.rs     # Account CRUD, Argon2id hashing, permissions
    ├── privacy/
    │   ├── mod.rs
    │   └── hashing.rs      # IPID (daily-rotating) and HDID hashing via HMAC-SHA256
    ├── moderation/
    │   ├── mod.rs
    │   └── bans.rs         # BanRecord, BanManager, soft-delete
    ├── storage/
    │   ├── mod.rs
    │   └── db.rs           # EncryptedDb: redb + AES-256-GCM wrapper
    ├── network/
    │   ├── mod.rs          # AoTransport enum, handle_connection entry point
    │   ├── tcp.rs          # TCP listener, PROXY Protocol v2 detection
    │   └── websocket.rs    # WebSocket listener, header-based IP recovery
    ├── protocol/
    │   ├── mod.rs
    │   ├── packet.rs       # Packet struct, AO2 wire encoding/decoding
    │   └── handlers.rs     # Full AO2 packet handler dispatch (~930 lines)
    ├── game/
    │   ├── mod.rs
    │   ├── areas.rs        # Area struct, character slots, evidence, lock/CM logic
    │   └── characters.rs   # Character list loader, SM packet builder
    └── commands/
        ├── mod.rs
        └── registry.rs     # All /command implementations (~785 lines)
```

---

## Contributing

Pull requests are welcome. For significant changes, open an issue first to discuss the approach.

Please ensure:
- No raw IPs, HDIDs, or passwords appear in logs or stored data
- New commands include appropriate permission checks
- Database writes use the encrypted helpers in `storage/db.rs`

---

*Ferris-AO is not affiliated with the official Attorney Online project.*
