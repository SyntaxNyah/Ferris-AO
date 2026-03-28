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
- **Moderation suite** — Kick, ban (temporary or permanent), mute (IC/OOC/music/judge/shadow variants), warn, announce, private messaging, watchlist
- **Watchlist** — Flag player HDIDs with notes; all authenticated mods are alerted when a watched player connects
- **Pairing system** — `cccc_ic_support` pairing: players can request to appear side-by-side in IC messages
- **Private messaging** — `/pm` and `/r` commands for direct player-to-player messages
- **WebSocket keepalive** — Configurable Ping/Pong intervals to detect and drop stale connections
- **PROXY Protocol v2** — Recovers real client IPs when running behind nginx (required for accurate IPIDs behind a proxy)
- **Cloudflare-ready** — WebSocket proxy handles `CF-Connecting-IP` and `X-Real-IP` headers (trusted only from loopback)
- **Word censor** — Optional `data/censor.txt` word list; IC messages containing a censored word are silently intercepted (shown to the sender as sent, not broadcast to others)
- **Packet size enforcement** — Configurable hard limit on incoming packet bytes; oversized packets are dropped before parsing
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
| `moderation` | Ban records (`BanManager`), watchlist (`WatchlistManager`) |
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
| `max_packet_bytes` | integer | `8192` | Hard limit on incoming packet size in bytes. Packets larger than this are dropped before parsing. |

### `[network]`

| Key | Type | Default | Description |
|---|---|---|---|
| `tcp_port` | integer | `27017` | Port for legacy TCP (AO2) connections |
| `ws_port` | integer | `27018` | Port for WebSocket connections |
| `bind_addr` | string | `"0.0.0.0"` | Address to bind both listeners to. Use `"127.0.0.1"` when running behind nginx |
| `reverse_proxy_mode` | boolean | `false` | When `true`, trust `X-Forwarded-For` and `X-Real-IP` headers for real client IPs, and detect PROXY Protocol v2 on TCP. **Must be `false` for direct (no proxy) deployments** — trusting these headers without a proxy is a security risk. |
| `reverse_proxy_http_port` | integer | `80` | External HTTP port advertised to the master server when `reverse_proxy_mode = true` |
| `reverse_proxy_https_port` | integer | `443` | External HTTPS/WSS port advertised to the master server when `reverse_proxy_mode = true` |
| `ws_ping_interval_secs` | integer | `30` | Seconds between WebSocket Ping frames for keepalive. Set to `0` to disable. |
| `ws_ping_timeout_secs` | integer | `90` | Seconds to wait for a Pong response before treating the connection as stale and closing it. Set to `0` to disable. |

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

When `reverse_proxy_mode = true`, the server advertises **both** `ws_port` (`reverse_proxy_http_port`, e.g. `80`) **and** `wss_port` (`reverse_proxy_https_port`, e.g. `443`) to the master server. nginx routes both external ports to the same single internal `ws_port` listener, so only one Ferris-AO WebSocket process is needed. When `reverse_proxy_mode = false`, only `ws_port` (plain WebSocket, no TLS) is advertised.

The server posts immediately on startup, every 5 minutes, and whenever the player count changes.

### `[censor]`

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `false` | When `true`, IC messages containing any word from `data/censor.txt` are silently intercepted — the sender sees their message as delivered but it is not broadcast to others. Has no effect if `data/censor.txt` is absent or contains no active words. |

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
max_packet_bytes = 8192

[network]
tcp_port = 27017
ws_port = 27018
bind_addr = "0.0.0.0"
reverse_proxy_mode = false
ws_ping_interval_secs = 30
ws_ping_timeout_secs = 90

[privacy]
# server_secret = "your_64_char_hex_string_here"

[logging]
log_level = "info"
log_chat = false

[censor]
enabled = false

[master_server]
advertise = true
addr = "https://servers.aceattorneyonline.com/servers"
# hostname = "your.domain.example"

[rate_limits]
ic_rate = 3.0
ic_burst = 5
mc_rate = 1.0
mc_burst = 3
ct_rate = 2.0
ct_burst = 5
evidence_rate = 5.0
evidence_burst = 10
zz_cooldown_secs = 60
conn_rate = 1.0
conn_burst = 5
```

**Example `config.toml` — behind nginx + Cloudflare:**

```toml
[network]
tcp_port = 27017
ws_port = 27018
bind_addr = "127.0.0.1"        # Only accept connections from nginx
reverse_proxy_mode = true
reverse_proxy_http_port  = 80  # Advertised as ws://  to master server
reverse_proxy_https_port = 443 # Advertised as wss:// to master server
ws_ping_interval_secs = 30
ws_ping_timeout_secs = 90

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
| `WATCHLIST` | Yes | Watchlist entries keyed by hashed HDID |
| `IPID_BANS` | Yes | IPID ban records keyed by hashed IPID |

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

### `data/censor.txt`

Optional. One word or phrase per line. Lines that are blank or start with `#` are ignored. Matching is **case-insensitive** and checks whether the word appears **anywhere** in the IC message text.

```
# Lines starting with # are comments
badword
offensive phrase
```

Enable the filter in `config.toml`:
```toml
[censor]
enabled = true
```

The censor list is hot-reloadable via `/reload` without restarting the server.

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

| Key | Type | Default | Description |
|---|---|---|---|
| `name` | string | *(required)* | Display name of the area |
| `background` | string | *(required)* | Default background on area reset |
| `evidence_mode` | string | *(required)* | Who can add/edit evidence: `any`, `cms`, `mods` |
| `allow_iniswap` | bool | *(required)* | Allow players to use iniswapped characters |
| `allow_cms` | bool | *(required)* | Allow players to become case managers (`/cm`) |
| `force_nointerrupt` | bool | *(required)* | Force all messages to be non-interrupting |
| `force_bglist` | bool | *(required)* | Restrict backgrounds to the server's `backgrounds.txt` list |
| `lock_bg` | bool | *(required)* | Prevent background changes entirely |
| `lock_music` | bool | *(required)* | Prevent music changes via packet (mods can still override) |
| `max_players` | integer | *(none)* | Optional cap on players in this area. Omit for unlimited. |
| `owner` | string | *(none)* | Optional account username that automatically receives CM status when they join this area. |

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
| `setrole <username> <role>` | Change an existing account's role (`admin`, `mod`, `trial`, `cm`, `none`) |
| `shutdown` | Gracefully shut down the server |
| `help` | List available CLI commands |

---

## Reverse Proxy Setup

Running Ferris-AO behind a reverse proxy is strongly recommended for TLS termination, DDoS protection (Cloudflare), and IP privacy. Set `reverse_proxy_mode = true` in `config.toml` for any proxy. The real client IP is recovered from `X-Forwarded-For` or `X-Real-IP`; Ferris-AO hashes it immediately and never stores the raw address.

| Proxy | Logs IPs by default | TLS | WebSocket | Best for |
|---|---|---|---|---|
| **nginx** | Yes — disable with `access_log off` | certbot (Let's Encrypt) | Manual config | Production, Cloudflare, advanced tuning |
| **Caddy** | No | Automatic (Let's Encrypt) | Automatic | Simple setups, bare metal |
| **Traefik** | No | Automatic (Let's Encrypt) | Automatic | Docker / container deployments |

---

### nginx + Cloudflare (recommended production setup)

This guide uses two domains as an example:

| Domain | Cloudflare | Purpose |
|---|---|---|
| `hatsune.miku.pizza` | **Gray cloud** (DNS only) | Game connections (TCP + WSS). Must be direct — certbot needs port 80, TCP clients need port 27017. |
| `miku.pizza` | **Orange cloud** (proxied) | Asset URL. Cloudflare CDN caches your asset bundle files. |

#### 1. DNS setup in Cloudflare

In your Cloudflare dashboard, add two A records pointing to your VPS IP:

```
Type  Name              Content       Proxy
A     miku.pizza        <VPS IP>      Proxied (orange)
A     hatsune.miku.pizza <VPS IP>     DNS only (gray)
```

**Why gray-cloud for the game subdomain?**
- TCP clients connect directly to `hatsune.miku.pizza:27017` — Cloudflare cannot proxy raw TCP on the free tier
- certbot's HTTP-01 challenge requires a direct connection to your VPS on port 80
- WebSocket connections are more stable over a direct path

#### 2. Install nginx and certbot on your VPS

```bash
sudo apt update
sudo apt install nginx certbot python3-certbot-nginx
```

#### 3. Install the nginx config

```bash
# Copy the example config (adjust paths if you cloned elsewhere)
sudo cp nginx/nyahao.conf /etc/nginx/sites-available/ferris-ao

# Edit it — replace hatsune.miku.pizza with your actual subdomain
sudo nano /etc/nginx/sites-available/ferris-ao

# Symlink into sites-enabled
sudo ln -s /etc/nginx/sites-available/ferris-ao /etc/nginx/sites-enabled/ferris-ao

# Test the config
sudo nginx -t

# Apply
sudo systemctl reload nginx
```

#### 4. Issue a TLS certificate

```bash
sudo certbot --nginx -d hatsune.miku.pizza
```

Certbot will automatically edit the nginx config to fill in the certificate paths and set up HTTPS. It also installs a cron job that auto-renews the certificate every 60 days.

Verify renewal works:
```bash
sudo certbot renew --dry-run
```

#### 5. Open firewall ports

```bash
sudo ufw allow 27017/tcp   # TCP game clients (direct)
sudo ufw allow 80/tcp      # HTTP (certbot renewal)
sudo ufw allow 443/tcp     # HTTPS/WSS (WebSocket clients via nginx)
sudo ufw enable
```

#### 6. Configure Ferris-AO

```toml
[server]
# Asset URL uses the orange-clouded domain so Cloudflare CDN serves the files
asset_url = "https://miku.pizza/assets"

[network]
bind_addr                = "0.0.0.0"   # TCP must be directly reachable
tcp_port                 = 27017       # Direct TCP — no nginx involved
ws_port                  = 27018       # nginx forwards both :80 AND :443 → here
reverse_proxy_mode       = true
reverse_proxy_http_port  = 80          # Advertised as ws://  to master server
reverse_proxy_https_port = 443         # Advertised as wss:// to master server

[master_server]
advertise = true
hostname  = "hatsune.miku.pizza"       # Advertised in the server list
```

The server will advertise:
- **TCP:** `hatsune.miku.pizza:27017` (direct)
- **WS:** `ws://hatsune.miku.pizza:80` (via nginx → localhost:27018)
- **WSS:** `wss://hatsune.miku.pizza:443` (via nginx → localhost:27018)

Both `ws://` and `wss://` are routed by nginx to the **same single** Ferris-AO WebSocket listener on port 27018 — no second process needed.

#### How traffic flows

```
Player (AO2 desktop)
  └─ TCP :27017 ──────────────────→ VPS :27017 → Ferris-AO (direct)

Player (WebAO — plain WS)
  └─ ws://hatsune.miku.pizza:80
       └─ gray DNS → VPS :80 → nginx → localhost:27018 → Ferris-AO

Player (WebAO — secure WSS)
  └─ wss://hatsune.miku.pizza:443
       └─ gray DNS → VPS :443 → nginx → localhost:27018 → Ferris-AO

Asset download
  └─ https://miku.pizza/assets/...
       └─ orange DNS → Cloudflare CDN → VPS (cached)
```

#### The nginx config file (`nginx/nyahao.conf`)

```nginx
# Port 80 — plain WebSocket (ws://) + certbot + redirect
# nginx routes WebSocket upgrades to Ferris-AO; plain HTTP → HTTPS redirect.
server {
    listen 80;
    server_name hatsune.miku.pizza;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        if ($http_upgrade = "websocket") {
            proxy_pass http://127.0.0.1:27018;
        }
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host       $host;
        proxy_set_header   X-Real-IP       $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 7200s;
        proxy_send_timeout 30s;
        proxy_buffering    off;
        return 301 https://$host$request_uri;  # Non-WebSocket → HTTPS
    }
}

# Port 443 — WSS (wss://) WebSocket proxy
server {
    listen 443 ssl;
    server_name hatsune.miku.pizza;

    ssl_certificate     /etc/letsencrypt/live/hatsune.miku.pizza/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/hatsune.miku.pizza/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    access_log off;   # Privacy — Ferris-AO never stores raw IPs either

    location / {
        proxy_pass         http://127.0.0.1:27018;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade    $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host       $host;
        proxy_set_header   X-Real-IP       $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 7200s;
        proxy_send_timeout 30s;
        proxy_buffering    off;
    }
}
```

Both blocks forward to the **same** `localhost:27018` listener. Only one Ferris-AO process is needed.

The full annotated config with TCP stream block and setup comments is at `nginx/nyahao.conf`.

---

### Caddy

[Caddy](https://caddyserver.com/) produces **no access logs by default** and handles TLS and WebSocket upgrades automatically — the simplest privacy-friendly option.

**With Cloudflare** (Cloudflare terminates TLS, Caddy on port 80):
```caddyfile
your.domain.example:80 {
    reverse_proxy localhost:27018 {
        header_up X-Forwarded-For {http.request.header.CF-Connecting-IP}
        header_up X-Real-IP       {http.request.header.CF-Connecting-IP}
    }
}
```

**Without Cloudflare** (Caddy handles HTTPS automatically via Let's Encrypt):
```caddyfile
your.domain.example {
    reverse_proxy localhost:27018 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP       {remote_host}
    }
}
```

`config.toml`:
```toml
[network]
ws_port = 27018
bind_addr = "127.0.0.1"
reverse_proxy_mode = true
reverse_proxy_http_port  = 80   # Advertised as ws://  to master server
reverse_proxy_https_port = 443  # Advertised as wss:// to master server

[master_server]
advertise = true
hostname = "your.domain.example"
```

---

### Traefik

[Traefik](https://traefik.io/) has access logging **disabled by default** and is well suited to Docker deployments.

**`traefik.yml`:**
```yaml
entryPoints:
  websecure:
    address: ":443"
certificatesResolvers:
  letsencrypt:
    acme:
      email: your@email.com
      storage: /letsencrypt/acme.json
      tlsChallenge: {}
providers:
  file:
    filename: /etc/traefik/dynamic.yml
# Do not add an accessLog block — logging is off by default.
```

**`dynamic.yml`:**
```yaml
http:
  routers:
    ferris-ao:
      rule: "Host(`your.domain.example`)"
      entryPoints: [websecure]
      tls:
        certResolver: letsencrypt
      service: ferris-ao
  services:
    ferris-ao:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:27018"
```

> With Cloudflare in front, add `forwardedHeaders.trustedIPs` set to [Cloudflare's IP ranges](https://www.cloudflare.com/ips/) so `X-Forwarded-For` cannot be spoofed.

**Docker Compose:**
```yaml
services:
  traefik:
    image: traefik:v3.0
    command:
      - "--accesslog=false"
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.le.acme.tlschallenge=true"
      - "--certificatesresolvers.le.acme.email=your@email.com"
      - "--certificatesresolvers.le.acme.storage=/letsencrypt/acme.json"
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./letsencrypt:/letsencrypt
  ferris-ao:
    build: .
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.ferris.rule=Host(`your.domain.example`)"
      - "traefik.http.routers.ferris.entrypoints=websecure"
      - "traefik.http.routers.ferris.tls.certresolver=le"
      - "traefik.http.services.ferris.loadbalancer.server.port=27018"
```

---

### nginx

A full example config is at `nginx/nyahao.conf`. nginx **logs IP addresses by default** — disable this in the `http {}` block:

```nginx
access_log off;
# or strip IPs from the format:
# log_format no_ip '$time_local "$request" $status $body_bytes_sent';
# access_log /var/log/nginx/access.log no_ip;
```

**With Cloudflare** (nginx on port 80, Cloudflare handles TLS):
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

**Without Cloudflare** (nginx handles TLS with Let's Encrypt):
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

**Legacy TCP clients** (requires nginx compiled with `--with-stream`; Cloudflare Spectrum needed for TCP passthrough):
```nginx
stream {
    server {
        listen     27016;
        proxy_pass 127.0.0.1:27017;
        proxy_protocol        on;
        proxy_connect_timeout 10s;
        proxy_timeout         7200s;
    }
}
```

With `proxy_protocol on`, nginx prepends a PROXY Protocol v2 header so Ferris-AO can recover the real client IP. Requires `reverse_proxy_mode = true`.

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
| `/pair <uid>` | Request to pair with another player (side-by-side IC messages) |
| `/unpair` | Cancel your current pairing |
| `/pm <uid> <message>` | Send a private message to a player |
| `/r <message>` | Reply to the last player who sent you a private message |
| `/ignore <uid>` | Hide IC and OOC messages from a player (session only — resets on disconnect) |
| `/unignore <uid>` | Stop ignoring a player |
| `/ignorelist` | Show which UIDs you are currently ignoring |

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
| `/shadowmute <uid>` | `MUTE` | Stealth mute a player — their messages appear to go through but are invisible to others. |
| `/warn <uid> <reason>` | `KICK` | Increment a player's warning count and notify them. |
| `/announce <message>` | `MOD_CHAT` | Send a server-wide OOC announcement to all players. |
| `/modchat <message>` | `MOD_CHAT` | Send a message only visible to authenticated moderators. |
| `/ipban <uid> [duration] <reason>` | `KICK` | Ban a player by their current IPID. Duration: `1h`, `6h`, `12h`, `1d`, `7d`; omit for permanent (until daily IPID rotation). |
| `/unipban <ipid>` | `BAN` | Remove an IPID ban. |
| `/watchlist add <hdid> [note]` | `WATCHLIST` | Add a hashed HDID to the watchlist with an optional note. |
| `/watchlist remove <hdid>` | `WATCHLIST` | Remove a hashed HDID from the watchlist. |
| `/watchlist list` | `WATCHLIST` | List all watchlist entries with who added them and when. |
| `/reload` | `ADMIN` | Hot-reload characters, music, and backgrounds without restarting. |
| `/logoutall` | `ADMIN` | Force-logout all authenticated moderator sessions. |

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
| `WATCHLIST` | `4096` | Can add/remove/list watchlist entries |
| `ADMIN` | `ALL` | All permissions |

### Roles

When creating accounts via `mkusr`, specify one of these role names:

| Role | Permissions Granted |
|---|---|
| `admin` | All permissions (`ADMIN`) |
| `mod` / `moderator` | `KICK`, `BAN`, `BYPASS_LOCK`, `MOD_EVI`, `MODIFY_AREA`, `MOVE_USERS`, `MOD_SPEAK`, `BAN_INFO`, `MOD_CHAT`, `MUTE`, `LOG`, `WATCHLIST` |
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
│   ├── music.txt           # Music list with category headers
│   └── censor.txt          # Optional word censor list (one word/phrase per line)
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
    │   ├── bans.rs         # BanRecord, BanManager, soft-delete
    │   └── watchlist.rs    # WatchEntry, WatchlistManager
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
    ├── commands/
    │   ├── mod.rs
    │   └── registry.rs     # All /command implementations
    ├── ratelimit.rs         # TokenBucket implementation
    └── ms.rs               # Master server advertisement
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
