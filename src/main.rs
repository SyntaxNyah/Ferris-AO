mod auth;
mod client;
mod commands;
mod config;
mod game;
mod moderation;
mod ms;
mod network;
mod privacy;
mod protocol;
mod ratelimit;
mod server;
mod storage;

use std::{
    net::SocketAddr,
    path::Path,
    sync::{atomic::Ordering, Arc},
};

use anyhow::{Context, Result};
use tokio::sync::{broadcast, watch};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::{
    config::Config,
    game::{areas::load_areas, characters::build_sm_packet, characters::load_censor_words, characters::load_lines},
    privacy::hashing::PrivacyLayer,
    server::{ReloadableData, ServerState},
    storage::db::EncryptedDb,
};

#[tokio::main]
async fn main() -> Result<()> {
    // ── Load config ────────────────────────────────────────────────────────────
    let config_path = Path::new("config.toml");
    let config = Config::load(config_path).context("Failed to load config.toml")?;

    // ── Init tracing ───────────────────────────────────────────────────────────
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.logging.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!("Starting NyahAO server…");

    // ── Config validation ──────────────────────────────────────────────────────
    if config.server.name.is_empty() {
        warn!("server.name is empty in config.toml — clients will see a blank server name.");
    } else if config.server.name == "My AO Server" || config.server.name == "NyahAO Server" {
        warn!("server.name is still a placeholder ('{}') — consider changing it in config.toml.", config.server.name);
    }
    if config.server.max_players == 0 {
        warn!("server.max_players is 0 — no clients will be able to connect.");
    }

    // ── Determine AES-256 key for the DB ───────────────────────────────────────
    let db_key: [u8; 32] = {
        if let Ok(hex_key) = std::env::var("NYAHAO_DB_KEY") {
            let bytes = hex::decode(hex_key.trim())
                .context("NYAHAO_DB_KEY must be a 64-char hex string (32 bytes)")?;
            if bytes.len() != 32 {
                anyhow::bail!("NYAHAO_DB_KEY must decode to exactly 32 bytes");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        } else {
            // Default dev key — insecure; warn loudly.
            warn!("NYAHAO_DB_KEY not set — using insecure default key. Set this env var in production!");
            [0x4e_u8; 32] // 0x4e = 'N'
        }
    };

    // ── Open encrypted database ────────────────────────────────────────────────
    std::fs::create_dir_all("data").ok();
    let db = Arc::new(
        EncryptedDb::open("data/nyahao.db", &db_key).context("Failed to open database")?,
    );

    // ── Load or generate server secret (for privacy hashing) ──────────────────
    let server_secret: [u8; 32] = {
        let stored = db.config_get("server_secret")?;
        if let Some(bytes) = stored {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            } else {
                warn!("Stored server_secret has wrong length; regenerating.");
                generate_and_store_secret(&db)?
            }
        } else {
            info!("No server_secret found — generating new one.");
            generate_and_store_secret(&db)?
        }
    };
    let privacy = PrivacyLayer::new(server_secret);

    // ── Load game data ─────────────────────────────────────────────────────────
    let characters = load_lines(Path::new("data/characters.txt"))
        .context("Failed to load data/characters.txt")?;
    let music = load_lines(Path::new("data/music.txt"))
        .context("Failed to load data/music.txt")?;
    let backgrounds = load_lines(Path::new("data/backgrounds.txt"))
        .context("Failed to load data/backgrounds.txt")?;
    let areas_raw = load_areas(Path::new("data/areas.toml"), characters.len())
        .context("Failed to load data/areas.toml")?;

    let censor_words = load_censor_words(Path::new("data/censor.txt"));

    info!(
        "Loaded {} characters, {} music entries, {} areas, {} censor words.",
        characters.len(),
        music.len(),
        areas_raw.len(),
        censor_words.len(),
    );

    // Build SM packet (pre-computed; sent to every joining client).
    let area_names: Vec<&str> = areas_raw.iter().map(|a| a.name.as_str()).collect();
    let sm_packet = build_sm_packet(&area_names, &music);

    // Bundle hot-reloadable data.
    let reloadable = ReloadableData { characters, music, backgrounds, sm_packet, censor_words };

    // Wrap areas in Arc<RwLock<_>>.
    let areas: Vec<Arc<tokio::sync::RwLock<crate::game::areas::Area>>> = areas_raw
        .into_iter()
        .map(|a| Arc::new(tokio::sync::RwLock::new(a)))
        .collect();

    // ── Build shared server state ──────────────────────────────────────────────
    let (player_watch_tx, player_watch_rx) = watch::channel(0usize);
    let state = Arc::new(ServerState::new(
        config,
        reloadable,
        areas,
        privacy,
        Arc::clone(&db),
        player_watch_tx,
    ));

    // ── Shutdown broadcast channel ─────────────────────────────────────────────
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // ── Spawn TCP listener ─────────────────────────────────────────────────────
    let tcp_addr: SocketAddr = format!(
        "{}:{}",
        state.config.network.bind_addr, state.config.network.tcp_port
    )
    .parse()
    .context("Invalid TCP bind address")?;

    let tcp_state = Arc::clone(&state);
    let tcp_shutdown = shutdown_tx.clone();
    let tcp_task = tokio::spawn(async move {
        if let Err(e) = network::tcp::listen_tcp(tcp_addr, tcp_state, tcp_shutdown).await {
            error!("TCP listener error: {}", e);
        }
    });

    // ── Spawn WebSocket listener ───────────────────────────────────────────────
    let ws_addr: SocketAddr = format!(
        "{}:{}",
        state.config.network.bind_addr, state.config.network.ws_port
    )
    .parse()
    .context("Invalid WebSocket bind address")?;

    let ws_state = Arc::clone(&state);
    let ws_shutdown = shutdown_tx.clone();
    let ws_task = tokio::spawn(async move {
        if let Err(e) = network::websocket::listen_ws(ws_addr, ws_state, ws_shutdown).await {
            error!("WebSocket listener error: {}", e);
        }
    });

    // ── Spawn master server advertisement task ─────────────────────────────────
    {
        let ms_state = Arc::clone(&state);
        tokio::spawn(async move {
            ms::advertise(ms_state, player_watch_rx).await;
        });
    }

    // ── Spawn stdin CLI task ───────────────────────────────────────────────────
    let cli_state = Arc::clone(&state);
    let cli_shutdown_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        run_stdin_cli(cli_state, cli_shutdown_tx).await;
    });

    // ── Wait for Ctrl-C or shutdown ────────────────────────────────────────────
    tokio::signal::ctrl_c().await.ok();
    info!("Shutting down…");
    let _ = shutdown_tx.send(());

    // Give listeners a moment to stop.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    tcp_task.abort();
    ws_task.abort();

    info!("NyahAO stopped.");
    Ok(())
}

/// Generate a random 32-byte server secret and persist it in the DB.
fn generate_and_store_secret(db: &EncryptedDb) -> Result<[u8; 32]> {
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    db.config_set("server_secret", &secret)
        .context("Failed to store server_secret in DB")?;
    Ok(secret)
}

/// Simple stdin command-line interface for server admins.
async fn run_stdin_cli(state: Arc<ServerState>, shutdown_tx: broadcast::Sender<()>) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let cmd = parts.next().unwrap_or("").to_lowercase();
        let arg1 = parts.next().unwrap_or("").to_string();
        let arg2 = parts.next().unwrap_or("").to_string();

        match cmd.as_str() {
            "players" => {
                let count = state.player_count.load(Ordering::Relaxed);
                let max = state.config.server.max_players;
                println!("[CLI] Players: {}/{}", count, max);
                let clients = state.clients.lock().await;
                for handle in clients.values() {
                    println!(
                        "  UID={} area={} auth={} ipid={}",
                        handle.uid, handle.area_idx, handle.authenticated, handle.ipid
                    );
                }
            }
            "say" => {
                // Broadcast a server-wide OOC message.
                let msg = if arg2.is_empty() {
                    arg1.clone()
                } else {
                    format!("{} {}", arg1, arg2)
                };
                let name = crate::protocol::packet::ao_encode(&state.config.server.name);
                let encoded = crate::protocol::packet::ao_encode(&msg);
                state.broadcast("CT", &[&name, &encoded, "1"]).await;
                println!("[CLI] Broadcast: {}", msg);
            }
            "mkusr" => {
                // mkusr <username> <password> [role]
                if arg1.is_empty() {
                    println!("[CLI] Usage: mkusr <username> <password> [admin|mod|trial|cm]");
                    continue;
                }
                // arg2 contains "<password> <role>" due to splitn(3)
                let mut pw_role = arg2.splitn(2, ' ');
                let pw = pw_role.next().unwrap_or("").to_string();
                let role = pw_role.next().unwrap_or("mod").to_string();
                if pw.is_empty() {
                    println!("[CLI] Usage: mkusr <username> <password> [role]");
                    continue;
                }
                let accounts = state.accounts.clone();
                let u = arg1.clone();
                let p = pw.clone();
                let r = role.clone();
                match tokio::task::spawn_blocking(move || accounts.create(&u, &p, &r)).await {
                    Ok(Ok(_)) => println!("[CLI] Created user '{}' with role '{}'.", arg1, role),
                    Ok(Err(e)) => println!("[CLI] Error: {}", e),
                    Err(e) => println!("[CLI] Task error: {}", e),
                }
            }
            "rmusr" => {
                if arg1.is_empty() {
                    println!("[CLI] Usage: rmusr <username>");
                    continue;
                }
                match state.accounts.delete(&arg1) {
                    Ok(true) => println!("[CLI] Deleted user '{}'.", arg1),
                    Ok(false) => println!("[CLI] User '{}' not found.", arg1),
                    Err(e) => println!("[CLI] Error: {}", e),
                }
            }
            "setrole" => {
                // setrole <username> <role>
                if arg1.is_empty() || arg2.is_empty() {
                    println!("[CLI] Usage: setrole <username> <role>  (roles: admin, mod, trial, cm, none)");
                    continue;
                }
                let perms = crate::auth::accounts::perms::from_role(&arg2);
                let accounts = state.accounts.clone();
                let u = arg1.clone();
                match tokio::task::spawn_blocking(move || accounts.set_permissions(&u, perms)).await {
                    Ok(Ok(true)) => println!("[CLI] Updated role for '{}' to '{}'.", arg1, arg2),
                    Ok(Ok(false)) => println!("[CLI] User '{}' not found.", arg1),
                    Ok(Err(e)) => println!("[CLI] Error: {}", e),
                    Err(e) => println!("[CLI] Task error: {}", e),
                }
            }
            "shutdown" => {
                println!("[CLI] Shutting down server…");
                let _ = shutdown_tx.send(());
                break;
            }
            "help" => {
                println!(
                    "[CLI] Commands:\n\
                     \x20 players                 — list connected players\n\
                     \x20 say <msg>               — broadcast OOC message\n\
                     \x20 mkusr <u> <p> [r]       — create user (roles: admin,mod,trial,cm)\n\
                     \x20 rmusr <u>               — delete user\n\
                     \x20 setrole <u> <role>       — change a user's role (admin,mod,trial,cm,none)\n\
                     \x20 shutdown                — stop the server\n\
                     \x20 help                    — this help"
                );
            }
            other => {
                println!("[CLI] Unknown command '{}'. Type 'help' for a list.", other);
            }
        }
    }
}
