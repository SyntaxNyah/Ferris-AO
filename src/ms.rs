//! Master server advertisement.
//!
//! When `advertise = true` in `[master_server]`, posts server info to the
//! AAO master server immediately on startup, then every 5 minutes, and
//! immediately whenever the player count changes.
//!
//! When `reverse_proxy_mode = true`, advertises BOTH `ws_port` (the external
//! HTTP port, typically 80) AND `wss_port` (the external HTTPS port, typically
//! 443). nginx forwards both external ports to the same internal `ws_port`
//! listener, so only one Ferris-AO WebSocket process is needed.
//! When `reverse_proxy_mode = false`, only `ws_port` (plain WebSocket) is
//! advertised — there is no TLS terminator.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::watch;
use tokio::time;
use tracing::{info, warn};

use crate::server::ServerState;

#[derive(Debug, Serialize)]
struct Advertisement {
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    ws_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wss_port: Option<u16>,
    players: usize,
    name: String,
    description: String,
}

/// Spawn and run the master server advertisement loop.
/// Returns immediately if `advertise = false`.
pub async fn advertise(state: Arc<ServerState>, mut player_rx: watch::Receiver<usize>) {
    if !state.config.master_server.advertise {
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Master server: failed to build HTTP client: {}", e);
            return;
        }
    };

    let url = state.config.master_server.addr.clone();

    // Post immediately on startup.
    post(&client, &url, &build_advert(&state)).await;

    // Consume the initial watch value so the first `changed()` fires on a real change.
    let _ = player_rx.has_changed();

    let mut interval = time::interval(Duration::from_secs(5 * 60));
    interval.tick().await; // consume the immediate first tick

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = player_rx.changed() => {},
        }
        post(&client, &url, &build_advert(&state)).await;
    }
}

fn build_advert(state: &ServerState) -> Advertisement {
    let net = &state.config.network;
    let srv = &state.config.server;
    let ms = &state.config.master_server;

    // When behind a reverse proxy, nginx routes both the plain HTTP port (e.g. 80)
    // and the HTTPS port (e.g. 443) to the same internal ws_port listener.
    // Advertise both so the master server can offer ws:// and wss:// entries.
    // Without a proxy, only the plain ws_port is advertised.
    let (ws_port, wss_port) = if net.reverse_proxy_mode {
        (
            Some(net.reverse_proxy_http_port),
            Some(net.reverse_proxy_https_port),
        )
    } else {
        (Some(net.ws_port), None)
    };

    Advertisement {
        ip: ms.hostname.clone(),
        port: net.tcp_port,
        ws_port,
        wss_port,
        players: state.player_count(),
        name: srv.name.clone(),
        description: srv.description.clone(),
    }
}

async fn post(client: &reqwest::Client, url: &str, advert: &Advertisement) {
    match client.post(url).json(advert).send().await {
        Ok(_) => info!("Master server: advertised ({} players).", advert.players),
        Err(e) => warn!("Master server: advertisement failed: {}", e),
    }
}
