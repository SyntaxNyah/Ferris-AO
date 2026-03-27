//! WebSocket listener.
//!
//! When `reverse_proxy_mode = true` in config, the real client IP is extracted
//! from proxy headers in priority order: `X-Forwarded-For` (first address) →
//! `X-Real-IP`. This matches how Nyathena handles reverse proxy IP extraction.
//! When `reverse_proxy_mode = false`, the raw TCP peer address is used.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        handshake::server::{Request, Response},
        Message,
    },
    WebSocketStream,
};
use tracing::{debug, error, info};

use crate::protocol::packet::Packet;
use crate::server::ServerState;

use super::{handle_connection, AoTransport};

/// A WebSocket transport that accumulates frames until `%` appears.
pub struct WsTransport {
    ws: WebSocketStream<TcpStream>,
    buf: String,
}

impl WsTransport {
    pub async fn send(&mut self, data: &str) -> Result<()> {
        self.ws.send(Message::Text(data.to_string())).await?;
        Ok(())
    }

    pub async fn recv_packet(&mut self) -> Option<Result<Packet>> {
        loop {
            // Check buffer for a complete packet.
            if let Some(idx) = self.buf.find('%') {
                let raw = self.buf[..idx].to_string();
                self.buf.drain(..=idx);
                return Some(Packet::parse(raw.as_bytes()).map_err(Into::into));
            }

            // Receive next WebSocket frame.
            match self.ws.next().await? {
                Ok(msg) => match msg {
                    Message::Text(t) => self.buf.push_str(&t),
                    Message::Binary(b) => {
                        if let Ok(s) = std::str::from_utf8(&b) {
                            self.buf.push_str(s);
                        }
                    }
                    Message::Close(_) => return None,
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
                },
                Err(e) => return Some(Err(e.into())),
            }
        }
    }
}

/// Spawn the WebSocket listener task.
pub async fn listen_ws(
    addr: SocketAddr,
    state: Arc<ServerState>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("WebSocket listener on {}", addr);

    let mut shutdown_rx = shutdown_tx.subscribe();
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        let state2 = Arc::clone(&state);
                        let client_shutdown = shutdown_tx.subscribe();
                        tokio::spawn(async move {
                            if let Err(e) = accept_ws(stream, peer, state2, client_shutdown).await {
                                debug!("WS connection error from {}: {}", peer, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("WS accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => break,
        }
    }
    Ok(())
}

/// Handle a single WebSocket upgrade: extract real IP from headers, hand off.
async fn accept_ws(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<ServerState>,
    shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let proxy_mode = state.config.network.reverse_proxy_mode;

    // Use Arc<Mutex> so the FnOnce callback can write and we can read after.
    let extracted_ip: Arc<Mutex<Option<IpAddr>>> = Arc::new(Mutex::new(None));
    let extracted_ip_cb = Arc::clone(&extracted_ip);

    let ws = accept_hdr_async(stream, move |req: &Request, res: Response| {
        if proxy_mode {
            let headers = req.headers();
            // Priority: X-Forwarded-For (first address) → X-Real-IP
            let raw = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .or_else(|| {
                    headers
                        .get("x-real-ip")
                        .and_then(|v| v.to_str().ok())
                        .map(str::trim)
                })
                .unwrap_or("");

            if let Ok(ip) = raw.parse::<IpAddr>() {
                if let Ok(mut guard) = extracted_ip_cb.lock() {
                    *guard = Some(ip);
                }
            }
        }
        Ok(res)
    })
    .await?;

    let real_ip = extracted_ip.lock().unwrap().unwrap_or(peer.ip());
    debug!("WS client resolved IP={}", real_ip);

    let transport = AoTransport::Ws(WsTransport { ws, buf: String::new() });
    handle_connection(transport, real_ip, state, shutdown).await;
    Ok(())
}
