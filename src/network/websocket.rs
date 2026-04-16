//! WebSocket listener.
//!
//! When `reverse_proxy_mode = true` in config, the real client IP is extracted
//! from proxy headers in priority order: `X-Forwarded-For` (first address) →
//! `X-Real-IP`. This matches how Nyathena handles reverse proxy IP extraction.
//! When `reverse_proxy_mode = false`, the raw TCP peer address is used.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio_rustls::TlsAcceptor;

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{Request, Response},
        protocol::WebSocketConfig,
        Message,
    },
    WebSocketStream,
};
use tracing::{debug, error, info, warn};

use crate::protocol::packet::Packet;
use crate::server::ServerState;

use super::{handle_connection, AoTransport};

/// Combined async read+write trait used to box plain TCP and TLS streams
/// under the same WebSocket transport type.
trait AsyncIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncIo for T {}

/// A WebSocket transport that accumulates frames until `%` appears.
pub struct WsTransport {
    ws: WebSocketStream<Box<dyn AsyncIo>>,
    buf: String,
    /// Time of the last received Pong frame (or transport creation).
    pub last_pong: std::time::Instant,
    /// Hard packet size cap in bytes.
    max_packet_bytes: usize,
    /// Maximum number of `#`-separated fields allowed per packet.
    max_packet_fields: usize,
}

impl WsTransport {
    pub async fn send(&mut self, data: &str) -> Result<()> {
        self.ws.send(Message::Text(data.to_string().into())).await?;
        Ok(())
    }

    /// Send raw binary data as a WebSocket Binary frame (for MessagePack payloads).
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.ws.send(Message::Binary(data.to_vec().into())).await?;
        Ok(())
    }

    /// Send a WebSocket Ping frame for keepalive.
    pub async fn send_ping(&mut self) -> Result<()> {
        self.ws.send(Message::Ping(vec![].into())).await?;
        Ok(())
    }

    /// Returns true if no Pong has been received within `timeout`.
    pub fn is_stale(&self, timeout: std::time::Duration) -> bool {
        self.last_pong.elapsed() > timeout
    }

    pub async fn recv_packet(&mut self) -> Option<Result<Packet>> {
        loop {
            // Check buffer for a complete packet.
            if let Some(idx) = self.buf.find('%') {
                let raw = self.buf[..idx].to_string();
                self.buf.drain(..=idx);
                let max_bytes = if self.max_packet_bytes > 0 {
                    self.max_packet_bytes
                } else {
                    crate::protocol::packet::MAX_PACKET_SIZE
                };
                let max_fields = if self.max_packet_fields > 0 {
                    self.max_packet_fields
                } else {
                    crate::protocol::packet::MAX_PACKET_FIELDS
                };
                return Some(
                    Packet::parse_with_limit(raw.as_bytes(), max_bytes, max_fields)
                        .map_err(Into::into),
                );
            }

            // Hard-drop if buffer exceeds the packet size cap.
            if self.max_packet_bytes > 0 && self.buf.len() > self.max_packet_bytes {
                warn!("WS packet exceeded max_packet_bytes ({}); dropping connection.", self.max_packet_bytes);
                self.buf.clear();
                return Some(Err(anyhow::anyhow!("packet too large")));
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
                    Message::Ping(_) => {} // tungstenite auto-replies with Pong
                    Message::Pong(_) => {
                        self.last_pong = std::time::Instant::now();
                    }
                    Message::Frame(_) => {}
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
    tls: Option<Arc<TlsAcceptor>>,
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
                        let tls2 = tls.clone();
                        tokio::spawn(async move {
                            if let Err(e) = accept_ws(stream, peer, state2, client_shutdown, tls2).await {
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
    tls: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let proxy_mode = state.config.network.reverse_proxy_mode;

    // Use Arc<Mutex> so the FnOnce callback can write and we can read after.
    let extracted_ip: Arc<Mutex<Option<IpAddr>>> = Arc::new(Mutex::new(None));
    let extracted_ip_cb = Arc::clone(&extracted_ip);

    // Tuned WebSocket config.
    // Write-buffer headroom: 128 KiB flush threshold, 256 KiB hard cap.
    // These values accommodate batch-written multi-packet bursts without
    // excessive buffering.
    //
    // Inbound message/frame ceilings are derived from `max_packet_bytes`
    // (with a floor of 64 KiB for handshake/control traffic).  This prevents
    // an attacker from sending a single multi-gigabyte frame that would
    // exhaust memory before our own post-parse packet-size check runs.
    //
    // NOTE: permessage-deflate (RFC 7692) compression is not yet available in
    // tungstenite 0.26.  The `network.ws_compression` config field is reserved
    // for future use.  When we upgrade to a version that exposes
    // WebSocketConfig::compression, enable it here with DeflateConfig::default()
    // when `state.config.network.ws_compression = true`.
    // TODO: Enable when tungstenite exposes permessage-deflate in WebSocketConfig.
    let inbound_cap = state
        .config
        .server
        .max_packet_bytes
        .max(65_536)
        .min(4 * 1024 * 1024); // hard ceiling of 4 MiB
    let ws_config = WebSocketConfig::default()
        .write_buffer_size(128 * 1024)
        .max_write_buffer_size(256 * 1024)
        .max_message_size(Some(inbound_cap))
        .max_frame_size(Some(inbound_cap));

    // Disable Nagle for responsive AO2 packets.
    let _ = stream.set_nodelay(true);

    let handshake_timeout = std::time::Duration::from_secs(
        state.config.server.handshake_timeout_secs.max(5),
    );

    // Optionally wrap in TLS before WebSocket upgrade.  Bound the TLS
    // handshake with a timeout so a silent attacker cannot hold a worker
    // task open indefinitely.
    let boxed_stream: Box<dyn AsyncIo> = if let Some(acceptor) = tls.as_deref() {
        match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
            Ok(Ok(tls_stream)) => Box::new(tls_stream),
            Ok(Err(e)) => {
                debug!("TLS handshake failed from {}: {}", peer, e);
                return Ok(());
            }
            Err(_) => {
                debug!("TLS handshake timeout from {}", peer);
                return Ok(());
            }
        }
    } else {
        Box::new(stream)
    };

    let ws_fut = accept_hdr_async_with_config(boxed_stream, move |req: &Request, mut res: Response| {
        // Sub-protocol acknowledgement: if the client advertises "AO2", echo it back.
        if let Some(proto_hdr) = req.headers().get("sec-websocket-protocol") {
            if let Ok(p) = proto_hdr.to_str() {
                if p.split(',').any(|s| s.trim() == "AO2") {
                    if let Ok(val) = "AO2".parse() {
                        res.headers_mut().insert("sec-websocket-protocol", val);
                    }
                }
            }
        }

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
    }, Some(ws_config));

    // Hard cap on the HTTP upgrade — blocks slowloris-style hangs.
    let ws = match tokio::time::timeout(handshake_timeout, ws_fut).await {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => {
            debug!("WS upgrade failed from {}: {}", peer, e);
            return Ok(());
        }
        Err(_) => {
            debug!("WS upgrade timeout from {}", peer);
            return Ok(());
        }
    };

    let real_ip = extracted_ip.lock().unwrap().unwrap_or(peer.ip());
    debug!("WS client resolved IP={}", real_ip);

    if !state.check_conn_rate(real_ip).await {
        debug!("WS connection rate limit exceeded for {}", real_ip);
        return Ok(());
    }

    // Reserve global + per-IP slot; guard holds until this task ends.
    let _slot = match state.try_reserve_conn(real_ip) {
        Some(slot) => slot,
        None => {
            debug!("WS connection denied (cap reached) for {}", real_ip);
            return Ok(());
        }
    };

    let max_packet_bytes = state.config.server.max_packet_bytes;
    let max_packet_fields = state.config.server.max_packet_fields;
    let transport = AoTransport::Ws(WsTransport {
        ws,
        buf: String::new(),
        last_pong: std::time::Instant::now(),
        max_packet_bytes,
        max_packet_fields,
    });
    handle_connection(transport, real_ip, state, shutdown).await;
    drop(_slot);
    Ok(())
}
