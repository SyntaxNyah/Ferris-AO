//! TCP listener with optional PROXY Protocol v2 detection.
//!
//! When `reverse_proxy_mode = true`, nginx is expected to prepend a PP2
//! header (`proxy_protocol on`) so we can recover the real client IP.
//! When `reverse_proxy_mode = false`, the raw peer address is used directly.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::protocol::packet::Packet;
use crate::server::ServerState;

use super::{handle_connection, AoTransport};

/// PP2 magic bytes (12 bytes).
const PP2_MAGIC: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

/// A framed TCP transport that reads `%`-delimited AO2 packets.
pub struct TcpTransport {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
    buf: String,
    /// Bytes peeked ahead of time before the transport was created.
    /// These are replayed as the first data from the stream.
    prefix: Vec<u8>,
    /// Hard packet size cap. Packets exceeding this are dropped before parsing.
    max_packet_bytes: usize,
    /// Maximum number of `#`-separated fields allowed per packet.
    max_packet_fields: usize,
}

impl TcpTransport {
    fn new(
        reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
        writer: tokio::net::tcp::OwnedWriteHalf,
        prefix: Vec<u8>,
        max_packet_bytes: usize,
        max_packet_fields: usize,
    ) -> Self {
        Self {
            reader,
            writer,
            buf: String::new(),
            prefix,
            max_packet_bytes,
            max_packet_fields,
        }
    }

    pub async fn send(&mut self, data: &str) -> Result<()> {
        self.writer.write_all(data.as_bytes()).await?;
        Ok(())
    }

    pub async fn recv_packet(&mut self) -> Option<Result<Packet>> {
        // Drain prefix bytes first (non-PP2 data that was peeked).
        if !self.prefix.is_empty() {
            match std::str::from_utf8(&self.prefix) {
                Ok(s) => self.buf.push_str(s),
                Err(_) => {
                    self.prefix.clear();
                    return Some(Err(anyhow::anyhow!("invalid UTF-8 in prefix bytes")));
                }
            }
            self.prefix.clear();
        }

        loop {
            // Check if we already have a complete packet in the buffer.
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

            // Hard-drop if buffer exceeds the packet size cap (no '%' found yet).
            if self.max_packet_bytes > 0 && self.buf.len() > self.max_packet_bytes {
                warn!("TCP packet exceeded max_packet_bytes ({}); dropping connection.", self.max_packet_bytes);
                self.buf.clear();
                return Some(Err(anyhow::anyhow!("packet too large")));
            }

            // Read more data.
            let mut chunk = vec![0u8; 4096];
            match self.reader.read(&mut chunk).await {
                Ok(0) => return None, // EOF
                Ok(n) => {
                    match std::str::from_utf8(&chunk[..n]) {
                        Ok(s) => self.buf.push_str(s),
                        Err(_) => return Some(Err(anyhow::anyhow!("invalid UTF-8 from client"))),
                    }
                }
                Err(e) => return Some(Err(e.into())),
            }
        }
    }
}

/// Spawn the TCP listener task.
pub async fn listen_tcp(
    addr: std::net::SocketAddr,
    state: Arc<ServerState>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("TCP listener on {}", addr);

    let mut shutdown_rx = shutdown_tx.subscribe();
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        let state2 = Arc::clone(&state);
                        let client_shutdown = shutdown_tx.subscribe();
                        tokio::spawn(async move {
                            if let Err(e) = accept_tcp(stream, peer, state2, client_shutdown).await {
                                debug!("TCP connection error from {}: {}", peer, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("TCP accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => break,
        }
    }
    Ok(())
}

/// Handle a single accepted TCP connection: detect PP2, extract IP, hand off.
async fn accept_tcp(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<ServerState>,
    shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    // Disable Nagle for low-latency AO2 packets.
    let _ = stream.set_nodelay(true);

    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let handshake_timeout = std::time::Duration::from_secs(
        state.config.server.handshake_timeout_secs.max(5),
    );

    let (real_ip, prefix): (IpAddr, Vec<u8>) = if state.config.network.reverse_proxy_mode {
        // Read exactly 12 bytes to detect the PP2 magic prefix, with a
        // hard timeout so a silent client cannot hold the task open.
        let mut peek = [0u8; 12];
        match tokio::time::timeout(handshake_timeout, reader.read_exact(&mut peek)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => bail!("TCP PP2 preamble timeout from {}", peer),
        }

        if &peek == PP2_MAGIC {
            // PP2 present: read the full PP2 header and extract source addr.
            let ip = tokio::time::timeout(handshake_timeout, parse_pp2(&mut reader, &peek))
                .await
                .map_err(|_| anyhow::anyhow!("PP2 header read timeout from {}", peer))??;
            (ip, vec![])
        } else {
            // Proxy mode on but no PP2 header — fall back to peer addr.
            (peer.ip(), peek.to_vec())
        }
    } else {
        // Direct connection: use the raw peer address, no peeking needed.
        (peer.ip(), vec![])
    };

    debug!("TCP client resolved IP={}", real_ip);

    // Rate limit (new connections per second per IP).
    if !state.check_conn_rate(real_ip).await {
        debug!("TCP connection rate limit exceeded for {}", real_ip);
        return Ok(());
    }

    // Reserve a global + per-IP slot; RAII guard releases on drop.
    let _slot = match state.try_reserve_conn(real_ip) {
        Some(slot) => slot,
        None => {
            debug!("TCP connection denied (cap reached) for {}", real_ip);
            return Ok(());
        }
    };

    let transport = AoTransport::Tcp(TcpTransport::new(
        reader,
        write_half,
        prefix,
        state.config.server.max_packet_bytes,
        state.config.server.max_packet_fields,
    ));
    handle_connection(transport, real_ip, state, shutdown).await;
    drop(_slot);
    Ok(())
}

/// Parse the PROXY Protocol v2 header and return the source address.
/// The caller has already read the 12-byte magic; this reads the rest.
async fn parse_pp2(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    magic: &[u8; 12],
) -> Result<IpAddr> {
    // PP2 header layout after magic (12 bytes):
    //   [12] version+command (1 byte)
    //   [13] family+protocol (1 byte)
    //   [14-15] length of additional address data (2 bytes, big-endian)
    //   [16..] address data

    let mut header_rest = [0u8; 4];
    reader.read_exact(&mut header_rest).await?;

    let addr_len = u16::from_be_bytes([header_rest[2], header_rest[3]]) as usize;
    if addr_len > 216 {
        bail!("PP2 address length implausibly large: {}", addr_len);
    }

    let mut addr_data = vec![0u8; addr_len];
    reader.read_exact(&mut addr_data).await?;

    // Build the full PP2 bytes for the ppp crate to parse.
    let mut full = Vec::with_capacity(12 + 4 + addr_len);
    full.extend_from_slice(magic);
    full.extend_from_slice(&header_rest);
    full.extend_from_slice(&addr_data);

    // Use the `ppp` crate to parse.
    use ppp::v2::{Addresses, Header};
    let header = Header::try_from(full.as_slice())
        .map_err(|e| anyhow::anyhow!("PP2 parse error: {:?}", e))?;

    let ip = match header.addresses {
        Addresses::IPv4(a) => IpAddr::V4(a.source_address),
        Addresses::IPv6(a) => IpAddr::V6(a.source_address),
        other => {
            warn!("PP2 non-IP address family: {:?}; using loopback", other);
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
    };

    Ok(ip)
}
