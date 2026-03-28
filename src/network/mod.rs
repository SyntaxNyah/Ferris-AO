pub mod tcp;
pub mod websocket;

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::broadcast;

use crate::protocol::packet::Packet;
use crate::server::ServerState;

/// Concrete enum over the two transport kinds, avoiding the need for
/// `async_trait` or boxed futures on a trait object.
pub enum AoTransport {
    Tcp(tcp::TcpTransport),
    Ws(websocket::WsTransport),
}

impl AoTransport {
    pub async fn send(&mut self, data: &str) -> Result<()> {
        match self {
            AoTransport::Tcp(t) => t.send(data).await,
            AoTransport::Ws(t) => t.send(data).await,
        }
    }

    pub async fn recv_packet(&mut self) -> Option<Result<Packet>> {
        match self {
            AoTransport::Tcp(t) => t.recv_packet().await,
            AoTransport::Ws(t) => t.recv_packet().await,
        }
    }

    /// Send a keepalive ping (WebSocket only; no-op for TCP).
    pub async fn keepalive_ping(&mut self) -> Result<()> {
        match self {
            AoTransport::Tcp(_) => Ok(()),
            AoTransport::Ws(t) => t.send_ping().await,
        }
    }

    /// Returns true if the transport has not received a pong within `timeout`
    /// (WebSocket only; TCP always returns false).
    pub fn is_stale(&self, timeout: std::time::Duration) -> bool {
        match self {
            AoTransport::Tcp(_) => false,
            AoTransport::Ws(t) => t.is_stale(timeout),
        }
    }
}

/// Shared entry point called once transport + real IP are resolved.
pub async fn handle_connection(
    transport: AoTransport,
    real_ip: IpAddr,
    state: Arc<ServerState>,
    mut shutdown: broadcast::Receiver<()>,
) {
    use crate::protocol::handlers::run_client;
    tokio::select! {
        _ = run_client(transport, real_ip, state) => {},
        _ = shutdown.recv() => {},
    }
}
