use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Instant};

use anyhow::Context;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use log::debug;
use subtle::ConstantTimeEq;
use tokio::{
    sync::{RwLock, mpsc, mpsc::UnboundedSender, oneshot},
    time::{Duration, timeout},
};

use crate::{
    config::TokenEntry,
    router::AuthMode,
    rpc::{EventEnvelope, EventServiceInstance},
    sock::LureConnection,
    utils::{logging::LureLogger, spawn_named},
};

mod registry;

/// Timeout duration for waiting for ForwardAck from master
const ACK_TIMEOUT: Duration = Duration::from_secs(10);
/// Agent is considered stale if no health beacon arrives within this window.
const AGENT_BEACON_STALE_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug)]
pub enum TunnelInspectMsg {
    Snapshot {
        req: u64,
        respond: oneshot::Sender<crate::telemetry::inspect::TunnelInspectSnapshot>,
    },
}

pub struct TunnelInspectHook {
    tx: UnboundedSender<TunnelInspectMsg>,
    is_master: bool,
    instance_id: String,
}

impl TunnelInspectHook {
    #[must_use]
    pub fn new(
        tx: UnboundedSender<TunnelInspectMsg>,
        is_master: bool,
        instance_id: String,
    ) -> Self {
        Self {
            tx,
            is_master,
            instance_id,
        }
    }
}

#[async_trait]
impl crate::rpc::event::EventHook<EventEnvelope, EventEnvelope> for TunnelInspectHook {
    async fn on_event(
        &self,
        service: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        if let EventEnvelope::ListTunnelRequest(req) = event {
            if !self.is_master {
                return Ok(());
            }
            let (tx, rx) = oneshot::channel();
            let _ = self.tx.send(TunnelInspectMsg::Snapshot {
                req: req.req,
                respond: tx,
            });

            if let Ok(snapshot) = rx.await {
                service
                    .produce_event(EventEnvelope::ListTunnelResponse(
                        crate::telemetry::inspect::ListTunnelResponse {
                            req: req.req,
                            inst: self.instance_id.clone(),
                            snapshot,
                        },
                    ))
                    .await?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum TunnelControlMsg {
    Flush,
    Upsert(TokenEntry),
}

pub struct TunnelControlHook {
    tx: UnboundedSender<TunnelControlMsg>,
}

impl TunnelControlHook {
    #[must_use]
    pub const fn new(tx: UnboundedSender<TunnelControlMsg>) -> Self {
        Self { tx }
    }
}

#[async_trait]
impl crate::rpc::event::EventHook<EventEnvelope, EventEnvelope> for TunnelControlHook {
    async fn on_event(
        &self,
        _: &EventServiceInstance,
        event: &'_ EventEnvelope,
    ) -> anyhow::Result<()> {
        match event {
            EventEnvelope::FlushTunnelTokens(_) => {
                log::info!("tunnel: flush token registry (control-plane)");
                let _ = self.tx.send(TunnelControlMsg::Flush);
            }
            EventEnvelope::SetTunnelToken(entry) => {
                log::info!(
                    "tunnel: upsert token (control-plane): key_id={} zone={:?} name={:?}",
                    entry.key_id,
                    entry.zone,
                    entry.name
                );
                let _ = self.tx.send(TunnelControlMsg::Upsert(entry.clone()));
            }
            _ => {}
        }
        Ok(())
    }
}

fn key_id_prefix(key_id: &[u8; 8]) -> String {
    format!("{:02x}", key_id[0])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TokenKeyId(pub [u8; 8]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionToken(pub [u8; 32]);

pub struct TokenInfo {
    /// Full 32-byte secret for HMAC
    pub secret: [u8; 32],
    /// Optional human-readable name
    pub name: Option<String>,
    /// Creation timestamp
    pub created_at: Instant,
    /// Last authentication timestamp
    pub last_used: RwLock<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelAgentMode {
    Master,
    Slave,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelAgentDispatch {
    LocalAgent,
    Master(SocketAddr),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MasterForwardTunnelRequest {
    pub tunnel_id: TokenKeyId,
    pub session: SessionToken,
    pub ttl: u8,
    pub tunnel_agent_request: tun::TunnelAgentRequest,
    pub client_addr: Option<SocketAddr>,
}

pub struct TunnelAgentController {
    registry: Arc<TunnelRegistry>,
}

pub struct AcceptedTunnelConnection {
    pub connection: LureConnection,
    pub agent_version: u8,
}

pub struct TunnelRegistry {
    /// Token registry by `key_id`
    tokens: RwLock<HashMap<TokenKeyId, Arc<TokenInfo>>>,
    /// Optional mapping from zone -> `key_id` (set when token entries include zone).
    zones: RwLock<HashMap<u64, TokenKeyId>>,
    /// Active agents by `key_id`
    agents: RwLock<HashMap<TokenKeyId, AgentRecord>>,
    /// Monotonic id for per-key agent generations.
    agent_gen: std::sync::atomic::AtomicU64,
    /// Pending sessions
    pending: RwLock<HashMap<SessionToken, PendingSession>>,
    /// Expired sessions counter
    expired_sessions: std::sync::atomic::AtomicU64,
    /// Cached endpoint list from bootstrap poller
    pub endpoint_cache: tokio::sync::RwLock<Vec<crate::config::EndpointInfo>>,
}

struct AgentRecord {
    id: u64,
    version: u8,
    peer_addr: SocketAddr,
    tx: mpsc::Sender<TunnelCommand>,
    task: tokio::task::JoinHandle<()>,
    connected_at: Instant,
    last_beacon_at: Instant,
    offers_sent: u64,
}

struct PendingSession {
    key_id: TokenKeyId,
    target: SocketAddr,
    respond: Option<oneshot::Sender<AcceptedTunnelConnection>>,
    created_at: Instant,
}

enum TunnelCommand {
    ForwardRequest {
        session: SessionToken,
        ttl: u8,
        request: tun::TunnelAgentRequest,
        client_addr: Option<SocketAddr>,
    },
}

impl Default for TunnelRegistry {
    fn default() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            zones: RwLock::new(HashMap::new()),
            agents: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            expired_sessions: std::sync::atomic::AtomicU64::new(0),
            agent_gen: std::sync::atomic::AtomicU64::new(1),
            endpoint_cache: tokio::sync::RwLock::new(Vec::new()),
        }
    }
}

impl TunnelAgentController {
    #[must_use]
    pub fn new(registry: Arc<TunnelRegistry>) -> Self {
        Self { registry }
    }

    pub async fn dispatch_router_request(
        &self,
        request: MasterForwardTunnelRequest,
        target: SocketAddr,
        auth_mode: &AuthMode,
        dispatch: TunnelAgentDispatch,
    ) -> anyhow::Result<oneshot::Receiver<AcceptedTunnelConnection>> {
        let tunnel_id = request.tunnel_id;
        let session = request.session;
        let receiver = self
            .registry
            .prepare_local_session(tunnel_id, session, target, auth_mode)
            .await?;

        let dispatch_result = match dispatch {
            TunnelAgentDispatch::LocalAgent => {
                self.registry
                    .forward_request_to_agent(
                        tunnel_id,
                        session,
                        request.tunnel_agent_request,
                        0,
                        request.client_addr,
                    )
                    .await
            }
            TunnelAgentDispatch::Master(master_addr) => {
                self.forward_request_to_master(
                    MasterForwardTunnelRequest {
                        ttl: request.ttl.max(1),
                        ..request
                    },
                    master_addr,
                )
                .await
            }
        };

        if let Err(err) = dispatch_result {
            self.registry
                .rollback_local_session(tunnel_id, session)
                .await;
            return Err(err);
        }

        Ok(receiver)
    }

    pub async fn dispatch_external_request(
        &self,
        request: MasterForwardTunnelRequest,
        timestamp: u64,
        hmac: [u8; 32],
        mode: TunnelAgentMode,
    ) -> anyhow::Result<()> {
        if mode == TunnelAgentMode::Slave {
            anyhow::bail!("slave mode must not accept forwarded tunnel requests");
        }
        if request.ttl == 0 {
            anyhow::bail!("forwarded tunnel request ttl exhausted");
        }

        self.registry
            .validate_hmac(
                &request.tunnel_id,
                timestamp,
                tun::Intent::Forward,
                Some(&request.session.0),
                Some(&request.tunnel_agent_request),
                request.ttl,
                request.client_addr.as_ref(),
                &hmac,
            )
            .await?;

        LureLogger::tunnel_forward_request_received(
            &key_id_prefix(&request.tunnel_id.0),
            &request.tunnel_agent_request.from,
            &request.tunnel_agent_request.to,
        );

        self.registry
            .forward_request_to_agent(
                request.tunnel_id,
                request.session,
                request.tunnel_agent_request,
                request.ttl.saturating_sub(1),
                request.client_addr,
            )
            .await
    }

    async fn forward_request_to_master(
        &self,
        request: MasterForwardTunnelRequest,
        master_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let secret = self
            .registry
            .secret_for_key(&request.tunnel_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("no tunnel secret loaded for key_id"))?;

        let mut connection = tun::connect_agent(master_addr).await?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let hmac = tun::compute_agent_hmac(
            &secret,
            &request.tunnel_id.0,
            timestamp,
            tun::Intent::Forward,
            Some(&request.session.0),
            Some(&request.tunnel_agent_request),
            request.ttl,
            request.client_addr.as_ref(),
        );

        let hello = tun::AgentHello {
            version: tun::VERSION,
            intent: tun::Intent::Forward,
            key_id: request.tunnel_id.0,
            timestamp,
            hmac,
            session: None,
            forward: Some(tun::ForwardHello {
                session: request.session.0,
                ttl: request.ttl,
                request: request.tunnel_agent_request,
                client_addr: request.client_addr,
            }),
        };
        let mut buf = Vec::new();
        tun::encode_agent_hello(&hello, &mut buf)?;
        connection.write_all(buf).await?;

        let mut buf = Vec::new();
        let mut read_buf = vec![0u8; 1024];
        let ack_result = timeout(ACK_TIMEOUT, async {
            loop {
                if let Some((msg, consumed)) = tun::decode_server_msg(&buf)? {
                    buf.drain(..consumed);
                    if let tun::ServerMsg::ForwardAck(session) = msg {
                        if session == request.session.0 {
                            return Ok::<(), anyhow::Error>(());
                        }
                        anyhow::bail!("master acknowledged unexpected session");
                    }
                }

                let (n, next) = connection.read_chunk(read_buf).await?;
                read_buf = next;
                if n == 0 {
                    anyhow::bail!("master closed forwarded request connection");
                }
                buf.extend_from_slice(&read_buf[..n]);
            }
        })
        .await;

        match ack_result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => anyhow::bail!("timed out waiting for master acknowledgment"),
        }
    }
}
