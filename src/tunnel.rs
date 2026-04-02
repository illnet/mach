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
    logging::LureLogger,
    router::AuthMode,
    sock::LureConnection,
    telemetry::{EventEnvelope, EventServiceInstance},
    utils::spawn_named,
};

/// Timeout duration for waiting for ForwardAck from master
const ACK_TIMEOUT: Duration = Duration::from_secs(10);

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
impl crate::telemetry::event::EventHook<EventEnvelope, EventEnvelope> for TunnelInspectHook {
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
impl crate::telemetry::event::EventHook<EventEnvelope, EventEnvelope> for TunnelControlHook {
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
            version: forward_wire_version(request.client_addr),
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

impl TunnelRegistry {
    /// Load tokens from configuration
    pub async fn load_tokens(&self, config: &crate::config::TunnelConfig) -> anyhow::Result<()> {
        let mut tokens = self.tokens.write().await;
        let mut zones = self.zones.write().await;
        tokens.clear();
        zones.clear();

        for entry in &config.token {
            let key_id = parse_key_id(&entry.key_id).context("parsing key_id")?;
            let secret = parse_secret(&entry.secret).context("parsing secret")?;

            let token_key = TokenKeyId(key_id);
            if let Some(zone) = entry.zone {
                zones.insert(zone, token_key);
            }

            tokens.insert(
                token_key,
                Arc::new(TokenInfo {
                    secret,
                    name: entry.name.clone(),
                    created_at: Instant::now(),
                    last_used: RwLock::new(Instant::now()),
                }),
            );
        }

        log::info!("tunnel: loaded {} tokens (settings.toml)", tokens.len());
        Ok(())
    }

    /// Clear only the token registry (and pending sessions).
    ///
    /// Agents are not disconnected/cleared here: agents register directly with Lure,
    /// and a control-plane resync should not kick them out. If a token is removed,
    /// offers will fail because the `key_id` is no longer present.
    pub async fn clear_runtime(&self) {
        {
            let mut tokens = self.tokens.write().await;
            tokens.clear();
        }
        {
            let mut zones = self.zones.write().await;
            zones.clear();
        }
        {
            let mut pending = self.pending.write().await;
            pending.clear();
        }
        log::info!("tunnel: cleared runtime token/zone/pending state");
    }

    pub async fn upsert_token(&self, entry: &TokenEntry) -> anyhow::Result<()> {
        let key_id = parse_key_id(&entry.key_id).context("parsing key_id")?;
        let secret = parse_secret(&entry.secret).context("parsing secret")?;

        let token_key = TokenKeyId(key_id);

        let mut tokens = self.tokens.write().await;
        let mut zones = self.zones.write().await;
        if let Some(zone) = entry.zone {
            zones.insert(zone, token_key);
        }
        tokens.insert(
            token_key,
            Arc::new(TokenInfo {
                secret,
                name: entry.name.clone(),
                created_at: Instant::now(),
                last_used: RwLock::new(Instant::now()),
            }),
        );
        log::info!(
            "tunnel: token upserted: key_id={} zone={:?} name={:?} (total={})",
            entry.key_id,
            entry.zone,
            entry.name,
            tokens.len()
        );
        Ok(())
    }

    pub async fn key_id_for_zone(&self, zone: u64) -> Option<TokenKeyId> {
        self.zones.read().await.get(&zone).copied()
    }

    pub async fn secret_for_key(&self, key_id: &TokenKeyId) -> Option<[u8; 32]> {
        self.tokens.read().await.get(key_id).map(|info| info.secret)
    }

    /// Validate HMAC authentication
    async fn validate_hmac(
        &self,
        key_id: &TokenKeyId,
        timestamp: u64,
        intent: tun::Intent,
        session: Option<&[u8; 32]>,
        request: Option<&tun::TunnelAgentRequest>,
        ttl: u8,
        client_addr: Option<&SocketAddr>,
        provided_hmac: &[u8; 32],
    ) -> anyhow::Result<Arc<TokenInfo>> {
        // Check timestamp is within a small window for replay protection.
        //
        // In practice, production boxes (or containers) can drift a bit; keep this tolerant enough
        // to avoid flapping when NTP isn't perfect.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if now.abs_diff(timestamp) > 60 {
            anyhow::bail!("timestamp out of range (replay protection failed)");
        }

        // Look up token
        let token_info = self
            .tokens
            .read()
            .await
            .get(key_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("invalid key_id"))?;

        // Compute expected HMAC
        let expected_hmac = tun::compute_agent_hmac(
            &token_info.secret,
            &key_id.0,
            timestamp,
            intent,
            session,
            request,
            ttl,
            client_addr,
        );

        // Constant-time comparison to prevent timing attacks
        let choice: subtle::Choice = provided_hmac.ct_eq(&expected_hmac);
        if !bool::from(choice) {
            anyhow::bail!("HMAC validation failed");
        }

        // Update last_used
        *token_info.last_used.write().await = Instant::now();
        Ok(token_info)
    }

    pub async fn register_listener(
        self: &Arc<Self>,
        key_id: TokenKeyId,
        timestamp: u64,
        hmac: [u8; 32],
        mut connection: LureConnection,
        agent_version: u8,
    ) -> anyhow::Result<()> {
        let peer_addr = *connection.addr();

        // Validate HMAC
        let _token_info = self
            .validate_hmac(
                &key_id,
                timestamp,
                tun::Intent::Listen,
                None,
                None,
                0,
                None,
                &hmac,
            )
            .await?;

        let (tx, mut rx) = mpsc::channel(8);
        let id = self
            .agent_gen
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        LureLogger::tunnel_agent_registered(&key_id_prefix(&key_id.0));

        // Spawn the task that will push offers to the agent. If a new agent registers with the
        // same key_id (restart), we abort the old task and replace it.
        let registry = Arc::clone(self);
        let task = spawn_named("tunnel-agent-listener", async move {
            while let Some(cmd) = rx.recv().await {
                let mut buf = Vec::new();
                match cmd {
                    TunnelCommand::ForwardRequest {
                        session,
                        ttl,
                        request,
                        client_addr,
                    } => {
                        if agent_version >= tun::VERSION && client_addr.is_some() {
                            // v4: include real client IP
                            tun::encode_server_msg(
                                &tun::ServerMsg::ForwardRequestV4(tun::ForwardRequestV4Msg {
                                    session: session.0,
                                    ttl,
                                    request,
                                    client_addr: client_addr.expect("checked above"),
                                }),
                                &mut buf,
                            );
                        } else {
                            // v3 / legacy: no client IP field
                            tun::encode_server_msg(
                                &tun::ServerMsg::ForwardRequest(tun::ForwardRequestMsg {
                                    session: session.0,
                                    ttl,
                                    request,
                                }),
                                &mut buf,
                            );
                        }
                    }
                }
                if connection.write_all(buf).await.is_err() {
                    break;
                }
            }
            let mut agents = registry.agents.write().await;
            if let Some(active) = agents.get(&key_id)
                && active.id == id
            {
                agents.remove(&key_id);
            }
            LureLogger::tunnel_agent_disconnected(&key_id_prefix(&key_id.0));
        })
        .context("failed to spawn tunnel listener task")?;

        // Replace any existing registration for this key_id (common on agent restart).
        let old = {
            let mut agents = self.agents.write().await;
            agents.insert(
                key_id,
                AgentRecord {
                    id,
                    version: agent_version,
                    peer_addr,
                    tx: tx.clone(),
                    task,
                    connected_at: Instant::now(),
                    offers_sent: 0,
                },
            )
        };

        if let Some(old) = old {
            LureLogger::tunnel_agent_replaced(
                &key_id_prefix(&key_id.0),
                &old.peer_addr,
                old.version,
                &peer_addr,
                agent_version,
            );
            old.task.abort();
        }

        Ok(())
    }

    pub async fn prepare_local_session(
        &self,
        key_id: TokenKeyId,
        session: SessionToken,
        target: SocketAddr,
        auth_mode: &AuthMode,
    ) -> anyhow::Result<oneshot::Receiver<AcceptedTunnelConnection>> {
        // If the key_id isn't currently registered, don't offer a session (prevents
        // offering to stale/removed tokens and avoids pending-session leaks).
        {
            let tokens = self.tokens.read().await;
            if !tokens.contains_key(&key_id) {
                anyhow::bail!("tunnel token not registered for key_id");
            }
        }

        // Check if this key_id is authorized for this route
        match auth_mode {
            AuthMode::Public => {
                // Public routes don't use tunnel auth
                anyhow::bail!("public routes require different handling");
            }
            AuthMode::Protected => {
                // Any valid token (already validated) can access
            }
            AuthMode::Restricted { allowed_tokens } => {
                // Only specific tokens allowed
                if !allowed_tokens.contains(&key_id.0) {
                    anyhow::bail!("key_id not authorized for this route (restricted auth_mode)");
                }
            }
        }

        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.write().await;
            pending.insert(
                session,
                PendingSession {
                    key_id,
                    target,
                    respond: Some(tx),
                    created_at: Instant::now(),
                },
            );
        }

        LureLogger::tunnel_session_offered(&key_id_prefix(&key_id.0), &target);
        Ok(rx)
    }

    pub async fn rollback_local_session(&self, key_id: TokenKeyId, session: SessionToken) {
        let mut pending = self.pending.write().await;
        if pending
            .get(&session)
            .is_some_and(|record| record.key_id == key_id)
        {
            pending.remove(&session);
        }
    }

    pub async fn forward_request_to_agent(
        &self,
        key_id: TokenKeyId,
        session: SessionToken,
        request: tun::TunnelAgentRequest,
        ttl: u8,
        client_addr: Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        {
            let tokens = self.tokens.read().await;
            if !tokens.contains_key(&key_id) {
                anyhow::bail!("tunnel token not registered for key_id");
            }
        }

        {
            let mut agents = self.agents.write().await;
            if let Some(agent) = agents.get_mut(&key_id) {
                agent.offers_sent = agent.offers_sent.saturating_add(1);
            }
        }

        let agent_tx = { self.agents.read().await.get(&key_id).map(|a| a.tx.clone()) };
        let Some(agent_tx) = agent_tx else {
            LureLogger::tunnel_agent_missing(
                &key_id_prefix(&key_id.0),
                &format!("{:02x}", session.0[0]),
            );
            anyhow::bail!("no active tunnel agent registered for key_id");
        };

        if agent_tx
            .send(TunnelCommand::ForwardRequest {
                session,
                ttl,
                request,
                client_addr,
            })
            .await
            .is_ok()
        {
            Ok(())
        } else {
            LureLogger::tunnel_agent_missing(
                &key_id_prefix(&key_id.0),
                &format!("{:02x}", session.0[0]),
            );
            anyhow::bail!("failed to notify tunnel agent")
        }
    }

    pub async fn accept_connect(
        &self,
        key_id: TokenKeyId,
        timestamp: u64,
        hmac: [u8; 32],
        session: SessionToken,
        mut connection: LureConnection,
        agent_version: u8,
    ) -> anyhow::Result<()> {
        // Validate HMAC with session
        self.validate_hmac(
            &key_id,
            timestamp,
            tun::Intent::Connect,
            Some(&session.0),
            None,
            0,
            None,
            &hmac,
        )
        .await?;

        let pending = {
            let mut pending = self.pending.write().await;
            pending.remove(&session)
        };
        let Some(pending) = pending else {
            LureLogger::tunnel_session_missing(&format!("{:02x}", session.0[0]));
            anyhow::bail!("no pending tunnel session");
        };

        // Validate that the provided key_id matches the one that created this session
        if pending.key_id != key_id {
            LureLogger::tunnel_token_mismatch(
                &key_id_prefix(&key_id.0),
                &format!("{:02x}", session.0[0]),
            );
            anyhow::bail!("key_id mismatch: unauthorized accept attempt");
        }

        let Some(respond) = pending.respond else {
            anyhow::bail!("session was recorded without a local responder");
        };

        LureLogger::tunnel_session_accepted(&key_id_prefix(&key_id.0), &pending.target);

        if agent_version < tun::VERSION {
            // v3 / legacy: send TargetAddr so agent knows where to connect
            let mut buf = Vec::new();
            tun::encode_server_msg(&tun::ServerMsg::TargetAddr(pending.target), &mut buf);
            connection
                .write_all(buf)
                .await
                .context("failed to send tunnel target")?;
        }
        // v4+: agent already has target from ForwardRequestV4.request.to; skip round-trip

        respond
            .send(AcceptedTunnelConnection {
                connection,
                agent_version,
            })
            .map_err(|_| anyhow::anyhow!("pending tunnel session closed"))?;

        let agents = self.agents.read().await;
        if !agents.contains_key(&key_id) {
            // Agent may not be registered anymore; best-effort only.
        }

        Ok(())
    }

    pub async fn inspect_snapshot(&self) -> crate::telemetry::inspect::TunnelInspectSnapshot {
        use crate::telemetry::inspect::{
            TunnelAgentInspect, TunnelInspectSnapshot, TunnelPendingInspect, TunnelTokenInspect,
        };

        let now = Instant::now();

        let tokens = self.tokens.read().await;
        let zones = self.zones.read().await;
        let agents = self.agents.read().await;
        let pending = self.pending.read().await;

        let mut token_out: Vec<TunnelTokenInspect> = Vec::with_capacity(tokens.len());
        for (key, info) in tokens.iter() {
            let key_id = format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                key.0[0], key.0[1], key.0[2], key.0[3], key.0[4], key.0[5], key.0[6], key.0[7]
            );
            let zone = zones
                .iter()
                .find_map(|(z, kid)| if kid == key { Some(*z) } else { None });

            let last_used = *info.last_used.read().await;
            token_out.push(TunnelTokenInspect {
                key_id,
                zone,
                name: info.name.clone(),
                created_ms_ago: u64::try_from(now.duration_since(info.created_at).as_millis())
                    .unwrap_or(u64::MAX),
                last_used_ms_ago: u64::try_from(now.duration_since(last_used).as_millis())
                    .unwrap_or(u64::MAX),
                has_agent: agents.contains_key(key),
            });
        }
        token_out.sort_by(|a, b| a.zone.cmp(&b.zone).then(a.key_id.cmp(&b.key_id)));

        let mut agent_out: Vec<TunnelAgentInspect> = Vec::with_capacity(agents.len());
        for (key, record) in agents.iter() {
            let key_id = format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                key.0[0], key.0[1], key.0[2], key.0[3], key.0[4], key.0[5], key.0[6], key.0[7]
            );
            agent_out.push(TunnelAgentInspect {
                key_id,
                connected_ms_ago: u64::try_from(
                    now.duration_since(record.connected_at).as_millis(),
                )
                .unwrap_or(u64::MAX),
                offers_sent: record.offers_sent,
            });
        }
        agent_out.sort_by(|a, b| a.key_id.cmp(&b.key_id));

        let mut pending_out: Vec<TunnelPendingInspect> = Vec::with_capacity(pending.len().min(50));
        for (_token, p) in pending.iter().take(50) {
            let key_id = format!(
                "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                p.key_id.0[0],
                p.key_id.0[1],
                p.key_id.0[2],
                p.key_id.0[3],
                p.key_id.0[4],
                p.key_id.0[5],
                p.key_id.0[6],
                p.key_id.0[7]
            );
            pending_out.push(TunnelPendingInspect {
                key_id,
                target: p.target.to_string(),
                age_ms: u64::try_from(now.duration_since(p.created_at).as_millis())
                    .unwrap_or(u64::MAX),
            });
        }
        pending_out.sort_by(|a, b| a.age_ms.cmp(&b.age_ms).reverse());

        TunnelInspectSnapshot {
            tokens_total: tokens.len() as u64,
            agents_total: agents.len() as u64,
            pending_total: pending.len() as u64,
            expired_total: self
                .expired_sessions
                .load(std::sync::atomic::Ordering::Relaxed),
            tokens: token_out,
            agents: agent_out,
            pending: pending_out,
        }
    }

    pub async fn start_bootstrap_poller(self: &Arc<Self>, bootstrap_url: String) {
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(client) => client,
            Err(e) => {
                log::error!("[tunnel-bootstrap] failed to build HTTP client: {e}");
                return;
            }
        };
        let url = format!("{}/api/open/endpoints", bootstrap_url.trim_end_matches('/'));
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<Vec<crate::config::EndpointInfo>>().await {
                        Ok(nodes) => {
                            let count = nodes.len();
                            *self.endpoint_cache.write().await = nodes;
                            log::info!(
                                "[tunnel-bootstrap] refreshed {} endpoints from {}",
                                count,
                                url
                            );
                        }
                        Err(e) => log::warn!("[tunnel-bootstrap] JSON parse error: {e}"),
                    }
                }
                Ok(resp) => {
                    log::warn!("[tunnel-bootstrap] HTTP {} from {}", resp.status(), url)
                }
                Err(e) => log::warn!("[tunnel-bootstrap] fetch failed: {e}"),
            }
        }
    }

    pub(crate) async fn cleanup_expired_sessions(&self) {
        const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

        let now = Instant::now();
        let expired: Vec<_> = {
            let pending = self.pending.read().await;
            pending
                .iter()
                .filter(|(_, session)| now.duration_since(session.created_at) > SESSION_TIMEOUT)
                .map(|(token, _)| *token)
                .collect()
        };

        let mut pending = self.pending.write().await;
        for token in expired {
            pending.remove(&token);
            self.expired_sessions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!("Tunnel session expired: {:?}", token.0[..8].to_vec());
        }
    }
}

fn parse_key_id(key_id_str: &str) -> anyhow::Result<[u8; 8]> {
    let trimmed = key_id_str.trim();
    if trimmed.len() != 16 {
        anyhow::bail!("key_id must be 16 hex characters, got {}", trimmed.len());
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("key_id must be hex-encoded");
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        let byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)?;
        out[i] = byte;
    }
    Ok(out)
}

fn parse_secret(secret_str: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = secret_str.trim();
    // Try hex first
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            let byte = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)?;
            out[i] = byte;
        }
        return Ok(out);
    }
    // Try base64
    let decoded = STANDARD.decode(trimmed)?;
    if decoded.len() != 32 {
        anyhow::bail!(
            "secret must be 64-char hex or valid base64 for 32 bytes, got {}",
            decoded.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

fn forward_wire_version(client_addr: Option<SocketAddr>) -> u8 {
    if client_addr.is_some() {
        tun::VERSION
    } else {
        tun::V3_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn zone_mapping_is_updated_on_upsert_and_cleared() {
        let registry = TunnelRegistry::default();
        let entry = TokenEntry {
            key_id: "0011223344556677".to_string(),
            secret: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            name: None,
            zone: Some(42),
        };

        registry.upsert_token(&entry).await.unwrap();

        let key = registry.key_id_for_zone(42).await.unwrap();
        assert_eq!(key.0, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);

        registry.clear_runtime().await;
        assert!(registry.key_id_for_zone(42).await.is_none());
    }

    #[tokio::test]
    async fn local_pending_session_is_recorded_in_snapshot() {
        let registry = TunnelRegistry::default();
        let entry = TokenEntry {
            key_id: "0011223344556677".to_string(),
            secret: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            name: Some("edge-a".to_string()),
            zone: None,
        };

        registry.upsert_token(&entry).await.unwrap();

        let key_id = TokenKeyId(parse_key_id(&entry.key_id).unwrap());
        let session = SessionToken([0xAA; 32]);
        let target: SocketAddr = "127.0.0.1:25565".parse().unwrap();

        let _receiver = registry
            .prepare_local_session(key_id, session, target, &crate::router::AuthMode::Protected)
            .await
            .unwrap();

        let snapshot = registry.inspect_snapshot().await;
        assert_eq!(snapshot.pending_total, 1);
        assert!(snapshot.pending[0].target.contains("127.0.0.1:25565"));
    }

    #[test]
    fn forward_wire_version_tracks_proxy_metadata_availability() {
        assert_eq!(forward_wire_version(None), tun::V3_VERSION);
        assert_eq!(
            forward_wire_version(Some("203.0.113.9:41234".parse().unwrap())),
            tun::VERSION
        );
    }
}
