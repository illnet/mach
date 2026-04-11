use super::*;

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
    pub(super) async fn validate_hmac(
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
                        if agent_version >= tun::VERSION {
                            // v4+: keep the target inline and encode a sentinel client address
                            // when no proxy metadata is being forwarded.
                            tun::encode_server_msg(
                                &tun::ServerMsg::ForwardRequestV4(tun::ForwardRequestV4Msg {
                                    session: session.0,
                                    ttl,
                                    request,
                                    client_addr,
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
                    last_beacon_at: Instant::now(),
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

    pub async fn record_beacon(
        &self,
        key_id: TokenKeyId,
        timestamp: u64,
        hmac: [u8; 32],
    ) -> anyhow::Result<()> {
        self.validate_hmac(
            &key_id,
            timestamp,
            tun::Intent::Beacon,
            None,
            None,
            0,
            None,
            &hmac,
        )
        .await?;

        let now = Instant::now();
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(&key_id) {
            agent.last_beacon_at = now;
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

    pub(crate) async fn cleanup_stale_agents(&self) {
        let now = Instant::now();
        let mut stale_tasks = Vec::new();
        {
            let mut agents = self.agents.write().await;
            let stale_keys: Vec<TokenKeyId> = agents
                .iter()
                .filter_map(|(key_id, record)| {
                    // Legacy listeners (pre-v4) do not emit beacons; keep prior behavior.
                    if record.version < tun::VERSION {
                        return None;
                    }
                    (now.duration_since(record.last_beacon_at) > AGENT_BEACON_STALE_TIMEOUT)
                        .then_some(*key_id)
                })
                .collect();
            for key_id in stale_keys {
                if let Some(agent) = agents.remove(&key_id) {
                    stale_tasks.push((key_id, agent.task));
                }
            }
        }

        if stale_tasks.is_empty() {
            return;
        }

        for (key_id, task) in stale_tasks {
            task.abort();
            log::warn!(
                "tunnel: agent evicted as stale (no beacon): key_id_prefix={}",
                key_id_prefix(&key_id.0)
            );
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
    fn tunnel_v4_forward_request_keeps_optional_proxy_metadata() {
        let mut buf = Vec::new();
        tun::encode_server_msg(
            &tun::ServerMsg::ForwardRequestV4(tun::ForwardRequestV4Msg {
                session: [0xAB; 32],
                ttl: 1,
                request: tun::TunnelAgentRequest {
                    from: "10.0.0.1:25565".parse().unwrap(),
                    to: "10.0.0.2:25566".parse().unwrap(),
                },
                client_addr: None,
            }),
            &mut buf,
        );

        let (decoded, consumed) = tun::decode_server_msg(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        match decoded {
            tun::ServerMsg::ForwardRequestV4(msg) => {
                assert_eq!(msg.request.to, "10.0.0.2:25566".parse().unwrap());
                assert_eq!(msg.client_addr, None);
            }
            other => panic!("unexpected server msg: {other:?}"),
        }
    }
}
