use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use log::{debug, error, info, warn};

use super::config::{
    MIN_RECONNECT, MiniTunConfig, TunConfig, ensure_parent_dir, load_config, resolve_endpoint,
};
use crate::{AgentHello, Intent, ServerMsg};

async fn read_server_msg(
    conn: &mut net::sock::LureConnection,
    buf: &mut Vec<u8>,
    read_buf: &mut Vec<u8>,
) -> anyhow::Result<ServerMsg> {
    loop {
        if let Some((msg, consumed)) = crate::decode_server_msg(buf)? {
            buf.drain(..consumed);
            return Ok(msg);
        }
        let (n, next) = conn.read_chunk(std::mem::take(read_buf)).await?;
        *read_buf = next;
        if n == 0 {
            anyhow::bail!("server closed connection");
        }
        buf.extend_from_slice(&read_buf[..n]);
    }
}

async fn send_agent_hello(
    conn: &mut net::sock::LureConnection,
    hello: AgentHello,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    crate::encode_agent_hello(&hello, &mut buf)?;
    conn.write_all(buf).await?;
    Ok(())
}

async fn send_health_beacon(ingress: SocketAddr, config: &TunConfig) -> anyhow::Result<()> {
    let mut beacon = crate::connect_agent(ingress).await?;
    tune_socket(&beacon);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let hmac = crate::compute_agent_hmac(
        &config.secret,
        &config.key_id,
        timestamp,
        Intent::Beacon,
        None,
        None,
        0,
        None,
    );

    send_agent_hello(
        &mut beacon,
        AgentHello {
            version: crate::VERSION,
            intent: Intent::Beacon,
            key_id: config.key_id,
            timestamp,
            hmac,
            session: None,
            forward: None,
        },
    )
    .await
}

fn spawn_health_beacon_probe(
    ingress: SocketAddr,
    config: TunConfig,
) -> tokio::sync::oneshot::Receiver<anyhow::Result<()>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    match net::sock::backend_kind() {
        net::sock::BackendKind::Tokio | net::sock::BackendKind::Epoll => {
            tokio::task::spawn_local(async move {
                let result = send_health_beacon(ingress, &config).await;
                let _ = tx.send(result);
            });
        }
        net::sock::BackendKind::Uring => {
            net::sock::uring::spawn(async move {
                let result = send_health_beacon(ingress, &config).await;
                let _ = tx.send(result);
            });
        }
    }
    rx
}

fn tune_socket(conn: &net::sock::LureConnection) {
    if std::env::var("NO_NODELAY").is_err()
        && let Err(err) = conn.set_nodelay(true)
    {
        debug!("failed to enable TCP_NODELAY: {err}");
    }
}

// =============================================================================
// Shared State
// =============================================================================

struct SharedState {
    config: Arc<tokio::sync::RwLock<MiniTunConfig>>,
    session_slots: Arc<tokio::sync::Semaphore>,
}

const MAX_CONCURRENT_TUNNEL_SESSIONS: usize = 1000;
const HEALTH_BEACON_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);
const HEALTH_BEACON_WARN_EVERY: u8 = 3;

// =============================================================================
// Session and Tunnel Handling
// =============================================================================

/// Build a minimal PROXY protocol v2 binary header with the given client address.
/// No TLV extensions — just the proxy address block.
fn build_proxy_protocol_v2_header(client_addr: SocketAddr) -> anyhow::Result<Vec<u8>> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    let (family, address) = match client_addr {
        SocketAddr::V4(addr) => (
            net::Family::Inet,
            net::AddressInfo::Ipv4(addr, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        ),
        SocketAddr::V6(addr) => (
            net::Family::Inet6,
            net::AddressInfo::Ipv6(addr, SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        ),
    };
    let header = net::Header {
        command: net::Command::Proxy,
        family,
        protocol: net::Protocol::Stream,
        address,
        tlvs: vec![],
    };
    header.serialize().context("PPv2 serialize failed")
}

async fn handle_session(
    shared: Arc<SharedState>,
    ingress: SocketAddr,
    config: TunConfig,
    session: [u8; 32],
    client_addr: Option<SocketAddr>, // v4: real client IP for PPv2
    target_override: Option<SocketAddr>, // v4: skip TargetAddr round-trip
) -> anyhow::Result<()> {
    let session_prefix = format!("{:02x}", session[0]);
    let _permit = match shared.session_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            warn!(
                "dropping session offer: session={session_prefix} active_session_limit={MAX_CONCURRENT_TUNNEL_SESSIONS}"
            );
            return Ok(());
        }
    };
    let connect_version = if target_override.is_some() {
        crate::VERSION
    } else {
        crate::V3_VERSION
    };
    info!(
        "session forwarded: key_id={} session={session_prefix} (connecting back to edge, wire_version={})",
        config.label, connect_version
    );
    let mut agent_conn = crate::connect_agent(ingress).await?;
    tune_socket(&agent_conn);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let hmac = crate::compute_agent_hmac(
        &config.secret,
        &config.key_id,
        timestamp,
        Intent::Connect,
        Some(&session),
        None,
        0,
        None,
    );

    send_agent_hello(
        &mut agent_conn,
        AgentHello {
            version: connect_version,
            intent: Intent::Connect,
            key_id: config.key_id,
            timestamp,
            hmac,
            session: Some(session),
            forward: None,
        },
    )
    .await?;

    let mut buf = Vec::new();
    let mut read_buf = vec![0u8; 1024];
    let target = if let Some(override_addr) = target_override {
        // v4: target was included in ForwardRequestV4; skip the TargetAddr round-trip
        override_addr
    } else {
        loop {
            match read_server_msg(&mut agent_conn, &mut buf, &mut read_buf).await? {
                ServerMsg::TargetAddr(addr) => break addr,
                _ => continue,
            }
        }
    };

    // Strict mode check
    {
        let cfg = shared.config.read().await;
        if cfg.strict {
            let target_str = target.to_string();
            let allowed = cfg.map.values().any(|v| v == &target_str);
            if !allowed {
                warn!(
                    "strict mode: rejected target {target} for key_id={} session={session_prefix}",
                    config.label
                );
                return Ok(());
            }
        }
    }

    info!(
        "tunnel target received: key_id={} session={session_prefix} target={target}",
        config.label
    );
    let mut target_conn = net::sock::LureConnection::connect(target).await?;
    tune_socket(&target_conn);
    debug!(
        "backend connected: session={session_prefix} local={:?} peer={:?}",
        target_conn.local_addr().ok(),
        target_conn.peer_addr().ok()
    );
    // v4 request includes client_addr only when Lure wants early PP authoring.
    if let Some(caddr) = client_addr {
        let pp = build_proxy_protocol_v2_header(caddr).context("failed to build PPv2 header")?;
        target_conn
            .write_all(pp)
            .await
            .context("failed to send PPv2 header to backend")?;
        debug!("PPv2 sent: session={session_prefix} client_addr={caddr}");
    }
    if !buf.is_empty() {
        debug!(
            "forwarding buffered tunneled bytes: session={session_prefix} bytes={}",
            buf.len()
        );
        target_conn.write_all(std::mem::take(&mut buf)).await?;
    }
    info!(
        "tunnel passthrough start: key_id={} session={session_prefix}",
        config.label
    );
    let handle = agent_conn.into_proxy(target_conn)?;
    handle.future.await?;
    info!(
        "tunnel passthrough end: key_id={} session={session_prefix}",
        config.label
    );
    Ok(())
}

async fn listen_once(
    ingress: SocketAddr,
    config: &TunConfig,
    shared: Arc<SharedState>,
) -> anyhow::Result<()> {
    let mut listener = crate::connect_agent(ingress).await?;
    tune_socket(&listener);
    debug!(
        "connected to proxy: local={:?} peer={:?}",
        listener.local_addr().ok(),
        listener.peer_addr().ok()
    );
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let hmac = crate::compute_agent_hmac(
        &config.secret,
        &config.key_id,
        timestamp,
        Intent::Listen,
        None,
        None,
        0,
        None,
    );

    send_agent_hello(
        &mut listener,
        AgentHello {
            version: crate::VERSION,
            intent: Intent::Listen,
            key_id: config.key_id,
            timestamp,
            hmac,
            session: None,
            forward: None,
        },
    )
    .await?;

    info!(
        "sent listen hello: key_id={} wire_version={}",
        config.label,
        crate::VERSION
    );

    let mut buf = Vec::new();
    let mut read_buf = vec![0u8; 1024];
    let mut beacon_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + HEALTH_BEACON_INTERVAL,
        HEALTH_BEACON_INTERVAL,
    );
    beacon_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut beacon_failures: u8 = 0;
    let mut beacon_probe: Option<tokio::sync::oneshot::Receiver<anyhow::Result<()>>> = None;
    loop {
        let msg = tokio::select! {
            maybe_beacon_result = async {
                if let Some(probe) = &mut beacon_probe {
                    Some(probe.await)
                } else {
                    None
                }
            }, if beacon_probe.is_some() => {
                match maybe_beacon_result {
                    Some(Ok(Ok(()))) => {
                        if beacon_failures > 0 {
                            info!(
                                "health beacon recovered: key_id={} endpoint={ingress}",
                                config.label
                            );
                        }
                        beacon_failures = 0;
                    }
                    Some(Ok(Err(err))) => {
                        beacon_failures = beacon_failures.saturating_add(1);
                        if beacon_failures == 1
                            || beacon_failures.is_multiple_of(HEALTH_BEACON_WARN_EVERY)
                        {
                            warn!(
                                "health beacon failed (non-fatal): key_id={} endpoint={ingress} failures={} err={err}",
                                config.label,
                                beacon_failures
                            );
                        }
                    }
                    Some(Err(_)) => {
                        beacon_failures = beacon_failures.saturating_add(1);
                        if beacon_failures == 1
                            || beacon_failures.is_multiple_of(HEALTH_BEACON_WARN_EVERY)
                        {
                            warn!(
                                "health beacon probe task dropped (non-fatal): key_id={} endpoint={ingress} failures={}",
                                config.label,
                                beacon_failures
                            );
                        }
                    }
                    None => {}
                }
                beacon_probe = None;
                continue;
            }
            msg = read_server_msg(&mut listener, &mut buf, &mut read_buf) => msg?,
            _ = beacon_interval.tick() => {
                if beacon_probe.is_none() {
                    beacon_probe = Some(spawn_health_beacon_probe(ingress, config.clone()));
                }
                continue;
            }
        };
        let (session, ingress, client_addr, target_override) = match msg {
            ServerMsg::ForwardRequest(forward) => {
                // v3: agent must wait for TargetAddr from server; no client IP
                (forward.session, forward.request.from, None, None)
            }
            ServerMsg::ForwardRequestV4(forward) => {
                // v4: target is known upfront; client_addr is present only when
                // Lure wants the tunnel to emit PROXY protocol.
                (
                    forward.session,
                    forward.request.from,
                    forward.client_addr,
                    Some(forward.request.to),
                )
            }
            _ => continue,
        };
        let session_prefix = format!("{:02x}", session[0]);
        info!(
            "session forwarded: session={session_prefix} ingress={ingress} client={client_addr:?}",
        );
        let config = TunConfig {
            key_id: config.key_id,
            secret: config.secret,
            label: config.label.clone(),
            endpoints: config.endpoints.clone(),
            proxy_protocol: config.proxy_protocol,
        };
        let shared = Arc::clone(&shared);
        match net::sock::backend_kind() {
            net::sock::BackendKind::Tokio | net::sock::BackendKind::Epoll => {
                tokio::task::spawn_local(async move {
                    if let Err(e) = handle_session(
                        shared,
                        ingress,
                        config,
                        session,
                        client_addr,
                        target_override,
                    )
                    .await
                    {
                        error!("minitun handle_session failed: {e}");
                    }
                });
            }
            net::sock::BackendKind::Uring => {
                net::sock::uring::spawn(async move {
                    if let Err(e) = handle_session(
                        shared,
                        ingress,
                        config,
                        session,
                        client_addr,
                        target_override,
                    )
                    .await
                    {
                        error!("minitun handle_session failed: {e}");
                    }
                });
            }
        }
    }
}

async fn run(config: TunConfig, shared: Arc<SharedState>) {
    let mut delay = std::time::Duration::from_millis(250);
    let mut endpoint_idx: usize = 0;

    loop {
        let max_delay = {
            let cfg = shared.config.read().await;
            cfg.reconnect.as_duration().max(MIN_RECONNECT)
        };

        let endpoints = &config.endpoints;
        if endpoints.is_empty() {
            error!("tunnel key_id={} has no endpoints; stopping", config.label);
            return;
        }
        let endpoint_str = &endpoints[endpoint_idx % endpoints.len()];

        let ingress = match resolve_endpoint(endpoint_str) {
            Ok(addr) => addr,
            Err(e) => {
                error!(
                    "cannot resolve endpoint {endpoint_str} for key_id={}: {e}; \
                     retrying in {delay:?}",
                    config.label
                );
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(max_delay, delay.saturating_mul(2));
                endpoint_idx = endpoint_idx.wrapping_add(1);
                continue;
            }
        };

        match listen_once(ingress, &config, Arc::clone(&shared)).await {
            Ok(()) => {
                delay = std::time::Duration::from_millis(250);
            }
            Err(e) => {
                error!(
                    "listener disconnected: key_id={} endpoint={endpoint_str} err={e}; \
                     reconnecting in {delay:?}",
                    config.label
                );
                tokio::time::sleep(delay).await;
                delay = std::cmp::min(max_delay, delay.saturating_mul(2));
                endpoint_idx = endpoint_idx.wrapping_add(1);
            }
        }
    }
}

fn spawn_tunnel_task(tc: TunConfig, shared: Arc<SharedState>) -> tokio::task::JoinHandle<()> {
    match net::sock::backend_kind() {
        net::sock::BackendKind::Tokio | net::sock::BackendKind::Epoll => {
            tokio::task::spawn_local(async move {
                run(tc, shared).await;
            })
        }
        net::sock::BackendKind::Uring => {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
            net::sock::uring::spawn(async move {
                let _ = run(tc, shared).await;
                let _ = tx.send(()).await;
            });
            // Return a join handle that waits on the channel.
            // This is a simplified solution; for production, use CancellationToken.
            tokio::task::spawn_local(async move {
                let _ = rx.recv().await;
            })
        }
    }
}

// =============================================================================
// PID File Management
// =============================================================================

fn write_pid_file(path: &Path) -> anyhow::Result<()> {
    ensure_parent_dir(path)?;
    let pid = std::process::id();
    std::fs::write(path, format!("{pid}\n"))?;
    Ok(())
}

struct PidFileGuard(PathBuf);

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// =============================================================================
// Orchestrator and Reload Logic
// =============================================================================

async fn apply_reload(
    task_map: &mut HashMap<[u8; 8], tokio::task::JoinHandle<()>>,
    active_configs: &mut HashMap<[u8; 8], TunConfig>,
    shared: &Arc<SharedState>,
    new_config: MiniTunConfig,
) {
    // Build new tunnel map by key_id.
    let mut new_entries: HashMap<[u8; 8], TunConfig> = HashMap::new();
    for entry in &new_config.tunnels {
        match TunConfig::from_entry(entry) {
            Ok(tc) => {
                new_entries.insert(tc.key_id, tc);
            }
            Err(e) => {
                error!("skipping invalid tunnel entry: {e}");
            }
        }
    }

    // Find and remove tunnels that are no longer in config.
    let removed: Vec<[u8; 8]> = task_map
        .keys()
        .filter(|k| !new_entries.contains_key(*k))
        .copied()
        .collect();
    for key_id in removed {
        info!("reload: removing tunnel key_id={}", hex::encode(key_id));
        if let Some(handle) = task_map.remove(&key_id) {
            handle.abort();
        }
        active_configs.remove(&key_id);
    }

    // Check for changed endpoints/token in existing tunnels.
    let to_restart: Vec<[u8; 8]> = active_configs
        .iter()
        .filter_map(|(key_id, old_config)| match new_entries.get(key_id) {
            Some(new_config) => {
                if old_config.endpoints != new_config.endpoints
                    || old_config.secret != new_config.secret
                {
                    Some(*key_id)
                } else {
                    None
                }
            }
            None => None,
        })
        .collect();

    for key_id in to_restart {
        info!(
            "reload: restarting tunnel key_id={} (config changed)",
            hex::encode(key_id)
        );
        if let Some(handle) = task_map.remove(&key_id) {
            handle.abort();
        }
        if let Some(new_tc) = new_entries.get(&key_id) {
            let handle = spawn_tunnel_task(new_tc.clone(), Arc::clone(shared));
            task_map.insert(key_id, handle);
            active_configs.insert(key_id, new_tc.clone());
        }
    }

    // Add new tunnels.
    for (key_id, tc) in &new_entries {
        if !task_map.contains_key(key_id) {
            info!("reload: adding tunnel key_id={}", hex::encode(key_id));
            let handle = spawn_tunnel_task(tc.clone(), Arc::clone(shared));
            task_map.insert(*key_id, handle);
            active_configs.insert(*key_id, tc.clone());
        }
    }

    // Update shared config for map/strict changes.
    {
        let mut cfg = shared.config.write().await;
        *cfg = new_config;
    }

    info!("reload complete: {} active tunnels", task_map.len());
}

pub(super) async fn run_orchestrator(
    initial_config: MiniTunConfig,
    config_path: PathBuf,
    pid_path: PathBuf,
) -> anyhow::Result<()> {
    // Write PID file.
    write_pid_file(&pid_path)?;
    let _pid_guard = PidFileGuard(pid_path.clone());

    let shared_config = Arc::new(tokio::sync::RwLock::new(initial_config.clone()));
    let session_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_TUNNEL_SESSIONS));
    let shared = Arc::new(SharedState {
        config: Arc::clone(&shared_config),
        session_slots,
    });

    let mut task_map: HashMap<[u8; 8], tokio::task::JoinHandle<()>> = HashMap::new();
    let mut active_configs: HashMap<[u8; 8], TunConfig> = HashMap::new();

    // Spawn initial tasks.
    for entry in &initial_config.tunnels {
        let tc = TunConfig::from_entry(entry).map_err(|e| anyhow::anyhow!("invalid token: {e}"))?;
        let key_id = tc.key_id;
        let handle = spawn_tunnel_task(tc.clone(), Arc::clone(&shared));
        task_map.insert(key_id, handle);
        active_configs.insert(key_id, tc);
    }

    info!(
        "minitun started: {} tunnels, config={}",
        initial_config.tunnels.len(),
        config_path.display()
    );

    // Set up SIGHUP handler.
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    loop {
        #[cfg(unix)]
        {
            sighup.recv().await;
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<()>().await;
        }

        info!(
            "SIGHUP received, reloading config from {}",
            config_path.display()
        );
        let new_config = match load_config(&config_path) {
            Ok(c) => c,
            Err(e) => {
                error!("config reload failed: {e}; keeping current config");
                continue;
            }
        };

        apply_reload(&mut task_map, &mut active_configs, &shared, new_config).await;
    }
}
