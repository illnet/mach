use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use tun::{AgentHello, Intent, ServerMsg};

// =============================================================================
// CLI Structures
// =============================================================================

#[derive(Parser)]
#[command(name = "minitun")]
#[command(about = "Lure mini tunnel agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the tunnel agent using ~/.config/minitun.toml
    Run,
    /// Install binary and manage config (user: ~/.local/bin, system: /usr/local/bin)
    Install(InstallArgs),
    /// Send SIGHUP to the running minitun process to reload config
    Reload,
    /// Self-update from GitHub releases
    Update,
    /// Manage systemd service unit
    Systemd(SystemdArgs),
    /// Manage config file
    Config(ConfigArgs),
    /// Compute a valid HMAC signature for a hello message (development helper)
    Sign(SignArgs),
}

#[derive(Args)]
struct InstallArgs {
    /// Authentication token (format: key_id:secret, both hex-encoded).
    /// Repeat to add multiple tunnel entries.
    #[arg(long = "token", action = clap::ArgAction::Append)]
    tokens: Vec<String>,

    /// Endpoints for tunnel entries (space or comma separated, repeatable).
    /// If single --endpoints, it applies to all --tokens.
    #[arg(long = "endpoints", action = clap::ArgAction::Append)]
    endpoints: Vec<String>,

    /// Add/update a map entry key (must be paired with --map-addr).
    #[arg(long = "map-name")]
    map_name: Option<String>,

    /// Map entry local address (paired with --map-name).
    #[arg(long = "map-addr")]
    map_addr: Option<String>,

    /// Enable strict mode in config.
    #[arg(long)]
    strict: bool,

    /// Set reconnect backoff duration (e.g. "1s", "500ms", "2m").
    #[arg(long)]
    reconnect: Option<String>,

    /// Install system-wide: binary → /usr/local/bin/minitun, config → /etc/minitun.toml.
    #[arg(long)]
    system: bool,
}

#[derive(Args)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Print the current config file.
    Show,
    /// Add a tunnel entry.
    AddTunnel(AddTunnelArgs),
    /// Remove a tunnel entry by index or key_id prefix.
    RemoveTunnel { index_or_key: String },
    /// Add a map entry.
    AddMap { name: String, addr: String },
    /// Remove a map entry.
    RemoveMap { name: String },
}

#[derive(Args)]
struct AddTunnelArgs {
    /// Endpoints for the tunnel (space or comma separated, repeatable).
    #[arg(long = "endpoints", action = clap::ArgAction::Append)]
    endpoints: Vec<String>,
    /// Token in format key_id:secret (both hex-encoded).
    #[arg(long)]
    token: String,
}

#[derive(Args)]
struct SystemdArgs {
    #[command(subcommand)]
    command: SystemdCommand,
}

#[derive(Subcommand)]
enum SystemdCommand {
    /// Generate a systemd unit file template for the current config.
    Gensys {
        /// Install as a per-user service.
        #[arg(long)]
        user: bool,
        /// Install as a system-wide service (default).
        #[arg(long)]
        system: bool,
        /// Service name (default: minitun).
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Args)]
struct SignArgs {
    /// Token (format: key_id:secret, both hex-encoded)
    #[arg(short, long, env = "MINITUN_TOKEN")]
    token: String,

    /// Intent to sign for
    #[arg(long, value_parser = ["listen", "connect"])]
    intent: String,

    /// Unix timestamp (seconds). If omitted, uses current time.
    #[arg(long)]
    timestamp: Option<u64>,

    /// Session token for connect intent (64 hex chars, 32 bytes)
    #[arg(long)]
    session: Option<String>,
}

// =============================================================================
// Config Structs and Serialization
// =============================================================================

/// Human-readable duration: "1s", "500ms", "2m". Default: 1s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HumanDuration(pub std::time::Duration);

impl HumanDuration {
    pub fn as_duration(self) -> std::time::Duration {
        self.0
    }
}

impl Default for HumanDuration {
    fn default() -> Self {
        Self(std::time::Duration::from_secs(5))
    }
}

const MIN_RECONNECT: std::time::Duration = std::time::Duration::from_secs(1);

fn parse_human_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let s = s.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        let n: u64 = ms.trim().parse().context("invalid ms value")?;
        return Ok(std::time::Duration::from_millis(n));
    }
    if let Some(secs) = s.strip_suffix('s') {
        let n: u64 = secs.trim().parse().context("invalid s value")?;
        return Ok(std::time::Duration::from_secs(n));
    }
    if let Some(mins) = s.strip_suffix('m') {
        let n: u64 = mins.trim().parse().context("invalid m value")?;
        return Ok(std::time::Duration::from_secs(n * 60));
    }
    // Fallback: bare integer treated as seconds
    let n: u64 = s.parse().context("invalid duration")?;
    Ok(std::time::Duration::from_secs(n))
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_human_duration(&s)
            .map(Self)
            .map_err(|e| serde::de::Error::custom(format!("{e}")))
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let ms = self.0.as_millis();
        if ms % 1000 == 0 {
            s.serialize_str(&format!("{}s", ms / 1000))
        } else {
            s.serialize_str(&format!("{ms}ms"))
        }
    }
}

/// One [[tunnel]] entry in the TOML config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEntry {
    pub endpoints: Vec<String>,
    pub token: String,
    #[serde(default)]
    pub proxy_protocol: bool,
}

/// Root config struct. All fields have sane defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MiniTunConfig {
    pub strict: bool,
    pub reconnect: HumanDuration,
    #[serde(rename = "tunnel")]
    pub tunnels: Vec<TunnelEntry>,
    pub map: HashMap<String, String>,
}

/// Internal struct derived from TunnelEntry after hex-parsing.
#[derive(Clone)]
pub struct TunConfig {
    pub key_id: [u8; 8],
    pub secret: [u8; 32],
    pub label: String,          // hex::encode(key_id)
    pub endpoints: Vec<String>, // raw endpoint strings for round-robin
    pub proxy_protocol: bool,
}

impl std::fmt::Debug for TunConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunConfig")
            .field("label", &self.label)
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

fn parse_hex_exact<const N: usize>(input: &str) -> Result<[u8; N], String> {
    let trimmed = input.trim();
    let want_len = N * 2;
    if trimmed.len() != want_len {
        return Err(format!(
            "expected {want_len} hex characters, got {}",
            trimmed.len()
        ));
    }
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("value must be hex-encoded".to_string());
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let byte =
            u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16).map_err(|err| err.to_string())?;
        out[i] = byte;
    }
    Ok(out)
}

impl TunConfig {
    fn from_entry(entry: &TunnelEntry) -> Result<Self, String> {
        let parts: Vec<&str> = entry.token.split(':').collect();
        if parts.len() != 2 {
            return Err("token format: key_id:secret (both hex-encoded)".to_string());
        }

        let key_id = parse_hex_exact::<8>(parts[0])?;
        let secret = parse_hex_exact::<32>(parts[1])?;

        Ok(Self {
            key_id,
            secret,
            label: hex::encode(key_id),
            endpoints: entry.endpoints.clone(),
            proxy_protocol: entry.proxy_protocol,
        })
    }
}

// =============================================================================
// Path Helpers
// =============================================================================

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn xdg_config_home() -> Option<PathBuf> {
    if let Some(v) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(v));
    }
    home_dir().map(|h| h.join(".config"))
}

fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    Ok(())
}

fn copy_self_to(target: &Path) -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    ensure_parent_dir(target)?;
    std::fs::copy(&exe, target)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn find_config_path() -> Option<PathBuf> {
    if let Some(cfg_home) = xdg_config_home() {
        let p = cfg_home.join("minitun.toml");
        if p.exists() {
            return Some(p);
        }
    }
    let etc = PathBuf::from("/etc/minitun.toml");
    if etc.exists() {
        return Some(etc);
    }
    let local = PathBuf::from("minitun.toml");
    if local.exists() {
        return Some(local);
    }
    None
}

fn default_config_path() -> anyhow::Result<PathBuf> {
    if let Some(h) = xdg_config_home() {
        return Ok(h.join("minitun.toml"));
    }
    Ok(PathBuf::from("/etc/minitun.toml"))
}

fn pid_file_path() -> anyhow::Result<PathBuf> {
    if let Some(h) = xdg_config_home() {
        return Ok(h.join("minitun.pid"));
    }
    Ok(PathBuf::from("/run/minitun.pid"))
}

// =============================================================================
// Config I/O
// =============================================================================

fn load_config(path: &Path) -> anyhow::Result<MiniTunConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config: {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing config: {}", path.display()))
}

fn save_config(path: &Path, config: &MiniTunConfig) -> anyhow::Result<()> {
    let serialized = toml::to_string_pretty(config)?;
    // Validate the round-trip: re-parse what we just serialized.
    let _: MiniTunConfig =
        toml::from_str(&serialized).context("config round-trip validation failed")?;
    ensure_parent_dir(path)?;
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, &serialized)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn load_or_default_config(path: &Path) -> MiniTunConfig {
    if path.exists() {
        load_config(path).unwrap_or_else(|e| {
            error!("failed to load config: {e}; starting fresh");
            MiniTunConfig::default()
        })
    } else {
        MiniTunConfig::default()
    }
}

/// Check for legacy env-var-based configuration (MINITUN_ENDPOINT, MINITUN_TOKEN,
/// MINITUN_TOKENS) and, if found, build a MiniTunConfig from them.
/// Returns Ok(None) if none of those env vars are set.
fn try_migrate_from_env() -> anyhow::Result<Option<MiniTunConfig>> {
    let endpoint_raw = std::env::var("MINITUN_ENDPOINT").unwrap_or_default();
    let endpoints = parse_endpoints(&endpoint_raw);

    let mut tokens: Vec<String> = Vec::new();

    // Single token shorthand
    if let Ok(t) = std::env::var("MINITUN_TOKEN") {
        let t = t.trim().to_owned();
        if !t.is_empty() {
            tokens.push(t);
        }
    }

    // Multi-token list (comma or newline separated)
    if let Ok(ts) = std::env::var("MINITUN_TOKENS") {
        for t in ts.split([',', '\n']) {
            let t = t.trim().to_owned();
            if !t.is_empty() && !tokens.contains(&t) {
                tokens.push(t);
            }
        }
    }

    if tokens.is_empty() {
        return Ok(None);
    }

    let mut tunnel_entries: Vec<TunnelEntry> = Vec::new();
    for tok in &tokens {
        let entry = TunnelEntry {
            endpoints: endpoints.clone(),
            token: tok.clone(),
            proxy_protocol: false,
        };
        // Validate the token is parseable before writing a config
        TunConfig::from_entry(&entry)
            .map_err(|e| anyhow::anyhow!("env var token is invalid ({tok}): {e}"))?;
        tunnel_entries.push(entry);
    }

    Ok(Some(MiniTunConfig {
        tunnels: tunnel_entries,
        ..Default::default()
    }))
}

// =============================================================================
// Utilities
// =============================================================================

fn parse_endpoints(raw: &str) -> Vec<String> {
    raw.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn resolve_endpoint(endpoint: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = endpoint.to_socket_addrs()?;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses found for endpoint: {endpoint}"))
}

// =============================================================================
// Async Protocol Functions
// =============================================================================

async fn read_server_msg(
    conn: &mut net::sock::LureConnection,
    buf: &mut Vec<u8>,
    read_buf: &mut Vec<u8>,
) -> anyhow::Result<ServerMsg> {
    loop {
        if let Some((msg, consumed)) = tun::decode_server_msg(buf)? {
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
    tun::encode_agent_hello(&hello, &mut buf)?;
    conn.write_all(buf).await?;
    Ok(())
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
    info!(
        "session forwarded: key_id={} session={session_prefix} (connecting back to edge, wire_version={})",
        config.label,
        tun::VERSION
    );
    let mut agent_conn = tun::connect_agent(ingress).await?;
    tune_socket(&agent_conn);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let hmac = tun::compute_agent_hmac(
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
            version: tun::VERSION,
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
    let mut listener = tun::connect_agent(ingress).await?;
    tune_socket(&listener);
    debug!(
        "connected to proxy: local={:?} peer={:?}",
        listener.local_addr().ok(),
        listener.peer_addr().ok()
    );
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let hmac = tun::compute_agent_hmac(
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
            version: tun::VERSION,
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
        tun::VERSION
    );

    let mut buf = Vec::new();
    let mut read_buf = vec![0u8; 1024];
    loop {
        let msg = read_server_msg(&mut listener, &mut buf, &mut read_buf).await?;
        let (session, ingress, client_addr, target_override) = match msg {
            ServerMsg::ForwardRequest(forward) => {
                // v3: agent must wait for TargetAddr from server; no client IP
                (forward.session, forward.request.from, None, None)
            }
            ServerMsg::ForwardRequestV4(forward) => {
                // v4: target is known upfront, real client IP included
                (
                    forward.session,
                    forward.request.from,
                    Some(forward.client_addr),
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

async fn run_orchestrator(
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

// =============================================================================
// Commands
// =============================================================================

fn run_install(args: InstallArgs) -> anyhow::Result<()> {
    // Copy binary to ~/.local/bin/minitun (user) or /usr/local/bin/minitun (system)
    let bin_dest = if args.system {
        PathBuf::from("/usr/local/bin/minitun")
    } else {
        home_dir()
            .ok_or_else(|| anyhow::anyhow!("HOME not set"))?
            .join(".local")
            .join("bin")
            .join("minitun")
    };
    if let Err(err) = copy_self_to(&bin_dest) {
        error!("failed to install binary: {err}");
    }

    let path = default_config_path()?;
    let mut config = load_or_default_config(&path);

    // Parse endpoints
    let all_endpoints: Vec<String> = args
        .endpoints
        .iter()
        .flat_map(|e| parse_endpoints(e))
        .collect();

    // Merge tokens
    if !args.tokens.is_empty() {
        let mut parsed_tokens = Vec::new();
        for token_str in &args.tokens {
            TunConfig::from_entry(&TunnelEntry {
                endpoints: all_endpoints.clone(),
                token: token_str.clone(),
                proxy_protocol: false,
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            parsed_tokens.push((token_str.clone(), all_endpoints.clone()));
        }

        for (token, endpoints) in parsed_tokens {
            // Find and update existing, or append
            let parts: Vec<&str> = token.split(':').collect();
            if parts.len() == 2 {
                if let Ok(key_id) = parse_hex_exact::<8>(parts[0]) {
                    let mut found = false;
                    for entry in &mut config.tunnels {
                        if let Ok(tc) = TunConfig::from_entry(entry) {
                            if tc.key_id == key_id {
                                entry.endpoints = endpoints.clone();
                                found = true;
                                break;
                            }
                        }
                    }
                    if !found {
                        config.tunnels.push(TunnelEntry {
                            endpoints: endpoints.clone(),
                            token: token.clone(),
                            proxy_protocol: false,
                        });
                    }
                }
            }
        }
    }

    // Merge map entries
    if let (Some(name), Some(addr)) = (&args.map_name, &args.map_addr) {
        config.map.insert(name.clone(), addr.clone());
    }

    // Set strict mode if flag given
    if args.strict {
        config.strict = true;
    }

    // Set reconnect if given
    if let Some(dur_str) = &args.reconnect {
        config.reconnect =
            HumanDuration(parse_human_duration(dur_str).context("invalid reconnect duration")?);
    }

    save_config(&path, &config)?;
    info!("config saved to: {}", path.display());

    Ok(())
}

fn run_reload() -> anyhow::Result<()> {
    let pid_path = pid_file_path()?;
    let raw = std::fs::read_to_string(&pid_path)
        .with_context(|| format!("could not read PID file: {}", pid_path.display()))?;
    let pid: u32 = raw
        .trim()
        .parse()
        .context("PID file contains invalid number")?;
    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGHUP) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("failed to send SIGHUP to pid {pid}: {err}");
        }
        info!("sent SIGHUP to minitun pid={pid}");
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("reload is not supported on this platform");
    }
    Ok(())
}

fn run_update() -> anyhow::Result<()> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        "windows" => "windows",
        other => anyhow::bail!("unsupported OS for auto-update: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => anyhow::bail!("unsupported arch for auto-update: {other}"),
    };

    let url =
        format!("https://github.com/hUwUtao/Lure/releases/latest/download/minitun-{os}-{arch}");
    info!("downloading update from {url}");

    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("minitun/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let response = client.get(&url).send()?;
    if !response.status().is_success() {
        anyhow::bail!("update download failed: HTTP {}", response.status());
    }
    let bytes = response.bytes()?;

    let current_exe = std::env::current_exe()?;
    let tmp_path = current_exe.with_extension("update.tmp");
    std::fs::write(&tmp_path, &bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
    }

    std::fs::rename(&tmp_path, &current_exe)
        .context("failed to replace current exe with updated binary")?;

    info!("minitun updated successfully; restart to use new version");
    Ok(())
}

fn run_config(args: ConfigArgs) -> anyhow::Result<()> {
    match args.command {
        ConfigCommand::Show => {
            let path = find_config_path().ok_or_else(|| anyhow::anyhow!("no config file found"))?;
            let cfg = load_config(&path)?;
            println!("{}", toml::to_string_pretty(&cfg)?);
        }
        ConfigCommand::AddTunnel(a) => {
            let path = default_config_path()?;
            let mut cfg = load_or_default_config(&path);
            let endpoints = a
                .endpoints
                .iter()
                .flat_map(|e| parse_endpoints(e))
                .collect::<Vec<_>>();
            // Validate token before inserting.
            TunConfig::from_entry(&TunnelEntry {
                endpoints: endpoints.clone(),
                token: a.token.clone(),
                proxy_protocol: false,
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            cfg.tunnels.push(TunnelEntry {
                endpoints,
                token: a.token,
                proxy_protocol: false,
            });
            save_config(&path, &cfg)?;
            info!("tunnel added; {} total", cfg.tunnels.len());
        }
        ConfigCommand::RemoveTunnel { index_or_key } => {
            let path = default_config_path()?;
            let mut cfg = load_or_default_config(&path);
            if let Ok(idx) = index_or_key.parse::<usize>() {
                if idx >= cfg.tunnels.len() {
                    anyhow::bail!("index {idx} out of range (have {})", cfg.tunnels.len());
                }
                cfg.tunnels.remove(idx);
            } else {
                let before = cfg.tunnels.len();
                cfg.tunnels.retain(|e| {
                    e.token
                        .split(':')
                        .next()
                        .map(|k| !k.starts_with(&index_or_key))
                        .unwrap_or(true)
                });
                let removed = before - cfg.tunnels.len();
                if removed == 0 {
                    anyhow::bail!("no tunnel matched key_id prefix: {index_or_key}");
                }
            }
            save_config(&path, &cfg)?;
        }
        ConfigCommand::AddMap { name, addr } => {
            let path = default_config_path()?;
            let mut cfg = load_or_default_config(&path);
            cfg.map.insert(name, addr);
            save_config(&path, &cfg)?;
        }
        ConfigCommand::RemoveMap { name } => {
            let path = default_config_path()?;
            let mut cfg = load_or_default_config(&path);
            if cfg.map.remove(&name).is_none() {
                anyhow::bail!("map entry '{name}' not found");
            }
            save_config(&path, &cfg)?;
        }
    }
    Ok(())
}

fn run_systemd_gensys(user: bool, system: bool, name: Option<String>) -> anyhow::Result<()> {
    let scope_user = user && !system;
    if system && user {
        anyhow::bail!("choose one: --user or --system");
    }

    let normalized_service = name
        .as_deref()
        .map(|n| {
            let basename = n
                .trim()
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("minitun")
                .trim();
            let normalized = basename.strip_suffix(".service").unwrap_or(basename);
            if normalized.is_empty() {
                "minitun".to_string()
            } else {
                normalized.to_string()
            }
        })
        .unwrap_or_else(|| "minitun".to_string());

    let unit_dir = if scope_user {
        let cfg_home = xdg_config_home()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve config dir (HOME required)"))?;
        cfg_home.join("systemd").join("user")
    } else {
        PathBuf::from("/etc/systemd/system")
    };

    let exe = std::env::current_exe()?;
    let config_path = default_config_path()?;
    let service_file = if normalized_service.ends_with(".service") {
        normalized_service.clone()
    } else {
        format!("{normalized_service}.service")
    };

    let working_dir = if scope_user { "~" } else { "/etc" };

    // Generate unit file content.
    let unit_content = format!(
        r#"[Unit]
Description=Minitun tunnel agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} run
WorkingDirectory={working_dir}
Restart=always
RestartSec=2

[Install]
WantedBy={wanted_by}
"#,
        exe = exe.display(),
        working_dir = working_dir,
        wanted_by = if scope_user {
            "default.target"
        } else {
            "multi-user.target"
        },
    );

    let unit_path = unit_dir.join(&service_file);

    println!("# Generated systemd unit file for: {}", normalized_service);
    println!("# Install location:");
    println!("#   User:   {}", unit_path.display());
    println!("#   System: /etc/systemd/system/{}", service_file);
    println!();
    println!("# Config file location: {}", config_path.display());
    println!();
    println!("{}", unit_content);
    println!();
    println!("# To install:");
    println!("# 1. Copy the above unit file to the appropriate location");
    println!(
        "# 2. Run: systemctl{} daemon-reload",
        if scope_user { " --user" } else { "" }
    );
    println!(
        "# 3. Run: systemctl{} enable --now {}",
        if scope_user { " --user" } else { "" },
        service_file
    );

    Ok(())
}

fn run_sign(args: SignArgs) -> anyhow::Result<()> {
    let intent = match args.intent.as_str() {
        "listen" => Intent::Listen,
        "connect" => Intent::Connect,
        other => anyhow::bail!("invalid intent {other}"),
    };

    let parts: Vec<&str> = args.token.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("token format: key_id:secret (both hex-encoded)");
    }
    let key_id = parse_hex_exact::<8>(parts[0]).map_err(|e| anyhow::anyhow!("{e}"))?;
    let secret = parse_hex_exact::<32>(parts[1]).map_err(|e| anyhow::anyhow!("{e}"))?;

    let timestamp = args.timestamp.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs()
    });

    let session = match intent {
        Intent::Listen => None,
        Intent::Connect => {
            let s = args
                .session
                .ok_or_else(|| anyhow::anyhow!("--session is required for connect intent"))?;
            Some(parse_hex_exact::<32>(&s).map_err(|e| anyhow::anyhow!("{e}"))?)
        }
        Intent::Forward => anyhow::bail!("forward intent is not supported by `sign`"),
    };

    let hmac = tun::compute_agent_hmac(
        &secret,
        &key_id,
        timestamp,
        intent,
        session.as_ref(),
        None,
        0,
        None,
    );

    println!("version={}", tun::VERSION);
    println!("intent={}", args.intent);
    println!("key_id={}", hex::encode(key_id));
    println!("timestamp={timestamp}");
    if let Some(s) = session {
        println!("session={}", hex::encode(s));
    }
    println!("hmac={}", hex::encode(hmac));

    Ok(())
}

// =============================================================================
// Main Entry Point
// =============================================================================

const SENTRY_DSN: &str =
    "https://d8cb23f37184d406d4b129c0dc0b24d4@o1192891.ingest.us.sentry.io/4511109122293760";

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let sentry = init_sentry("minitun");

    if let Err(err) = try_main() {
        sentry::capture_message(&err.to_string(), sentry::Level::Error);
        error!("{err}");
        drop(sentry);
        std::process::exit(1);
    }
}

fn try_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    sentry::configure_scope(|scope| {
        scope.set_tag("command", command_name(&cli.command));
    });

    match cli.command {
        Command::Run => {
            let (path, config) = if let Some(path) = find_config_path() {
                let config = load_config(&path)?;
                (path, config)
            } else if let Some(migrated) = try_migrate_from_env()? {
                let path = default_config_path()?;
                warn!(
                    "[migration] no config file found; auto-migrating from env vars \
                     (MINITUN_ENDPOINT / MINITUN_TOKEN / MINITUN_TOKENS) \
                     to {}",
                    path.display()
                );
                save_config(&path, &migrated)?;
                info!(
                    "[migration] config written to {}. \
                     Future starts use this file automatically. \
                     To install as a service: `minitun systemd gensys`",
                    path.display()
                );
                (path, migrated)
            } else {
                anyhow::bail!(
                    "no config file found; run `minitun install --token <t> --endpoints <e>` first, \
                     or set MINITUN_ENDPOINT and MINITUN_TOKEN env vars"
                )
            };
            if config.tunnels.is_empty() {
                anyhow::bail!("config has no [[tunnel]] entries");
            }
            let pid_path = pid_file_path()?;

            let backend = net::sock::backend_kind();
            sentry::configure_scope(|scope| {
                scope.set_tag("socket_backend", backend_kind_name(backend));
            });

            match backend {
                net::sock::BackendKind::Tokio | net::sock::BackendKind::Epoll => {
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()?;
                    let local = tokio::task::LocalSet::new();
                    rt.block_on(local.run_until(run_orchestrator(config, path, pid_path)))?;
                }
                net::sock::BackendKind::Uring => {
                    net::sock::uring::start(async move {
                        run_orchestrator(config, path, pid_path).await
                    })?;
                }
            }
        }
        Command::Install(args) => {
            run_install(args)?;
        }
        Command::Reload => {
            run_reload()?;
        }
        Command::Update => {
            run_update()?;
        }
        Command::Systemd(args) => match args.command {
            SystemdCommand::Gensys { user, system, name } => {
                run_systemd_gensys(user, system, name)?;
            }
        },
        Command::Config(args) => {
            run_config(args)?;
        }
        Command::Sign(args) => {
            run_sign(args)?;
        }
    }

    Ok(())
}

fn init_sentry(service: &'static str) -> Option<sentry::ClientInitGuard> {
    if std::env::var_os("NOSENTRY").is_some() {
        return None;
    }

    let guard = sentry::init((
        SENTRY_DSN,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            send_default_pii: false,
            server_name: None,
            ..Default::default()
        },
    ));
    sentry::configure_scope(|scope| {
        scope.set_tag("service", service);
        scope.set_tag("binary", "minitun");
    });
    Some(guard)
}

fn backend_kind_name(kind: net::sock::BackendKind) -> &'static str {
    match kind {
        net::sock::BackendKind::Tokio => "tokio",
        net::sock::BackendKind::Epoll => "epoll",
        net::sock::BackendKind::Uring => "uring",
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Run => "run",
        Command::Install(_) => "install",
        Command::Reload => "reload",
        Command::Update => "update",
        Command::Systemd(_) => "systemd",
        Command::Config(_) => "config",
        Command::Sign(_) => "sign",
    }
}
