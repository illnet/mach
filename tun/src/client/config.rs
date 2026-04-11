use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Human-readable duration: "1s", "500ms", "2m". Default: 1s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HumanDuration(pub std::time::Duration);

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

pub(super) const MIN_RECONNECT: std::time::Duration = std::time::Duration::from_secs(1);

pub(super) fn parse_human_duration(s: &str) -> anyhow::Result<std::time::Duration> {
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
        if ms.is_multiple_of(1000) {
            s.serialize_str(&format!("{}s", ms / 1000))
        } else {
            s.serialize_str(&format!("{ms}ms"))
        }
    }
}

/// One [[tunnel]] entry in the TOML config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct TunnelEntry {
    pub endpoints: Vec<String>,
    pub token: String,
    #[serde(default)]
    pub proxy_protocol: bool,
}

/// Root config struct. All fields have sane defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub(super) struct MiniTunConfig {
    pub strict: bool,
    pub reconnect: HumanDuration,
    #[serde(rename = "tunnel")]
    pub tunnels: Vec<TunnelEntry>,
    pub map: HashMap<String, String>,
}

/// Internal struct derived from TunnelEntry after hex-parsing.
#[derive(Clone)]
pub(super) struct TunConfig {
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

pub(super) fn parse_hex_exact<const N: usize>(input: &str) -> Result<[u8; N], String> {
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
    pub(super) fn from_entry(entry: &TunnelEntry) -> Result<Self, String> {
        if entry.endpoints.is_empty() {
            return Err("tunnel must contain at least one endpoint".to_string());
        }

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

pub(super) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

pub(super) fn xdg_config_home() -> Option<PathBuf> {
    if let Some(v) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(v));
    }
    home_dir().map(|h| h.join(".config"))
}

pub(super) fn xdg_runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from)
}

pub(super) fn ensure_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

pub(super) fn ensure_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    Ok(())
}

pub(super) fn copy_self_to(target: &Path) -> anyhow::Result<()> {
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

pub(super) fn find_config_path() -> Option<PathBuf> {
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

pub(super) fn default_config_path() -> anyhow::Result<PathBuf> {
    if let Some(h) = xdg_config_home() {
        return Ok(h.join("minitun.toml"));
    }
    Ok(PathBuf::from("/etc/minitun.toml"))
}

pub(super) fn pid_file_path() -> anyhow::Result<PathBuf> {
    if let Some(runtime) = xdg_runtime_dir() {
        return Ok(runtime.join("minitun.pid"));
    }

    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        if uid > 0 {
            let runtime_uid = PathBuf::from(format!("/run/user/{uid}/minitun.pid"));
            return Ok(runtime_uid);
        }
    }

    if let Some(home) = home_dir() {
        return Ok(home.join(".cache").join("minitun.pid"));
    }

    Ok(PathBuf::from("/tmp/minitun.pid"))
}

// =============================================================================
// Config I/O
// =============================================================================

pub(super) fn load_config(path: &Path) -> anyhow::Result<MiniTunConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config: {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parsing config: {}", path.display()))
}

pub(super) fn save_config(path: &Path, config: &MiniTunConfig) -> anyhow::Result<()> {
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

pub(super) fn load_or_default_config(path: &Path) -> anyhow::Result<MiniTunConfig> {
    if path.exists() {
        load_config(path)
    } else {
        Ok(MiniTunConfig::default())
    }
}

/// Check for legacy env-var-based configuration (MINITUN_ENDPOINT, MINITUN_TOKEN,
/// MINITUN_TOKENS) and, if found, build a MiniTunConfig from them.
/// Returns Ok(None) if none of those env vars are set.
pub(super) fn try_migrate_from_env() -> anyhow::Result<Option<MiniTunConfig>> {
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

pub(super) fn parse_endpoints(raw: &str) -> Vec<String> {
    raw.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) async fn resolve_endpoint(endpoint: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let endpoint = endpoint.to_string();
    let endpoint_for_lookup = endpoint.clone();
    let mut addrs = tokio::task::spawn_blocking(move || endpoint_for_lookup.to_socket_addrs())
        .await
        .context("endpoint DNS resolution task failed")??;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses found for endpoint: {endpoint}"))
}
