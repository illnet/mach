use serde::{Deserialize, Serialize};

use crate::router::Profile;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Generic request envelope carrying correlation id.
pub struct InspectRequest {
    pub req: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Per-token tunnel registry inspection record.
pub struct TunnelTokenInspect {
    pub key_id: String,
    pub zone: Option<u64>,
    pub name: Option<String>,
    /// Age since token creation (best-effort, monotonic clock), in milliseconds.
    pub created_ms_ago: u64,
    /// Age since last successful use (best-effort, monotonic clock), in milliseconds.
    pub last_used_ms_ago: u64,
    /// Whether an agent is currently registered for this `key_id`.
    pub has_agent: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Per-agent tunnel inspection record.
pub struct TunnelAgentInspect {
    pub key_id: String,
    /// Age since this agent registered (best-effort, monotonic clock), in milliseconds.
    pub connected_ms_ago: u64,
    pub offers_sent: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Pending tunnel-forward session inspection record.
pub struct TunnelPendingInspect {
    pub key_id: String,
    pub target: String,
    pub age_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Full tunnel registry snapshot used by inspect API.
pub struct TunnelInspectSnapshot {
    pub tokens_total: u64,
    pub agents_total: u64,
    pub pending_total: u64,
    pub expired_total: u64,
    pub tokens: Vec<TunnelTokenInspect>,
    pub agents: Vec<TunnelAgentInspect>,
    pub pending: Vec<TunnelPendingInspect>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// RPC response wrapper for tunnel inspection.
pub struct ListTunnelResponse {
    pub req: u64,
    pub inst: String,
    pub snapshot: TunnelInspectSnapshot,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
/// Rolling traffic counters for inspect views.
pub struct TrafficCounters {
    pub c2s_bytes: u64,
    pub s2c_bytes: u64,
    pub c2s_chunks: u64,
    pub s2c_chunks: u64,
    pub c2s_bps: u64,
    pub s2c_bps: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
/// Arbitrary per-session metadata exposed to inspect API.
pub struct SessionAttributes {}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Session-level inspection view.
pub struct SessionInspect {
    pub id: u64,
    pub zone: u64,
    pub route_id: u64,
    pub client_addr: String,
    pub destination_addr: String,
    pub hostname: String,
    pub endpoint_host: String,
    #[serde(default)]
    pub tunnel: bool,
    pub created_at_ms: u64,
    pub last_activity_ms: u64,
    pub traffic: TrafficCounters,
    pub attributes: SessionAttributes,
    pub profile: Profile,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// RPC response wrapper for active session listing.
pub struct ListSessionsResponse {
    pub req: u64,
    pub inst: String,
    pub _v: Vec<SessionInspect>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Instance-level traffic and capacity stats.
pub struct InstanceStats {
    pub inst: String,
    pub uptime_ms: u64,
    pub routes_active: u64,
    pub sessions_active: u64,
    pub traffic: TrafficCounters,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Route-level aggregated stats.
pub struct RouteStats {
    pub id: u64,
    pub zone: u64,
    pub active_sessions: u64,
    pub traffic: TrafficCounters,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Tenant/zone-level aggregated stats.
pub struct TenantStats {
    pub zone: u64,
    pub active_sessions: u64,
    pub traffic: TrafficCounters,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Hot session stats projection.
pub struct SessionStats {
    pub id: u64,
    pub zone: u64,
    pub route_id: u64,
    pub last_activity_ms: u64,
    pub traffic: TrafficCounters,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// RPC response wrapper for full stats snapshot.
pub struct ListStatsResponse {
    pub req: u64,
    pub instance: InstanceStats,
    pub tenants: Vec<TenantStats>,
    pub routes: Vec<RouteStats>,
    pub sessions: Vec<SessionStats>,
}
