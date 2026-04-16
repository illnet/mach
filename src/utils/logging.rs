use std::{
    error::Error as StdError,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Error;
use log::{debug, error, info, warn};

use crate::error::ReportableError;

/// Centralized structured logging helpers for proxy runtime.
pub struct LureLogger;

fn sentry_origin_label(tunnel: bool) -> &'static str {
    if tunnel { "tunnel_client" } else { "proxy" }
}

fn sentry_io_error_text(err: &std::io::Error) -> String {
    let text = err.to_string();
    if text.trim().is_empty() {
        format!("{:?}", err.kind())
    } else {
        text
    }
}

fn format_std_error_chain(err: &(dyn StdError + 'static)) -> String {
    let mut rendered = err.to_string();
    let mut sources = Vec::new();
    let mut current = err.source();
    while let Some(source) = current {
        let text = source.to_string();
        if !text.is_empty() && sources.last() != Some(&text) && text != rendered {
            sources.push(text);
        }
        current = source.source();
    }

    if !sources.is_empty() {
        rendered.push_str(" | causes: ");
        rendered.push_str(&sources.join(" -> "));
    }

    rendered
}

fn format_anyhow_chain(err: &Error) -> String {
    let mut chain = err.chain();
    let mut rendered = chain
        .next()
        .map(ToString::to_string)
        .unwrap_or_else(|| err.to_string());
    let mut sources = Vec::new();
    for source in chain {
        let text = source.to_string();
        if !text.is_empty() && sources.last() != Some(&text) && text != rendered {
            sources.push(text);
        }
    }
    if !sources.is_empty() {
        rendered.push_str(" | causes: ");
        rendered.push_str(&sources.join(" -> "));
    }
    rendered
}

impl LureLogger {
    // ============================================================================
    // Standard Info/Debug (Ignored by Sentry hook, safe for PII)
    // ============================================================================

    pub fn preparing_socket(address: &str) {
        info!("Preparing socket {address}");
    }

    pub fn rate_limited(ip: &IpAddr) {
        debug!("Rate-limited {ip}");
    }

    pub fn new_connection(address: &SocketAddr) {
        info!("New connection {address}");
    }

    pub fn handshake_completed(elapsed_ms: u64, next_state: &str) {
        debug!("Handshake completed in {elapsed_ms}ms, next state: {next_state}");
    }

    pub fn session_creation_timeout(addr: &SocketAddr, hostname: &str) {
        debug!("Session creation timed out for {addr} (host '{hostname}')");
    }

    // ============================================================================
    // Split Logging: Info/Debug (PII) + Warn/Error (Sentry-safe)
    // ============================================================================

    pub fn tcp_nodelay_failed(err: &std::io::Error) {
        error!("Failed to set TCP_NODELAY: {err}");
    }

    pub fn connection_closed(addr: &SocketAddr, err: &Error) {
        // Keeping in debug as it's a standard flow, but sanitized just in case
        // you ever bump connection closures to warn level.
        debug!("Connection {addr} closed: {}", format_anyhow_chain(err));
    }

    pub fn passthrough_unexpected_termination(
        _session_id: u64,
        client: &SocketAddr,
        backend: &SocketAddr,
        tunnel: bool,
        err: &std::io::Error,
    ) {
        // 1. Stdout PII
        info!("Passthrough termination context: client={client} backend={backend}");

        // 2. Sentry sanitized
        sentry::with_scope(
            |scope| {
                scope.set_tag("event", "passthrough_unexpected_termination");
                scope.set_tag("error_origin", sentry_origin_label(tunnel));
                scope.set_tag("io_error_kind", format!("{:?}", err.kind()));
            },
            || {
                warn!(
                    "Passthrough terminated abnormal err={}",
                    sentry_io_error_text(err)
                );
            },
        );
    }

    pub fn session_replaced(client: &SocketAddr, _old_session_id: u64, _new_session_id: u64) {
        info!("Session replaced context: client={client}");
    }

    pub(crate) fn connection_error(
        client: &SocketAddr,
        server: Option<&SocketAddr>,
        err: &ReportableError,
    ) {
        if dotenvy::var("DO_NOT_LOG_CONNECTION_ERROR").is_ok() {
            return;
        }
        let server_str = server.map(|s| format!(" -> {s}")).unwrap_or_default();

        info!("Connection error context: {client}{server_str}");
        error!("Connection error: {}", format_std_error_chain(err));
    }

    pub fn disconnect_warning(addr: &SocketAddr, reason: &str) {
        info!("Disconnecting client context: {addr}");
        warn!("Disconnecting client: {reason}");
    }

    pub fn disconnect_failure(addr: &SocketAddr, err: &Error) {
        info!("Disconnect failure context: {addr}");
        warn!("Failed to send disconnect: {}", format_anyhow_chain(err));
    }

    pub fn session_creation_failed(addr: &SocketAddr, hostname: &str, err: &Error) {
        info!("Session creation failed context: addr={addr} host='{hostname}'");
        warn!("Failed to create session: {}", format_anyhow_chain(err));
    }

    pub fn parser_failure(addr: &SocketAddr, stage: &str, err: &Error) {
        info!("Parser failure context: client={addr}");
        warn!("Parser failed during {stage}: {}", format_anyhow_chain(err));
    }

    pub fn tunnel_protocol_rejected(addr: &SocketAddr, version: u8, current: u8) {
        info!("Protocol rejected context: client={addr}");
        sentry::with_scope(
            |scope| {
                scope.set_tag("event", "tunnel_protocol_rejected");
                scope.set_tag("error_origin", "tunnel_client");
                scope.set_tag("tunnel_version", version.to_string());
                scope.set_tag("tunnel_current_version", current.to_string());
            },
            || {
                warn!(
                    "Rejected tunnel protocol version {version}; current supported version is {current}"
                );
            },
        );
    }

    pub fn tunnel_legacy_protocol(
        addr: &SocketAddr,
        version: u8,
        current: u8,
        intent: tun::Intent,
    ) {
        info!("Legacy protocol context: client={addr}");
        sentry::with_scope(
            |scope| {
                scope.set_tag("event", "tunnel_protocol_legacy");
                scope.set_tag("error_origin", "tunnel_client");
                scope.set_tag("tunnel_version", version.to_string());
                scope.set_tag("tunnel_current_version", current.to_string());
                scope.set_tag("tunnel_intent", format!("{intent:?}"));
            },
            || {
                warn!(
                    "Accepted legacy tunnel protocol version {version}; current version is {current} (intent={intent:?})"
                );
            },
        );
    }

    pub fn backend_failure(
        client: Option<&SocketAddr>,
        backend: SocketAddr,
        stage: &str,
        err: &Error,
    ) {
        let client_str = client
            .map(|c| format!("client={c} -> "))
            .unwrap_or_default();
        info!("Backend failure context: {client_str}backend={backend}");
        error!("Backend {stage} failed: {}", format_anyhow_chain(err));
    }

    pub fn deadline_missed(
        stage: &str,
        duration: Duration,
        client: Option<&SocketAddr>,
        target: Option<&str>,
    ) {
        let mut context = String::new();
        if let Some(addr) = client {
            context.push_str(&format!(" client={addr}"));
        }
        if let Some(t) = target {
            context.push_str(&format!(" target={t}"));
        }

        if !context.is_empty() {
            info!("Deadline exceeded context:{context}");
        }
        warn!("Deadline exceeded while {stage} (limit {duration:?})");
    }

    // ============================================================================
    // Tunnel-specific logging
    // ============================================================================

    pub fn tunnel_agent_registered(token_prefix: &str) {
        info!("Tunnel agent registered: token={token_prefix}");
    }

    pub fn tunnel_agent_replaced(
        token_prefix: &str,
        old_addr: &SocketAddr,
        old_version: u8,
        new_addr: &SocketAddr,
        new_version: u8,
    ) {
        info!(
            "Tunnel agent replaced context: token={token_prefix} old_peer={old_addr} new_peer={new_addr} old_v={old_version} new_v={new_version}"
        );
    }

    pub fn tunnel_agent_disconnected(token_prefix: &str) {
        debug!("Tunnel agent disconnected: token={token_prefix}");
    }

    pub fn tunnel_session_offered(token_prefix: &str, target: &SocketAddr) {
        debug!("Tunnel session offered: token={token_prefix} target={target}");
    }

    pub fn tunnel_session_accepted(token_prefix: &str, target: &SocketAddr) {
        debug!("Tunnel session accepted: token={token_prefix} target={target}");
    }

    pub fn tunnel_forward_request_received(
        token_prefix: &str,
        from: &SocketAddr,
        target: &SocketAddr,
    ) {
        debug!("Tunnel forward request received: token={token_prefix} from={from} target={target}");
    }

    pub fn tunnel_session_timeout(session_prefix: &str) {
        debug!("Tunnel session expired: session={session_prefix}");
    }

    pub fn tunnel_session_missing(session_prefix: &str) {
        info!("Tunnel session missing context: session={session_prefix}");
        warn!("Tunnel session not found");
    }

    pub fn tunnel_agent_missing(token_prefix: &str, session_prefix: &str) {
        info!("Tunnel agent missing context: token={token_prefix} session={session_prefix}");
        warn!("Tunnel agent not found");
    }

    pub fn tunnel_token_mismatch(agent_token_prefix: &str, session_token_prefix: &str) {
        info!(
            "Tunnel token mismatch context: agent={agent_token_prefix} session={session_token_prefix}"
        );
        warn!("Tunnel token mismatch (unauthorized accept attempt)");
    }

    pub fn tunnel_ingress_error(stage: &str, err: &Error) {
        warn!(
            "Tunnel ingress error during {stage}: {}",
            format_anyhow_chain(err)
        );
    }

    pub(crate) fn tunnel_session_error(
        stage: &str,
        target: &SocketAddr,
        backend: Option<&str>,
        err: &ReportableError,
    ) {
        let backend_str = backend
            .map(|backend| format!(" backend={backend}"))
            .unwrap_or_default();

        info!("Tunnel session error context: target={target}{backend_str}");
        error!(
            "Tunnel error on stage {stage}: {}",
            format_std_error_chain(err)
        );
    }
}
