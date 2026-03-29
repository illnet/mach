use std::{
    error::Error as StdError,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Error;
use log::{debug, error, info, warn};

use crate::error::ReportableError;

pub struct LureLogger;

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
    pub fn preparing_socket(address: &str) {
        info!("Preparing socket {address}");
    }

    pub fn rate_limited(ip: &IpAddr) {
        debug!("Rate-limited {ip}");
    }

    pub fn tcp_nodelay_failed(err: &std::io::Error) {
        error!("Failed to set TCP_NODELAY: {err}");
    }

    pub fn new_connection(address: &SocketAddr) {
        info!("New connection {address}");
    }

    pub fn handshake_completed(elapsed_ms: u64, next_state: &str) {
        debug!("Handshake completed in {elapsed_ms}ms, next state: {next_state}");
    }

    pub fn connection_closed(addr: &SocketAddr, err: &Error) {
        debug!("Connection {addr} closed: {}", format_anyhow_chain(err));
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
        error!(
            "connection error@{client}{server_str}: {}",
            format_std_error_chain(err)
        );
    }

    pub fn disconnect_warning(addr: &SocketAddr, reason: &str) {
        warn!("Disconnecting client {addr}: {reason}");
    }

    pub fn disconnect_failure(addr: &SocketAddr, err: &Error) {
        debug!(
            "Failed to send disconnect to {addr}: {}",
            format_anyhow_chain(err)
        );
    }

    pub fn session_creation_failed(addr: &SocketAddr, hostname: &str, err: &Error) {
        debug!(
            "Failed to create session for {addr} (host '{hostname}'): {}",
            format_anyhow_chain(err)
        );
    }

    pub fn session_creation_timeout(addr: &SocketAddr, hostname: &str) {
        debug!("Session creation timed out for {addr} (host '{hostname}')");
    }

    pub fn parser_failure(addr: &SocketAddr, stage: &str, err: &Error) {
        warn!(
            "Parser failed during {stage} for client {addr}: {}",
            format_anyhow_chain(err)
        );
    }

    pub fn tunnel_protocol_rejected(addr: &SocketAddr, version: u8, current: u8) {
        warn!(
            "Rejected tunnel protocol version {version} from {addr}; current supported version is {current}"
        );
        sentry::with_scope(
            |scope| {
                scope.set_tag("event", "tunnel_protocol_rejected");
                scope.set_tag("peer_addr", addr.to_string());
                scope.set_tag("tunnel_version", version.to_string());
                scope.set_tag("tunnel_current_version", current.to_string());
            },
            || {
                sentry::capture_message(
                    &format!(
                        "Rejected tunnel protocol version {version} from {addr}; current version {current}"
                    ),
                    sentry::Level::Warning,
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
        warn!(
            "Accepted legacy tunnel protocol version {version} from {addr}; current version is {current} (intent={intent:?})"
        );
        sentry::with_scope(
            |scope| {
                scope.set_tag("event", "tunnel_protocol_legacy");
                scope.set_tag("peer_addr", addr.to_string());
                scope.set_tag("tunnel_version", version.to_string());
                scope.set_tag("tunnel_current_version", current.to_string());
                scope.set_tag("tunnel_intent", format!("{intent:?}"));
            },
            || {
                sentry::capture_message(
                    &format!(
                        "Accepted legacy tunnel protocol version {version} from {addr} (current {current}, intent {intent:?})"
                    ),
                    sentry::Level::Warning,
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
        match client {
            Some(addr) => error!(
                "Backend {stage} failed for client {addr} -> {backend}: {}",
                format_anyhow_chain(err)
            ),
            None => error!(
                "Backend {stage} failed for {backend}: {}",
                format_anyhow_chain(err)
            ),
        }
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
        warn!("Deadline exceeded while {stage} (limit {duration:?}){context}");
    }

    // ============================================================================
    // Tunnel-specific logging
    // ============================================================================

    pub fn tunnel_agent_registered(token_prefix: &str) {
        info!("Tunnel agent registered: token={token_prefix}");
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
        debug!(
            "Tunnel forward request received: token={token_prefix} \
             from={from} target={target}"
        );
    }

    pub fn tunnel_session_timeout(session_prefix: &str) {
        debug!("Tunnel session expired: session={session_prefix}");
    }

    pub fn tunnel_session_missing(session_prefix: &str) {
        warn!("Tunnel session not found: session={session_prefix}");
    }

    pub fn tunnel_agent_missing(token_prefix: &str, session_prefix: &str) {
        warn!("Tunnel agent not found: token={token_prefix} session={session_prefix}");
    }

    pub fn tunnel_token_mismatch(agent_token_prefix: &str, session_token_prefix: &str) {
        warn!(
            "Tunnel token mismatch (unauthorized accept attempt): agent={agent_token_prefix} session={session_token_prefix}"
        );
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
        let backend = backend
            .map(|backend| format!(" backend={backend}"))
            .unwrap_or_default();
        error!(
            "Tunnel session error during {stage} (target {target}{backend}): {}",
            format_std_error_chain(err)
        );
    }
}
