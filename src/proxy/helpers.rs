use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::OnceLock,
};

use net::mc::{HandshakeC2s, PacketDecode, PacketFrame, ProtoError};

use crate::{
    config::LureConfig,
    packet::OwnedHandshake,
    router::{Route, TunnelOpt},
    sock::BackendKind,
    tunnel::TokenKeyId,
};

pub(super) fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            None => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
        },
    }
}

pub(super) fn is_routable_forward_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_documentation()
                && !v4.is_multicast()
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => {
                !v4.is_unspecified()
                    && !v4.is_loopback()
                    && !v4.is_private()
                    && !v4.is_link_local()
                    && !v4.is_broadcast()
                    && !v4.is_documentation()
                    && !v4.is_multicast()
            }
            None => {
                !v6.is_unspecified()
                    && !v6.is_loopback()
                    && !v6.is_unique_local()
                    && !v6.is_unicast_link_local()
                    && !v6.is_multicast()
            }
        },
    }
}

pub(super) fn enforce_local_ip_block() -> bool {
    static ENFORCE: OnceLock<bool> = OnceLock::new();

    *ENFORCE.get_or_init(|| {
        std::env::var("MACH_ENFORCE_LOCAL_BLOCK")
            .ok()
            .as_deref()
            .map(|value| matches!(value, "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"))
            .unwrap_or(false)
    })
}

pub(super) fn normalize_optional_url(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn resolve_socket_addr(value: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let mut addrs = value.to_socket_addrs()?;
    addrs
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses resolved for {value}"))
}

pub(super) fn decode_handshake_frame(frame: &PacketFrame) -> anyhow::Result<HandshakeC2s<'_>> {
    if frame.id != HandshakeC2s::ID {
        return Err(anyhow::anyhow!(
            "unexpected packet id {} (expected {})",
            frame.id,
            HandshakeC2s::ID
        ));
    }
    let mut body = frame.body.as_slice();
    let pkt = HandshakeC2s::decode_body(&mut body)?;
    if !body.is_empty() {
        return Err(ProtoError::TrailingBytes(body.len()).into());
    }
    Ok(pkt)
}

pub(super) fn unsupported_tunnel_version(err: &anyhow::Error) -> Option<u8> {
    match err.downcast_ref::<tun::TunnelError>() {
        Some(tun::TunnelError::UnsupportedVersion(version)) => Some(*version),
        _ => None,
    }
}

pub(super) fn route_requests_tunnel(route: &Route, tunnel: TunnelOpt) -> bool {
    match tunnel {
        TunnelOpt::KeyId(_) => true,
        TunnelOpt::ZoneDefault => true,
        TunnelOpt::None => route.tunnel(),
    }
}

pub(super) fn should_pretend_tunnel_key(config: &LureConfig, key_id: TokenKeyId) -> bool {
    let pretended = pretend_tunnel_names();
    if pretended.is_empty() {
        return false;
    }

    let key_hex = hex::encode(key_id.0);
    if pretended.contains(&key_hex) {
        return true;
    }

    config.tunnel.token.iter().any(|token| {
        token.key_id.trim().eq_ignore_ascii_case(&key_hex)
            && token
                .name
                .as_deref()
                .is_some_and(|name| pretended.contains(&name.trim().to_ascii_lowercase()))
    })
}

fn pretend_tunnel_names() -> &'static HashSet<String> {
    static PRETENDED: OnceLock<HashSet<String>> = OnceLock::new();

    PRETENDED.get_or_init(|| {
        std::env::var("MACH_PROXY_PRETEND_TUNNELS")
            .unwrap_or_default()
            .split([',', '\n', '\r', '\t', ' '])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    })
}

pub(super) fn socket_backend_label(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Tokio => "tokio",
        BackendKind::Epoll => "epoll",
        BackendKind::Uring => "uring",
    }
}

pub(super) enum IngressHello {
    Minecraft {
        handshake: OwnedHandshake,
        buffered: Vec<u8>,
        raw: Vec<u8>,
    },
    Tunnel {
        hello: tun::AgentHello,
    },
}
