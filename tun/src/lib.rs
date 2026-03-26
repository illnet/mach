use std::net::{IpAddr, SocketAddr};

pub use net::sock;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("buffer too short")]
    ShortBuffer,
    #[error("invalid magic")]
    InvalidMagic,
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid intent {0}")]
    InvalidIntent(u8),
    #[error("invalid edge id")]
    InvalidEdgeId,
    #[error("invalid message kind {0}")]
    InvalidMsgKind(u8),
    #[error("invalid address family {0}")]
    InvalidAddrFamily(u8),
}

pub const MAGIC: [u8; 4] = *b"LTUN";
pub const VERSION: u8 = 3;
const MAX_SOCKET_ADDR_PAYLOAD_LEN: usize = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Intent {
    Listen = 1,
    Connect = 2,
    Forward = 3,
}

impl Intent {
    const fn from_u8(value: u8) -> Result<Self, TunnelError> {
        match value {
            1 => Ok(Self::Listen),
            2 => Ok(Self::Connect),
            3 => Ok(Self::Forward),
            other => Err(TunnelError::InvalidIntent(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelAgentRequest {
    pub from: SocketAddr,
    pub to: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHello {
    pub version: u8,
    pub intent: Intent,
    pub key_id: [u8; 8],
    pub timestamp: u64,
    pub hmac: [u8; 32],
    pub session: Option<[u8; 32]>,
    pub forward: Option<ForwardHello>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardHello {
    pub session: [u8; 32],
    pub ttl: u8,
    pub request: TunnelAgentRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardRequestMsg {
    pub session: [u8; 32],
    pub ttl: u8,
    pub request: TunnelAgentRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ServerMsgKind {
    SessionOffer = 1,
    TargetAddr = 2,
    ForwardAck = 3,
    ForwardRequest = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerMsg {
    SessionOffer([u8; 32]),
    TargetAddr(SocketAddr),
    ForwardAck([u8; 32]),
    ForwardRequest(ForwardRequestMsg),
}

pub async fn connect_agent(addr: SocketAddr) -> std::io::Result<sock::LureConnection> {
    sock::LureConnection::connect(addr).await
}

pub async fn listen_agent(addr: SocketAddr) -> std::io::Result<sock::LureListener> {
    sock::LureListener::bind(addr).await
}

pub fn decode_agent_hello(buf: &[u8]) -> Result<Option<(AgentHello, usize)>, TunnelError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    if buf[..4] != MAGIC {
        return Err(TunnelError::InvalidMagic);
    }
    if buf.len() < 5 {
        // Need at least magic + version.
        return Ok(None);
    }

    let version = buf[4];
    if version != VERSION {
        return Err(TunnelError::UnsupportedVersion(version));
    }

    // Need at least: magic(4) + version(1) + intent(1) + key_id(8) + timestamp(8) + hmac(32)
    // = 54 bytes
    if buf.len() < 54 {
        return Ok(None);
    }

    let intent = Intent::from_u8(buf[5])?;

    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&buf[6..14]);

    let timestamp = u64::from_be_bytes([
        buf[14], buf[15], buf[16], buf[17], buf[18], buf[19], buf[20], buf[21],
    ]);

    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&buf[22..54]);

    let mut consumed = 54;
    let (session, forward) = match intent {
        Intent::Listen => (None, None),
        Intent::Connect => {
            if buf.len() < consumed + 32 {
                return Ok(None);
            }
            let mut session = [0u8; 32];
            session.copy_from_slice(&buf[consumed..consumed + 32]);
            consumed += 32;
            (Some(session), None)
        }
        Intent::Forward => {
            if buf.len() < consumed + 33 {
                return Ok(None);
            }
            let mut session = [0u8; 32];
            session.copy_from_slice(&buf[consumed..consumed + 32]);
            consumed += 32;
            let ttl = buf[consumed];
            consumed += 1;
            let Some((from, consumed_from)) = decode_socket_addr_payload(&buf[consumed..])? else {
                return Ok(None);
            };
            consumed += consumed_from;
            let Some((to, consumed_to)) = decode_socket_addr_payload(&buf[consumed..])? else {
                return Ok(None);
            };
            consumed += consumed_to;
            (
                None,
                Some(ForwardHello {
                    session,
                    ttl,
                    request: TunnelAgentRequest { from, to },
                }),
            )
        }
    };

    Ok(Some((
        AgentHello {
            version,
            intent,
            key_id,
            timestamp,
            hmac,
            session,
            forward,
        },
        consumed,
    )))
}

pub fn encode_agent_hello(hello: &AgentHello, out: &mut Vec<u8>) -> Result<(), TunnelError> {
    // Validate intent/session invariant: only Connect may have a session, others must not
    match hello.intent {
        Intent::Connect => {
            if hello.session.is_none() || hello.forward.is_some() {
                return Err(TunnelError::InvalidIntent(hello.intent as u8));
            }
        }
        Intent::Listen => {
            if hello.session.is_some() || hello.forward.is_some() {
                return Err(TunnelError::InvalidIntent(hello.intent as u8));
            }
        }
        Intent::Forward => {
            if hello.session.is_some() || hello.forward.is_none() {
                return Err(TunnelError::InvalidIntent(hello.intent as u8));
            }
        }
    }

    out.extend_from_slice(&MAGIC);
    out.push(hello.version);
    out.push(hello.intent as u8);
    out.extend_from_slice(&hello.key_id);
    out.extend_from_slice(&hello.timestamp.to_be_bytes());
    out.extend_from_slice(&hello.hmac);
    match hello.intent {
        Intent::Listen => {}
        Intent::Connect => {
            out.extend_from_slice(&hello.session.expect("validated above"));
        }
        Intent::Forward => {
            let forward = hello.forward.as_ref().expect("validated above");
            out.extend_from_slice(&forward.session);
            out.push(forward.ttl);
            encode_socket_addr_payload(forward.request.from, out);
            encode_socket_addr_payload(forward.request.to, out);
        }
    }
    Ok(())
}

pub fn encode_server_msg(msg: &ServerMsg, out: &mut Vec<u8>) {
    match msg {
        ServerMsg::SessionOffer(token) => {
            out.push(ServerMsgKind::SessionOffer as u8);
            out.extend_from_slice(token);
        }
        ServerMsg::TargetAddr(addr) => {
            out.push(ServerMsgKind::TargetAddr as u8);
            encode_socket_addr_payload(*addr, out);
        }
        ServerMsg::ForwardAck(session) => {
            out.push(ServerMsgKind::ForwardAck as u8);
            out.extend_from_slice(session);
        }
        ServerMsg::ForwardRequest(request) => {
            out.push(ServerMsgKind::ForwardRequest as u8);
            out.extend_from_slice(&request.session);
            out.push(request.ttl);
            encode_socket_addr_payload(request.request.from, out);
            encode_socket_addr_payload(request.request.to, out);
        }
    }
}

pub fn decode_server_msg(buf: &[u8]) -> Result<Option<(ServerMsg, usize)>, TunnelError> {
    if buf.is_empty() {
        return Ok(None);
    }
    match buf[0] {
        x if x == ServerMsgKind::SessionOffer as u8 => {
            if buf.len() < 1 + 32 {
                return Ok(None);
            }
            let mut token = [0u8; 32];
            token.copy_from_slice(&buf[1..33]);
            Ok(Some((ServerMsg::SessionOffer(token), 33)))
        }
        x if x == ServerMsgKind::TargetAddr as u8 => {
            let Some((addr, consumed)) = decode_socket_addr_payload(&buf[1..])? else {
                return Ok(None);
            };
            Ok(Some((ServerMsg::TargetAddr(addr), 1 + consumed)))
        }
        x if x == ServerMsgKind::ForwardAck as u8 => {
            if buf.len() < 1 + 32 {
                return Ok(None);
            }
            let mut token = [0u8; 32];
            token.copy_from_slice(&buf[1..33]);
            Ok(Some((ServerMsg::ForwardAck(token), 33)))
        }
        x if x == ServerMsgKind::ForwardRequest as u8 => {
            if buf.len() < 1 + 32 + 1 {
                return Ok(None);
            }
            let mut session = [0u8; 32];
            session.copy_from_slice(&buf[1..33]);
            let ttl = buf[33];
            let Some((from, consumed_from)) = decode_socket_addr_payload(&buf[34..])? else {
                return Ok(None);
            };
            let offset = 34 + consumed_from;
            let Some((to, consumed_to)) = decode_socket_addr_payload(&buf[offset..])? else {
                return Ok(None);
            };
            Ok(Some((
                ServerMsg::ForwardRequest(ForwardRequestMsg {
                    session,
                    ttl,
                    request: TunnelAgentRequest { from, to },
                }),
                offset + consumed_to,
            )))
        }
        other => Err(TunnelError::InvalidMsgKind(other)),
    }
}

fn encode_socket_addr_payload(addr: SocketAddr, out: &mut Vec<u8>) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&addr.port().to_be_bytes());
            out.extend_from_slice(&ip.octets());
        }
    }
}

fn decode_socket_addr_payload(buf: &[u8]) -> Result<Option<(SocketAddr, usize)>, TunnelError> {
    if buf.len() < 1 + 2 {
        return Ok(None);
    }
    let family = buf[0];
    let port = u16::from_be_bytes([buf[1], buf[2]]);
    match family {
        4 => {
            if buf.len() < 1 + 2 + 4 {
                return Ok(None);
            }
            let ip = std::net::Ipv4Addr::new(buf[3], buf[4], buf[5], buf[6]);
            Ok(Some((SocketAddr::new(IpAddr::V4(ip), port), 7)))
        }
        6 => {
            if buf.len() < 1 + 2 + 16 {
                return Ok(None);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[3..19]);
            let ip = std::net::Ipv6Addr::from(octets);
            Ok(Some((SocketAddr::new(IpAddr::V6(ip), port), 19)))
        }
        other => Err(TunnelError::InvalidAddrFamily(other)),
    }
}

/// Compute HMAC-SHA256 for agent authentication
#[must_use]
pub fn compute_agent_hmac(
    secret: &[u8; 32],
    key_id: &[u8; 8],
    timestamp: u64,
    intent: Intent,
    session: Option<&[u8; 32]>,
    request: Option<&TunnelAgentRequest>,
    ttl: u8,
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(key_id);
    mac.update(&timestamp.to_be_bytes());
    mac.update(&[intent as u8]);
    if let Some(session) = session {
        mac.update(session);
    }
    if let Some(request) = request {
        mac.update(&[ttl]);
        let mut buf = Vec::with_capacity(MAX_SOCKET_ADDR_PAYLOAD_LEN * 2);
        encode_socket_addr_payload(request.from, &mut buf);
        encode_socket_addr_payload(request.to, &mut buf);
        mac.update(&buf);
    }

    let result = mac.finalize();
    let mut hmac_array = [0u8; 32];
    hmac_array.copy_from_slice(result.into_bytes().as_ref());
    hmac_array
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    // ============================================================================
    // encode_agent_hello tests
    // ============================================================================

    #[test]
    fn test_encode_agent_hello_listen() {
        let hello = AgentHello {
            version: VERSION,
            intent: Intent::Listen,
            key_id: [1u8; 8],
            timestamp: 1234567890,
            hmac: [42u8; 32],
            session: None,
            forward: None,
        };
        let mut buf = Vec::new();
        assert!(encode_agent_hello(&hello, &mut buf).is_ok());
        assert_eq!(&buf[..4], &MAGIC);
        assert_eq!(buf[4], VERSION);
        assert_eq!(buf[5], Intent::Listen as u8);
        assert_eq!(&buf[6..14], &[1u8; 8]); // key_id
        assert_eq!(&buf[14..22], &1234567890u64.to_be_bytes()); // timestamp
        assert_eq!(&buf[22..54], &[42u8; 32]); // hmac
        assert_eq!(buf.len(), 54);
    }

    #[test]
    fn test_encode_agent_hello_connect() {
        let hello = AgentHello {
            version: VERSION,
            intent: Intent::Connect,
            key_id: [2u8; 8],
            timestamp: 9876543210,
            hmac: [43u8; 32],
            session: Some([44u8; 32]),
            forward: None,
        };
        let mut buf = Vec::new();
        assert!(encode_agent_hello(&hello, &mut buf).is_ok());
        assert_eq!(&buf[..4], &MAGIC);
        assert_eq!(buf[4], VERSION);
        assert_eq!(buf[5], Intent::Connect as u8);
        assert_eq!(&buf[6..14], &[2u8; 8]); // key_id
        assert_eq!(&buf[14..22], &9876543210u64.to_be_bytes()); // timestamp
        assert_eq!(&buf[22..54], &[43u8; 32]); // hmac
        assert_eq!(&buf[54..86], &[44u8; 32]); // session
        assert_eq!(buf.len(), 86);
    }

    #[test]
    fn test_encode_agent_hello_connect_without_session_fails() {
        let hello = AgentHello {
            version: VERSION,
            intent: Intent::Connect,
            key_id: [2u8; 8],
            timestamp: 9876543210,
            hmac: [43u8; 32],
            session: None,
            forward: None,
        };
        let mut buf = Vec::new();
        assert!(encode_agent_hello(&hello, &mut buf).is_err());
    }

    #[test]
    fn test_encode_agent_hello_listen_with_session_fails() {
        let hello = AgentHello {
            version: VERSION,
            intent: Intent::Listen,
            key_id: [1u8; 8],
            timestamp: 1234567890,
            hmac: [42u8; 32],
            session: Some([44u8; 32]),
            forward: None,
        };
        let mut buf = Vec::new();
        assert!(encode_agent_hello(&hello, &mut buf).is_err());
    }

    // ============================================================================
    // decode_agent_hello tests
    // ============================================================================

    #[test]
    fn test_decode_agent_hello_listen_roundtrip() {
        let hello = AgentHello {
            version: VERSION,
            intent: Intent::Listen,
            key_id: [1u8; 8],
            timestamp: 1234567890,
            hmac: [42u8; 32],
            session: None,
            forward: None,
        };
        let mut buf = Vec::new();
        encode_agent_hello(&hello, &mut buf).unwrap();

        let (decoded, consumed) = decode_agent_hello(&buf).unwrap().unwrap();
        assert_eq!(decoded.version, hello.version);
        assert_eq!(decoded.intent, hello.intent);
        assert_eq!(decoded.key_id, hello.key_id);
        assert_eq!(decoded.timestamp, hello.timestamp);
        assert_eq!(decoded.hmac, hello.hmac);
        assert_eq!(decoded.session, hello.session);
        assert_eq!(consumed, 54);
    }

    #[test]
    fn test_decode_agent_hello_connect_roundtrip() {
        let hello = AgentHello {
            version: VERSION,
            intent: Intent::Connect,
            key_id: [2u8; 8],
            timestamp: 9876543210,
            hmac: [43u8; 32],
            session: Some([44u8; 32]),
            forward: None,
        };
        let mut buf = Vec::new();
        encode_agent_hello(&hello, &mut buf).unwrap();

        let (decoded, consumed) = decode_agent_hello(&buf).unwrap().unwrap();
        assert_eq!(decoded.version, hello.version);
        assert_eq!(decoded.intent, hello.intent);
        assert_eq!(decoded.key_id, hello.key_id);
        assert_eq!(decoded.timestamp, hello.timestamp);
        assert_eq!(decoded.hmac, hello.hmac);
        assert_eq!(decoded.session, hello.session);
        assert_eq!(consumed, 86);
    }

    #[test]
    fn test_decode_agent_hello_forward_roundtrip() {
        let request = TunnelAgentRequest {
            from: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 25565),
            to: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4)), 25566),
        };
        let hello = AgentHello {
            version: VERSION,
            intent: Intent::Forward,
            key_id: [9u8; 8],
            timestamp: 111222333,
            hmac: [7u8; 32],
            session: None,
            forward: Some(ForwardHello {
                session: [8u8; 32],
                ttl: 1,
                request,
            }),
        };
        let mut buf = Vec::new();
        encode_agent_hello(&hello, &mut buf).unwrap();

        let (decoded, consumed) = decode_agent_hello(&buf).unwrap().unwrap();
        assert_eq!(decoded.intent, Intent::Forward);
        assert_eq!(decoded.session, None);
        let forward = decoded.forward.expect("forward payload");
        assert_eq!(forward.session, [8u8; 32]);
        assert_eq!(forward.ttl, 1);
        assert_eq!(forward.request, request);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_decode_agent_hello_buffer_too_short_for_magic() {
        let buf = vec![1, 2, 3];
        assert!(decode_agent_hello(&buf).unwrap().is_none());
    }

    #[test]
    fn test_decode_agent_hello_invalid_magic() {
        let mut buf = vec![0u8; 38];
        buf[0] = b'X';
        buf[1] = b'X';
        buf[2] = b'X';
        buf[3] = b'X';
        assert!(matches!(
            decode_agent_hello(&buf),
            Err(TunnelError::InvalidMagic)
        ));
    }

    #[test]
    fn test_decode_agent_hello_buffer_too_short_for_header() {
        let mut buf = MAGIC.to_vec();
        buf.push(VERSION);
        buf.push(Intent::Listen as u8);
        buf.extend_from_slice(&[0u8; 20]); // partial key_id and timestamp
        assert!(decode_agent_hello(&buf).unwrap().is_none());
    }

    #[test]
    fn test_decode_agent_hello_unsupported_version() {
        let mut buf = MAGIC.to_vec();
        buf.push(99);
        buf.push(Intent::Listen as u8);
        buf.extend_from_slice(&[0u8; 48]); // key_id(8) + timestamp(8) + hmac(32)
        assert!(matches!(
            decode_agent_hello(&buf),
            Err(TunnelError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn test_decode_agent_hello_invalid_intent() {
        let mut buf = MAGIC.to_vec();
        buf.push(VERSION);
        buf.push(99);
        buf.extend_from_slice(&[0u8; 48]); // key_id(8) + timestamp(8) + hmac(32)
        assert!(matches!(
            decode_agent_hello(&buf),
            Err(TunnelError::InvalidIntent(99))
        ));
    }

    #[test]
    fn test_decode_agent_hello_connect_buffer_too_short() {
        let mut buf = MAGIC.to_vec();
        buf.push(VERSION);
        buf.push(Intent::Connect as u8);
        buf.extend_from_slice(&[0u8; 48]); // partial: key_id(8) + timestamp(8) + hmac(32)
        // Connect requires session but buffer is too short
        assert!(decode_agent_hello(&buf).unwrap().is_none());
    }

    #[test]
    fn test_decode_agent_hello_listen_with_extra_bytes() {
        let mut buf = MAGIC.to_vec();
        buf.push(VERSION);
        buf.push(Intent::Listen as u8);
        buf.extend_from_slice(&[1u8; 8]); // key_id
        buf.extend_from_slice(&1234567890u64.to_be_bytes()); // timestamp
        buf.extend_from_slice(&[42u8; 32]); // hmac
        buf.extend_from_slice(&[99u8; 50]); // extra bytes

        let (decoded, consumed) = decode_agent_hello(&buf).unwrap().unwrap();
        assert_eq!(decoded.intent, Intent::Listen);
        assert_eq!(consumed, 54);
        // Extra bytes are not consumed by decoder
    }

    // ============================================================================
    // encode_server_msg tests - SessionOffer
    // ============================================================================

    #[test]
    fn test_encode_server_msg_session_offer() {
        let msg = ServerMsg::SessionOffer([55u8; 32]);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);
        assert_eq!(buf[0], ServerMsgKind::SessionOffer as u8);
        assert_eq!(&buf[1..33], &[55u8; 32]);
        assert_eq!(buf.len(), 33);
    }

    // ============================================================================
    // encode_server_msg tests - TargetAddr IPv4
    // ============================================================================

    #[test]
    fn test_encode_server_msg_target_addr_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let msg = ServerMsg::TargetAddr(addr);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);

        assert_eq!(buf[0], ServerMsgKind::TargetAddr as u8);
        assert_eq!(buf[1], 4); // IPv4
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 8080);
        assert_eq!(buf[4], 192);
        assert_eq!(buf[5], 168);
        assert_eq!(buf[6], 1);
        assert_eq!(buf[7], 1);
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn test_encode_server_msg_target_addr_ipv4_min_port() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1);
        let msg = ServerMsg::TargetAddr(addr);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);

        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 1);
    }

    #[test]
    fn test_encode_server_msg_target_addr_ipv4_max_port() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 65535);
        let msg = ServerMsg::TargetAddr(addr);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);

        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 65535);
    }

    // ============================================================================
    // encode_server_msg tests - TargetAddr IPv6
    // ============================================================================

    #[test]
    fn test_encode_server_msg_target_addr_ipv6() {
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            9000,
        );
        let msg = ServerMsg::TargetAddr(addr);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);

        assert_eq!(buf[0], ServerMsgKind::TargetAddr as u8);
        assert_eq!(buf[1], 6); // IPv6
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 9000);
        assert_eq!(buf.len(), 20);
    }

    #[test]
    fn test_encode_server_msg_target_addr_ipv6_loopback() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let msg = ServerMsg::TargetAddr(addr);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);

        assert_eq!(buf[0], ServerMsgKind::TargetAddr as u8);
        assert_eq!(buf[1], 6); // IPv6
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 443);
        assert_eq!(buf.len(), 20);
    }

    // ============================================================================
    // decode_server_msg tests - SessionOffer
    // ============================================================================

    #[test]
    fn test_decode_server_msg_session_offer_roundtrip() {
        let msg = ServerMsg::SessionOffer([55u8; 32]);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);

        let (decoded, consumed) = decode_server_msg(&buf).unwrap().unwrap();
        if let ServerMsg::SessionOffer(token) = decoded {
            assert_eq!(token, [55u8; 32]);
        } else {
            panic!("Expected SessionOffer");
        }
        assert_eq!(consumed, 33);
    }

    #[test]
    fn test_decode_server_msg_forward_ack_roundtrip() {
        let msg = ServerMsg::ForwardAck([0xAB; 32]);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);

        let (decoded, consumed) = decode_server_msg(&buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, 33);
    }

    #[test]
    fn test_decode_server_msg_session_offer_buffer_too_short() {
        let buf = vec![ServerMsgKind::SessionOffer as u8, 1, 2, 3];
        assert!(decode_server_msg(&buf).unwrap().is_none());
    }

    // ============================================================================
    // decode_server_msg tests - TargetAddr IPv4
    // ============================================================================

    #[test]
    fn test_decode_server_msg_target_addr_ipv4_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000);
        let msg = ServerMsg::TargetAddr(addr);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);

        let (decoded, consumed) = decode_server_msg(&buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_decode_server_msg_target_addr_ipv4_buffer_too_short_for_family() {
        let buf = vec![ServerMsgKind::TargetAddr as u8];
        assert!(decode_server_msg(&buf).unwrap().is_none());
    }

    #[test]
    fn test_decode_server_msg_target_addr_ipv4_buffer_too_short_for_data() {
        let buf = vec![ServerMsgKind::TargetAddr as u8, 4, 0, 80, 1, 2]; // Incomplete IPv4
        assert!(decode_server_msg(&buf).unwrap().is_none());
    }

    #[test]
    fn test_decode_server_msg_target_addr_invalid_family() {
        let buf = vec![ServerMsgKind::TargetAddr as u8, 5, 0, 80, 1, 2, 3, 4];
        assert!(matches!(
            decode_server_msg(&buf),
            Err(TunnelError::InvalidAddrFamily(5))
        ));
    }

    // ============================================================================
    // decode_server_msg tests - TargetAddr IPv6
    // ============================================================================

    #[test]
    fn test_decode_server_msg_target_addr_ipv6_roundtrip() {
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8080,
        );
        let msg = ServerMsg::TargetAddr(addr);
        let mut buf = Vec::new();
        encode_server_msg(&msg, &mut buf);

        let (decoded, consumed) = decode_server_msg(&buf).unwrap().unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, 20);
    }

    #[test]
    fn test_decode_server_msg_target_addr_ipv6_buffer_too_short_for_data() {
        let mut buf = vec![ServerMsgKind::TargetAddr as u8, 6, 1, 187]; // Port 443 in big-endian
        buf.extend_from_slice(&[1u8; 10]); // Incomplete IPv6
        assert!(decode_server_msg(&buf).unwrap().is_none());
    }

    // ============================================================================
    // Edge cases and error conditions
    // ============================================================================

    #[test]
    fn test_decode_server_msg_empty_buffer() {
        let buf = vec![];
        assert!(decode_server_msg(&buf).unwrap().is_none());
    }

    #[test]
    fn test_decode_server_msg_invalid_message_kind() {
        let buf = vec![99, 0, 0];
        assert!(matches!(
            decode_server_msg(&buf),
            Err(TunnelError::InvalidMsgKind(99))
        ));
    }

    #[test]
    fn test_intent_listen_value() {
        assert_eq!(Intent::Listen as u8, 1);
    }

    #[test]
    fn test_intent_connect_value() {
        assert_eq!(Intent::Connect as u8, 2);
    }

    #[test]
    fn test_server_msg_kind_session_offer_value() {
        assert_eq!(ServerMsgKind::SessionOffer as u8, 1);
    }

    #[test]
    fn test_server_msg_kind_target_addr_value() {
        assert_eq!(ServerMsgKind::TargetAddr as u8, 2);
    }

    // ============================================================================
    // compute_agent_hmac tests
    // ============================================================================

    #[test]
    fn test_compute_agent_hmac_listen() {
        let secret = [0x42u8; 32];
        let key_id = [0x01u8; 8];
        let timestamp = 1234567890u64;

        let hmac = compute_agent_hmac(&secret, &key_id, timestamp, Intent::Listen, None, None, 0);
        // HMAC should be 32 bytes
        assert_eq!(hmac.len(), 32);
    }

    #[test]
    fn test_compute_agent_hmac_connect() {
        let secret = [0x42u8; 32];
        let key_id = [0x01u8; 8];
        let timestamp = 1234567890u64;
        let session = [0x99u8; 32];

        let hmac = compute_agent_hmac(
            &secret,
            &key_id,
            timestamp,
            Intent::Connect,
            Some(&session),
            None,
            0,
        );
        // HMAC should be 32 bytes
        assert_eq!(hmac.len(), 32);
    }

    #[test]
    fn test_compute_agent_hmac_listen_vs_connect_different() {
        let secret = [0x42u8; 32];
        let key_id = [0x01u8; 8];
        let timestamp = 1234567890u64;
        let session = [0x99u8; 32];

        let hmac_listen =
            compute_agent_hmac(&secret, &key_id, timestamp, Intent::Listen, None, None, 0);
        let hmac_connect = compute_agent_hmac(
            &secret,
            &key_id,
            timestamp,
            Intent::Connect,
            Some(&session),
            None,
            0,
        );

        // Different intents should produce different HMACs
        assert_ne!(hmac_listen, hmac_connect);
    }

    #[test]
    fn test_compute_agent_hmac_with_without_session_different() {
        let secret = [0x42u8; 32];
        let key_id = [0x01u8; 8];
        let timestamp = 1234567890u64;
        let session = [0x99u8; 32];

        let hmac_without_session =
            compute_agent_hmac(&secret, &key_id, timestamp, Intent::Connect, None, None, 0);
        let hmac_with_session = compute_agent_hmac(
            &secret,
            &key_id,
            timestamp,
            Intent::Connect,
            Some(&session),
            None,
            0,
        );

        // Session should change the HMAC
        assert_ne!(hmac_without_session, hmac_with_session);
    }

    #[test]
    fn test_compute_agent_hmac_deterministic() {
        let secret = [0x42u8; 32];
        let key_id = [0x01u8; 8];
        let timestamp = 1234567890u64;

        let hmac1 = compute_agent_hmac(&secret, &key_id, timestamp, Intent::Listen, None, None, 0);
        let hmac2 = compute_agent_hmac(&secret, &key_id, timestamp, Intent::Listen, None, None, 0);

        // Same inputs should produce same HMAC
        assert_eq!(hmac1, hmac2);
    }

    #[test]
    fn test_compute_agent_hmac_different_key_id() {
        let secret = [0x42u8; 32];
        let key_id1 = [0x01u8; 8];
        let key_id2 = [0x02u8; 8];
        let timestamp = 1234567890u64;

        let hmac1 = compute_agent_hmac(&secret, &key_id1, timestamp, Intent::Listen, None, None, 0);
        let hmac2 = compute_agent_hmac(&secret, &key_id2, timestamp, Intent::Listen, None, None, 0);

        // Different key_ids should produce different HMACs
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_compute_agent_hmac_different_timestamp() {
        let secret = [0x42u8; 32];
        let key_id = [0x01u8; 8];
        let timestamp1 = 1234567890u64;
        let timestamp2 = 1234567891u64;

        let hmac1 = compute_agent_hmac(&secret, &key_id, timestamp1, Intent::Listen, None, None, 0);
        let hmac2 = compute_agent_hmac(&secret, &key_id, timestamp2, Intent::Listen, None, None, 0);

        // Different timestamps should produce different HMACs
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_compute_agent_hmac_different_secret() {
        let secret1 = [0x42u8; 32];
        let secret2 = [0x43u8; 32];
        let key_id = [0x01u8; 8];
        let timestamp = 1234567890u64;

        let hmac1 = compute_agent_hmac(&secret1, &key_id, timestamp, Intent::Listen, None, None, 0);
        let hmac2 = compute_agent_hmac(&secret2, &key_id, timestamp, Intent::Listen, None, None, 0);

        // Different secrets should produce different HMACs
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_compute_agent_hmac_forward_changes_with_edge() {
        let secret = [0x42u8; 32];
        let key_id = [0x01u8; 8];
        let timestamp = 1234567890u64;
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)), 25565);

        let hmac1 = compute_agent_hmac(
            &secret,
            &key_id,
            timestamp,
            Intent::Forward,
            None,
            Some(&TunnelAgentRequest {
                from: target,
                to: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 25566),
            }),
            1,
        );
        let hmac2 = compute_agent_hmac(
            &secret,
            &key_id,
            timestamp,
            Intent::Forward,
            None,
            Some(&TunnelAgentRequest {
                from: target,
                to: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 25566),
            }),
            2,
        );

        assert_ne!(hmac1, hmac2);
    }

    // v2 only: no protocol flags.
}
