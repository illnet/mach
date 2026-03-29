/// Integration tests for tunnel protocol and registry
/// Tests protocol encoding/decoding, registry state management, and concurrent safety
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

#[test]
fn tunnel_basic_types() {
    // Test: Basic tunnel types are valid
    use lure::tunnel::{SessionToken, TokenKeyId};

    let key_id = TokenKeyId([0u8; 8]);
    let session = SessionToken([1u8; 32]);

    // Verify these can be cloned and compared
    let key_id2 = key_id;
    assert_eq!(key_id, key_id2);

    let session2 = session;
    assert_eq!(session, session2);
}

#[test]
fn tunnel_protocol_agent_hello_roundtrip() {
    // Test: Protocol encoding/decoding works end-to-end for AgentHello
    // Verifies wire format is correct

    use tun::{AgentHello, Intent, decode_agent_hello, encode_agent_hello};

    // Test Connect intent
    let hello = AgentHello {
        version: tun::VERSION,
        intent: Intent::Connect,
        key_id: [20u8; 8],
        timestamp: 1234567890,
        hmac: [25u8; 32],
        session: Some([21u8; 32]),
        forward: None,
    };

    let mut buf = Vec::new();
    encode_agent_hello(&hello, &mut buf).expect("encode should work");

    // Verify buffer structure
    assert_eq!(&buf[..4], &tun::MAGIC, "Magic bytes should match");
    assert_eq!(buf[4], tun::VERSION, "Version should match");
    assert_eq!(buf[5], Intent::Connect as u8, "Intent should be Connect");

    // Decode
    let (decoded, consumed) = decode_agent_hello(&buf)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded.version, hello.version);
    assert_eq!(decoded.intent, hello.intent);
    assert_eq!(decoded.key_id, hello.key_id);
    assert_eq!(decoded.timestamp, hello.timestamp);
    assert_eq!(decoded.hmac, hello.hmac);
    assert_eq!(decoded.session, hello.session);
    assert_eq!(decoded.forward, hello.forward);
    assert_eq!(consumed, 86, "Connect message should be 86 bytes");

    // Test Listen intent
    let hello_listen = AgentHello {
        version: tun::VERSION,
        intent: Intent::Listen,
        key_id: [22u8; 8],
        timestamp: 9876543210,
        hmac: [23u8; 32],
        session: None,
        forward: None,
    };

    let mut buf2 = Vec::new();
    encode_agent_hello(&hello_listen, &mut buf2).expect("encode should work");
    assert_eq!(buf2.len(), 54, "Listen message should be 54 bytes");

    let (decoded2, consumed2) = decode_agent_hello(&buf2)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded2.intent, Intent::Listen);
    assert_eq!(decoded2.key_id, hello_listen.key_id);
    assert_eq!(decoded2.timestamp, hello_listen.timestamp);
    assert_eq!(decoded2.hmac, hello_listen.hmac);
    assert_eq!(decoded2.forward, None);
    assert_eq!(consumed2, 54);
}

#[test]
fn tunnel_protocol_agent_hello_forward_roundtrip() {
    use tun::{
        AgentHello, ForwardHello, Intent, TunnelAgentRequest, decode_agent_hello,
        encode_agent_hello,
    };

    let hello = AgentHello {
        version: tun::VERSION,
        intent: Intent::Forward,
        key_id: [24u8; 8],
        timestamp: 123,
        hmac: [26u8; 32],
        session: None,
        forward: Some(ForwardHello {
            session: [27u8; 32],
            ttl: 60,
            request: TunnelAgentRequest {
                from: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 25565),
                to: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 25566),
            },
        }),
    };

    let mut buf = Vec::new();
    encode_agent_hello(&hello, &mut buf).expect("encode should work");

    let (decoded, consumed) = decode_agent_hello(&buf)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded.version, hello.version);
    assert_eq!(decoded.intent, hello.intent);
    assert_eq!(decoded.key_id, hello.key_id);
    assert_eq!(decoded.timestamp, hello.timestamp);
    assert_eq!(decoded.hmac, hello.hmac);
    assert_eq!(decoded.session, hello.session);
    assert_eq!(decoded.forward, hello.forward);
    assert_eq!(consumed, buf.len());
}

#[test]
fn tunnel_ipv4_target_addr_roundtrip() {
    // Test: IPv4 target address encoding/decoding
    use tun::{ServerMsg, decode_server_msg, encode_server_msg};

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 25565);
    let msg = ServerMsg::TargetAddr(addr);

    let mut buf = Vec::new();
    encode_server_msg(&msg, &mut buf);

    let (decoded, consumed) = decode_server_msg(&buf)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded, msg, "Roundtrip should preserve address");
    assert_eq!(consumed, 8, "IPv4 message should be 8 bytes");
}

#[test]
fn tunnel_ipv6_target_addr_roundtrip() {
    // Test: IPv6 target address encoding/decoding
    use tun::{ServerMsg, decode_server_msg, encode_server_msg};

    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        8080,
    );
    let msg = ServerMsg::TargetAddr(addr);

    let mut buf = Vec::new();
    encode_server_msg(&msg, &mut buf);

    let (decoded, consumed) = decode_server_msg(&buf)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded, msg, "Roundtrip should preserve IPv6 address");
    assert_eq!(consumed, 20, "IPv6 message should be 20 bytes");
}

#[test]
fn tunnel_session_offer_roundtrip() {
    // Test: SessionOffer message encoding/decoding
    use tun::{ServerMsg, decode_server_msg, encode_server_msg};

    let msg = ServerMsg::SessionOffer([30u8; 32]);

    let mut buf = Vec::new();
    encode_server_msg(&msg, &mut buf);

    let (decoded, consumed) = decode_server_msg(&buf)
        .expect("decode should work")
        .expect("should have complete message");

    assert_eq!(decoded, msg, "Roundtrip should preserve session offer");
    assert_eq!(consumed, 33, "SessionOffer message should be 33 bytes");
}

#[test]
fn tunnel_protocol_error_handling() {
    // Test: Protocol errors are handled correctly
    use tun::{TunnelError, decode_agent_hello, decode_server_msg};

    // Invalid magic bytes
    let mut buf = vec![0u8; 54];
    buf[0] = b'X';
    let result = decode_agent_hello(&buf);
    assert!(matches!(result, Err(TunnelError::InvalidMagic)));

    // Invalid message kind
    let bad_msg = vec![99u8; 10];
    let result = decode_server_msg(&bad_msg);
    assert!(matches!(result, Err(TunnelError::InvalidMsgKind(99))));

    // Invalid address family
    let mut bad_addr = vec![2u8, 99u8, 0, 80]; // TargetAddr with family 99
    bad_addr.extend_from_slice(&[0u8; 4]);
    let result = decode_server_msg(&bad_addr);
    assert!(matches!(result, Err(TunnelError::InvalidAddrFamily(99))));
}

#[test]
fn tunnel_buffer_handling() {
    // Test: Protocol correctly handles incomplete/truncated buffers
    use tun::{decode_agent_hello, decode_server_msg};

    // Buffer too short for AgentHello header
    let short_buf = vec![b'L', b'T', b'U', b'N']; // Only magic, no header
    let result = decode_agent_hello(&short_buf);
    assert!(
        result.unwrap().is_none(),
        "Should return None for incomplete buffer"
    );

    // Buffer too short for ServerMsg
    let msg_header = vec![1u8]; // Only message kind
    let result = decode_server_msg(&msg_header);
    assert!(
        result.unwrap().is_none(),
        "Should return None for incomplete message"
    );
}

#[test]
fn tunnel_hmac_computation() {
    // Test: HMAC computation for authentication
    use tun::{Intent, compute_agent_hmac};

    let secret = [0x42u8; 32];
    let key_id = [0x01u8; 8];
    let timestamp = 1234567890u64;
    let session = [0x99u8; 32];
    let request = tun::TunnelAgentRequest {
        from: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 25565),
        to: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)), 25566),
    };

    // Listen intent (no session)
    let hmac_listen =
        compute_agent_hmac(&secret, &key_id, timestamp, Intent::Listen, None, None, 0);
    assert_eq!(hmac_listen.len(), 32, "HMAC should be 32 bytes");

    // Connect intent (with session)
    let hmac_connect = compute_agent_hmac(
        &secret,
        &key_id,
        timestamp,
        Intent::Connect,
        Some(&session),
        None,
        0,
    );
    assert_eq!(hmac_connect.len(), 32, "HMAC should be 32 bytes");

    // Different intents should produce different HMACs
    assert_ne!(
        hmac_listen, hmac_connect,
        "Listen and Connect should produce different HMACs"
    );

    // Same inputs should be deterministic
    let hmac_listen2 =
        compute_agent_hmac(&secret, &key_id, timestamp, Intent::Listen, None, None, 0);
    assert_eq!(hmac_listen, hmac_listen2, "HMAC should be deterministic");

    // Different key_id should change HMAC
    let key_id2 = [0x02u8; 8];
    let hmac_different_key =
        compute_agent_hmac(&secret, &key_id2, timestamp, Intent::Listen, None, None, 0);
    assert_ne!(
        hmac_listen, hmac_different_key,
        "Different key_id should produce different HMAC"
    );

    let hmac_forward = compute_agent_hmac(
        &secret,
        &key_id,
        timestamp,
        Intent::Forward,
        Some(&session),
        Some(&request),
        60,
    );
    let hmac_forward_repeat = compute_agent_hmac(
        &secret,
        &key_id,
        timestamp,
        Intent::Forward,
        Some(&session),
        Some(&request),
        60,
    );
    let hmac_forward_default = compute_agent_hmac(
        &secret,
        &key_id,
        timestamp,
        Intent::Forward,
        Some(&session),
        None,
        0,
    );
    assert_eq!(hmac_forward.len(), 32, "Forward HMAC should be 32 bytes");
    assert_eq!(
        hmac_forward, hmac_forward_repeat,
        "Forward HMAC should be deterministic"
    );
    assert_ne!(
        hmac_forward, hmac_forward_default,
        "Request payload and ttl should affect the HMAC"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tunnel_registry_live_auth_handshake() {
    use lure::{
        config::TokenEntry,
        router::AuthMode,
        sock::{LureConnection, LureListener},
        tunnel::{SessionToken, TokenKeyId, TunnelRegistry},
    };
    use tokio::{
        sync::oneshot,
        task::LocalSet,
        time::{Duration, timeout},
    };
    use tun::{Intent, ServerMsg, compute_agent_hmac, decode_server_msg};

    LocalSet::new()
        .run_until(async move {
            let secret = [0x42u8; 32];
            let key_id = [0x01u8; 8];
            let session = [0xAAu8; 32];
            let target: SocketAddr = "127.0.0.1:25565".parse().unwrap();

            let registry = Arc::new(TunnelRegistry::default());
            registry
                .upsert_token(&TokenEntry {
                    key_id: hex::encode(key_id),
                    secret: hex::encode(secret),
                    name: Some("integration-test".to_string()),
                    zone: None,
                })
                .await
                .expect("token upsert should succeed");

            let listener = LureListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .expect("listener bind should succeed");
            let ingress = listener
                .local_addr()
                .expect("listener should have local addr");

            let (registered_tx, registered_rx) = oneshot::channel();
            let registry_task = tokio::task::spawn_local({
                let registry = Arc::clone(&registry);
                async move {
                    let (listener_conn, _) = listener.accept().await?;
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs();
                    let listen_hmac = compute_agent_hmac(
                        &secret,
                        &key_id,
                        timestamp,
                        Intent::Listen,
                        None,
                        None,
                        0,
                    );
                    registry
                        .register_listener(
                            TokenKeyId(key_id),
                            timestamp,
                            listen_hmac,
                            listener_conn,
                        )
                        .await?;
                    let _ = registered_tx.send(());

                    let (connect_conn, _) = listener.accept().await?;
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs();
                    let connect_hmac = compute_agent_hmac(
                        &secret,
                        &key_id,
                        timestamp,
                        Intent::Connect,
                        Some(&session),
                        None,
                        0,
                    );
                    registry
                        .accept_connect(
                            TokenKeyId(key_id),
                            timestamp,
                            connect_hmac,
                            SessionToken(session),
                            connect_conn,
                        )
                        .await
                }
            });

            let _listen_agent = LureConnection::connect(ingress)
                .await
                .expect("listen agent should connect");
            timeout(Duration::from_secs(5), registered_rx)
                .await
                .expect("listener registration should complete in time")
                .expect("listener registration signal should succeed");

            let session_rx = registry
                .prepare_local_session(
                    TokenKeyId(key_id),
                    SessionToken(session),
                    target,
                    &AuthMode::Protected,
                )
                .await
                .expect("session preparation should succeed");

            let mut connect_agent = LureConnection::connect(ingress)
                .await
                .expect("connect agent should connect");

            let (read, mut buf) = timeout(
                Duration::from_secs(5),
                connect_agent.read_chunk(vec![0u8; 64]),
            )
            .await
            .expect("target address frame should arrive in time")
            .expect("read from authenticated connect should succeed");
            buf.truncate(read);

            let (msg, consumed) = decode_server_msg(&buf)
                .expect("target address frame should decode")
                .expect("target address frame should be complete");
            assert_eq!(
                consumed,
                buf.len(),
                "decoded frame should consume the buffer"
            );
            assert_eq!(msg, ServerMsg::TargetAddr(target));

            let delivered_conn = timeout(Duration::from_secs(5), session_rx)
                .await
                .expect("prepared session should complete in time")
                .expect("prepared session should receive a connection");
            drop(delivered_conn);

            registry_task
                .await
                .expect("registry task should join")
                .expect("registry operations should succeed");
        })
        .await;
}
