use super::{
    packets::{
        HandshakeC2s, LoginDisconnectS2c, LoginStartC2s, LoginStartSigData, ServerboundPacket,
        StatusPingC2s,
    },
    state::{HandshakeNextState, PacketState},
    types::{PacketDecoder, PacketEncode, PacketEncoder, Uuid},
    varint::{read_varint, write_varint},
};

const PROTOCOL_VERSION_WITH_SIG_DATA: i32 = 763;
const PROTOCOL_VERSION_WITH_UUID: i32 = 766;

struct VersionedLoginStart<'a> {
    packet: &'a LoginStartC2s<'a>,
    protocol_version: i32,
}

impl<'a> PacketEncode for VersionedLoginStart<'a> {
    const ID: i32 = LoginStartC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> super::error::Result<()> {
        self.packet
            .encode_body_with_version(out, self.protocol_version)
    }
}

#[test]
fn varint_roundtrip() {
    let values = [0, 1, 2, 127, 128, 255, 2_147_483_647, -1, -2_147_483_648];
    for value in values {
        let mut buf = Vec::new();
        write_varint(&mut buf, value);
        let mut slice = buf.as_slice();
        let decoded = read_varint(&mut slice).unwrap();
        assert_eq!(decoded, value);
        assert!(slice.is_empty());
    }
}

#[test]
fn handshake_roundtrip() {
    let packet = HandshakeC2s {
        protocol_version: PROTOCOL_VERSION_WITH_SIG_DATA,
        server_address: "localhost",
        server_port: 25565,
        next_state: HandshakeNextState::Login,
    };

    let mut enc = PacketEncoder::new();
    enc.write_packet(&packet).unwrap();
    let bytes = enc.take();

    let mut dec = PacketDecoder::new();
    dec.queue_slice(&bytes);
    let frame = dec.try_next_packet().unwrap().unwrap();
    let decoded = frame
        .decode_serverbound(PacketState::Handshaking, PROTOCOL_VERSION_WITH_SIG_DATA)
        .unwrap();

    match decoded {
        ServerboundPacket::Handshake(actual) => assert_eq!(actual, packet),
        _ => panic!("unexpected packet"),
    }
}

#[test]
fn login_start_roundtrip_with_signature_data() {
    let public_key = [1u8, 2, 3, 4];
    let signature = [9u8, 8, 7];
    let packet = LoginStartC2s {
        username: "player",
        profile_id: None,
        sig_data: Some(LoginStartSigData {
            timestamp: 1_694_857_600,
            public_key: &public_key,
            signature: &signature,
        }),
    };

    let mut enc = PacketEncoder::new();
    let versioned = VersionedLoginStart {
        packet: &packet,
        protocol_version: PROTOCOL_VERSION_WITH_SIG_DATA,
    };
    enc.write_packet(&versioned).unwrap();
    let bytes = enc.take();

    let mut dec = PacketDecoder::new();
    dec.queue_slice(&bytes);
    let frame = dec.try_next_packet().unwrap().unwrap();
    let decoded = frame
        .decode_serverbound(PacketState::Login, PROTOCOL_VERSION_WITH_SIG_DATA)
        .unwrap();

    match decoded {
        ServerboundPacket::LoginStart(actual) => assert_eq!(actual, packet),
        _ => panic!("unexpected packet"),
    }
}

#[test]
fn login_start_roundtrip_with_uuid() {
    let packet = LoginStartC2s {
        username: "player",
        profile_id: Some(Uuid::from_u64s(
            0x0102_0304_0506_0708,
            0x090a_0b0c_0d0e_0f10,
        )),
        sig_data: None,
    };

    let mut enc = PacketEncoder::new();
    let versioned = VersionedLoginStart {
        packet: &packet,
        protocol_version: PROTOCOL_VERSION_WITH_UUID,
    };
    enc.write_packet(&versioned).unwrap();
    let bytes = enc.take();

    let mut dec = PacketDecoder::new();
    dec.queue_slice(&bytes);
    let frame = dec.try_next_packet().unwrap().unwrap();
    let decoded = frame
        .decode_serverbound(PacketState::Login, PROTOCOL_VERSION_WITH_UUID)
        .unwrap();

    match decoded {
        ServerboundPacket::LoginStart(actual) => assert_eq!(actual, packet),
        _ => panic!("unexpected packet"),
    }
}

#[test]
fn status_ping_roundtrip() {
    let packet = StatusPingC2s { payload: 1_234_567 };

    let mut enc = PacketEncoder::new();
    enc.write_packet(&packet).unwrap();
    let bytes = enc.take();

    let mut dec = PacketDecoder::new();
    dec.queue_slice(&bytes);
    let frame = dec.try_next_packet().unwrap().unwrap();
    let decoded = frame
        .decode_serverbound(PacketState::Status, PROTOCOL_VERSION_WITH_SIG_DATA)
        .unwrap();

    match decoded {
        ServerboundPacket::StatusPing(actual) => assert_eq!(actual, packet),
        _ => panic!("unexpected packet"),
    }
}

#[test]
fn login_disconnect_roundtrip() {
    let packet = LoginDisconnectS2c {
        reason: "{\"text\":\"Bye\"}",
    };

    let mut enc = PacketEncoder::new();
    enc.write_packet(&packet).unwrap();
    let bytes = enc.take();

    let mut dec = PacketDecoder::new();
    dec.queue_slice(&bytes);
    let frame = dec.try_next_packet().unwrap().unwrap();
    assert_eq!(frame.id, LoginDisconnectS2c::ID);

    let mut body = frame.body.as_slice();
    let decoded = LoginDisconnectS2c::decode_body(&mut body).unwrap();
    assert_eq!(decoded, packet);
    assert!(body.is_empty());
}

struct MetaCollector {
    metas: Vec<super::stream::PacketMeta>,
    names: Vec<String>,
}

impl super::stream::PacketHook for MetaCollector {
    fn on_packet(&mut self, event: super::stream::PacketEvent<'_>) {
        if let super::stream::ParsedPacket::Serverbound(ServerboundPacket::LoginStart(pkt)) =
            event.packet
        {
            self.names.push(pkt.username.to_owned());
        }
        if let super::stream::ParsedPacket::Clientbound(
            super::packets::ClientboundPacket::LoginSuccess(pkt),
        ) = event.packet
        {
            self.names.push(pkt.username.to_owned());
        }
        self.metas.push(event.meta);
    }
}

fn write_test_string(out: &mut Vec<u8>, value: &str) {
    write_varint(out, i32::try_from(value.len()).unwrap());
    out.extend_from_slice(value.as_bytes());
}

fn write_test_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(out, i32::try_from(bytes.len()).unwrap());
    out.extend_from_slice(bytes);
}

#[test]
fn stream_parser_tracks_login_auth_and_compression() {
    use super::{
        state::{PacketDirection, StreamAuthMode, StreamSecurity},
        stream::MinecraftStreamParser,
    };

    let mut parser = MinecraftStreamParser::new();
    let mut hook = MetaCollector {
        metas: Vec::new(),
        names: Vec::new(),
    };

    let handshake = HandshakeC2s {
        protocol_version: PROTOCOL_VERSION_WITH_UUID,
        server_address: "example.test",
        server_port: 25565,
        next_state: HandshakeNextState::Login,
    };
    let mut bytes = Vec::new();
    super::types::encode_packet(&mut bytes, &handshake).unwrap();
    parser.queue_slice(&bytes);
    assert_eq!(
        parser
            .drain_with_hook(PacketDirection::C2s, &mut hook)
            .unwrap(),
        1
    );
    assert_eq!(parser.state(), PacketState::Login);
    assert_eq!(parser.protocol_version(), Some(PROTOCOL_VERSION_WITH_UUID));

    let login = LoginStartC2s {
        username: "shielded",
        profile_id: Some(Uuid::from_u64s(1, 2)),
        sig_data: None,
    };
    let versioned = VersionedLoginStart {
        packet: &login,
        protocol_version: PROTOCOL_VERSION_WITH_UUID,
    };
    let mut enc = PacketEncoder::new();
    enc.write_packet(&versioned).unwrap();
    parser.queue_slice(&enc.take());
    assert_eq!(
        parser
            .drain_with_hook(PacketDirection::C2s, &mut hook)
            .unwrap(),
        1
    );
    assert_eq!(parser.auth_mode(), StreamAuthMode::Offline);

    let mut body = Vec::new();
    write_test_string(&mut body, "");
    write_test_bytes(&mut body, &[1, 2]);
    write_test_bytes(&mut body, &[3, 4, 5, 6]);
    super::io::write_bool(&mut body, false);
    let mut raw = Vec::new();
    super::types::encode_raw_packet(&mut raw, super::packets::EncryptionRequestS2c::ID, &body)
        .unwrap();
    parser.queue_slice(&raw);
    assert_eq!(
        parser
            .drain_with_hook(PacketDirection::S2c, &mut hook)
            .unwrap(),
        1
    );
    assert_eq!(parser.security(), StreamSecurity::EncryptionRequested);
    assert_eq!(parser.auth_mode(), StreamAuthMode::OfflineEncryption);

    let mut body = Vec::new();
    write_varint(&mut body, 256);
    let mut raw = Vec::new();
    super::types::encode_raw_packet(&mut raw, super::packets::SetCompressionS2c::ID, &body)
        .unwrap();
    parser.queue_slice(&raw);
    assert_eq!(
        parser
            .drain_with_hook(PacketDirection::S2c, &mut hook)
            .unwrap(),
        1
    );
    assert_eq!(parser.compression_threshold(), Some(256));

    assert_eq!(hook.names, ["shielded"]);
    assert_eq!(hook.metas[0].kind, super::packets::PacketKind::Handshake);
    assert_eq!(hook.metas[1].kind, super::packets::PacketKind::LoginStart);
    assert_eq!(
        hook.metas[2].kind,
        super::packets::PacketKind::EncryptionRequest
    );
    assert_eq!(
        hook.metas[3].kind,
        super::packets::PacketKind::SetCompression
    );
}

#[test]
fn stream_parser_labels_legacy_play_packets() {
    use super::{state::PacketDirection, stream::MinecraftStreamParser};

    let mut parser = MinecraftStreamParser::new();
    let mut hook = MetaCollector {
        metas: Vec::new(),
        names: Vec::new(),
    };

    let handshake = HandshakeC2s {
        protocol_version: 758,
        server_address: "example.test",
        server_port: 25565,
        next_state: HandshakeNextState::Login,
    };
    let mut raw = Vec::new();
    super::types::encode_packet(&mut raw, &handshake).unwrap();
    parser.queue_slice(&raw);
    parser
        .drain_with_hook(PacketDirection::C2s, &mut hook)
        .unwrap();

    let mut body = Vec::new();
    body.extend_from_slice(Uuid::from_u64s(3, 4).as_bytes());
    write_test_string(&mut body, "joined");
    let mut raw = Vec::new();
    super::types::encode_raw_packet(&mut raw, super::packets::LoginSuccessS2c::ID, &body).unwrap();
    parser.queue_slice(&raw);
    parser
        .drain_with_hook(PacketDirection::S2c, &mut hook)
        .unwrap();
    assert_eq!(parser.state(), PacketState::Play);

    let mut body = Vec::new();
    body.extend_from_slice(&42_i32.to_be_bytes());
    body.push(0);
    let mut raw = Vec::new();
    super::types::encode_raw_packet(&mut raw, 0x24, &body).unwrap();
    parser.queue_slice(&raw);
    parser
        .drain_with_hook(PacketDirection::S2c, &mut hook)
        .unwrap();

    assert_eq!(hook.names, ["joined"]);
    assert_eq!(hook.metas[1].kind, super::packets::PacketKind::LoginSuccess);
    assert_eq!(hook.metas[2].kind, super::packets::PacketKind::JoinGame);
}
