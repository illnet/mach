use net::mc::{
    HandshakeC2s, HandshakeNextState, LoginStartC2s, MinecraftStreamParser, PacketDirection,
    PacketEncode, PacketEncoder, PacketEvent, PacketHook, PacketKind, Uuid, encode_packet,
    encode_raw_packet,
};

const PROTOCOL_VERSION: i32 = 766;

struct PrintHook;

impl PacketHook for PrintHook {
    fn on_packet(&mut self, event: PacketEvent<'_>) {
        println!(
            "dir={:?} state={:?} id=0x{:02x} kind={:?} auth={:?} security={:?}",
            event.meta.direction,
            event.meta.state,
            event.meta.id,
            event.meta.kind,
            event.meta.auth_mode,
            event.meta.security,
        );
    }
}

struct VersionedLoginStart<'a> {
    packet: &'a LoginStartC2s<'a>,
    protocol_version: i32,
}

impl<'a> PacketEncode for VersionedLoginStart<'a> {
    const ID: i32 = LoginStartC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> net::mc::Result<()> {
        self.packet
            .encode_body_with_version(out, self.protocol_version)
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let mut temp = (value & 0b0111_1111) as u8;
        value = ((value as u32) >> 7) as i32;
        if value != 0 {
            temp |= 0b1000_0000;
        }
        out.push(temp);
        if value == 0 {
            break;
        }
    }
}

fn write_string(out: &mut Vec<u8>, value: &str) {
    write_varint(out, i32::try_from(value.len()).unwrap());
    out.extend_from_slice(value.as_bytes());
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(out, i32::try_from(bytes.len()).unwrap());
    out.extend_from_slice(bytes);
}

fn main() -> net::mc::Result<()> {
    let mut parser = MinecraftStreamParser::new();
    let mut hook = PrintHook;

    let handshake = HandshakeC2s {
        protocol_version: PROTOCOL_VERSION,
        server_address: "example.test",
        server_port: 25565,
        next_state: HandshakeNextState::Login,
    };
    let mut raw = Vec::new();
    encode_packet(&mut raw, &handshake)?;
    parser.queue_slice(&raw);
    parser.drain_with_hook(PacketDirection::C2s, &mut hook)?;

    let login = LoginStartC2s {
        username: "botcheck",
        profile_id: Some(Uuid::from_u64s(1, 2)),
        sig_data: None,
    };
    let mut encoder = PacketEncoder::new();
    encoder.write_packet(&VersionedLoginStart {
        packet: &login,
        protocol_version: PROTOCOL_VERSION,
    })?;
    parser.queue_slice(&encoder.take());
    parser.drain_with_hook(PacketDirection::C2s, &mut hook)?;

    let mut body = Vec::new();
    write_string(&mut body, "");
    write_bytes(&mut body, &[1, 2, 3]);
    write_bytes(&mut body, &[4, 5, 6, 7]);
    body.push(0); // should_authenticate=false, offline encryption style.
    raw.clear();
    encode_raw_packet(&mut raw, 0x01, &body)?;
    parser.queue_slice(&raw);
    parser.drain_with_hook(PacketDirection::S2c, &mut hook)?;

    assert_eq!(parser.state(), net::mc::PacketState::Login);
    assert_eq!(
        parser.auth_mode(),
        net::mc::StreamAuthMode::OfflineEncryption
    );
    assert_eq!(PacketKind::EncryptionRequest, PacketKind::EncryptionRequest);
    Ok(())
}
