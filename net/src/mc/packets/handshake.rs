use crate::mc::{
    HandshakeNextState, PacketDecode, PacketEncode, ProtoError, Result,
    io::{read_string_bounded, read_u16_be, write_string_bounded, write_u16_be},
    varint::{read_varint, write_varint},
};

/// Handshake (C2S) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeC2s<'a> {
    pub protocol_version: i32,
    pub server_address: &'a str,
    pub server_port: u16,
    pub next_state: HandshakeNextState,
}

impl<'a> HandshakeC2s<'a> {
    pub const ID: i32 = 0x00;

    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        let protocol_version = read_varint(input)?;
        let server_address = read_string_bounded(input, 255)?;
        let server_port = read_u16_be(input)?;
        let next_state_raw = read_varint(input)?;
        let next_state = match next_state_raw {
            1 => HandshakeNextState::Status,
            2 => HandshakeNextState::Login,
            other => return Err(ProtoError::InvalidHandshakeState(other)),
        };

        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }
}

impl<'a> PacketDecode<'a> for HandshakeC2s<'a> {
    const ID: i32 = HandshakeC2s::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        HandshakeC2s::decode_body(input)
    }
}

impl PacketEncode for HandshakeC2s<'_> {
    const ID: i32 = HandshakeC2s::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_varint(out, self.protocol_version);
        write_string_bounded(out, self.server_address, 255)?;
        write_u16_be(out, self.server_port);
        let next = match self.next_state {
            HandshakeNextState::Status => 1,
            HandshakeNextState::Login => 2,
        };
        write_varint(out, next);
        Ok(())
    }
}
