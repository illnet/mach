mod encryption_request;
mod encryption_response;
mod handshake;
mod join_game;
mod login_disconnect;
mod login_start;
mod login_success;
mod player_position;
mod respawn;
mod set_compression;
mod status_ping;
mod status_pong;
mod status_request;
mod status_response;
mod transfer_config;

pub use encryption_request::EncryptionRequestS2c;
pub use encryption_response::EncryptionResponseC2s;
pub use handshake::HandshakeC2s;
pub use join_game::JoinGameS2c;
pub use login_disconnect::LoginDisconnectS2c;
pub use login_start::{LoginStartC2s, LoginStartSigData};
pub use login_success::LoginSuccessS2c;
pub use player_position::PlayerPositionS2c;
pub use respawn::RespawnS2c;
pub use set_compression::SetCompressionS2c;
pub use status_ping::StatusPingC2s;
pub use status_pong::StatusPongS2c;
pub use status_request::StatusRequestC2s;
pub use status_response::StatusResponseS2c;
pub use transfer_config::TransferConfigS2c;

use super::{
    error::{ProtoError, Result, debug_log_error},
    io::take,
    state::{PacketDirection, PacketState},
    types::PacketFrame,
    varint::read_varint,
};

/// Packet kind labels stable enough for WAF rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Handshake,
    LoginStart,
    EncryptionRequest,
    EncryptionResponse,
    SetCompression,
    LoginSuccess,
    JoinGame,
    Respawn,
    PlayerPosition,
    StatusRequest,
    StatusPing,
    StatusResponse,
    StatusPong,
    LoginDisconnect,
    Unknown,
}

/// Any serverbound packet supported by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerboundPacket<'a> {
    Handshake(HandshakeC2s<'a>),
    StatusRequest(StatusRequestC2s),
    StatusPing(StatusPingC2s),
    LoginStart(LoginStartC2s<'a>),
    EncryptionResponse(EncryptionResponseC2s<'a>),
}

/// Any clientbound packet supported by this crate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClientboundPacket<'a> {
    StatusResponse(StatusResponseS2c<'a>),
    StatusPong(StatusPongS2c),
    LoginDisconnect(LoginDisconnectS2c<'a>),
    EncryptionRequest(EncryptionRequestS2c<'a>),
    SetCompression(SetCompressionS2c),
    LoginSuccess(LoginSuccessS2c<'a>),
    JoinGame(JoinGameS2c<'a>),
    Respawn(RespawnS2c<'a>),
    PlayerPosition(PlayerPositionS2c<'a>),
}

impl PacketFrame {
    pub fn decode_serverbound(
        &self,
        state: PacketState,
        protocol_version: i32,
    ) -> Result<ServerboundPacket<'_>> {
        ServerboundPacket::decode(state, protocol_version, self)
    }
}

impl<'a> ServerboundPacket<'a> {
    pub fn decode(
        state: PacketState,
        protocol_version: i32,
        frame: &'a PacketFrame,
    ) -> Result<Self> {
        let mut input = frame.body.as_slice();
        let packet = match state {
            PacketState::Handshaking => {
                if frame.id != HandshakeC2s::ID {
                    return Err(ProtoError::InvalidPacketId {
                        state,
                        id: frame.id,
                    });
                }
                HandshakeC2s::decode_body(&mut input).map(ServerboundPacket::Handshake)
            }
            PacketState::Status => match frame.id {
                StatusRequestC2s::ID => {
                    StatusRequestC2s::decode_body(&mut input).map(ServerboundPacket::StatusRequest)
                }
                StatusPingC2s::ID => {
                    StatusPingC2s::decode_body(&mut input).map(ServerboundPacket::StatusPing)
                }
                _ => Err(ProtoError::InvalidPacketId {
                    state,
                    id: frame.id,
                }),
            },
            PacketState::Login => match frame.id {
                LoginStartC2s::ID => {
                    LoginStartC2s::decode_body_with_version(&mut input, protocol_version)
                        .map(ServerboundPacket::LoginStart)
                }
                EncryptionResponseC2s::ID => EncryptionResponseC2s::decode_body(&mut input)
                    .map(ServerboundPacket::EncryptionResponse),
                _ => Err(ProtoError::InvalidPacketId {
                    state,
                    id: frame.id,
                }),
            },
            PacketState::Configuration | PacketState::Play => Err(ProtoError::InvalidPacketId {
                state,
                id: frame.id,
            }),
        };

        let packet = match packet {
            Ok(value) => value,
            Err(err) => {
                debug_log_error("packet body decode failed", &err);
                return Err(err);
            }
        };

        if !input.is_empty() {
            let err = ProtoError::TrailingBytes(input.len());
            debug_log_error("packet had trailing bytes", &err);
            return Err(err);
        }

        Ok(packet)
    }

    pub fn decode_known(
        state: PacketState,
        protocol_version: i32,
        kind: PacketKind,
        frame: &'a PacketFrame,
    ) -> Result<Option<Self>> {
        if kind == PacketKind::Unknown {
            return Ok(None);
        }
        match kind {
            PacketKind::Handshake
            | PacketKind::LoginStart
            | PacketKind::EncryptionResponse
            | PacketKind::StatusRequest
            | PacketKind::StatusPing => Self::decode(state, protocol_version, frame).map(Some),
            _ => Ok(None),
        }
    }
}

impl<'a> ClientboundPacket<'a> {
    pub fn decode_known(
        state: PacketState,
        protocol_version: i32,
        kind: PacketKind,
        frame: &'a PacketFrame,
    ) -> Result<Option<Self>> {
        let mut input = frame.body.as_slice();
        let packet = match (state, kind) {
            (PacketState::Status, PacketKind::StatusResponse) => {
                Some(StatusResponseS2c::decode_body(&mut input).map(Self::StatusResponse)?)
            }
            (PacketState::Status, PacketKind::StatusPong) => {
                Some(StatusPongS2c::decode_body(&mut input).map(Self::StatusPong)?)
            }
            (PacketState::Login, PacketKind::LoginDisconnect) => {
                Some(LoginDisconnectS2c::decode_body(&mut input).map(Self::LoginDisconnect)?)
            }
            (PacketState::Login, PacketKind::EncryptionRequest) => Some(Self::EncryptionRequest(
                EncryptionRequestS2c::decode_body_with_version(&mut input, protocol_version)?,
            )),
            (PacketState::Login, PacketKind::SetCompression) => {
                Some(SetCompressionS2c::decode_body(&mut input).map(Self::SetCompression)?)
            }
            (PacketState::Login, PacketKind::LoginSuccess) => Some(Self::LoginSuccess(
                LoginSuccessS2c::decode_body_with_version(&mut input, protocol_version)?,
            )),
            (PacketState::Play, PacketKind::JoinGame)
            | (PacketState::Configuration, PacketKind::JoinGame) => {
                Some(JoinGameS2c::decode_body(&mut input).map(Self::JoinGame)?)
            }
            (PacketState::Play, PacketKind::Respawn) => {
                Some(Self::Respawn(RespawnS2c::decode_body(&mut input)))
            }
            (PacketState::Play, PacketKind::PlayerPosition) => {
                Some(PlayerPositionS2c::decode_body(&mut input).map(Self::PlayerPosition)?)
            }
            _ => None,
        };

        if !input.is_empty() {
            return Err(ProtoError::TrailingBytes(input.len()));
        }
        Ok(packet)
    }
}

pub(crate) fn read_byte_array<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let len = read_varint(input)?;
    if len < 0 {
        return Err(ProtoError::NegativeLength(len));
    }
    let len = usize::try_from(len).map_err(|_| ProtoError::NegativeLength(len))?;
    take(input, len)
}

pub fn packet_kind_for(
    state: PacketState,
    direction: PacketDirection,
    protocol_version: i32,
    id: i32,
) -> PacketKind {
    match (state, direction, id) {
        (PacketState::Handshaking, PacketDirection::C2s, 0x00) => PacketKind::Handshake,
        (PacketState::Status, PacketDirection::C2s, 0x00) => PacketKind::StatusRequest,
        (PacketState::Status, PacketDirection::C2s, 0x01) => PacketKind::StatusPing,
        (PacketState::Status, PacketDirection::S2c, 0x00) => PacketKind::StatusResponse,
        (PacketState::Status, PacketDirection::S2c, 0x01) => PacketKind::StatusPong,
        (PacketState::Login, PacketDirection::C2s, 0x00) => PacketKind::LoginStart,
        (PacketState::Login, PacketDirection::C2s, 0x01) => PacketKind::EncryptionResponse,
        (PacketState::Login, PacketDirection::S2c, 0x00) => PacketKind::LoginDisconnect,
        (PacketState::Login, PacketDirection::S2c, 0x01) => PacketKind::EncryptionRequest,
        (PacketState::Login, PacketDirection::S2c, 0x02) => PacketKind::LoginSuccess,
        (PacketState::Login, PacketDirection::S2c, 0x03) => PacketKind::SetCompression,
        (PacketState::Configuration, PacketDirection::S2c, _)
            if is_join_game_id(protocol_version, id) =>
        {
            PacketKind::JoinGame
        }
        (PacketState::Play, PacketDirection::S2c, _) if is_join_game_id(protocol_version, id) => {
            PacketKind::JoinGame
        }
        (PacketState::Play, PacketDirection::S2c, _) if is_respawn_id(protocol_version, id) => {
            PacketKind::Respawn
        }
        (PacketState::Play, PacketDirection::S2c, _)
            if is_player_position_id(protocol_version, id) =>
        {
            PacketKind::PlayerPosition
        }
        _ => PacketKind::Unknown,
    }
}

fn is_join_game_id(protocol_version: i32, id: i32) -> bool {
    matches!(
        (protocol_version, id),
        (47, 0x01) | (107..=340, 0x23) | (393..=404, 0x25) | (477..=578, 0x26) | (735..=758, 0x24)
    )
}

fn is_respawn_id(protocol_version: i32, id: i32) -> bool {
    matches!(
        (protocol_version, id),
        (47, 0x07)
            | (107..=335, 0x33)
            | (338..=340, 0x35)
            | (393..=404, 0x38)
            | (477..=498, 0x3a)
            | (573..=578, 0x3b)
            | (735..=758, 0x39)
    )
}

fn is_player_position_id(protocol_version: i32, id: i32) -> bool {
    matches!(
        (protocol_version, id),
        (47, 0x08)
            | (107..=340, 0x2f)
            | (393..=404, 0x32)
            | (477..=498, 0x35)
            | (573..=578, 0x36)
            | (735..=758, 0x34)
    )
}
