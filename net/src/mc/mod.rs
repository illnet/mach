//! Minimal Minecraft protocol framing for handshake, status, and login start.

mod error;
mod io;
mod packets;
mod state;
mod stream;
mod types;
mod varint;

#[cfg(test)]
mod tests;

pub use error::{ProtoError, Result};
pub use packets::{
    ClientboundPacket, EncryptionRequestS2c, EncryptionResponseC2s, HandshakeC2s, JoinGameS2c,
    LoginDisconnectS2c, LoginStartC2s, LoginStartSigData, LoginSuccessS2c, PacketKind,
    PlayerPositionS2c, RespawnS2c, ServerboundPacket, SetCompressionS2c, StatusPingC2s,
    StatusPongS2c, StatusRequestC2s, StatusResponseS2c, TransferConfigS2c, packet_kind_for,
};
pub use state::{HandshakeNextState, PacketDirection, PacketState, StreamAuthMode, StreamSecurity};
pub use stream::{MinecraftStreamParser, PacketEvent, PacketHook, PacketMeta, ParsedPacket};
pub use types::{
    MAX_PACKET_SIZE, PacketDecode, PacketDecoder, PacketEncode, PacketEncoder, PacketFrame, Uuid,
    encode_packet, encode_raw_packet,
};
