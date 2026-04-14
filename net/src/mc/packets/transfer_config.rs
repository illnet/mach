use crate::mc::{
    PacketEncode, Result,
    io::{write_string_bounded, write_u16_be},
};

/// Transfer in Configuration state (S2C) — Minecraft 1.20.5+ only (protocol >= 766).
/// Instructs the client to reconnect to a different server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferConfigS2c<'a> {
    pub host: &'a str,
    pub port: u16,
}

impl TransferConfigS2c<'_> {
    pub const ID: i32 = 0x0B;
}

impl PacketEncode for TransferConfigS2c<'_> {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_string_bounded(out, self.host, 255)?;
        write_u16_be(out, self.port);
        Ok(())
    }
}
