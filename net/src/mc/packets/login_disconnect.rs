use crate::mc::{
    PacketDecode, PacketEncode, Result,
    io::{read_string_bounded, write_string_bounded},
};

/// Login disconnect (S2C) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginDisconnectS2c<'a> {
    pub reason: &'a str,
}

impl<'a> LoginDisconnectS2c<'a> {
    pub const ID: i32 = 0x00;

    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Ok(Self {
            reason: read_string_bounded(input, 32_767)?,
        })
    }
}

impl<'a> PacketDecode<'a> for LoginDisconnectS2c<'a> {
    const ID: i32 = LoginDisconnectS2c::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        LoginDisconnectS2c::decode_body(input)
    }
}

impl PacketEncode for LoginDisconnectS2c<'_> {
    const ID: i32 = LoginDisconnectS2c::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_string_bounded(out, self.reason, 32_767)
    }
}
