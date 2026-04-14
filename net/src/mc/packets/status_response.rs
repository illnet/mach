use crate::mc::{
    PacketDecode, PacketEncode, Result,
    io::{read_string_bounded, write_string_bounded},
};

/// Status response (S2C) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusResponseS2c<'a> {
    pub json: &'a str,
}

impl<'a> StatusResponseS2c<'a> {
    pub const ID: i32 = 0x00;

    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Ok(Self {
            json: read_string_bounded(input, 32_767)?,
        })
    }
}

impl<'a> PacketDecode<'a> for StatusResponseS2c<'a> {
    const ID: i32 = StatusResponseS2c::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        StatusResponseS2c::decode_body(input)
    }
}

impl PacketEncode for StatusResponseS2c<'_> {
    const ID: i32 = StatusResponseS2c::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_string_bounded(out, self.json, 32_767)
    }
}
