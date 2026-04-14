use crate::mc::{
    PacketDecode, PacketEncode, Result,
    io::{read_i64_be, write_i64_be},
};

/// Status ping (C2S) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusPingC2s {
    pub payload: i64,
}

impl StatusPingC2s {
    pub const ID: i32 = 0x01;

    pub fn decode_body(input: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            payload: read_i64_be(input)?,
        })
    }
}

impl<'a> PacketDecode<'a> for StatusPingC2s {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body(input)
    }
}

impl PacketEncode for StatusPingC2s {
    const ID: i32 = Self::ID;

    fn encode_body(&self, out: &mut Vec<u8>) -> Result<()> {
        write_i64_be(out, self.payload);
        Ok(())
    }
}
