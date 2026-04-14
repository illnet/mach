use crate::mc::{PacketDecode, PacketEncode, Result};

/// Status request (C2S) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusRequestC2s;

impl StatusRequestC2s {
    pub const ID: i32 = 0x00;

    pub const fn decode_body(_input: &mut &[u8]) -> Result<Self> {
        Ok(Self)
    }
}

impl<'a> PacketDecode<'a> for StatusRequestC2s {
    const ID: i32 = Self::ID;

    fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        Self::decode_body(input)
    }
}

impl PacketEncode for StatusRequestC2s {
    const ID: i32 = Self::ID;

    fn encode_body(&self, _out: &mut Vec<u8>) -> Result<()> {
        Ok(())
    }
}
