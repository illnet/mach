use crate::mc::{Result, varint::read_varint};

/// Set Compression (S2C) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetCompressionS2c {
    pub threshold: i32,
}

impl SetCompressionS2c {
    pub const ID: i32 = 0x03;

    pub fn decode_body(input: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            threshold: read_varint(input)?,
        })
    }
}
