use crate::mc::{Result, packets::read_byte_array};

/// Encryption Response (C2S) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionResponseC2s<'a> {
    pub shared_secret: &'a [u8],
    pub verify_token: &'a [u8],
    pub trailing: &'a [u8],
}

impl<'a> EncryptionResponseC2s<'a> {
    pub const ID: i32 = 0x01;

    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        let shared_secret = read_byte_array(input)?;
        let verify_token = if input.is_empty() {
            &[]
        } else {
            read_byte_array(input)?
        };
        let trailing = *input;
        *input = &[];
        Ok(Self {
            shared_secret,
            verify_token,
            trailing,
        })
    }
}
