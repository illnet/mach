use crate::mc::{
    Result,
    io::{read_bool, read_string_bounded},
    packets::read_byte_array,
};

/// Encryption Request (S2C) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionRequestS2c<'a> {
    pub server_id: &'a str,
    pub public_key: &'a [u8],
    pub verify_token: &'a [u8],
    /// Present in modern protocol versions where encryption can be requested without online auth.
    pub should_authenticate: Option<bool>,
}

impl<'a> EncryptionRequestS2c<'a> {
    pub const ID: i32 = 0x01;

    pub fn decode_body_with_version(input: &mut &'a [u8], protocol_version: i32) -> Result<Self> {
        let server_id = read_string_bounded(input, 20)?;
        let public_key = read_byte_array(input)?;
        let verify_token = read_byte_array(input)?;
        let should_authenticate = if protocol_version >= 766 && !input.is_empty() {
            Some(read_bool(input)?)
        } else {
            None
        };
        Ok(Self {
            server_id,
            public_key,
            verify_token,
            should_authenticate,
        })
    }
}
