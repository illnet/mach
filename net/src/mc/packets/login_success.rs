use crate::mc::{
    Result, Uuid,
    io::{read_string_bounded, read_uuid},
};

/// Login Success (S2C) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginSuccessS2c<'a> {
    pub uuid: Option<Uuid>,
    pub uuid_text: Option<&'a str>,
    pub username: &'a str,
    pub trailing: &'a [u8],
}

impl<'a> LoginSuccessS2c<'a> {
    pub const ID: i32 = 0x02;

    pub fn decode_body_with_version(input: &mut &'a [u8], protocol_version: i32) -> Result<Self> {
        let (uuid, uuid_text) = if protocol_version >= 735 {
            (Some(read_uuid(input)?), None)
        } else {
            (None, Some(read_string_bounded(input, 36)?))
        };
        let username = read_string_bounded(input, 16)?;
        let trailing = *input;
        *input = &[];
        Ok(Self {
            uuid,
            uuid_text,
            username,
            trailing,
        })
    }
}
