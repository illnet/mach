use crate::mc::{Result, io::read_i32_be};

/// Join Game / Login Play (S2C) packet. Large version-specific tail is retained raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinGameS2c<'a> {
    pub entity_id: i32,
    pub trailing: &'a [u8],
}

impl<'a> JoinGameS2c<'a> {
    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        let entity_id = read_i32_be(input)?;
        let trailing = *input;
        *input = &[];
        Ok(Self {
            entity_id,
            trailing,
        })
    }
}
