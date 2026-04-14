/// Respawn (S2C) packet. Body is highly version-specific; retained raw for metadata hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RespawnS2c<'a> {
    pub body: &'a [u8],
}

impl<'a> RespawnS2c<'a> {
    pub fn decode_body(input: &mut &'a [u8]) -> Self {
        let body = *input;
        *input = &[];
        Self { body }
    }
}
