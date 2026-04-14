use crate::mc::{
    Result,
    io::{read_f32_be, read_f64_be, take},
};

/// Player Position And Look / Synchronize Player Position (S2C) packet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlayerPositionS2c<'a> {
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub z: Option<f64>,
    pub yaw: Option<f32>,
    pub pitch: Option<f32>,
    pub flags: Option<u8>,
    pub trailing: &'a [u8],
}

impl<'a> PlayerPositionS2c<'a> {
    pub fn decode_body(input: &mut &'a [u8]) -> Result<Self> {
        if input.len() < 33 {
            let trailing = *input;
            *input = &[];
            return Ok(Self {
                x: None,
                y: None,
                z: None,
                yaw: None,
                pitch: None,
                flags: None,
                trailing,
            });
        }

        let x = read_f64_be(input)?;
        let y = read_f64_be(input)?;
        let z = read_f64_be(input)?;
        let yaw = read_f32_be(input)?;
        let pitch = read_f32_be(input)?;
        let flags = take(input, 1)?[0];
        let trailing = *input;
        *input = &[];
        Ok(Self {
            x: Some(x),
            y: Some(y),
            z: Some(z),
            yaw: Some(yaw),
            pitch: Some(pitch),
            flags: Some(flags),
            trailing,
        })
    }
}
