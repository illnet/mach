use crate::mc::{
    PacketDecode, PacketEncode, ProtoError, Result, Uuid,
    io::{
        read_bool, read_i64_be, read_string_bounded, read_uuid, take, write_bool, write_i64_be,
        write_string_bounded, write_uuid,
    },
    varint::{read_varint, write_varint},
};

const LOGIN_START_SIGNATURE_DATA_PROTOCOL: i32 = 759;
const LOGIN_START_UUID_PROTOCOL: i32 = 766;

/// Login start (C2S) packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginStartC2s<'a> {
    pub username: &'a str,
    pub profile_id: Option<Uuid>,
    pub sig_data: Option<LoginStartSigData<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginStartSigData<'a> {
    pub timestamp: i64,
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}

impl<'a> LoginStartC2s<'a> {
    pub const ID: i32 = 0x00;

    pub fn decode_body_with_version(input: &mut &'a [u8], protocol_version: i32) -> Result<Self> {
        let username = read_string_bounded(input, 16)?;
        let mut profile_id = None;
        let mut sig_data = None;

        if input.is_empty() {
            return Ok(Self {
                username,
                profile_id,
                sig_data,
            });
        }

        if protocol_version >= LOGIN_START_UUID_PROTOCOL {
            if input.len() < 16 {
                return Err(ProtoError::UnexpectedEof);
            }
            profile_id = Some(read_uuid(input)?);
        } else if protocol_version >= LOGIN_START_SIGNATURE_DATA_PROTOCOL {
            let has_sig_data = read_bool(input)?;
            if has_sig_data {
                if input.len() == 16 {
                    profile_id = Some(read_uuid(input)?);
                    *input = &[];
                    return Ok(Self {
                        username,
                        profile_id,
                        sig_data,
                    });
                }

                let timestamp = read_i64_be(input)?;
                let public_key_len = read_varint(input)?;
                if public_key_len < 0 {
                    return Err(ProtoError::NegativeLength(public_key_len));
                }
                let public_key_len_usize = usize::try_from(public_key_len)
                    .map_err(|_| ProtoError::NegativeLength(public_key_len))?;
                let public_key = take(input, public_key_len_usize)?;
                let signature_len = read_varint(input)?;
                if signature_len < 0 {
                    return Err(ProtoError::NegativeLength(signature_len));
                }
                let signature_len_usize = usize::try_from(signature_len)
                    .map_err(|_| ProtoError::NegativeLength(signature_len))?;
                let signature = take(input, signature_len_usize)?;
                sig_data = Some(LoginStartSigData {
                    timestamp,
                    public_key,
                    signature,
                });
            }
        }
        *input = &[];

        Ok(Self {
            username,
            profile_id,
            sig_data,
        })
    }

    pub fn encode_body_with_version(&self, out: &mut Vec<u8>, protocol_version: i32) -> Result<()> {
        write_string_bounded(out, self.username, 16)?;
        if protocol_version >= LOGIN_START_UUID_PROTOCOL {
            let uuid = self
                .profile_id
                .ok_or(ProtoError::MissingField("login_start.uuid"))?;
            write_uuid(out, &uuid);
            return Ok(());
        }

        if protocol_version >= LOGIN_START_SIGNATURE_DATA_PROTOCOL {
            let has_sig_data = self.sig_data.is_some();
            write_bool(out, has_sig_data);
            if let Some(sig_data) = self.sig_data {
                write_i64_be(out, sig_data.timestamp);
                let public_key_len_i32 =
                    i32::try_from(sig_data.public_key.len()).map_err(|_| {
                        ProtoError::LengthTooLarge {
                            max: i32::MAX as usize,
                            actual: sig_data.public_key.len(),
                        }
                    })?;
                write_varint(out, public_key_len_i32);
                out.extend_from_slice(sig_data.public_key);
                let signature_len_i32 = i32::try_from(sig_data.signature.len()).map_err(|_| {
                    ProtoError::LengthTooLarge {
                        max: i32::MAX as usize,
                        actual: sig_data.signature.len(),
                    }
                })?;
                write_varint(out, signature_len_i32);
                out.extend_from_slice(sig_data.signature);
            }
        }
        Ok(())
    }
}

impl<'a> PacketDecode<'a> for LoginStartC2s<'a> {
    const ID: i32 = LoginStartC2s::ID;

    fn decode_body(_input: &mut &'a [u8]) -> Result<Self> {
        Err(ProtoError::MissingField("login_start.protocol_version"))
    }
}

impl PacketEncode for LoginStartC2s<'_> {
    const ID: i32 = LoginStartC2s::ID;

    fn encode_body(&self, _out: &mut Vec<u8>) -> Result<()> {
        Err(ProtoError::MissingField("login_start.protocol_version"))
    }
}
