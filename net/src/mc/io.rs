use super::{
    Uuid,
    error::{ProtoError, Result},
    varint::read_varint,
};

#[inline]
/// Splits `len` bytes from front of input and advances cursor.
pub const fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    if input.len() < len {
        return Err(ProtoError::UnexpectedEof);
    }

    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

#[inline]
/// Reads one `u8`.
pub fn read_u8(input: &mut &[u8]) -> Result<u8> {
    Ok(take(input, 1)?[0])
}

#[inline]
/// Reads boolean encoded as `0` or `1`.
pub fn read_bool(input: &mut &[u8]) -> Result<bool> {
    let value = read_u8(input)?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(ProtoError::InvalidBool(other)),
    }
}

#[inline]
/// Writes boolean as `0` or `1`.
pub fn write_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

#[inline]
/// Reads big-endian `u16`.
pub fn read_u16_be(input: &mut &[u8]) -> Result<u16> {
    let bytes: [u8; 2] = take(input, 2)?.try_into().unwrap();
    Ok(u16::from_be_bytes(bytes))
}

#[inline]
/// Writes big-endian `u16`.
pub fn write_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[inline]
/// Reads big-endian `i64`.
pub fn read_i64_be(input: &mut &[u8]) -> Result<i64> {
    let bytes: [u8; 8] = take(input, 8)?.try_into().unwrap();
    Ok(i64::from_be_bytes(bytes))
}

#[inline]
/// Writes big-endian `i64`.
pub fn write_i64_be(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[inline]
/// Reads big-endian `u64`.
pub fn read_u64_be(input: &mut &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = take(input, 8)?.try_into().unwrap();
    Ok(u64::from_be_bytes(bytes))
}

#[inline]
/// Writes big-endian `u64`.
pub fn write_u64_be(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[inline]
/// Reads UUID from two big-endian `u64` words.
pub fn read_uuid(input: &mut &[u8]) -> Result<Uuid> {
    let msb = read_u64_be(input)?;
    let lsb = read_u64_be(input)?;
    Ok(Uuid::from_u64s(msb, lsb))
}

#[inline]
/// Writes UUID as two big-endian `u64` words.
pub fn write_uuid(out: &mut Vec<u8>, value: &Uuid) {
    let (msb, lsb) = value.as_u64s();
    write_u64_be(out, msb);
    write_u64_be(out, lsb);
}

/// Reads VarInt-length UTF-8 string with character bound checks.
pub fn read_string_bounded<'a>(input: &mut &'a [u8], max_chars: usize) -> Result<&'a str> {
    let byte_len = read_varint(input)?;
    if byte_len < 0 {
        return Err(ProtoError::NegativeLength(byte_len));
    }

    let byte_len = usize::try_from(byte_len).map_err(|_| ProtoError::NegativeLength(byte_len))?;
    let max_bytes = max_chars.saturating_mul(4);
    if byte_len > max_bytes {
        return Err(ProtoError::LengthTooLarge {
            max: max_bytes,
            actual: byte_len,
        });
    }

    let bytes = take(input, byte_len)?;
    let s = std::str::from_utf8(bytes).map_err(|_| ProtoError::InvalidUtf8)?;

    let char_count = s.encode_utf16().count();
    if char_count > max_chars {
        return Err(ProtoError::StringTooLong {
            max: max_chars,
            actual: char_count,
        });
    }

    Ok(s)
}

/// Writes UTF-8 string as VarInt-length payload with character bound checks.
pub fn write_string_bounded(out: &mut Vec<u8>, value: &str, max_chars: usize) -> Result<()> {
    let char_count = value.encode_utf16().count();
    if char_count > max_chars {
        return Err(ProtoError::StringTooLong {
            max: max_chars,
            actual: char_count,
        });
    }

    let len = value.len();
    if len > i32::MAX as usize {
        return Err(ProtoError::LengthTooLarge {
            max: i32::MAX as usize,
            actual: len,
        });
    }

    let len_i32 = i32::try_from(len).map_err(|_| ProtoError::LengthTooLarge {
        max: i32::MAX as usize,
        actual: len,
    })?;
    super::varint::write_varint(out, len_i32);
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
