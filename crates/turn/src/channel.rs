use crate::error::TurnError;
use bytes::{BufMut, Bytes, BytesMut};

/// Minimum valid TURN channel number.
pub const CHANNEL_MIN: u16 = 0x4000;

/// Maximum valid TURN channel number.
pub const CHANNEL_MAX: u16 = 0x7FFF;

/// ChannelData header length in bytes (2 bytes channel + 2 bytes length).
pub const CHANNEL_DATA_HEADER_LEN: usize = 4;

/// Demultiplexing helper: checks if the first byte belongs to ChannelData (0x4000..=0x7FFF)
/// as opposed to a STUN message (0x0000..=0x03FF) or DTLS/RTP.
#[inline]
pub fn is_channel_data(buf: &[u8]) -> bool {
    if buf.len() < CHANNEL_DATA_HEADER_LEN {
        return false;
    }
    let first_byte = buf[0];
    (0x40..=0x7F).contains(&first_byte)
}

/// Encode a ChannelData message into destination buffer.
pub fn encode_channel_data(
    channel_number: u16,
    payload: &[u8],
    pad_to_4: bool,
    out: &mut BytesMut,
) -> Result<(), TurnError> {
    if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel_number) {
        return Err(TurnError::InvalidChannelNumber(channel_number));
    }

    out.reserve(CHANNEL_DATA_HEADER_LEN + payload.len() + 4);
    out.put_u16(channel_number);
    out.put_u16(payload.len() as u16);
    out.put_slice(payload);

    if pad_to_4 {
        let padding = (4 - (payload.len() % 4)) % 4;
        for _ in 0..padding {
            out.put_u8(0);
        }
    }

    Ok(())
}

/// Decode a ChannelData message from buffer.
/// Returns `(channel_number, payload, total_consumed_bytes)`.
pub fn decode_channel_data(buf: &[u8]) -> Result<(u16, Bytes, usize), TurnError> {
    if buf.len() < CHANNEL_DATA_HEADER_LEN {
        return Err(TurnError::BufferTooShort {
            expected: CHANNEL_DATA_HEADER_LEN,
            actual: buf.len(),
        });
    }

    let channel_number = u16::from_be_bytes([buf[0], buf[1]]);
    if !(CHANNEL_MIN..=CHANNEL_MAX).contains(&channel_number) {
        return Err(TurnError::InvalidChannelNumber(channel_number));
    }

    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let total_len = CHANNEL_DATA_HEADER_LEN + length;
    if buf.len() < total_len {
        return Err(TurnError::BufferTooShort {
            expected: total_len,
            actual: buf.len(),
        });
    }

    let payload = Bytes::copy_from_slice(&buf[CHANNEL_DATA_HEADER_LEN..total_len]);
    Ok((channel_number, payload, total_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_data_encode_decode_roundtrip() {
        let mut buf = BytesMut::new();
        let payload = b"WireGuard encapsulated data packet over TURN channel";
        encode_channel_data(0x4001, payload, false, &mut buf).expect("encode channel data");

        assert!(is_channel_data(&buf));

        let (chan, decoded_payload, consumed) =
            decode_channel_data(&buf).expect("decode channel data");
        assert_eq!(chan, 0x4001);
        assert_eq!(decoded_payload, &payload[..]);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_invalid_channel_number_rejected() {
        let mut buf = BytesMut::new();
        assert!(encode_channel_data(0x0001, b"test", false, &mut buf).is_err());
        assert!(encode_channel_data(0x8000, b"test", false, &mut buf).is_err());
    }
}
