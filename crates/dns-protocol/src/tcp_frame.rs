//! DNS-over-TCP length-prefix frame codec (RFC 7766).
//!
//! DNS messages over TCP are preceded by a 2-byte length prefix in
//! network byte order. The maximum frame size defaults to 65535 bytes
//! (the maximum value of a u16).
///
/// ```text
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |          Length (2 bytes)     |       DNS Message        |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
use dns_types::ProtocolError;

/// Default maximum TCP DNS frame size (65535 bytes).
pub const DEFAULT_MAX_TCP_FRAME: u16 = u16::MAX;

/// Encode a DNS message with the TCP 2-byte length prefix.
///
/// # Panics
///
/// Panics if `message.len()` exceeds `u16::MAX`. In practice DNS messages
/// are well under this limit.
#[must_use]
pub fn encode_tcp_frame(message: &[u8]) -> Vec<u8> {
    let len = message.len() as u16;
    let mut frame = Vec::with_capacity(2 + message.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(message);
    frame
}

/// Decode a single DNS message from a TCP length-prefixed frame.
///
/// Reads exactly 2 bytes for the length, then reads that many bytes as
/// the DNS message. Any trailing bytes in `data` are ignored (caller can
/// check `consumed` to find where the next frame starts).
///
/// # Errors
///
/// Returns `BufferUnderflow` if fewer than 2 bytes or fewer than `length`
/// bytes remain. Returns `TcpFrameTooLarge` if the length exceeds the limit.
pub fn decode_tcp_frame<'a>(
    data: &'a [u8],
    max_frame_size: u16,
) -> Result<(&'a [u8], usize), ProtocolError> {
    if data.len() < 2 {
        return Err(ProtocolError::BufferUnderflow {
            need: 2,
            have: data.len(),
        });
    }

    let length = u16::from_be_bytes([data[0], data[1]]) as usize;

    if length > max_frame_size as usize {
        return Err(ProtocolError::TcpFrameTooLarge {
            length: length as u16,
            limit: max_frame_size,
        });
    }

    let total = 2 + length;
    if data.len() < total {
        return Err(ProtocolError::BufferUnderflow {
            need: total,
            have: data.len(),
        });
    }

    Ok((&data[2..total], total))
}

/// A streaming TCP frame decoder that handles partial reads.
///
/// Feed bytes incrementally via `feed()` and poll via `try_decode()`.
#[derive(Debug)]
pub struct TcpFrameDecoder {
    buf: Vec<u8>,
    max_frame_size: u16,
}

impl TcpFrameDecoder {
    /// Create a new decoder with default max frame size (65535).
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
            max_frame_size: DEFAULT_MAX_TCP_FRAME,
        }
    }

    /// Create a new decoder with a custom max frame size.
    #[must_use]
    pub fn with_max_frame_size(max_frame_size: u16) -> Self {
        Self {
            buf: Vec::with_capacity(4096),
            max_frame_size,
        }
    }

    /// Feed raw bytes from the TCP stream.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to decode one complete DNS message frame from the internal buffer.
    ///
    /// Returns `Ok(Some((message, consumed)))` if a complete frame is available,
    /// `Ok(None)` if more data is needed, or `Err` on malformed input.
    ///
    /// The returned `Vec<u8>` is an owned copy of the DNS message bytes.
    pub fn try_decode(&mut self) -> Result<Option<(Vec<u8>, usize)>, ProtocolError> {
        if self.buf.len() < 2 {
            return Ok(None);
        }

        let length = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;

        if length > self.max_frame_size as usize {
            return Err(ProtocolError::TcpFrameTooLarge {
                length: length as u16,
                limit: self.max_frame_size,
            });
        }

        let total = 2 + length;
        if self.buf.len() < total {
            return Ok(None);
        }

        let message = self.buf[2..total].to_vec();
        let consumed = total;

        // Consume the frame from the buffer.
        self.buf.drain(..total);

        Ok(Some((message, consumed)))
    }

    /// Reset the internal buffer, discarding any buffered data.
    pub fn reset(&mut self) {
        self.buf.clear();
    }

    /// Number of bytes currently buffered.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}

impl Default for TcpFrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// A streaming TCP frame encoder.
///
/// Wraps DNS messages with the 2-byte length prefix for TCP transmission.
#[derive(Debug)]
pub struct TcpFrameEncoder;

impl TcpFrameEncoder {
    /// Encode a DNS message with the TCP length prefix.
    #[must_use]
    pub fn encode(message: &[u8]) -> Vec<u8> {
        encode_tcp_frame(message)
    }
}

/// Helper to extract multiple DNS messages from a TCP byte buffer.
///
/// Returns a list of decoded messages and the number of bytes consumed.
/// Useful for initial buffering or bulk processing.
pub fn decode_tcp_frames(
    data: &[u8],
    max_frame_size: u16,
) -> Result<(Vec<&[u8]>, usize), ProtocolError> {
    let mut messages = Vec::new();
    let mut offset = 0;

    loop {
        if offset >= data.len() {
            break;
        }
        if data.len() - offset < 2 {
            break; // Incomplete length prefix.
        }

        let (message, consumed) = decode_tcp_frame(&data[offset..], max_frame_size)?;
        messages.push(message);
        offset += consumed;
    }

    Ok((messages, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_tcp_frame() {
        let dns_msg = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01];
        let frame = encode_tcp_frame(&dns_msg);
        assert_eq!(frame.len(), 2 + 6);
        assert_eq!(frame[0], 0x00);
        assert_eq!(frame[1], 0x06);
        assert_eq!(&frame[2..], &dns_msg);
    }

    #[test]
    fn test_decode_tcp_frame_roundtrip() {
        let dns_msg = vec![0xAB, 0xCD, 0x01, 0x00];
        let frame = encode_tcp_frame(&dns_msg);
        let (decoded, consumed) = decode_tcp_frame(&frame, DEFAULT_MAX_TCP_FRAME).unwrap();
        assert_eq!(decoded, &dns_msg[..]);
        assert_eq!(consumed, 2 + 4);
    }

    #[test]
    fn test_decode_tcp_frame_trailing_data() {
        let dns_msg = vec![0x01, 0x02];
        let frame = encode_tcp_frame(&dns_msg);
        let dns_msg2 = vec![0x03, 0x04];
        let frame2 = encode_tcp_frame(&dns_msg2);
        let mut data = frame;
        data.extend_from_slice(&frame2);

        let (decoded, consumed) = decode_tcp_frame(&data, DEFAULT_MAX_TCP_FRAME).unwrap();
        assert_eq!(decoded, &dns_msg[..]);
        assert_eq!(consumed, 4); // Only the first frame.

        // Decode second frame.
        let (decoded2, consumed2) =
            decode_tcp_frame(&data[consumed..], DEFAULT_MAX_TCP_FRAME).unwrap();
        assert_eq!(decoded2, &dns_msg2[..]);
        assert_eq!(consumed2, 4);
    }

    #[test]
    fn test_decode_tcp_frame_too_short() {
        let data = [0x00];
        assert!(decode_tcp_frame(&data, DEFAULT_MAX_TCP_FRAME).is_err());
    }

    #[test]
    fn test_decode_tcp_frame_incomplete() {
        // Length says 10 bytes, but only 3 bytes of message follow.
        let data = [0x00, 0x0A, 0x01, 0x02, 0x03];
        assert!(decode_tcp_frame(&data, DEFAULT_MAX_TCP_FRAME).is_err());
    }

    #[test]
    fn test_decode_tcp_frame_exceeds_limit() {
        // Length says 100 bytes.
        let mut data = vec![0x00, 100];
        data.extend_from_slice(&vec![0; 100]);
        assert!(decode_tcp_frame(&data, 50).is_err());
    }

    #[test]
    fn test_tcp_frame_decoder_streaming() {
        let mut decoder = TcpFrameDecoder::new();

        let msg1 = vec![0xAA, 0xBB];
        let msg2 = vec![0xCC, 0xDD, 0xEE];
        let frame1 = encode_tcp_frame(&msg1);
        let frame2 = encode_tcp_frame(&msg2);

        // Feed partial frame 1.
        decoder.feed(&frame1[..3]);
        assert!(decoder.try_decode().unwrap().is_none());

        // Feed rest of frame 1.
        decoder.feed(&frame1[3..]);
        let (msg, _) = decoder.try_decode().unwrap().unwrap();
        assert_eq!(msg, &msg1[..]);

        // Feed both bytes of frame2 at once.
        decoder.feed(&frame2);
        let (msg, _) = decoder.try_decode().unwrap().unwrap();
        assert_eq!(msg, &msg2[..]);
    }

    #[test]
    fn test_tcp_frame_decoder_multiple_frames_in_buffer() {
        let mut decoder = TcpFrameDecoder::new();

        let msg1 = vec![0x01, 0x02];
        let msg2 = vec![0x03, 0x04, 0x05];
        let mut combined = encode_tcp_frame(&msg1);
        combined.extend_from_slice(&encode_tcp_frame(&msg2));

        decoder.feed(&combined);

        let (msg, _) = decoder.try_decode().unwrap().unwrap();
        assert_eq!(msg, &msg1[..]);
        assert_eq!(decoder.buffered(), 5); // frame2 still buffered (2 prefix + 3 data)

        let (msg, _) = decoder.try_decode().unwrap().unwrap();
        assert_eq!(msg, &msg2[..]);
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn test_decode_tcp_frames_bulk() {
        let msg1 = vec![0x01, 0x02];
        let msg2 = vec![0x03, 0x04];
        let mut data = encode_tcp_frame(&msg1);
        data.extend_from_slice(&encode_tcp_frame(&msg2));

        let (messages, consumed) = decode_tcp_frames(&data, DEFAULT_MAX_TCP_FRAME).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], &msg1[..]);
        assert_eq!(messages[1], &msg2[..]);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_max_frame_size_boundary() {
        // Exactly at limit should work.
        let mut data = vec![0x00, 10]; // length = 10
        data.extend_from_slice(&vec![0; 10]);
        let result = decode_tcp_frame(&data, 10);
        assert!(result.is_ok());

        // Over limit should fail.
        let mut data2 = vec![0x00, 11]; // length = 11
        data2.extend_from_slice(&vec![0; 11]);
        let result2 = decode_tcp_frame(&data2, 10);
        assert!(result2.is_err());
    }
}
