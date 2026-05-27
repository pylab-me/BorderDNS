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
/// Uses a read cursor (`read_pos`) instead of `drain()` to avoid O(n)
/// memmove on every decoded frame. The buffer is compacted only when
/// the consumed region exceeds half the buffer capacity.
#[derive(Debug)]
pub struct TcpFrameDecoder {
    buf: Vec<u8>,
    read_pos: usize,
    max_frame_size: u16,
}

impl TcpFrameDecoder {
    /// Create a new decoder with default max frame size (65535).
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(4096),
            read_pos: 0,
            max_frame_size: DEFAULT_MAX_TCP_FRAME,
        }
    }

    /// Create a new decoder with a custom max frame size.
    #[must_use]
    pub fn with_max_frame_size(max_frame_size: u16) -> Self {
        Self {
            buf: Vec::with_capacity(4096),
            read_pos: 0,
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
        let available = self.buf.len() - self.read_pos;

        if available < 2 {
            return Ok(None);
        }

        let header_start = self.read_pos;
        let length =
            u16::from_be_bytes([self.buf[header_start], self.buf[header_start + 1]]) as usize;

        if length > self.max_frame_size as usize {
            return Err(ProtocolError::TcpFrameTooLarge {
                length: length as u16,
                limit: self.max_frame_size,
            });
        }

        let total = 2 + length;
        if available < total {
            return Ok(None);
        }

        // Copy message bytes out (skip the 2-byte length prefix).
        let message = self.buf[header_start + 2..header_start + total].to_vec();
        self.read_pos += total;

        // Compact: if we've consumed more than half the buffer, memmove the
        // remainder to the front. This amortises the copy cost.
        if self.read_pos > 0 && self.read_pos >= self.buf.len() / 2 {
            self.buf.drain(..self.read_pos);
            self.read_pos = 0;
        }

        Ok(Some((message, total)))
    }

    /// Reset the internal buffer, discarding any buffered data.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.read_pos = 0;
    }

    /// Number of bytes currently buffered (including already-consumed bytes).
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.read_pos
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
#[path = "tcp_frame_tests.rs"]
mod tests;
