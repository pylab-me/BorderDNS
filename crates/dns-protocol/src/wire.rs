//! Cursor-based wire reader for DNS message decoding.
//!
//! `WireReader` wraps a byte slice and tracks read position. All multi-byte
//! integers are read in network byte order (big-endian) per RFC 1035.

use dns_types::ProtocolError;
use smallvec::SmallVec;

// Maximum depth for compression pointer chains (referenced by name module).

/// Cursor-based reader for DNS wire format.
///
/// Tracks read position and enforces bounds. All methods return
/// `Result` to avoid panics on malformed input.
#[derive(Debug, Clone)]
pub struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Saved positions for backtracking (e.g., RDATA boundary).
    /// SmallVec avoids heap allocation for typical 1–2 level nesting.
    saved_pos: SmallVec<[usize; 4]>,
}

impl<'a> WireReader<'a> {
    /// Create a new reader over the given buffer.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            saved_pos: SmallVec::new(),
        }
    }

    /// Current read position.
    #[must_use]
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Set read position (must be within buffer bounds).
    ///
    /// # Errors
    ///
    /// Returns `BufferUnderflow` if `new_pos` exceeds buffer length.
    pub fn set_pos(&mut self, new_pos: usize) -> Result<(), ProtocolError> {
        if new_pos > self.buf.len() {
            return Err(ProtocolError::BufferUnderflow {
                need: 0,
                have: self.buf.len().saturating_sub(self.pos),
            });
        }
        self.pos = new_pos;
        Ok(())
    }

    /// Remaining bytes in buffer.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Full message buffer (needed for compression pointer resolution).
    #[must_use]
    pub fn message_buf(&self) -> &'a [u8] {
        self.buf
    }

    /// Save the current position for later restore.
    pub fn save_position(&mut self) {
        self.saved_pos.push(self.pos);
    }

    /// Restore the last saved position.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError` if no position has been saved.
    pub fn restore_position(&mut self) -> Result<(), ProtocolError> {
        let saved = self
            .saved_pos
            .pop()
            .ok_or_else(|| ProtocolError::DecodeError("no saved position to restore".into()))?;
        self.pos = saved;
        Ok(())
    }

    /// Read a single byte and advance.
    ///
    /// # Errors
    ///
    /// Returns `BufferUnderflow` if no bytes remain.
    pub fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        if self.pos >= self.buf.len() {
            return Err(ProtocolError::BufferUnderflow { need: 1, have: 0 });
        }
        let val = self.buf[self.pos];
        self.pos += 1;
        Ok(val)
    }

    /// Read a 16-bit unsigned integer in network byte order.
    ///
    /// # Errors
    ///
    /// Returns `BufferUnderflow` if fewer than 2 bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        let remaining = self.remaining();
        if remaining < 2 {
            return Err(ProtocolError::BufferUnderflow {
                need: 2,
                have: remaining,
            });
        }
        let val = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    /// Read a 32-bit unsigned integer in network byte order.
    ///
    /// # Errors
    ///
    /// Returns `BufferUnderflow` if fewer than 4 bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, ProtocolError> {
        let remaining = self.remaining();
        if remaining < 4 {
            return Err(ProtocolError::BufferUnderflow {
                need: 4,
                have: remaining,
            });
        }
        let val = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    /// Read exactly `len` bytes without copying.
    ///
    /// # Errors
    ///
    /// Returns `BufferUnderflow` if fewer than `len` bytes remain.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        let remaining = self.remaining();
        if remaining < len {
            return Err(ProtocolError::BufferUnderflow {
                need: len,
                have: remaining,
            });
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Peek at the next byte without advancing.
    ///
    /// # Errors
    ///
    /// Returns `BufferUnderflow` if no bytes remain.
    pub fn peek_u8(&self) -> Result<u8, ProtocolError> {
        if self.pos >= self.buf.len() {
            return Err(ProtocolError::BufferUnderflow { need: 1, have: 0 });
        }
        Ok(self.buf[self.pos])
    }

    /// Check if the next byte has the top two bits set (compression pointer marker).
    #[must_use]
    pub fn is_compression_pointer(&self) -> bool {
        self.peek_u8().map(|b| b & 0xC0 == 0xC0).unwrap_or(false)
    }
}

/// Cursor-based writer for DNS wire format.
///
/// Writes to an internal `Vec<u8>` buffer in network byte order.
#[derive(Debug, Clone)]
pub struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    /// Create a new writer with empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(512),
        }
    }

    /// Create a writer with pre-allocated capacity.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Current write position (buffer length).
    #[must_use]
    pub fn pos(&self) -> usize {
        self.buf.len()
    }

    /// Consume the writer and return the buffer.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Get a reference to the current buffer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Get a mutable reference to the current buffer (for patching bytes in place).
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Write a single byte.
    pub fn write_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    /// Write a 16-bit integer in network byte order.
    pub fn write_u16(&mut self, val: u16) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Write a 32-bit integer in network byte order.
    pub fn write_u32(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Write raw bytes.
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
}

impl Default for WireWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
