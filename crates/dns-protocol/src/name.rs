//! DNS domain name codec with compression pointer support (RFC 1035 Section 4.1.4).
//!
//! Domain names are stored as a single contiguous byte buffer with label
//! boundary offsets. This eliminates per-label heap allocation — a typical
//! 3-label name uses 1 allocation instead of 4.

use std::fmt;

use dns_types::MAX_LABEL_COUNT;
use dns_types::MAX_LABEL_LENGTH;
use dns_types::ProtocolError;

use crate::wire::WireReader;
use crate::wire::WireWriter;

/// A decoded DNS domain name.
///
/// Stored as a single contiguous byte buffer (`buf`) containing all label
/// bytes concatenated, with cumulative end-offsets (`ends`) marking where
/// each label ends. This avoids N+1 heap allocations for an N-label name.
///
/// # Examples
///
/// ```text
/// "www.example.com." → buf: [wwwexamplecom], ends: [3, 10, 13]
/// "." (root)         → buf: [], ends: []
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName {
    /// All label bytes concatenated (no length prefixes, no root terminator).
    buf: Box<[u8]>,
    /// Cumulative byte-offset where each label ends within `buf`.
    /// `ends[i]` = sum of lengths of labels 0..=i.
    /// Length of `ends` = number of labels.
    /// Empty for root domain.
    ends: smallvec::SmallVec<[u8; 8]>,
}

impl DomainName {
    /// The root domain name (empty label sequence).
    #[must_use]
    pub fn root() -> Self {
        Self {
            buf: Box::default(),
            ends: smallvec::SmallVec::new(),
        }
    }

    /// Create from an iterator of label byte slices.
    ///
    /// # Errors
    ///
    /// Returns error if any label exceeds 63 bytes or total labels exceed 128.
    pub fn from_labels<I, S>(labels: I) -> Result<Self, ProtocolError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut buf = Vec::new();
        let mut ends = smallvec::SmallVec::new();
        for label in labels {
            let bytes = label.as_ref();
            if bytes.len() > MAX_LABEL_LENGTH {
                return Err(ProtocolError::LabelTooLong(bytes.len()));
            }
            if bytes.is_empty() {
                continue;
            }
            buf.extend_from_slice(bytes);
            ends.push(
                u8::try_from(buf.len()).map_err(|_| ProtocolError::TooManyLabels(ends.len()))?,
            );
        }
        if ends.len() > MAX_LABEL_COUNT {
            return Err(ProtocolError::TooManyLabels(ends.len()));
        }
        Ok(Self {
            buf: buf.into(),
            ends,
        })
    }

    /// Whether this is the root name.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.ends.is_empty()
    }

    /// Number of labels.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.ends.len()
    }

    /// Get a label by index.
    #[must_use]
    pub fn label(&self, index: usize) -> Option<&[u8]> {
        if index >= self.ends.len() {
            return None;
        }
        let end = self.ends[index] as usize;
        let start = if index == 0 {
            0
        } else {
            self.ends[index - 1] as usize
        };
        Some(&self.buf[start..end])
    }

    /// Byte length of label at `index`.
    #[must_use]
    fn label_len(&self, index: usize) -> usize {
        let end = self.ends[index] as usize;
        let start = if index == 0 {
            0
        } else {
            self.ends[index - 1] as usize
        };
        end - start
    }

    /// Iterator over labels.
    pub fn labels(&self) -> impl Iterator<Item = &[u8]> {
        let buf: &[u8] = &self.buf;
        let ends: &smallvec::SmallVec<[u8; 8]> = &self.ends;
        (0..ends.len()).map(move |i| {
            let end = ends[i] as usize;
            let start = if i == 0 { 0 } else { ends[i - 1] as usize };
            &buf[start..end]
        })
    }

    /// Compute wire-format length (without compression).
    ///
    /// For root: 1 byte (the zero-length label).
    /// For "www.example.com.": 4 + 8 + 4 + 1 = 17 bytes.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        if self.ends.is_empty() {
            return 1; // root: single zero byte
        }
        // Each label: 1 length byte + label bytes; plus 1 trailing zero
        self.buf.len() + self.ends.len() + 1
    }

    /// Parse a presentation-format domain name (e.g., "www.example.com." or "www.example.com").
    ///
    /// A trailing dot indicates FQDN; absence is also accepted (treated as FQDN).
    ///
    /// # Errors
    ///
    /// Returns error on malformed name.
    pub fn from_str(s: &str) -> Result<Self, ProtocolError> {
        let s = if s == "." {
            return Ok(Self::root());
        } else {
            s.trim_end_matches('.')
        };

        if s.is_empty() {
            return Ok(Self::root());
        }

        let mut buf = Vec::new();
        let mut ends = smallvec::SmallVec::new();
        for label_str in s.split('.') {
            let bytes = label_str.as_bytes();
            if bytes.len() > MAX_LABEL_LENGTH {
                return Err(ProtocolError::LabelTooLong(bytes.len()));
            }
            if bytes.is_empty() {
                continue;
            }
            buf.extend_from_slice(bytes);
            ends.push(
                u8::try_from(buf.len()).map_err(|_| ProtocolError::TooManyLabels(ends.len()))?,
            );
        }

        if ends.len() > MAX_LABEL_COUNT {
            return Err(ProtocolError::TooManyLabels(ends.len()));
        }

        Ok(Self {
            buf: buf.into(),
            ends,
        })
    }

    /// Encode to uncompressed wire format.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut writer = WireWriter::with_capacity(self.wire_len());
        self.write_wire_uncompressed(&mut writer);
        writer.into_bytes()
    }

    /// Write uncompressed wire format to the writer.
    pub fn write_wire_uncompressed(&self, writer: &mut WireWriter) {
        let mut prev_end = 0usize;
        for &end in &self.ends {
            let end = end as usize;
            writer.write_u8((end - prev_end) as u8);
            writer.write_bytes(&self.buf[prev_end..end]);
            prev_end = end;
        }
        writer.write_u8(0); // root terminator
    }

    /// Create a new name by appending a label.
    #[must_use]
    pub fn append_label(&self, label: &[u8]) -> Result<Self, ProtocolError> {
        if label.len() > MAX_LABEL_LENGTH {
            return Err(ProtocolError::LabelTooLong(label.len()));
        }
        let mut new_buf = Vec::with_capacity(self.buf.len() + label.len());
        new_buf.extend_from_slice(&self.buf);
        new_buf.extend_from_slice(label);
        let mut new_ends = self.ends.clone();
        new_ends.push(
            u8::try_from(new_buf.len())
                .map_err(|_| ProtocolError::TooManyLabels(new_ends.len()))?,
        );
        if new_ends.len() > MAX_LABEL_COUNT {
            return Err(ProtocolError::TooManyLabels(new_ends.len()));
        }
        Ok(Self {
            buf: new_buf.into(),
            ends: new_ends,
        })
    }

    /// Create a parent name (remove the first label).
    #[must_use]
    pub fn parent(&self) -> Self {
        if self.ends.is_empty() {
            return Self::root();
        }
        let first_end = self.ends[0] as usize;
        let new_buf: Box<[u8]> = self.buf[first_end..].into();
        let new_ends: smallvec::SmallVec<[u8; 8]> = self.ends[1..]
            .iter()
            .map(|&e| e - first_end as u8)
            .collect();
        Self {
            buf: new_buf,
            ends: new_ends,
        }
    }

    /// Check if this name equals or is a suffix of `other`.
    ///
    /// For example, `example.com` is a suffix of `www.example.com`.
    #[must_use]
    pub fn is_suffix_of(&self, other: &Self) -> bool {
        if self.ends.is_empty() {
            return true; // root is suffix of everything
        }
        if self.ends.len() > other.ends.len() {
            return false;
        }
        // Compare buf bytes of self against the tail of other.buf
        let self_len = self.buf.len();
        let other_len = other.buf.len();
        if self_len > other_len {
            return false;
        }
        self.buf[..] == other.buf[other_len - self_len..]
    }

    /// Compute a FNV-1a hash of the wire-format suffix starting at label index `start`.
    ///
    /// This replaces `suffix_wire()` to avoid heap allocation during compression
    /// map lookups (P0-2 fix).
    fn suffix_hash_from(&self, start: usize) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
        let mut prev_end = if start == 0 {
            0usize
        } else {
            self.ends[start - 1] as usize
        };
        for i in start..self.ends.len() {
            let end = self.ends[i] as usize;
            let label_len = (end - prev_end) as u8;
            // Hash length byte
            h ^= u64::from(label_len);
            h = h.wrapping_mul(0x100000001b3);
            // Hash label bytes
            for &b in &self.buf[prev_end..end] {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x100000001b3);
            }
            prev_end = end;
        }
        // Hash root terminator
        h ^= 0;
        h = h.wrapping_mul(0x100000001b3);
        h
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ends.is_empty() {
            return write!(f, ".");
        }
        let mut first = true;
        for label in self.labels() {
            if !first {
                write!(f, ".")?;
            }
            first = false;
            for &byte in label {
                if byte.is_ascii_graphic() && byte != b'.' && byte != b'\\' {
                    write!(f, "{}", byte as char)?;
                } else {
                    write!(f, "\\{:03}", byte)?;
                }
            }
        }
        write!(f, ".")
    }
}

// ─── Wire codec ──────────────────────────────────────────────────────

/// Read a domain name from wire format, resolving compression pointers.
///
/// # Arguments
///
/// * `reader` — current read position in the DNS message.
/// * `message` — the full DNS message buffer (for resolving pointers).
///
/// # Errors
///
/// Returns error on malformed name, pointer loop, or buffer overrun.
pub fn read_name(reader: &mut WireReader<'_>, message: &[u8]) -> Result<DomainName, ProtocolError> {
    read_name_with_depth(reader, message, 0)
}

fn read_name_with_depth(
    reader: &mut WireReader<'_>,
    message: &[u8],
    depth: usize,
) -> Result<DomainName, ProtocolError> {
    if depth > MAX_LABEL_LENGTH {
        return Err(ProtocolError::PointerLoop {
            offset: reader.pos(),
            depth,
        });
    }

    let mut buf = Vec::new();
    let mut ends = smallvec::SmallVec::<[u8; 8]>::new();

    loop {
        if reader.remaining() == 0 {
            return Err(ProtocolError::BufferUnderflow { need: 1, have: 0 });
        }

        let byte = reader.peek_u8()?;

        match byte {
            // Compression pointer: top two bits are 11.
            0xC0..=0xFF => {
                let _ = reader.read_u8()?;
                let pointer_byte2 = reader.read_u8()?;
                let offset = (((byte & 0x3F) as usize) << 8) | (pointer_byte2 as usize);

                if offset >= message.len() {
                    return Err(ProtocolError::PointerOutOfBounds {
                        pointer: offset,
                        message_len: message.len(),
                    });
                }

                // Follow the pointer and merge labels from the target.
                let mut ptr_reader = WireReader::new(message);
                ptr_reader.set_pos(offset)?;
                let suffix = read_name_with_depth(&mut ptr_reader, message, depth + 1)?;
                // Append suffix labels to current buf/ends
                let buf_start = buf.len();
                buf.extend_from_slice(&suffix.buf);
                for &end in &suffix.ends {
                    ends.push(
                        u8::try_from(buf_start + end as usize)
                            .map_err(|_| ProtocolError::TooManyLabels(ends.len()))?,
                    );
                }
                break;
            }
            // Root label (zero length).
            0x00 => {
                let _ = reader.read_u8()?;
                break;
            }
            // Regular label: length byte 0x01..=0x3F.
            len @ 0x01..=0x3F => {
                let _ = reader.read_u8()?;
                let label_len = len as usize;
                let label_data = reader.read_bytes(label_len)?;
                buf.extend_from_slice(label_data);
                ends.push(
                    u8::try_from(buf.len())
                        .map_err(|_| ProtocolError::TooManyLabels(ends.len()))?,
                );
            }
            // Label length 0x40..=0xBF is reserved and invalid.
            _ => {
                return Err(ProtocolError::InvalidPointerMarker {
                    offset: reader.pos(),
                    byte,
                });
            }
        }
    }

    Ok(DomainName {
        buf: buf.into(),
        ends,
    })
}

/// Read a domain name from a raw message buffer starting at `offset`.
///
/// Convenience wrapper that creates a temporary `WireReader`.
pub fn read_name_at(message: &[u8], offset: usize) -> Result<(DomainName, usize), ProtocolError> {
    let mut reader = WireReader::new(message);
    reader.set_pos(offset)?;
    let name = read_name(&mut reader, message)?;
    Ok((name, reader.pos()))
}

/// Write a domain name in uncompressed wire format.
pub fn write_name_uncompressed(name: &DomainName, writer: &mut WireWriter) {
    name.write_wire_uncompressed(writer);
}

/// Write a domain name in compressed wire format.
///
/// Uses a FNV-1a hash-based compression map to reference previously seen
/// name suffixes without allocating intermediate `Vec<u8>` keys (P0-2 fix).
/// Returns the number of bytes written.
pub fn write_name_compressed(
    name: &DomainName,
    writer: &mut WireWriter,
    compression_map: &mut std::collections::HashMap<u64, usize>,
) -> usize {
    let base_offset = writer.pos();

    // Walk suffixes from shortest (root) to longest (full name).
    // Find the longest suffix that's already in the compression map.
    let num_labels = name.label_count();
    for i in 0..num_labels {
        let hash = name.suffix_hash_from(i);
        if let Some(&offset) = compression_map.get(&hash) {
            // Write labels before the compressible suffix, then a pointer.
            for j in 0..i {
                let label = name.label(j).unwrap_or(b"");
                writer.write_u8(label.len() as u8);
                writer.write_bytes(label);
            }
            let pointer_val = offset as u16;
            writer.write_u8(0xC0 | ((pointer_val >> 8) & 0x3F) as u8);
            writer.write_u8((pointer_val & 0xFF) as u8);
            return writer.pos() - base_offset;
        }
    }

    // No compressible suffix found; write all labels uncompressed.
    name.write_wire_uncompressed(writer);

    // Register all suffixes of this name in the compression map.
    let mut label_offset = base_offset;
    for i in 0..num_labels {
        let hash = name.suffix_hash_from(i);
        compression_map.insert(hash, label_offset);
        label_offset += 1 + name.label_len(i); // length byte + label bytes
    }

    writer.pos() - base_offset
}

#[cfg(test)]
#[path = "name_tests.rs"]
mod tests;
