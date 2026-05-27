//! DNS domain name codec with compression pointer support (RFC 1035 Section 4.1.4).
//!
//! Domain names are stored as a sequence of labels. The wire format uses
//! length-prefixed labels terminated by a zero-length root label.

use std::fmt;

use dns_types::MAX_LABEL_COUNT;
use dns_types::MAX_LABEL_LENGTH;
use dns_types::ProtocolError;

use crate::wire::WireReader;
use crate::wire::WireWriter;

/// A decoded DNS domain name.
///
/// Stored as a list of labels (each label is raw bytes without length prefix).
/// An empty name represents the root domain (`.`).
///
/// # Examples
///
/// ```text
/// "www.example.com." → labels: [b"www", b"example", b"com"]
/// "." (root)         → labels: []
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName {
    labels: Vec<Vec<u8>>,
}

impl DomainName {
    /// The root domain name (empty label sequence).
    #[must_use]
    pub fn root() -> Self {
        Self { labels: Vec::new() }
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
        let mut result = Vec::new();
        for label in labels {
            let bytes = label.as_ref();
            if bytes.len() > MAX_LABEL_LENGTH {
                return Err(ProtocolError::LabelTooLong(bytes.len()));
            }
            if bytes.is_empty() {
                continue;
            }
            result.push(bytes.to_vec());
        }
        if result.len() > MAX_LABEL_COUNT {
            return Err(ProtocolError::TooManyLabels(result.len()));
        }
        Ok(Self { labels: result })
    }

    /// Whether this is the root name.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Number of labels.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Get a label by index.
    #[must_use]
    pub fn label(&self, index: usize) -> Option<&[u8]> {
        self.labels.get(index).map(Vec::as_slice)
    }

    /// Iterator over labels.
    pub fn labels(&self) -> impl Iterator<Item = &[u8]> {
        self.labels.iter().map(Vec::as_slice)
    }

    /// Compute wire-format length (without compression).
    ///
    /// For root: 1 byte (the zero-length label).
    /// For "www.example.com.": 4 + 8 + 4 + 1 = 17 bytes.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        if self.labels.is_empty() {
            return 1; // root: single zero byte
        }
        let labels_len: usize = self.labels.iter().map(|l| 1 + l.len()).sum();
        labels_len + 1 // +1 for trailing zero label
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

        let mut labels = Vec::new();
        for label_str in s.split('.') {
            let bytes = label_str.as_bytes();
            if bytes.len() > MAX_LABEL_LENGTH {
                return Err(ProtocolError::LabelTooLong(bytes.len()));
            }
            if bytes.is_empty() {
                continue;
            }
            labels.push(bytes.to_vec());
        }

        if labels.len() > MAX_LABEL_COUNT {
            return Err(ProtocolError::TooManyLabels(labels.len()));
        }

        Ok(Self { labels })
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
        for label in &self.labels {
            writer.write_u8(label.len() as u8);
            writer.write_bytes(label);
        }
        writer.write_u8(0); // root terminator
    }

    /// Create a new name by appending a label.
    #[must_use]
    pub fn append_label(&self, label: &[u8]) -> Result<Self, ProtocolError> {
        if label.len() > MAX_LABEL_LENGTH {
            return Err(ProtocolError::LabelTooLong(label.len()));
        }
        let mut labels = self.labels.clone();
        labels.push(label.to_vec());
        if labels.len() > MAX_LABEL_COUNT {
            return Err(ProtocolError::TooManyLabels(labels.len()));
        }
        Ok(Self { labels })
    }

    /// Create a parent name (remove the first label).
    #[must_use]
    pub fn parent(&self) -> Self {
        if self.labels.is_empty() {
            return Self::root();
        }
        Self {
            labels: self.labels[1..].to_vec(),
        }
    }

    /// Check if this name equals or is a suffix of `other`.
    ///
    /// For example, `example.com` is a suffix of `www.example.com`.
    #[must_use]
    pub fn is_suffix_of(&self, other: &Self) -> bool {
        if self.labels.len() > other.labels.len() {
            return false;
        }
        let offset = other.labels.len() - self.labels.len();
        self.labels == other.labels[offset..]
    }

    /// Get the wire-format bytes for a suffix starting at label index `start`.
    ///
    /// Used internally for compression map registration.
    fn suffix_wire(&self, start: usize) -> Vec<u8> {
        let mut w = WireWriter::new();
        for label in &self.labels[start..] {
            w.write_u8(label.len() as u8);
            w.write_bytes(label);
        }
        w.write_u8(0);
        w.into_bytes()
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return write!(f, ".");
        }
        for (i, label) in self.labels.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
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

    let mut labels = Vec::new();

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
                labels.extend(suffix.labels);
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
                labels.push(label_data.to_vec());
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

    Ok(DomainName { labels })
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
/// Uses the compression map to reference previously seen name suffixes.
/// Returns the number of bytes written.
pub fn write_name_compressed(
    name: &DomainName,
    writer: &mut WireWriter,
    compression_map: &mut std::collections::HashMap<Vec<u8>, usize>,
) -> usize {
    let base_offset = writer.pos();

    // Walk suffixes from shortest (root) to longest (full name).
    // Find the longest suffix that's already in the compression map.
    let num_labels = name.label_count();
    for i in 0..num_labels {
        let suffix_wire = name.suffix_wire(i);
        if let Some(&offset) = compression_map.get(&suffix_wire) {
            // Write labels before the compressible suffix, then a pointer.
            for label in &name.labels[..i] {
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
        let suffix_wire = name.suffix_wire(i);
        compression_map.insert(suffix_wire, label_offset);
        label_offset += 1 + name.labels[i].len(); // length byte + label bytes
    }

    writer.pos() - base_offset
}

#[cfg(test)]
#[path = "name_tests.rs"]
mod tests;
