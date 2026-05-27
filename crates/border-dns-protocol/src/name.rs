//! DNS domain name codec with compression pointer support (RFC 1035 Section 4.1.4).
//!
//! Domain names are stored as a sequence of labels. The wire format uses
//! length-prefixed labels terminated by a zero-length root label.

use std::fmt;

use border_dns_types::MAX_LABEL_COUNT;
use border_dns_types::MAX_LABEL_LENGTH;
use border_dns_types::ProtocolError;

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
mod tests {
    use super::*;

    // ─── DomainName construction tests ────────────────────────────

    #[test]
    fn test_root_name() {
        let root = DomainName::root();
        assert!(root.is_root());
        assert_eq!(root.label_count(), 0);
        assert_eq!(root.wire_len(), 1);
        assert_eq!(root.to_string(), ".");
    }

    #[test]
    fn test_from_labels() {
        let name = DomainName::from_labels(["www", "example", "com"]).unwrap();
        assert_eq!(name.label_count(), 3);
        assert_eq!(name.label(0), Some(b"www".as_slice()));
        assert_eq!(name.label(1), Some(b"example".as_slice()));
        assert_eq!(name.label(2), Some(b"com".as_slice()));
        assert_eq!(name.to_string(), "www.example.com.");
        assert_eq!(name.wire_len(), 4 + 8 + 4 + 1); // 3 labels + root
    }

    #[test]
    fn test_from_str_fqdn() {
        let name = DomainName::from_str("www.example.com.").unwrap();
        assert_eq!(name.label_count(), 3);
        assert_eq!(name.to_string(), "www.example.com.");
    }

    #[test]
    fn test_from_str_no_trailing_dot() {
        let name = DomainName::from_str("www.example.com").unwrap();
        assert_eq!(name.label_count(), 3);
        assert_eq!(name.to_string(), "www.example.com.");
    }

    #[test]
    fn test_from_str_root() {
        let name = DomainName::from_str(".").unwrap();
        assert!(name.is_root());
    }

    #[test]
    fn test_from_str_empty() {
        let name = DomainName::from_str("").unwrap();
        assert!(name.is_root());
    }

    #[test]
    fn test_label_too_long() {
        let long_label = vec![b'a'; 64];
        assert!(DomainName::from_labels([&long_label.as_slice()]).is_err());
    }

    #[test]
    fn test_too_many_labels() {
        let labels: Vec<String> = (0..129).map(|i| format!("l{i}")).collect();
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        assert!(DomainName::from_labels(refs).is_err());
    }

    // ─── Wire encode/decode roundtrip tests ────────────────────────

    #[test]
    fn test_root_wire_roundtrip() {
        let root = DomainName::root();
        let wire = root.to_wire();
        assert_eq!(wire, vec![0x00]);

        let mut reader = WireReader::new(&wire);
        let decoded = read_name(&mut reader, &wire).unwrap();
        assert!(decoded.is_root());
    }

    #[test]
    fn test_simple_name_wire_roundtrip() {
        let name = DomainName::from_str("www.example.com").unwrap();
        let wire = name.to_wire();
        // Expected: \x03www\x07example\x03com\x00
        assert_eq!(
            wire,
            vec![
                0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
                b'o', b'm', 0x00
            ]
        );

        let mut reader = WireReader::new(&wire);
        let decoded = read_name(&mut reader, &wire).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn test_compression_pointer() {
        // Simulate: "www.example.com" at offset 0..17, then a pointer at offset 17
        // pointing to offset 4 (which is "example.com\0").
        let mut message = Vec::new();
        // "www.example.com\0" at offset 0..17
        message.extend_from_slice(&[
            0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c',
            b'o', b'm', 0x00,
        ]);
        let pointer_offset = 4_u16; // Points to "example.com\0"
        message.push(0xC0 | ((pointer_offset >> 8) & 0x3F) as u8);
        message.push((pointer_offset & 0xFF) as u8);

        // Read the pointer at offset 17.
        let mut reader = WireReader::new(&message);
        reader.set_pos(17).unwrap();
        let decoded = read_name(&mut reader, &message).unwrap();

        let expected = DomainName::from_str("example.com").unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_pointer_loop_detection() {
        // Pointer to itself at offset 0.
        let mut message = Vec::new();
        message.push(0xC0);
        message.push(0x00);

        let mut reader = WireReader::new(&message);
        let result = read_name(&mut reader, &message);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("loop") || err.to_string().contains("chain depth"));
    }

    #[test]
    fn test_pointer_out_of_bounds() {
        let mut message = Vec::new();
        message.push(0xC0);
        message.push(100);

        let mut reader = WireReader::new(&message);
        let result = read_name(&mut reader, &message);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds message length"));
    }

    #[test]
    fn test_labels_with_suffixes() {
        let root = DomainName::root();
        let com = DomainName::from_labels(["com"]).unwrap();
        let example_com = DomainName::from_labels(["example", "com"]).unwrap();
        let www_example_com = DomainName::from_labels(["www", "example", "com"]).unwrap();

        assert!(com.is_suffix_of(&www_example_com));
        assert!(example_com.is_suffix_of(&www_example_com));
        assert!(!www_example_com.is_suffix_of(&example_com));
        assert!(root.is_suffix_of(&www_example_com));
    }

    #[test]
    fn test_parent() {
        let name = DomainName::from_str("www.example.com").unwrap();
        let parent = name.parent();
        assert_eq!(parent, DomainName::from_str("example.com").unwrap());

        let single = DomainName::from_labels(["com"]).unwrap();
        assert_eq!(single.parent(), DomainName::root());
    }

    #[test]
    fn test_append_label() {
        let com = DomainName::from_labels(["com"]).unwrap();
        let com_example = com.append_label(b"example").unwrap();
        assert_eq!(
            com_example,
            DomainName::from_labels(["com", "example"]).unwrap()
        );
    }

    #[test]
    fn test_display_escape() {
        let labels: Vec<&[u8]> = vec![b"hello world".as_ref(), b"com"];
        let name = DomainName::from_labels(labels).unwrap();
        assert_eq!(name.to_string(), "hello\\032world.com.");
    }

    #[test]
    fn test_compression_roundtrip() {
        // Build a message with two names, using compression for the second.
        use std::collections::HashMap;

        let name1 = DomainName::from_str("www.example.com").unwrap();
        let name2 = DomainName::from_str("mail.example.com").unwrap();

        let mut writer = WireWriter::new();
        let mut compression_map = HashMap::new();

        write_name_compressed(&name1, &mut writer, &mut compression_map);
        let name2_offset = writer.pos();
        write_name_compressed(&name2, &mut writer, &mut compression_map);

        let wire = writer.into_bytes();

        // name1 should be fully written: \x03www\x07example\x03com\x00 = 17 bytes
        assert_eq!(name2_offset, 17);

        // name2 should use a pointer for "example.com" suffix:
        // \x04mail + pointer(4) = 5 + 2 = 7 bytes
        assert_eq!(wire.len(), 17 + 7);

        // Verify name1 decodes correctly.
        let mut reader = WireReader::new(&wire);
        let decoded1 = read_name(&mut reader, &wire).unwrap();
        assert_eq!(decoded1, name1);

        // Verify name2 decodes correctly.
        let mut reader2 = WireReader::new(&wire);
        reader2.set_pos(name2_offset).unwrap();
        let decoded2 = read_name(&mut reader2, &wire).unwrap();
        assert_eq!(decoded2, name2);
    }
}
