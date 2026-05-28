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
        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o',
        b'm', 0x00,
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
    let mut compression_map: HashMap<u64, usize> = HashMap::new();

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
