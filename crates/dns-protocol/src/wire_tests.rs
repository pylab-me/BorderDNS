use super::*;

#[test]
fn test_wire_reader_u8() {
    let data = [0x42];
    let mut reader = WireReader::new(&data);
    assert_eq!(reader.read_u8().unwrap(), 0x42);
    assert_eq!(reader.remaining(), 0);
}

#[test]
fn test_wire_reader_u16_big_endian() {
    let data = [0x01, 0x00];
    let mut reader = WireReader::new(&data);
    assert_eq!(reader.read_u16().unwrap(), 256);
}

#[test]
fn test_wire_reader_u32_big_endian() {
    let data = [0x00, 0x00, 0x01, 0x00];
    let mut reader = WireReader::new(&data);
    assert_eq!(reader.read_u32().unwrap(), 256);
}

#[test]
fn test_wire_reader_buffer_underflow() {
    let data = [0x01];
    let mut reader = WireReader::new(&data);
    assert!(reader.read_u16().is_err());
}

#[test]
fn test_wire_reader_save_restore() {
    let data = [0x01, 0x02, 0x03, 0x04];
    let mut reader = WireReader::new(&data);
    let _ = reader.read_u8();
    reader.save_position();
    let _ = reader.read_u16();
    assert_eq!(reader.pos(), 3);
    reader.restore_position().unwrap();
    assert_eq!(reader.pos(), 1);
}

#[test]
fn test_wire_writer_u16() {
    let mut writer = WireWriter::new();
    writer.write_u16(0x0100);
    assert_eq!(writer.as_bytes(), &[0x01, 0x00]);
}

#[test]
fn test_wire_writer_u32() {
    let mut writer = WireWriter::new();
    writer.write_u32(0xDEADBEEF);
    assert_eq!(writer.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_wire_writer_into_bytes() {
    let mut writer = WireWriter::new();
    writer.write_u8(0xAA);
    writer.write_u16(0xBBCC);
    let bytes = writer.into_bytes();
    assert_eq!(bytes, vec![0xAA, 0xBB, 0xCC]);
}
