use super::*;

#[test]
fn test_header_wire_roundtrip() {
    let header = DnsHeader {
        id: 0x1234,
        qr: true,
        opcode: OpCode::Query,
        aa: true,
        tc: false,
        rd: true,
        ra: true,
        z: 0,
        rcode: ResponseCode::NoError,
        qdcount: 1,
        ancount: 3,
        nscount: 0,
        arcount: 1,
    };

    let mut writer = WireWriter::new();
    header.write(&mut writer);
    let wire = writer.into_bytes();
    assert_eq!(wire.len(), DnsHeader::WIRE_SIZE);

    let mut reader = WireReader::new(&wire);
    let decoded = DnsHeader::read(&mut reader).unwrap();
    assert_eq!(decoded, header);
}

#[test]
fn test_query_header() {
    let header = DnsHeader::query(0xABCD);
    assert!(!header.qr);
    assert!(header.rd);
    assert_eq!(header.id, 0xABCD);
    assert_eq!(header.opcode, OpCode::Query);
}

#[test]
fn test_response_header() {
    let header = DnsHeader::response(0xABCD, true);
    assert!(header.qr);
    assert!(header.rd);
    assert!(header.ra);
    assert_eq!(header.id, 0xABCD);
}

#[test]
fn test_all_flags() {
    let header = DnsHeader {
        id: 0,
        qr: true,
        opcode: OpCode::Query,
        aa: true,
        tc: true,
        rd: true,
        ra: true,
        z: 0,
        rcode: ResponseCode::NXDomain,
        qdcount: 1,
        ancount: 1,
        nscount: 1,
        arcount: 1,
    };

    let mut writer = WireWriter::new();
    header.write(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = DnsHeader::read(&mut reader).unwrap();
    assert_eq!(decoded.qr, true);
    assert_eq!(decoded.aa, true);
    assert_eq!(decoded.tc, true);
    assert_eq!(decoded.rd, true);
    assert_eq!(decoded.ra, true);
    assert_eq!(decoded.rcode, ResponseCode::NXDomain);
}
