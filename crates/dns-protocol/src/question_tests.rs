use dns_types::RecordType;

use super::*;

#[test]
fn test_question_wire_roundtrip() {
    let q = DnsQuestion::new(
        DomainName::from_str("www.example.com").unwrap(),
        QType::Type(RecordType::A),
        QClass::Class(dns_types::RecordClass::In),
    );

    let mut writer = WireWriter::new();
    q.write(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = DnsQuestion::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded, q);
}

#[test]
fn test_question_any_class() {
    let q = DnsQuestion::new(
        DomainName::from_str("example.com").unwrap(),
        QType::All,
        QClass::Any,
    );

    let mut writer = WireWriter::new();
    q.write(&mut writer);
    let wire = writer.into_bytes();

    let mut reader = WireReader::new(&wire);
    let decoded = DnsQuestion::read(&mut reader, &wire).unwrap();
    assert_eq!(decoded.qtype, QType::All);
    assert_eq!(decoded.qclass, QClass::Any);
}
