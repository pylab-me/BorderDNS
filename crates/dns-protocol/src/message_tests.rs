use std::net::Ipv4Addr;

use dns_types::QClass;
use dns_types::QType;
use dns_types::RecordClass;
use dns_types::RecordType;

use super::*;
use crate::name::DomainName;
use crate::rr::RData;
use crate::rr::ResourceRecord;

#[test]
fn test_query_message_roundtrip() {
    let q = DnsQuestion::new(
        DomainName::from_str("www.example.com").unwrap(),
        QType::Type(RecordType::A),
        QClass::Class(RecordClass::In),
    );
    let msg = DnsMessage::query(0x1234, q.clone());

    let wire = msg.to_wire();
    let decoded = DnsMessage::from_wire(&wire).unwrap();

    assert_eq!(decoded.header.id, 0x1234);
    assert!(!decoded.header.qr);
    assert!(decoded.header.rd);
    assert_eq!(decoded.questions.len(), 1);
    assert_eq!(decoded.questions[0], q);
}

#[test]
fn test_response_message_roundtrip() {
    let q = DnsQuestion::new(
        DomainName::from_str("example.com").unwrap(),
        QType::Type(RecordType::A),
        QClass::Class(RecordClass::In),
    );
    let query = DnsMessage::query(0xABCD, q);
    let mut resp = DnsMessage::response(&query);

    resp.add_answer(ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::A,
        class: RecordClass::In,
        ttl: 300,
        rdata: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
    });

    let wire = resp.to_wire();
    let decoded = DnsMessage::from_wire(&wire).unwrap();

    assert!(decoded.is_response());
    assert_eq!(decoded.header.id, 0xABCD);
    assert_eq!(decoded.header.ancount, 1);
    assert_eq!(decoded.answers.len(), 1);
}

#[test]
fn test_empty_message_roundtrip() {
    let mut header = DnsHeader::query(0);
    header.qdcount = 0;
    let msg = DnsMessage {
        header,
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    let wire = msg.to_wire();
    let decoded = DnsMessage::from_wire(&wire).unwrap();
    assert_eq!(decoded.questions.len(), 0);
    assert_eq!(decoded.answers.len(), 0);
}

#[test]
fn test_message_with_multiple_answers() {
    let q = DnsQuestion::new(
        DomainName::from_str("example.com").unwrap(),
        QType::Type(RecordType::A),
        QClass::Class(RecordClass::In),
    );
    let mut msg = DnsMessage::query(1, q);

    msg.add_answer(ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::A,
        class: RecordClass::In,
        ttl: 300,
        rdata: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
    });
    msg.add_answer(ResourceRecord {
        name: DomainName::from_str("example.com").unwrap(),
        rr_type: RecordType::A,
        class: RecordClass::In,
        ttl: 300,
        rdata: RData::A(Ipv4Addr::new(5, 6, 7, 8)),
    });

    let wire = msg.to_wire();
    let decoded = DnsMessage::from_wire(&wire).unwrap();
    assert_eq!(decoded.header.ancount, 2);
    assert_eq!(decoded.answers.len(), 2);
}

#[test]
fn test_truncated_buffer() {
    let data = [0x00; 5]; // Too short for header.
    assert!(DnsMessage::from_wire(&data).is_err());
}
