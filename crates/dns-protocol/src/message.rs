//! DNS message (RFC 1035 Section 4.1).
//!
//! A complete DNS message consists of Header, Question, Answer, Authority,
//! and Additional sections.

use border_dns_types::ProtocolError;

use crate::header::DnsHeader;
use crate::question::DnsQuestion;
use crate::rr::ResourceRecord;
use crate::wire::WireReader;
use crate::wire::WireWriter;

/// Maximum DNS message size without EDNS.
pub const MAX_MESSAGE_SIZE: usize = 512;

/// Maximum DNS message size with EDNS.
pub const MAX_EDNS_MESSAGE_SIZE: usize = 4096;

/// A complete DNS message.
///
/// ```text
///     +---------------------+
///     |        Header       |
///     +---------------------+
///     |       Question      |
///     +---------------------+
///     |        Answer       |
///     +---------------------+
///     |      Authority      |
///     +---------------------+
///     |      Additional     |
///     +---------------------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    /// Message header.
    pub header: DnsHeader,
    /// Question section.
    pub questions: Vec<DnsQuestion>,
    /// Answer section.
    pub answers: Vec<ResourceRecord>,
    /// Authority section.
    pub authorities: Vec<ResourceRecord>,
    /// Additional section.
    pub additionals: Vec<ResourceRecord>,
}

impl DnsMessage {
    /// Create an empty query message with the given ID and a single question.
    #[must_use]
    pub fn query(id: u16, question: DnsQuestion) -> Self {
        let mut header = DnsHeader::query(id);
        header.qdcount = 1;
        Self {
            header,
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Create a response message that mirrors the query's ID and RD bit.
    #[must_use]
    pub fn response(query: &DnsMessage) -> Self {
        let mut header = DnsHeader::response(query.header.id, query.header.rd);
        header.qdcount = query.questions.len() as u16;
        Self {
            header,
            questions: query.questions.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Decode a DNS message from wire bytes.
    ///
    /// # Errors
    ///
    /// Returns error on malformed message, section count mismatch,
    /// or buffer overrun.
    pub fn from_wire(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < DnsHeader::WIRE_SIZE {
            return Err(ProtocolError::BufferUnderflow {
                need: DnsHeader::WIRE_SIZE,
                have: data.len(),
            });
        }

        let mut reader = WireReader::new(data);
        let header = DnsHeader::read(&mut reader)?;

        // Read questions.
        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            questions.push(DnsQuestion::read(&mut reader, data)?);
        }

        // Read answers.
        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            answers.push(ResourceRecord::read(&mut reader, data)?);
        }

        // Read authorities.
        let mut authorities = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            authorities.push(ResourceRecord::read(&mut reader, data)?);
        }

        // Read additionals.
        let mut additionals = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            additionals.push(ResourceRecord::read(&mut reader, data)?);
        }

        Ok(Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Encode this message to wire format.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut writer = WireWriter::with_capacity(512);
        self.write_to(&mut writer);
        writer.into_bytes()
    }

    /// Write this message to the given writer.
    pub fn write_to(&self, writer: &mut WireWriter) {
        self.header.write(writer);

        for q in &self.questions {
            q.write(writer);
        }
        for rr in &self.answers {
            rr.write_to(writer);
        }
        for rr in &self.authorities {
            rr.write_to(writer);
        }
        for rr in &self.additionals {
            rr.write_to(writer);
        }
    }

    /// Set the header counts to match actual section lengths.
    pub fn update_counts(&mut self) {
        self.header.qdcount = self.questions.len() as u16;
        self.header.ancount = self.answers.len() as u16;
        self.header.nscount = self.authorities.len() as u16;
        self.header.arcount = self.additionals.len() as u16;
    }

    /// Whether this message is a response (QR bit set).
    #[must_use]
    pub fn is_response(&self) -> bool {
        self.header.qr
    }

    /// Whether this message was truncated (TC bit set).
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.header.tc
    }

    /// Get the first question, if any.
    #[must_use]
    pub fn first_question(&self) -> Option<&DnsQuestion> {
        self.questions.first()
    }

    /// Add an answer record and update the count.
    pub fn add_answer(&mut self, rr: ResourceRecord) {
        self.answers.push(rr);
        self.header.ancount = self.answers.len() as u16;
    }

    /// Add an authority record and update the count.
    pub fn add_authority(&mut self, rr: ResourceRecord) {
        self.authorities.push(rr);
        self.header.nscount = self.authorities.len() as u16;
    }

    /// Add an additional record and update the count.
    pub fn add_additional(&mut self, rr: ResourceRecord) {
        self.additionals.push(rr);
        self.header.arcount = self.additionals.len() as u16;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use border_dns_types::QClass;
    use border_dns_types::QType;
    use border_dns_types::RecordClass;
    use border_dns_types::RecordType;

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
}
