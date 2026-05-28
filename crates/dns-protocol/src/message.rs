//! DNS message (RFC 1035 Section 4.1).
//!
//! A complete DNS message consists of Header, Question, Answer, Authority,
//! and Additional sections.

use dns_types::ProtocolError;

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
    ///
    /// Pre-allocates capacity based on estimated wire size to avoid mid-encode
    /// reallocation (P2-1 fix).
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let cap = self.wire_size_estimate();
        let mut writer = WireWriter::with_capacity(cap);
        self.write_to(&mut writer);
        writer.into_bytes()
    }

    /// Estimate the wire-format size of this message for pre-allocation.
    fn wire_size_estimate(&self) -> usize {
        let mut size = 12; // header
        for q in &self.questions {
            size += q.wire_len();
        }
        // RRs: rough estimate — name wire len + 10 (type+class+ttl+rdlen) + avg rdata
        for rr in &self.answers {
            size += rr.name.wire_len() + 10 + 64; // 64 = avg rdata size
        }
        for rr in &self.authorities {
            size += rr.name.wire_len() + 10 + 64;
        }
        for rr in &self.additionals {
            size += rr.name.wire_len() + 10 + 64;
        }
        size.max(512)
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
#[path = "message_tests.rs"]
mod tests;
