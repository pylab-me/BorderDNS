//! DNS question section (RFC 1035 Section 4.1.2).
//!
//! The question section contains QDCOUNT entries, each with QNAME, QTYPE, and QCLASS.

use dns_types::ProtocolError;
use dns_types::QClass;
use dns_types::QType;

use crate::name::DomainName;
use crate::name::read_name;
use crate::wire::WireReader;
use crate::wire::WireWriter;

/// A single DNS question entry.
///
/// ```text
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                     QNAME                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QTYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     QCLASS                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Query domain name.
    pub qname: DomainName,
    /// Query type.
    pub qtype: QType,
    /// Query class.
    pub qclass: QClass,
}

impl DnsQuestion {
    /// Create a new question.
    #[must_use]
    pub fn new(qname: DomainName, qtype: QType, qclass: QClass) -> Self {
        Self {
            qname,
            qtype,
            qclass,
        }
    }

    /// Read a single question from wire format.
    pub fn read(reader: &mut WireReader<'_>, message: &[u8]) -> Result<Self, ProtocolError> {
        let qname = read_name(reader, message)?;
        let qtype_raw = reader.read_u16()?;
        let qclass_raw = reader.read_u16()?;
        Ok(Self {
            qname,
            qtype: QType::from_u16(qtype_raw),
            qclass: QClass::from_u16(qclass_raw),
        })
    }

    /// Write question to wire format.
    pub fn write(&self, writer: &mut WireWriter) {
        crate::name::write_name_uncompressed(&self.qname, writer);
        writer.write_u16(self.qtype.as_u16());
        writer.write_u16(self.qclass.as_u16());
    }

    /// Wire size estimate (without name compression).
    /// Name wire length + 2 (QTYPE) + 2 (QCLASS).
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.qname.wire_len() + 4
    }
}

#[cfg(test)]
#[path = "question_tests.rs"]
mod tests;
