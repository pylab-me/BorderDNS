//! DNS header section (RFC 1035 Section 4.1.1).
//!
//! The header is always present and includes fields for message identification,
//! flags, and section counts.

use border_dns_types::ProtocolError;

use crate::wire::WireReader;
use crate::wire::WireWriter;

/// DNS operation codes (OPCODE field, 4 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpCode {
    /// Standard query (QUERY).
    Query,
    /// Inverse query (IQUERY, obsolete).
    IQuery,
    /// Server status request (STATUS).
    Status,
    /// Notify (RFC 1996).
    Notify,
    /// Update (RFC 2136).
    Update,
    /// Unknown opcode.
    Unknown(u8),
}

impl OpCode {
    /// Convert numeric opcode to `OpCode`.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            other => Self::Unknown(other & 0x0F),
        }
    }

    /// Get the numeric value.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Query => 0,
            Self::IQuery => 1,
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Unknown(v) => v & 0x0F,
        }
    }
}

/// DNS response codes (RCODE field, 4 bits).
///
/// Extended RCODE (EDNS) is handled separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseCode {
    /// No error (RCODE 0).
    NoError,
    /// Format error (RCODE 1).
    FormErr,
    /// Server failure (RCODE 2).
    ServFail,
    /// Non-existent domain (RCODE 3).
    NXDomain,
    /// Not implemented (RCODE 4).
    NotImp,
    /// Query refused (RCODE 5).
    Refused,
    /// Unknown RCODE.
    Unknown(u8),
}

impl ResponseCode {
    /// Convert numeric rcode to `ResponseCode`.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            other => Self::Unknown(other),
        }
    }

    /// Get the numeric value.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NXDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::Unknown(v) => v,
        }
    }
}

/// DNS message header (RFC 1035 Section 4.1.1).
///
/// ```text
///                                     1  1  1  1  1  1
///       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      ID                       |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    QDCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ANCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    NSCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ARCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    /// Message identifier (copied in request/response pairs).
    pub id: u16,
    /// Query/Response flag.
    pub qr: bool,
    /// Operation code.
    pub opcode: OpCode,
    /// Authoritative Answer.
    pub aa: bool,
    /// Truncation.
    pub tc: bool,
    /// Recursion Desired.
    pub rd: bool,
    /// Recursion Available.
    pub ra: bool,
    /// Reserved (must be zero).
    pub z: u8,
    /// Response code.
    pub rcode: ResponseCode,
    /// Number of entries in the Question section.
    pub qdcount: u16,
    /// Number of entries in the Answer section.
    pub ancount: u16,
    /// Number of entries in the Authority section.
    pub nscount: u16,
    /// Number of entries in the Additional section.
    pub arcount: u16,
}

impl DnsHeader {
    /// Header section size in bytes (RFC 1035: always 12 bytes).
    pub const WIRE_SIZE: usize = 12;

    /// Create a default query header with the given ID and recursion desired.
    #[must_use]
    pub fn query(id: u16) -> Self {
        Self {
            id,
            qr: false,
            opcode: OpCode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
            rcode: ResponseCode::NoError,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Create a default response header mirroring the query ID and RD bit.
    #[must_use]
    pub fn response(id: u16, rd: bool) -> Self {
        Self {
            id,
            qr: true,
            opcode: OpCode::Query,
            aa: false,
            tc: false,
            rd,
            ra: true,
            z: 0,
            rcode: ResponseCode::NoError,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Read header from wire format.
    ///
    /// # Errors
    ///
    /// Returns `BufferUnderflow` if fewer than 12 bytes remain.
    pub fn read(reader: &mut WireReader<'_>) -> Result<Self, ProtocolError> {
        let id = reader.read_u16()?;
        let flags = reader.read_u16()?;

        let qr = (flags & 0x8000) != 0;
        let opcode = OpCode::from_u8(((flags >> 11) & 0x0F) as u8);
        let aa = (flags & 0x0400) != 0;
        let tc = (flags & 0x0200) != 0;
        let rd = (flags & 0x0100) != 0;
        let ra = (flags & 0x0080) != 0;
        let z = ((flags >> 4) & 0x07) as u8;
        let rcode = ResponseCode::from_u8((flags & 0x000F) as u8);

        let qdcount = reader.read_u16()?;
        let ancount = reader.read_u16()?;
        let nscount = reader.read_u16()?;
        let arcount = reader.read_u16()?;

        Ok(Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }

    /// Write header to wire format.
    pub fn write(&self, writer: &mut WireWriter) {
        writer.write_u16(self.id);

        let mut flags: u16 = 0;
        if self.qr {
            flags |= 0x8000;
        }
        flags |= (self.opcode.as_u8() as u16) << 11;
        if self.aa {
            flags |= 0x0400;
        }
        if self.tc {
            flags |= 0x0200;
        }
        if self.rd {
            flags |= 0x0100;
        }
        if self.ra {
            flags |= 0x0080;
        }
        flags |= (self.z as u16) << 4;
        flags |= self.rcode.as_u8() as u16;

        writer.write_u16(flags);
        writer.write_u16(self.qdcount);
        writer.write_u16(self.ancount);
        writer.write_u16(self.nscount);
        writer.write_u16(self.arcount);
    }
}

#[cfg(test)]
mod tests {
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
}
