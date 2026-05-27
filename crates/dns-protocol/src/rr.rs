//! DNS resource record and RData (RFC 1035 Section 3.2.1, 4.1.3).
//!
//! Resource records share the same wire format across Answer, Authority,
//! and Additional sections. RDATA encoding varies by record type.

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use dns_types::ProtocolError;
use dns_types::RecordClass;
use dns_types::RecordType;

use crate::name::read_name;
use crate::name::write_name_uncompressed;
use crate::wire::WireReader;
use crate::wire::WireWriter;

/// SOA record fields (RFC 1035 Section 3.3.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaRecord {
    pub mname: DomainName,
    pub rname: DomainName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

/// Re-export for convenience — `DomainName` from the name module.
use crate::name::DomainName;

impl SoaRecord {
    /// Read SOA RDATA from wire format.
    ///
    /// # Errors
    ///
    /// Returns error on malformed name or insufficient data.
    pub fn read(reader: &mut WireReader<'_>, message: &[u8]) -> Result<Self, ProtocolError> {
        let mname = read_name(reader, message)?;
        let rname = read_name(reader, message)?;
        let serial = reader.read_u32()?;
        let refresh = reader.read_u32()?;
        let retry = reader.read_u32()?;
        let expire = reader.read_u32()?;
        let minimum = reader.read_u32()?;
        Ok(Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }

    /// Write SOA RDATA to wire format.
    pub fn write(&self, writer: &mut WireWriter) {
        write_name_uncompressed(&self.mname, writer);
        write_name_uncompressed(&self.rname, writer);
        writer.write_u32(self.serial);
        writer.write_u32(self.refresh);
        writer.write_u32(self.retry);
        writer.write_u32(self.expire);
        writer.write_u32(self.minimum);
    }

    /// Wire size of SOA RDATA (without header/name).
    #[must_use]
    pub fn rdata_wire_len(&self) -> usize {
        20 + self.mname.wire_len() + self.rname.wire_len() // 5 × u32 + two names
    }
}

/// MX record fields (RFC 1035 Section 3.3.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: DomainName,
}

impl MxRecord {
    /// Read MX RDATA from wire format.
    pub fn read(reader: &mut WireReader<'_>, message: &[u8]) -> Result<Self, ProtocolError> {
        let preference = reader.read_u16()?;
        let exchange = read_name(reader, message)?;
        Ok(Self {
            preference,
            exchange,
        })
    }

    /// Write MX RDATA to wire format.
    pub fn write(&self, writer: &mut WireWriter) {
        writer.write_u16(self.preference);
        write_name_uncompressed(&self.exchange, writer);
    }
}

/// SRV record fields (RFC 2782).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: DomainName,
}

impl SrvRecord {
    /// Read SRV RDATA from wire format.
    pub fn read(reader: &mut WireReader<'_>, message: &[u8]) -> Result<Self, ProtocolError> {
        let priority = reader.read_u16()?;
        let weight = reader.read_u16()?;
        let port = reader.read_u16()?;
        let target = read_name(reader, message)?;
        Ok(Self {
            priority,
            weight,
            port,
            target,
        })
    }

    /// Write SRV RDATA to wire format.
    pub fn write(&self, writer: &mut WireWriter) {
        writer.write_u16(self.priority);
        writer.write_u16(self.weight);
        writer.write_u16(self.port);
        write_name_uncompressed(&self.target, writer);
    }
}

/// SVCB/HTTPS record fields (RFC 9460).
///
/// First version: basic decode with priority, target, and opaque SvcParams.
/// Full SvcParam parsing will be added in Sprint 0.6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcbRecord {
    pub priority: u16,
    pub target: DomainName,
    /// Raw SvcParams wire data (key-value pairs as defined by RFC 9460).
    pub svc_params: Vec<u8>,
}

/// EDNS(0) OPT pseudo-RR (RFC 6891).
///
/// Stored as a special RData variant; OPT uses the CLASS field for
/// sender's UDP payload size and TTL for extended RCODE/version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptRecord {
    /// Sender's UDP payload size (from CLASS field).
    pub udp_payload_size: u16,
    /// Extended RCODE (upper 8 bits).
    pub extended_rcode: u8,
    /// EDNS version.
    pub version: u8,
    /// DO bit (DNSSEC OK) and Z bits (from TTL upper bits).
    pub do_flag: bool,
    /// Raw EDNS options.
    pub options: Vec<u8>,
}

/// RDATA — the parsed content of a DNS resource record.
///
/// Unknown types are stored as opaque bytes to preserve wire-format integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    /// IPv4 address (RFC 1035 Section 3.4.1).
    A(Ipv4Addr),
    /// IPv6 address (RFC 3596).
    AAAA(Ipv6Addr),
    /// Canonical name alias (RFC 1035 Section 3.3.1).
    CNAME(DomainName),
    /// Authoritative name server (RFC 1035 Section 3.3.11).
    NS(DomainName),
    /// Domain name pointer (RFC 1035 Section 3.3.12).
    PTR(DomainName),
    /// Mail exchange (RFC 1035 Section 3.3.9).
    MX(MxRecord),
    /// Text strings (RFC 1035 Section 3.3.14).
    TXT(Vec<Vec<u8>>),
    /// Start of authority (RFC 1035 Section 3.3.13).
    SOA(SoaRecord),
    /// Service locator (RFC 2782).
    SRV(SrvRecord),
    /// Service binding (RFC 9460).
    SVCB(SvcbRecord),
    /// HTTPS service binding (RFC 9460).
    HTTPS(SvcbRecord),
    /// EDNS(0) OPT pseudo-RR (RFC 6891).
    OPT(OptRecord),
    /// Unknown record type — opaque passthrough.
    Unknown { rr_type: u16, data: Vec<u8> },
}

impl RData {
    /// Decode RDATA from wire format.
    ///
    /// # Arguments
    ///
    /// * `rr_type` — the record type determining RDATA format.
    /// * `rdlength` — the RDLENGTH field from the wire.
    /// * `reader` — positioned at the start of RDATA.
    /// * `message` — full message buffer (for name decompression).
    pub fn read(
        rr_type: RecordType,
        rdlength: u16,
        reader: &mut WireReader<'_>,
        message: &[u8],
    ) -> Result<Self, ProtocolError> {
        let start_pos = reader.pos();
        let rdata_end = start_pos + rdlength as usize;

        if rdata_end > message.len() {
            return Err(ProtocolError::RdLengthExceedsBuffer {
                rdlength,
                available: reader.remaining(),
            });
        }

        let rdata = match rr_type {
            RecordType::A => {
                if rdlength != 4 {
                    return Err(ProtocolError::MalformedRData {
                        rr_type: 1,
                        reason: format!("A record RDLENGTH must be 4, got {rdlength}"),
                    });
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(reader.read_bytes(4)?);
                RData::A(Ipv4Addr::from(octets))
            }
            RecordType::AAAA => {
                if rdlength != 16 {
                    return Err(ProtocolError::MalformedRData {
                        rr_type: 28,
                        reason: format!("AAAA record RDLENGTH must be 16, got {rdlength}"),
                    });
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(reader.read_bytes(16)?);
                RData::AAAA(Ipv6Addr::from(octets))
            }
            RecordType::CNAME => RData::CNAME(read_name(reader, message)?),
            RecordType::NS => RData::NS(read_name(reader, message)?),
            RecordType::PTR => RData::PTR(read_name(reader, message)?),
            RecordType::MX => RData::MX(MxRecord::read(reader, message)?),
            RecordType::SOA => RData::SOA(SoaRecord::read(reader, message)?),
            RecordType::TXT => {
                let mut strings = Vec::new();
                while reader.pos() < rdata_end {
                    let len = reader.read_u8()? as usize;
                    let data = reader.read_bytes(len)?.to_vec();
                    strings.push(data);
                }
                RData::TXT(strings)
            }
            RecordType::SRV => RData::SRV(SrvRecord::read(reader, message)?),
            RecordType::SVCB => RData::SVCB(read_svcb(reader, message, rdata_end)?),
            RecordType::HTTPS => RData::HTTPS(read_svcb(reader, message, rdata_end)?),
            RecordType::OPT => {
                let opt_data = reader.read_bytes(rdlength as usize)?.to_vec();
                RData::OPT(OptRecord {
                    udp_payload_size: 0,
                    extended_rcode: 0,
                    version: 0,
                    do_flag: false,
                    options: opt_data,
                })
            }
            RecordType::Unknown(type_val) => {
                let data = reader.read_bytes(rdlength as usize)?.to_vec();
                RData::Unknown {
                    rr_type: type_val,
                    data,
                }
            }
        };

        // Ensure we consumed exactly rdlength bytes.
        let consumed = reader.pos() - start_pos;
        if consumed != rdlength as usize {
            let skip = (rdlength as usize).saturating_sub(consumed);
            if skip > 0 {
                let _ = reader.read_bytes(skip)?;
            }
        }

        Ok(rdata)
    }

    /// Write RDATA to wire format.
    ///
    /// Returns the number of RDATA bytes written.
    pub fn write(&self, writer: &mut WireWriter) -> usize {
        let start = writer.pos();
        match self {
            RData::A(ip) => {
                writer.write_bytes(&ip.octets());
            }
            RData::AAAA(ip) => {
                writer.write_bytes(&ip.octets());
            }
            RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => {
                write_name_uncompressed(name, writer);
            }
            RData::MX(mx) => mx.write(writer),
            RData::SOA(soa) => soa.write(writer),
            RData::TXT(strings) => {
                for s in strings {
                    writer.write_u8(s.len() as u8);
                    writer.write_bytes(s);
                }
            }
            RData::SRV(srv) => srv.write(writer),
            RData::SVCB(svcb) | RData::HTTPS(svcb) => {
                writer.write_u16(svcb.priority);
                write_name_uncompressed(&svcb.target, writer);
                writer.write_bytes(&svcb.svc_params);
            }
            RData::OPT(opt) => {
                writer.write_bytes(&opt.options);
            }
            RData::Unknown { data, .. } => {
                writer.write_bytes(data);
            }
        }
        writer.pos() - start
    }
}

/// Read SVCB/HTTPS RDATA (RFC 9460).
fn read_svcb(
    reader: &mut WireReader<'_>,
    message: &[u8],
    rdata_end: usize,
) -> Result<SvcbRecord, ProtocolError> {
    let priority = reader.read_u16()?;
    let target = read_name(reader, message)?;
    let remaining = rdata_end.saturating_sub(reader.pos());
    let svc_params = reader.read_bytes(remaining)?.to_vec();
    Ok(SvcbRecord {
        priority,
        target,
        svc_params,
    })
}

/// A DNS resource record (RFC 1035 Section 4.1.3).
///
/// ```text
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                      NAME                     /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     CLASS                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TTL                      |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                   RDLENGTH                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                     RDATA                     /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Owner name.
    pub name: DomainName,
    /// Record type.
    pub rr_type: RecordType,
    /// Record class.
    pub class: RecordClass,
    /// Time-to-live in seconds.
    pub ttl: u32,
    /// Parsed record data.
    pub rdata: RData,
}

impl ResourceRecord {
    /// Read a single resource record from wire format.
    pub fn read(reader: &mut WireReader<'_>, message: &[u8]) -> Result<Self, ProtocolError> {
        let name = read_name(reader, message)?;
        let rr_type_raw = reader.read_u16()?;
        let rr_type = RecordType::from_u16(rr_type_raw);
        let class_raw = reader.read_u16()?;
        let class = RecordClass::from_u16(class_raw);
        let ttl = reader.read_u32()?;
        let rdlength = reader.read_u16()?;

        let rdata = if rr_type == RecordType::OPT {
            let opt_data = reader.read_bytes(rdlength as usize)?;
            let do_flag = (ttl & 0x8000) != 0;
            let version = ((ttl >> 16) & 0xFF) as u8;
            let extended_rcode = ((ttl >> 24) & 0xFF) as u8;
            RData::OPT(OptRecord {
                udp_payload_size: class_raw,
                extended_rcode,
                version,
                do_flag,
                options: opt_data.to_vec(),
            })
        } else {
            RData::read(rr_type, rdlength, reader, message)?
        };

        Ok(Self {
            name,
            rr_type,
            class,
            ttl,
            rdata,
        })
    }

    /// Write resource record to wire format.
    pub fn write_to(&self, writer: &mut WireWriter) {
        write_name_uncompressed(&self.name, writer);

        if let RData::OPT(opt) = &self.rdata {
            // OPT pseudo-RR: CLASS = UDP payload size, TTL = extended RCODE/version/flags.
            writer.write_u16(self.rr_type.as_u16());
            writer.write_u16(opt.udp_payload_size);
            let mut ttl_field: u32 = (opt.extended_rcode as u32) << 24;
            ttl_field |= (opt.version as u32) << 16;
            if opt.do_flag {
                ttl_field |= 0x8000;
            }
            writer.write_u32(ttl_field);
            writer.write_u16(opt.options.len() as u16);
            writer.write_bytes(&opt.options);
            return;
        }

        writer.write_u16(self.rr_type.as_u16());
        writer.write_u16(self.class.as_u16());
        writer.write_u32(self.ttl);

        // Reserve 2 bytes for RDLENGTH, write RDATA, then patch.
        let rdlen_pos = writer.pos();
        writer.write_u16(0); // placeholder
        let rdata_start = writer.pos();
        self.rdata.write(writer);
        let rdata_len = (writer.pos() - rdata_start) as u16;

        // Patch RDLENGTH.
        let bytes = writer.as_bytes_mut();
        bytes[rdlen_pos] = (rdata_len >> 8) as u8;
        bytes[rdlen_pos + 1] = (rdata_len & 0xFF) as u8;
    }
}

#[cfg(test)]
#[path = "rr_tests.rs"]
mod tests;
