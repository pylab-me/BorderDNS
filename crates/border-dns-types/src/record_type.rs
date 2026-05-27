//! DNS record type codes (RFC 1035 Section 3.2.2, plus common extensions).

/// Standard DNS record type (TYPE field).
///
/// Values follow IANA assignments. Unknown types are handled via
/// the `Unknown(u16)` variant to preserve wire-format integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum RecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    SRV,
    SVCB,
    HTTPS,
    OPT,
    Unknown(u16),
}

impl RecordType {
    /// Convert numeric type code to `RecordType`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            12 => Self::PTR,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            33 => Self::SRV,
            41 => Self::OPT,
            64 => Self::SVCB,
            65 => Self::HTTPS,
            other => Self::Unknown(other),
        }
    }

    /// Get the numeric value for this record type.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::PTR => 12,
            Self::MX => 15,
            Self::TXT => 16,
            Self::AAAA => 28,
            Self::SRV => 33,
            Self::OPT => 41,
            Self::SVCB => 64,
            Self::HTTPS => 65,
            Self::Unknown(v) => v,
        }
    }

    /// Human-readable name for well-known types; `TYPE{n}` for unknown.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::NS => "NS",
            Self::CNAME => "CNAME",
            Self::SOA => "SOA",
            Self::PTR => "PTR",
            Self::MX => "MX",
            Self::TXT => "TXT",
            Self::AAAA => "AAAA",
            Self::SRV => "SRV",
            Self::SVCB => "SVCB",
            Self::HTTPS => "HTTPS",
            Self::OPT => "OPT",
            Self::Unknown(_) => "TYPE?",
        }
    }

    /// Whether this type's RDATA contains a domain name that may use compression.
    pub fn has_name_rdata(self) -> bool {
        matches!(
            self,
            Self::CNAME | Self::NS | Self::PTR | Self::MX | Self::SOA | Self::SRV
        )
    }
}

/// Query type (QTYPE field). Superset of `RecordType` with meta-types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QType {
    /// Exact record type.
    Type(RecordType),
    /// `*` — request all records (QTYPE 255).
    All,
    /// AXFR — zone transfer (QTYPE 252).
    Axfr,
    /// MAILB — mailbox-related (QTYPE 253).
    Mailb,
    /// MAILA — mail agent (QTYPE 254, obsolete).
    Maila,
}

impl QType {
    /// Convert numeric QTYPE code to `QType`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            252 => Self::Axfr,
            253 => Self::Mailb,
            254 => Self::Maila,
            255 => Self::All,
            other => Self::Type(RecordType::from_u16(other)),
        }
    }

    /// Get the numeric value.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Type(rt) => rt.as_u16(),
            Self::All => 255,
            Self::Axfr => 252,
            Self::Mailb => 253,
            Self::Maila => 254,
        }
    }

    /// Get the inner `RecordType` if this is a concrete type query.
    pub fn as_record_type(self) -> Option<RecordType> {
        match self {
            Self::Type(rt) => Some(rt),
            _ => None,
        }
    }
}
