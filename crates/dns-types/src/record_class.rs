//! DNS record class codes (RFC 1035 Section 3.2.4).

/// DNS record class (CLASS field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordClass {
    /// Internet class (CLASS 1).
    In,
    /// Chaos class (CLASS 3).
    Ch,
    /// Hesiod class (CLASS 4).
    Hs,
    /// Unknown class.
    Unknown(u16),
}

impl RecordClass {
    /// Convert numeric class code to `RecordClass`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::In,
            3 => Self::Ch,
            4 => Self::Hs,
            other => Self::Unknown(other),
        }
    }

    /// Get the numeric value.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::In => 1,
            Self::Ch => 3,
            Self::Hs => 4,
            Self::Unknown(v) => v,
        }
    }
}

/// Query class (QCLASS field). Superset of `RecordClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QClass {
    /// Exact class.
    Class(RecordClass),
    /// `*` — any class (QCLASS 255).
    Any,
}

impl QClass {
    /// Convert numeric QCLASS code to `QClass`.
    pub fn from_u16(value: u16) -> Self {
        match value {
            255 => Self::Any,
            other => Self::Class(RecordClass::from_u16(other)),
        }
    }

    /// Get the numeric value.
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Class(rc) => rc.as_u16(),
            Self::Any => 255,
        }
    }
}
