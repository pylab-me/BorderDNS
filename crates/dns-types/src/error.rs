//! Error types for DNS protocol operations.

/// Errors produced by DNS protocol codec and related operations.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Buffer too short to contain the expected data.
    #[error("buffer underflow: need {need} bytes but only {have} available")]
    BufferUnderflow { need: usize, have: usize },

    /// Domain name exceeds 255 octets in wire format.
    #[error(
        "domain name exceeds maximum wire length ({0} > {MAX_NAME_WIRE_LENGTH})",
        MAX_NAME_WIRE_LENGTH = 255
    )]
    NameTooLong(usize),

    /// Individual label exceeds 63 octets.
    #[error("label exceeds maximum length ({0} > 63)")]
    LabelTooLong(usize),

    /// Too many labels in domain name (safety limit).
    #[error(
        "too many labels in domain name ({0} > {MAX_LABELS})",
        MAX_LABELS = 128
    )]
    TooManyLabels(usize),

    /// Compression pointer points outside the message buffer.
    #[error("compression pointer offset {pointer} exceeds message length {message_len}")]
    PointerOutOfBounds { pointer: usize, message_len: usize },

    /// Compression pointer loop detected.
    #[error("compression pointer loop detected at offset {offset} (depth {depth})")]
    PointerLoop { offset: usize, depth: usize },

    /// Maximum compression pointer chain depth exceeded.
    #[error("compression pointer chain depth exceeded ({depth} > {max_depth})")]
    PointerChainDepthExceeded { depth: usize, max_depth: usize },

    /// Invalid compression pointer: top two bits are not `11`.
    #[error("invalid compression pointer marker at offset {offset}: got {byte:#04x}")]
    InvalidPointerMarker { offset: usize, byte: u8 },

    /// RDLENGTH exceeds remaining buffer.
    #[error("RDLENGTH ({rdlength}) exceeds remaining buffer ({available})")]
    RdLengthExceedsBuffer { rdlength: u16, available: usize },

    /// Malformed RDATA for the given record type.
    #[error("malformed RDATA for type {rr_type}: {reason}")]
    MalformedRData { rr_type: u16, reason: String },

    /// Unknown or unsupported record type encountered.
    #[error("unsupported record type: {0}")]
    UnsupportedRecordType(u16),

    /// Header section count mismatch.
    #[error(
        "header section count mismatch: expected {expected} {section} records but decoded {decoded}"
    )]
    SectionCountMismatch {
        section: &'static str,
        expected: u16,
        decoded: usize,
    },

    /// EDNS version not supported.
    #[error("unsupported EDNS version: {0}")]
    UnsupportedEdnsVersion(u8),

    /// Message exceeds maximum allowed size.
    #[error("message size {size} exceeds maximum {max}")]
    MessageTooLarge { size: usize, max: usize },

    /// SVCB/HTTPS RDATA malformed.
    #[error("SVCB/HTTPS malformed: {0}")]
    SvcbMalformed(String),

    /// SOA record malformed.
    #[error("SOA malformed: {0}")]
    SoaMalformed(String),

    /// MX record malformed.
    #[error("MX malformed: {0}")]
    MxMalformed(String),

    /// TCP frame length exceeds limit.
    #[error("TCP frame length {length} exceeds limit {limit}")]
    TcpFrameTooLarge { length: u16, limit: u16 },

    /// Generic decode error.
    #[error("decode error: {0}")]
    DecodeError(String),
}
