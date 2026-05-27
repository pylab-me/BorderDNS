//! Foundation types for BorderDNS.
//!
//! This crate contains zero-dependency domain types shared across the BorderDNS workspace.
//! It must not depend on any other BorderDNS crate.

mod error;
mod record_class;
mod record_type;
pub mod route;

pub use error::ProtocolError;
pub use record_class::QClass;
pub use record_class::RecordClass;
pub use record_type::QType;
pub use record_type::RecordType;
pub use route::CnameHint;
pub use route::Confidence;
pub use route::DomainPrior;
pub use route::IpGeoScope;
pub use route::ReasonCode;
pub use route::ResolverLocation;
pub use route::Route;
pub use route::RouteSource;

/// Maximum label length as defined by RFC 1035 (63 octets).
pub const MAX_LABEL_LENGTH: usize = 63;

/// Maximum wire-format domain name length (255 octets).
pub const MAX_NAME_WIRE_LENGTH: usize = 255;

/// Maximum number of labels in a domain name (hard safety limit).
pub const MAX_LABEL_COUNT: usize = 128;

/// Maximum DNS message size without EDNS (512 octets).
pub const MAX_UDP_MESSAGE_SIZE: usize = 512;

/// Default EDNS UDP payload size.
pub const DEFAULT_EDNS_UDP_PAYLOAD: u16 = 4096;

/// Maximum UDP payload size we'll accept.
pub const MAX_EDNS_UDP_PAYLOAD: u16 = 65535;
