//! BorderDNS DNS protocol wire codec.
//!
//! Sprint 0: independent DNS message decode/encode, name compression,
//! EDNS(0), SVCB/HTTPS, TCP framing, DoH/DoT/DoQ payload contracts.
//!
//! This crate owns the DNS wire format layer. It must not depend on
//! async runtimes, network IO, or runtime crates.

pub mod header;
pub mod message;
pub mod name;
pub mod question;
pub mod rr;
pub mod tcp_frame;
pub mod transport;
pub mod wire;

// Re-export key types at crate root for convenience.
pub use dns_types as types;
// Header.
pub use header::{DnsHeader, OpCode, ResponseCode};
// Message.
pub use message::DnsMessage;
// Name codec.
pub use name::{
    DomainName, read_name, read_name_at, write_name_compressed, write_name_uncompressed,
};
// Question.
pub use question::DnsQuestion;
// Resource record + RData.
pub use rr::{MxRecord, OptRecord, RData, ResourceRecord, SoaRecord, SrvRecord, SvcbRecord};
// TCP framing.
pub use tcp_frame::{TcpFrameDecoder, TcpFrameEncoder};
// Wire codec.
pub use wire::{WireReader, WireWriter};
