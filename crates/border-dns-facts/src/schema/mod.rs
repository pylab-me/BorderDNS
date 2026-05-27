//! Schema-level types for BorderDNS fact governance.
//!
//! Contains:
//! - Core governance enums (`GovernancePhase`, `EvidenceStrength`, etc.)
//! - Schema version constants

pub mod enums;
pub mod schema_version;

pub use enums::*;
pub use schema_version::*;
