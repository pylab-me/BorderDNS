//! Facts schema, governance state, event DTOs, and value registry
//! for the BorderDNS facts-aware governance loop.
//!
//! This crate is responsible for:
//! - Fact schema version
//! - Governance enums (GovernancePhase, ConflictKind, EvidenceStrength, etc.)
//! - Fact event DTO (BorderDnsFactEvent and sub-facts)
//! - DomainGovernanceState DTO
//! - Threshold configurations
//! - ThirdPartyEvidenceSummary
//!
//! This crate is NOT responsible for:
//! - Route scoring (→ border-dns-route-policy)
//! - Governance phase transition logic (→ border-dns-route-policy)
//! - Route decision (→ border-dns-route-policy)
//! - Probe execution (→ border-dns-probes)
//! - Third-party network IO
//! - JSONL file I/O (future: border-dns-runtime background worker)

mod enums;
mod fact_event;
mod governance_state;
mod governance_store;
mod observation;
mod schema_version;

pub use enums::*;
pub use fact_event::*;
pub use governance_state::*;
pub use governance_store::*;
pub use observation::*;
pub use schema_version::*;
