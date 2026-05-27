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
//!
//! ## Module Organization
//!
//! Types are organized into five submodules:
//!
//! - `schema` — Core governance enums and schema version constants
//! - `emit` — Fact emission and observation task types
//! - `store` — Fact persistence, governance state store, and manifest
//! - `review` — Domain governance state and review candidate types
//! - `thresholds` — Governance threshold configurations

pub mod emit;
pub mod review;
pub mod schema;
pub mod store;
pub mod thresholds;

// Re-export all public types at crate root for backward compatibility.
pub use emit::*;
pub use review::*;
pub use schema::*;
pub use store::*;
pub use thresholds::*;
