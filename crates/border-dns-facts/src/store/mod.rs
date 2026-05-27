//! Fact persistence and storage types.
//!
//! Contains:
//! - `BorderDnsFactEvent` — top-level fact event DTO
//! - `FactEventWriter` — JSONL event writer
//! - `GovernanceStateStore` — in-memory governance state store
//! - `FactStoreManifest` — store manifest and retention policy
//! - Sub-fact DTOs (`QueryFact`, `DecisionFact`, etc.)

pub mod fact_event;
pub mod fact_store;
pub mod governance_store;
pub mod store_manifest;

pub use fact_event::*;
pub use fact_store::*;
pub use governance_store::*;
pub use store_manifest::*;
