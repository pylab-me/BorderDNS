//! Domain governance state and review candidate types.
//!
//! Contains:
//! - `DomainGovernanceState` — per-domain governance state
//! - `ThirdPartyEvidenceSummary` — third-party observation summary
//! - `ReviewCandidate` — review candidate entry

pub mod governance_state;

pub use governance_state::*;
